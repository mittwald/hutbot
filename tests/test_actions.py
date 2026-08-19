import copy

from tests._common import *  # noqa: F401,F403



@pytest.mark.asyncio
async def test_multi_cancel_reaction_added():
    app = AsyncMock()
    channel_id = "C123"
    user1_id = "U1"
    user2 = User(id="U2", name="user2", real_name="User Two", team="B")
    ts = "12345.6789"
    event = {'item': {'channel': channel_id, 'ts': ts}, 'user': user2.id}
    configs = {
        "config1": {**DEFAULT_CONFIG.copy(), "included_teams": ["A"]},
        "config2": {**DEFAULT_CONFIG.copy(), "included_teams": ["B"]},
    }
    channel = Channel(id=channel_id, name="test-ch", configs=configs)

    task1 = AsyncMock()
    task1.cancel = MagicMock()
    task2 = AsyncMock()
    task2.cancel = MagicMock()

    hutbot.state.scheduled_messages.clear()
    hutbot.state.scheduled_messages[(channel_id, ts, "config1")] = ScheduledReply(task=task1, user_id=user1_id)
    hutbot.state.scheduled_messages[(channel_id, ts, "config2")] = ScheduledReply(task=task2, user_id=user1_id)

    with patch('hutbot.slackcache.get_channel_by_id', return_value=channel), patch('hutbot.slackcache.get_user_by_id', side_effect=[user2, User(id=user1_id, name="user1", real_name="User One", team="A")]):
        await handle_reaction_added(app, event)

    task1.cancel.assert_called_once()
    task2.cancel.assert_not_called()
    assert list(hutbot.state.scheduled_messages.keys()) == [(channel_id, ts, "config2")]



@pytest.mark.asyncio
async def test_set_action_normalizes_dashes():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "test", "Test User", "Testers")
    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message'):
        await process_command(app, "set action dm-user <@U999>", channel, user)
        assert channel.configs["default"]["action"] == "dm_user"
        await process_command(app, "set action group-dm @sre", channel, user)
        assert channel.configs["default"]["action"] == "group_dm"



@pytest.mark.asyncio
async def test_add_condition_accepts_operator_aliases():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "test", "Test User", "Testers")
    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message'):
        await process_command(app, "add condition message has urgent", channel, user)
        await process_command(app, "condition {{team}} is Platform", channel, user)
        await process_command(app, "add condition calendar_current_summary not contains daily", channel, user)
    conditions = channel.configs["default"]["conditions"]
    assert [(c["variable"], c["operator"], c["value"]) for c in conditions] == [
        ("message", "contains", "urgent"),
        ("team", "equals", "Platform"),
        ("calendar_current_summary", "not_contains", "daily"),
    ]
    assert channel.configs["default"]["conditions_mode"] == "all"



@pytest.mark.asyncio
async def test_conditions_gate_run_action():
    app = AsyncMock()
    config = copy.deepcopy(DEFAULT_CONFIG)
    config["reply_message"] = "ping"
    config["conditions"] = [{"variable": "message", "operator": "contains", "value": "deploy"}]
    channel = _mk_channel({"gated": config})
    with patch('hutbot.messaging._post_message', new=AsyncMock(return_value={"channel": "C12345", "ts": "9.1"})) as post:
        posted, reason = await hutbot.actions.run_action_with_reason(
            app, "token", channel, config, "gated", context={"text": "nothing to see"})
        assert posted is None and "did not match" in reason
        post.assert_not_awaited()

        posted, reason = await hutbot.actions.run_action_with_reason(
            app, "token", channel, config, "gated", context={"text": "please deploy this"})
        assert posted is not None and reason == ""
        assert post.await_count == 1



@pytest.mark.asyncio
async def test_blocked_config_does_not_page_opsgenie():
    app = AsyncMock()
    hutbot.state.opsgenie_configured = True
    config = copy.deepcopy(DEFAULT_CONFIG)
    config["opsgenie"] = True
    config["conditions"] = [{"variable": "message", "operator": "not_empty"}]
    channel = _mk_channel({"page": config})
    with patch('hutbot.opsgenie.post_opsgenie_alert', new=AsyncMock()) as alert, \
         patch('hutbot.messaging._post_message', new=AsyncMock(return_value={"channel": "C12345", "ts": "9.1"})):
        # No message behind the run, so `{{message}}` is empty and the gate closes.
        posted = await hutbot.actions.run_action(app, "token", channel, config, "page", context={"channel_id": "C12345"})
    assert posted is None
    alert.assert_not_awaited()



@pytest.mark.asyncio
async def test_conditions_build_variables_once():
    """The gate, the message, and the alert share one resolution — never three."""
    app = AsyncMock()
    hutbot.state.opsgenie_configured = True
    config = copy.deepcopy(DEFAULT_CONFIG)
    config["opsgenie"] = True
    config["reply_message"] = "on call: {{opsgenie_current_user}}"
    config["opsgenie_message"] = "alert for {{opsgenie_current_user}}"
    config["conditions"] = [{"variable": "opsgenie_current_user", "operator": "not_empty"}]
    channel = _mk_channel({"page": config})
    resolved = {"opsgenie_current_user": "<@U9>"}
    with patch('hutbot.opsgenie.get_opsgenie_template_variables', new=AsyncMock(return_value=resolved)) as og, \
         patch('hutbot.opsgenie.post_opsgenie_alert', new=AsyncMock()), \
         patch('hutbot.messaging._post_message', new=AsyncMock(return_value={"channel": "C12345", "ts": "9.1"})):
        posted = await hutbot.actions.run_action(app, "token", channel, config, "page", context={"channel_id": "C12345"})
    assert posted is not None
    assert og.await_count == 1



@pytest.mark.asyncio
async def test_conditions_do_not_fetch_opsgenie_when_unreferenced():
    app = AsyncMock()
    config = copy.deepcopy(DEFAULT_CONFIG)
    config["reply_message"] = "ping"
    config["conditions"] = [{"variable": "config", "operator": "not_empty"}]
    channel = _mk_channel({"plain": config})
    with patch('hutbot.opsgenie.get_opsgenie_template_variables', new=AsyncMock(return_value={})) as og, \
         patch('hutbot.calendarfeed.get_calendar_template_variables', new=AsyncMock(return_value={})) as cal, \
         patch('hutbot.messaging._post_message', new=AsyncMock(return_value={"channel": "C12345", "ts": "9.1"})):
        await hutbot.actions.run_action(app, "token", channel, config, "plain", context={"channel_id": "C12345"})
    og.assert_not_awaited()
    cal.assert_not_awaited()



@pytest.mark.asyncio
async def test_action_dm_user_opens_dm_and_posts():
    app = AsyncMock()
    app.client.conversations_open.return_value = {"channel": {"id": "D999"}}
    app.client.chat_postMessage.return_value = {"ts": "1.1"}
    config = DEFAULT_CONFIG.copy()
    config["action"] = hutbot.constants.ACTION_DM_USER
    config["action_target"] = "<@U777>"
    channel = _mk_channel({"src": config})
    with patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=User("U777", "alice", "Alice", "Team"))):
        posted = await hutbot.actions.run_action(app, "token", channel, config, "src")
    app.client.conversations_open.assert_awaited_once_with(users=["U777"])
    assert app.client.chat_postMessage.call_args.kwargs["channel"] == "D999"
    assert posted["channel"] == "D999"



@pytest.mark.asyncio
async def test_action_group_dm_resolves_members_and_opens_mpim():
    app = AsyncMock()
    app.client.conversations_open.return_value = {"channel": {"id": "G888"}}
    app.client.chat_postMessage.return_value = {"ts": "2.2"}
    config = DEFAULT_CONFIG.copy()
    config["action"] = hutbot.constants.ACTION_GROUP_DM
    config["action_target"] = "@oncall"
    channel = _mk_channel({"src": config})
    with patch('hutbot.slackcache.get_usergroup_by_handle', new=AsyncMock(return_value=Usergroup("S1", "oncall", "On Call"))), \
         patch('hutbot.slackcache.get_usergroup_members', new=AsyncMock(return_value=["U1", "U2", "U3"])):
        posted = await hutbot.actions.run_action(app, "token", channel, config, "src")
    app.client.conversations_open.assert_awaited_once_with(users=["U1", "U2", "U3"])
    assert app.client.chat_postMessage.call_args.kwargs["channel"] == "G888"
    assert posted["channel"] == "G888"


@pytest.mark.asyncio
async def test_run_action_fires_opsgenie_when_slack_post_fails():
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(), "opsgenie": True}
    channel = _mk_channel({"src": config})

    with patch('hutbot.actions.action_reply', new=AsyncMock(return_value=None)), \
         patch('hutbot.actions.maybe_post_opsgenie_alert', new=AsyncMock()) as alert:
        posted = await hutbot.actions.run_action(app, "token", channel, config, "src", {"text": "DB down"})

    assert posted is None
    # The trailing None is the shared variable dict: this config has no conditions, so
    # nothing was resolved up front and the alert renders its own.
    alert.assert_awaited_once_with(app, "token", channel, config, "src", {"text": "DB down"}, "", None)



# ----- action_reply threads only within the same channel -----

@pytest.mark.asyncio
async def test_action_reply_threads_only_in_same_channel():
    app = AsyncMock()
    app.client.chat_postMessage.return_value = {"ts": "9"}
    channel = _mk_channel({"d": DEFAULT_CONFIG.copy()})
    # Same channel as the original message → threads.
    await hutbot.actions.action_reply(app, channel, {}, {"channel_id": "C12345", "message_ts": "7.7"}, "t", None)
    assert app.client.chat_postMessage.call_args.kwargs.get("thread_ts") == "7.7"
    # Different conversation (e.g. button on a DM) → must NOT thread.
    app.client.chat_postMessage.reset_mock()
    await hutbot.actions.action_reply(app, channel, {}, {"channel_id": "D999", "message_ts": "7.7"}, "t", None)
    assert "thread_ts" not in app.client.chat_postMessage.call_args.kwargs
