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
async def test_set_condition_aliases():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "test", "Test User", "Testers")
    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message'):
        await process_command(app, "set condition outlook", channel, user)
        assert channel.configs["default"]["condition"] == hutbot.constants.CONDITION_OUTLOOK
        await process_command(app, "set condition none", channel, user)
        assert channel.configs["default"]["condition"] == ""



# ----- Conditions -----

@pytest.mark.asyncio
async def test_evaluate_condition_none_is_true():
    app = AsyncMock()
    config = DEFAULT_CONFIG.copy()
    assert await hutbot.actions.evaluate_condition(app, config) is True



@pytest.mark.asyncio
async def test_evaluate_condition_outlook_passes_negate():
    app = AsyncMock()
    config = DEFAULT_CONFIG.copy()
    config["condition"] = hutbot.constants.CONDITION_OUTLOOK
    config["outlook_subject_pattern"] = "standup"
    config["condition_negate"] = True
    with patch('hutbot.actions.outlook.calendar_condition_met', new=AsyncMock(return_value=False)) as met:
        result = await hutbot.actions.evaluate_condition(app, config)
        assert result is False
        met.assert_awaited_once_with("standup", "", True)



@pytest.mark.asyncio
async def test_outlook_stub_reads_env(monkeypatch):
    monkeypatch.setenv("HUTBOT_OUTLOOK_STUB_EVENTS", json.dumps([
        {"subject": "Daily standup", "body": "join here"},
        {"subject": "1:1", "body": "private"},
    ]))
    events = await outlook.find_calendar_events("standup")
    assert len(events) == 1 and events[0]["subject"] == "Daily standup"
    assert await outlook.calendar_condition_met("standup") is True
    assert await outlook.calendar_condition_met("standup", negate=True) is False
    assert await outlook.calendar_condition_met("no-such-meeting") is False
    assert await outlook.calendar_condition_met("no-such-meeting", negate=True) is True



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
    alert.assert_awaited_once_with(app, "token", channel, config, "src", {"text": "DB down"}, "")



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
