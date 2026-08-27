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
        await process_command(app, "add condition calendar_summary not contains daily", channel, user)
    conditions = channel.configs["default"]["conditions"]
    assert [(c["variable"], c["operator"], c["value"]) for c in conditions] == [
        ("message", "contains", "urgent"),
        ("team", "equals", "Platform"),
        ("calendar_summary", "not_contains", "daily"),
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
    # The trailing argument is the shared variable dict: every run builds one before rendering,
    # so the message, the target and the alert cannot disagree about a time-dependent value.
    alert.assert_awaited_once_with(app, "token", channel, config, "src", {"text": "DB down"}, "", ANY)
    assert isinstance(alert.await_args.args[-1], dict)



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


# ----- who a config's message reached -----

@pytest.mark.asyncio
async def test_a_reply_reports_the_channel_it_landed_in():
    app = AsyncMock()
    app.client.chat_postMessage.return_value = {"ts": "1.1"}
    config = DEFAULT_CONFIG.copy()
    channel = _mk_channel({"src": config})

    posted = await hutbot.actions.run_action(app, "token", channel, config, "src")

    assert posted["recipients"] == ["#general"]


@pytest.mark.asyncio
async def test_a_dm_reports_the_person_and_not_the_dm_conversation():
    """The posted `channel` is a `D…` id, which names nobody — only the action knows who."""
    app = AsyncMock()
    app.client.conversations_open.return_value = {"channel": {"id": "D999"}}
    app.client.chat_postMessage.return_value = {"ts": "1.1"}
    config = {**DEFAULT_CONFIG.copy(), "action": hutbot.constants.ACTION_DM_USER, "action_target": "<@U777>"}
    channel = _mk_channel({"src": config})

    with patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=User("U777", "alice", "Alice", "Team"))):
        posted = await hutbot.actions.run_action(app, "token", channel, config, "src")

    assert posted["recipients"] == ["<@U777>"]


@pytest.mark.asyncio
async def test_a_group_dm_reports_every_member_it_opened():
    app = AsyncMock()
    app.client.conversations_open.return_value = {"channel": {"id": "G888"}}
    app.client.chat_postMessage.return_value = {"ts": "2.2"}
    config = {**DEFAULT_CONFIG.copy(), "action": hutbot.constants.ACTION_GROUP_DM, "action_target": "@oncall"}
    channel = _mk_channel({"src": config})

    with patch('hutbot.slackcache.get_usergroup_by_handle', new=AsyncMock(return_value=Usergroup("S1", "oncall", "On Call"))), \
         patch('hutbot.slackcache.get_usergroup_members', new=AsyncMock(return_value=["U1", "U2", "U3"])):
        posted = await hutbot.actions.run_action(app, "token", channel, config, "src")

    assert posted["recipients"] == ["<@U1>", "<@U2>", "<@U3>"]


@pytest.mark.asyncio
async def test_a_group_dm_reports_the_eight_it_opened_not_the_nine_it_resolved():
    app = AsyncMock()
    app.client.conversations_open.return_value = {"channel": {"id": "G888"}}
    app.client.chat_postMessage.return_value = {"ts": "2.2"}
    config = {**DEFAULT_CONFIG.copy(), "action": hutbot.constants.ACTION_GROUP_DM, "action_target": "@oncall"}
    channel = _mk_channel({"src": config})
    members = [f"U{index}" for index in range(1, 10)]

    with patch('hutbot.slackcache.get_usergroup_by_handle', new=AsyncMock(return_value=Usergroup("S1", "oncall", "On Call"))), \
         patch('hutbot.slackcache.get_usergroup_members', new=AsyncMock(return_value=members)):
        posted = await hutbot.actions.run_action(app, "token", channel, config, "src")

    assert posted["recipients"] == [f"<@U{index}>" for index in range(1, 9)]


@pytest.mark.asyncio
async def test_a_channel_post_reports_the_target_channel_not_the_defining_one():
    app = AsyncMock()
    app.client.chat_postMessage.return_value = {"ts": "3.3"}
    config = {**DEFAULT_CONFIG.copy(), "action": hutbot.constants.ACTION_POST_CHANNEL, "action_target": "<#C777>"}
    channel = _mk_channel({"src": config})

    app.client.conversations_info.return_value = {"channel": {"name": "incidents"}}

    posted = await hutbot.actions.run_action(app, "token", channel, config, "src")

    assert posted["recipients"] == ["#incidents"]


@pytest.mark.asyncio
async def test_a_channel_post_falls_back_to_the_form_slack_expands_itself():
    """`#C777` would render as literal text, so an unresolved channel keeps the mention form."""
    app = AsyncMock()
    app.client.chat_postMessage.return_value = {"ts": "3.3"}
    app.client.conversations_info.return_value = {"channel": {}}
    config = {**DEFAULT_CONFIG.copy(), "action": hutbot.constants.ACTION_POST_CHANNEL, "action_target": "<#C777>"}
    channel = _mk_channel({"src": config})

    posted = await hutbot.actions.run_action(app, "token", channel, config, "src")

    assert posted["recipients"] == ["<#C777>"]


# ----- the facts a chained config gets to read -----

@pytest.mark.asyncio
async def test_the_parent_facts_describe_the_run_that_built_them():
    app = AsyncMock()
    app.client.conversations_open.return_value = {"channel": {"id": "G888"}}
    app.client.chat_postMessage.return_value = {"ts": "2.2"}
    config = {**DEFAULT_CONFIG.copy(), "action": hutbot.constants.ACTION_GROUP_DM,
              "action_target": "@oncall", "reply_message": "Ping {{user}} in {{channel}}",
              "buttons": [{"label": "Go", "action": "config", "value": "tgt"}]}
    channel = _mk_channel({"src": config})

    with patch('hutbot.slackcache.get_usergroup_by_handle', new=AsyncMock(return_value=Usergroup("S1", "oncall", "On Call"))), \
         patch('hutbot.slackcache.get_usergroup_members', new=AsyncMock(return_value=["U1", "U2"])), \
         patch('hutbot.buttons.register_escalation', new=AsyncMock()) as reg:
        await hutbot.actions.run_action(app, "token", channel, config, "src",
                                        {"user": User("U5", "bob", "Bob", "T"), "channel_id": "C12345"})

    facts = reg.await_args.kwargs["parent"]
    assert facts["variable_names"] == ["user", "channel"]
    assert facts["variables"] == ["<@U5>", "#general"]
    assert facts["action"] == "group_dm"
    assert facts["target"] == "@oncall"
    assert facts["recipients"] == ["<@U1>", "<@U2>"]
    # Not the name, the text or the ts: the record already stores those under their own keys,
    # which is what lets a record written before this existed still answer them.
    assert "config_name" not in facts and "message" not in facts and "timestamp" not in facts


@pytest.mark.asyncio
async def test_the_parent_facts_record_a_rendered_target_not_the_template():
    app = AsyncMock()
    app.client.conversations_open.return_value = {"channel": {"id": "D999"}}
    app.client.chat_postMessage.return_value = {"ts": "1.1"}
    config = {**DEFAULT_CONFIG.copy(), "action": hutbot.constants.ACTION_DM_USER,
              "action_target": "{{user}}", "buttons": [{"label": "Go", "action": "config", "value": "tgt"}]}
    channel = _mk_channel({"src": config})

    with patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=User("U5", "bob", "Bob", "T"))), \
         patch('hutbot.buttons.register_escalation', new=AsyncMock()) as reg:
        await hutbot.actions.run_action(app, "token", channel, config, "src",
                                        {"user": User("U5", "bob", "Bob", "T")})

    assert reg.await_args.kwargs["parent"]["target"] == "<@U5>"


@pytest.mark.asyncio
async def test_the_parent_facts_are_capped_so_a_chain_cannot_compound_them():
    app = AsyncMock()
    app.client.chat_postMessage.return_value = {"ts": "1.1"}
    config = {**DEFAULT_CONFIG.copy(),
              "reply_message": "{{message}} " * (hutbot.constants.MAX_PARENT_VARIABLES + 10),
              "buttons": [{"label": "Go", "action": "config", "value": "tgt"}]}
    channel = _mk_channel({"src": config})

    with patch('hutbot.buttons.register_escalation', new=AsyncMock()) as reg:
        await hutbot.actions.run_action(app, "token", channel, config, "src",
                                        {"text": "x" * (hutbot.constants.PARENT_VARIABLE_LENGTH_LIMIT + 50)})

    facts = reg.await_args.kwargs["parent"]
    assert len(facts["variables"]) == hutbot.constants.MAX_PARENT_VARIABLES
    assert len(facts["variable_names"]) == hutbot.constants.MAX_PARENT_VARIABLES
    assert all(len(value) <= hutbot.constants.PARENT_VARIABLE_LENGTH_LIMIT for value in facts["variables"])


@pytest.mark.asyncio
async def test_a_config_without_conditions_resolves_a_provider_once_for_message_and_alert():
    """One namespace per run, so the message and the alert cannot disagree about a value."""
    app = AsyncMock()
    app.client.chat_postMessage.return_value = {"ts": "1.1"}
    config = {**DEFAULT_CONFIG.copy(), "opsgenie": True,
              "reply_message": "{{opsgenie_current_user}} is on call",
              "opsgenie_message": "paging {{opsgenie_current_user}}"}
    channel = _mk_channel({"src": config})
    hutbot.state.opsgenie_configured = True
    try:
        with patch('hutbot.opsgenie.get_opsgenie_template_variables',
                   new=AsyncMock(return_value={"opsgenie_current_user": "<@U1>"})) as og, \
             patch('hutbot.opsgenie.post_opsgenie_alert', new=AsyncMock()):
            await hutbot.actions.run_action(app, "token", channel, config, "src", {"text": "DB down"})
    finally:
        hutbot.state.opsgenie_configured = False

    assert og.await_count == 1


# ----- a chain cannot run forever -----

@pytest.mark.asyncio
async def test_the_chain_depth_counts_one_hop_per_config():
    app = AsyncMock()
    app.client.chat_postMessage.return_value = {"ts": "1.1"}
    config = {**DEFAULT_CONFIG.copy(), "buttons": [{"label": "Go", "action": "config", "value": "tgt"}]}
    channel = _mk_channel({"src": config})

    with patch('hutbot.buttons.register_escalation', new=AsyncMock()) as reg:
        await hutbot.actions.run_action(app, "token", channel, config, "src", {"parent": {"depth": 3}})

    assert reg.await_args.kwargs["parent"]["depth"] == 4


@pytest.mark.asyncio
async def test_a_run_with_no_parent_starts_the_count_at_one():
    app = AsyncMock()
    app.client.chat_postMessage.return_value = {"ts": "1.1"}
    config = {**DEFAULT_CONFIG.copy(), "buttons": [{"label": "Go", "action": "config", "value": "tgt"}]}
    channel = _mk_channel({"src": config})

    with patch('hutbot.buttons.register_escalation', new=AsyncMock()) as reg:
        await hutbot.actions.run_action(app, "token", channel, config, "src")

    assert reg.await_args.kwargs["parent"]["depth"] == 1


@pytest.mark.asyncio
async def test_too_deep_a_chain_stops_without_posting():
    app = AsyncMock()
    config = DEFAULT_CONFIG.copy()
    channel = _mk_channel({"src": config})
    too_deep = {"parent": {"depth": hutbot.constants.MAX_ACTION_CHAIN_DEPTH + 1}}

    posted, reason = await hutbot.actions.run_action_with_reason(
        app, "token", channel, config, "src", too_deep)

    assert posted is None
    assert reason == f"action chain is more than {hutbot.constants.MAX_ACTION_CHAIN_DEPTH} configs deep"
    app.client.chat_postMessage.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_chain_at_the_limit_still_runs():
    app = AsyncMock()
    app.client.chat_postMessage.return_value = {"ts": "1.1"}
    config = DEFAULT_CONFIG.copy()
    channel = _mk_channel({"src": config})
    at_limit = {"parent": {"depth": hutbot.constants.MAX_ACTION_CHAIN_DEPTH}}

    posted, reason = await hutbot.actions.run_action_with_reason(
        app, "token", channel, config, "src", at_limit)

    assert reason == "" and posted is not None


@pytest.mark.asyncio
async def test_a_record_without_a_depth_starts_counting_again():
    """A record written before the guard shipped: an in-flight chain resumes from zero."""
    app = AsyncMock()
    app.client.chat_postMessage.return_value = {"ts": "1.1"}
    config = {**DEFAULT_CONFIG.copy(), "buttons": [{"label": "Go", "action": "config", "value": "tgt"}]}
    channel = _mk_channel({"src": config})

    with patch('hutbot.buttons.register_escalation', new=AsyncMock()) as reg:
        await hutbot.actions.run_action(app, "token", channel, config, "src", {"parent": {"config_name": "old"}})

    assert reg.await_args.kwargs["parent"]["depth"] == 1


# ----- a template this run cannot render costs nothing -----

def _dead_alert_config(**overrides):
    """OpsGenie switched off, but the alert template it left behind names both providers."""
    return {**DEFAULT_CONFIG.copy(), "opsgenie": False,
            "reply_message": "plain reply",
            "opsgenie_message": "paging {{opsgenie_current_user}} about {{calendar_summary}}",
            **overrides}


@pytest.mark.asyncio
@pytest.mark.parametrize("conditions", [
    [],
    [{"variable": "message", "operator": "contains", "value": "x"}],
])
async def test_an_alert_template_that_cannot_fire_resolves_no_provider(conditions):
    """Switching OpsGenie off does not clear `opsgenie_message`, and nothing renders it — so
    counting its variables would buy a round-trip, and its timeout, for text nobody sees."""
    app = AsyncMock()
    app.client.chat_postMessage.return_value = {"ts": "1.1"}
    config = _dead_alert_config(conditions=conditions)
    channel = _mk_channel({"src": config})

    with patch('hutbot.opsgenie.get_opsgenie_template_variables', new=AsyncMock(return_value={})) as og, \
         patch('hutbot.calendarfeed.get_calendar_template_variables', new=AsyncMock(return_value={})) as cal:
        await hutbot.actions.run_action(app, "token", channel, config, "src", {"text": "x"})

    og.assert_not_awaited()
    cal.assert_not_awaited()


@pytest.mark.asyncio
async def test_an_alert_template_nothing_else_names_still_resolves_when_it_can_fire():
    """The other half of the gate: an enabled alert is the only reader, and still gets its values."""
    app = AsyncMock()
    app.client.chat_postMessage.return_value = {"ts": "1.1"}
    config = _dead_alert_config(opsgenie=True)
    channel = _mk_channel({"src": config})
    hutbot.state.opsgenie_configured = True
    try:
        with patch('hutbot.opsgenie.get_opsgenie_template_variables',
                   new=AsyncMock(return_value={"opsgenie_current_user": "<@U1>"})) as og, \
             patch('hutbot.calendarfeed.get_calendar_template_variables',
                   new=AsyncMock(return_value={"calendar_summary": "Standup"})) as cal, \
             patch('hutbot.opsgenie.post_opsgenie_alert', new=AsyncMock()) as alert:
            await hutbot.actions.run_action(app, "token", channel, config, "src", {"text": "x"})
    finally:
        hutbot.state.opsgenie_configured = False

    assert og.await_count == 1 and cal.await_count == 1
    assert alert.await_args.args[5] == "paging <@U1> about Standup"


@pytest.mark.asyncio
async def test_an_alert_template_costs_nothing_on_an_instance_without_opsgenie():
    """`opsgenie: true` on a config means nothing when the instance has no token."""
    app = AsyncMock()
    app.client.chat_postMessage.return_value = {"ts": "1.1"}
    config = _dead_alert_config(opsgenie=True)
    channel = _mk_channel({"src": config})

    with patch('hutbot.opsgenie.get_opsgenie_template_variables', new=AsyncMock(return_value={})) as og, \
         patch('hutbot.calendarfeed.get_calendar_template_variables', new=AsyncMock(return_value={})) as cal:
        await hutbot.actions.run_action(app, "token", channel, config, "src", {"text": "x"})

    og.assert_not_awaited()
    cal.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_condition_on_a_provider_is_resolved_even_with_the_alert_off():
    """Narrowing the templates must not narrow the conditions — the gate still has to be judged."""
    app = AsyncMock()
    app.client.chat_postMessage.return_value = {"ts": "1.1"}
    config = _dead_alert_config(conditions=[
        {"variable": "opsgenie_current_user", "operator": "not_empty", "value": ""}])
    channel = _mk_channel({"src": config})

    with patch('hutbot.opsgenie.get_opsgenie_template_variables',
               new=AsyncMock(return_value={"opsgenie_current_user": "<@U1>"})) as og:
        posted = await hutbot.actions.run_action(app, "token", channel, config, "src", {"text": "x"})

    assert og.await_count == 1
    assert posted is not None
