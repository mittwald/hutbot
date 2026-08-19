from tests._common import *  # noqa: F401,F403



@pytest.mark.asyncio
async def test_process_command_set_pattern():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as mock_send_message:
        await set_pattern(app, channel, "default", '".*alarm.*"', "true", user, "")
        assert channel.configs["default"]["pattern"] == ".*alarm.*"
        assert channel.configs["default"]["pattern_case_sensitive"] is True
        mock_send_message.assert_called_with(app, channel, user, "Pattern set to `.*alarm.*` for configuration `default`. (case-sensitive)", "")

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await set_pattern(app, channel, "default", '"*"', None, user, "")
        mock_send_message.assert_called_with(app, channel, user, "Invalid pattern: `nothing to repeat at position 0`", "")



@pytest.mark.asyncio
async def test_process_command_set_pattern_empty():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as mock_send_message:
        await set_pattern(app, channel, "default", '""', "true", user, "")
        assert channel.configs["default"]["pattern"] == ""
        assert channel.configs["default"]["pattern_case_sensitive"] is True
        mock_send_message.assert_called_with(app, channel, user, "Pattern set to `` for configuration `default`. (case-sensitive)", "")



@pytest.mark.asyncio
async def test_process_command_set_pattern_custom_config():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")
    
    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as mock_send_message:
        await set_pattern(app, channel, "my-config", '".*alarm.*"', "true", user, "")
        assert channel.configs["my-config"]["pattern"] == ".*alarm.*"
        assert channel.configs["my-config"]["pattern_case_sensitive"] is True
        mock_send_message.assert_called_with(app, channel, user, "Pattern set to `.*alarm.*` for configuration `my-config`. (case-sensitive)", "")



@pytest.mark.asyncio
async def test_handle_channel_message_multi_config_and_pattern():
    app = AsyncMock()
    configs = {
        "config1": {"pattern": ".*alarm.*", "reply_message": "Alarm message"},
        "config2": {"pattern": ".*report.*", "reply_message": "Report message"},
        "config3": {"pattern": ".*nothing.*", "reply_message": "Nothing message"}
    }

    for name, cfg in configs.items():
        for k, v in DEFAULT_CONFIG.items():
            if k not in cfg:
                cfg[k] = v

    channel = Channel(id="C12345", name="general", configs=configs)
    user = User(id="U12345", name="test", real_name="Test User", team="team1")

    with patch('hutbot.datetimefmt.is_work_day', return_value=True), \
         patch('hutbot.scheduling.schedule_reply') as mock_schedule_reply:

        hutbot.state.scheduled_messages.clear()
        await handle_channel_message(app, "token", channel, user, "This is an alarm and a report", "1234.1")

        assert mock_schedule_reply.call_count == 2

        snapshot = {"conditions": [], "conditions_mode": "all"}
        calls = [
            call(app, "token", channel, configs["config1"], "config1", user, "This is an alarm and a report", "1234.1", conditions_snapshot=snapshot),
            call(app, "token", channel, configs["config2"], "config2", user, "This is an alarm and a report", "1234.1", conditions_snapshot=snapshot)
        ]
        mock_schedule_reply.assert_has_calls(calls, any_order=True)



@pytest.mark.asyncio
async def test_multi_cancel_thread_response():
    app = AsyncMock()
    configs = {
        "config1": {**DEFAULT_CONFIG.copy(), "included_teams": ["A"]},
        "config2": {**DEFAULT_CONFIG.copy(), "included_teams": ["B"]},
    }
    channel = Channel(id="C123", name="test-ch", configs=configs)
    user1 = User(id="U1", name="user1", real_name="User One", team="A")
    user2 = User(id="U2", name="user2", real_name="User Two", team="B")
    ts = "12345.6789"

    task1 = AsyncMock()
    task1.cancel = MagicMock()
    task2 = AsyncMock()
    task2.cancel = MagicMock()

    hutbot.state.scheduled_messages.clear()
    hutbot.state.scheduled_messages[(channel.id, ts, "config1")] = ScheduledReply(task=task1, user_id=user1.id)
    hutbot.state.scheduled_messages[(channel.id, ts, "config2")] = ScheduledReply(task=task2, user_id=user1.id)

    with patch('hutbot.slackcache.get_user_by_id', return_value=user1):
        await handle_thread_response(app, channel, user2, ts)

    task1.cancel.assert_called_once()
    task2.cancel.assert_not_called()
    assert list(hutbot.state.scheduled_messages.keys()) == [(channel.id, ts, "config2")]



@pytest.mark.asyncio
async def test_handle_channel_message_ignores_bot_for_configs_without_include_bots():
    app = AsyncMock()
    configs = {
        "bots": {**DEFAULT_CONFIG.copy(), "include_bots": True},
        "humans": {**DEFAULT_CONFIG.copy(), "include_bots": False},
    }
    channel = Channel(id="C12345", name="general", configs=configs)
    bot_user = User(id="B12345", name="alert-bot", real_name="Alert Bot", team="Bots")

    with patch('hutbot.datetimefmt.is_work_day', return_value=True), \
         patch('hutbot.scheduling.schedule_reply') as mock_schedule_reply:
        hutbot.state.scheduled_messages.clear()
        await handle_channel_message(app, "token", channel, bot_user, "Alarm", "1234.1", actor_is_bot=True)

    mock_schedule_reply.assert_called_once_with(app, "token", channel, configs["bots"], "bots", bot_user, "Alarm", "1234.1",
                                                conditions_snapshot={"conditions": [], "conditions_mode": "all"})



@pytest.mark.asyncio
async def test_route_message_schedules_bot_attachment_text_when_bots_included():
    app = AsyncMock()
    configs = {
        "alerts": {
            **DEFAULT_CONFIG.copy(),
            "include_bots": True,
            "pattern": "FailedTemporalExecutions",
        },
    }
    channel = Channel(id="C12345", name="general", configs=configs)
    bot_user = User(id="B12345", name="alertmanager", real_name="Alertmanager", team="Bots")
    event = {
        "type": "message",
        "subtype": "bot_message",
        "text": "",
        "attachments": [{
            "fallback": "[FIRING:1] FailedTemporalExecutions noisy fallback",
            "text": "Alerts: \n       - 1 removeQueueItemForAbortedOrder temporal executions needs operating.",
            "title": "[FIRING:1] FailedTemporalExecutions",
        }],
        "ts": "1234.1",
        "bot_id": bot_user.id,
        "channel": channel.id,
        "event_ts": "1234.1",
        "channel_type": "channel",
    }

    extracted_text = (
        "[FIRING:1] FailedTemporalExecutions\n"
        "Alerts: \n       - 1 removeQueueItemForAbortedOrder temporal executions needs operating."
    )

    with patch('hutbot.slackcache.get_channel_by_id', return_value=channel), \
         patch('hutbot.slackcache.get_user_by_id', return_value=bot_user), \
         patch('hutbot.datetimefmt.is_work_day', return_value=True), \
         patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()), \
         patch('hutbot.scheduling.schedule_reply') as mock_schedule_reply:
        hutbot.state.scheduled_messages.clear()
        hutbot.state._scheduled_replies_cache.clear()
        await route_message(app, "token", event)

    mock_schedule_reply.assert_called_once_with(app, "token", channel, configs["alerts"], "alerts", bot_user, extracted_text, "1234.1",
                                                conditions_snapshot={"conditions": [], "conditions_mode": "all"})
    assert hutbot.state._scheduled_replies_cache[(channel.id, "1234.1", "alerts")]["text"] == extracted_text



@pytest.mark.asyncio
async def test_thread_response_by_bot_cancels_only_configs_without_include_bots():
    app = AsyncMock()
    configs = {
        "bots": {**DEFAULT_CONFIG.copy(), "include_bots": True},
        "humans": {**DEFAULT_CONFIG.copy(), "include_bots": False},
    }
    channel = Channel(id="C123", name="test-ch", configs=configs)
    bot_user = User(id="B1", name="alert-bot", real_name="Alert Bot", team="Bots")
    message_user = User(id="U1", name="user1", real_name="User One", team="A")
    ts = "12345.6789"

    task1 = AsyncMock()
    task1.cancel = MagicMock()
    task2 = AsyncMock()
    task2.cancel = MagicMock()

    hutbot.state.scheduled_messages.clear()
    hutbot.state.scheduled_messages[(channel.id, ts, "bots")] = ScheduledReply(task=task1, user_id=message_user.id)
    hutbot.state.scheduled_messages[(channel.id, ts, "humans")] = ScheduledReply(task=task2, user_id=message_user.id)

    with patch('hutbot.slackcache.get_user_by_id', return_value=message_user):
        await handle_thread_response(app, channel, bot_user, ts, actor_is_bot=True)

    task1.cancel.assert_not_called()
    task2.cancel.assert_called_once()
    assert list(hutbot.state.scheduled_messages.keys()) == [(channel.id, ts, "bots")]


@pytest.mark.asyncio
async def test_handle_channel_message_skips_disabled_config():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={
        "active": {**DEFAULT_CONFIG.copy(), "enabled": True, "wait_time": 0},
        "silent": {**DEFAULT_CONFIG.copy(), "enabled": False, "wait_time": 0},
    })
    user = User("U12345", "test", "Test User", "Testers")

    with patch('hutbot.scheduling.schedule_reply') as mock_schedule, patch('hutbot.persistence.flush_replies_cache'):
        await handle_channel_message(app, "", channel, user, "hello", "1234.1")

    called_config_names = [call[0][4] for call in mock_schedule.call_args_list]
    assert "active" in called_config_names
    assert "silent" not in called_config_names



@pytest.mark.asyncio
async def test_handle_channel_message_enabled_by_default():
    app = AsyncMock()
    config = DEFAULT_CONFIG.copy()
    config.pop("enabled", None)
    channel = Channel(id="C12345", name="general", configs={"default": {**config, "wait_time": 0}})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('hutbot.scheduling.schedule_reply') as mock_schedule, patch('hutbot.persistence.flush_replies_cache'):
        await handle_channel_message(app, "", channel, user, "hello", "1234.1")

    assert mock_schedule.called



# ----- Trigger gating -----

@pytest.mark.asyncio
async def test_handle_channel_message_skips_non_message_trigger():
    app = AsyncMock()
    msg_cfg = DEFAULT_CONFIG.copy()
    sched_cfg = DEFAULT_CONFIG.copy()
    sched_cfg["trigger"] = "schedule"
    channel = _mk_channel({"msg": msg_cfg, "sched": sched_cfg})
    user = User("U1", "test", "Test User", "Testers")
    with patch('hutbot.datetimefmt.is_work_day', return_value=True), \
         patch('hutbot.persistence.flush_replies_cache'), \
         patch('hutbot.scheduling.schedule_reply') as mock_schedule:
        hutbot.state.scheduled_messages.clear()
        await handle_channel_message(app, "token", channel, user, "hello", "1.1")
        assert mock_schedule.call_count == 1  # only the message-trigger config



# ----- Slash command registration -----

def test_normalize_slash_command():
    assert normalize_slash_command("") == "/hutbot"
    assert normalize_slash_command("   ") == "/hutbot"
    assert normalize_slash_command(None) == "/hutbot"
    assert normalize_slash_command("/hutbot_dev") == "/hutbot_dev"
    assert normalize_slash_command("hutbot_dev") == "/hutbot_dev"
    assert normalize_slash_command(" hutbot_dev ") == "/hutbot_dev"


def test_register_app_handlers_uses_configured_slash_command():
    app = MagicMock()
    with patch('hutbot.state.slash_command', '/hutbot_dev'):
        register_app_handlers(app)
    assert app.command.call_args.args[0] == "/hutbot_dev"


# ----- Channel membership (bot added / removed) -----

def _membership_configs():
    return {
        "default": {**DEFAULT_CONFIG.copy(), "enabled": True},
        "nightly": {**DEFAULT_CONFIG.copy(), "enabled": True, "trigger": "schedule"},
        "off-by-hand": {**DEFAULT_CONFIG.copy(), "enabled": False},
    }


@pytest.mark.asyncio
async def test_handle_bot_removed_disables_configs_and_cancels_replies():
    app = AsyncMock()
    channel_id = "C12345"
    hutbot.state.channel_config[channel_id] = _membership_configs()
    hutbot.state.channel_config["C99999"] = {"default": {**DEFAULT_CONFIG.copy(), "enabled": True}}

    task = AsyncMock()
    task.cancel = MagicMock()
    other_task = AsyncMock()
    other_task.cancel = MagicMock()
    hutbot.state.scheduled_messages[(channel_id, "1.1", "default")] = ScheduledReply(task=task, user_id="U1")
    hutbot.state.scheduled_messages[("C99999", "2.2", "default")] = ScheduledReply(task=other_task, user_id="U1")
    hutbot.state._scheduled_replies_cache[(channel_id, "1.1", "default")] = {'channel_id': channel_id}

    with patch('hutbot.persistence.save_configuration') as mock_save, \
         patch('hutbot.persistence.flush_replies_cache') as mock_flush, \
         patch('hutbot.buttons.cancel_channel_pending_buttons') as mock_cancel_buttons:
        await handle_bot_removed_from_channel(app, channel_id)

    mock_cancel_buttons.assert_awaited_once_with(channel_id)

    configs = hutbot.state.channel_config[channel_id]
    assert configs["default"]["enabled"] is False
    assert configs["default"]["disabled_reason"] == DISABLED_REASON_REMOVED
    assert configs["nightly"]["enabled"] is False
    assert configs["nightly"]["disabled_reason"] == DISABLED_REASON_REMOVED
    # A config a user had disabled keeps its (empty) reason.
    assert configs["off-by-hand"]["disabled_reason"] == ""
    # Other channels are untouched.
    assert hutbot.state.channel_config["C99999"]["default"]["enabled"] is True

    task.cancel.assert_called_once()
    other_task.cancel.assert_not_called()
    assert list(hutbot.state.scheduled_messages.keys()) == [("C99999", "2.2", "default")]
    assert hutbot.state._scheduled_replies_cache == {}
    mock_save.assert_called_once()
    mock_flush.assert_called_once()


@pytest.mark.asyncio
async def test_handle_bot_removed_without_configs_saves_nothing():
    app = AsyncMock()
    with patch('hutbot.persistence.save_configuration') as mock_save, \
         patch('hutbot.persistence.flush_replies_cache') as mock_flush:
        await handle_bot_removed_from_channel(app, "C-unknown")
    assert "C-unknown" not in hutbot.state.channel_config
    mock_save.assert_not_called()
    mock_flush.assert_not_called()


@pytest.mark.asyncio
async def test_handle_bot_added_reports_configs_disabled_by_removal():
    app = AsyncMock()
    channel_id = "C12345"
    hutbot.state.channel_config[channel_id] = {
        "default": {**DEFAULT_CONFIG.copy(), "enabled": False, "disabled_reason": DISABLED_REASON_REMOVED},
        "nightly": {**DEFAULT_CONFIG.copy(), "enabled": False, "disabled_reason": DISABLED_REASON_REMOVED},
        "off-by-hand": {**DEFAULT_CONFIG.copy(), "enabled": False},
        "running": {**DEFAULT_CONFIG.copy(), "enabled": True},
    }

    with patch('hutbot.messaging._post_message') as mock_post:
        await handle_bot_added_to_channel(app, channel_id)

    mock_post.assert_called_once()
    text = mock_post.call_args.args[2]
    assert "`default`, `nightly`" in text
    assert "off-by-hand" not in text
    assert f"{hutbot.state.slash_command} [config] enable" in text
    # Nothing is re-enabled automatically.
    assert hutbot.state.channel_config[channel_id]["default"]["enabled"] is False


@pytest.mark.asyncio
async def test_handle_bot_added_stays_silent_without_auto_disabled_configs():
    app = AsyncMock()
    hutbot.state.channel_config["C12345"] = {"off-by-hand": {**DEFAULT_CONFIG.copy(), "enabled": False}}
    with patch('hutbot.messaging._post_message') as mock_post:
        await handle_bot_added_to_channel(app, "C12345")
    mock_post.assert_not_called()


def test_is_bot_membership_event():
    hutbot.state.bot_user_id = "UBOT"
    assert is_bot_membership_event({"user": "UBOT", "channel": "C1"}) is True
    assert is_bot_membership_event({"user": "U1", "channel": "C1"}) is False
    hutbot.state.bot_user_id = None
    assert is_bot_membership_event({"user": "UBOT"}) is False


@pytest.mark.asyncio
async def test_membership_handlers_only_react_to_the_bot():
    app = MagicMock()
    handlers = {}

    def event_decorator(name):
        def register(fn):
            handlers[name] = fn
            return fn
        return register

    app.event = MagicMock(side_effect=event_decorator)
    register_app_handlers(app)
    assert "member_left_channel" in handlers and "member_joined_channel" in handlers

    hutbot.state.bot_user_id = "UBOT"
    with patch('hutbot.routing.handle_bot_removed_from_channel') as mock_removed, \
         patch('hutbot.routing.handle_bot_added_to_channel') as mock_added:
        await handlers["member_left_channel"]({"event": {"user": "U1", "channel": "C1"}}, None)
        await handlers["member_joined_channel"]({"event": {"user": "U1", "channel": "C1"}}, None)
        mock_removed.assert_not_called()
        mock_added.assert_not_called()

        await handlers["member_left_channel"]({"event": {"user": "UBOT", "channel": "C1"}}, None)
        await handlers["member_joined_channel"]({"event": {"user": "UBOT", "channel": "C2"}}, None)
        mock_removed.assert_called_once_with(app, "C1")
        mock_added.assert_called_once_with(app, "C2")


@pytest.mark.asyncio
async def test_route_message_treats_an_app_bot_user_as_a_bot():
    import hutbot
    app = AsyncMock()
    channel = Channel(id="C12345", name="davetest", configs={"default": DEFAULT_CONFIG.copy()})
    # An app posting through its bot user sends `user` *and* `bot_id`, and users.info
    # reports is_bot — none of which used to count as "a bot wrote this".
    bot_user = User(id="U0A9NGY2U5B", name="mping", real_name="mPing", team=TEAM_UNKNOWN, is_bot=True)
    event = {
        "type": "message", "text": "mr-merged m3-helmfile", "ts": "1786709950.634419",
        "user": bot_user.id, "bot_id": "B0A9NGY2U5B", "app_id": "A0A9",
        "channel": channel.id, "channel_type": "channel",
    }

    with patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=bot_user)), \
         patch('hutbot.datetimefmt.is_work_day', return_value=True), \
         patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()), \
         patch('hutbot.scheduling.schedule_reply') as mock_schedule_reply:
        hutbot.state.scheduled_messages.clear()
        hutbot.state._scheduled_replies_cache.clear()
        await route_message(app, "token", event)

    mock_schedule_reply.assert_not_called()

    # With include_bots the same message is handled.
    channel.configs["default"]["include_bots"] = True
    with patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=bot_user)), \
         patch('hutbot.datetimefmt.is_work_day', return_value=True), \
         patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()), \
         patch('hutbot.scheduling.schedule_reply') as mock_schedule_reply:
        await route_message(app, "token", event)

    mock_schedule_reply.assert_called_once()
    for scheduled in list(hutbot.state.scheduled_messages.values()):
        scheduled.task.cancel()


@pytest.mark.asyncio
async def test_route_message_treats_a_bot_user_without_bot_id_as_a_bot():
    import hutbot
    app = AsyncMock()
    channel = Channel(id="C12345", name="davetest", configs={"default": DEFAULT_CONFIG.copy()})
    bot_user = User(id="UBOTUSER", name="somebot", real_name="Some Bot", team=TEAM_UNKNOWN, is_bot=True)
    event = {"type": "message", "text": "beep", "ts": "1234.1", "user": bot_user.id,
             "channel": channel.id, "channel_type": "channel"}

    with patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=bot_user)), \
         patch('hutbot.datetimefmt.is_work_day', return_value=True), \
         patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()), \
         patch('hutbot.scheduling.schedule_reply') as mock_schedule_reply:
        hutbot.state.scheduled_messages.clear()
        await route_message(app, "token", event)

    mock_schedule_reply.assert_not_called()


def test_build_user_marks_bots_and_skips_employee_mapping():
    import hutbot
    employees = {"d.grieser": {"fullname": "David Grieser", "group": "Platform"}}

    with patch('hutbot.slackcache.log_warning') as mock_log_warning:
        _, bot = hutbot.slackcache.build_user(
            {"id": "U0A9NGY2U5B", "name": "mping", "is_bot": True, "real_name": "mPing"}, employees, {})
        _, slackbot = hutbot.slackcache.build_user({"id": "USLACKBOT", "name": "slackbot"}, employees, {})
        _, human = hutbot.slackcache.build_user(
            {"id": "U1", "name": "nobody", "real_name": "No Body"}, employees, {})

    assert bot.is_bot is True and bot.team == TEAM_UNKNOWN
    assert slackbot.is_bot is True
    assert human.is_bot is False
    # Only the human is worth an employee-mapping warning.
    assert mock_log_warning.call_count == 1
    assert "@nobody" in mock_log_warning.call_args.args[0]
