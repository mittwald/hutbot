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

        calls = [
            call(app, "token", channel, configs["config1"], "config1", user, "This is an alarm and a report", "1234.1"),
            call(app, "token", channel, configs["config2"], "config2", user, "This is an alarm and a report", "1234.1")
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

    mock_schedule_reply.assert_called_once_with(app, "token", channel, configs["bots"], "bots", bot_user, "Alarm", "1234.1")



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

    mock_schedule_reply.assert_called_once_with(app, "token", channel, configs["alerts"], "alerts", bot_user, extracted_text, "1234.1")
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
async def test_set_forward_channel_with_bare_id():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as mock_send_message:
        await set_forward_channel(app, channel, "default", "CFWDCHAN", user)

    assert channel.configs["default"]["forward_channel"] == "CFWDCHAN"
    mock_send_message.assert_called_with(app, channel, user, "*Forward channel* set to <#CFWDCHAN> in configuration `default`.", "")



@pytest.mark.asyncio
async def test_set_forward_channel_rejects_invalid_ref():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await set_forward_channel(app, channel, "default", "not-a-channel", user, thread_ts)

    assert channel.configs["default"].get("forward_channel") == ""
    app.client.chat_postMessage.assert_not_awaited()
    mock_send_message.assert_called_with(app, channel, user, "Invalid channel: `not-a-channel`. Use a #channel mention.", thread_ts)



@pytest.mark.asyncio
async def test_set_forward_channel_reports_api_error():
    app = AsyncMock()
    app.client.chat_postMessage.side_effect = SlackApiError("not_in_channel", {"error": "not_in_channel"})
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await set_forward_channel(app, channel, "default", "<#CFWDCHAN|forward-channel>", user, thread_ts)

    assert channel.configs["default"].get("forward_channel") == ""
    mock_send_message.assert_called_with(app, channel, user, "Cannot post to <#CFWDCHAN>: `not_in_channel`.", thread_ts)



@pytest.mark.asyncio
async def test_clear_forward_channel():
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(), "forward_channel": "CFWDCHAN"}
    channel = Channel(id="C12345", name="general", configs={"default": config})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as mock_send_message:
        await clear_forward_channel(app, channel, "default", user, thread_ts)

    assert "forward_channel" not in channel.configs["default"]
    mock_send_message.assert_called_with(app, channel, user, "*Forward channel* cleared in configuration `default`.", thread_ts)



@pytest.mark.asyncio
async def test_process_command_set_forward_channel():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message'):
        await process_command(app, "set forward-channel <#CFWDCHAN|logs>", channel, user, thread_ts)

    assert channel.configs["default"]["forward_channel"] == "CFWDCHAN"



@pytest.mark.asyncio
async def test_process_command_clear_forward_channel():
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(), "forward_channel": "CFWDCHAN"}
    channel = Channel(id="C12345", name="general", configs={"default": config})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message'):
        await process_command(app, "clear forward-channel", channel, user, thread_ts)

    assert "forward_channel" not in channel.configs["default"]



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
