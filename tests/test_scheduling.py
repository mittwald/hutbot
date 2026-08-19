import copy

from tests._common import *  # noqa: F401,F403



@pytest.mark.asyncio
async def test_schedule_reply_cleans_up_scheduled_message_after_send():
    app = AsyncMock()
    app.client.chat_getPermalink.return_value = {"permalink": "https://slack.test/message"}
    app.client.chat_postMessage.return_value = {"ts": "1234.1"}
    channel = Channel(id="C12345", name="general", configs={})
    user = User("U12345", "test", "Test User", "Testers")
    config = DEFAULT_CONFIG.copy()
    config["wait_time"] = 0
    ts = "1234.1"
    key = (channel.id, ts, "alerts")

    hutbot.state.scheduled_messages.clear()
    hutbot.state.scheduled_messages[key] = ScheduledReply(task=AsyncMock(), user_id=user.id)

    with patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()):
        await schedule_reply(app, "token", channel, config, "alerts", user, "Original text", ts)

    app.client.chat_postMessage.assert_awaited_once()
    assert key not in hutbot.state.scheduled_messages



@pytest.mark.asyncio
async def test_schedule_reply_keeps_plain_message_unchanged():
    app = AsyncMock()
    app.client.chat_getPermalink.return_value = {"permalink": "https://slack.test/message"}
    app.client.chat_postMessage.return_value = {"ts": "1234.1"}
    channel = Channel(id="C12345", name="general", configs={})
    user = User("U12345", "test", "Test User", "Testers")
    config = DEFAULT_CONFIG.copy()
    config["wait_time"] = 0
    config["reply_message"] = "Anybody?"

    with patch('hutbot.opsgenie.get_opsgenie_template_variables', new=AsyncMock()) as mock_get_opsgenie_template_variables, \
         patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()):
        await schedule_reply(app, "token", channel, config, "default", user, "Original text", "1234.1")

    mock_get_opsgenie_template_variables.assert_not_awaited()
    app.client.chat_postMessage.assert_awaited_once_with(channel="C12345", text="Anybody?", mrkdwn=True, thread_ts="1234.1")



@pytest.mark.asyncio
async def test_restore_scheduled_replies_skips_unknown_channel():
    import hutbot
    hutbot.state._scheduled_replies_cache.clear()
    hutbot.state._scheduled_replies_cache[('C_GONE', '1000.1', 'default')] = {
        'channel_id': 'C_GONE',
        'ts': '1000.1',
        'config_name': 'default',
        'user_id': 'U1',
        'text': 'msg',
        'send_at': (datetime.datetime.now() + datetime.timedelta(seconds=60)).isoformat(),
    }
    app = AsyncMock()
    hutbot.state.scheduled_messages.clear()

    with patch('hutbot.state.channel_config', {}), patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()):
        await restore_scheduled_replies(app, "token")

    assert len(hutbot.state.scheduled_messages) == 0
    assert hutbot.state._scheduled_replies_cache == {}



@pytest.mark.asyncio
async def test_restore_scheduled_replies_schedules_with_remaining_time():
    import hutbot
    import asyncio
    future = datetime.datetime.now() + datetime.timedelta(seconds=300)
    hutbot.state._scheduled_replies_cache.clear()
    hutbot.state._scheduled_replies_cache[('C123', '1000.1', 'default')] = {
        'channel_id': 'C123',
        'ts': '1000.1',
        'config_name': 'default',
        'user_id': 'U456',
        'text': 'hello',
        'send_at': future.isoformat(),
    }
    config = {**DEFAULT_CONFIG.copy(), 'wait_time': 1800}
    app = AsyncMock()
    app.client.conversations_info.return_value = {'channel': {'name': 'general'}}
    hutbot.state.scheduled_messages.clear()

    captured_override = []

    async def fake_schedule_reply(*args, wait_time_override=None, **kwargs):
        captured_override.append(wait_time_override)

    with patch('hutbot.state.channel_config', {'C123': {'default': config}}), \
         patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=User('U456', 'user', 'User', 'Team'))), \
         patch('hutbot.scheduling.schedule_reply', side_effect=fake_schedule_reply), \
         patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()):
        await restore_scheduled_replies(app, "token")
        await asyncio.gather(*[sr.task for sr in hutbot.state.scheduled_messages.values()])

    assert len(captured_override) == 1
    assert 290 <= captured_override[0] <= 310



@pytest.mark.asyncio
async def test_restore_scheduled_replies_sends_immediately_when_overdue():
    import hutbot
    import asyncio
    past = datetime.datetime.now() - datetime.timedelta(seconds=60)
    hutbot.state._scheduled_replies_cache.clear()
    hutbot.state._scheduled_replies_cache[('C123', '1000.1', 'default')] = {
        'channel_id': 'C123',
        'ts': '1000.1',
        'config_name': 'default',
        'user_id': 'U456',
        'text': 'hello',
        'send_at': past.isoformat(),
    }
    config = {**DEFAULT_CONFIG.copy(), 'wait_time': 1800}
    app = AsyncMock()
    app.client.conversations_info.return_value = {'channel': {'name': 'general'}}
    hutbot.state.scheduled_messages.clear()

    captured_override = []

    async def fake_schedule_reply(*args, wait_time_override=None, **kwargs):
        captured_override.append(wait_time_override)

    with patch('hutbot.state.channel_config', {'C123': {'default': config}}), \
         patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=User('U456', 'user', 'User', 'Team'))), \
         patch('hutbot.scheduling.schedule_reply', side_effect=fake_schedule_reply), \
         patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()):
        await restore_scheduled_replies(app, "token")
        await asyncio.gather(*[sr.task for sr in hutbot.state.scheduled_messages.values()])

    assert captured_override[0] == 0.0



@pytest.mark.asyncio
async def test_schedule_reply_removes_entry_from_cache():
    import hutbot
    app = AsyncMock()
    app.client.chat_getPermalink.return_value = {"permalink": ""}
    app.client.chat_postMessage.return_value = {"ts": "reply-ts"}
    channel = Channel(id="C12345", name="general", configs={})
    user = User("U12345", "test", "Test User", "Testers")
    config = DEFAULT_CONFIG.copy()
    config["wait_time"] = 0
    ts = "9999.1"
    key = (channel.id, ts, "default")

    hutbot.state._scheduled_replies_cache.clear()
    hutbot.state._scheduled_replies_cache[key] = {'channel_id': channel.id, 'ts': ts, 'config_name': 'default', 'user_id': user.id, 'text': 'x', 'send_at': '2026-01-01T00:00:00'}

    with patch('hutbot.messaging.send_message'), patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()):
        await schedule_reply(app, "token", channel, config, "default", user, "x", ts)

    assert key not in hutbot.state._scheduled_replies_cache




# ----- Scheduler -----

@pytest.mark.asyncio
async def test_scheduler_tick_fires_due_schedule_when_condition_met():
    app = AsyncMock()
    sched = DEFAULT_CONFIG.copy()
    sched["trigger"] = TRIGGER_CRON
    sched["cron"] = "* * * * *"
    channel = _mk_channel({"sched": sched})
    hutbot.state._scheduler_last_check = datetime.datetime.now(datetime.timezone.utc)
    with patch.dict('hutbot.state.channel_config', {"C12345": {"sched": sched}}, clear=True), \
         patch('hutbot.scheduling._cron_due', return_value=True), \
         patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.actions.run_action', new=AsyncMock()) as run:
        await hutbot.scheduling.scheduler_tick(app, "token")
    assert run.await_count == 1
    assert run.await_args.args[4] == "sched"



@pytest.mark.asyncio
async def test_scheduler_tick_skips_when_condition_not_met():
    """`run_action` owns the gate, so this drives it for real instead of patching it out."""
    app = AsyncMock()
    sched = copy.deepcopy(DEFAULT_CONFIG)
    sched["trigger"] = TRIGGER_CRON
    sched["cron"] = "* * * * *"
    # A cron run has no message behind it, so `{{message}}` is empty and this cannot hold.
    sched["conditions"] = [{"variable": "message", "operator": "not_empty", "value": "", "case_sensitive": False}]
    channel = _mk_channel({"sched": sched})
    hutbot.state._scheduler_last_check = datetime.datetime.now(datetime.timezone.utc)
    with patch.dict('hutbot.state.channel_config', {"C12345": {"sched": sched}}, clear=True), \
         patch('hutbot.scheduling._cron_due', return_value=True), \
         patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.messaging._post_message', new=AsyncMock()) as post:
        await hutbot.scheduling.scheduler_tick(app, "token")
    post.assert_not_awaited()



@pytest.mark.asyncio
async def test_scheduler_tick_ignores_message_trigger():
    app = AsyncMock()
    msg = DEFAULT_CONFIG.copy()  # trigger defaults to "message"
    hutbot.state._scheduler_last_check = datetime.datetime.now(datetime.timezone.utc)
    with patch.dict('hutbot.state.channel_config', {"C12345": {"default": msg}}, clear=True), \
         patch('hutbot.scheduling._cron_due', return_value=True), \
         patch('hutbot.actions.run_action', new=AsyncMock()) as run:
        await hutbot.scheduling.scheduler_tick(app, "token")
    assert run.await_count == 0



# ----- Message-triggered rules honor actions/buttons -----

@pytest.mark.asyncio
async def test_schedule_reply_routes_to_action_for_non_reply_action():
    app = AsyncMock()
    cfg = DEFAULT_CONFIG.copy()
    cfg["action"] = hutbot.constants.ACTION_DM_USER
    cfg["action_target"] = "<@U1>"
    cfg["reply_message"] = "hi"
    channel = _mk_channel({"src": cfg})
    user = User("U2", "x", "X", "T")
    with patch('hutbot.slackcache.get_message_permalink', new=AsyncMock(return_value='')), \
         patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()), \
         patch('hutbot.actions.run_action', new=AsyncMock(return_value={"channel": "C", "ts": "1", "text": "hi"})) as run:
        await hutbot.scheduling.schedule_reply(app, "tok", channel, cfg, "src", user, "orig", "1.1", wait_time_override=0)
    assert run.await_count == 1
    assert run.await_args.args[4] == "src"
    assert run.await_args.kwargs["context"]["thread_ts"] == "1.1"



@pytest.mark.asyncio
async def test_schedule_reply_always_routes_through_run_action():
    # Even a plain default config (action=reply, no buttons) now uses the unified engine.
    app = AsyncMock()
    cfg = DEFAULT_CONFIG.copy()
    cfg["reply_message"] = "hi"
    channel = _mk_channel({"src": cfg})
    user = User("U2", "x", "X", "T")
    with patch('hutbot.slackcache.get_message_permalink', new=AsyncMock(return_value='')), \
         patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()), \
         patch('hutbot.messaging.send_message', new=AsyncMock()) as send, \
         patch('hutbot.actions.run_action', new=AsyncMock(return_value={"channel": "C", "ts": "1", "text": "hi"})) as run:
        await hutbot.scheduling.schedule_reply(app, "tok", channel, cfg, "src", user, "orig", "1.1", wait_time_override=0)
    assert run.await_count == 1
    assert send.await_count == 0


@pytest.mark.asyncio
async def test_restore_logs_the_original_wait_time_not_the_current_one():
    import hutbot
    app = AsyncMock()
    channel = Channel(id="C1", name="davetest", configs={"default": {**DEFAULT_CONFIG.copy(), "wait_time": 60}})
    user = User("U1", "d.grieser", "Dave", "T")
    hutbot.state.channel_config[channel.id] = channel.configs
    future = datetime.datetime.now() + datetime.timedelta(seconds=223)
    hutbot.state._scheduled_replies_cache[(channel.id, "M1", "default")] = {
        'channel_id': channel.id, 'ts': "M1", 'config_name': "default",
        'user_id': user.id, 'text': "x", 'send_at': future.isoformat(), 'wait_time': 1800,
    }

    logged = []
    with patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=user)), \
         patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()), \
         patch('hutbot.scheduling.log', side_effect=lambda *a: logged.append(" ".join(str(x) for x in a))):
        await hutbot.scheduling.restore_scheduled_replies(app, "tok")
        await asyncio.sleep(0)
        for entry in list(hutbot.state.scheduled_messages.values()):
            entry.task.cancel()

    rescheduled = next(line for line in logged if line.startswith("Rescheduling"))
    assert "223s remaining of the original 30 mins" in rescheduled
    assert "config now 1 min" in rescheduled
    assert not any("wait time 1 min," in line for line in logged)
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_restore_omits_the_original_wait_time_for_legacy_cache_entries():
    import hutbot
    app = AsyncMock()
    channel = Channel(id="C1", name="davetest", configs={"default": {**DEFAULT_CONFIG.copy(), "wait_time": 60}})
    user = User("U1", "d.grieser", "Dave", "T")
    hutbot.state.channel_config[channel.id] = channel.configs
    future = datetime.datetime.now() + datetime.timedelta(seconds=90)
    hutbot.state._scheduled_replies_cache[(channel.id, "M2", "default")] = {
        'channel_id': channel.id, 'ts': "M2", 'config_name': "default",
        'user_id': user.id, 'text': "x", 'send_at': future.isoformat(),
    }

    logged = []
    with patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=user)), \
         patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()), \
         patch('hutbot.scheduling.log', side_effect=lambda *a: logged.append(" ".join(str(x) for x in a))):
        await hutbot.scheduling.restore_scheduled_replies(app, "tok")
        await asyncio.sleep(0)
        for entry in list(hutbot.state.scheduled_messages.values()):
            entry.task.cancel()

    rescheduled = next(line for line in logged if line.startswith("Rescheduling"))
    assert "90s remaining," in rescheduled
    assert "original" not in rescheduled
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_handle_channel_message_caches_the_wait_time_it_scheduled_with():
    import hutbot
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(), "wait_time": 1800}
    channel = Channel(id="C1", name="davetest", configs={"default": config})
    user = User("U1", "d.grieser", "Dave", "T")

    with patch('hutbot.datetimefmt.is_work_day', return_value=True), \
         patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()), \
         patch('hutbot.scheduling.schedule_reply', new=AsyncMock()):
        await hutbot.routing.handle_channel_message(app, "tok", channel, user, "hello", "M3")

    entry = hutbot.state._scheduled_replies_cache[(channel.id, "M3", "default")]
    assert entry['wait_time'] == 1800
    for scheduled in list(hutbot.state.scheduled_messages.values()):
        scheduled.task.cancel()
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_cron_fires_in_the_configured_datetime_timezone():
    import hutbot
    # 09:00 in Tokyo is 00:00 UTC; a daily 9am cron is due at that instant for a
    # Tokyo config and not for a Berlin one (where 9am is still 7 hours away).
    last = datetime.datetime(2026, 4, 26, 23, 30, tzinfo=datetime.timezone.utc)
    now = datetime.datetime(2026, 4, 27, 0, 5, tzinfo=datetime.timezone.utc)

    tokyo = {**DEFAULT_CONFIG.copy(), "datetime_timezone": "Asia/Tokyo"}
    berlin = {**DEFAULT_CONFIG.copy(), "datetime_timezone": "Europe/Berlin"}

    assert hutbot.scheduling._cron_due("0 9 * * *", tokyo, last, now) is True
    assert hutbot.scheduling._cron_due("0 9 * * *", berlin, last, now) is False


@pytest.mark.asyncio
async def test_cron_falls_back_to_server_local_time():
    import hutbot
    last = datetime.datetime(2026, 4, 26, 23, 30, tzinfo=datetime.timezone.utc)
    now = datetime.datetime(2026, 4, 27, 0, 5, tzinfo=datetime.timezone.utc)
    config = DEFAULT_CONFIG.copy()

    with patch('hutbot.datetimefmt.get_local_timezone', return_value=ZoneInfo("Asia/Tokyo")):
        assert hutbot.scheduling._cron_due("0 9 * * *", config, last, now) is True
    with patch('hutbot.datetimefmt.get_local_timezone', return_value=ZoneInfo("Europe/Berlin")):
        assert hutbot.scheduling._cron_due("0 9 * * *", config, last, now) is False
