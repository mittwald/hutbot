from tests._common import *  # noqa: F401,F403



@pytest.mark.asyncio
async def test_migrate_and_apply_defaults():
    app = AsyncMock()
    app.client.conversations_info.return_value = {"channel": {"id": "C123", "name": "general"}}

    old_config = {
        "C123": {
            "wait_time": 60,
            "reply_message": "Old message"
        }
    }

    migrated_config = await migrate_and_apply_defaults(app, old_config)

    assert "default" in migrated_config["C123"]
    assert migrated_config["C123"]["default"]["wait_time"] == 60
    assert migrated_config["C123"]["default"]["reply_message"] == "Old message"
    assert migrated_config["C123"]["default"]["opsgenie"] is False
    assert migrated_config["C123"]["default"]["opsgenie_schedule_name"] == ""
    assert migrated_config["C123"]["default"]["opsgenie_priority"] == "P4"
    assert migrated_config["C123"]["default"]["pattern"] is None


@pytest.mark.asyncio
async def test_migrate_preserves_configs_named_after_new_default_fields():
    app = AsyncMock()
    config = {
        "C123": {
            "trigger": {"wait_time": 60},
            "action": {"reply_message": "Action config"},
            "buttons": {"enabled": False},
        }
    }

    migrated_config = await migrate_and_apply_defaults(app, config)

    assert set(migrated_config["C123"]) == {"trigger", "action", "buttons"}
    assert migrated_config["C123"]["trigger"]["wait_time"] == 60
    assert migrated_config["C123"]["action"]["reply_message"] == "Action config"
    assert migrated_config["C123"]["buttons"]["enabled"] is False
    assert all("trigger" in value for value in migrated_config["C123"].values())



@pytest.mark.asyncio
async def test_load_and_flush_replies_cache_roundtrip():
    import hutbot
    entry = {
        'channel_id': 'C123',
        'ts': '1000.1',
        'config_name': 'default',
        'user_id': 'U456',
        'text': 'hello',
        'send_at': '2026-04-23T13:00:00',
    }
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump([entry], f)
        tmp_path = f.name

    try:
        with patch('hutbot.constants.SCHEDULED_REPLIES_CACHE_FILE', tmp_path):
            hutbot.state._scheduled_replies_cache.clear()
            await load_replies_cache()
            assert ('C123', '1000.1', 'default') in hutbot.state._scheduled_replies_cache

            hutbot.state._scheduled_replies_cache[('C123', '1000.1', 'default')]['text'] = 'updated'
            await flush_replies_cache()

            with open(tmp_path) as f:
                data = json.load(f)
            assert data[0]['text'] == 'updated'
    finally:
        os.unlink(tmp_path)
        hutbot.state._scheduled_replies_cache.clear()



@pytest.mark.asyncio
async def test_load_replies_cache_handles_missing_file():
    import hutbot
    with patch('hutbot.constants.SCHEDULED_REPLIES_CACHE_FILE', '/nonexistent/path/to/cache.json'):
        hutbot.state._scheduled_replies_cache.clear()
        await load_replies_cache()
        assert hutbot.state._scheduled_replies_cache == {}


@pytest.mark.asyncio
async def test_migration_drops_the_legacy_forward_channel():
    app = AsyncMock()
    config = {
        "C123": {
            "default": {**DEFAULT_CONFIG.copy(), "forward_channel": "CFWDCHAN"},
            "clean": DEFAULT_CONFIG.copy(),
        }
    }

    with patch('hutbot.persistence.log_warning') as mock_log_warning:
        migrated = await migrate_and_apply_defaults(app, config)

    assert "forward_channel" not in migrated["C123"]["default"]
    assert "forward_channel" not in migrated["C123"]["clean"]
    warning = mock_log_warning.call_args.args[0]
    assert "Dropping the forward channel CFWDCHAN of config 'default' in channel C123" in warning
    assert "set action post-channel <#CFWDCHAN>" in warning
    assert "{{message_link}}" in warning
    # Only the config that had one is reported.
    assert mock_log_warning.call_count == 1


@pytest.mark.asyncio
async def test_migration_moves_a_schedule_timezone_into_the_datetime_timezone():
    app = AsyncMock()
    config = {
        "C123": {
            "own": {**DEFAULT_CONFIG.copy(), "schedule_timezone": "Asia/Tokyo"},
            "both": {**DEFAULT_CONFIG.copy(), "schedule_timezone": "Asia/Tokyo", "datetime_timezone": "Europe/Berlin"},
            "same": {**DEFAULT_CONFIG.copy(), "schedule_timezone": "Europe/Berlin", "datetime_timezone": "Europe/Berlin"},
        }
    }

    with patch('hutbot.persistence.log_warning') as mock_log_warning:
        migrated = await migrate_and_apply_defaults(app, config)

    assert all("schedule_timezone" not in cfg for cfg in migrated["C123"].values())
    # No date/time timezone of its own: the cron keeps its wall-clock time.
    assert migrated["C123"]["own"]["datetime_timezone"] == "Asia/Tokyo"
    # Both set: the date/time one wins and the shift is reported.
    assert migrated["C123"]["both"]["datetime_timezone"] == "Europe/Berlin"
    warnings = [call.args[0] for call in mock_log_warning.call_args_list]
    assert any("moved the schedule timezone Asia/Tokyo" in w for w in warnings)
    assert any("dropping the schedule timezone Asia/Tokyo; its cron now fires in Europe/Berlin" in w for w in warnings)
    # Identical values are not worth a warning.
    assert len(warnings) == 2


@pytest.mark.asyncio
async def test_migration_normalizes_a_hand_edited_builtin_calendar_name():
    app = AsyncMock()
    config = {"C123": {"cal": {**DEFAULT_CONFIG.copy(), "calendar_builtin": "  Rota "}}}

    migrated = await migrate_and_apply_defaults(app, config)

    assert migrated["C123"]["cal"]["calendar_builtin"] == "rota"


@pytest.mark.asyncio
async def test_migration_backfills_the_builtin_calendar_key():
    app = AsyncMock()
    stale = {key: value for key, value in DEFAULT_CONFIG.items() if key != "calendar_builtin"}
    config = {"C123": {"cal": stale}}

    migrated = await migrate_and_apply_defaults(app, config)

    assert migrated["C123"]["cal"]["calendar_builtin"] == ""


@pytest.mark.asyncio
async def test_migration_warns_when_a_config_names_a_builtin_calendar_and_a_url():
    """Only a hand-edited file gets here; both values are kept, and the built-in wins."""
    app = AsyncMock()
    url = "https://cal.example.com/SECRETTOKEN/rota.ics"
    config = {"C123": {"cal": {**DEFAULT_CONFIG.copy(), "calendar_builtin": "rota", "calendar_url": url}}}

    with patch('hutbot.persistence.log_warning') as mock_log_warning:
        migrated = await migrate_and_apply_defaults(app, config)

    assert migrated["C123"]["cal"]["calendar_builtin"] == "rota"
    assert migrated["C123"]["cal"]["calendar_url"] == url
    warning = mock_log_warning.call_args.args[0]
    assert "names both the built-in calendar 'rota'" in warning and "the built-in wins" in warning
    assert "cal.example.com/…" in warning and "SECRETTOKEN" not in warning


@pytest.mark.asyncio
async def test_saving_skips_a_conversation_with_no_rules():
    """`slackcache.get_channel_by_id` adds an empty entry for any conversation the bot sees a
    message in — every DM and group DM among them. Persisting those grew the file by a key per
    conversation forever, and put DMs in both UIs' channel pickers."""
    hutbot.state.channel_config = {
        "C_RULES": {"default": {"wait_time": 600}},
        "C_SEEN": {},
        "D_DM": {},
    }
    with patch('fileutil.write_json_file', new=AsyncMock(return_value=True)) as written:
        await hutbot.persistence.save_configuration()
    assert written.await_args.args[1] == {"C_RULES": {"default": {"wait_time": 600}}}


@pytest.mark.asyncio
async def test_saving_a_disabled_rule_still_writes_its_channel():
    # Removing the bot from a channel disables that channel's rules and keeps them, so the
    # channel still carries information and has to survive a save.
    hutbot.state.channel_config = {
        "C1": {"default": {"enabled": False, "disabled_reason": DISABLED_REASON_REMOVED}}}
    with patch('fileutil.write_json_file', new=AsyncMock(return_value=True)) as written:
        await hutbot.persistence.save_configuration()
    assert "C1" in written.await_args.args[1]
