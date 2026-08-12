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
