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
