import pytest
import datetime
from unittest.mock import AsyncMock, patch, call, MagicMock
from bot import (
    replace_ids, Channel, User, Usergroup, get_team_of, process_command,
    clean_slack_text, send_message, route_message, handle_channel_message,
    scheduled_messages, set_work_hours, parse_time, is_work_day, is_work_time,
    DEFAULT_CONFIG, migrate_and_apply_defaults, set_pattern, show_config,
    handle_thread_response, handle_reaction_added, handle_message_deletion,
    ScheduledReply
)
from slack_sdk.errors import SlackApiError
import base64
from bot import get_env_var

def test_get_env_var_decoding_and_passthrough(monkeypatch):
    encoded = base64.b64encode(b"hello world").decode("utf-8")
    monkeypatch.setenv("MY_ENV_VAR", encoded)
    assert get_env_var("MY_ENV_VAR") == "hello world"
    monkeypatch.setenv("MY_ENV_VAR_PLAIN", "plain value")
    assert get_env_var("MY_ENV_VAR_PLAIN") == "plain value"

@pytest.mark.asyncio
async def test_process_command_set_wait_time():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    with patch('bot.save_configuration'), patch('bot.send_message') as mock_send_message:
        await process_command(app, "set wait-time 10", channel, user, thread_ts)
        assert channel.configs["default"]["wait_time"] == 600
        mock_send_message.assert_called_with(app, channel, user, "*Wait time* set to `10` minutes in configuration `default`.", thread_ts)

@pytest.mark.asyncio
async def test_process_command_set_wait_time_custom_config():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    with patch('bot.save_configuration'), patch('bot.send_message') as mock_send_message:
        await process_command(app, "my-config set wait-time 20", channel, user, thread_ts)
        assert channel.configs["my-config"]["wait_time"] == 1200
        mock_send_message.assert_called_with(app, channel, user, "*Wait time* set to `20` minutes in configuration `my-config`.", thread_ts)

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
    assert migrated_config["C123"]["default"]["pattern"] is None

@pytest.mark.asyncio
async def test_process_command_set_pattern():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('bot.save_configuration'), patch('bot.send_message') as mock_send_message:
        await set_pattern(app, channel, "default", '".*alarm.*"', "true", user, "")
        assert channel.configs["default"]["pattern"] == ".*alarm.*"
        assert channel.configs["default"]["pattern_case_sensitive"] is True
        mock_send_message.assert_called_with(app, channel, user, "Pattern set to `.*alarm.*` for configuration `default`. (case-sensitive)", "")

    with patch('bot.send_message') as mock_send_message:
        await set_pattern(app, channel, "default", '"*"', None, user, "")
        mock_send_message.assert_called_with(app, channel, user, "Invalid pattern: `nothing to repeat at position 0`", "")

@pytest.mark.asyncio
async def test_process_command_set_pattern_empty():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('bot.save_configuration'), patch('bot.send_message') as mock_send_message:
        await set_pattern(app, channel, "default", '""', "true", user, "")
        assert channel.configs["default"]["pattern"] == ""
        assert channel.configs["default"]["pattern_case_sensitive"] is True
        mock_send_message.assert_called_with(app, channel, user, "Pattern set to `` for configuration `default`. (case-sensitive)", "")

@pytest.mark.asyncio
async def test_process_command_set_pattern_custom_config():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")
    
    with patch('bot.save_configuration'), patch('bot.send_message') as mock_send_message:
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

    with patch('bot.is_work_day', return_value=True), \
         patch('bot.schedule_reply') as mock_schedule_reply:

        scheduled_messages.clear()
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
    channel = Channel(id="C123", name="test-ch", configs={})
    user1 = User(id="U1", name="user1", real_name="User One", team="A")
    user2 = User(id="U2", name="user2", real_name="User Two", team="B")
    ts = "12345.6789"

    task1 = AsyncMock()
    task1.cancel = MagicMock()
    task2 = AsyncMock()
    task2.cancel = MagicMock()

    scheduled_messages.clear()
    scheduled_messages[(channel.id, ts, "config1")] = ScheduledReply(task=task1, user_id=user1.id)
    scheduled_messages[(channel.id, ts, "config2")] = ScheduledReply(task=task2, user_id=user1.id)

    with patch('bot.get_user_by_id', return_value=user1):
        await handle_thread_response(app, channel, user2, ts)

    task1.cancel.assert_called_once()
    task2.cancel.assert_called_once()
    assert len(scheduled_messages) == 0

@pytest.mark.asyncio
async def test_multi_cancel_reaction_added():
    app = AsyncMock()
    channel_id = "C123"
    user1_id = "U1"
    user2_id = "U2"
    ts = "12345.6789"
    event = {'item': {'channel': channel_id, 'ts': ts}, 'user': user2_id}

    task1 = AsyncMock()
    task1.cancel = MagicMock()
    task2 = AsyncMock()
    task2.cancel = MagicMock()

    scheduled_messages.clear()
    scheduled_messages[(channel_id, ts, "config1")] = ScheduledReply(task=task1, user_id=user1_id)
    scheduled_messages[(channel_id, ts, "config2")] = ScheduledReply(task=task2, user_id=user1_id)

    with patch('bot.get_channel_by_id'), patch('bot.get_user_by_id'):
        await handle_reaction_added(app, event)

    task1.cancel.assert_called_once()
    task2.cancel.assert_called_once()
    assert len(scheduled_messages) == 0

@pytest.mark.asyncio
async def test_show_config():
    app = AsyncMock()
    configs = {
        "alarms": {"pattern": ".*alarm.*", "wait_time": 300, "reply_message": "Alarm message"},
        "default": {"wait_time": 600, "reply_message": "Default message"}
    }
    for name, cfg in configs.items():
        for k, v in DEFAULT_CONFIG.items():
            if k not in cfg:
                cfg[k] = v
    channel = Channel(id="C123", name="general", configs=configs)
    user = User(id="U123", name="test", real_name="Test User", team="A")

    with patch('bot.send_message') as mock_send_message:
        await show_config(app, channel, user, "")

        sent_message = mock_send_message.call_args.args[3]
        assert "*Configuration*: `default`" in sent_message
        assert "*Wait time*: `10` minutes" in sent_message
        assert "Default message" in sent_message
        assert "*Configuration*: `alarms`" in sent_message
        assert "*Wait time*: `5` minutes" in sent_message
        assert "*Pattern*: `.*alarm.*` (case-insensitive)" in sent_message
        assert "Alarm message" in sent_message

@pytest.mark.asyncio
async def test_process_command_delete_config():
    app = AsyncMock()
    configs = {
        "default": DEFAULT_CONFIG.copy(),
        "todelete": DEFAULT_CONFIG.copy()
    }
    channel = Channel(id="C12345", name="general", configs=configs)
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    with patch('bot.save_configuration'), patch('bot.send_message') as mock_send_message:
        # Test deleting a config
        await process_command(app, "delete config todelete", channel, user, thread_ts)
        assert "todelete" not in channel.configs
        mock_send_message.assert_called_with(app, channel, user, "Configuration `todelete` has been deleted.", thread_ts)

        # Test deleting default config
        await process_command(app, "delete config default", channel, user, thread_ts)
        assert "default" in channel.configs
        mock_send_message.assert_called_with(app, channel, user, "The `default` configuration cannot be deleted.", thread_ts)

        # Test deleting non-existent config
        await process_command(app, "delete config non-existent", channel, user, thread_ts)
        mock_send_message.assert_called_with(app, channel, user, "Configuration `non-existent` not found.", thread_ts)
