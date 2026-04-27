import pytest
import datetime
from unittest.mock import AsyncMock, patch, call, MagicMock
import json
import tempfile
import os
from bot import (
    replace_ids, Channel, User, Usergroup, get_team_of, process_command,
    clean_slack_text, send_message, route_message, handle_channel_message,
    scheduled_messages, set_work_hours, parse_time, is_work_day, is_work_time,
    DEFAULT_CONFIG, migrate_and_apply_defaults, set_pattern, show_config,
    handle_thread_response, handle_reaction_added, handle_message_deletion,
    ScheduledReply, set_reply_message, schedule_reply,
    load_replies_cache, flush_replies_cache, restore_scheduled_replies,
    extract_message_text, _scheduled_replies_cache,
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

def test_extract_message_text_prefers_top_level_text():
    event = {
        "text": "Top-level text",
        "attachments": [{"text": "Attachment text"}],
    }

    assert extract_message_text(event) == "Top-level text"

def test_extract_message_text_extracts_attachment_text():
    event = {
        "text": "",
        "attachments": [{
            "text": "Alerts: \n       - 1 removeQueueItemForAbortedOrder temporal executions needs operating."
        }],
    }

    assert extract_message_text(event) == "Alerts: \n       - 1 removeQueueItemForAbortedOrder temporal executions needs operating."

def test_extract_message_text_includes_attachment_title_and_text():
    event = {
        "text": "",
        "attachments": [{
            "title": "[FIRING:1] FailedTemporalExecutions",
            "text": "Alerts: temporal executions need operating.",
            "fallback": "Noisy fallback",
        }],
    }

    assert extract_message_text(event) == "[FIRING:1] FailedTemporalExecutions\nAlerts: temporal executions need operating."

def test_extract_message_text_uses_fallback_only_without_cleaner_attachment_text():
    event = {
        "text": "",
        "attachments": [{
            "fallback": "[FIRING:1] FailedTemporalExecutions noisy fallback",
        }],
    }

    assert extract_message_text(event) == "[FIRING:1] FailedTemporalExecutions noisy fallback"

def test_extract_message_text_handles_missing_attachments():
    assert extract_message_text({"text": ""}) == ""

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
    assert migrated_config["C123"]["default"]["opsgenie_schedule_name"] == ""
    assert migrated_config["C123"]["default"]["pattern"] is None

@pytest.mark.asyncio
async def test_process_command_set_opsgenie_schedule():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    with patch('bot.save_configuration'), patch('bot.send_message') as mock_send_message:
        await process_command(app, "set opsgenie-schedule Team Primary", channel, user, thread_ts)
        assert channel.configs["default"]["opsgenie_schedule_name"] == "Team Primary"
        mock_send_message.assert_called_with(app, channel, user, "*OpsGenie schedule* set to `Team Primary` in configuration `default`.", thread_ts)

@pytest.mark.asyncio
async def test_process_command_set_datetime_format_with_quotes_timezone_and_locale():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    with patch('bot.save_configuration'), patch('bot.send_message') as mock_send_message:
        await process_command(app, "set datetime-format \"%a, %d %b %Y\" \"%H:%M\" Europe/Berlin de-DE", channel, user, thread_ts)

    assert channel.configs["default"]["date_format"] == "%a, %d %b %Y"
    assert channel.configs["default"]["time_format"] == "%H:%M"
    assert channel.configs["default"]["datetime_timezone"] == "Europe/Berlin"
    assert channel.configs["default"]["datetime_locale"] == "de_DE"
    mock_send_message.assert_called_with(
        app,
        channel,
        user,
        "*Date/time format* set to date `%a, %d %b %Y` and time `%H:%M`, timezone `Europe/Berlin`, locale `de_DE` in configuration `default`.",
        thread_ts
    )

@pytest.mark.asyncio
async def test_process_command_set_datefmt_alias_rejects_invalid_timezone():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    with patch('bot.save_configuration') as mock_save, patch('bot.send_message') as mock_send_message:
        await process_command(app, "set datefmt %Y %H:%M Mars/Base de-DE", channel, user, thread_ts)

    mock_save.assert_not_called()
    sent_message = mock_send_message.call_args.args[3]
    assert "Invalid *date/time format*" in sent_message
    assert "unknown timezone `Mars/Base`" in sent_message

@pytest.mark.asyncio
async def test_process_command_list_opsgenie_schedules():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    response = AsyncMock()
    response.status = 200
    response.json = AsyncMock(return_value={
        "data": [
            {"name": "Zulu"},
            {"name": "alpha"},
        ]
    })
    response_context = AsyncMock()
    response_context.__aenter__.return_value = response
    response_context.__aexit__.return_value = None

    session = MagicMock()
    session.get.return_value = response_context
    session_context = AsyncMock()
    session_context.__aenter__.return_value = session
    session_context.__aexit__.return_value = None

    with patch('bot.get_env_var', return_value="token"), \
         patch('bot.aiohttp.ClientSession', return_value=session_context), \
         patch('bot.send_message') as mock_send_message:
        await process_command(app, "list opsgenie-schedules", channel, user, thread_ts)

        mock_send_message.assert_called_with(
            app,
            channel,
            user,
            "*OpsGenie schedules*:\n`alpha`\n`Zulu`",
            thread_ts
        )

@pytest.mark.asyncio
async def test_process_command_list_opsgenie_schedules_without_token():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    with patch('bot.get_env_var', return_value=""), patch('bot.send_message') as mock_send_message:
        await process_command(app, "list opsgenie-schedules", channel, user, thread_ts)

        mock_send_message.assert_called_with(
            app,
            channel,
            user,
            "OpsGenie is not configured. Missing `OPSGENIE_TOKEN`.",
            thread_ts
        )

@pytest.mark.asyncio
async def test_process_command_on_call_uses_configured_schedule():
    import bot
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    channel.configs["default"]["opsgenie_schedule_name"] = "Team Primary"
    user = User("U12345", "test", "Test User", "Testers")
    on_call_user = User("U999", "oncall", "On Call User", "Ops")
    thread_ts = "1234567890.123456"
    start = "2026-04-26T08:00:00Z"
    end = "2026-04-27T08:00:00Z"

    with patch('bot.resolve_opsgenie_on_call', new=AsyncMock(return_value=("oncall@example.com", on_call_user))) as mock_resolve, \
         patch('bot.resolve_opsgenie_on_call_period', new=AsyncMock(return_value=(start, end))) as mock_period, \
         patch('bot.send_message') as mock_send_message:
        await process_command(app, "on-call", channel, user, thread_ts, opsgenie_token="token")

    mock_resolve.assert_awaited_once_with(app, "token", "Team Primary")
    mock_period.assert_awaited_once_with("token", "Team Primary", "oncall@example.com")
    mock_send_message.assert_called_with(
        app,
        channel,
        user,
        "*Schedule*: `Team Primary`\n"
        "*On-call*: <@U999>\n"
        f"*Start*: `{bot.format_opsgenie_datetime(start)}`\n"
        f"*End*: `{bot.format_opsgenie_datetime(end)}`",
        thread_ts
    )

@pytest.mark.asyncio
async def test_process_command_on_call_uses_explicit_schedule():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    channel.configs["default"]["opsgenie_schedule_name"] = "Configured Schedule"
    user = User("U12345", "test", "Test User", "Testers")
    on_call_user = User("U999", "oncall", "On Call User", "Ops")
    thread_ts = "1234567890.123456"

    with patch('bot.resolve_opsgenie_on_call', new=AsyncMock(return_value=("oncall@example.com", on_call_user))) as mock_resolve, \
         patch('bot.resolve_opsgenie_on_call_period', new=AsyncMock(return_value=("2026-04-26T08:00:00Z", "2026-04-27T08:00:00Z"))) as mock_period, \
         patch('bot.send_message') as mock_send_message:
        await process_command(app, "on-call Team Secondary", channel, user, thread_ts, opsgenie_token="token")

    mock_resolve.assert_awaited_once_with(app, "token", "Team Secondary")
    mock_period.assert_awaited_once_with("token", "Team Secondary", "oncall@example.com")
    sent_message = mock_send_message.call_args.args[3]
    assert "*Schedule*: `Team Secondary`" in sent_message
    assert "*On-call*: <@U999>" in sent_message

@pytest.mark.asyncio
async def test_process_command_on_call_uses_selected_config():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={
        "default": DEFAULT_CONFIG.copy(),
        "alerts": DEFAULT_CONFIG.copy(),
    })
    channel.configs["default"]["opsgenie_schedule_name"] = "Default Schedule"
    channel.configs["alerts"]["opsgenie_schedule_name"] = "Alerts Schedule"
    user = User("U12345", "test", "Test User", "Testers")
    on_call_user = User("U999", "oncall", "On Call User", "Ops")
    thread_ts = "1234567890.123456"

    with patch('bot.resolve_opsgenie_on_call', new=AsyncMock(return_value=("oncall@example.com", on_call_user))) as mock_resolve, \
         patch('bot.resolve_opsgenie_on_call_period', new=AsyncMock(return_value=("2026-04-26T08:00:00Z", "2026-04-27T08:00:00Z"))) as mock_period, \
         patch('bot.send_message') as mock_send_message:
        await process_command(app, "alerts on-call", channel, user, thread_ts, opsgenie_token="token")

    mock_resolve.assert_awaited_once_with(app, "token", "Alerts Schedule")
    mock_period.assert_awaited_once_with("token", "Alerts Schedule", "oncall@example.com")
    sent_message = mock_send_message.call_args.args[3]
    assert "*Schedule*: `Alerts Schedule`" in sent_message
    assert "*On-call*: <@U999>" in sent_message

@pytest.mark.asyncio
async def test_process_command_on_call_falls_back_to_email_when_unmapped():
    import bot
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    channel.configs["default"]["opsgenie_schedule_name"] = "Team Primary"
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"
    start = "2026-04-26T08:00:00Z"
    end = "2026-04-27T08:00:00Z"

    with patch('bot.resolve_opsgenie_on_call', new=AsyncMock(return_value=("oncall@example.com", None))), \
         patch('bot.resolve_opsgenie_on_call_period', new=AsyncMock(return_value=(start, end))), \
         patch('bot.send_message') as mock_send_message:
        await process_command(app, "on-call", channel, user, thread_ts, opsgenie_token="token")

    sent_message = mock_send_message.call_args.args[3]
    assert "*On-call*: oncall@example.com" in sent_message
    assert f"*Start*: `{bot.format_opsgenie_datetime(start)}`" in sent_message
    assert f"*End*: `{bot.format_opsgenie_datetime(end)}`" in sent_message

@pytest.mark.asyncio
async def test_process_command_on_call_uses_upcoming_period_when_no_current_on_call():
    import bot
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    channel.configs["default"]["opsgenie_schedule_name"] = "Cloud Hosting_schedule"
    user = User("U12345", "test", "Test User", "Testers")
    upcoming_user = User("U999", "next", "Next User", "Ops")
    thread_ts = "1234567890.123456"
    start = "2026-04-28T08:00:00Z"
    end = "2026-04-29T08:00:00Z"

    with patch('bot.resolve_opsgenie_on_call', new=AsyncMock(return_value=("", None))) as mock_resolve, \
         patch('bot.resolve_opsgenie_upcoming_on_call_period', new=AsyncMock(return_value=("next@example.com", start, end))) as mock_upcoming, \
         patch('bot.resolve_slack_user_for_opsgenie_recipient', new=AsyncMock(return_value=upcoming_user)) as mock_slack_user, \
         patch('bot.send_message') as mock_send_message:
        await process_command(app, "on-call", channel, user, thread_ts, opsgenie_token="token")

    mock_resolve.assert_awaited_once_with(app, "token", "Cloud Hosting_schedule")
    mock_upcoming.assert_awaited_once_with("token", "Cloud Hosting_schedule")
    mock_slack_user.assert_awaited_once_with(app, "next@example.com")
    mock_send_message.assert_called_with(
        app,
        channel,
        user,
        "*Schedule*: `Cloud Hosting_schedule`\n"
        "*On-call*: <@U999>\n"
        f"*Start*: `{bot.format_opsgenie_datetime(start)}`\n"
        f"*End*: `{bot.format_opsgenie_datetime(end)}`",
        thread_ts
    )

@pytest.mark.asyncio
async def test_process_command_on_call_uses_configured_datetime_defaults():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    channel.configs["default"]["opsgenie_schedule_name"] = "Team Primary"
    channel.configs["default"]["date_format"] = "%d.%m.%Y"
    channel.configs["default"]["time_format"] = "%H:%M"
    channel.configs["default"]["datetime_timezone"] = "Europe/Berlin"
    user = User("U12345", "test", "Test User", "Testers")
    on_call_user = User("U999", "oncall", "On Call User", "Ops")
    thread_ts = "1234567890.123456"

    with patch('bot.resolve_opsgenie_on_call', new=AsyncMock(return_value=("oncall@example.com", on_call_user))), \
         patch('bot.resolve_opsgenie_on_call_period', new=AsyncMock(return_value=("2026-04-26T08:00:00Z", "2026-04-26T16:00:00Z"))), \
         patch('bot.send_message') as mock_send_message:
        await process_command(app, "on-call", channel, user, thread_ts, opsgenie_token="token")

    sent_message = mock_send_message.call_args.args[3]
    assert "*Start*: `26.04.2026 10:00`" in sent_message
    assert "*End*: `26.04.2026 18:00`" in sent_message

@pytest.mark.asyncio
async def test_process_command_on_call_errors_when_no_current_or_upcoming_on_call():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    channel.configs["default"]["opsgenie_schedule_name"] = "Cloud Hosting_schedule"
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    with patch('bot.resolve_opsgenie_on_call', new=AsyncMock(return_value=("", None))), \
         patch('bot.resolve_opsgenie_upcoming_on_call_period', new=AsyncMock(return_value=("", "", ""))), \
         patch('bot.send_message') as mock_send_message:
        await process_command(app, "on-call", channel, user, thread_ts, opsgenie_token="token")

    mock_send_message.assert_called_with(app, channel, user, "Failed to resolve on-call user for OpsGenie schedule `Cloud Hosting_schedule`.", thread_ts)

@pytest.mark.asyncio
async def test_process_command_on_call_without_schedule():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    with patch('bot.resolve_opsgenie_on_call', new=AsyncMock()) as mock_resolve, \
         patch('bot.resolve_opsgenie_on_call_period', new=AsyncMock()) as mock_period, \
         patch('bot.send_message') as mock_send_message:
        await process_command(app, "on-call", channel, user, thread_ts, opsgenie_token="token")

    mock_resolve.assert_not_awaited()
    mock_period.assert_not_awaited()
    mock_send_message.assert_called_with(
        app,
        channel,
        user,
        "No OpsGenie schedule configured. Use `/hutbot [config] set opsgenie-schedule <name>` or `/hutbot [config] on-call <schedule name>`.",
        thread_ts
    )

@pytest.mark.asyncio
async def test_process_command_on_call_without_token():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    channel.configs["default"]["opsgenie_schedule_name"] = "Team Primary"
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    with patch('bot.resolve_opsgenie_on_call', new=AsyncMock()) as mock_resolve, \
         patch('bot.resolve_opsgenie_on_call_period', new=AsyncMock()) as mock_period, \
         patch('bot.send_message') as mock_send_message:
        await process_command(app, "on-call", channel, user, thread_ts)

    mock_resolve.assert_not_awaited()
    mock_period.assert_not_awaited()
    mock_send_message.assert_called_with(app, channel, user, "OpsGenie is not configured. Missing `OPSGENIE_TOKEN`.", thread_ts)

def test_find_opsgenie_on_call_period_prefers_matching_current_period():
    import bot

    data = {
        "finalTimeline": {
            "rotations": [{
                "periods": [
                    {
                        "startDate": "2026-04-26T06:00:00Z",
                        "endDate": "2026-04-26T08:00:00Z",
                        "recipient": {"name": "previous@example.com"},
                    },
                    {
                        "startDate": "2026-04-26T08:00:00Z",
                        "endDate": "2026-04-27T08:00:00Z",
                        "recipient": {"name": "oncall@example.com"},
                    },
                ],
            }],
        },
    }
    now = datetime.datetime(2026, 4, 26, 10, 0, tzinfo=datetime.timezone.utc)

    assert bot.find_opsgenie_on_call_period(data, "oncall@example.com", now) == (
        "2026-04-26T08:00:00Z",
        "2026-04-27T08:00:00Z",
    )

def test_format_opsgenie_datetime_uses_local_timezone():
    import bot

    local_tz = datetime.timezone(datetime.timedelta(hours=2), "CEST")

    assert bot.format_opsgenie_datetime("2026-04-26T08:00:00Z", local_tz) == "Sun, 26 Apr 2026 10:00"

def test_format_datetime_value_supports_python_format_timezone_and_locale():
    import bot

    config = {
        **DEFAULT_CONFIG.copy(),
        "date_format": "%A, %d %B %Y",
        "time_format": "%H:%M",
        "datetime_timezone": "Europe/Berlin",
        "datetime_locale": "de-DE",
    }

    assert bot.format_datetime_value("2026-04-26T08:00:00Z", "datetime", config) == "Sonntag, 26 April 2026 10:00"

def test_format_datetime_value_supports_go_layout_args():
    import bot

    rendered = bot.format_datetime_value(
        "2026-04-26T08:00:00Z",
        "datetime",
        DEFAULT_CONFIG.copy(),
        {"fmt": "02.01.2006 15:04", "tz": "UTC", "lc": "en-us"},
    )

    assert rendered == "26.04.2026 08:00"

def test_find_opsgenie_on_call_period_merges_adjacent_matching_periods():
    import bot

    data = {
        "finalTimeline": {
            "rotations": [{
                "periods": [
                    {
                        "startDate": "2026-04-24T16:00:00Z",
                        "endDate": "2026-04-26T17:19:04.912Z",
                        "recipient": {"name": "oncall@example.com"},
                    },
                    {
                        "startDate": "2026-04-26T17:19:04.912Z",
                        "endDate": "2026-05-14T06:00:00Z",
                        "recipient": {"name": "oncall@example.com"},
                    },
                    {
                        "startDate": "2026-05-14T06:00:00Z",
                        "endDate": "2026-05-31T22:00:00Z",
                        "recipient": {"name": "next@example.com"},
                    },
                ],
            }],
        },
    }
    now = datetime.datetime(2026, 4, 26, 16, 35, tzinfo=datetime.timezone.utc)

    assert bot.find_opsgenie_on_call_period(data, "oncall@example.com", now) == (
        "2026-04-24T16:00:00Z",
        "2026-05-14T06:00:00Z",
    )

def test_find_opsgenie_upcoming_on_call_period_selects_next_period():
    import bot

    data = {
        "finalTimeline": {
            "rotations": [{
                "periods": [
                    {
                        "startDate": "2026-04-26T08:00:00Z",
                        "endDate": "2026-04-26T10:00:00Z",
                        "recipient": {"name": "past@example.com"},
                    },
                    {
                        "startDate": "2026-04-27T08:00:00Z",
                        "endDate": "2026-04-27T12:00:00Z",
                        "recipient": {"name": "next@example.com"},
                    },
                    {
                        "startDate": "2026-04-27T12:00:00Z",
                        "endDate": "2026-04-27T18:00:00Z",
                        "recipient": {"name": "next@example.com"},
                    },
                ],
            }],
        },
    }
    now = datetime.datetime(2026, 4, 26, 12, 0, tzinfo=datetime.timezone.utc)

    assert bot.find_opsgenie_upcoming_on_call_period(data, now) == (
        "next@example.com",
        "2026-04-27T08:00:00Z",
        "2026-04-27T18:00:00Z",
    )

def test_find_opsgenie_upcoming_on_call_period_skips_current_period():
    import bot

    data = {
        "finalTimeline": {
            "rotations": [{
                "periods": [
                    {
                        "startDate": "2026-04-26T08:00:00Z",
                        "endDate": "2026-04-26T12:00:00Z",
                        "recipient": {"name": "current@example.com"},
                    },
                    {
                        "startDate": "2026-04-26T12:00:00Z",
                        "endDate": "2026-04-26T18:00:00Z",
                        "recipient": {"name": "current@example.com"},
                    },
                    {
                        "startDate": "2026-04-26T18:00:00Z",
                        "endDate": "2026-04-26T20:00:00Z",
                        "recipient": {"name": "next@example.com"},
                    },
                ],
            }],
        },
    }
    now = datetime.datetime(2026, 4, 26, 10, 0, tzinfo=datetime.timezone.utc)

    assert bot.find_opsgenie_upcoming_on_call_period(data, now) == (
        "next@example.com",
        "2026-04-26T18:00:00Z",
        "2026-04-26T20:00:00Z",
    )

@pytest.mark.asyncio
async def test_resolve_opsgenie_on_call_period_requests_past_anchored_wide_timeline():
    import bot

    response = AsyncMock()
    response.status = 200
    response.json = AsyncMock(return_value={"data": {}})
    response_context = AsyncMock()
    response_context.__aenter__.return_value = response
    response_context.__aexit__.return_value = None

    session = MagicMock()
    session.get.return_value = response_context
    session_context = AsyncMock()
    session_context.__aenter__.return_value = session
    session_context.__aexit__.return_value = None

    with patch('bot.aiohttp.ClientSession', return_value=session_context):
        await bot.resolve_opsgenie_on_call_period("token", "Team Primary", "oncall@example.com")

    params = session.get.call_args.kwargs["params"]
    assert params["identifierType"] == "name"
    assert params["interval"] == "6"
    assert params["intervalUnit"] == "months"
    assert params["date"].endswith("Z")

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

    scheduled_messages.clear()
    scheduled_messages[(channel.id, ts, "config1")] = ScheduledReply(task=task1, user_id=user1.id)
    scheduled_messages[(channel.id, ts, "config2")] = ScheduledReply(task=task2, user_id=user1.id)

    with patch('bot.get_user_by_id', return_value=user1):
        await handle_thread_response(app, channel, user2, ts)

    task1.cancel.assert_called_once()
    task2.cancel.assert_not_called()
    assert list(scheduled_messages.keys()) == [(channel.id, ts, "config2")]

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

    scheduled_messages.clear()
    scheduled_messages[(channel_id, ts, "config1")] = ScheduledReply(task=task1, user_id=user1_id)
    scheduled_messages[(channel_id, ts, "config2")] = ScheduledReply(task=task2, user_id=user1_id)

    with patch('bot.get_channel_by_id', return_value=channel), patch('bot.get_user_by_id', side_effect=[user2, User(id=user1_id, name="user1", real_name="User One", team="A")]):
        await handle_reaction_added(app, event)

    task1.cancel.assert_called_once()
    task2.cancel.assert_not_called()
    assert list(scheduled_messages.keys()) == [(channel_id, ts, "config2")]

@pytest.mark.asyncio
async def test_handle_channel_message_ignores_bot_for_configs_without_include_bots():
    app = AsyncMock()
    configs = {
        "bots": {**DEFAULT_CONFIG.copy(), "include_bots": True},
        "humans": {**DEFAULT_CONFIG.copy(), "include_bots": False},
    }
    channel = Channel(id="C12345", name="general", configs=configs)
    bot_user = User(id="B12345", name="alert-bot", real_name="Alert Bot", team="Bots")

    with patch('bot.is_work_day', return_value=True), \
         patch('bot.schedule_reply') as mock_schedule_reply:
        scheduled_messages.clear()
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

    with patch('bot.get_channel_by_id', return_value=channel), \
         patch('bot.get_user_by_id', return_value=bot_user), \
         patch('bot.is_work_day', return_value=True), \
         patch('bot.flush_replies_cache', new=AsyncMock()), \
         patch('bot.schedule_reply') as mock_schedule_reply:
        scheduled_messages.clear()
        _scheduled_replies_cache.clear()
        await route_message(app, "token", event)

    mock_schedule_reply.assert_called_once_with(app, "token", channel, configs["alerts"], "alerts", bot_user, extracted_text, "1234.1")
    assert _scheduled_replies_cache[(channel.id, "1234.1", "alerts")]["text"] == extracted_text

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

    scheduled_messages.clear()
    scheduled_messages[(channel.id, ts, "bots")] = ScheduledReply(task=task1, user_id=message_user.id)
    scheduled_messages[(channel.id, ts, "humans")] = ScheduledReply(task=task2, user_id=message_user.id)

    with patch('bot.get_user_by_id', return_value=message_user):
        await handle_thread_response(app, channel, bot_user, ts, actor_is_bot=True)

    task1.cancel.assert_not_called()
    task2.cancel.assert_called_once()
    assert list(scheduled_messages.keys()) == [(channel.id, ts, "bots")]

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
        assert "*OpsGenie schedule*: ``" in sent_message
        assert "*Date format*: `%a, %d %b %Y`" in sent_message
        assert "*Time format*: `%H:%M`" in sent_message
        assert "*Date/time timezone*: `<server local>`" in sent_message
        assert "*Date/time locale*: `<default>`" in sent_message
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

@pytest.mark.asyncio
async def test_set_reply_message_template():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('bot.save_configuration'), patch('bot.send_message') as mock_send_message:
        await set_reply_message(
            app,
            channel,
            "default",
            "Hi {{user}}, {{user_name}}, {{team}}, {{channel}}, {{channel_name}}, {{message}}, {{message_link}}, {{config}}, {{wait_minutes}}, {{timestamp}}, {{opsgenie_current_user}}, {{opsgenie_current_email}}, {{opsgenie_current_name}}",
            user,
            ""
        )

        assert "{{user}}" in channel.configs["default"]["reply_message"]
        mock_send_message.assert_called_with(
            app,
            channel,
            user,
            "*Reply message* set to: Hi {{user}}, {{user_name}}, {{team}}, {{channel}}, {{channel_name}}, {{message}}, {{message_link}}, {{config}}, {{wait_minutes}}, {{timestamp}}, {{opsgenie_current_user}}, {{opsgenie_current_email}}, {{opsgenie_current_name}} in configuration `default`.",
            ""
        )

@pytest.mark.asyncio
async def test_set_reply_message_template_accepts_datetime_args():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")
    message = (
        "{{opsgenie_current_start_datetime(fmt=\"%d.%m.%Y %H:%M\", tz='Europe/Berlin', lc=de-DE)}} "
        "{{opsgenie_next_start_datetime(format=02.01.2006 15:04, timezone=UTC, locale=en_us)}}"
    )

    with patch('bot.save_configuration'), patch('bot.send_message') as mock_send_message:
        await set_reply_message(app, channel, "default", message, user, "")

    assert channel.configs["default"]["reply_message"] == message
    assert mock_send_message.call_args.args[3] == f"*Reply message* set to: {message} in configuration `default`."

@pytest.mark.asyncio
async def test_set_reply_message_rejects_unknown_template_variable():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('bot.send_message') as mock_send_message:
        await set_reply_message(app, channel, "default", "Hi {{unknown}}", user, "")

        assert channel.configs["default"]["reply_message"] == "Anybody?"
        sent_message = mock_send_message.call_args.args[3]
        assert "unsupported template variable(s) `{{unknown}}`" in sent_message
        assert "`{{user}}`" in sent_message
        assert "`{{message_link}}`" in sent_message

@pytest.mark.asyncio
async def test_set_reply_message_rejects_malformed_datetime_args():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('bot.send_message') as mock_send_message:
        await set_reply_message(app, channel, "default", "{{opsgenie_current_start_datetime(fmt='%Y',)}}", user, "")

    sent_message = mock_send_message.call_args.args[3]
    assert "Invalid *reply message*: malformed template expression" in sent_message
    assert "missing argument after `,`" in sent_message

@pytest.mark.asyncio
async def test_set_reply_message_rejects_unknown_arg_invalid_timezone_and_locale():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('bot.send_message') as mock_send_message:
        await set_reply_message(app, channel, "default", "{{opsgenie_current_start_datetime(foo=bar)}}", user, "")
    assert "unknown argument `foo`" in mock_send_message.call_args.args[3]

    with patch('bot.send_message') as mock_send_message:
        await set_reply_message(app, channel, "default", "{{opsgenie_current_start_datetime(tz=Mars/Base)}}", user, "")
    assert "unknown timezone `Mars/Base`" in mock_send_message.call_args.args[3]

    with patch('bot.send_message') as mock_send_message:
        await set_reply_message(app, channel, "default", "{{opsgenie_current_start_datetime(lc=not-a-locale)}}", user, "")
    assert "locale must look like" in mock_send_message.call_args.args[3]

@pytest.mark.asyncio
async def test_schedule_reply_renders_template_variables():
    app = AsyncMock()
    app.client.chat_getPermalink.return_value = {"permalink": "https://slack.test/message"}
    channel = Channel(id="C12345", name="general", configs={})
    user = User("U12345", "test", "Test User", "Testers")
    config = DEFAULT_CONFIG.copy()
    config["wait_time"] = 0
    config["reply_message"] = (
        "Hi {{user}} ({{user_name}}) from {{team}} in {{channel}}/{{channel_name}}. "
        "Config={{config}} Wait={{wait_minutes}} Ts={{timestamp}} "
        "Message={{message}} Link={{message_link}}"
    )

    with patch('bot.send_message') as mock_send_message:
        await schedule_reply(app, "token", channel, config, "alerts", user, "Original text", "1234.1")

        mock_send_message.assert_called_with(
            app,
            channel,
            user,
            "Hi <@U12345> (Test User) from Testers in #general/general. Config=alerts Wait=0 Ts=1234.1 Message=Original text Link=https://slack.test/message",
            "1234.1"
        )

@pytest.mark.asyncio
async def test_schedule_reply_cleans_up_scheduled_message_after_send():
    app = AsyncMock()
    app.client.chat_getPermalink.return_value = {"permalink": "https://slack.test/message"}
    channel = Channel(id="C12345", name="general", configs={})
    user = User("U12345", "test", "Test User", "Testers")
    config = DEFAULT_CONFIG.copy()
    config["wait_time"] = 0
    ts = "1234.1"
    key = (channel.id, ts, "alerts")

    scheduled_messages.clear()
    scheduled_messages[key] = ScheduledReply(task=AsyncMock(), user_id=user.id)

    with patch('bot.send_message') as mock_send_message:
        await schedule_reply(app, "token", channel, config, "alerts", user, "Original text", ts)

    mock_send_message.assert_called_once()
    assert key not in scheduled_messages

@pytest.mark.asyncio
async def test_schedule_reply_renders_opsgenie_template_variables():
    app = AsyncMock()
    app.client.chat_getPermalink.return_value = {"permalink": "https://slack.test/message"}
    channel = Channel(id="C12345", name="general", configs={})
    user = User("U12345", "test", "Test User", "Testers")
    config = DEFAULT_CONFIG.copy()
    config["wait_time"] = 0
    config["opsgenie_schedule_name"] = "Team Primary"
    config["reply_message"] = "On call: {{opsgenie_current_user}} / {{opsgenie_current_email}} / {{opsgenie_current_name}}"

    with patch('bot.get_opsgenie_template_variables', new=AsyncMock(return_value={
        "opsgenie_current_user": "<@U999>",
        "opsgenie_current_email": "oncall@example.com",
        "opsgenie_current_name": "On Call User",
    })), patch('bot.send_message') as mock_send_message:
        await schedule_reply(app, "token", channel, config, "alerts", user, "Original text", "1234.1")

        mock_send_message.assert_called_with(
            app,
            channel,
            user,
            "On call: <@U999> / oncall@example.com / On Call User",
            "1234.1"
        )

@pytest.mark.asyncio
async def test_get_opsgenie_template_variables_renders_current_and_next_periods():
    import bot

    app = AsyncMock()
    current_user = User("U999", "oncall", "On Call User", "Ops")
    next_user = User("U998", "next", "Next User", "Ops")
    config = {
        **DEFAULT_CONFIG.copy(),
        "opsgenie_schedule_name": "Team Primary",
        "date_format": "%d.%m.%Y",
        "time_format": "%H:%M",
        "datetime_timezone": "Europe/Berlin",
    }
    context = bot.OpsGenieContext(
        "Team Primary",
        bot.OpsGeniePeriod("oncall@example.com", current_user, "2026-04-26T08:00:00Z", "2026-04-26T16:00:00Z"),
        bot.OpsGeniePeriod("next@example.com", next_user, "2026-04-27T08:00:00Z", "2026-04-27T16:00:00Z"),
    )

    with patch('bot.resolve_opsgenie_on_call_context', new=AsyncMock(return_value=context)):
        variables = await bot.get_opsgenie_template_variables(app, "token", config)

    assert variables["opsgenie_schedule_name"] == "Team Primary"
    assert variables["opsgenie_current_user"] == "<@U999>"
    assert variables["opsgenie_current_email"] == "oncall@example.com"
    assert variables["opsgenie_current_name"] == "On Call User"
    assert variables["opsgenie_current_start_datetime"] == "26.04.2026 10:00"
    assert variables["opsgenie_current_end_time"] == "18:00"
    assert variables["opsgenie_next_user"] == "<@U998>"
    assert variables["opsgenie_next_email"] == "next@example.com"
    assert variables["opsgenie_next_start_datetime"] == "27.04.2026 10:00"

@pytest.mark.asyncio
async def test_get_opsgenie_template_variables_keeps_current_placeholders_when_only_next_exists():
    import bot

    app = AsyncMock()
    next_user = User("U998", "next", "Next User", "Ops")
    config = {
        **DEFAULT_CONFIG.copy(),
        "opsgenie_schedule_name": "Team Primary",
        "datetime_timezone": "UTC",
    }
    context = bot.OpsGenieContext(
        "Team Primary",
        bot.OpsGeniePeriod("", None, "", ""),
        bot.OpsGeniePeriod("next@example.com", next_user, "2026-04-27T08:00:00Z", "2026-04-27T16:00:00Z"),
    )

    with patch('bot.resolve_opsgenie_on_call_context', new=AsyncMock(return_value=context)):
        variables = await bot.get_opsgenie_template_variables(app, "token", config)

    assert variables["opsgenie_current_user"] == "<no-user-set>"
    assert variables["opsgenie_current_email"] == "<no-email-set>"
    assert variables["opsgenie_current_start_datetime"] == "<unknown>"
    assert variables["opsgenie_next_user"] == "<@U998>"
    assert variables["opsgenie_next_start_datetime"] == "Mon, 27 Apr 2026 08:00"

def test_render_reply_message_template_datetime_args_override_config():
    import bot

    config = {
        **DEFAULT_CONFIG.copy(),
        "date_format": "%d.%m.%Y",
        "time_format": "%H:%M",
        "datetime_timezone": "Europe/Berlin",
    }
    variables = bot.get_opsgenie_placeholder_variables(config)
    raw_key = "__opsgenie_current_start_datetime_raw"
    variables[raw_key] = "2026-04-26T08:00:00Z"

    rendered = bot.render_reply_message_template(
        "{{opsgenie_current_start_datetime(format='02.01.2006 15:04', timezone='UTC', locale='en_US')}}",
        variables,
        config,
    )

    assert rendered == "26.04.2026 08:00"

@pytest.mark.asyncio
async def test_schedule_reply_uses_placeholder_for_unmapped_opsgenie_user():
    app = AsyncMock()
    app.client.chat_getPermalink.return_value = {"permalink": "https://slack.test/message"}
    channel = Channel(id="C12345", name="general", configs={})
    user = User("U12345", "test", "Test User", "Testers")
    config = DEFAULT_CONFIG.copy()
    config["wait_time"] = 0
    config["opsgenie_schedule_name"] = "Team Primary"
    config["reply_message"] = "On call: {{opsgenie_current_user}} / {{opsgenie_current_email}} / {{opsgenie_current_name}}"

    with patch('bot.get_opsgenie_template_variables', new=AsyncMock(return_value={
        "opsgenie_current_user": "<unknown-oncall>",
        "opsgenie_current_email": "oncall@example.com",
        "opsgenie_current_name": "oncall@example.com",
    })), patch('bot.send_message') as mock_send_message:
        await schedule_reply(app, "token", channel, config, "alerts", user, "Original text", "1234.1")

        mock_send_message.assert_called_with(
            app,
            channel,
            user,
            "On call: <unknown-oncall> / oncall@example.com / oncall@example.com",
            "1234.1"
        )

@pytest.mark.asyncio
async def test_schedule_reply_keeps_plain_message_unchanged():
    app = AsyncMock()
    app.client.chat_getPermalink.return_value = {"permalink": "https://slack.test/message"}
    channel = Channel(id="C12345", name="general", configs={})
    user = User("U12345", "test", "Test User", "Testers")
    config = DEFAULT_CONFIG.copy()
    config["wait_time"] = 0
    config["reply_message"] = "Anybody?"

    with patch('bot.get_opsgenie_template_variables', new=AsyncMock()) as mock_get_opsgenie_template_variables, \
         patch('bot.send_message') as mock_send_message:
        await schedule_reply(app, "token", channel, config, "default", user, "Original text", "1234.1")

        mock_get_opsgenie_template_variables.assert_not_awaited()
        mock_send_message.assert_called_with(app, channel, user, "Anybody?", "1234.1")

@pytest.mark.asyncio
async def test_process_command_test_renders_default_reply_and_variables():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")
    channel.configs["default"]["wait_time"] = 600
    channel.configs["default"]["reply_message"] = "Hi {{user}}, wait {{wait_minutes}} in {{channel}}: {{message_link}}"

    with patch('bot.get_opsgenie_template_variables', new=AsyncMock(return_value={
        "opsgenie_current_user": "<@U999>",
        "opsgenie_current_email": "oncall@example.com",
        "opsgenie_current_name": "On Call User",
    })) as mock_get_opsgenie_template_variables, patch('bot.send_message') as mock_send_message:
        await process_command(app, "test", channel, user)

    mock_get_opsgenie_template_variables.assert_awaited_once()
    app.client.chat_getPermalink.assert_not_called()
    sent_message = mock_send_message.call_args.args[3]
    assert "*Reply preview for configuration `default`:*" in sent_message
    assert "Hi <@U12345>, wait 10 in #general: " in sent_message
    assert "`{{channel}}`: #general" in sent_message
    assert "`{{config}}`: default" in sent_message
    assert "`{{message}}`: " in sent_message
    assert "`{{message_link}}`: " in sent_message
    assert "`{{opsgenie_current_user}}`: <@U999>" in sent_message
    assert "`{{timestamp}}`: " in sent_message

@pytest.mark.asyncio
async def test_process_command_test_uses_selected_config():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={
        "default": DEFAULT_CONFIG.copy(),
        "alerts": DEFAULT_CONFIG.copy(),
    })
    channel.configs["alerts"]["wait_time"] = 120
    channel.configs["alerts"]["reply_message"] = "Config {{config}} waits {{wait_minutes}}: {{message}}"
    user = User("U12345", "test", "Test User", "Testers")

    with patch('bot.get_opsgenie_template_variables', new=AsyncMock(return_value={})), patch('bot.send_message') as mock_send_message:
        await process_command(app, "alerts test", channel, user)

    sent_message = mock_send_message.call_args.args[3]
    assert "*Reply preview for configuration `alerts`:*" in sent_message
    assert "Config alerts waits 2: " in sent_message
    assert "`{{config}}`: alerts" in sent_message
    assert "`{{wait_minutes}}`: 2" in sent_message

@pytest.mark.asyncio
async def test_process_command_mention_test_uses_trailing_text_as_message():
    import bot
    app = AsyncMock()
    app.client.chat_getPermalink.return_value = {"permalink": "https://slack.test/message"}
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    channel.configs["default"]["reply_message"] = "Preview: {{message}} {{timestamp}} {{message_link}}"
    user = User("U12345", "test", "Test User", "Testers")

    with patch.object(bot, 'bot_user_id', "UBOT"), \
         patch('bot.get_opsgenie_template_variables', new=AsyncMock(return_value={})), \
         patch('bot.send_message') as mock_send_message:
        await process_command(app, "<@UBOT> test hello world", channel, user, "1234.1", allow_test_message=True, command_ts="1234.1")

    app.client.chat_getPermalink.assert_awaited_once_with(channel="C12345", message_ts="1234.1")
    sent_message = mock_send_message.call_args.args[3]
    assert "Preview: hello world 1234.1 https://slack.test/message" in sent_message
    assert "`{{message}}`: hello world" in sent_message
    assert "`{{timestamp}}`: 1234.1" in sent_message
    assert "`{{message_link}}`: https://slack.test/message" in sent_message

@pytest.mark.asyncio
async def test_process_command_slash_test_with_trailing_text_is_unknown():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('bot.get_opsgenie_template_variables', new=AsyncMock()) as mock_get_opsgenie_template_variables, \
         patch('bot.send_message') as mock_send_message:
        await process_command(app, "test hello world", channel, user)

    mock_get_opsgenie_template_variables.assert_not_awaited()
    mock_send_message.assert_called_with(app, channel, user, "Huh? :thinking_face: Maybe type `/hutbot help` for a list of commands.", "")

@pytest.mark.asyncio
async def test_process_command_news_mentions_on_call_and_test_commands():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('bot.send_message') as mock_send_message:
        await process_command(app, "news", channel, user)

    sent_message = mock_send_message.call_args.args[3]
    assert "`/hutbot [config] on-call [schedule name]`" in sent_message
    assert "`/hutbot [config] test`" in sent_message
    assert "`@Hutbot [config] test <message>`" in sent_message

@pytest.mark.asyncio
async def test_process_command_test_uses_opsgenie_placeholders_when_unavailable():
    import bot
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    channel.configs["default"]["reply_message"] = "Anybody?"
    user = User("U12345", "test", "Test User", "Testers")

    with patch('bot.get_opsgenie_template_variables', new=AsyncMock(return_value=bot.get_opsgenie_placeholder_variables())) as mock_get_opsgenie_template_variables, \
         patch('bot.send_message') as mock_send_message:
        await process_command(app, "test", channel, user, opsgenie_token="token")

    mock_get_opsgenie_template_variables.assert_awaited_once_with(app, "token", channel.configs["default"])
    sent_message = mock_send_message.call_args.args[3]
    assert "`{{opsgenie_current_user}}`: <no-user-set>" in sent_message
    assert "`{{opsgenie_current_email}}`: <no-email-set>" in sent_message
    assert "`{{opsgenie_current_name}}`: <no-name-set>" in sent_message

@pytest.mark.asyncio
async def test_load_and_flush_replies_cache_roundtrip():
    import bot
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
        with patch('bot.SCHEDULED_REPLIES_CACHE_FILE', tmp_path):
            bot._scheduled_replies_cache.clear()
            await load_replies_cache()
            assert ('C123', '1000.1', 'default') in bot._scheduled_replies_cache

            bot._scheduled_replies_cache[('C123', '1000.1', 'default')]['text'] = 'updated'
            await flush_replies_cache()

            with open(tmp_path) as f:
                data = json.load(f)
            assert data[0]['text'] == 'updated'
    finally:
        os.unlink(tmp_path)
        bot._scheduled_replies_cache.clear()

@pytest.mark.asyncio
async def test_load_replies_cache_handles_missing_file():
    import bot
    with patch('bot.SCHEDULED_REPLIES_CACHE_FILE', '/nonexistent/path/to/cache.json'):
        bot._scheduled_replies_cache.clear()
        await load_replies_cache()
        assert bot._scheduled_replies_cache == {}

@pytest.mark.asyncio
async def test_restore_scheduled_replies_skips_unknown_channel():
    import bot
    bot._scheduled_replies_cache.clear()
    bot._scheduled_replies_cache[('C_GONE', '1000.1', 'default')] = {
        'channel_id': 'C_GONE',
        'ts': '1000.1',
        'config_name': 'default',
        'user_id': 'U1',
        'text': 'msg',
        'send_at': (datetime.datetime.now() + datetime.timedelta(seconds=60)).isoformat(),
    }
    app = AsyncMock()
    scheduled_messages.clear()

    with patch('bot.channel_config', {}), patch('bot.flush_replies_cache', new=AsyncMock()):
        await restore_scheduled_replies(app, "token")

    assert len(scheduled_messages) == 0
    assert bot._scheduled_replies_cache == {}

@pytest.mark.asyncio
async def test_restore_scheduled_replies_schedules_with_remaining_time():
    import bot
    import asyncio
    future = datetime.datetime.now() + datetime.timedelta(seconds=300)
    bot._scheduled_replies_cache.clear()
    bot._scheduled_replies_cache[('C123', '1000.1', 'default')] = {
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
    scheduled_messages.clear()

    captured_override = []

    async def fake_schedule_reply(*args, wait_time_override=None, **kwargs):
        captured_override.append(wait_time_override)

    with patch('bot.channel_config', {'C123': {'default': config}}), \
         patch('bot.get_user_by_id', new=AsyncMock(return_value=User('U456', 'user', 'User', 'Team'))), \
         patch('bot.schedule_reply', side_effect=fake_schedule_reply), \
         patch('bot.flush_replies_cache', new=AsyncMock()):
        await restore_scheduled_replies(app, "token")
        await asyncio.gather(*[sr.task for sr in scheduled_messages.values()])

    assert len(captured_override) == 1
    assert 290 <= captured_override[0] <= 310

@pytest.mark.asyncio
async def test_restore_scheduled_replies_sends_immediately_when_overdue():
    import bot
    import asyncio
    past = datetime.datetime.now() - datetime.timedelta(seconds=60)
    bot._scheduled_replies_cache.clear()
    bot._scheduled_replies_cache[('C123', '1000.1', 'default')] = {
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
    scheduled_messages.clear()

    captured_override = []

    async def fake_schedule_reply(*args, wait_time_override=None, **kwargs):
        captured_override.append(wait_time_override)

    with patch('bot.channel_config', {'C123': {'default': config}}), \
         patch('bot.get_user_by_id', new=AsyncMock(return_value=User('U456', 'user', 'User', 'Team'))), \
         patch('bot.schedule_reply', side_effect=fake_schedule_reply), \
         patch('bot.flush_replies_cache', new=AsyncMock()):
        await restore_scheduled_replies(app, "token")
        await asyncio.gather(*[sr.task for sr in scheduled_messages.values()])

    assert captured_override[0] == 0.0

@pytest.mark.asyncio
async def test_schedule_reply_removes_entry_from_cache():
    import bot
    app = AsyncMock()
    app.client.chat_getPermalink.return_value = {"permalink": ""}
    channel = Channel(id="C12345", name="general", configs={})
    user = User("U12345", "test", "Test User", "Testers")
    config = DEFAULT_CONFIG.copy()
    config["wait_time"] = 0
    ts = "9999.1"
    key = (channel.id, ts, "default")

    bot._scheduled_replies_cache.clear()
    bot._scheduled_replies_cache[key] = {'channel_id': channel.id, 'ts': ts, 'config_name': 'default', 'user_id': user.id, 'text': 'x', 'send_at': '2026-01-01T00:00:00'}

    with patch('bot.send_message'), patch('bot.flush_replies_cache', new=AsyncMock()):
        await schedule_reply(app, "token", channel, config, "default", user, "x", ts)

    assert key not in bot._scheduled_replies_cache
