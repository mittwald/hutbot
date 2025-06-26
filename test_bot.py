import pytest
import datetime
from unittest.mock import AsyncMock, patch
from bot import replace_ids, Channel, User, Usergroup, get_team_of, process_command, clean_slack_text, send_message, route_message, handle_channel_message, scheduled_messages, set_work_hours, parse_time, is_work_day, is_work_time
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
async def test_replace_ids_user_id():
    app = AsyncMock()
    text = "Hello <@U12345>!"

    app.client.users_info.return_value = {"user": {"id": "U12345", "real_name": "John Doe"}}

    with patch('bot.get_user_by_id', return_value=User(id="U12345", name="johndoe", real_name="John Doe", team="team1")):
        result = await replace_ids(app, None, text)

    assert result == "Hello John Doe!"

@pytest.mark.asyncio
async def test_replace_ids_channel_id():
    app = AsyncMock()
    text = "Check out <#C67890> channel."

    app.client.conversations_info.return_value = {"channel": {"id": "C67890", "name": "random"}}

    with patch('bot.get_channel_by_id', return_value=Channel(id="C67890", name="random", config={})):
        result = await replace_ids(app, None, text)

    assert result == "Check out #random channel."

@pytest.mark.asyncio
async def test_replace_ids_fallback():
    app = AsyncMock()
    text = "Hello <@U99999|unknown>!"

    with patch('bot.get_user_by_id', return_value=User(id=None, name="unknown", real_name="", team="")):
        result = await replace_ids(app, None, text)

    assert result == "Hello unknown!"

@pytest.mark.asyncio
async def test_replace_ids_no_user():
    app = AsyncMock()
    text = "Hello <@U99999|>!"

    with patch('bot.get_user_by_id', return_value=User(id=None, name="unknown", real_name="", team="")):
        result = await replace_ids(app, None, text)

    assert result == "Hello @U99999!"

@pytest.mark.asyncio
async def test_replace_ids_usergroup():
    app = AsyncMock()
    text = "Hello <!subteam^S07RS6NT467>!"

    with patch('bot.get_usergroup_by_id', return_value=Usergroup(id="S07RS6NT467", handle="supergroup", name="The Super Group")):
        result = await replace_ids(app, None, text)

    assert result == "Hello @supergroup!"

@pytest.mark.asyncio
async def test_replace_ids_no_match():
    app = AsyncMock()
    text = "Hello world!"

    result = await replace_ids(app, None, text)

    assert result == "Hello world!"

@pytest.mark.asyncio
async def test_get_team_of_single_user():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    username = "<@U12345>"
    user = User(id="U12345", name="test", real_name="Test User", team="Testers")
    thread_ts = "1234567890.123456"

    with patch('bot.get_user_by_id', return_value=User(id="U12345", name="johndoe", real_name="John Doe", team="team1")):
        with patch('bot.send_message') as mock_send_message:
            await get_team_of(app, channel, username, user, thread_ts)
            mock_send_message.assert_called_once_with(app, channel, user, "*John Doe* (<@U12345>): `team1`", thread_ts)

@pytest.mark.asyncio
async def test_get_team_of_multiple_users():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    username = "<@U12345> <@U67890>"
    user = User(id="U12345", name="test", real_name="Test User", team="Testers")
    thread_ts = "1234567890.123456"

    with patch('bot.get_user_by_id', side_effect=[
        User(id="U12345", name="johndoe", real_name="John Doe", team="team1"),
        User(id="U67890", name="janedoe", real_name="Jane Doe", team="team2")
    ]):
        with patch('bot.send_message') as mock_send_message:
            await get_team_of(app, channel, username, user, thread_ts)
            mock_send_message.assert_called_once_with(app, channel, user, "*John Doe* (<@U12345>): `team1`\n*Jane Doe* (<@U67890>): `team2`", thread_ts)

@pytest.mark.asyncio
async def test_get_team_of_unknown_user():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    username = "<@U12345>"
    user = User(id="U12345", name="test", real_name="Test User", team="Testers")
    thread_ts = "1234567890.123456"

    with patch('bot.get_user_by_id', return_value=User(id=None, name="unknownuser", real_name="", team="")):
        with patch('bot.send_message') as mock_send_message:
            await get_team_of(app, channel, username, user, thread_ts)
            mock_send_message.assert_called_once_with(app, channel, user, "Unknown user: `<@U12345>`.", thread_ts)

@pytest.mark.asyncio
async def test_get_team_of_no_mentions():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    username = "no mentions here"
    user = User(id="U12345", name="test", real_name="Test User", team="Testers")
    thread_ts = "1234567890.123456"

    with patch('bot.send_message') as mock_send_message:
        await get_team_of(app, channel, username, user, thread_ts)
        mock_send_message.assert_called_once_with(app, channel, user, "Unknown user: `no mentions here`.", thread_ts)

@pytest.mark.asyncio
async def test_process_command_set_wait_time():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    for text in [ "set wait-time 10", "wait-time 10", "set wait_time 10", "set waittime 10", "waittime   \"10\"", "waittime   '10'" ]:
        with patch('bot.set_wait_time') as mock_set_wait_time:
            await process_command(app, text, channel, user, thread_ts)
            mock_set_wait_time.assert_called_once_with(app, channel, 10, user, thread_ts)

@pytest.mark.asyncio
async def test_process_command_set_reply_message():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    for text in [ "set message \"Hello, world!\"", "message  \"Hello, world!\"", "message  'Hello, world!'", "message  Hello, world!" ]:
        with patch('bot.set_reply_message') as mock_set_reply_message:
            await process_command(app, text, channel, user, thread_ts)
            mock_set_reply_message.assert_called_once_with(app, channel, "Hello, world!", user, thread_ts)

@pytest.mark.asyncio
async def test_process_command_enable_opsgenie():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"
    text = f"enable opsgenie"

    for text in [ "enable opsgenie", "enable  alerts", "enable alert" ]:
        with patch('bot.set_opsgenie') as mock_set_opsgenie:
            await process_command(app, text, channel, user, thread_ts)
            mock_set_opsgenie.assert_called_once_with(app, channel, True, user, thread_ts)

@pytest.mark.asyncio
async def test_process_command_disable_opsgenie():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    for text in [ "disable opsgenie", "disable alerts", "disable alert" ]:
        with patch('bot.set_opsgenie') as mock_set_opsgenie:
            await process_command(app, text, channel, user, thread_ts)
            mock_set_opsgenie.assert_called_once_with(app, channel, False, user, thread_ts)

@pytest.mark.asyncio
async def test_process_command_list_teams():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    for text in [ "list teams", "list  team", "teams", "team" ]:
        with patch('bot.list_teams') as mock_list_teams:
            await process_command(app, text, channel, user, thread_ts)
            mock_list_teams.assert_called_once_with(app, channel, user, thread_ts)

@pytest.mark.asyncio
async def test_process_command_get_team_of():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    for text in [ "team of @johndoe", "team @johndoe", "team   @johndoe", "team  of   @johndoe", "team  of   \"@johndoe\"", "team  of   '@johndoe'" ]:
        with patch('bot.get_team_of') as mock_get_team_of:
            await process_command(app, text, channel, user, thread_ts)
            mock_get_team_of.assert_called_once_with(app, channel, "@johndoe", user, thread_ts)

@pytest.mark.asyncio
async def test_process_command_add_excluded_team():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"
    text = f"add excluded-team team1"

    for text in [ "add excluded-teams team1", "add exclude  team1", "add excluded   team1", "add excluded-team team1", "add exclude_team team1", "add exclude_team \"team1\"", "add exclude_team 'team1'" ]:
        with patch('bot.add_excluded_team') as mock_add_excluded_team:
            await process_command(app, text, channel, user, thread_ts)
            mock_add_excluded_team.assert_called_once_with(app, channel, "team1", user, thread_ts)

@pytest.mark.asyncio
async def test_process_command_clear_excluded_team():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    for text in [ "clear excluded-teams", "clear exclude", "clear excluded", "clear excluded-team", "clear exclude_team" ]:
        with patch('bot.clear_excluded_team') as mock_clear_excluded_team:
            await process_command(app, text, channel, user, thread_ts)
            mock_clear_excluded_team.assert_called_once_with(app, channel, user, thread_ts)

@pytest.mark.asyncio
async def test_process_command_add_included_team():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    for text in [ "add included-teams team1", "add include  team1", "add included   team1", "add included-team team1", "add include_team team1", "add include_team \"team1\"", "add include_team 'team1'" ]:
        with patch('bot.add_included_team') as mock_add_included_team:
            await process_command(app, text, channel, user, thread_ts)
            mock_add_included_team.assert_called_once_with(app, channel, "team1", user, thread_ts)

@pytest.mark.asyncio
async def test_process_command_clear_included_team():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    for text in [ "clear included-teams", "clear include", "clear included", "clear included-team", "clear include_team" ]:
        with patch('bot.clear_included_team') as mock_clear_included_team:
            await process_command(app, text, channel, user, thread_ts)
            mock_clear_included_team.assert_called_once_with(app, channel, user, thread_ts)

@pytest.mark.asyncio
async def test_process_command_show_config():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    for text in [ "show config", "config", "show configuration", "configuration" ]:
        with patch('bot.show_config') as mock_show_config:
            await process_command(app, text, channel, user, thread_ts)
            mock_show_config.assert_called_once_with(app, channel, user, thread_ts)

@pytest.mark.asyncio
async def test_process_command_help():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"
    text = f"help"

    with patch('bot.send_help_message') as mock_send_help_message:
        await process_command(app, text, channel, user, thread_ts)
        mock_send_help_message.assert_called_once_with(app, channel, user, thread_ts)

@pytest.mark.asyncio
async def test_process_command_unknown():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"
    text = f"unknown command"

    with patch('bot.send_message') as mock_send_message:
        await process_command(app, text, channel, user, thread_ts)
        mock_send_message.assert_called_once_with(app, channel, user, "Huh? :thinking_face: Maybe type `/hutbot help` for a list of commands.", thread_ts)

@pytest.mark.asyncio
async def test_clean_slack_text_unescape_formatting():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    text = r"Hello \*world\*!"

    result = await clean_slack_text(app, channel, text)

    assert result == "Hello world!"

@pytest.mark.asyncio
async def test_clean_slack_text_replace_ids():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    text = "Hello <@U12345>!"

    with patch('bot.replace_ids', return_value="Hello John Doe!"):
        result = await clean_slack_text(app, channel, text)

    assert result == "Hello John Doe!"

@pytest.mark.asyncio
async def test_clean_slack_text_replace_links():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    text = "Check this link: <http://example.com|example>"

    result = await clean_slack_text(app, channel, text)

    assert result == "Check this link: example"

@pytest.mark.asyncio
async def test_clean_slack_text_replace_links_no_text():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    text = "Check this link: <http://example.com>"

    result = await clean_slack_text(app, channel, text)

    assert result == "Check this link: [URL]"

@pytest.mark.asyncio
async def test_clean_slack_text_remove_formatting():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    text = """
    *bold* _italic_ ~strikethrough~ `code`
    ```
    code
    block
    ```
    """

    result = await clean_slack_text(app, channel, text)

    assert result == "bold italic strikethrough code code block"

@pytest.mark.asyncio
async def test_clean_slack_text_remove_newlines():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    text = "Hello\nworld!"

    result = await clean_slack_text(app, channel, text)

    assert result == "Hello world!"

@pytest.mark.asyncio
async def test_send_message_success():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user = User(id="U12345", name="johndoe", real_name="John Doe", team="team1")
    text = "Hello, world!"
    thread_ts = "1234567890.123456"

    with patch('bot.log_debug') as mock_log_debug:
        await send_message(app, channel, user, text, thread_ts)
        app.client.chat_postMessage.assert_called_once_with(
            channel=channel.id,
            thread_ts=thread_ts,
            text=text,
            mrkdwn=True
        )
        mock_log_debug.assert_called()

@pytest.mark.asyncio
async def test_send_message_ephemeral_success():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user = User(id="U12345", name="johndoe", real_name="John Doe", team="team1")
    text = "Hello, world!"

    with patch('bot.log_debug') as mock_log_debug:
        await send_message(app, channel, user, text)
        app.client.chat_postEphemeral.assert_called_once_with(
            channel=channel.id,
            user=user.id,
            text=text,
            mrkdwn=True
        )
        mock_log_debug.assert_called()

@pytest.mark.asyncio
async def test_send_message_retry():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user = User(id="U12345", name="johndoe", real_name="John Doe", team="team1")
    text = "Hello, world!"
    thread_ts = "1234567890.123456"

    app.client.chat_postMessage.side_effect = [SlackApiError("error", "error"), None]

    with patch('bot.log_warning') as mock_log_warning, patch('bot.log_debug') as mock_log_debug:
        await send_message(app, channel, user, text, thread_ts)
        assert app.client.chat_postMessage.call_count == 2
        mock_log_warning.assert_called()
        mock_log_debug.assert_called()

@pytest.mark.asyncio
async def test_send_message_fail():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user = User(id="U12345", name="johndoe", real_name="John Doe", team="team1")
    text = "Hello, world!"
    thread_ts = "1234567890.123456"

    app.client.chat_postMessage.side_effect = SlackApiError("error", "error")

    with patch('bot.log_error') as mock_log_error, patch('bot.log_warning') as mock_log_warning, patch('bot.log_debug') as mock_log_debug:
        await send_message(app, channel, user, text, thread_ts)
        assert app.client.chat_postMessage.call_count == 3
        mock_log_warning.assert_called()
        mock_log_error.assert_called()
        mock_log_debug.assert_called()

@pytest.mark.asyncio
async def test_send_message_ephemeral_fail():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user = User(id="U12345", name="johndoe", real_name="John Doe", team="team1")
    text = "Hello, world!"

    app.client.chat_postEphemeral.side_effect = SlackApiError("error", "error")

    with patch('bot.log_error') as mock_log_error, patch('bot.log_warning') as mock_log_warning, patch('bot.log_debug') as mock_log_debug:
        await send_message(app, channel, user, text)
        assert app.client.chat_postEphemeral.call_count == 3
        mock_log_warning.assert_called()
        mock_log_error.assert_called()
        mock_log_debug.assert_called()

@pytest.mark.asyncio
async def test_route_message_ignore_subtype():
    app = AsyncMock()
    opsgenie_token = "dummy_token"
    event = {
        "channel": "C12345",
        "user": "U67890",
        "subtype": "channel_join",
        "text": "Hello, world!",
        "ts": "1234567890.123456"
    }

    with patch('bot.get_channel_name', return_value="general"), patch('bot.log') as mock_log:
        await route_message(app, opsgenie_token, event)
        mock_log.assert_called_with("Ignoring message with subtype 'channel_join' for channel #general.")

@pytest.mark.asyncio
async def test_route_message_deleted_message():
    app = AsyncMock()
    opsgenie_token = "dummy_token"
    event = {
        "channel": "C12345",
        "user": "U67890",
        "subtype": "message_deleted",
        "previous_message": {
            "user": "U12345",
            "ts": "1234567890.123456"
        }
    }

    with patch('bot.get_channel_by_id', return_value=Channel(id="C12345", name="general", config={})), \
            patch('bot.get_user_by_id', side_effect=[User(id="U67890", name="test", real_name="Test User", team="Testers"), User(id="U12345", name="johndoe", real_name="John Doe", team="team1")]), \
            patch('bot.handle_message_deletion') as mock_handle_message_deletion:
        await route_message(app, opsgenie_token, event)
        mock_handle_message_deletion.assert_called_once_with(app, Channel(id="C12345", name="general", config={}), User(id="U12345", name="johndoe", real_name="John Doe", team="team1"), "1234567890.123456")

@pytest.mark.asyncio
async def test_route_message_command():
    app = AsyncMock()
    opsgenie_token = "dummy_token"
    event = {
        "channel": "C12345",
        "user": "U67890",
        "text": "set wait-time 10",
        "ts": "1234567890.123456"
    }

    with patch('bot.get_channel_by_id', return_value=Channel(id="C12345", name="general", config={})), \
            patch('bot.get_user_by_id', return_value=User(id="U67890", name="test", real_name="Test User", team="Testers")), \
            patch('bot.is_command', return_value=True), \
            patch('bot.process_command') as mock_process_command:
        await route_message(app, opsgenie_token, event)
        mock_process_command.assert_called_once_with(app, "set wait-time 10", Channel(id="C12345", name="general", config={}), User(id="U67890", name="test", real_name="Test User", team="Testers"), "1234567890.123456")

@pytest.mark.asyncio
async def test_route_message_thread_response():
    app = AsyncMock()
    opsgenie_token = "dummy_token"
    event = {
        "channel": "C12345",
        "user": "U67890",
        "text": "Hello, world!",
        "ts": "1234567890.123456",
        "thread_ts": "1234567890.123456"
    }

    with patch('bot.get_channel_by_id', return_value=Channel(id="C12345", name="general", config={})), \
            patch('bot.get_user_by_id', return_value=User(id="U67890", name="test", real_name="Test User", team="Testers")), \
            patch('bot.handle_thread_response') as mock_handle_thread_response:
        await route_message(app, opsgenie_token, event)
        mock_handle_thread_response.assert_called_once_with(app, Channel(id="C12345", name="general", config={}), User(id="U67890", name="test", real_name="Test User", team="Testers"), "1234567890.123456")

@pytest.mark.asyncio
async def test_route_message_channel_message():
    app = AsyncMock()
    opsgenie_token = "dummy_token"
    event = {
        "channel": "C12345",
        "user": "U67890",
        "text": "Hello, world!",
        "ts": "1234567890.123456"
    }

    with patch('bot.get_channel_by_id', return_value=Channel(id="C12345", name="general", config={})), \
            patch('bot.get_user_by_id', return_value=User(id="U67890", name="test", real_name="Test User", team="Testers")), \
            patch('bot.handle_channel_message') as mock_handle_channel_message:
        await route_message(app, opsgenie_token, event)
        mock_handle_channel_message.assert_called_once_with(app, opsgenie_token, Channel(id="C12345", name="general", config={}), User(id="U67890", name="test", real_name="Test User", team="Testers"), "Hello, world!", "1234567890.123456")

@pytest.mark.asyncio
async def test_process_command_set_work_hours():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    for test in [ [ "set work-hours 9:00 17:00", "9:00", "17:00" ], [ "work-hours 9 17", "9", "17" ], [ "set work_hours 9:00 17:00", "9:00", "17:00" ], [ "set workhours 9:00 17:00", "9:00", "17:00" ], [ "workhours   \"9:00\" \"17:00\"", "9:00", "17:00" ], [ "workhours   '9:00' '17:00'", "9:00", "17:00" ] ]:
        with patch('bot.set_work_hours') as mock_set_work_hours:
            await process_command(app, test[0], channel, user, thread_ts)
            mock_set_work_hours.assert_called_once_with(app, channel, test[1], test[2], user, thread_ts)

@pytest.mark.asyncio
async def test_process_command_enable_only_work_days():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    for text in [ "enable only-work-days", "enable only_work_days", "enable work-days", "enable work_days" ]:
        with patch('bot.set_only_work_days') as mock_set_only_work_days:
            await process_command(app, text, channel, user, thread_ts)
            mock_set_only_work_days.assert_called_once_with(app, channel, True, user, thread_ts)

@pytest.mark.asyncio
async def test_process_command_disable_only_work_days():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    for text in [ "disable only-work-days", "disable only_work_days", "disable work-days", "disable work_days" ]:
        with patch('bot.set_only_work_days') as mock_set_only_work_days:
            await process_command(app, text, channel, user, thread_ts)
            mock_set_only_work_days.assert_called_once_with(app, channel, False, user, thread_ts)

@pytest.mark.asyncio
async def test_process_command_enable_bots():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    for text in [ "enable bots", "include bots", "set bots" ]:
        with patch('bot.set_bots') as mock_set_bots:
            await process_command(app, text, channel, user, thread_ts)
            mock_set_bots.assert_called_once_with(app, channel, True, user, thread_ts)

@pytest.mark.asyncio
async def test_process_command_disable_bots():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    for text in [ "disable bots", "exclude bots" ]:
        with patch('bot.set_bots') as mock_set_bots:
            await process_command(app, text, channel, user, thread_ts)
            mock_set_bots.assert_called_once_with(app, channel, False, user, thread_ts)

@pytest.mark.asyncio
async def test_handle_channel_message_on_non_work_day():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={'only_work_days': True})
    user = User(id="U12345", name="test", real_name="Test User", team="team1")

    with patch('bot.is_work_day', return_value=False), \
            patch('bot.log') as mock_log:
        await handle_channel_message(app, "token", channel, user, "test", "1234.5678")
        mock_log.assert_called_once_with("Message from user @test in #general will be ignored because of a non work day.")

@pytest.mark.asyncio
async def test_handle_channel_message_outside_work_hours():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={'hours': ['9:00', '17:00']})
    user = User(id="U12345", name="test", real_name="Test User", team="team1")

    with patch('bot.is_work_day', return_value=True), \
            patch('bot.is_work_time', return_value=False), \
            patch('bot.log') as mock_log:
        await handle_channel_message(app, "token", channel, user, "test", "1234.5678")
        mock_log.assert_called_once_with("Message from user @test in #general will be ignored because it was sent outside work time.")

@pytest.mark.asyncio
async def test_handle_channel_message_team_not_included():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={'included_teams': ['team2'], 'excluded_teams': [], 'hours': []})
    user = User(id="U12345", name="test", real_name="Test User", team="team1")

    with patch('bot.is_work_day', return_value=True), \
            patch('bot.log') as mock_log:
        await handle_channel_message(app, "token", channel, user, "test", "1234.5678")
        mock_log.assert_called_once_with("Message from user @test in #general will be ignored because team 'team1' is not included.")

@pytest.mark.asyncio
async def test_handle_channel_message_team_excluded():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={'included_teams': [], 'excluded_teams': ['team1'], 'hours': []})
    user = User(id="U12345", name="test", real_name="Test User", team="team1")

    with patch('bot.is_work_day', return_value=True), \
            patch('bot.log') as mock_log:
        await handle_channel_message(app, "token", channel, user, "test", "1234.5678")
        mock_log.assert_called_once_with("Message from user @test in #general will be ignored because team 'team1' is excluded.")

@pytest.mark.asyncio
async def test_handle_channel_message_schedule_reply():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={'included_teams': [], 'excluded_teams': [], 'hours': []})
    user = User(id="U12345", name="test", real_name="Test User", team="team1")
    text = "test message"
    ts = "1234.5678"

    with patch('bot.is_work_day', return_value=True), \
            patch('asyncio.create_task') as mock_create_task:
        await handle_channel_message(app, "token", channel, user, text, ts)

        mock_create_task.assert_called_once()
        assert (channel.id, ts) in scheduled_messages
        assert scheduled_messages[(channel.id, ts)].user_id == user.id

@pytest.mark.asyncio
async def test_set_work_hours_valid():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    test_cases = [
        ("9:00", "17:00"),
        ("9", "17"),
        ("09:00", "17:00")
    ]

    for start, end in test_cases:
        with patch('bot.save_configuration') as mock_save_config, \
                patch('bot.send_message') as mock_send_message:
            await set_work_hours(app, channel, start, end, user, thread_ts)

            expected_hours = [parse_time(start).strftime("%H:%M"),
                            parse_time(end).strftime("%H:%M")]
            assert channel.config['hours'] == expected_hours

            mock_save_config.assert_called_once()
            mock_send_message.assert_called_once_with(
                app, channel, user,
                f"*Work hours* set to `{expected_hours[0]}` - `{expected_hours[1]}`",
                thread_ts
            )

@pytest.mark.asyncio
async def test_set_work_hours_invalid_start():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    with patch('bot.send_message') as mock_send_message:
        await set_work_hours(app, channel, "invalid", "17:00", user, thread_ts)
        mock_send_message.assert_called_once_with(
            app, channel, user,
            "Invalid time format `invalid`.",
            thread_ts
        )
        assert 'hours' not in channel.config

@pytest.mark.asyncio
async def test_set_work_hours_invalid_end():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    with patch('bot.send_message') as mock_send_message:
        await set_work_hours(app, channel, "9:00", "invalid", user, thread_ts)
        mock_send_message.assert_called_once_with(
            app, channel, user,
            "Invalid time format `invalid`.",
            thread_ts
        )
        assert 'hours' not in channel.config

@pytest.mark.asyncio
async def test_set_work_hours_midnight():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    with patch('bot.save_configuration') as mock_save_config, \
            patch('bot.send_message') as mock_send_message:
        await set_work_hours(app, channel, "00:00", "00:00", user, thread_ts)

        assert channel.config['hours'] == []
        mock_save_config.assert_called_once()
        mock_send_message.assert_called_once_with(
            app, channel, user,
            "*Work hours* set to all day",
            thread_ts
        )

def test_parse_time_valid_formats():
    # Test valid time formats
    test_cases = [
        ("9:00", datetime.time(9, 0)),
        ("09:00", datetime.time(9, 0)),
        ("9", datetime.time(9, 0)),
        ("09", datetime.time(9, 0)),
        ("23:59", datetime.time(23, 59)),
        ("0:00", datetime.time(0, 0))
    ]

    for time_str, expected in test_cases:
        assert parse_time(time_str) == expected

def test_parse_time_invalid_formats():
    # Test invalid time formats
    test_cases = [
        "invalid",
        "25:00",
        "9:60",
        "-1:00",
        "9:00am",
        "abc",
        "",
        ":::",
        "999"
    ]

    for time_str in test_cases:
        assert parse_time(time_str) is None

@pytest.mark.parametrize("day,expected", [
    (datetime.date(2023, 12, 18), True),  # Monday
    (datetime.date(2023, 12, 19), True),  # Tuesday
    (datetime.date(2023, 12, 20), True),  # Wednesday
    (datetime.date(2023, 12, 21), True),  # Thursday
    (datetime.date(2023, 12, 22), True),  # Friday
    (datetime.date(2023, 12, 23), False), # Saturday
    (datetime.date(2023, 12, 24), False), # Sunday
])
def test_is_work_day(monkeypatch, day, expected):
    class MockDate:
        @classmethod
        def today(cls):
            return day
    monkeypatch.setattr(datetime, 'date', MockDate)
    assert is_work_day() == expected

@pytest.mark.parametrize("now,start,end,expected", [
    # During work hours
    (datetime.datetime(2023, 12, 18, 10, 0), "9:00", "17:00", True),
    (datetime.datetime(2023, 12, 18, 16, 59), "9:00", "17:00", True),

    # Outside work hours - too early
    (datetime.datetime(2023, 12, 18, 8, 59), "9:00", "17:00", False),

    # Outside work hours - too late
    (datetime.datetime(2023, 12, 18, 17, 0), "9:00", "17:00", False),

    # Edge cases
    (datetime.datetime(2023, 12, 18, 9, 0), "9:00", "17:00", False),  # At start time
    (datetime.datetime(2023, 12, 18, 0, 0), "0:00", "24:00", True),   # Midnight

    # Using hour-only format
    (datetime.datetime(2023, 12, 18, 10, 0), "9", "17", True),

    # Invalid time formats should return True
    (datetime.datetime(2023, 12, 18, 10, 0), "invalid", "17:00", True),
    (datetime.datetime(2023, 12, 18, 10, 0), "9:00", "invalid", True),
])
def test_is_work_time(monkeypatch, now, start, end, expected):
    class MockDate:
        strptime = datetime.datetime.strptime
        combine = datetime.datetime.combine

        @classmethod
        def now(cls):
            return now
    monkeypatch.setattr(datetime, 'datetime', MockDate)
    assert is_work_time(start, end) == expected
