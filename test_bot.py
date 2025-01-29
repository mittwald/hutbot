import pytest
from unittest.mock import AsyncMock, patch
from bot import replace_ids, Channel, User, Usergroup, get_team_of, handle_command, clean_slack_text, send_message
from slack_sdk.errors import SlackApiError

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
    username = "@johndoe"
    user = User(id="U12345", name="test", real_name="Test User", team="Testers")
    thread_ts = "1234567890.123456"

    with patch('bot.get_user_by_name', return_value=User(id="U12345", name="johndoe", real_name="John Doe", team="team1")):
        with patch('bot.send_message') as mock_send_message:
            await get_team_of(app, channel, username, user, thread_ts)
            mock_send_message.assert_called_once_with(app, channel, user, "*John Doe* (<@U12345>): team1", thread_ts)

@pytest.mark.asyncio
async def test_get_team_of_multiple_users():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    username = "@johndoe @janedoe"
    user = User(id="U12345", name="test", real_name="Test User", team="Testers")
    thread_ts = "1234567890.123456"

    with patch('bot.get_user_by_name', side_effect=[
        User(id="U12345", name="johndoe", real_name="John Doe", team="team1"),
        User(id="U67890", name="janedoe", real_name="Jane Doe", team="team2")
    ]):
        with patch('bot.send_message') as mock_send_message:
            await get_team_of(app, channel, username, user, thread_ts)
            mock_send_message.assert_called_once_with(app, channel, user, "*John Doe* (<@U12345>): team1\n*Jane Doe* (<@U67890>): team2", thread_ts)

@pytest.mark.asyncio
async def test_get_team_of_unknown_user():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    username = "@unknownuser"
    user = User(id="U12345", name="test", real_name="Test User", team="Testers")
    thread_ts = "1234567890.123456"

    with patch('bot.get_user_by_name', return_value=User(id=None, name="unknownuser", real_name="", team="")):
        with patch('bot.send_message') as mock_send_message:
            await get_team_of(app, channel, username, user, thread_ts)
            mock_send_message.assert_called_once_with(app, channel, user, "Unknown user: `@unknownuser`.", thread_ts)

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
async def test_handle_command_set_wait_time():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user_id = "U12345"
    thread_ts = "1234567890.123456"

    for text in [ "set wait-time 10", "wait-time 10", "set wait_time 10", "set waittime 10", "waittime   \"10\"", "waittime   '10'" ]:
        with patch('bot.set_wait_time') as mock_set_wait_time:
            await handle_command(app, text, channel, user_id, thread_ts)
            mock_set_wait_time.assert_called_once_with(app, channel, 10, user_id, thread_ts)

@pytest.mark.asyncio
async def test_handle_command_set_reply_message():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user_id = "U12345"
    thread_ts = "1234567890.123456"

    for text in [ "set message \"Hello, world!\"", "message  \"Hello, world!\"", "message  'Hello, world!'", "message  Hello, world!" ]:
        with patch('bot.set_reply_message') as mock_set_reply_message:
            await handle_command(app, text, channel, user_id, thread_ts)
            mock_set_reply_message.assert_called_once_with(app, channel, "Hello, world!", user_id, thread_ts)

@pytest.mark.asyncio
async def test_handle_command_enable_opsgenie():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user_id = "U12345"
    thread_ts = "1234567890.123456"
    text = f"enable opsgenie"

    for text in [ "enable opsgenie", "enable  alerts", "enable alert" ]:
        with patch('bot.set_opsgenie') as mock_set_opsgenie:
            await handle_command(app, text, channel, user_id, thread_ts)
            mock_set_opsgenie.assert_called_once_with(app, channel, True, user_id, thread_ts)

@pytest.mark.asyncio
async def test_handle_command_disable_opsgenie():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user_id = "U12345"
    thread_ts = "1234567890.123456"

    for text in [ "disable opsgenie", "disable alerts", "disable alert" ]:
        with patch('bot.set_opsgenie') as mock_set_opsgenie:
            await handle_command(app, text, channel, user_id, thread_ts)
            mock_set_opsgenie.assert_called_once_with(app, channel, False, user_id, thread_ts)

@pytest.mark.asyncio
async def test_handle_command_list_teams():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user_id = "U12345"
    thread_ts = "1234567890.123456"

    for text in [ "list teams", "list  team", "teams", "team" ]:
        with patch('bot.list_teams') as mock_list_teams:
            await handle_command(app, text, channel, user_id, thread_ts)
            mock_list_teams.assert_called_once_with(app, channel, user_id, thread_ts)

@pytest.mark.asyncio
async def test_handle_command_get_team_of():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user_id = "U12345"
    thread_ts = "1234567890.123456"

    for text in [ "team of @johndoe", "team @johndoe", "team   @johndoe", "team  of   @johndoe", "team  of   \"@johndoe\"", "team  of   '@johndoe'" ]:
        with patch('bot.get_team_of') as mock_get_team_of:
            await handle_command(app, text, channel, user_id, thread_ts)
            mock_get_team_of.assert_called_once_with(app, channel, "@johndoe", user_id, thread_ts)

@pytest.mark.asyncio
async def test_handle_command_add_excluded_team():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user_id = "U12345"
    thread_ts = "1234567890.123456"
    text = f"add excluded-team team1"

    for text in [ "add excluded-teams team1", "add exclude  team1", "add excluded   team1", "add excluded-team team1", "add exclude_team team1", "add exclude_team \"team1\"", "add exclude_team 'team1'" ]:
        with patch('bot.add_excluded_team') as mock_add_excluded_team:
            await handle_command(app, text, channel, user_id, thread_ts)
            mock_add_excluded_team.assert_called_once_with(app, channel, "team1", user_id, thread_ts)

@pytest.mark.asyncio
async def test_handle_command_clear_excluded_team():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user_id = "U12345"
    thread_ts = "1234567890.123456"

    for text in [ "clear excluded-teams", "clear exclude", "clear excluded", "clear excluded-team", "clear exclude_team" ]:
        with patch('bot.clear_excluded_team') as mock_clear_excluded_team:
            await handle_command(app, text, channel, user_id, thread_ts)
            mock_clear_excluded_team.assert_called_once_with(app, channel, user_id, thread_ts)

@pytest.mark.asyncio
async def test_handle_command_add_included_team():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user_id = "U12345"
    thread_ts = "1234567890.123456"

    for text in [ "add included-teams team1", "add include  team1", "add included   team1", "add included-team team1", "add include_team team1", "add include_team \"team1\"", "add include_team 'team1'" ]:
        with patch('bot.add_included_team') as mock_add_included_team:
            await handle_command(app, text, channel, user_id, thread_ts)
            mock_add_included_team.assert_called_once_with(app, channel, "team1", user_id, thread_ts)

@pytest.mark.asyncio
async def test_handle_command_clear_included_team():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user_id = "U12345"
    thread_ts = "1234567890.123456"

    for text in [ "clear included-teams", "clear include", "clear included", "clear included-team", "clear include_team" ]:
        with patch('bot.clear_included_team') as mock_clear_included_team:
            await handle_command(app, text, channel, user_id, thread_ts)
            mock_clear_included_team.assert_called_once_with(app, channel, user_id, thread_ts)

@pytest.mark.asyncio
async def test_handle_command_show_config():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user_id = "U12345"
    thread_ts = "1234567890.123456"

    for text in [ "show config", "config", "show configuration", "configuration" ]:
        with patch('bot.show_config') as mock_show_config:
            await handle_command(app, text, channel, user_id, thread_ts)
            mock_show_config.assert_called_once_with(app, channel, user_id, thread_ts)

@pytest.mark.asyncio
async def test_handle_command_help():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user_id = "U12345"
    thread_ts = "1234567890.123456"
    text = f"help"

    with patch('bot.send_help_message') as mock_send_help_message:
        await handle_command(app, text, channel, user_id, thread_ts)
        mock_send_help_message.assert_called_once_with(app, channel, user_id, thread_ts)

@pytest.mark.asyncio
async def test_handle_command_unknown():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", config={})
    user_id = "U12345"
    thread_ts = "1234567890.123456"
    text = f"unknown command"

    with patch('bot.send_message') as mock_send_message:
        await handle_command(app, text, channel, user_id, thread_ts)
        mock_send_message.assert_called_once_with(app, channel, user_id, "Huh? :thinking_face: Maybe type `/hutbot help` for a list of commands.", thread_ts)

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