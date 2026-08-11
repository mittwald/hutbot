from tests._common import *  # noqa: F401,F403



@pytest.mark.asyncio
async def test_process_command_set_wait_time():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "set wait-time 10", channel, user, thread_ts)
        assert channel.configs["default"]["wait_time"] == 600
        mock_send_message.assert_called_with(app, channel, user, "*Wait time* set to `10` minutes in configuration `default`.", thread_ts)



@pytest.mark.asyncio
async def test_process_command_set_wait_time_custom_config():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "my-config set wait-time 20", channel, user, thread_ts)
        assert channel.configs["my-config"]["wait_time"] == 1200
        mock_send_message.assert_called_with(app, channel, user, "*Wait time* set to `20` minutes in configuration `my-config`.", thread_ts)



@pytest.mark.asyncio
async def test_process_command_set_wait_time_invalid_value():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"
    original_wait_time = channel.configs["default"]["wait_time"]

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "set wait-time 30s", channel, user, thread_ts)
        assert channel.configs["default"]["wait_time"] == original_wait_time
        mock_send_message.assert_called_with(app, channel, user, "Invalid wait time. Must be a number between 0 and 1440.", thread_ts)


@pytest.mark.asyncio
async def test_process_command_reports_unexpected_errors():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    with patch('hutbot.messaging.send_message') as mock_send_message, \
            patch('hutbot.commands.dispatch.parse_and_execute_command', side_effect=RuntimeError("boom")):
        await process_command(app, "set wait-time 10", channel, user, thread_ts)
        assert mock_send_message.await_count == 1
        assert "something went wrong" in mock_send_message.await_args.args[3]


@pytest.mark.asyncio
async def test_process_command_set_datetime_format_with_quotes_timezone_and_locale():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as mock_send_message:
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

    with patch('hutbot.persistence.save_configuration') as mock_save, patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "set datefmt %Y %H:%M Mars/Base de-DE", channel, user, thread_ts)

    mock_save.assert_not_called()
    sent_message = mock_send_message.call_args.args[3]
    assert "Invalid *date/time format*" in sent_message
    assert "unknown timezone `Mars/Base`" in sent_message



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

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as mock_send_message:
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
async def test_set_reply_message_rejects_malformed_datetime_args():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await set_reply_message(app, channel, "default", "{{opsgenie_current_start_datetime(fmt='%Y',)}}", user, "")

    sent_message = mock_send_message.call_args.args[3]
    assert "Invalid *reply message*: malformed template expression" in sent_message
    assert "missing argument after `,`" in sent_message



@pytest.mark.asyncio
async def test_set_reply_message_rejects_unknown_arg_invalid_timezone_and_locale():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await set_reply_message(app, channel, "default", "{{opsgenie_current_start_datetime(foo=bar)}}", user, "")
    assert "unknown argument `foo`" in mock_send_message.call_args.args[3]

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await set_reply_message(app, channel, "default", "{{opsgenie_current_start_datetime(tz=Mars/Base)}}", user, "")
    assert "unknown timezone `Mars/Base`" in mock_send_message.call_args.args[3]

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await set_reply_message(app, channel, "default", "{{opsgenie_current_start_datetime(lc=not-a-locale)}}", user, "")
    assert "locale must look like" in mock_send_message.call_args.args[3]



@pytest.mark.asyncio
async def test_process_command_test_renders_default_reply_and_variables():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")
    channel.configs["default"]["wait_time"] = 600
    channel.configs["default"]["reply_message"] = "Hi {{user}}, wait {{wait_minutes}} in {{channel}}: {{message_link}}"

    with patch('hutbot.opsgenie.get_opsgenie_template_variables', new=AsyncMock(return_value={
        "opsgenie_current_user": "<@U999>",
        "opsgenie_current_email": "oncall@example.com",
        "opsgenie_current_name": "On Call User",
    })) as mock_get_opsgenie_template_variables, patch('hutbot.messaging.send_message') as mock_send_message:
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

    with patch('hutbot.opsgenie.get_opsgenie_template_variables', new=AsyncMock(return_value={})), patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "alerts test", channel, user)

    sent_message = mock_send_message.call_args.args[3]
    assert "*Reply preview for configuration `alerts`:*" in sent_message
    assert "Config alerts waits 2: " in sent_message
    assert "`{{config}}`: alerts" in sent_message
    assert "`{{wait_minutes}}`: 2" in sent_message



@pytest.mark.asyncio
async def test_process_command_slash_test_with_trailing_text_is_unknown():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('hutbot.opsgenie.get_opsgenie_template_variables', new=AsyncMock()) as mock_get_opsgenie_template_variables, \
         patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "test hello world", channel, user)

    mock_get_opsgenie_template_variables.assert_not_awaited()
    mock_send_message.assert_called_with(app, channel, user, "Huh? :thinking_face: Maybe type `/hutbot help` for a list of commands.", "")



@pytest.mark.asyncio
async def test_set_replies_enabled_enables():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": {**DEFAULT_CONFIG.copy(), "enabled": False}})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as mock_send:
        await set_replies_enabled(app, channel, "default", True, user)

    assert channel.configs["default"]["enabled"] is True
    mock_send.assert_awaited_once()
    assert "enabled" in mock_send.call_args[0][3]



@pytest.mark.asyncio
async def test_set_replies_enabled_disables():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as mock_send:
        await set_replies_enabled(app, channel, "default", False, user)

    assert channel.configs["default"]["enabled"] is False
    assert "disabled" in mock_send.call_args[0][3]



@pytest.mark.asyncio
async def test_set_replies_enabled_creates_config():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message'):
        await set_replies_enabled(app, channel, "newcfg", False, user)

    assert "newcfg" in channel.configs
    assert channel.configs["newcfg"]["enabled"] is False



@pytest.mark.asyncio
async def test_process_command_enable_replies():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": {**DEFAULT_CONFIG.copy(), "enabled": False}})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message'):
        await process_command(app, "enable", channel, user)

    assert channel.configs["default"]["enabled"] is True



@pytest.mark.asyncio
async def test_process_command_disable_replies():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message'):
        await process_command(app, "disable", channel, user)

    assert channel.configs["default"]["enabled"] is False



# ----- Setters -----

@pytest.mark.asyncio
async def test_set_trigger_valid_and_invalid():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "test", "Test User", "Testers")
    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as send:
        await process_command(app, "set trigger schedule", channel, user)
        assert channel.configs["default"]["trigger"] == "schedule"
        await process_command(app, "set trigger bogus", channel, user)
        assert channel.configs["default"]["trigger"] == "schedule"  # unchanged
        assert "Invalid *trigger*" in send.call_args_list[-1].args[3]


@pytest.mark.asyncio
async def test_set_replies_enabled_clears_the_automatic_disable_reason():
    app = AsyncMock()
    configs = {"default": {**DEFAULT_CONFIG.copy(), "enabled": False, "disabled_reason": DISABLED_REASON_REMOVED}}
    channel = Channel(id="C12345", name="general", configs=configs)
    user = User("U12345", "test", "Test User", "Testers")

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message'):
        await set_replies_enabled(app, channel, "default", True, user)

    assert channel.configs["default"]["enabled"] is True
    assert channel.configs["default"]["disabled_reason"] == ""
