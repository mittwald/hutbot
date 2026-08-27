import copy

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
async def test_set_reply_message_decodes_escaped_newlines():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
            patch('hutbot.messaging.send_message', new=AsyncMock()) as mock_send_message:
        await process_command(app, 'set message "First line.\\nSecond line."', channel, user)

    assert channel.configs["default"]["reply_message"] == "First line.\nSecond line."
    # The confirmation quotes the message back with the break already in place.
    assert "First line.\nSecond line." in mock_send_message.call_args.args[3]


@pytest.mark.asyncio
async def test_set_reply_message_keeps_a_literal_backslash_n():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
            patch('hutbot.messaging.send_message', new=AsyncMock()):
        await set_reply_message(app, channel, "default", "path\\\\name and %Y\\%m", user, "")

    assert channel.configs["default"]["reply_message"] == "path\\name and %Y\\%m"


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
        await process_command(app, "set trigger cron \"0 9 * * 1-5\"", channel, user)
        assert channel.configs["default"]["trigger"] == TRIGGER_CRON
        assert channel.configs["default"]["cron"] == "0 9 * * 1-5"
        # `schedule` still resolves to the cron trigger.
        await process_command(app, "set trigger schedule \"0 8 * * *\"", channel, user)
        assert channel.configs["default"]["cron"] == "0 8 * * *"
        await process_command(app, "set trigger bogus", channel, user)
        assert channel.configs["default"]["trigger"] == TRIGGER_CRON  # unchanged
        assert "Invalid *trigger*" in send.call_args_list[-1].args[3]


@pytest.mark.asyncio
async def test_set_trigger_cron_requires_a_valid_expression():
    app = AsyncMock()
    config = DEFAULT_CONFIG.copy()
    channel = Channel(id="C1", name="davetest", configs={"default": config})
    user = User("U1", "dave", "Dave", "T")

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, "set trigger cron", channel, user)
        assert send.call_args.args[3] == (
            'Trigger `cron` needs an expression: `/hutbot default set trigger cron "0 9 * * 1-5"`.'
        )
        await process_command(app, "set trigger cron not a cron", channel, user)
        assert "Invalid *cron* expression: `not a cron`" in send.call_args.args[3]

    # Neither attempt stored anything, so no rule sits there never firing.
    assert config["trigger"] == "message"
    assert config["cron"] == ""


@pytest.mark.asyncio
async def test_set_trigger_message_takes_no_expression_and_clears_the_cron():
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(), "trigger": TRIGGER_CRON, "cron": "0 9 * * 1-5"}
    channel = Channel(id="C1", name="davetest", configs={"default": config})
    user = User("U1", "dave", "Dave", "T")

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, "set trigger message 0 9 * * 1-5", channel, user)
        assert send.call_args.args[3] == "Trigger `message` takes no expression; only `cron` does."
        assert config["cron"] == "0 9 * * 1-5"

        await process_command(app, "set trigger message", channel, user)

    assert send.call_args.args[3] == "*Trigger* set to `message` in configuration `default`."
    assert config["cron"] == ""


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


@pytest.mark.asyncio
@pytest.mark.parametrize("command", ["clear work-hours", "unset hours", "remove work hours"])
async def test_clear_work_hours_reacts_at_any_hour(command):
    app = AsyncMock()
    channel = Channel(id="C1", name="general", configs={"default": {**DEFAULT_CONFIG.copy(), "hours": ["8:00", "16:00"]}})
    user = User("U1", "test", "Test User", "Testers")

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, command, channel, user)

    assert channel.configs["default"]["hours"] == []
    assert mock_send_message.call_args.args[3] == (
        "*Work hours* cleared in configuration `default`; messages are handled at any hour."
    )


@pytest.mark.asyncio
async def test_set_work_hours_all_day_points_at_the_clear_command():
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(), "hours": ["8:00", "16:00"]}
    channel = Channel(id="C1", name="general", configs={"default": config})
    user = User("U1", "test", "Test User", "Testers")

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "set work-hours all day", channel, user)

    assert mock_send_message.call_args.args[3] == (
        "To handle messages at any hour, use `/hutbot default clear work-hours`."
    )
    assert config["hours"] == ["8:00", "16:00"]


@pytest.mark.asyncio
async def test_set_work_hours_still_takes_two_times():
    app = AsyncMock()
    channel = Channel(id="C1", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U1", "test", "Test User", "Testers")

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "set work-hours 9 17", channel, user)

    assert channel.configs["default"]["hours"] == ["09:00", "17:00"]
    assert mock_send_message.call_args.args[3] == "*Work hours* set to `09:00` - `17:00` in configuration `default`"


@pytest.mark.asyncio
@pytest.mark.parametrize("command", ["test", "run"])
async def test_test_and_run_populate_the_time_variables(command):
    import hutbot
    app = AsyncMock()
    app.client.chat_postMessage.return_value = {"ts": "R1"}
    config = {**DEFAULT_CONFIG.copy(), "reply_message": "at {{time}} on {{date}}, ts {{timestamp}}"}
    channel = Channel(id="C1", name="davetest", configs={"default": config})
    user = User("U1", "dave", "Dave", "T")

    with patch('hutbot.opsgenie.get_opsgenie_template_variables', new=AsyncMock(return_value={})), \
         patch('hutbot.messaging._post_message', new=AsyncMock(return_value={"channel": "C1", "ts": "R1"})) as post, \
         patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, command, channel, user)

    rendered = mock_send_message.call_args.args[3] if command == "test" else post.await_args.args[2]
    assert "at  on , ts \n" not in rendered
    assert "ts {{timestamp}}" not in rendered
    assert re.search(r"at \d{2}:\d{2} on \w{3}, \d{2} \w{3} \d{4}, ts \d+\.\d+", rendered), rendered


@pytest.mark.asyncio
async def test_set_action_requires_a_target_in_the_same_command():
    app = AsyncMock()
    config = DEFAULT_CONFIG.copy()
    channel = Channel(id="C1", name="davetest", configs={"default": config})
    user = User("U1", "dave", "Dave", "T")

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "set action post-channel", channel, user)

    assert mock_send_message.call_args.args[3] == (
        "Action `post_channel` needs a target: `/hutbot default set action post-channel <#channel>`."
    )
    # Nothing was stored, so the config cannot end up in a state that fails when it runs.
    assert config["action"] == ACTION_REPLY
    assert config["action_target"] == ""


@pytest.mark.asyncio
@pytest.mark.parametrize("command,action,target", [
    ("set action post-channel <#CTARGET|targets>", ACTION_POST_CHANNEL, "<#CTARGET|targets>"),
    ("set action dm-user <@U999>", ACTION_DM_USER, "<@U999>"),
    ("set action group-dm @sre", ACTION_GROUP_DM, "@sre"),
])
async def test_set_action_stores_action_and_target_together(command, action, target):
    app = AsyncMock()
    config = DEFAULT_CONFIG.copy()
    channel = Channel(id="C1", name="davetest", configs={"default": config})
    user = User("U1", "dave", "Dave", "T")

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, command, channel, user)

    assert config["action"] == action
    assert config["action_target"] == target
    assert mock_send_message.call_args.args[3] == (
        f"*Action* set to `{action}` sending to `{target}` in configuration `default`."
    )


@pytest.mark.asyncio
async def test_set_action_reply_takes_no_target_and_clears_the_old_one():
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(), "action": ACTION_POST_CHANNEL, "action_target": "<#CTARGET|targets>"}
    channel = Channel(id="C1", name="davetest", configs={"default": config})
    user = User("U1", "dave", "Dave", "T")

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "set action reply <#CTARGET|targets>", channel, user)
        assert mock_send_message.call_args.args[3] == "Action `reply` posts in this channel and takes no target."
        assert config["action"] == ACTION_POST_CHANNEL

        await process_command(app, "set action reply", channel, user)

    assert mock_send_message.call_args.args[3] == "*Action* set to `reply` in configuration `default`."
    assert config["action"] == ACTION_REPLY
    assert config["action_target"] == ""


@pytest.mark.asyncio
async def test_set_action_rejects_a_non_channel_target_for_post_channel():
    app = AsyncMock()
    config = DEFAULT_CONFIG.copy()
    channel = Channel(id="C1", name="davetest", configs={"default": config})
    user = User("U1", "dave", "Dave", "T")

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "set action post-channel @dave", channel, user)

    assert "Invalid *target* `@dave` for action `post_channel`" in mock_send_message.call_args.args[3]
    assert config["action"] == ACTION_REPLY
    assert config["action_target"] == ""


@pytest.mark.asyncio
async def test_run_refuses_a_config_whose_action_has_no_target():
    import hutbot
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(), "action": ACTION_POST_CHANNEL}
    channel = Channel(id="C1", name="davetest", configs={"default": config})
    user = User("U1", "dave", "Dave", "T")

    with patch('hutbot.messaging._post_message', new=AsyncMock()) as post, \
         patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "run", channel, user)

    assert mock_send_message.call_args.args[3] == (
        "Cannot run configuration `default`: action `post_channel` has no target. "
        "Set one with `/hutbot default set action post-channel <#channel>`."
    )
    post.assert_not_awaited()


@pytest.mark.asyncio
async def test_run_action_refuses_instead_of_posting_with_an_empty_target():
    import hutbot
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(), "action": ACTION_POST_CHANNEL}
    channel = Channel(id="C1", name="davetest", configs={"default": config})

    with patch('hutbot.messaging._post_message', new=AsyncMock()) as post:
        posted = await hutbot.actions.run_action(app, "tok", channel, config, "default", context={'channel_id': channel.id})

    assert posted is None
    post.assert_not_awaited()
    assert hutbot.actions.missing_target_reason({**DEFAULT_CONFIG.copy()}) == ""
    assert hutbot.actions.missing_target_reason({**config, "action_target": "not-a-channel"}) == (
        "action `post_channel` target `not-a-channel` is not a channel"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("command", [
    "action post-channel <#CTARGET|targets>",
    "set action post-channel <#CTARGET|targets>",
])
async def test_action_command_works_with_and_without_set(command):
    app = AsyncMock()
    config = DEFAULT_CONFIG.copy()
    channel = Channel(id="C1", name="davetest", configs={"default": config})
    user = User("U1", "dave", "Dave", "T")

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, command, channel, user)

    assert config["action"] == ACTION_POST_CHANNEL
    assert config["action_target"] == "<#CTARGET|targets>"
    assert mock_send_message.call_args.args[3] == (
        "*Action* set to `post_channel` sending to `<#CTARGET|targets>` in configuration `default`."
    )


@pytest.mark.asyncio
async def test_bare_action_command_still_takes_a_config_name():
    app = AsyncMock()
    configs = {"logs": DEFAULT_CONFIG.copy()}
    channel = Channel(id="C1", name="davetest", configs=configs)
    user = User("U1", "dave", "Dave", "T")

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "logs action dm-user <@U999>", channel, user)
        assert configs["logs"]["action"] == ACTION_DM_USER
        assert configs["logs"]["action_target"] == "<@U999>"

        # `action` alone is not a command.
        await process_command(app, "action", channel, user)

    assert "Huh?" in mock_send_message.call_args.args[3]


@pytest.mark.asyncio
@pytest.mark.parametrize("command", ["clear pattern", "unset pattern", "remove pattern"])
async def test_clear_pattern_makes_every_message_match_again(command):
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(), "pattern": ".*alarm.*", "pattern_case_sensitive": True}
    channel = Channel(id="C1", name="davetest", configs={"default": config})
    user = User("U1", "dave", "Dave", "T")

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, command, channel, user)

    assert config["pattern"] is None
    # Case sensitivity is part of the pattern, so it goes back to the default too.
    assert config["pattern_case_sensitive"] is False
    assert mock_send_message.call_args.args[3] == (
        "*Pattern* cleared in configuration `default`; every message matches now."
    )


@pytest.mark.asyncio
async def test_clear_pattern_does_not_shadow_setting_one():
    app = AsyncMock()
    config = DEFAULT_CONFIG.copy()
    channel = Channel(id="C1", name="davetest", configs={"default": config})
    user = User("U1", "dave", "Dave", "T")

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message'):
        await process_command(app, 'set pattern ".*alarm.*" 1', channel, user)

    assert config["pattern"] == ".*alarm.*"
    assert config["pattern_case_sensitive"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("command,field,value", [
    ('trigger cron "0 9 * * 1-5"', "cron", "0 9 * * 1-5"),
    ('pattern ".*alarm.*"', "pattern", ".*alarm.*"),
    ("opsgenie-schedule SRE", "opsgenie_schedule_name", "SRE"),
    ("opsgenie-priority P2", "opsgenie_priority", "P2"),
    ("opsgenie-message Alert!", "opsgenie_message", "Alert!"),
    ("condition-mode any", "conditions_mode", "any"),
    ("calendar https://cal.example.com/a/b/calendar.ics", "calendar_url", "https://cal.example.com/a/b/calendar.ics"),
    ("escalation 5 config alarm", "escalation_timeout", 300),
])
async def test_every_setting_command_works_without_the_word_set(command, field, value):
    app = AsyncMock()
    user = User("U1", "dave", "Dave", "T")

    for text in (command, f"set {command}"):
        config = copy.deepcopy(DEFAULT_CONFIG)
        channel = Channel(id="C1", name="davetest", configs={"default": config})
        with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
             patch('hutbot.messaging.send_message'):
            await process_command(app, text, channel, user)
        assert config[field] == value, text


@pytest.mark.asyncio
async def test_an_existing_config_wins_an_ambiguous_first_word():
    app = AsyncMock()
    configs = {"default": DEFAULT_CONFIG.copy(), "trigger": DEFAULT_CONFIG.copy()}
    channel = Channel(id="C1", name="davetest", configs=configs)
    user = User("U1", "dave", "Dave", "T")

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as mock_send_message:
        # Both readings fit: the `trigger` config's message, or the default config's
        # trigger. The named config wins.
        await process_command(app, "trigger message hello", channel, user)
        assert configs["trigger"]["reply_message"] == "hello"
        assert configs["default"]["reply_message"] == DEFAULT_CONFIG["reply_message"]

        # `cron "…"` is not a command on its own, so this can only be the command.
        await process_command(app, 'trigger cron "0 9 * * 1-5"', channel, user)

    assert configs["default"]["trigger"] == TRIGGER_CRON
    assert configs["trigger"]["trigger"] == "message"
    assert "in configuration `default`" in mock_send_message.call_args.args[3]


@pytest.mark.asyncio
async def test_a_command_word_is_not_taken_as_a_config_name():
    app = AsyncMock()
    configs = {"default": DEFAULT_CONFIG.copy()}
    channel = Channel(id="C1", name="davetest", configs=configs)
    user = User("U1", "dave", "Dave", "T")

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "set enable", channel, user)

    assert mock_send_message.call_args.args[3] == (
        "`set` cannot be a configuration name; it starts a command. Check the syntax with `/hutbot help`."
    )
    assert sorted(configs) == ["default"]


@pytest.mark.asyncio
async def test_a_typo_does_not_create_a_config():
    app = AsyncMock()
    configs = {"default": DEFAULT_CONFIG.copy()}
    channel = Channel(id="C1", name="davetest", configs=configs)
    user = User("U1", "dave", "Dave", "T")

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "wiat-time 5", channel, user)
        assert "Huh?" in mock_send_message.call_args.args[3]
        # A real command behind a new name still creates it.
        await process_command(app, "alarms wait-time 5", channel, user)

    assert configs["alarms"]["wait_time"] == 300
    assert sorted(configs) == ["alarms", "default"]


@pytest.mark.asyncio
@pytest.mark.parametrize("text", ["", "   ", "\n", "  \n  "])
async def test_a_bare_command_prints_the_help(text):
    """`/hutbot` with nothing after it is someone looking for the command list."""
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")
    with patch('hutbot.messaging.send_message') as send:
        await process_command(app, text, channel, user)
    assert "Here's what I can do" in sent_messages(send)
    assert "Huh?" not in sent_messages(send)


@pytest.mark.asyncio
@pytest.mark.parametrize("text", ["<@U0BOT>", "<@U0BOT> ", "  <@U0BOT>  "])
async def test_a_lone_mention_prints_the_help(text):
    """A mention with no command reduces to empty text once the bot id is stripped."""
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")
    hutbot.state.bot_user_id = "U0BOT"
    with patch('hutbot.messaging.send_message') as send:
        await process_command(app, text, channel, user, allow_test_message=True)
    assert "Here's what I can do" in sent_messages(send)


@pytest.mark.asyncio
async def test_real_nonsense_still_gets_a_hint_not_the_whole_help():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")
    with patch('hutbot.messaging.send_message') as send:
        await process_command(app, "wat is this", channel, user)
    assert "Huh?" in send.call_args.args[3]


@pytest.mark.asyncio
async def test_a_reply_quotes_the_command_it_answers():
    """Every command reply ends with the command that produced it."""
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")
    hutbot.state.slash_command = "/hutbot"
    with patch('hutbot.persistence.save_configuration', new=AsyncMock()):
        await process_command(app, "set wait-time 5", channel, user)
    kwargs = app.client.chat_postEphemeral.await_args.kwargs
    # A `rich_text` block, because mrkdwn cannot put a code block inside a quote: the bar
    # beside the command comes from `border: 1` on the code block itself.
    assert kwargs["blocks"][-1] == {
        "type": "rich_text",
        "elements": [
            {"type": "rich_text_quote",
             "elements": [{"type": "text", "text": "Response to command:"}]},
            {"type": "rich_text_preformatted", "border": 1,
             "elements": [{"type": "text", "text": "/hutbot set wait-time 5"}]},
        ],
    }
    # The notification fallback still spells the footer out, so a push notification is not
    # missing the command the reply answers.
    assert kwargs["text"].endswith("Response to command:\n```\n/hutbot set wait-time 5\n```")


@pytest.mark.asyncio
async def test_a_mention_is_quoted_back_as_the_slash_command():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")
    hutbot.state.slash_command = "/hutbot"
    hutbot.state.bot_user_id = "U0BOT"
    with patch('hutbot.persistence.save_configuration', new=AsyncMock()):
        await process_command(app, "<@U0BOT> set wait-time 7", channel, user, allow_test_message=True)
    kwargs = app.client.chat_postEphemeral.await_args.kwargs
    assert kwargs["blocks"][-1]["elements"][1]["elements"][0]["text"] == "/hutbot set wait-time 7"
    assert "Response to command:\n```\n/hutbot set wait-time 7\n```" in kwargs["text"]


@pytest.mark.asyncio
async def test_a_chunked_reply_is_quoted_once_at_the_end():
    """The help runs to several messages; repeating the footer on each would be noise."""
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")
    await process_command(app, "help", channel, user)
    calls = app.client.chat_postEphemeral.await_args_list
    footers = [[b for b in c.kwargs["blocks"] if b["type"] == "rich_text"] for c in calls]
    assert len(calls) > 1
    assert sum(bool(f) for f in footers) == 1
    assert footers[-1]
    # Every message still fits one section, so no chunk is cut in half by the 3000-char cap.
    assert all(sum(b["type"] == "section" for b in c.kwargs["blocks"]) == 1 for c in calls)


@pytest.mark.asyncio
@pytest.mark.parametrize("command,field,expected", [
    ("set calendar `http://127.0.0.1:8073/calendar.ics?token=abc`", "calendar_url",
     "http://127.0.0.1:8073/calendar.ics?token=abc"),
    ("set pattern `.*alarm.*`", "pattern", ".*alarm.*"),
    ("set message `Hey there`", "reply_message", "Hey there"),
    ("set opsgenie-schedule `Team Primary`", "opsgenie_schedule_name", "Team Primary"),
    ("set datetime-format `02.01.2006` `15:04`", "date_format", "02.01.2006"),
])
async def test_backticks_work_as_quotes(command, field, expected):
    """Slack renders `like this` as code, so people reach for backticks."""
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")
    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message'):
        await process_command(app, command, channel, user)
    assert channel.configs["default"][field] == expected


@pytest.mark.asyncio
async def test_a_backticked_button_label_keeps_its_apostrophe():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")
    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message'):
        await process_command(app, "add button `I've got it` ack `On it`", channel, user)
    assert channel.configs["default"]["buttons"] == [
        {"label": "I've got it", "action": "ack", "value": "On it"}]


# ----- the config that triggered this one -----

@pytest.mark.asyncio
async def test_set_message_accepts_every_parent_variable():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")
    template = " ".join(f"{{{{{variable}}}}}" for variable in sorted(hutbot.constants.PARENT_TEMPLATE_VARIABLES))

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()):
        await process_command(app, f'set message "{template}"', channel, user)

    assert channel.configs["default"]["reply_message"] == template


@pytest.mark.asyncio
async def test_set_message_rejects_a_misspelled_of_argument():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, 'set message "{{parent_variables(of=\\"usre\\")}}"', channel, user)

    assert "`of` names a template variable" in send.call_args.args[3]
    assert channel.configs["default"]["reply_message"] == DEFAULT_CONFIG["reply_message"]


@pytest.mark.asyncio
async def test_the_test_preview_renders_the_parent_variables_as_placeholders():
    """`test` has no parent, so every one of them has to say so rather than show braces."""
    app = AsyncMock()
    app.client.chat_getPermalink.return_value = {"permalink": "https://slack.test/p/1"}
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, "test", channel, user)

    preview = "\n".join(str(arg) for call in send.call_args_list for arg in call.args)
    for variable in hutbot.constants.PARENT_TEMPLATE_VARIABLES:
        assert f"{{{{{variable}}}}}" in preview, variable
    assert "<no-parent>" in preview


@pytest.mark.asyncio
@pytest.mark.parametrize("action,target,expected", [
    ("reply", "", "in a thread in this channel, for everyone here"),
    ("post_channel", "C777", "in a thread in the channel this rule posts to, for everyone there"),
    ("dm_user", "U777", "in a thread in the direct message this rule sends, for its recipient only"),
    ("group_dm", "S123", "in a thread in the group message this rule sends, for its members only"),
])
async def test_adding_an_ack_button_with_text_says_where_that_text_lands(action, target, expected):
    app = AsyncMock()
    channel = _mk_channel({"default": {**DEFAULT_CONFIG.copy(), "action": action, "action_target": target}})
    user = User("U1", "test", "Test User", "Testers")

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as send:
        await process_command(app, 'add button "Got it" ack "On it."', channel, user)

    assert send.await_args.args[3] == (
        f"Added button `Got it` (`ack` → `On it.`) in configuration `default`. "
        f"When pressed, its text is posted {expected}.")


@pytest.mark.asyncio
async def test_an_ack_button_without_text_says_nothing_about_where_text_lands():
    """Nothing is posted, so there is no landing to report."""
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "test", "Test User", "Testers")

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as send:
        await process_command(app, 'add button "Silent" ack', channel, user)
        await process_command(app, 'add button "Run" config other', channel, user)

    for call in send.await_args_list:
        assert "When pressed, its text is posted" not in call.args[3], call.args[3]


def test_message_text_is_split_into_sections_on_line_boundaries():
    """A section holds 3000 characters, and a cut inside a code fence breaks the rest."""
    limit = hutbot.messaging.SLACK_SECTION_TEXT_LIMIT
    text = "\n".join(["x" * 1000] * 5)

    blocks = hutbot.messaging.section_blocks(text)

    # 1000-char lines: two per section, since a third would pass the cap.
    assert [len(b["text"]["text"]) for b in blocks] == [2001, 2001, 1000]
    assert all(len(b["text"]["text"]) <= limit for b in blocks)
    # Every line survives whole, and in order.
    assert "\n".join(b["text"]["text"] for b in blocks) == text


def test_a_line_longer_than_a_section_is_sliced_because_it_has_no_boundary():
    limit = hutbot.messaging.SLACK_SECTION_TEXT_LIMIT

    blocks = hutbot.messaging.section_blocks("y" * (limit + 10))

    assert [len(b["text"]["text"]) for b in blocks] == [limit, 10]


def test_empty_text_still_produces_a_postable_section():
    """Slack rejects an empty section, and a reply is always sent as blocks."""
    assert hutbot.messaging.section_blocks("") == [
        {"type": "section", "text": {"type": "mrkdwn", "text": " "}}]


def test_there_is_no_footer_outside_a_command():
    hutbot.state.current_command.set("")
    assert hutbot.messaging.command_footer_blocks() == []
    assert hutbot.messaging.command_footer() == ""
