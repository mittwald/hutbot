from tests._common import *  # noqa: F401,F403



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

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await show_config(app, channel, user, "")

        sent_message = sent_messages(mock_send_message)
        assert "\n\n*Configuration*: `default` (enabled)" in sent_message
        assert "> *Trigger*: `message`\n>\n> *Reply message*:\n> Default message\n>\n> *Replied in* <#C123> (in thread)\n>\n> *Settings*:\n```" in sent_message
        assert "\nTrigger" not in sent_message
        assert "OpsGenie schedule" in sent_message
        assert "OpsGenie priority   P4" in sent_message
        # Settings are grouped, each group separated by a blank line.
        assert (
            "Wait time           10 minutes\n"
            "Only work days      disabled\n"
            "Work hours          all day\n"
            "\n"
            "OpsGenie            disabled"
        ) in sent_message
        assert "Date format         %a, %d %b %Y" in sent_message
        assert "Time format         %H:%M" in sent_message
        assert "Wait time           10 minutes" in sent_message
        assert "Default message" in sent_message
        assert "\n\n*Configuration*: `alarms` (enabled)" in sent_message
        assert "Wait time           5 minutes" in sent_message
        assert "Pattern             .*alarm.* (case-insensitive)" in sent_message
        assert "Alarm message" in sent_message



@pytest.mark.asyncio
async def test_show_config_resolves_the_server_timezone_and_locale():
    app = AsyncMock()
    configs = {
        "default": DEFAULT_CONFIG.copy(),
        "tokyo": {**DEFAULT_CONFIG.copy(), "datetime_timezone": "Asia/Tokyo", "datetime_locale": "de-DE"},
    }
    channel = Channel(id="C123", name="general", configs=configs)
    user = User(id="U123", name="test", real_name="Test User", team="A")

    with patch.dict(os.environ, {"TZ": "Europe/Berlin"}), \
         patch('hutbot.datetimefmt.get_server_locale_name', return_value="de_DE"), \
         patch('hutbot.messaging.send_message') as mock_send_message:
        await show_config(app, channel, user, "")

    lines = sent_messages(mock_send_message).splitlines()
    assert any(line.startswith("Date/time timezone  Europe/Berlin (") and line.endswith(", server local time)") for line in lines)
    assert "Date/time locale    English names (server locale de_DE not applied)" in lines
    assert "Date/time timezone  Asia/Tokyo (JST, UTC+09:00)" in lines
    assert "Date/time locale    de_DE" in lines
    assert "<server local>" not in sent_messages(mock_send_message)



@pytest.mark.asyncio
async def test_show_config_displays_multiline_team_values():
    app = AsyncMock()
    config = {
        **DEFAULT_CONFIG.copy(),
        "excluded_teams": [
            "Cloud Hosting",
            "m-kubed (m³)",
            "Systemarchitektur Infrastruktur/Technik",
            "Site Reliability",
        ],
    }
    channel = Channel(id="C123", name="general", configs={"default": config})
    user = User(id="U123", name="test", real_name="Test User", team="A")

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await show_config(app, channel, user, "")

    sent_message = sent_messages(mock_send_message)
    assert (
        "Excluded teams      Cloud Hosting\n"
        "                    m-kubed (m³)\n"
        "                    Systemarchitektur Infrastruktur/Technik\n"
        "                    Site Reliability"
    ) in sent_message



@pytest.mark.asyncio
async def test_process_command_mention_test_uses_trailing_text_as_message():
    import hutbot
    app = AsyncMock()
    app.client.chat_getPermalink.return_value = {"permalink": "https://slack.test/message"}
    app.client.chat_postMessage.return_value = {"ts": "1234.1"}
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    channel.configs["default"]["reply_message"] = "Preview: {{message}} {{timestamp}} {{message_link}}"
    user = User("U12345", "test", "Test User", "Testers")

    with patch.object(hutbot.state, 'bot_user_id', "UBOT"), \
         patch('hutbot.opsgenie.get_opsgenie_template_variables', new=AsyncMock(return_value={})), \
         patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "<@UBOT> test hello world", channel, user, "1234.1", allow_test_message=True, command_ts="1234.1")

    app.client.chat_getPermalink.assert_awaited_once_with(channel="C12345", message_ts="1234.1")
    sent_message = sent_messages(mock_send_message)
    assert "Preview: hello world 1234.1 https://slack.test/message" in sent_message
    assert "`{{message}}`: hello world" in sent_message
    assert "`{{timestamp}}`: 1234.1" in sent_message
    assert "`{{message_link}}`: https://slack.test/message" in sent_message



@pytest.mark.asyncio
async def test_process_command_help_uses_compact_command_reference():
    app = AsyncMock()
    channel = Channel(id="C12345", name="team-asylum", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "help", channel, user)

    sent_message = sent_messages(mock_send_message)
    assert "*Show All Configurations:*" in sent_message
    assert "Either use the command `/hutbot` or just `@Hutbot` me." in sent_message
    assert "```/hutbot show config\n@Hutbot show config```" in sent_message
    assert "Displays all configurations for `#team-asylum`." in sent_message
    assert "*Commands:*\n```" in sent_message
    assert "/hutbot [config] set wait-time <minutes>" in sent_message
    assert "Set reminder delay." in sent_message
    # Commands are grouped, each group headed and separated by a blank line.
    assert "# Configurations\n/hutbot show config" in sent_message
    assert "\n\n# Trigger\n" in sent_message
    assert "\n\n# OpsGenie\n" in sent_message
    assert "\n\n# Help\n/hutbot news" in sent_message
    assert sent_message.index("# Trigger") < sent_message.index("# When to react") < sent_message.index("# Buttons")
    assert "/hutbot [config] set work-hours all day" in sent_message
    assert "/hutbot [config] set trigger cron \"<expr>\"" in sent_message
    # Removed commands are gone from the reference.
    for stale in ("set target", "set cron <", "set schedule-timezone", "forward-channel",
                  "button-timeout", "default-button"):
        assert stale not in sent_message, stale
    # Every dispatched command is documented.
    assert "/hutbot [config] clear opsgenie-message" in sent_message
    assert '/hutbot [config] set escalation <minutes> button "<label>"' in sent_message
    assert "/hutbot [config] set escalation none" in sent_message
    assert "/hutbot [config] clear pattern" in sent_message
    assert "@Hutbot [config] test <message>" in sent_message
    assert "Preview reply with <message> as {{message}}." in sent_message
    assert "*Enable OpsGenie Integration:*" not in sent_message



@pytest.mark.asyncio
async def test_process_command_help_uses_configured_slash_command():
    app = AsyncMock()
    channel = Channel(id="C12345", name="team-asylum", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('hutbot.state.slash_command', '/hutbot_dev'), \
         patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "help", channel, user)

    sent_message = sent_messages(mock_send_message)
    assert "Either use the command `/hutbot_dev` or just `@Hutbot` me." in sent_message
    assert "/hutbot_dev [config] set wait-time <minutes>" in sent_message
    assert "/hutbot " not in sent_message



@pytest.mark.asyncio
async def test_process_command_help_uses_configured_bot_name():
    app = AsyncMock()
    channel = Channel(id="C12345", name="team-asylum", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('hutbot.state.bot_name', 'Hutbot (DEV)'), \
         patch('hutbot.state.bot_user_name', 'hutbot_dev'), \
         patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "help", channel, user)

    sent_message = sent_messages(mock_send_message)
    assert "I am *Hutbot (DEV)*" in sent_message
    assert "or just `@hutbot_dev` me." in sent_message
    assert "@hutbot_dev show config```" in sent_message
    assert "@hutbot_dev [config] test <message>" in sent_message
    assert "@Hutbot" not in sent_message


@pytest.mark.asyncio
async def test_show_config_names_the_destination_per_action():
    app = AsyncMock()
    configs = {
        "post": {**DEFAULT_CONFIG.copy(), "action": ACTION_POST_CHANNEL, "action_target": "<#CTARGET|targets>"},
        "dm": {**DEFAULT_CONFIG.copy(), "action": ACTION_DM_USER, "action_target": "d.grieser@mittwald.de"},
        "group": {**DEFAULT_CONFIG.copy(), "action": ACTION_GROUP_DM, "action_target": "SGROUP"},
        "scheduled": {**DEFAULT_CONFIG.copy(), "trigger": TRIGGER_CRON, "cron": "0 9 * * 1-5"},
    }
    channel = Channel(id="C123", name="general", configs=configs)
    user = User(id="U123", name="test", real_name="Test User", team="A")

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await show_config(app, channel, user, "")

    sent_message = sent_messages(mock_send_message)
    assert "*Posted in* <#CTARGET>" in sent_message
    assert "*Sent to* `d.grieser@mittwald.de` (direct message)" in sent_message
    assert "*Sent to* <!subteam^SGROUP> (group message)" in sent_message
    # No message to thread on for a schedule trigger.
    assert "*Replied in* <#C123>\n" in sent_message
    # The cron expression rides with the trigger, not as a settings row.
    assert "> *Trigger*: `cron` `0 9 * * 1-5`" in sent_message
    assert "\nCron " not in sent_message
    # Non-reply actions title their template "Message", not "Reply message".
    assert "*Message*:" in sent_message
    assert "Action target" not in sent_message



@pytest.mark.asyncio
async def test_show_config_displays_replies_enabled():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": {**DEFAULT_CONFIG.copy(), "enabled": True}})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('hutbot.messaging.send_message') as mock_send:
        await show_config(app, channel, user)

    sent_message = sent_messages(mock_send)
    assert "\n\n*Configuration*: `default` (enabled)" in sent_message



@pytest.mark.asyncio
async def test_show_config_displays_replies_disabled():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": {**DEFAULT_CONFIG.copy(), "enabled": False}})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('hutbot.messaging.send_message') as mock_send:
        await show_config(app, channel, user)

    sent_message = sent_messages(mock_send)
    assert "\n\n*Configuration*: `default` (disabled)" in sent_message



@pytest.mark.asyncio
async def test_need_help_yes_no_workflow_end_to_end():
    # "Need help?" with Yes (message) / No (ack); wait 5m ⇒ auto-press Yes.
    app = AsyncMock()
    app.client.chat_getPermalink.return_value = {"permalink": "p"}
    app.client.chat_postMessage.return_value = {"ts": "R1"}
    ch = Channel(id="C1", name="support", configs={})
    u = User("U1", "dave", "Dave", "T")
    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), patch('hutbot.messaging.send_message', new=AsyncMock()), \
         patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()), patch('hutbot.persistence.flush_button_cache', new=AsyncMock()):
        await process_command(app, 'set message Need help?', ch, u)
        await process_command(app, 'add button "Yes" message "Here is the help doc"', ch, u)
        await process_command(app, 'add button "No" ack', ch, u)
        await process_command(app, 'set escalation 5 button "Yes"', ch, u)
        cfg = ch.configs["default"]

        # Fire the reply; an auto-press-Yes escalation is registered (no inline message yet).
        hutbot.state.pending_buttons.clear()
        await hutbot.scheduling.schedule_reply(app, "tok", ch, cfg, "default", u, "orig", "M1", wait_time_override=0)
        entry = hutbot.state.pending_buttons.get(("C1", "R1"))
        assert entry is not None and entry["escalation_kind"] == "button" and entry["escalation_target"] == "Yes"
        # Drop the live 5-minute timer; we trigger the escalation manually below.
        if entry["task"]:
            entry["task"].cancel()

        # No press within timeout ⇒ escalation auto-presses Yes ⇒ posts the help message.
        with patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=Channel("C1", "support", ch.configs))), \
             patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=u)), \
             patch('hutbot.messaging._post_message', new=AsyncMock()) as post:
            await hutbot.buttons._escalation_task(app, "tok", ("C1", "R1"), 0)
        post.assert_awaited_once_with(app, "C1", "Here is the help doc", None, "R1")
    await asyncio.sleep(0)  # let the cancelled timer settle


@pytest.mark.asyncio
async def test_show_config_explains_an_automatic_disable():
    app = AsyncMock()
    configs = {
        "removed": {**DEFAULT_CONFIG.copy(), "enabled": False, "disabled_reason": DISABLED_REASON_REMOVED},
        "by-hand": {**DEFAULT_CONFIG.copy(), "enabled": False},
    }
    channel = Channel(id="C123", name="general", configs=configs)
    user = User(id="U123", name="test", real_name="Test User", team="A")
    hutbot.state.bot_name = "Hutbot"

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await show_config(app, channel, user, "")

    sent_message = sent_messages(mock_send_message)
    assert "*Configuration*: `removed` (disabled, because Hutbot was removed from this channel)" in sent_message
    assert "*Configuration*: `by-hand` (disabled)" in sent_message


@pytest.mark.asyncio
async def test_show_config_marks_the_instance_default_locale():
    app = AsyncMock()
    channel = Channel(id="C123", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User(id="U123", name="test", real_name="Test User", team="A")

    with patch('hutbot.state.default_datetime_locale', "de_DE"), \
         patch('hutbot.messaging.send_message') as mock_send_message:
        await show_config(app, channel, user, "")

    assert "Date/time locale    de_DE (instance default)" in sent_messages(mock_send_message).splitlines()


@pytest.mark.asyncio
@pytest.mark.parametrize("command", ["help", "news"])
async def test_help_and_news_name_the_running_version(command):
    app = AsyncMock()
    channel = Channel(id="C1", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U1", "test", "Test User", "Testers")

    with patch('hutbot.state.version', "v1.2.3"), \
         patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, command, channel, user)

    assert "I am *Hutbot* `v1.2.3` :palm_up_hand::tophat:" in sent_messages(mock_send_message)


@pytest.mark.asyncio
async def test_help_is_split_into_messages_slack_will_not_cut_apart():
    import hutbot
    app = AsyncMock()
    channel = Channel(id="C1", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U1", "test", "Test User", "Testers")

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "help", channel, user)

    texts = [call.args[3] for call in mock_send_message.call_args_list]
    assert len(texts) > 1
    for text in texts:
        assert len(text) <= hutbot.messaging.SLACK_MESSAGE_CHARACTER_LIMIT, len(text)
        # Every code fence a message opens, it also closes.
        assert text.count("```") % 2 == 0, text
    assert "*Commands:*" in texts[1]
    assert "*Commands (continued):*" in texts[2]


@pytest.mark.asyncio
async def test_show_config_splits_many_configs_into_several_messages():
    import hutbot
    app = AsyncMock()
    configs = {f"config-{index}": DEFAULT_CONFIG.copy() for index in range(8)}
    channel = Channel(id="C1", name="general", configs=configs)
    user = User("U1", "test", "Test User", "Testers")

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await show_config(app, channel, user, "")

    texts = [call.args[3] for call in mock_send_message.call_args_list]
    assert len(texts) > 1
    for text in texts:
        assert len(text) <= hutbot.messaging.SLACK_MESSAGE_CHARACTER_LIMIT, len(text)
        assert text.count("```") % 2 == 0, text
    # No config is spread over two messages.
    joined = sent_messages(mock_send_message)
    for name in configs:
        assert joined.count(f"*Configuration*: `{name}`") == 1


def test_pack_message_chunks_keeps_an_oversized_part_whole():
    import hutbot
    parts = ["a" * 3000, "b" * 3000, "c" * 5000]

    chunks = hutbot.messaging.pack_message_chunks(parts)

    assert chunks == ["a" * 3000, "b" * 3000, "c" * 5000]
    assert hutbot.messaging.pack_message_chunks(["x", "y"]) == ["x\n\ny"]
    assert hutbot.messaging.pack_message_chunks([]) == []
