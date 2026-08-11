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

        sent_message = mock_send_message.call_args.args[3]
        assert "\n\n*Configuration*: `default` (enabled)" in sent_message
        assert "> *Trigger*: `message`\n>\n> *Reply message*:\n> Default message\n>\n> *Replied to*: <#C123> (in thread)\n>\n> *Settings*:\n```" in sent_message
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

    lines = mock_send_message.call_args.args[3].splitlines()
    assert any(line.startswith("Date/time timezone  Europe/Berlin (") and line.endswith(", server local time)") for line in lines)
    assert "Date/time locale    English names (server locale de_DE not applied)" in lines
    assert "Date/time timezone  Asia/Tokyo (JST, UTC+09:00)" in lines
    assert "Date/time locale    de_DE" in lines
    assert "<server local>" not in mock_send_message.call_args.args[3]



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

    sent_message = mock_send_message.call_args.args[3]
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
    sent_message = mock_send_message.call_args.args[3]
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

    sent_message = mock_send_message.call_args.args[3]
    assert "*Show All Configurations:*" in sent_message
    assert "Either use the command `/hutbot` or just `@Hutbot` me." in sent_message
    assert "```/hutbot show config\n@Hutbot show config```" in sent_message
    assert "Displays all configurations for `#team-asylum`." in sent_message
    assert "*Commands:*\n```" in sent_message
    assert "/hutbot [config] set wait-time <minutes>" in sent_message
    assert "Set reminder delay." in sent_message
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

    sent_message = mock_send_message.call_args.args[3]
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

    sent_message = mock_send_message.call_args.args[3]
    assert "I am *Hutbot (DEV)*" in sent_message
    assert "or just `@hutbot_dev` me." in sent_message
    assert "@hutbot_dev show config```" in sent_message
    assert "@hutbot_dev [config] test <message>" in sent_message
    assert "@Hutbot" not in sent_message



@pytest.mark.asyncio
async def test_set_forward_channel_with_mention():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as mock_send_message:
        await set_forward_channel(app, channel, "default", "<#CFWDCHAN|forward-channel>", user, thread_ts)

    assert channel.configs["default"]["forward_channel"] == "CFWDCHAN"
    app.client.chat_postMessage.assert_awaited_once_with(
        channel="CFWDCHAN",
        text="Reply messages from #general (config `default`) will now be forwarded here by Hutbot :palm_up_hand::tophat:",
        mrkdwn=True,
    )
    mock_send_message.assert_called_with(app, channel, user, "*Forward channel* set to <#CFWDCHAN> in configuration `default`.", thread_ts)



@pytest.mark.asyncio
async def test_show_config_displays_forward_channel():
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(), "forward_channel": "CFWDCHAN"}
    channel = Channel(id="C123", name="general", configs={"default": config})
    user = User(id="U123", name="test", real_name="Test User", team="A")

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await show_config(app, channel, user, "")

    sent_message = mock_send_message.call_args.args[3]
    assert "*Replied to*: <#C123> (in thread)\n> *Forwarded to*: <#CFWDCHAN>" in sent_message



@pytest.mark.asyncio
async def test_show_config_omits_forward_line_without_forward_channel():
    app = AsyncMock()
    channel = Channel(id="C123", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User(id="U123", name="test", real_name="Test User", team="A")

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await show_config(app, channel, user, "")

    sent_message = mock_send_message.call_args.args[3]
    assert "*Replied to*: <#C123> (in thread)" in sent_message
    assert "Forwarded to" not in sent_message



@pytest.mark.asyncio
async def test_show_config_names_the_destination_per_action():
    app = AsyncMock()
    configs = {
        "post": {**DEFAULT_CONFIG.copy(), "action": ACTION_POST_CHANNEL, "action_target": "<#CTARGET|targets>"},
        "dm": {**DEFAULT_CONFIG.copy(), "action": ACTION_DM_USER, "action_target": "d.grieser@mittwald.de"},
        "group": {**DEFAULT_CONFIG.copy(), "action": ACTION_GROUP_DM, "action_target": "SGROUP"},
        "scheduled": {**DEFAULT_CONFIG.copy(), "trigger": TRIGGER_SCHEDULE, "schedule_cron": "0 9 * * 1-5"},
    }
    channel = Channel(id="C123", name="general", configs=configs)
    user = User(id="U123", name="test", real_name="Test User", team="A")

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await show_config(app, channel, user, "")

    sent_message = mock_send_message.call_args.args[3]
    assert "*Posted to*: <#CTARGET>" in sent_message
    assert "*Sent to*: `d.grieser@mittwald.de` (direct message)" in sent_message
    assert "*Sent to*: <!subteam^SGROUP> (group message)" in sent_message
    # No message to thread on for a schedule trigger.
    assert "*Replied to*: <#C123>\n" in sent_message
    assert "Cron                0 9 * * 1-5" in sent_message
    assert any(line.startswith("Schedule timezone   ") and "server local" in line for line in sent_message.splitlines())
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

    sent_message = mock_send.call_args[0][3]
    assert "\n\n*Configuration*: `default` (enabled)" in sent_message



@pytest.mark.asyncio
async def test_show_config_displays_replies_disabled():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": {**DEFAULT_CONFIG.copy(), "enabled": False}})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('hutbot.messaging.send_message') as mock_send:
        await show_config(app, channel, user)

    sent_message = mock_send.call_args[0][3]
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
        await process_command(app, 'set button-timeout 5', ch, u)
        await process_command(app, 'set default-button "Yes"', ch, u)
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

    sent_message = mock_send_message.call_args.args[3]
    assert "*Configuration*: `removed` (disabled, because Hutbot was removed from this channel)" in sent_message
    assert "*Configuration*: `by-hand` (disabled)" in sent_message
