import copy

from tests._common import *  # noqa: F401,F403



@pytest.mark.asyncio
async def test_show_config():
    app = AsyncMock()
    configs = {
        "alarms": {"pattern": ".*alarm.*", "wait_time": 300, "reply_message": "Alarm message", "opsgenie": True},
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
        # Details only where OpsGenie is on; the disabled config shows just the one row.
        assert "OpsGenie schedule" in sent_message
        assert "OpsGenie priority" in sent_message
        assert any(line.startswith("OpsGenie ") and line.endswith("disabled (not configured)") for line in sent_message.splitlines())
        # Settings are grouped, each group separated by a blank line.
        assert (
            "Wait time       10 minutes\n"
            "Only work days  disabled\n"
            "Work hours      any hour"
        ) in sent_message
        assert "Wait time       10 minutes" in sent_message
        assert "Default message" in sent_message
        assert "\n\n*Configuration*: `alarms` (enabled)" in sent_message
        assert "Wait time          5 minutes" in sent_message  # wider column: the OpsGenie rows
        assert "Pattern            .*alarm.* (case-insensitive)" in sent_message
        assert "Alarm message" in sent_message



@pytest.mark.asyncio
async def test_show_config_resolves_the_server_timezone_and_locale():
    app = AsyncMock()
    configs = {
        "default": {**DEFAULT_CONFIG.copy(), "reply_message": "at {{time}}"},
        "tokyo": {**DEFAULT_CONFIG.copy(), "reply_message": "at {{time}}",
                  "datetime_timezone": "Asia/Tokyo", "datetime_locale": "de-DE"},
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
    first = next(line for line in sent_message.splitlines() if line.startswith("Excluded teams"))
    indent = " " * (len(first) - len("Cloud Hosting"))
    assert (
        f"{first}\n"
        f"{indent}m-kubed (m³)\n"
        f"{indent}Systemarchitektur Infrastruktur/Technik\n"
        f"{indent}Site Reliability"
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
    # Not "\n\n# OpsGenie": a group can land at the top of a continuation message.
    assert "# OpsGenie\n/hutbot [config] enable opsgenie" in sent_message
    assert "# Help\n/hutbot news" in sent_message
    assert sent_message.index("# Trigger") < sent_message.index("# When to react") < sent_message.index("# Buttons")
    assert "/hutbot [config] clear work-hours" in sent_message
    assert "/hutbot [config] set trigger cron \"<expr>\"" in sent_message
    # Removed commands are gone from the reference.
    for stale in ("set target", "set cron <", "set schedule-timezone", "forward-channel",
                  "button-timeout", "default-button"):
        assert stale not in sent_message, stale
    # Every dispatched command is documented.
    assert "/hutbot [config] clear opsgenie-message" in sent_message
    # Past the column limit a command stacks its arguments; see the wrapping test below.
    assert "/hutbot [config] set escalation " in sent_message
    assert '\n                     button "<label>"' in sent_message
    assert "/hutbot [config] clear escalation" in sent_message
    assert "/hutbot [config] clear pattern" in sent_message
    assert "@Hutbot [config] test <message>" in sent_message
    assert "Preview it with <message> as {{message}}." in sent_message
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
        await process_command(app, 'add button "Yes" ack "Here is the help doc"', ch, u)
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

    channel.configs["default"]["reply_message"] = "at {{time}}"
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
@pytest.mark.parametrize("command", ["help variables", "help variable", "help vars", "help var",
                                     "help placeholders", "help template-variables"])
async def test_help_variables_documents_every_variable_and_operator(command):
    import hutbot
    app = AsyncMock()
    channel = Channel(id="C1", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U1", "test", "Test User", "Testers")

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, command, channel, user)

    texts = [call.args[3] for call in mock_send_message.call_args_list]
    sent_message = sent_messages(mock_send_message)
    for variable in SUPPORTED_TEMPLATE_VARIABLES:
        assert f"`{{{{{variable}}}}}`" in sent_message, variable
    for operator in CONDITION_OPERATORS_ORDERED:
        assert f"`{operator}`" in sent_message, operator
    # Grouped by where the variable comes from, not one flat list.
    for title in ("*Message, sender and config*", "*Date and time*", "*OpsGenie*", "*Calendar*"):
        assert title in sent_message, title
    assert "*Condition operators*" in sent_message
    assert "`{{calendar_attendees(nth=2)}}` is the second" in sent_message
    # Both calendar arguments are documented, and so is the condition spelling.
    assert "`{{calendar_summary(offset=next)}}` the one after it" in sent_message
    assert "or as a signed offset from now: `+2h`" in sent_message
    assert "add condition calendar_summary(at=+1d) contains Wartung" in sent_message
    assert "`fmt`/`format`, `tz`/`timezone` and `lc`/`locale`" in sent_message
    # The command table stays in `help`; this reply is only the variables.
    assert "*Commands:*" not in sent_message
    for text in texts:
        assert len(text) <= hutbot.messaging.SLACK_MESSAGE_CHARACTER_LIMIT, len(text)


@pytest.mark.asyncio
async def test_help_points_at_the_variables_help_instead_of_listing_them():
    app = AsyncMock()
    channel = Channel(id="C1", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U1", "test", "Test User", "Testers")

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "help", channel, user)

    sent_message = sent_messages(mock_send_message)
    assert "/hutbot help variables" in sent_message
    assert "`[config]` is optional; omitted commands use `default`." in sent_message
    # The lists themselves moved out of the command help.
    assert "Supported reply variables:" not in sent_message
    assert "Supported condition operators:" not in sent_message
    assert "{{opsgenie_current_start_datetime}}" not in sent_message


@pytest.mark.asyncio
async def test_show_config_splits_many_configs_into_several_messages():
    import hutbot
    app = AsyncMock()
    configs = {f"config-{index}": {**DEFAULT_CONFIG.copy(), "reply_message": "at {{time}}"} for index in range(8)}
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


@pytest.mark.asyncio
async def test_show_config_hides_settings_that_do_not_apply():
    app = AsyncMock()
    configs = {
        # manual: no matching, no reminder delay, no work hours, nothing renders a date
        "post": {**DEFAULT_CONFIG.copy(), "trigger": "manual", "reply_message": ":x: pressed"},
        # cron with a date in its message: condition + full date/time block
        "standup": {**DEFAULT_CONFIG.copy(), "trigger": TRIGGER_CRON, "cron": "0 9 * * 1-5",
                    "reply_message": "Standup at {{time}}",
                    "conditions": [{"variable": "calendar_summary", "operator": "contains",
                                    "value": "standup", "case_sensitive": False}]},
        # message trigger with work hours: timezone only, no formats
        "watch": {**DEFAULT_CONFIG.copy(), "hours": ["9:00", "17:00"]},
    }
    channel = Channel(id="C1", name="davetest", configs=configs)
    user = User("U1", "dave", "Dave", "T")

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await show_config(app, channel, user, "")

    sections = {name: part for name, part in
                ((p.split("`")[1], p) for p in sent_messages(mock_send_message).split("*Configuration*: ")[1:])}

    manual = sections["post"]
    for mute in ("Pattern", "Included teams", "Include bots", "Wait time", "Only work days",
                 "Work hours", "Date format", "Date/time timezone", "Conditions", "Calendar"):
        assert mute not in manual, mute
    assert "OpsGenie" in manual

    cron = sections["standup"]
    # Conditions gate every trigger now, and a single one needs no `Match` row.
    assert '{{calendar_summary}} contains "standup"' in cron
    assert "Conditions" in cron and "Match" not in cron
    assert "Date format" in cron and "Date/time locale" in cron
    for mute in ("Pattern", "Wait time", "Work hours", "Include bots"):
        assert mute not in cron, mute

    watch = sections["watch"]
    assert "Work hours          9:00 - 17:00" in watch
    # Work hours are counted in that timezone, but nothing renders a date.
    assert "Date/time timezone" in watch
    assert "Date format" not in watch and "Date/time locale" not in watch

    assert "_Only the settings that apply to each configuration are shown._" in sent_messages(mock_send_message)


@pytest.mark.asyncio
async def test_show_config_hides_a_condition_on_a_non_cron_trigger():
    app = AsyncMock()
    # A condition is only evaluated when a cron fires, so it is noise elsewhere.
    config = {**DEFAULT_CONFIG.copy(), "condition": "outlook_calendar", "outlook_subject_pattern": ".*x.*"}
    channel = Channel(id="C1", name="davetest", configs={"default": config})
    user = User("U1", "dave", "Dave", "T")

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await show_config(app, channel, user, "")

    sent_message = sent_messages(mock_send_message)
    assert "Condition" not in sent_message
    assert "Outlook subject" not in sent_message


@pytest.mark.asyncio
async def test_process_command_list_calendars():
    app = AsyncMock()
    channel = Channel(id="C1", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U1", "test", "Test User", "Testers")

    with _patch_builtin_calendars(), patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "list calendars", channel, user)

    message = mock_send_message.call_args.args[3]
    assert message.startswith("*Built-in calendars*:\n`holidays` — Company holidays\n`rota` — Platform on-call rota")
    assert "set calendar <name>" in message
    # Name and title only: the feed URL belongs to the instance, not to the channel.
    assert "cal.example.com" not in message and "SECRETTOKEN" not in message


@pytest.mark.asyncio
async def test_process_command_list_calendars_names_one_without_a_title():
    """A bridge calendar whose ICS has not been read yet is listed by its name."""
    app = AsyncMock()
    channel = Channel(id="C1", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U1", "test", "Test User", "Testers")
    untitled = [BuiltinCalendar("rota", "", "https://cal.example.com/SECRETTOKEN/rota.ics", True)]

    with _patch_builtin_calendars(untitled), patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "list calendars", channel, user)

    message = mock_send_message.call_args.args[3]
    assert "`rota` — rota" in message


@pytest.mark.asyncio
async def test_process_command_list_calendars_without_any():
    app = AsyncMock()
    channel = Channel(id="C1", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U1", "test", "Test User", "Testers")

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "list calendars", channel, user)

    assert "No built-in calendars are configured" in mock_send_message.call_args.args[3]


@pytest.mark.asyncio
@pytest.mark.parametrize("action,target,expected", [
    ("reply", "", "in a thread in this channel, for everyone here"),
    ("post_channel", "C777", "in a thread in the channel this rule posts to, for everyone there"),
    # The one the destination line alone does not answer: an ack on a DM'd message is a reply
    # inside that DM, and never reaches the channel the rule lives in.
    ("dm_user", "U777", "in a thread in the direct message this rule sends, for its recipient only"),
    ("group_dm", "S123", "in a thread in the group message this rule sends, for its members only"),
])
async def test_show_config_says_where_an_ack_text_lands(action, target, expected):
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(), "action": action, "action_target": target, "buttons": [
        {"label": "Silent", "action": "ack", "value": ""},
        {"label": "I've got it", "action": "ack", "value": "On it, thanks!"},
    ]}
    channel = Channel(id="C123", name="general", configs={"default": config})
    user = User(id="U123", name="test", real_name="Test User", team="A")

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await show_config(app, channel, user, "")

    sent_message = sent_messages(mock_send_message)
    assert f"Ack text        {expected}" in sent_message


@pytest.mark.asyncio
async def test_show_config_omits_the_ack_note_when_no_ack_button_posts_text():
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(), "buttons": [
        {"label": "Silent", "action": "ack", "value": ""},
        {"label": "Run", "action": "config", "value": "other"},
    ]}
    channel = Channel(id="C123", name="general", configs={"default": config})
    user = User(id="U123", name="test", real_name="Test User", team="A")

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await show_config(app, channel, user, "")

    assert "Ack text" not in sent_messages(mock_send_message)


@pytest.mark.asyncio
async def test_help_variables_groups_and_explains_the_press_family():
    app = AsyncMock()
    channel = Channel(id="C1", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U1", "test", "Test User", "Testers")

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "help variables", channel, user)

    sent_message = sent_messages(mock_send_message)
    assert "*The button press that ran this*" in sent_message
    for variable in hutbot.constants.PRESS_TEMPLATE_VARIABLES:
        assert f"`{{{{{variable}}}}}`" in sent_message, variable
    # The two things the family exists for: naming the presser, and telling a real press
    # from a timeout that pressed for them.
    assert "`{{press_kind}}` is `user` when a person pressed and `timeout` when nobody did" in sent_message
    assert "`<no-press>` anywhere else" in sent_message


# ----- the help table's command column -----

def test_a_command_splits_into_the_words_to_type_and_the_values_to_fill_in():
    split = hutbot.messaging.split_command_spec

    assert split("/hutbot [config] add condition <var> <operator> [value] [0|1]") == (
        "/hutbot [config] add condition", ["<var>", "<operator>", "[value]", "[0|1]"])
    # A keyword that introduces a value stays with it: neither half means anything alone.
    assert split('/hutbot [config] set escalation <minutes> button "<label>"') == (
        "/hutbot [config] set escalation", ["<minutes>", 'button "<label>"'])
    # A bracketed group is one argument, quotes and nesting included.
    assert split('/hutbot [config] set datetime-format "<date>" "<time>" [<tz> <locale>]') == (
        "/hutbot [config] set datetime-format", ['"<date>"', '"<time>"', "[<tz> <locale>]"])
    # `[config]` belongs to the head; a command without arguments is all head.
    assert split("/hutbot [config] clear buttons") == ("/hutbot [config] clear buttons", [])


def test_the_command_column_is_capped_but_never_narrower_than_the_longest_head():
    width = hutbot.messaging.command_column_width
    limit = hutbot.messaging.COMMAND_COLUMN_LIMIT

    # Short commands keep a short column: the limit is a ceiling, not a target.
    assert width(["/hutbot help", "/hutbot news"]) == len("/hutbot help")
    # A command past the limit does not set the width — it wraps, so only its head has to
    # fit the column.
    outlier = '/hutbot [config] set datetime-format "<date>" "<time>" [<tz> <locale>]'
    assert len(outlier) > limit
    assert width(["/hutbot [config] clear buttons", outlier]) == len("/hutbot [config] set datetime-format")
    # A head longer than the limit still gets its column, or it would have nowhere to go.
    head = "/hutbot [config] " + "a" * limit
    assert width([f"{head} <value>"]) == len(head)


def test_a_long_command_fills_the_column_and_stacks_the_rest_under_its_head():
    rows = [('/hutbot [config] set datetime-format "<date>" "<time>" [<tz> <locale>]',
             "Date/time output."),
            ("/hutbot [config] clear calendar", "Stop reading a calendar feed.")]
    width = hutbot.messaging.command_column_width([command for command, _ in rows])

    lines = hutbot.messaging.format_command_rows(rows, width)

    # Here the column is exactly the long command's head — the other row is shorter — so its
    # first line has no room to spare and every argument goes underneath.
    assert width == len("/hutbot [config] set datetime-format")
    assert lines == [
        "/hutbot [config] set datetime-format  Date/time output.",
        '                     "<date>"',
        '                     "<time>"',
        "                     [<tz> <locale>]",
        "/hutbot [config] clear calendar       Stop reading a calendar feed.",
    ]
    # Nothing overruns the column, and the description keeps its two spaces.
    assert all(len(line.split("  ")[0]) <= width for line in lines)


def test_commands_sharing_a_head_break_at_the_same_argument():
    """Three spellings of one command, so three different break points read as three commands."""
    rows = [('/hutbot [config] add button "<label>" config <config>', "Run another config."),
            ('/hutbot [config] add button "<label>" ack [text]', "Mark it handled.")]
    # A column the short spelling fits in whole and the long one does not.
    lines = hutbot.messaging.format_command_rows(rows, len('/hutbot [config] add button "<label>" ack [text]'))

    assert lines == [
        '/hutbot [config] add button "<label>"             Run another config.',
        "                     config <config>",
        '/hutbot [config] add button "<label>"             Mark it handled.',
        "                     ack [text]",
    ]


def test_a_wrapped_row_fills_the_first_line_up_to_the_column():
    """The point of the wrap: use the column, do not stack what still fits beside the head."""
    rows = [("/hutbot [config] add condition <var> <operator> [value] [0|1]", "Gate this rule."),
            ("/hutbot [config] clear conditions and then some padding", "Ungate it.")]
    width = hutbot.messaging.command_column_width([command for command, _ in rows])

    lines = hutbot.messaging.format_command_rows(rows, width)

    assert lines[0].startswith("/hutbot [config] add condition <var> <operator> [value]")
    assert lines[1] == "                     [0|1]"
    # Two spaces is the minimum, and the column is never overrun.
    assert lines[0][width:width + 2] == "  "
    assert all(len(line.rstrip()) <= width for line in lines[1:] if not line.strip().startswith("/"))


def test_an_argument_wider_than_the_column_still_gets_its_own_line():
    """Nowhere to break it, so it overruns alone rather than being dropped or looping."""
    rows = [("/hutbot set thing <a-very-long-single-argument-nothing-can-split>", "Set it.")]

    lines = hutbot.messaging.format_command_rows(rows, len("/hutbot set thing"))

    assert lines == [
        "/hutbot set thing  Set it.",
        "            <a-very-long-single-argument-nothing-can-split>",
    ]


@pytest.mark.asyncio
async def test_show_config_keeps_a_code_block_in_the_message_out_of_the_quote():
    """Slack prints a `>` inside a code block, so the block steps out of the quote instead."""
    app = AsyncMock()
    message = ("Nicht bestätigt :x:\n{{user}} steht im Kalender.\n"
               "```\nBeginn: {{date}}\nEnde:   {{time}}\n```\n")
    config = {**DEFAULT_CONFIG.copy(), "trigger": "manual", "reply_message": message}
    channel = Channel(id="C123", name="general", configs={"default": config})
    user = User(id="U1", name="test", real_name="Test User", team="A")

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await show_config(app, channel, user, "")

    sent_message = sent_messages(mock_send_message)
    assert ("> *Reply message*:\n"
            "> Nicht bestätigt :x:\n"
            "> {{user}} steht im Kalender.\n"
            "```\n"
            "Beginn: {{date}}\n"
            "Ende:   {{time}}\n"
            "```\n"
            "> *Replied in*") in sent_message
    # The lines around it are still quoted, and no separator is left stranded next to the
    # block, where it would render as a bare `>` of its own.
    assert "> *Trigger*: `manual`" in sent_message
    assert "```\n>\n" not in sent_message
    assert "\n>\n```" not in sent_message


def test_quote_lines_quotes_everything_but_a_fenced_block():
    quote = hutbot.messaging.quote_lines

    assert quote("a\n\nb") == "> a\n>\n> b"
    assert quote("before\n```\nx\n> y\n```\nafter") == "> before\n```\nx\n> y\n```\n> after"
    # A blank line beside the block would open or close a quote with nothing in it, which
    # Slack renders as a bare `>`; between two quoted lines it is a real gap and stays.
    assert quote("before\n\n```\nx\n```\n\nafter") == "> before\n```\nx\n```\n> after"
    assert quote("\nbefore\n\nafter\n") == "> before\n>\n> after"
    # An unterminated fence leaves the rest unquoted rather than quoting into the block.
    assert quote("before\n```\nx") == "> before\n```\nx"
    # A fence opened and closed on one line is not a block, so the next line is quoted again.
    assert quote("`​``x```\nafter".replace("\u200b", "")) == "```x```\n> after"


@pytest.mark.asyncio
async def test_show_config_keeps_the_settings_table_intact_around_awkward_values():
    """A template can carry line breaks and a fence of its own; the table survives both."""
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(), "opsgenie": True, "opsgenie_message": "Line one\nLine two",
              "buttons": [{"label": "Got it", "action": "ack", "value": "On it\n```\nfenced\n```"}]}
    channel = Channel(id="C123", name="general", configs={"default": config})
    user = User(id="U1", name="test", real_name="Test User", team="A")

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await show_config(app, channel, user, "")

    sent_message = sent_messages(mock_send_message)
    # The settings block opens and closes once: the value's own fence no longer ends it.
    assert sent_message.count("```") == 2
    assert "OpsGenie message   Line one\\nLine two" in sent_message
    assert "Got it → ack:On it\\n" in sent_message
    # Broken up with zero-width spaces rather than dropped.
    assert "```\nfenced" not in sent_message.split("*Settings*")[1]


def test_a_table_cell_shows_line_breaks_and_cannot_close_the_code_block():
    cell = hutbot.commands.info.table_cell

    assert cell("a\nb") == "a\\nb"
    assert "```" not in cell("x ``` y")
    # A non-string (a list is handled by the caller) passes through untouched.
    assert cell(5) == 5


@pytest.mark.asyncio
async def test_news_is_split_into_messages_that_each_keep_their_quote_block():
    app = AsyncMock()
    channel = Channel(id="C1", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U1", "test", "Test User", "Testers")

    # A limit low enough to split whatever the list currently holds, so this stays a test of the
    # packing and not of how many entries there happen to be.
    with patch('hutbot.messaging.SLACK_MESSAGE_CHARACTER_LIMIT', 1000), \
         patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "news", channel, user)

    calls = mock_send_message.call_args_list
    texts = [call.args[3] for call in calls]
    assert len(texts) > 1, "the entries have to be spread over several messages"
    # An entry is never cut in half: each one opens with its own headline line.
    for text in texts:
        body = text.split("\n\n")[-1]
        # A blank line would end the quote, so entries are separated by an empty quoted line.
        assert all(line.startswith(">") for line in body.splitlines()), body
        assert body.startswith("> :"), body
    # Only the last part carries the command footer.
    footers = [call.kwargs.get("footer", call.args[5] if len(call.args) > 5 else True)
               for call in calls]
    assert footers == [False] * (len(texts) - 1) + [True]


@pytest.mark.asyncio
@pytest.mark.parametrize("command", ["help", "news"])
async def test_help_and_news_placeholders_are_not_slack_mentions(command):
    # Slack parses `<#…>` and `<@…>` as a channel or user mention wherever it finds them —
    # backticks and code fences included — so a placeholder written that way reaches the
    # reader as a resolved channel name or as nothing at all, instead of as the value they
    # are meant to fill in. Spelled `#<channel>` / `@<user>`, it stays readable.
    app = AsyncMock()
    channel = Channel(id="C1", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U1", "test", "Test User", "Testers")

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, command, channel, user)

    text = sent_messages(mock_send_message)
    assert "<#" not in text, text
    assert "<@" not in text, text


def _exported_json(text: str) -> dict:
    """The JSON payload out of an export message's code fence."""
    match = re.search(r"```\n(.*?)\n```", text, re.DOTALL)
    assert match, text
    return json.loads(match.group(1))


@pytest.mark.asyncio
async def test_export_config_prints_only_non_default_fields():
    app = AsyncMock()
    config = copy.deepcopy(DEFAULT_CONFIG)
    config.update({"wait_time": 300, "reply_message": "Alarm message", "opsgenie": True})
    channel = Channel(id="C123", name="general", configs={"default": copy.deepcopy(DEFAULT_CONFIG), "alarms": config})
    user = User(id="U123", name="test", real_name="Test User", team="A")

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "export config alarms", channel, user)

    text = sent_messages(mock_send_message)
    payload = _exported_json(text)
    assert payload["format"] == "hutbot-config/1"
    assert payload["name"] == "alarms"
    assert payload["settings"] == {"wait_time": 300, "reply_message": "Alarm message", "opsgenie": True}
    assert "import config" in text


@pytest.mark.asyncio
async def test_export_config_defaults_to_the_addressed_config():
    app = AsyncMock()
    config = copy.deepcopy(DEFAULT_CONFIG)
    config["wait_time"] = 300
    channel = Channel(id="C123", name="general", configs={"default": copy.deepcopy(DEFAULT_CONFIG), "alarms": config})
    user = User(id="U123", name="test", real_name="Test User", team="A")

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "alarms export config", channel, user)
    assert _exported_json(sent_messages(mock_send_message))["name"] == "alarms"

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "export config", channel, user)
    payload = _exported_json(sent_messages(mock_send_message))
    assert payload["name"] == "default"
    assert payload["settings"] == {}


@pytest.mark.asyncio
async def test_export_config_never_prints_the_calendar_url():
    app = AsyncMock()
    config = copy.deepcopy(DEFAULT_CONFIG)
    config["calendar_url"] = "https://cal.example.com/SECRETTOKEN/rota.ics"
    channel = Channel(id="C123", name="general", configs={"alarms": config})
    user = User(id="U123", name="test", real_name="Test User", team="A")

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "export config alarms", channel, user)

    text = sent_messages(mock_send_message)
    assert "SECRETTOKEN" not in text
    assert "was *not* exported" in text
    assert "calendar_url" not in _exported_json(text)["settings"]


@pytest.mark.asyncio
async def test_export_config_escapes_backticks_so_the_fence_survives():
    app = AsyncMock()
    config = copy.deepcopy(DEFAULT_CONFIG)
    config["reply_message"] = "run this:\n```\nmake all\n```"
    channel = Channel(id="C123", name="general", configs={"alarms": config})
    user = User(id="U123", name="test", real_name="Test User", team="A")

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "export config alarms", channel, user)

    text = sent_messages(mock_send_message)
    # Exactly the opening and closing fence of the export itself.
    assert text.count("```") == 2
    payload = _exported_json(text)
    # The ` escapes decode back to real backticks, so the round trip is exact.
    assert payload["settings"]["reply_message"] == config["reply_message"]


@pytest.mark.asyncio
async def test_export_config_unknown_name():
    app = AsyncMock()
    channel = Channel(id="C123", name="general", configs={"default": copy.deepcopy(DEFAULT_CONFIG)})
    user = User(id="U123", name="test", real_name="Test User", team="A")

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "export config nope", channel, user)
    assert "Configuration `nope` not found." in sent_messages(mock_send_message)


@pytest.mark.asyncio
async def test_an_oversized_export_is_one_preformatted_block():
    app = _ui_app()
    config = copy.deepcopy(DEFAULT_CONFIG)
    config["reply_message"] = "x" * 4000
    channel = Channel(id="C123", name="general", configs={"alarms": config})
    user = User(id="U123", name="test", real_name="Test User", team="A")

    await process_command(app, "export config alarms", channel, user)

    blocks = app.client.chat_postEphemeral.await_args.kwargs["blocks"]
    exports = [
        element
        for block in blocks if block["type"] == "rich_text"
        for element in block["elements"]
        if element["type"] == "rich_text_preformatted" and element.get("language") == "json"
    ]
    assert len(exports) == 1
    dumped = exports[0]["elements"][0]["text"]
    assert len(dumped) > hutbot.messaging.SLACK_SECTION_TEXT_LIMIT
    assert json.loads(dumped)["settings"]["reply_message"] == "x" * 4000
    assert all(
        len(block["text"]["text"]) <= hutbot.messaging.SLACK_SECTION_TEXT_LIMIT
        for block in blocks if block["type"] == "section"
    )
