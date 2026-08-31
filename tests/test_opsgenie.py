from tests._common import *  # noqa: F401,F403



@pytest.mark.asyncio
async def test_process_command_set_opsgenie_schedule():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "set opsgenie-schedule Team Primary", channel, user, thread_ts)
        assert channel.configs["default"]["opsgenie_schedule_name"] == "Team Primary"
        mock_send_message.assert_called_with(app, channel, user, "*OpsGenie schedule* set to `Team Primary` in configuration `default`.", thread_ts)



@pytest.mark.asyncio
async def test_process_command_set_opsgenie_priority():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "set opsgenie-priority P2", channel, user, thread_ts)
        assert channel.configs["default"]["opsgenie_priority"] == "P2"
        mock_send_message.assert_called_with(app, channel, user, "*OpsGenie priority* set to `P2` in configuration `default`.", thread_ts)



@pytest.mark.asyncio
async def test_process_command_set_opsgenie_priority_custom_config_normalizes_case():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "alerts set opsgenie-priority p1", channel, user, thread_ts)
        assert channel.configs["alerts"]["opsgenie_priority"] == "P1"
        mock_send_message.assert_called_with(app, channel, user, "*OpsGenie priority* set to `P1` in configuration `alerts`.", thread_ts)



@pytest.mark.asyncio
async def test_process_command_set_opsgenie_priority_rejects_invalid_value():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    with patch('hutbot.persistence.save_configuration') as mock_save, patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "set opsgenie-priority P0", channel, user, thread_ts)

    assert channel.configs["default"]["opsgenie_priority"] == "P4"
    mock_save.assert_not_called()
    sent_message = mock_send_message.call_args.args[3]
    assert "Invalid *OpsGenie priority*" in sent_message
    assert "`P1`, `P2`, `P3`, `P4`, `P5`" in sent_message



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

    with patch('hutbot.commands.info.get_env_var', return_value="token"), \
         patch('hutbot.opsgenie.aiohttp.ClientSession', return_value=session_context), \
         patch('hutbot.messaging.send_message') as mock_send_message:
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

    with patch('hutbot.commands.info.get_env_var', return_value=""), patch('hutbot.messaging.send_message') as mock_send_message:
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
    import hutbot
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    channel.configs["default"]["opsgenie_schedule_name"] = "Team Primary"
    user = User("U12345", "test", "Test User", "Testers")
    on_call_user = User("U999", "oncall", "On Call User", "Ops")
    thread_ts = "1234567890.123456"
    start = "2026-04-26T08:00:00Z"
    end = "2026-04-27T08:00:00Z"

    with patch('hutbot.opsgenie.resolve_opsgenie_on_call', new=AsyncMock(return_value=("oncall@example.com", on_call_user))) as mock_resolve, \
         patch('hutbot.opsgenie.resolve_opsgenie_on_call_period', new=AsyncMock(return_value=(start, end))) as mock_period, \
         patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "on-call", channel, user, thread_ts, opsgenie_token="token")

    mock_resolve.assert_awaited_once_with(app, "token", "Team Primary")
    mock_period.assert_awaited_once_with("token", "Team Primary", "oncall@example.com")
    mock_send_message.assert_called_with(
        app,
        channel,
        user,
        "*Schedule*: `Team Primary`\n"
        "*On-call*: <@U999>\n"
        f"*Start*: `{hutbot.datetimefmt.format_opsgenie_datetime(start)}`\n"
        f"*End*: `{hutbot.datetimefmt.format_opsgenie_datetime(end)}`",
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

    with patch('hutbot.opsgenie.resolve_opsgenie_on_call', new=AsyncMock(return_value=("oncall@example.com", on_call_user))) as mock_resolve, \
         patch('hutbot.opsgenie.resolve_opsgenie_on_call_period', new=AsyncMock(return_value=("2026-04-26T08:00:00Z", "2026-04-27T08:00:00Z"))) as mock_period, \
         patch('hutbot.messaging.send_message') as mock_send_message:
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

    with patch('hutbot.opsgenie.resolve_opsgenie_on_call', new=AsyncMock(return_value=("oncall@example.com", on_call_user))) as mock_resolve, \
         patch('hutbot.opsgenie.resolve_opsgenie_on_call_period', new=AsyncMock(return_value=("2026-04-26T08:00:00Z", "2026-04-27T08:00:00Z"))) as mock_period, \
         patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "alerts on-call", channel, user, thread_ts, opsgenie_token="token")

    mock_resolve.assert_awaited_once_with(app, "token", "Alerts Schedule")
    mock_period.assert_awaited_once_with("token", "Alerts Schedule", "oncall@example.com")
    sent_message = mock_send_message.call_args.args[3]
    assert "*Schedule*: `Alerts Schedule`" in sent_message
    assert "*On-call*: <@U999>" in sent_message



@pytest.mark.asyncio
async def test_process_command_on_call_falls_back_to_email_when_unmapped():
    import hutbot
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    channel.configs["default"]["opsgenie_schedule_name"] = "Team Primary"
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"
    start = "2026-04-26T08:00:00Z"
    end = "2026-04-27T08:00:00Z"

    with patch('hutbot.opsgenie.resolve_opsgenie_on_call', new=AsyncMock(return_value=("oncall@example.com", None))), \
         patch('hutbot.opsgenie.resolve_opsgenie_on_call_period', new=AsyncMock(return_value=(start, end))), \
         patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "on-call", channel, user, thread_ts, opsgenie_token="token")

    sent_message = mock_send_message.call_args.args[3]
    assert "*On-call*: oncall@example.com" in sent_message
    assert f"*Start*: `{hutbot.datetimefmt.format_opsgenie_datetime(start)}`" in sent_message
    assert f"*End*: `{hutbot.datetimefmt.format_opsgenie_datetime(end)}`" in sent_message



@pytest.mark.asyncio
async def test_process_command_on_call_uses_upcoming_period_when_no_current_on_call():
    import hutbot
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    channel.configs["default"]["opsgenie_schedule_name"] = "Cloud Hosting_schedule"
    user = User("U12345", "test", "Test User", "Testers")
    upcoming_user = User("U999", "next", "Next User", "Ops")
    thread_ts = "1234567890.123456"
    start = "2026-04-28T08:00:00Z"
    end = "2026-04-29T08:00:00Z"

    with patch('hutbot.opsgenie.resolve_opsgenie_on_call', new=AsyncMock(return_value=("", None))) as mock_resolve, \
         patch('hutbot.opsgenie.resolve_opsgenie_upcoming_on_call_period', new=AsyncMock(return_value=("next@example.com", start, end))) as mock_upcoming, \
         patch('hutbot.opsgenie.resolve_slack_user_for_opsgenie_recipient', new=AsyncMock(return_value=upcoming_user)) as mock_slack_user, \
         patch('hutbot.messaging.send_message') as mock_send_message:
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
        f"*Start*: `{hutbot.datetimefmt.format_opsgenie_datetime(start)}`\n"
        f"*End*: `{hutbot.datetimefmt.format_opsgenie_datetime(end)}`",
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

    with patch('hutbot.opsgenie.resolve_opsgenie_on_call', new=AsyncMock(return_value=("oncall@example.com", on_call_user))), \
         patch('hutbot.opsgenie.resolve_opsgenie_on_call_period', new=AsyncMock(return_value=("2026-04-26T08:00:00Z", "2026-04-26T16:00:00Z"))), \
         patch('hutbot.messaging.send_message') as mock_send_message:
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

    with patch('hutbot.opsgenie.resolve_opsgenie_on_call', new=AsyncMock(return_value=("", None))), \
         patch('hutbot.opsgenie.resolve_opsgenie_upcoming_on_call_period', new=AsyncMock(return_value=("", "", ""))), \
         patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "on-call", channel, user, thread_ts, opsgenie_token="token")

    mock_send_message.assert_called_with(app, channel, user, "Failed to resolve on-call user for OpsGenie schedule `Cloud Hosting_schedule`.", thread_ts)



@pytest.mark.asyncio
async def test_process_command_on_call_without_schedule():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")
    thread_ts = "1234567890.123456"

    with patch('hutbot.opsgenie.resolve_opsgenie_on_call', new=AsyncMock()) as mock_resolve, \
         patch('hutbot.opsgenie.resolve_opsgenie_on_call_period', new=AsyncMock()) as mock_period, \
         patch('hutbot.messaging.send_message') as mock_send_message:
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

    with patch('hutbot.opsgenie.resolve_opsgenie_on_call', new=AsyncMock()) as mock_resolve, \
         patch('hutbot.opsgenie.resolve_opsgenie_on_call_period', new=AsyncMock()) as mock_period, \
         patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "on-call", channel, user, thread_ts)

    mock_resolve.assert_not_awaited()
    mock_period.assert_not_awaited()
    mock_send_message.assert_called_with(app, channel, user, "OpsGenie is not configured. Missing `OPSGENIE_TOKEN`.", thread_ts)



def test_find_opsgenie_on_call_period_prefers_matching_current_period():
    import hutbot
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

    assert hutbot.opsgenie.find_opsgenie_on_call_period(data, "oncall@example.com", now) == (
        "2026-04-26T08:00:00Z",
        "2026-04-27T08:00:00Z",
    )



def test_format_opsgenie_datetime_uses_local_timezone():
    import hutbot
    local_tz = datetime.timezone(datetime.timedelta(hours=2), "CEST")

    assert hutbot.datetimefmt.format_opsgenie_datetime("2026-04-26T08:00:00Z", local_tz) == "Sun, 26 Apr 2026 10:00"



def test_find_opsgenie_on_call_period_merges_adjacent_matching_periods():
    import hutbot
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

    assert hutbot.opsgenie.find_opsgenie_on_call_period(data, "oncall@example.com", now) == (
        "2026-04-24T16:00:00Z",
        "2026-05-14T06:00:00Z",
    )



def test_find_opsgenie_upcoming_on_call_period_selects_next_period():
    import hutbot
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

    assert hutbot.opsgenie.find_opsgenie_upcoming_on_call_period(data, now) == (
        "next@example.com",
        "2026-04-27T08:00:00Z",
        "2026-04-27T18:00:00Z",
    )



def test_find_opsgenie_upcoming_on_call_period_skips_current_period():
    import hutbot
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

    assert hutbot.opsgenie.find_opsgenie_upcoming_on_call_period(data, now) == (
        "next@example.com",
        "2026-04-26T18:00:00Z",
        "2026-04-26T20:00:00Z",
    )



@pytest.mark.asyncio
async def test_resolve_opsgenie_on_call_period_requests_past_anchored_wide_timeline():
    import hutbot
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

    with patch('hutbot.opsgenie.aiohttp.ClientSession', return_value=session_context):
        await hutbot.opsgenie.resolve_opsgenie_on_call_period("token", "Team Primary", "oncall@example.com")

    params = session.get.call_args.kwargs["params"]
    assert params["identifierType"] == "name"
    assert params["interval"] == "6"
    assert params["intervalUnit"] == "months"
    assert params["date"].endswith("Z")



@pytest.mark.asyncio
async def test_schedule_reply_renders_opsgenie_template_variables():
    app = AsyncMock()
    app.client.chat_getPermalink.return_value = {"permalink": "https://slack.test/message"}
    app.client.chat_postMessage.return_value = {"ts": "1234.1"}
    channel = Channel(id="C12345", name="general", configs={})
    user = User("U12345", "test", "Test User", "Testers")
    config = DEFAULT_CONFIG.copy()
    config["wait_time"] = 0
    config["opsgenie_schedule_name"] = "Team Primary"
    config["reply_message"] = "On call: {{opsgenie_current_user}} / {{opsgenie_current_email}} / {{opsgenie_current_name}}"

    with patch('hutbot.opsgenie.get_opsgenie_template_variables', new=AsyncMock(return_value={
        "opsgenie_current_user": "<@U999>",
        "opsgenie_current_email": "oncall@example.com",
        "opsgenie_current_name": "On Call User",
    })), patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()):
        await schedule_reply(app, "token", channel, config, "alerts", user, "Original text", "1234.1")

    app.client.chat_postMessage.assert_awaited_once_with(
        channel="C12345",
        text="On call: <@U999> / oncall@example.com / On Call User",
        mrkdwn=True,
        thread_ts="1234.1",
    )



@pytest.mark.asyncio
async def test_get_opsgenie_template_variables_renders_current_and_next_periods():
    import hutbot
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
    context = hutbot.models.OpsGenieContext(
        "Team Primary",
        hutbot.models.OpsGeniePeriod("oncall@example.com", current_user, "2026-04-26T08:00:00Z", "2026-04-26T16:00:00Z"),
        hutbot.models.OpsGeniePeriod("next@example.com", next_user, "2026-04-27T08:00:00Z", "2026-04-27T16:00:00Z"),
    )

    with patch('hutbot.opsgenie.resolve_opsgenie_on_call_context', new=AsyncMock(return_value=context)):
        variables = await hutbot.opsgenie.get_opsgenie_template_variables(app, "token", config)

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
    import hutbot
    app = AsyncMock()
    next_user = User("U998", "next", "Next User", "Ops")
    config = {
        **DEFAULT_CONFIG.copy(),
        "opsgenie_schedule_name": "Team Primary",
        "datetime_timezone": "UTC",
    }
    context = hutbot.models.OpsGenieContext(
        "Team Primary",
        hutbot.models.OpsGeniePeriod("", None, "", ""),
        hutbot.models.OpsGeniePeriod("next@example.com", next_user, "2026-04-27T08:00:00Z", "2026-04-27T16:00:00Z"),
    )

    with patch('hutbot.opsgenie.resolve_opsgenie_on_call_context', new=AsyncMock(return_value=context)):
        variables = await hutbot.opsgenie.get_opsgenie_template_variables(app, "token", config)

    assert variables["opsgenie_current_user"] == "<no-user-set>"
    assert variables["opsgenie_current_email"] == "<no-email-set>"
    assert variables["opsgenie_current_start_datetime"] == "<unknown>"
    assert variables["opsgenie_next_user"] == "<@U998>"
    assert variables["opsgenie_next_start_datetime"] == "Mon, 27 Apr 2026 08:00"



@pytest.mark.asyncio
async def test_schedule_reply_uses_placeholder_for_unmapped_opsgenie_user():
    app = AsyncMock()
    app.client.chat_getPermalink.return_value = {"permalink": "https://slack.test/message"}
    app.client.chat_postMessage.return_value = {"ts": "1234.1"}
    channel = Channel(id="C12345", name="general", configs={})
    user = User("U12345", "test", "Test User", "Testers")
    config = DEFAULT_CONFIG.copy()
    config["wait_time"] = 0
    config["opsgenie_schedule_name"] = "Team Primary"
    config["reply_message"] = "On call: {{opsgenie_current_user}} / {{opsgenie_current_email}} / {{opsgenie_current_name}}"

    with patch('hutbot.opsgenie.get_opsgenie_template_variables', new=AsyncMock(return_value={
        "opsgenie_current_user": "<unknown-oncall>",
        "opsgenie_current_email": "oncall@example.com",
        "opsgenie_current_name": "oncall@example.com",
    })), patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()):
        await schedule_reply(app, "token", channel, config, "alerts", user, "Original text", "1234.1")

    app.client.chat_postMessage.assert_awaited_once_with(
        channel="C12345",
        text="On call: <unknown-oncall> / oncall@example.com / oncall@example.com",
        mrkdwn=True,
        thread_ts="1234.1",
    )



@pytest.mark.asyncio
async def test_post_opsgenie_alert_uses_configured_priority():
    import hutbot
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={})
    user = User("U12345", "test", "Test User", "Testers")
    config = DEFAULT_CONFIG.copy()
    config["opsgenie_priority"] = "P2"

    response = AsyncMock()
    response.status = 202
    response_context = AsyncMock()
    response_context.__aenter__.return_value = response
    response_context.__aexit__.return_value = None

    session = MagicMock()
    session.post.return_value = response_context
    session_context = AsyncMock()
    session_context.__aenter__.return_value = session
    session_context.__aexit__.return_value = None

    with patch('hutbot.opsgenie.aiohttp.ClientSession', return_value=session_context):
        await hutbot.opsgenie.post_opsgenie_alert(app, "token", channel, config, user, "Original text", "1234.1", "https://slack.test/message")

    payload = json.loads(session.post.call_args.kwargs["data"])
    assert payload["priority"] == "P2"



@pytest.mark.asyncio
async def test_post_opsgenie_alert_defaults_to_p4_without_configured_priority():
    import hutbot
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={})
    user = User("U12345", "test", "Test User", "Testers")
    config = DEFAULT_CONFIG.copy()
    config.pop("opsgenie_priority")

    response = AsyncMock()
    response.status = 202
    response_context = AsyncMock()
    response_context.__aenter__.return_value = response
    response_context.__aexit__.return_value = None

    session = MagicMock()
    session.post.return_value = response_context
    session_context = AsyncMock()
    session_context.__aenter__.return_value = session
    session_context.__aexit__.return_value = None

    with patch('hutbot.opsgenie.aiohttp.ClientSession', return_value=session_context):
        await hutbot.opsgenie.post_opsgenie_alert(app, "token", channel, config, user, "Original text", "1234.1", "https://slack.test/message")

    payload = json.loads(session.post.call_args.kwargs["data"])
    assert payload["priority"] == "P4"



@pytest.mark.asyncio
async def test_process_command_news_mentions_on_call_and_test_commands():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "news", channel, user)

    sent_message = sent_messages(mock_send_message)
    assert "`/hutbot [config] on-call [schedule name]`" in sent_message
    assert "`/hutbot [config] test`" in sent_message
    assert "`@Hutbot [config] test <message>`" in sent_message



@pytest.mark.asyncio
async def test_process_command_test_uses_opsgenie_placeholders_when_unavailable():
    import hutbot
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    channel.configs["default"]["reply_message"] = "Anybody?"
    user = User("U12345", "test", "Test User", "Testers")

    with patch('hutbot.opsgenie.get_opsgenie_template_variables', new=AsyncMock(return_value=hutbot.opsgenie.get_opsgenie_placeholder_variables())) as mock_get_opsgenie_template_variables, \
         patch('hutbot.messaging.send_message') as mock_send_message:
        await process_command(app, "test", channel, user, opsgenie_token="token")

    mock_get_opsgenie_template_variables.assert_awaited_once_with(app, "token", channel.configs["default"])
    sent_message = mock_send_message.call_args.args[3]
    assert "`{{opsgenie_current_user}}`: <no-user-set>" in sent_message
    assert "`{{opsgenie_current_email}}`: <no-email-set>" in sent_message
    assert "`{{opsgenie_current_name}}`: <no-name-set>" in sent_message



# ----- OpsGenie gating: inline when no buttons, escalation when buttons present -----

@pytest.mark.asyncio
async def test_schedule_reply_fires_opsgenie_inline_without_buttons():
    app = AsyncMock()
    app.client.chat_getPermalink.return_value = {"permalink": "p"}
    app.client.chat_postMessage.return_value = {"ts": "1"}
    cfg = DEFAULT_CONFIG.copy()
    cfg["opsgenie"] = True
    channel = _mk_channel({"src": cfg})
    user = User("U2", "x", "X", "T")
    with patch('hutbot.state.opsgenie_configured', True), \
         patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()), \
         patch('hutbot.opsgenie.post_opsgenie_alert', new=AsyncMock()) as alert:
        await hutbot.scheduling.schedule_reply(app, "tok", channel, cfg, "src", user, "orig", "1.1", wait_time_override=0)
    alert.assert_awaited_once()



@pytest.mark.asyncio
async def test_run_action_fires_opsgenie_for_opsgenie_config():
    # OpsGenie is now a property of any config that runs (no inline special-casing).
    app = AsyncMock()
    app.client.chat_postMessage.return_value = {"ts": "1"}
    cfg = DEFAULT_CONFIG.copy()
    cfg["opsgenie"] = True
    cfg["reply_message"] = "ping"
    channel = _mk_channel({"src": cfg})
    ctx = {"channel_id": "C12345", "user": User("U5", "carol", "Carol", "T"), "text": "DB down", "ts": "9.9", "permalink": "link"}
    with patch('hutbot.state.opsgenie_configured', True), \
         patch('hutbot.opsgenie.post_opsgenie_alert', new=AsyncMock()) as alert:
        await hutbot.actions.run_action(app, "tok", channel, cfg, "src", context=ctx)
    alert.assert_awaited_once()
    args = alert.await_args.args
    # default alert text = original message; ts/permalink from context
    assert args[5] == "DB down" and args[6] == "9.9" and args[7] == "link"



@pytest.mark.asyncio
async def test_run_action_opsgenie_message_template_overrides():
    app = AsyncMock()
    app.client.chat_postMessage.return_value = {"ts": "1"}
    cfg = DEFAULT_CONFIG.copy()
    cfg["opsgenie"] = True
    cfg["reply_message"] = "ping"
    cfg["opsgenie_message"] = "Unanswered in {{channel}}: {{message}}"
    channel = _mk_channel({"src": cfg})
    ctx = {"channel_id": "C12345", "user": User("U5", "carol", "Carol", "T"), "text": "DB down", "ts": "9.9", "permalink": "link"}
    with patch('hutbot.state.opsgenie_configured', True), \
         patch('hutbot.opsgenie.post_opsgenie_alert', new=AsyncMock()) as alert:
        await hutbot.actions.run_action(app, "tok", channel, cfg, "src", context=ctx)
    alert.assert_awaited_once()
    assert alert.await_args.args[5] == "Unanswered in #general: DB down"



@pytest.mark.asyncio
async def test_run_action_no_opsgenie_when_disabled():
    app = AsyncMock()
    app.client.chat_postMessage.return_value = {"ts": "1"}
    cfg = DEFAULT_CONFIG.copy()  # opsgenie off
    channel = _mk_channel({"src": cfg})
    with patch('hutbot.state.opsgenie_configured', True), \
         patch('hutbot.opsgenie.post_opsgenie_alert', new=AsyncMock()) as alert:
        await hutbot.actions.run_action(app, "tok", channel, cfg, "src", context={"channel_id": "C12345"})
    alert.assert_not_awaited()


@pytest.mark.asyncio
async def test_scheduled_opsgenie_alert_uses_posted_ts_for_unique_alias():
    # F5: a scheduled run has no original ts; the alert must use the posted message
    # ts so recurrences don't collapse via OpsGenie alias de-duplication.
    app = AsyncMock()
    app.client.chat_postMessage.return_value = {"ts": "111.222"}
    cfg = DEFAULT_CONFIG.copy()
    cfg["opsgenie"] = True
    cfg["reply_message"] = "scheduled ping"
    channel = _mk_channel({"sched": cfg})
    ctx = {"channel_id": "C12345"}  # scheduled trigger: no original message ts
    with patch('hutbot.state.opsgenie_configured', True), \
         patch('hutbot.opsgenie.post_opsgenie_alert', new=AsyncMock()) as alert:
        await hutbot.actions.run_action(app, "tok", channel, cfg, "sched", context=ctx)
    alert.assert_awaited_once()
    assert alert.await_args.args[6] == "111.222"  # ts arg for the alias = posted ts, not empty


# ----- Per-instance naming -----

def test_bot_slug():
    assert bot_slug("Hutbot") == "hutbot"
    assert bot_slug("Hutbot (DEV)") == "hutbot-dev"
    assert bot_slug("") == "hutbot"
    assert bot_slug(None) == "hutbot"


@pytest.mark.asyncio
async def test_post_opsgenie_alert_uses_bot_name_for_tag_and_alias():
    app = AsyncMock()
    channel = Channel(id="C1", name="general", configs={})
    user = User("U1", "test", "Test User", "Testers")

    class _Response:
        status = 202
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False

    posted = {}

    class _Session:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        def post(self, url, headers=None, data=None):
            posted['data'] = json.loads(data)
            return _Response()

    with patch('hutbot.state.bot_name', 'Hutbot (DEV)'), \
         patch('hutbot.opsgenie.aiohttp.ClientSession', return_value=_Session()), \
         patch('hutbot.messaging.clean_slack_text', new=AsyncMock(return_value="hello")):
        await hutbot.opsgenie.post_opsgenie_alert(app, "token", channel, None, user, "hello", "1.1", "https://slack.test/m")

    assert posted['data']["tags"] == ["Hutbot (DEV)"]
    assert posted['data']["alias"] == "hutbot-dev: Test User in #general 1.1"
    assert posted['data']["details"]["bot"] == "hutbot-dev"
