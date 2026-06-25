from tests._common import *  # noqa: F401,F403



@pytest.mark.asyncio
async def test_set_reply_message_template():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as mock_send_message:
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

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as mock_send_message:
        await set_reply_message(app, channel, "default", message, user, "")

    assert channel.configs["default"]["reply_message"] == message
    assert mock_send_message.call_args.args[3] == f"*Reply message* set to: {message} in configuration `default`."



@pytest.mark.asyncio
async def test_set_reply_message_rejects_unknown_template_variable():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('hutbot.messaging.send_message') as mock_send_message:
        await set_reply_message(app, channel, "default", "Hi {{unknown}}", user, "")

        assert channel.configs["default"]["reply_message"] == "Anybody?"
        sent_message = mock_send_message.call_args.args[3]
        assert "unsupported template variable(s) `{{unknown}}`" in sent_message
        assert "`{{user}}`" in sent_message
        assert "`{{message_link}}`" in sent_message



@pytest.mark.asyncio
async def test_schedule_reply_renders_template_variables():
    app = AsyncMock()
    app.client.chat_getPermalink.return_value = {"permalink": "https://slack.test/message"}
    app.client.chat_postMessage.return_value = {"ts": "1234.1"}
    channel = Channel(id="C12345", name="general", configs={})
    user = User("U12345", "test", "Test User", "Testers")
    config = DEFAULT_CONFIG.copy()
    config["wait_time"] = 0
    config["reply_message"] = (
        "Hi {{user}} ({{user_name}}) from {{team}} in {{channel}}/{{channel_name}}. "
        "Config={{config}} Wait={{wait_minutes}} Ts={{timestamp}} "
        "Message={{message}} Link={{message_link}}"
    )

    with patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()):
        await schedule_reply(app, "token", channel, config, "alerts", user, "Original text", "1234.1")

    app.client.chat_postMessage.assert_awaited_once_with(
        channel="C12345",
        text="Hi <@U12345> (Test User) from Testers in #general/general. Config=alerts Wait=0 Ts=1234.1 Message=Original text Link=https://slack.test/message",
        mrkdwn=True,
        thread_ts="1234.1",
    )



def test_render_reply_message_template_datetime_args_override_config():
    import hutbot
    config = {
        **DEFAULT_CONFIG.copy(),
        "date_format": "%d.%m.%Y",
        "time_format": "%H:%M",
        "datetime_timezone": "Europe/Berlin",
    }
    variables = hutbot.opsgenie.get_opsgenie_placeholder_variables(config)
    raw_key = "__opsgenie_current_start_datetime_raw"
    variables[raw_key] = "2026-04-26T08:00:00Z"

    rendered = hutbot.templating.render_reply_message_template(
        "{{opsgenie_current_start_datetime(format='02.01.2006 15:04', timezone='UTC', locale='en_US')}}",
        variables,
        config,
    )

    assert rendered == "26.04.2026 08:00"



@pytest.mark.asyncio
async def test_validate_config_payload_rejects_unknown_template_variable():
    _seed_user_caches()
    app = _ui_app()
    payload = {"reply_message": "Hello {{not_a_var}}"}

    cfg, errors = await validate_config_payload(payload, app)

    assert cfg is None
    assert "reply_message" in errors
