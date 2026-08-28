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


def test_render_date_time_and_datetime_from_the_message_timestamp():
    import hutbot
    config = {**DEFAULT_CONFIG.copy(), "date_format": "%d.%m.%Y", "time_format": "%H:%M", "datetime_timezone": "Europe/Berlin"}
    variables = {"__timestamp_raw": "1786453297.645799"}

    rendered = hutbot.templating.render_reply_message_template(
        "{{date}} / {{time}} / {{datetime}}", variables, config,
    )

    assert rendered == "11.08.2026 / 15:01 / 11.08.2026 15:01"


def test_date_time_variables_take_format_timezone_and_locale_arguments():
    import hutbot
    config = {**DEFAULT_CONFIG.copy(), "datetime_timezone": "Europe/Berlin"}
    variables = {"__timestamp_raw": "1786453297.645799"}

    rendered = hutbot.templating.render_reply_message_template(
        "{{datetime(tz='Asia/Tokyo')}} | {{date(lc='de_DE', fmt='%A, %d %B %Y')}} | {{time(fmt='15:04')}}",
        variables,
        config,
    )

    assert rendered == "Tue, 11 Aug 2026 22:01 | Dienstag, 11 August 2026 | 15:01"
    assert hutbot.templating.validate_template_expressions("{{date(tz='Asia/Tokyo')}}") == ""
    assert "does not support arguments" in hutbot.templating.validate_template_expressions("{{user(tz='Asia/Tokyo')}}")


def test_date_time_variables_take_an_at_argument():
    import hutbot
    config = {**DEFAULT_CONFIG.copy(), "date_format": "%d.%m.%Y", "time_format": "%H:%M", "datetime_timezone": "Europe/Berlin"}
    variables = {"__timestamp_raw": "1786453297.645799"}

    rendered = hutbot.templating.render_reply_message_template(
        '{{date}} | {{date(at="+2w")}} | {{datetime(at="+90m")}} | {{time(at="09:00")}} '
        '| {{date(at="2026-09-01", fmt="%d.%m.%Y")}}',
        variables,
        config,
    )

    assert rendered == "11.08.2026 | 25.08.2026 | 11.08.2026 16:31 | 09:00 | 01.09.2026"


def test_the_at_of_a_clock_variable_is_counted_from_the_message():
    """So `at="+0m"` is the plain form -- the same invariant the calendar slices keep."""
    import hutbot
    config = {**DEFAULT_CONFIG.copy(), "date_format": "%d.%m.%Y", "time_format": "%H:%M", "datetime_timezone": "Europe/Berlin"}
    variables = {"__timestamp_raw": "1786453297.645799"}

    rendered = hutbot.templating.render_reply_message_template(
        '{{datetime}} | {{datetime(at="+0m")}}', variables, config,
    )

    plain, moved = rendered.split(" | ")
    assert plain == moved == "11.08.2026 15:01"


@pytest.mark.parametrize("template,expected", [
    ('{{date(offset=next)}}', "does not take `offset`"),
    ('{{datetime(offset="+2")}}', "does not take `offset`"),
    ('{{time(at="next week")}}', "`at` must look like"),
    ('{{user(at="+1d")}}', "does not read a calendar event"),
])
def test_clock_variables_reject_an_at_or_offset_they_cannot_use(template, expected):
    import hutbot
    assert expected in hutbot.templating.validate_template_expressions(template)


def test_a_clock_variable_with_an_at_asks_the_calendar_for_nothing():
    """`{{date(at=...)}}` is arithmetic on a timestamp, so it must not cost a feed selection."""
    import hutbot

    assert hutbot.templating.find_calendar_selectors('{{date(at="+1d")}} {{time(at="09:00")}}') == []
    assert hutbot.templating.find_calendar_selectors('{{date(at="+1d")}} {{calendar_summary(at="+1d")}}') == [("+1d", "")]


def test_date_time_variables_are_supported_and_listed():
    import hutbot
    assert hutbot.templating.validate_template_expressions("{{date}} {{time}} {{datetime}}") == ""
    assert {"date", "time", "datetime"} <= hutbot.constants.SUPPORTED_TEMPLATE_VARIABLES


@pytest.mark.asyncio
async def test_build_template_variables_stands_in_now_without_a_message_timestamp():
    import hutbot
    app = AsyncMock()
    channel = Channel(id="C1", name="davetest", configs={})
    user = User("U1", "dave", "Dave", "T")

    variables = await hutbot.templating.build_reply_template_variables(
        app, "tok", channel, DEFAULT_CONFIG.copy(), "default", user, "", "", "",
    )

    assert variables["timestamp"]
    assert float(variables["timestamp"]) > 0
    assert variables["date"] and variables["time"] and variables["datetime"]
    assert variables["__timestamp_raw"] == variables["timestamp"]


@pytest.mark.asyncio
async def test_build_template_variables_keeps_a_real_message_timestamp():
    import hutbot
    app = AsyncMock()
    channel = Channel(id="C1", name="davetest", configs={})
    user = User("U1", "dave", "Dave", "T")
    config = {**DEFAULT_CONFIG.copy(), "date_format": "%d.%m.%Y", "datetime_timezone": "Europe/Berlin"}

    variables = await hutbot.templating.build_reply_template_variables(
        app, "tok", channel, config, "default", user, "hi", "1786453297.645799", "link",
    )

    assert variables["timestamp"] == "1786453297.645799"
    assert variables["date"] == "11.08.2026"
    assert variables["time"] == "15:01"


# ----- rendering a selector slice -----

def _slice_namespace():
    """A namespace with a default selection and one `at="+1d"` slice, built by hand."""
    from hutbot.constants import event_slice_name as slice_name

    return {
        "calendar_summary": "Today",
        "calendar_attendees": "Ann, Bob",
        f"__{slice_name('calendar_attendees', '+1d', '')}_items": ["Cleo", "Dan"],
        "__calendar_attendees_items": ["Ann", "Bob"],
        "calendar_start_time": "09:00",
        "__calendar_start_time_raw": "2026-08-26T09:00:00+02:00",
        f"__{slice_name('calendar_summary', '+1d', '')}": "Tomorrow",
        f"__{slice_name('calendar_attendees', '+1d', '')}": "Cleo, Dan",
        f"__{slice_name('calendar_start_time', '+1d', '')}_raw": "2026-08-27T11:30:00+02:00",
    }


def test_render_reads_a_scalar_from_a_slice():
    render = hutbot.templating.render_reply_message_template

    assert render("{{calendar_summary}} / {{calendar_summary(at=+1d)}}", _slice_namespace()) == "Today / Tomorrow"


def test_render_applies_the_formatting_arguments_to_a_slice():
    render = hutbot.templating.render_reply_message_template

    rendered = render('{{calendar_start_time(at=+1d, tz="UTC", fmt="15:04")}}', _slice_namespace())

    assert rendered == "09:30"


def test_render_applies_nth_to_a_slice():
    render = hutbot.templating.render_reply_message_template

    assert render("{{calendar_attendees(nth=1)}}", _slice_namespace()) == "Ann"
    assert render("{{calendar_attendees(at=+1d, nth=2)}}", _slice_namespace()) == "Dan"


def test_render_joins_a_list_slice_without_nth():
    render = hutbot.templating.render_reply_message_template

    assert render("{{calendar_attendees(at=+1d)}}", _slice_namespace()) == "Cleo, Dan"


def test_a_missing_slice_renders_a_placeholder_not_the_default_and_not_braces():
    """The one thing render must never do is answer about the wrong moment."""
    render = hutbot.templating.render_reply_message_template

    rendered = render("{{calendar_summary(at=+2d)}} {{calendar_start_time(at=+2d)}}", _slice_namespace())

    assert rendered == "<no-event> <unknown>"
    assert "Today" not in rendered and "{{" not in rendered


# ----- the config that triggered this one -----

def _parent_facts(**overrides):
    facts = {
        'config_name': 'reminder',
        'message': 'Standup in 5, <@U1>',
        'timestamp': '1786453297.645799',
        'action': hutbot.constants.ACTION_GROUP_DM,
        'target': '@oncall',
        'variable_names': ['user', 'calendar_summary'],
        'variables': ['<@U1>', 'Standup'],
        'recipients': ['<@U1>', '<@U2>'],
    }
    return {**facts, **overrides}


def test_the_parent_slice_covers_exactly_the_declared_variables():
    """A name added to the set but not to the builder renders `{{…}}` in a real message."""
    variables = hutbot.templating.parent_template_variables(_parent_facts())

    public = {name for name in variables if not name.startswith("__")}
    assert public == hutbot.constants.PARENT_TEMPLATE_VARIABLES
    assert {name for name in variables if name.startswith("__")} == {
        "__parent_date_raw", "__parent_time_raw", "__parent_datetime_raw",
        "__parent_variables_items", "__parent_variables_names", "__parent_recipients_items",
    }


def test_the_parent_slice_reports_what_the_parent_did():
    render = hutbot.templating.render_reply_message_template
    variables = hutbot.templating.parent_template_variables(_parent_facts())

    assert render("{{parent_config}}", variables) == "reminder"
    assert render("{{parent_message}}", variables) == "Standup in 5, <@U1>"
    assert render("{{parent_action}}", variables) == "group_dm"
    assert render("{{parent_target}}", variables) == "@oncall"
    assert render("{{parent_timestamp}}", variables) == "1786453297.645799"
    assert render("{{parent_recipients}}", variables) == "<@U1>, <@U2>"
    assert render("{{parent_recipients(nth=2)}}", variables) == "<@U2>"


def test_without_a_parent_every_variable_says_so():
    render = hutbot.templating.render_reply_message_template
    variables = hutbot.templating.parent_template_variables(None)

    for variable in hutbot.constants.PARENT_TEMPLATE_VARIABLES - {"parent_timestamp"}:
        rendered = render(f"{{{{{variable}}}}}", variables)
        assert rendered in ("<no-parent>", "<unknown>"), (variable, rendered)
    # The raw Slack timestamp is the one that renders empty, like `{{timestamp}}` itself.
    assert render("{{parent_timestamp}}", variables) == ""


def test_a_parent_that_used_no_variables_is_not_the_same_as_no_parent():
    render = hutbot.templating.render_reply_message_template
    variables = hutbot.templating.parent_template_variables(
        _parent_facts(variable_names=[], variables=[], recipients=[], target=''))

    assert render("{{parent_variables}}", variables) == ""
    assert render("{{parent_recipients}}", variables) == ""
    assert render("{{parent_target}}", variables) == ""
    assert render("{{parent_config}}", variables) == "reminder"


def test_the_parent_datetime_variables_take_the_formatting_arguments():
    render = hutbot.templating.render_reply_message_template
    variables = hutbot.templating.parent_template_variables(_parent_facts())

    assert render('{{parent_date(fmt="%Y-%m-%d", tz="UTC")}}', variables) == "2026-08-11"
    assert render('{{parent_time(fmt="%H:%M", tz="UTC")}}', variables) == "13:01"
    assert render('{{parent_datetime(fmt="%Y-%m-%d %H:%M", tz="Asia/Tokyo")}}', variables) == "2026-08-11 22:01"


def test_a_parent_datetime_with_no_parent_is_unknown_even_with_arguments():
    render = hutbot.templating.render_reply_message_template
    variables = hutbot.templating.parent_template_variables(None)

    assert render('{{parent_datetime(tz="UTC")}}', variables) == "<unknown>"


def test_nth_and_of_read_the_parents_own_variables():
    render = hutbot.templating.render_reply_message_template
    variables = hutbot.templating.parent_template_variables(_parent_facts())

    assert render("{{parent_variables}}", variables) == "<@U1>, Standup"
    assert render("{{parent_variables(nth=1)}}", variables) == "<@U1>"
    assert render("{{parent_variables(nth=2)}}", variables) == "Standup"
    assert render('{{parent_variables(of="user")}}', variables) == "<@U1>"
    assert render('{{parent_variables(of="calendar_summary")}}', variables) == "Standup"


def test_asking_the_parent_for_something_it_never_used_renders_empty():
    """Like an out-of-range `nth`: a message written for a richer parent still reads."""
    render = hutbot.templating.render_reply_message_template
    variables = hutbot.templating.parent_template_variables(_parent_facts())

    assert render("{{parent_variables(nth=99)}}", variables) == ""
    assert render('{{parent_variables(of="message")}}', variables) == ""


def test_of_names_the_first_use_when_the_parent_used_one_variable_twice():
    render = hutbot.templating.render_reply_message_template
    variables = hutbot.templating.parent_template_variables(
        _parent_facts(variable_names=['user', 'user'], variables=['<@U1>', '<@U1> again']))

    assert render('{{parent_variables(of="user")}}', variables) == "<@U1>"


# ----- collecting what a template rendered -----

def test_rendered_template_values_follows_the_message_order():
    variables = {"user": "<@U1>", "channel": "#general", "__timestamp_raw": "1786453297.6"}

    names, values = hutbot.templating.rendered_template_values(
        "Hi {{user}} in {{channel}} — {{user_name}}", variables)

    assert names == ["user", "channel", "user_name"]
    # An unresolved variable keeps its slot and contributes its literal: a shifted index
    # would silently change what `nth=2` means.
    assert values == ["<@U1>", "#general", "{{user_name}}"]


def test_rendered_template_values_reports_nothing_for_a_template_that_cannot_scan():
    assert hutbot.templating.rendered_template_values("{{user", {"user": "x"}) == ([], [])
    assert hutbot.templating.rendered_template_values("no variables here", {}) == ([], [])


def test_one_expression_renders_the_same_alone_as_it_does_in_a_message():
    variables = _slice_namespace()
    variables["__timestamp_raw"] = "1786453297.645799"
    for template in ("{{date}}", "{{calendar_start_time(at=+1d)}}", "{{calendar_attendees(nth=1)}}",
                     "{{calendar_attendees(at=+1d)}}", "{{calendar_summary(at=+2d)}}", "{{user_name}}"):
        expr = hutbot.templating.parse_template_expression(template[2:-2])
        alone = hutbot.templating.render_template_expression(expr, variables)
        in_message = hutbot.templating.render_reply_message_template(template, variables)
        assert (alone if alone is not None else template) == in_message, template


# ----- validating the parent arguments -----

@pytest.mark.parametrize("template", [
    '{{parent_config}}',
    '{{parent_datetime(fmt="%d.%m.%Y", tz="Europe/Berlin", lc="de_DE")}}',
    '{{parent_variables(nth=1)}}',
    '{{parent_variables(of="user")}}',
    '{{parent_recipients(nth=2)}}',
])
def test_the_parent_variables_accept_their_own_arguments(template):
    assert hutbot.templating.validate_template_expressions(template) == ""


@pytest.mark.parametrize("template,expected", [
    ('{{parent_config(fmt="x")}}', "does not support arguments"),
    ('{{parent_variables(tz="UTC")}}', "takes only `nth` and `of`"),
    ('{{parent_recipients(tz="UTC")}}', "takes only `nth`"),
    ('{{parent_date(at="+1d")}}', "does not read a calendar event"),
    ('{{parent_config(of="user")}}', "does not hold the parent's variables"),
    ('{{parent_recipients(of="user")}}', "does not hold the parent's variables"),
    ('{{calendar_attendees(of="user")}}', "does not hold the parent's variables"),
    ('{{parent_variables(of="nope")}}', "`of` names a template variable"),
    ('{{parent_variables(of="user", nth=2)}}', "takes `nth` or `of`, not both"),
    ('{{parent_variables(nth=2, of="user")}}', "takes `nth` or `of`, not both"),
])
def test_the_parent_variables_reject_an_argument_they_do_not_take(template, expected):
    assert expected in hutbot.templating.validate_template_expressions(template)


def test_the_parent_variables_are_supported_and_listed():
    assert hutbot.constants.PARENT_TEMPLATE_VARIABLES <= hutbot.constants.SUPPORTED_TEMPLATE_VARIABLES
    # Not calendar variables, which is what keeps the calendar placeholder coverage test honest.
    assert not (hutbot.constants.PARENT_TEMPLATE_VARIABLES & hutbot.constants.CALENDAR_TEMPLATE_VARIABLES)


# ----- the button press that ran this -----

def _press_facts(**overrides):
    facts = {
        'kind': hutbot.constants.PRESS_KIND_USER,
        'label': "I've got it",
        'timestamp': '1786453297.645799',
        'user': '<@U9>',
        'user_name': 'Bob Ops',
    }
    return {**facts, **overrides}


def test_the_press_slice_covers_exactly_the_declared_variables():
    """A name added to the set but not to the builder renders `{{…}}` in a real message."""
    variables = hutbot.templating.press_template_variables(_press_facts())

    public = {name for name in variables if not name.startswith("__")}
    assert public == hutbot.constants.PRESS_TEMPLATE_VARIABLES
    assert {name for name in variables if name.startswith("__")} == {
        "__press_date_raw", "__press_time_raw", "__press_datetime_raw",
    }


def test_the_press_slice_reports_who_pressed_what_and_when():
    render = hutbot.templating.render_reply_message_template
    config = {"date_format": "%d.%m.%Y", "datetime_timezone": "Europe/Berlin"}
    variables = hutbot.templating.press_template_variables(_press_facts(), config)

    assert render("{{press_kind}}", variables) == "user"
    assert render("{{press_label}}", variables) == "I've got it"
    assert render("{{press_user}}", variables) == "<@U9>"
    assert render("{{press_user_name}}", variables) == "Bob Ops"
    assert render("{{press_timestamp}}", variables) == "1786453297.645799"
    assert render("{{press_date}}", variables, config) == "11.08.2026"
    assert render('{{press_date(fmt="%Y-%m-%d", tz="UTC")}}', variables, config) == "2026-08-11"


def test_a_timeout_press_has_a_button_and_a_time_but_nobody_behind_it():
    """The distinction an ack text needs: dismissed by somebody vs. nobody answered in time."""
    render = hutbot.templating.render_reply_message_template
    variables = hutbot.templating.press_template_variables(
        _press_facts(kind=hutbot.constants.PRESS_KIND_TIMEOUT, user='', user_name=''))

    assert render("{{press_kind}}", variables) == "timeout"
    assert render("{{press_label}}", variables) == "I've got it"
    assert render("{{press_user}}", variables) == ""
    assert render("{{press_user_name}}", variables) == ""


def test_without_a_press_every_variable_says_so():
    render = hutbot.templating.render_reply_message_template
    variables = hutbot.templating.press_template_variables(None)

    for variable in hutbot.constants.PRESS_TEMPLATE_VARIABLES - {"press_timestamp"}:
        rendered = render(f"{{{{{variable}}}}}", variables)
        assert rendered in ("<no-press>", "<unknown>"), (variable, rendered)
    # The raw timestamp is the one that renders empty, like `{{timestamp}}` itself.
    assert render("{{press_timestamp}}", variables) == ""


@pytest.mark.parametrize("template,expected", [
    ('{{press_label(nth=2)}}', "is not a list"),
    ('{{press_user(fmt="%d")}}', "does not support arguments"),
    ('{{press_kind(of="user")}}', "does not hold the parent's variables"),
    ('{{press_date(at="+1d")}}', "does not read a calendar event"),
])
def test_the_press_variables_reject_an_argument_they_do_not_take(template, expected):
    assert expected in hutbot.templating.validate_template_expressions(template)


def test_the_press_variables_are_supported_and_listed():
    assert hutbot.constants.PRESS_TEMPLATE_VARIABLES <= hutbot.constants.SUPPORTED_TEMPLATE_VARIABLES
    # Its own family: neither the parent's nor the calendar's, whose placeholder coverage
    # tests count on the sets not overlapping.
    assert not (hutbot.constants.PRESS_TEMPLATE_VARIABLES & hutbot.constants.PARENT_TEMPLATE_VARIABLES)
    assert not (hutbot.constants.PRESS_TEMPLATE_VARIABLES & hutbot.constants.CALENDAR_TEMPLATE_VARIABLES)
