"""The `test` command: what a preview reports about one configuration."""

import copy

import icalendar

from tests._common import *  # noqa: F401,F403


# A rota feed with one entry running now and one starting after it, both with a shared mailbox
# as organizer and one real person as attendee — the shape every on-call rule reads.
def _rota_ics(now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)

    def stamp(moment):
        return moment.astimezone(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    def event(uid, summary, start, end):
        return [
            "BEGIN:VEVENT", f"UID:{uid}", f"DTSTAMP:{stamp(now)}",
            f"DTSTART:{stamp(start)}", f"DTEND:{stamp(end)}",
            f"SUMMARY:{summary}", "LOCATION:Rufbereitschaft",
            "DESCRIPTION:Ruf an\\, wenn was ist.",
            'ORGANIZER;CN="Notfallhotline":invalid:nomail',
            'ATTENDEE;CN="Notfallhotline";ROLE=REQ-PARTICIPANT:mailto:hotline@example.com',
            'ATTENDEE;CN="Some User";ROLE=REQ-PARTICIPANT:mailto:x@example.com',
            "STATUS:CONFIRMED", "TRANSP:OPAQUE", "END:VEVENT",
        ]

    hour = datetime.timedelta(hours=1)
    return "\r\n".join([
        "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//mittwald//tests//EN",
        "CALSCALE:GREGORIAN", "METHOD:PUBLISH", "X-WR-CALNAME:rota@example.com",
        *event("running", "Rufbereitschaft - Now", now - hour, now + hour),
        *event("upcoming", "Rufbereitschaft - Next", now + hour, now + 3 * hour),
        "END:VCALENDAR", "",
    ])


CALENDAR_CONFIG = {"datetime_timezone": "Europe/Berlin",
                   "calendar_url": "https://cal.example.com/a/b/calendar.ics"}


def _rota_calendar():
    return icalendar.Calendar.from_ical(_rota_ics())


@contextlib.contextmanager
def _patch_rota():
    with patch('hutbot.calendarfeed.fetch_calendar',
               new=AsyncMock(return_value=(_rota_calendar(), "Notfallhotline"))):
        yield


async def _preview(app, command, channel, user):
    with patch('hutbot.opsgenie.get_opsgenie_template_variables', new=AsyncMock(return_value={})), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, command, channel, user)
    return sent_messages(send)



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
    sent_message = sent_messages(mock_send_message)
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

    sent_message = await _preview(app, "alerts test", channel, user)

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
async def test_the_preview_reports_the_message_before_anything_else():
    """The rendered text is what somebody ran `test` to see, so nothing precedes it."""
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(), "reply_message": "Anybody? {{channel}}"}
    channel = Channel(id="C12345", name="general", configs={"default": config})
    user = User("U12345", "test", "Test User", "Testers")

    text = await _preview(app, "test", channel, user)

    assert text.startswith("*Reply preview for configuration `default`:*\nAnybody? #general")
    # And the whole namespace comes last, after the run, the variables it used and the events.
    assert text.index("*Variables used:*") < text.index("*All template variables:*")



@pytest.mark.asyncio
async def test_the_preview_resolves_the_destination_it_rendered():
    """A rota rule DMs whoever the calendar named, and only a preview can say who that is."""
    app = _ui_app()
    _seed_user_caches()
    config = {**copy.deepcopy(DEFAULT_CONFIG), **CALENDAR_CONFIG,
              "trigger": TRIGGER_CRON, "cron": "0 8 * * 1-5",
              "action": ACTION_DM_USER,
              "action_target": "{{calendar_other_attendee_users(nth=1)}}",
              "reply_message": "Du bist dran, {{calendar_other_attendees(nth=1)}}."}
    channel = _mk_channel({"rota": config})
    user = User("U1", "dave", "Dave", "T")

    with _patch_rota():
        text = await _preview(app, "rota test", channel, user)

    assert "*Message preview for configuration `rota`:*\nDu bist dran, Some User." in text
    assert "*Sent to* <@U1> (direct message)" in text
    # The rendered target beside the template it came from, so an empty DM is traceable.
    assert "*Target*: `{{calendar_other_attendee_users(nth=1)}}` → `<@U1>`" in text



@pytest.mark.asyncio
async def test_the_preview_says_when_the_rule_fires_next():
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(), "trigger": TRIGGER_CRON, "cron": "0 8 * * 1-5",
              "datetime_timezone": "Europe/Berlin"}
    channel = Channel(id="C12345", name="general", configs={"default": config})
    user = User("U12345", "test", "Test User", "Testers")

    text = await _preview(app, "test", channel, user)

    assert re.search(r"\*Trigger\*: `cron` `0 8 \* \* 1-5`, next run \w{3}, \d{2} \w{3} \d{4} 08:00 \(Europe/Berlin\)", text)



@pytest.mark.asyncio
async def test_a_message_rule_reports_where_and_when_it_replies():
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(), "wait_time": 600, "pattern": "urgent"}
    channel = Channel(id="C12345", name="general", configs={"default": config})
    user = User("U12345", "test", "Test User", "Testers")

    text = await _preview(app, "test", channel, user)

    assert "*Replied in* <#C12345> (in thread)" in text
    assert "*Trigger*: `message` in <#C12345> matching `urgent` (case-insensitive), 10 minutes after it arrives" in text



@pytest.mark.asyncio
async def test_the_preview_lists_the_variables_each_field_reads():
    """Grouped by the field that reads them, because that is what a fix has to be applied to."""
    app = _ui_app()
    _seed_user_caches()
    config = {**copy.deepcopy(DEFAULT_CONFIG), **CALENDAR_CONFIG,
              "reply_message": "Hallo {{calendar_other_attendees(nth=1)}}, bis {{calendar_end_time}}",
              "buttons": [{"label": "OK", "action": "ack", "value": "Danke {{user_name}}"}],
              "conditions": [{"variable": "calendar_summary", "operator": "contains", "value": "Rufbereitschaft"}]}
    channel = _mk_channel({"rota": config})
    user = User("U1", "dave", "Dave", "T")

    with _patch_rota():
        text = await _preview(app, "rota test", channel, user)

    used = text[text.index("*Variables used:*"):text.index("*Calendar*:")]
    assert "_Message_\n`{{calendar_other_attendees(nth=1)}}`: Some User" in used
    assert "`{{calendar_end_time}}`: " in used
    assert "_Ack text of `OK`_\n`{{user_name}}`: Dave" in used
    assert "_Conditions_\n`{{calendar_summary}}`: Rufbereitschaft - Now" in used
    # Only what the config reads: the rest of the namespace has its own section further down.
    assert "`{{opsgenie_current_user}}`" not in used



@pytest.mark.asyncio
async def test_the_preview_prints_a_clock_condition_at_the_moment_it_reads():
    """The condition line and the message read one value, so the verdict cannot disagree."""
    app = AsyncMock()
    config = {**copy.deepcopy(DEFAULT_CONFIG), "date_format": "%d.%m.%Y",
              "datetime_timezone": "Europe/Berlin",
              "reply_message": 'Deadline {{date(at="+2w")}}',
              "conditions": [{"variable": "date", "operator": "not_empty", "at": "+2w", "value": ""}]}
    channel = _mk_channel({"deadline": config})
    user = User("U1", "dave", "Dave", "T")

    text = await _preview(app, "deadline test", channel, user)

    assert '`{{date(at="+2w")}}` not_empty' in text
    # One rendered value, printed under both the message and the conditions.
    rendered = text[text.index("*Variables used:*"):]
    assert rendered.count('`{{date(at="+2w")}}`: ') == 2
    assert "would run" in text.lower()


@pytest.mark.asyncio
async def test_a_configuration_without_variables_says_so():
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(), "reply_message": "Anybody?"}
    channel = Channel(id="C12345", name="general", configs={"default": config})
    user = User("U12345", "test", "Test User", "Testers")

    text = await _preview(app, "test", channel, user)

    assert "*Variables used*: _none" in text



@pytest.mark.asyncio
async def test_the_preview_prints_every_event_it_resolved():
    """The events behind the values: same feed, same moments, no second fetch."""
    app = _ui_app()
    _seed_user_caches()
    config = {**copy.deepcopy(DEFAULT_CONFIG), **CALENDAR_CONFIG,
              "reply_message": "{{calendar_summary}} / {{calendar_summary(offset=next)}}"}
    channel = _mk_channel({"rota": config})
    user = User("U1", "dave", "Dave", "T")

    with _patch_rota():
        text = await _preview(app, "rota test", channel, user)

    assert "*Calendar*: `Notfallhotline`" in text
    assert "*Event* now, read at" in text
    assert "*Summary*: Rufbereitschaft - Now" in text
    assert "*Summary*: Rufbereitschaft - Next" in text
    # The detail a variable cannot show on its own: who is on the entry, and its body.
    assert "*Attendees*: Notfallhotline (hotline@example.com), Some User (x@example.com)" in text
    assert "*Other attendees*: Some User (x@example.com)" in text
    assert "*Description*: Ruf an, wenn was ist." in text



@pytest.mark.asyncio
async def test_the_preview_reads_the_whole_namespace_at_the_neighbouring_events():
    app = _ui_app()
    _seed_user_caches()
    config = {**copy.deepcopy(DEFAULT_CONFIG), **CALENDAR_CONFIG,
              "reply_message": "{{calendar_summary}}"}
    channel = _mk_channel({"rota": config})
    user = User("U1", "dave", "Dave", "T")

    with _patch_rota():
        text = await _preview(app, "rota test", channel, user)

    assert "*Calendar variables at `offset=next`:*" in text
    assert "`{{calendar_summary(offset=next)}}`: Rufbereitschaft - Next" in text
    assert "*Calendar variables at `offset=prev`:*" in text



@pytest.mark.asyncio
async def test_a_configuration_without_a_calendar_reports_no_events():
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={"default": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")

    text = await _preview(app, "test", channel, user)

    assert "*Calendar*" not in text
    assert "*Event*" not in text
    assert "offset=next" not in text



@pytest.mark.asyncio
async def test_the_preview_renders_the_button_texts_and_the_escalation():
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(),
              "buttons": [{"label": "OK", "action": "ack", "value": "Danke {{user_name}} :+1:"}],
              "escalation_timeout": 300 * 60, "escalation_kind": "button", "escalation_target": "OK"}
    channel = Channel(id="C12345", name="general", configs={"default": config})
    user = User("U12345", "test", "Test User", "Testers")

    text = await _preview(app, "test", channel, user)

    assert "*Buttons*: `OK` acknowledges and posts its text" in text
    assert "*Ack text* of `OK`: Danke Test User :+1:" in text
    assert "*Escalation*: after 300 minutes, auto-presses `OK`" in text



@pytest.mark.asyncio
async def test_the_preview_says_when_the_rule_would_not_run():
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(), "enabled": False,
              "action": ACTION_POST_CHANNEL, "action_target": ""}
    channel = Channel(id="C12345", name="general", configs={"default": config})
    user = User("U12345", "test", "Test User", "Testers")

    text = await _preview(app, "test", channel, user)

    # Only the trigger is cut off — `run`, a button and an escalation still reach it.
    assert "*Disabled*: its trigger does not fire it, but `/hutbot [config] run`, a button or an escalation still can" in text
    assert "*Cannot run*: action `post_channel` has no target" in text
    assert "This rule would *not* run — it is disabled, so its `message` trigger does not fire it." in text



@pytest.mark.asyncio
async def test_the_preview_reports_the_opsgenie_alert_it_would_send():
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(), "opsgenie": True, "opsgenie_schedule_name": "Platform",
              "opsgenie_priority": "P2", "opsgenie_message": "Nobody answered in {{channel}}"}
    channel = Channel(id="C12345", name="general", configs={"default": config})
    user = User("U12345", "test", "Test User", "Testers")

    with patch.object(hutbot.state, 'opsgenie_configured', True):
        text = await _preview(app, "test", channel, user)

    assert "*OpsGenie alert*: Nobody answered in #general (priority `P2`, schedule `Platform`)" in text



@pytest.mark.asyncio
async def test_a_group_dm_preview_stops_at_slacks_member_limit():
    """`action_group_dm` opens the conversation with the first eight, so the preview says who."""
    app = _ui_app()
    _seed_user_caches()
    people = [User(f"U{index}", f"user{index}", f"User {index}", "Platform") for index in range(1, 11)]
    hutbot.state.id_user_cache.update({person.id: person for person in people})
    config = {**DEFAULT_CONFIG.copy(), "action": ACTION_GROUP_DM,
              "action_target": " ".join(f"<@{person.id}>" for person in people)}
    channel = Channel(id="C12345", name="general", configs={"default": config})

    text = await _preview(app, "test", channel, people[0])

    assert "*Sent to* <@U1>, <@U2>, <@U3>, <@U4>, <@U5>, <@U6>, <@U7>, <@U8> (group message)" in text
    assert "<@U9>, <@U10> are left out by Slack's 8-member limit" in text



@pytest.mark.asyncio
async def test_the_preview_judges_the_gates_a_message_has_to_pass():
    """A pattern the test message does not match keeps the rule from ever being queued."""
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(), "pattern": "urgent", "included_teams": ["Testers"]}
    channel = Channel(id="C12345", name="general", configs={"default": config})
    user = User("U12345", "test", "Test User", "Testers")

    text = await _preview(app, "test", channel, user)

    assert ":white_check_mark: the sender matches this rule's audience" in text
    assert ":x: the message does not match `urgent` (case-insensitive), and there is no message here" in text
    assert "This rule would *not* run — the message does not match `urgent`" in text



@pytest.mark.asyncio
async def test_a_test_message_that_matches_passes_the_gates():
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(), "pattern": "urgent"}
    channel = Channel(id="C12345", name="general", configs={"default": config})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('hutbot.opsgenie.get_opsgenie_template_variables', new=AsyncMock(return_value={})), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, "test this is urgent", channel, user, allow_test_message=True)
    text = sent_messages(send)

    assert ":white_check_mark: the message matches `urgent` (case-insensitive)" in text
    assert "This rule would run." in text



@pytest.mark.asyncio
async def test_a_rule_outside_its_work_hours_would_not_run():
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(), "hours": ["09:00", "17:00"]}
    channel = Channel(id="C12345", name="general", configs={"default": config})
    user = User("U12345", "test", "Test User", "Testers")

    with patch('hutbot.datetimefmt.is_work_time', return_value=False):
        text = await _preview(app, "test", channel, user)

    assert ":x: now is outside the work hours 09:00 - 17:00" in text
    assert "This rule would *not* run — now is outside the work hours 09:00 - 17:00." in text



@pytest.mark.asyncio
async def test_a_cron_rule_is_not_judged_against_message_gates():
    """A pattern is dead weight on a `cron` rule, so it must not appear as a gate."""
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(), "trigger": TRIGGER_CRON, "cron": "0 8 * * *", "pattern": "urgent"}
    channel = Channel(id="C12345", name="general", configs={"default": config})
    user = User("U12345", "test", "Test User", "Testers")

    text = await _preview(app, "test", channel, user)

    assert "*Message gates:*" not in text
    assert "This rule would run." in text



@pytest.mark.asyncio
async def test_a_manual_rule_names_every_way_it_can_be_run():
    """A `config` button and an escalation run a manual rule, so `run` is not the only path."""
    app = AsyncMock()
    channel = Channel(id="C12345", name="general", configs={
        "page": {**DEFAULT_CONFIG.copy(), "trigger": "manual"},
        "incident": {**DEFAULT_CONFIG.copy(),
                     "buttons": [{"label": "Page", "action": "config", "value": "page"}],
                     "escalation_timeout": 300, "escalation_kind": "config", "escalation_target": "page"},
    })
    user = User("U12345", "test", "Test User", "Testers")

    text = await _preview(app, "page test", channel, user)

    assert "*Trigger*: `manual`, so nothing fires it on its own" in text
    assert "a `config` button or an escalation runs it" in text
    assert "*Also run by*: the button `Page` of `incident`, the escalation of `incident`" in text



@pytest.mark.asyncio
async def test_the_preview_flags_a_button_and_an_escalation_pointing_at_nothing():
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(),
              "buttons": [{"label": "Page", "action": "config", "value": "gone"},
                          {"label": "OK", "action": "ack", "value": ""}],
              "escalation_timeout": 600, "escalation_kind": "config", "escalation_target": "also-gone"}
    channel = Channel(id="C12345", name="general", configs={"default": config})
    user = User("U12345", "test", "Test User", "Testers")

    text = await _preview(app, "test", channel, user)

    assert "`Page` runs `gone` :warning: (no configuration `gone` in this channel)" in text
    assert "runs `also-gone` :warning: (no configuration `also-gone` in this channel)" in text



@pytest.mark.asyncio
async def test_the_preview_lists_every_config_a_button_or_escalation_runs():
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(),
              "buttons": [{"label": "Page", "action": "config", "value": "alarm, gone"}],
              "escalation_timeout": 600, "escalation_kind": "config", "escalation_target": "alarm, gone"}
    channel = Channel(id="C12345", name="general",
                      configs={"default": config, "alarm": DEFAULT_CONFIG.copy()})
    user = User("U12345", "test", "Test User", "Testers")

    text = await _preview(app, "test", channel, user)

    # Named in the order they run, with only the missing one flagged.
    assert "`Page` runs `alarm`, `gone` :warning: (no configuration `gone` in this channel)" in text
    assert "runs `alarm`, `gone` :warning: (no configuration `gone` in this channel)" in text
    # A rule named inside a list is still found by the "who runs me" listing.
    alarm_text = await _preview(app, "alarm test", channel, user)
    assert "*Also run by*: the button `Page` of `default`, the escalation of `default`" in alarm_text


@pytest.mark.asyncio
async def test_an_escalation_without_buttons_is_reported_as_inactive():
    """`run_action` only starts the timer for a message that carries buttons."""
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(), "buttons": [],
              "escalation_timeout": 600, "escalation_kind": "config", "escalation_target": "default"}
    channel = Channel(id="C12345", name="general", configs={"default": config})
    user = User("U12345", "test", "Test User", "Testers")

    text = await _preview(app, "test", channel, user)

    assert "*Escalation*: after 10 minutes, runs `default` — inactive: this rule posts no buttons" in text



@pytest.mark.asyncio
async def test_a_cron_rule_shows_the_empty_alert_body_it_would_send():
    """With no `opsgenie-message`, the alert carries the triggering message — and a cron has none."""
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(), "trigger": TRIGGER_CRON, "cron": "0 8 * * *",
              "opsgenie": True, "opsgenie_schedule_name": "Platform"}
    channel = Channel(id="C12345", name="general", configs={"default": config})
    user = User("U12345", "test", "Test User", "Testers")

    with patch.object(hutbot.state, 'opsgenie_configured', True):
        text = await _preview(app, "test", channel, user)

    assert "*OpsGenie alert*: _(empty)_" in text
    assert "this run has none, so the alert would go out with an empty body" in text
