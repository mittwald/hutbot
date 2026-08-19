import copy

from tests._common import *  # noqa: F401,F403

import icalendar

from hutbot.calendarfeed import (
    build_calendar_event,
    describe_calendar_url,
    fetch_calendar,
    find_current_and_next_events,
    get_calendar_placeholder_variables,
    validate_calendar_url,
)
from hutbot.constants import CALENDAR_DATETIME_TEMPLATE_VARIABLES


# A realistic published-Outlook feed: CRLF line endings, folded UID/ORGANIZER continuation
# lines, escaped `\n` in a long Teams DESCRIPTION, a Windows VTIMEZONE, an RRULE series with
# an EXDATE, an all-day event, a cancelled one, a transparent one, and a DURATION-only one.
SAMPLE_ICS = "\r\n".join([
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    "PRODID:-//Microsoft Corporation//Outlook 16.0 MIMEDIR//EN",
    "METHOD:PUBLISH",
    "X-WR-CALNAME:Team Kalender",
    "BEGIN:VTIMEZONE",
    "TZID:W. Europe Standard Time",
    "BEGIN:STANDARD",
    "DTSTART:16011028T030000",
    "TZOFFSETFROM:+0200",
    "TZOFFSETTO:+0100",
    "RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10",
    "END:STANDARD",
    "BEGIN:DAYLIGHT",
    "DTSTART:16010325T020000",
    "TZOFFSETFROM:+0100",
    "TZOFFSETTO:+0200",
    "RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=3",
    "END:DAYLIGHT",
    "END:VTIMEZONE",
    # The real sample event, folded exactly as Outlook emits it.
    "BEGIN:VEVENT",
    "UID:040000008200E00074C5B7101A82E008000000001468A3AD252EDD01000000000000000",
    " 010000000989440DBD852DB41A2D0BBCBD05ACD49-20260819T073500Z",
    "DTSTAMP:20260819T063026Z",
    "DTSTART:20260819T073500Z",
    "DTEND:20260819T083000Z",
    "SUMMARY:Composerbereitstellung",
    "LOCATION:Mario Kart",
    "DESCRIPTION:Einmal Benjamin abholen und sinnieren.\\n\\n_____________________",
    " ___________________________________________________________\\nMicrosoft Tea",
    " ms meeting\\nJoin: https://teams.microsoft.com/meet/355766204577407?p=aUGIx",
    " r19SjVkIwapqM\\nMeeting ID: 355 766 204 577 407\\nPasscode: o75NY2Zf",
    'ORGANIZER;CN="Michel Hopfner":mailto:/O=EXCHANGELABS/OU=EXCHANGE ADMINISTRA',
    " TIVE GROUP (FYDIBOHF23SPDLT)/CN=RECIPIENTS/CN=93292E5B58B74EB5960516D114B0",
    " ECD2-89B5B10E-06",
    "STATUS:CONFIRMED",
    "TRANSP:OPAQUE",
    "END:VEVENT",
    # All-day: DTEND is the RFC-exclusive next day.
    "BEGIN:VEVENT",
    "UID:allday-1",
    "DTSTAMP:20260819T063026Z",
    "DTSTART;VALUE=DATE:20260819",
    "DTEND;VALUE=DATE:20260820",
    "SUMMARY:Betriebsausflug",
    "END:VEVENT",
    # A multi-day conference covering the same instant.
    "BEGIN:VEVENT",
    "UID:multi-1",
    "DTSTAMP:20260819T063026Z",
    "DTSTART:20260818T060000Z",
    "DTEND:20260821T160000Z",
    "SUMMARY:Mehrtagskonferenz",
    "END:VEVENT",
    "BEGIN:VEVENT",
    "UID:cancelled-1",
    "DTSTAMP:20260819T063026Z",
    "DTSTART:20260819T075000Z",
    "DTEND:20260819T085000Z",
    "SUMMARY:Abgesagt",
    "STATUS:CANCELLED",
    "END:VEVENT",
    "BEGIN:VEVENT",
    "UID:transparent-1",
    "DTSTAMP:20260819T063026Z",
    "DTSTART:20260819T075500Z",
    "DTEND:20260819T081500Z",
    "SUMMARY:Frei verfuegbar",
    "TRANSP:TRANSPARENT",
    "END:VEVENT",
    "BEGIN:VEVENT",
    "UID:tentative-1",
    "DTSTAMP:20260819T063026Z",
    "DTSTART:20260819T110000Z",
    "DTEND:20260819T113000Z",
    "SUMMARY:Vielleicht",
    "STATUS:TENTATIVE",
    "END:VEVENT",
    # DURATION instead of DTEND.
    "BEGIN:VEVENT",
    "UID:duration-1",
    "DTSTAMP:20260819T063026Z",
    "DTSTART:20260819T120000Z",
    "DURATION:PT45M",
    "SUMMARY:Mit Dauer",
    "END:VEVENT",
    # Neither DTEND nor DURATION: zero length, per RFC.
    "BEGIN:VEVENT",
    "UID:nodtend-1",
    "DTSTAMP:20260819T063026Z",
    "DTSTART:20260819T140000Z",
    "SUMMARY:Ohne Ende",
    "END:VEVENT",
    # A weekday series in a Windows timezone, with one occurrence excluded.
    "BEGIN:VEVENT",
    "UID:series-1",
    "DTSTAMP:20260819T063026Z",
    "DTSTART;TZID=W. Europe Standard Time:20260819T110000",
    "DTEND;TZID=W. Europe Standard Time:20260819T113000",
    "SUMMARY:m3 daily",
    "LOCATION:Pong",
    'ORGANIZER;CN="mKubed":mailto:mkubed@example.com',
    "RRULE:FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR",
    "EXDATE;TZID=W. Europe Standard Time:20260820T110000",
    "END:VEVENT",
    "END:VCALENDAR",
])

# Pinned so nothing here depends on the wall clock.
NOW = datetime.datetime(2026, 8, 19, 8, 0, tzinfo=datetime.timezone.utc)
CONFIG = {"datetime_timezone": "Europe/Berlin", "calendar_url": "https://cal.example.com/a/b/calendar.ics"}


@pytest.fixture
def cal():
    return icalendar.Calendar.from_ical(SAMPLE_ICS)


def _live_ics(now=None):
    """An ICS whose events always straddle the caller's clock.

    A few tests go through the code paths that resolve "now" themselves
    (`render_action_text`, `run_action`), so a fixture pinned to a date would pass or fail
    depending on the hour the suite runs.
    """
    now = now or datetime.datetime.now(datetime.timezone.utc)
    fmt = "%Y%m%dT%H%M%SZ"
    started = (now - datetime.timedelta(minutes=10)).strftime(fmt)
    ends = (now + datetime.timedelta(minutes=50)).strftime(fmt)
    next_start = (now + datetime.timedelta(hours=2)).strftime(fmt)
    next_end = (now + datetime.timedelta(hours=2, minutes=30)).strftime(fmt)
    return "\r\n".join([
        "BEGIN:VCALENDAR", "VERSION:2.0", "X-WR-CALNAME:Team Kalender",
        "BEGIN:VEVENT", "UID:live-now", f"DTSTAMP:{started}",
        f"DTSTART:{started}", f"DTEND:{ends}",
        "SUMMARY:Composerbereitstellung", "LOCATION:Mario Kart",
        'ORGANIZER;CN="Michel Hopfner":mailto:michel@example.com',
        "END:VEVENT",
        "BEGIN:VEVENT", "UID:live-next", f"DTSTAMP:{started}",
        f"DTSTART:{next_start}", f"DTEND:{next_end}",
        "SUMMARY:m3 daily", "LOCATION:Pong", "END:VEVENT",
        "END:VCALENDAR",
    ])


@pytest.fixture
def live_cal():
    return icalendar.Calendar.from_ical(_live_ics())


def _event_named(calendar, summary, at=NOW):
    import recurring_ical_events
    query = recurring_ical_events.of(calendar, skip_bad_series=True)
    for event in query.between(at - datetime.timedelta(days=3), at + datetime.timedelta(days=3)):
        if str(event.get("SUMMARY")) == summary:
            return event
    raise AssertionError(f"no event named {summary!r}")


# ----- parsing -----

def test_calendar_name(cal):
    assert str(cal.get("X-WR-CALNAME")) == "Team Kalender"
    assert icalendar.Calendar.from_ical("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR").get("X-WR-CALNAME") is None


def test_folded_uid_is_reassembled(cal):
    event = build_calendar_event(_event_named(cal, "Composerbereitstellung"), CONFIG)
    assert event.uid.startswith("040000008200E00074C5B7101A82E008")
    assert " " not in event.uid and "\n" not in event.uid


def test_description_is_unfolded_and_unescaped(cal):
    event = build_calendar_event(_event_named(cal, "Composerbereitstellung"), CONFIG)
    assert event.description.startswith("Einmal Benjamin abholen und sinnieren.\n\n")
    assert "Microsoft Teams meeting" in event.description
    assert "\\n" not in event.description
    # vText leaks `vText(b'...')` through repr if it is not coerced with str().
    assert "vText" not in repr(event.description)
    assert type(event.description) is str


def test_plain_text_fields(cal):
    event = build_calendar_event(_event_named(cal, "Composerbereitstellung"), CONFIG)
    assert event.summary == "Composerbereitstellung"
    assert event.location == "Mario Kart"
    assert event.status == "CONFIRMED"
    assert type(event.summary) is str


def test_missing_status_reports_confirmed(cal):
    assert build_calendar_event(_event_named(cal, "Mehrtagskonferenz"), CONFIG).status == "CONFIRMED"


def test_tentative_status_is_preserved(cal):
    assert build_calendar_event(_event_named(cal, "Vielleicht"), CONFIG).status == "TENTATIVE"


# ----- organizer -----

def test_organizer_prefers_the_cn_over_an_x500_mailto(cal):
    """Exchange puts a useless X.500 DN in the mailto value, so CN has to win."""
    assert build_calendar_event(_event_named(cal, "Composerbereitstellung"), CONFIG).organizer == "Michel Hopfner"


def test_organizer_falls_back_to_a_real_address():
    ics = "\r\n".join([
        "BEGIN:VCALENDAR", "VERSION:2.0", "BEGIN:VEVENT", "UID:o-1",
        "DTSTAMP:20260819T060000Z", "DTSTART:20260819T075000Z", "DTEND:20260819T085000Z",
        "SUMMARY:Bare mailto", "ORGANIZER:mailto:jane@example.com", "END:VEVENT", "END:VCALENDAR",
    ])
    calendar = icalendar.Calendar.from_ical(ics)
    assert build_calendar_event(_event_named(calendar, "Bare mailto"), CONFIG).organizer == "jane@example.com"


def test_organizer_rejects_an_x500_dn_without_a_cn():
    ics = "\r\n".join([
        "BEGIN:VCALENDAR", "VERSION:2.0", "BEGIN:VEVENT", "UID:o-2",
        "DTSTAMP:20260819T060000Z", "DTSTART:20260819T075000Z", "DTEND:20260819T085000Z",
        "SUMMARY:DN only",
        "ORGANIZER:mailto:/O=EXCHANGELABS/OU=EXCHANGE ADMINISTRATIVE GROUP/CN=RECIPIENTS/CN=ABC",
        "END:VEVENT", "END:VCALENDAR",
    ])
    calendar = icalendar.Calendar.from_ical(ics)
    assert build_calendar_event(_event_named(calendar, "DN only"), CONFIG).organizer == ""


def test_organizer_absent(cal):
    assert build_calendar_event(_event_named(cal, "Betriebsausflug"), CONFIG).organizer == ""


# ----- current / next selection -----

def test_current_prefers_the_specific_timed_event(cal):
    """Three events cover 08:00Z. "Earliest start" would pick the wrong one."""
    current, _ = find_current_and_next_events(cal, CONFIG, NOW)
    assert current.summary == "Composerbereitstellung"
    assert current.summary not in ("Betriebsausflug", "Mehrtagskonferenz")


def test_current_skips_cancelled_but_keeps_transparent(cal):
    current, _ = find_current_and_next_events(cal, CONFIG, NOW)
    assert current.summary != "Abgesagt"
    # A transparent event is still an event; it just does not occupy the owner.
    assert hutbot.calendarfeed._is_usable(_event_named(cal, "Frei verfuegbar")) is True
    assert hutbot.calendarfeed._is_busy(_event_named(cal, "Frei verfuegbar")) is False
    assert hutbot.calendarfeed._is_usable(_event_named(cal, "Abgesagt")) is False


def test_next_skips_the_running_event(cal):
    """`after()` yields ongoing events first, so "next" must filter on the start."""
    current, next_event = find_current_and_next_events(cal, CONFIG, NOW)
    assert next_event.summary != current.summary
    assert next_event.summary == "m3 daily"
    assert next_event.start > current.start


def test_exdate_occurrence_is_excluded(cal):
    # The 20th is excluded, so the series next appears on the 21st.
    _, next_event = find_current_and_next_events(cal, CONFIG, datetime.datetime(2026, 8, 19, 12, 0, tzinfo=datetime.timezone.utc))
    assert next_event.summary != "m3 daily" or not next_event.start.startswith("2026-08-20")

    _, from_the_20th = find_current_and_next_events(cal, CONFIG, datetime.datetime(2026, 8, 20, 6, 0, tzinfo=datetime.timezone.utc))
    assert not (from_the_20th.summary == "m3 daily" and from_the_20th.start.startswith("2026-08-20"))


def test_rrule_series_survives_a_dst_change(cal):
    """The Windows VTIMEZONE resolves, so a 11:00 local slot shifts with the offset."""
    _, summer = find_current_and_next_events(cal, CONFIG, datetime.datetime(2026, 8, 19, 8, 30, tzinfo=datetime.timezone.utc))
    assert summer.summary == "m3 daily"
    assert summer.start.endswith("+02:00")

    _, winter = find_current_and_next_events(cal, CONFIG, datetime.datetime(2026, 12, 8, 6, 0, tzinfo=datetime.timezone.utc))
    assert winter.summary == "m3 daily"
    assert winter.start.endswith("+01:00")


def test_empty_calendar_yields_nothing():
    calendar = icalendar.Calendar.from_ical("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR")
    assert find_current_and_next_events(calendar, CONFIG, NOW) == (None, None)


def test_all_past_calendar_yields_nothing(cal):
    current, next_event = find_current_and_next_events(cal, CONFIG, datetime.datetime(2027, 6, 1, 8, 0, tzinfo=datetime.timezone.utc))
    # The weekday series runs forever, so only a feed without one goes fully quiet.
    assert current is None or current.summary == "m3 daily"
    assert next_event is None or next_event.summary == "m3 daily"


def test_naive_now_is_treated_as_utc(cal):
    current, _ = find_current_and_next_events(cal, CONFIG, datetime.datetime(2026, 8, 19, 8, 0))
    assert current.summary == "Composerbereitstellung"


# ----- all-day and end-time edge cases -----

def test_all_day_start_is_midnight_in_the_config_timezone(cal):
    event = build_calendar_event(_event_named(cal, "Betriebsausflug"), CONFIG)
    assert event.all_day is True
    assert event.start == "2026-08-19T00:00:00+02:00"


def test_all_day_end_is_the_inclusive_last_day(cal):
    """DTEND is 20260820 for a one-day event on the 19th; a reader wants the 19th."""
    event = build_calendar_event(_event_named(cal, "Betriebsausflug"), CONFIG)
    assert event.end.startswith("2026-08-19")


def test_multi_day_all_day_end_is_the_inclusive_last_day():
    ics = "\r\n".join([
        "BEGIN:VCALENDAR", "VERSION:2.0", "BEGIN:VEVENT", "UID:ad-2",
        "DTSTAMP:20260819T060000Z", "DTSTART;VALUE=DATE:20260819", "DTEND;VALUE=DATE:20260822",
        "SUMMARY:Drei Tage", "END:VEVENT", "END:VCALENDAR",
    ])
    calendar = icalendar.Calendar.from_ical(ics)
    event = build_calendar_event(_event_named(calendar, "Drei Tage"), CONFIG)
    assert event.start.startswith("2026-08-19") and event.end.startswith("2026-08-21")


def test_duration_is_used_when_there_is_no_dtend(cal):
    event = build_calendar_event(_event_named(cal, "Mit Dauer"), CONFIG)
    assert event.start.endswith("12:00:00+00:00") and event.end.endswith("12:45:00+00:00")


def test_missing_dtend_and_duration_is_zero_length(cal):
    event = build_calendar_event(_event_named(cal, "Ohne Ende"), CONFIG)
    assert event.start == event.end


# ----- template variables -----

def test_placeholders_cover_exactly_the_declared_variables():
    variables = get_calendar_placeholder_variables(CONFIG)
    public = {key for key in variables if not key.startswith("__")}
    assert public == CALENDAR_TEMPLATE_VARIABLES
    raw = {key for key in variables if key.startswith("__")}
    assert raw == {f"__{name}_raw" for name in CALENDAR_DATETIME_TEMPLATE_VARIABLES}


def test_placeholders_without_a_feed_say_so():
    variables = get_calendar_placeholder_variables({})
    assert variables["calendar_name"] == "<no-calendar-set>"
    assert variables["calendar_current_summary"] == "<no-event>"


def test_placeholder_calendar_name_is_redacted():
    assert get_calendar_placeholder_variables(CONFIG)["calendar_name"] == "cal.example.com/…/calendar.ics"


@pytest.mark.asyncio
async def test_template_variables_from_a_fetched_feed(cal):
    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(cal, "Team Kalender"))):
        variables = await hutbot.calendarfeed.get_calendar_template_variables(CONFIG, NOW)
    assert variables["calendar_name"] == "Team Kalender"
    assert variables["calendar_current_summary"] == "Composerbereitstellung"
    assert variables["calendar_current_location"] == "Mario Kart"
    assert variables["calendar_current_organizer"] == "Michel Hopfner"
    assert variables["calendar_next_summary"] == "m3 daily"
    # Rendered in the config timezone: 07:35Z is 09:35 in Berlin.
    assert variables["calendar_current_start_time"] == "09:35"
    assert variables["__calendar_current_start_datetime_raw"].startswith("2026-08-19T07:35")


@pytest.mark.asyncio
async def test_template_variables_without_a_url_are_all_placeholders():
    variables = await hutbot.calendarfeed.get_calendar_template_variables({})
    assert variables["calendar_current_summary"] == "<no-event>"


@pytest.mark.asyncio
async def test_calendar_datetime_variables_accept_format_arguments(live_cal):
    config = {**CONFIG, "reply_message": "{{calendar_current_start_datetime(fmt='02.01.2006 15:04', tz='Europe/Berlin', lc=de-DE)}}"}
    app = AsyncMock()
    channel = _mk_channel({"cal": config})
    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(live_cal, "Team Kalender"))), \
         patch('hutbot.slackcache.get_message_permalink', new=AsyncMock(return_value="")):
        text = await hutbot.actions.render_action_text(app, "token", channel, config, "cal", {"channel_id": "C12345"})
    current, _ = find_current_and_next_events(live_cal, config)
    expected = datetime.datetime.fromisoformat(current.start).astimezone(ZoneInfo("Europe/Berlin"))
    assert text == expected.strftime("%d.%m.%Y %H:%M")


def test_calendar_scalar_variables_reject_arguments():
    error = hutbot.templating.validate_template_expressions("{{calendar_current_summary(fmt='x')}}")
    assert "does not support arguments" in error
    assert hutbot.templating.validate_template_expressions("{{calendar_current_start_time(tz='UTC')}}") == ""


def test_calendar_variables_are_supported_template_variables():
    assert CALENDAR_TEMPLATE_VARIABLES <= SUPPORTED_TEMPLATE_VARIABLES
    assert hutbot.templating.validate_template_expressions("{{calendar_next_end_date}}") == ""


# ----- URL validation -----

@pytest.mark.parametrize("url", [
    "https://outlook.office365.com/owa/calendar/abc@tenant/xyz/calendar.ics",
    "https://cal.example.com/feed.ics",
])
def test_validate_calendar_url_accepts_public_https(url):
    assert validate_calendar_url(url) == url


@pytest.mark.parametrize("url,expected", [
    ("http://cal.example.com/feed.ics", "https"),
    ("file:///etc/passwd", "https"),
    ("ftp://cal.example.com/feed.ics", "https"),
    ("https://user:pw@cal.example.com/feed.ics", "credentials"),
    ("https://127.0.0.1/feed.ics", "internal"),
    ("https://169.254.169.254/latest/meta-data", "internal"),
    ("https://10.0.0.1/feed.ics", "internal"),
    ("https://192.168.1.1/feed.ics", "internal"),
    ("https://localhost/feed.ics", "localhost"),
    ("", "non-empty"),
    ("   ", "non-empty"),
])
def test_validate_calendar_url_rejections(url, expected):
    with pytest.raises(ValueError) as excinfo:
        validate_calendar_url(url)
    assert expected in str(excinfo.value)


def test_describe_calendar_url_redacts_the_path():
    described = describe_calendar_url("https://outlook.office365.com/owa/calendar/secret-guid@tenant/other-guid/calendar.ics")
    assert described == "outlook.office365.com/…/calendar.ics"
    assert "secret-guid" not in described
    assert describe_calendar_url("") == ""


# ----- Slack link unwrapping -----

@pytest.mark.parametrize("typed", [
    "https://cal.example.com/feed.ics",
    "<https://cal.example.com/feed.ics>",
    "<https://cal.example.com/feed.ics|cal.example.com/feed.ics>",
    '"https://cal.example.com/feed.ics"',
    "  <https://cal.example.com/feed.ics>  ",
])
def test_unwrap_slack_link(typed):
    assert unwrap_slack_link(typed) == "https://cal.example.com/feed.ics"


# ----- fetching and caching -----

class _FakeResponse:
    def __init__(self, status=200, text="", content_length=None):
        self.status = status
        self._text = text
        self.content_length = content_length if content_length is not None else len(text)

    async def text(self):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


class _FakeSession:
    def __init__(self, response, counter):
        self._response = response
        self._counter = counter

    def get(self, url, **kwargs):
        self._counter.append(url)
        return self._response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


def _patch_http(response, counter):
    return patch('hutbot.calendarfeed.aiohttp.ClientSession', lambda *a, **k: _FakeSession(response, counter))


@pytest.mark.asyncio
async def test_fetch_calendar_parses_and_caches():
    calls = []
    with _patch_http(_FakeResponse(text=SAMPLE_ICS), calls):
        calendar, name = await fetch_calendar("https://cal.example.com/feed.ics")
        assert name == "Team Kalender" and calendar is not None
        # Second call inside the TTL must not hit the network again.
        again, again_name = await fetch_calendar("https://cal.example.com/feed.ics")
    assert len(calls) == 1
    assert again is calendar and again_name == name


@pytest.mark.asyncio
async def test_fetch_calendar_refetches_after_the_ttl():
    calls = []
    with _patch_http(_FakeResponse(text=SAMPLE_ICS), calls), \
         patch('hutbot.calendarfeed._CALENDAR_TTL', 0):
        await fetch_calendar("https://cal.example.com/feed.ics")
        await fetch_calendar("https://cal.example.com/feed.ics")
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_state_reset_clears_the_calendar_cache():
    calls = []
    with _patch_http(_FakeResponse(text=SAMPLE_ICS), calls):
        await fetch_calendar("https://cal.example.com/feed.ics")
        assert hutbot.state._calendar_cache
        hutbot.state.reset()
        assert hutbot.state._calendar_cache == {}
        await fetch_calendar("https://cal.example.com/feed.ics")
    assert len(calls) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("response", [
    _FakeResponse(status=404, text="nope"),
    _FakeResponse(status=500, text="boom"),
    # An HTML sign-in page rather than a calendar.
    _FakeResponse(text="<html><body>Please sign in</body></html>"),
    # Oversized.
    _FakeResponse(text="BEGIN:VCALENDAR", content_length=99 * 1024 * 1024),
])
async def test_fetch_calendar_degrades_without_raising(response):
    with _patch_http(response, []):
        assert await fetch_calendar("https://cal.example.com/feed.ics") == (None, "")


@pytest.mark.asyncio
async def test_fetch_calendar_survives_a_transport_error():
    class _Boom:
        def get(self, url, **kwargs):
            raise RuntimeError("connection reset")

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

    with patch('hutbot.calendarfeed.aiohttp.ClientSession', lambda *a, **k: _Boom()):
        assert await fetch_calendar("https://cal.example.com/feed.ics") == (None, "")


@pytest.mark.asyncio
async def test_fetch_calendar_without_a_url_does_nothing():
    assert await fetch_calendar("") == (None, "")
    assert await fetch_calendar("   ") == (None, "")


@pytest.mark.asyncio
async def test_resolve_calendar_context_without_a_feed():
    context = await hutbot.calendarfeed.resolve_calendar_context({})
    assert context.name == "" and context.current is None and context.next is None


# ----- commands -----

@pytest.mark.asyncio
async def test_set_calendar_unwraps_the_slack_link_and_confirms_redacted():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")
    url = "https://outlook.office365.com/owa/calendar/secret-guid@tenant/other/calendar.ics"
    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, f"set calendar <{url}|outlook.office365.com>", channel, user)
    assert channel.configs["default"]["calendar_url"] == url
    confirmation = send.call_args.args[3]
    assert "outlook.office365.com/…/calendar.ics" in confirmation
    assert "secret-guid" not in confirmation


@pytest.mark.asyncio
async def test_set_calendar_rejects_plain_http():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")
    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, "set calendar <http://cal.example.com/feed.ics>", channel, user)
    assert channel.configs["default"]["calendar_url"] == ""
    assert "Invalid *calendar URL*" in send.call_args.args[3]


@pytest.mark.asyncio
async def test_clear_calendar():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")
    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message'):
        await process_command(app, "set calendar https://cal.example.com/feed.ics", channel, user)
        await process_command(app, "clear calendar", channel, user)
    assert channel.configs["default"]["calendar_url"] == ""


@pytest.mark.asyncio
async def test_show_calendar_prints_current_and_next(cal):
    """The live command resolves against the real clock, so pin the context, not the time."""
    app = AsyncMock()
    config = {**copy.deepcopy(DEFAULT_CONFIG), **CONFIG}
    channel = _mk_channel({"default": config})
    user = User("U1", "dave", "Dave", "T")
    current, next_event = find_current_and_next_events(cal, config, NOW)
    context = hutbot.models.CalendarContext("Team Kalender", current, next_event)
    with patch('hutbot.calendarfeed.resolve_calendar_context', new=AsyncMock(return_value=context)), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, "show calendar", channel, user)
    text = send.call_args.args[3]
    assert "Team Kalender" in text
    assert "*Now*: Composerbereitstellung" in text and "Mario Kart" in text
    assert "Michel Hopfner" in text
    assert "*Next*: m3 daily" in text


@pytest.mark.asyncio
async def test_show_calendar_reports_an_empty_calendar():
    app = AsyncMock()
    config = {**copy.deepcopy(DEFAULT_CONFIG), **CONFIG}
    channel = _mk_channel({"default": config})
    user = User("U1", "dave", "Dave", "T")
    context = hutbot.models.CalendarContext("Team Kalender", None, None)
    with patch('hutbot.calendarfeed.resolve_calendar_context', new=AsyncMock(return_value=context)), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, "show calendar", channel, user)
    assert "No current or upcoming events" in send.call_args.args[3]


@pytest.mark.asyncio
async def test_show_calendar_without_a_feed_says_so():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")
    with patch('hutbot.messaging.send_message') as send:
        await process_command(app, "show calendar", channel, user)
    assert "No calendar configured" in send.call_args.args[3]


@pytest.mark.asyncio
async def test_show_config_shows_only_the_redacted_calendar_url():
    app = AsyncMock()
    url = "https://outlook.office365.com/owa/calendar/secret-guid@tenant/other/calendar.ics"
    channel = _mk_channel({"default": {**copy.deepcopy(DEFAULT_CONFIG), "calendar_url": url}})
    user = User("U1", "dave", "Dave", "T")
    with patch('hutbot.messaging.send_message') as send:
        await show_config(app, channel, user, "")
    text = sent_messages(send)
    assert "outlook.office365.com/…/calendar.ics" in text
    assert "secret-guid" not in text


@pytest.mark.asyncio
async def test_calendar_patterns_are_recognised_as_commands():
    for text in ("set calendar https://x/y.ics", "clear calendar", "show calendar", "calendar"):
        assert hutbot.commands.dispatch.matches_a_command(text), text


# ----- lazy fetching -----

@pytest.mark.asyncio
async def test_calendar_is_not_fetched_when_no_variable_references_it():
    app = AsyncMock()
    config = {**copy.deepcopy(DEFAULT_CONFIG), **CONFIG, "reply_message": "Anybody?"}
    channel = _mk_channel({"plain": config})
    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(None, ""))) as fetch, \
         patch('hutbot.slackcache.get_message_permalink', new=AsyncMock(return_value="")):
        await hutbot.actions.render_action_text(app, "token", channel, config, "plain", {"channel_id": "C12345"})
    fetch.assert_not_awaited()


@pytest.mark.asyncio
async def test_calendar_is_fetched_once_when_a_variable_references_it(live_cal):
    app = AsyncMock()
    config = {**copy.deepcopy(DEFAULT_CONFIG), **CONFIG, "reply_message": "Now: {{calendar_current_summary}}"}
    channel = _mk_channel({"cal": config})
    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(live_cal, "Team Kalender"))) as fetch, \
         patch('hutbot.slackcache.get_message_permalink', new=AsyncMock(return_value="")):
        text = await hutbot.actions.render_action_text(app, "token", channel, config, "cal", {"channel_id": "C12345"})
    assert fetch.await_count == 1
    assert "Composerbereitstellung" in text


@pytest.mark.asyncio
async def test_calendar_condition_gates_a_rule(live_cal):
    """The whole point: a rule that only runs while a matching event is on."""
    app = AsyncMock()
    config = {**copy.deepcopy(DEFAULT_CONFIG), **CONFIG, "reply_message": "standup time"}
    config["conditions"] = [{"variable": "calendar_current_summary", "operator": "contains",
                             "value": "composer", "case_sensitive": False}]
    channel = _mk_channel({"gated": config})
    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(live_cal, "Team Kalender"))), \
         patch('hutbot.slackcache.get_message_permalink', new=AsyncMock(return_value="")), \
         patch('hutbot.messaging._post_message', new=AsyncMock(return_value={"channel": "C12345", "ts": "9.1"})) as post:
        posted, reason = await hutbot.actions.run_action_with_reason(
            app, "token", channel, config, "gated", context={"channel_id": "C12345"})
    assert posted is not None and reason == ""
    assert post.await_count == 1


@pytest.mark.asyncio
async def test_calendar_condition_blocks_when_no_event_matches(live_cal):
    app = AsyncMock()
    config = {**copy.deepcopy(DEFAULT_CONFIG), **CONFIG, "reply_message": "standup time"}
    config["conditions"] = [{"variable": "calendar_current_summary", "operator": "contains",
                             "value": "no such meeting", "case_sensitive": False}]
    channel = _mk_channel({"gated": config})
    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(live_cal, "Team Kalender"))), \
         patch('hutbot.slackcache.get_message_permalink', new=AsyncMock(return_value="")), \
         patch('hutbot.messaging._post_message', new=AsyncMock()) as post:
        posted, reason = await hutbot.actions.run_action_with_reason(
            app, "token", channel, config, "gated", context={"channel_id": "C12345"})
    assert posted is None and "did not match" in reason
    post.assert_not_awaited()
