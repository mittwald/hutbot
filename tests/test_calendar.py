import base64
import contextlib
import copy
import json

from tests._common import *  # noqa: F401,F403

import icalendar

from hutbot.calendarfeed import (
    build_calendar_event,
    builtin_calendar_names,
    describe_calendar_feed,
    describe_calendar_url,
    fetch_calendar,
    get_calendar_placeholder_variables,
    index_calendar,
    load_builtin_calendars,
    lookup_builtin_calendar,
    normalize_builtin_calendar_name,
    parse_builtin_calendars,
    resolve_calendar_feed,
    select_event,
    validate_calendar_url,
)
from hutbot.constants import (
    CALENDAR_DATETIME_TEMPLATE_VARIABLES,
    CALENDAR_SELECTIONS_KEY,
    CALENDAR_TEMPLATE_VARIABLES,
    EVENT_OFFSET_SAME_DAY,
    event_slice_name,
    event_slice_prefix,
    parse_event_offset,
    UNKNOWN_CALENDAR_BUILTIN_PLACEHOLDER,
    UNKNOWN_CALENDAR_PLACEHOLDER,
)


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
    current, _ = _current_and_next(cal, CONFIG, NOW)
    assert current.summary == "Composerbereitstellung"
    assert current.summary not in ("Betriebsausflug", "Mehrtagskonferenz")


def test_current_skips_cancelled_but_keeps_transparent(cal):
    current, _ = _current_and_next(cal, CONFIG, NOW)
    assert current.summary != "Abgesagt"
    # A transparent event is still an event; it just does not occupy the owner.
    assert hutbot.calendarfeed._is_usable(_event_named(cal, "Frei verfuegbar")) is True
    assert hutbot.calendarfeed._is_busy(_event_named(cal, "Frei verfuegbar")) is False
    assert hutbot.calendarfeed._is_usable(_event_named(cal, "Abgesagt")) is False


def test_next_skips_the_running_event(cal):
    """`after()` yields ongoing events first, so "next" must filter on the start."""
    current, next_event = _current_and_next(cal, CONFIG, NOW)
    assert next_event.summary != current.summary
    assert next_event.summary == "m3 daily"
    assert next_event.start > current.start


def test_exdate_occurrence_is_excluded(cal):
    # The 20th is excluded, so the series next appears on the 21st.
    _, next_event = _current_and_next(cal, CONFIG, datetime.datetime(2026, 8, 19, 12, 0, tzinfo=datetime.timezone.utc))
    assert next_event.summary != "m3 daily" or not next_event.start.startswith("2026-08-20")

    _, from_the_20th = _current_and_next(cal, CONFIG, datetime.datetime(2026, 8, 20, 6, 0, tzinfo=datetime.timezone.utc))
    assert not (from_the_20th.summary == "m3 daily" and from_the_20th.start.startswith("2026-08-20"))


def test_rrule_series_survives_a_dst_change(cal):
    """The Windows VTIMEZONE resolves, so a 11:00 local slot shifts with the offset."""
    _, summer = _current_and_next(cal, CONFIG, datetime.datetime(2026, 8, 19, 8, 30, tzinfo=datetime.timezone.utc))
    assert summer.summary == "m3 daily"
    assert summer.start.endswith("+02:00")

    _, winter = _current_and_next(cal, CONFIG, datetime.datetime(2026, 12, 8, 6, 0, tzinfo=datetime.timezone.utc))
    assert winter.summary == "m3 daily"
    assert winter.start.endswith("+01:00")


def test_empty_calendar_yields_nothing():
    calendar = icalendar.Calendar.from_ical("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR")
    assert _current_and_next(calendar, CONFIG, NOW) == (None, None)


def test_all_past_calendar_yields_nothing(cal):
    current, next_event = _current_and_next(cal, CONFIG, datetime.datetime(2027, 6, 1, 8, 0, tzinfo=datetime.timezone.utc))
    # The weekday series runs forever, so only a feed without one goes fully quiet.
    assert current is None or current.summary == "m3 daily"
    assert next_event is None or next_event.summary == "m3 daily"


def test_naive_now_is_treated_as_utc(cal):
    current, _ = _current_and_next(cal, CONFIG, datetime.datetime(2026, 8, 19, 8, 0))
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
    internal = {key for key in variables if key.startswith("__")}
    assert internal == (
        {f"__{name}_raw" for name in CALENDAR_DATETIME_TEMPLATE_VARIABLES}
        | {f"__{name}_items" for name in hutbot.constants.CALENDAR_LIST_TEMPLATE_VARIABLES}
    )
    # A list with no event behind it has no items, so `empty` is true for it.
    for name in hutbot.constants.CALENDAR_LIST_TEMPLATE_VARIABLES:
        assert variables[f"__{name}_items"] == []


def test_placeholders_without_a_feed_say_so():
    variables = get_calendar_placeholder_variables({})
    assert variables["calendar_name"] == "<no-calendar-set>"
    assert variables["calendar_summary"] == "<no-event>"


def test_placeholder_calendar_name_is_redacted():
    assert get_calendar_placeholder_variables(CONFIG)["calendar_name"] == "cal.example.com/…"


@pytest.mark.asyncio
async def test_template_variables_from_a_fetched_feed(cal):
    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(cal, "Team Kalender"))):
        variables = await hutbot.calendarfeed.get_calendar_template_variables(
            None, CONFIG, NOW, selectors=[("", "next")])
    assert variables["calendar_name"] == "Team Kalender"
    assert variables["calendar_summary"] == "Composerbereitstellung"
    assert variables["calendar_location"] == "Mario Kart"
    assert variables["calendar_organizer"] == "Michel Hopfner"
    # The next event lives in its own slice, keyed by the selector that asked for it.
    assert variables[f"__{event_slice_name('calendar_summary', '', 'next')}"] == "m3 daily"
    # Rendered in the config timezone: 07:35Z is 09:35 in Berlin.
    assert variables["calendar_start_time"] == "09:35"
    assert variables["__calendar_start_datetime_raw"].startswith("2026-08-19T07:35")


@pytest.mark.asyncio
async def test_template_variables_without_a_url_are_all_placeholders():
    variables = await hutbot.calendarfeed.get_calendar_template_variables(None, {})
    assert variables["calendar_summary"] == "<no-event>"


@pytest.mark.asyncio
async def test_calendar_datetime_variables_accept_format_arguments(live_cal):
    _seed_user_caches()
    config = {**CONFIG, "reply_message": "{{calendar_start_datetime(fmt='02.01.2006 15:04', tz='Europe/Berlin', lc=de-DE)}}"}
    app = AsyncMock()
    channel = _mk_channel({"cal": config})
    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(live_cal, "Team Kalender"))), \
         patch('hutbot.slackcache.get_message_permalink', new=AsyncMock(return_value="")):
        text = await hutbot.actions.render_action_text(app, OPSGENIE_TOKENS, channel, config, "cal", {"channel_id": "C12345"})
    current, _ = _current_and_next(live_cal, config)
    expected = datetime.datetime.fromisoformat(current.start).astimezone(ZoneInfo("Europe/Berlin"))
    assert text == expected.strftime("%d.%m.%Y %H:%M")


def test_calendar_scalar_variables_reject_arguments():
    error = hutbot.templating.validate_template_expressions("{{calendar_summary(fmt='x')}}")
    assert "takes only `at` and `offset`" in error
    assert hutbot.templating.validate_template_expressions("{{calendar_start_time(tz='UTC')}}") == ""


def test_calendar_variables_are_supported_template_variables():
    assert CALENDAR_TEMPLATE_VARIABLES <= SUPPORTED_TEMPLATE_VARIABLES
    assert hutbot.templating.validate_template_expressions("{{calendar_end_date(offset=next)}}") == ""


# ----- URL validation -----

@pytest.mark.parametrize("url", [
    "https://outlook.office365.com/owa/calendar/abc@tenant/xyz/calendar.ics",
    "https://cal.example.com/feed.ics",
])
def test_validate_calendar_url_accepts_public_https(url):
    assert validate_calendar_url(url) == url


@pytest.mark.parametrize("url", [
    # Serving a feed from a local file server is how this gets developed, so loopback is
    # allowed without TLS. Everything else still has to be https.
    "http://127.0.0.1:8073/calendar.ics?5363fdaeabdfbd2b2b91a8112d7040e36bab6fa6b477c0d6",
    "http://localhost:8073/calendar.ics",
    "http://[::1]:8073/calendar.ics",
    "http://dev.localhost:9000/calendar.ics",
    "https://127.0.0.1/calendar.ics",
    "https://localhost/calendar.ics",
])
def test_validate_calendar_url_allows_plain_http_for_loopback(url):
    assert validate_calendar_url(url) == url


@pytest.mark.parametrize("url,expected", [
    # Plain http is only for loopback.
    ("http://cal.example.com/feed.ics", "only allowed for localhost"),
    ("http://10.0.0.1/feed.ics", "only allowed for localhost"),
    ("http://169.254.169.254/latest/meta-data", "only allowed for localhost"),
    ("ftp://cal.example.com/feed.ics", "https"),
    ("file:///etc/passwd", "has no host"),
    ("https://user:pw@cal.example.com/feed.ics", "credentials"),
    # The addresses that make SSRF worth attempting stay refused even over https.
    ("https://169.254.169.254/latest/meta-data", "internal"),
    ("https://10.0.0.1/feed.ics", "internal"),
    ("https://192.168.1.1/feed.ics", "internal"),
    ("https://172.16.0.1/feed.ics", "internal"),
    ("", "non-empty"),
    ("   ", "non-empty"),
])
def test_validate_calendar_url_rejections(url, expected):
    with pytest.raises(ValueError) as excinfo:
        validate_calendar_url(url)
    assert expected in str(excinfo.value)


def test_validate_calendar_url_accepts_an_allow_listed_internal_host():
    """An operator-named host is exempt from the address check; the name matches case-folded."""
    url = "https://bridge.internal.example/feed.ics"
    with patch('hutbot.calendarfeed._CALENDAR_ALLOWED_HOSTS', frozenset({"bridge.internal.example"})):
        assert validate_calendar_url(url) == url
        assert validate_calendar_url("https://BRIDGE.Internal.Example/feed.ics") == \
            "https://BRIDGE.Internal.Example/feed.ics"


def test_validate_calendar_url_accepts_an_allow_listed_literal_address():
    """Naming the address itself works too — the host is compared as written."""
    with patch('hutbot.calendarfeed._CALENDAR_ALLOWED_HOSTS', frozenset({"10.42.41.4"})):
        assert validate_calendar_url("https://10.42.41.4/feed.ics") == "https://10.42.41.4/feed.ics"


def test_allow_listing_one_host_does_not_widen_to_others():
    with patch('hutbot.calendarfeed._CALENDAR_ALLOWED_HOSTS', frozenset({"bridge.internal.example"})):
        assert hutbot.calendarfeed._is_allowed_host("bridge.internal.example")
        # Exact match, not a suffix one: a name below the exempt one is a different host and
        # could be registered by somebody else entirely.
        assert not hutbot.calendarfeed._is_allowed_host("evil.bridge.internal.example")
        assert not hutbot.calendarfeed._is_allowed_host("other.internal.example")
        # An unlisted internal address is refused as before ...
        with pytest.raises(ValueError) as excinfo:
            validate_calendar_url("https://10.0.0.1/feed.ics")
        assert "internal" in str(excinfo.value)
        # ... and the exemption does not buy plain http.
        with pytest.raises(ValueError) as excinfo:
            validate_calendar_url("http://bridge.internal.example/feed.ics")
        assert "only allowed for localhost" in str(excinfo.value)


def test_allowed_hosts_are_read_from_the_environment():
    import importlib

    with patch.dict(os.environ, {"HUTBOT_CALENDAR_ALLOWED_HOSTS": " Bridge.Internal.Example , ,b.example "}):
        module = importlib.reload(hutbot.calendarfeed)
    try:
        assert module._CALENDAR_ALLOWED_HOSTS == frozenset({"bridge.internal.example", "b.example"})
    finally:
        importlib.reload(hutbot.calendarfeed)


def test_describe_calendar_url_redacts_the_path():
    described = describe_calendar_url("https://outlook.office365.com/owa/calendar/secret-guid@tenant/other-guid/calendar.ics")
    assert described == "outlook.office365.com/…"
    assert "secret-guid" not in described and "calendar.ics" not in described
    # Some providers use the final segment itself as the bearer capability.
    assert describe_calendar_url("https://cal.example/FINAL-BEARER-TOKEN") == "cal.example/…"
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

class _FakeContent:
    """The chunked-read interface `_read_capped` uses."""

    def __init__(self, body: bytes, chunk_size: int = 64 * 1024):
        self._body = body
        self._chunk_size = chunk_size

    async def iter_chunked(self, size):
        step = self._chunk_size or size
        for offset in range(0, len(self._body), step):
            yield self._body[offset:offset + step]


class _FakeResponse:
    def __init__(self, status=200, text="", content_length=None, headers=None, body=None):
        self.status = status
        self._body = body if body is not None else text.encode("utf-8")
        # A feed can understate or omit this, which is why the read is capped as it streams.
        self.content_length = content_length if content_length is not None else len(self._body)
        self.headers = headers or {}
        self.content = _FakeContent(self._body)

    def get_encoding(self):
        return "utf-8"

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


class _FakeSession:
    def __init__(self, responses, counter):
        self._responses = responses if isinstance(responses, list) else [responses]
        self._counter = counter

    def get(self, url, **kwargs):
        self._counter.append(url)
        index = min(len(self._counter) - 1, len(self._responses) - 1)
        return self._responses[index]

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


@contextlib.contextmanager
def _patch_http(responses, counter, resolves=True):
    """Fake the transport, and skip real DNS — resolution is covered on its own."""
    problem = "" if resolves else "`evil.example.com` resolves to the internal address 10.0.0.1"
    with patch('hutbot.calendarfeed.aiohttp.ClientSession', lambda *a, **k: _FakeSession(responses, counter)), \
         patch('hutbot.calendarfeed._resolve_public_host', new=AsyncMock(return_value=problem)):
        yield


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
async def test_fetch_calendar_retries_a_server_error():
    calls = []
    with _patch_http([_FakeResponse(status=503, text="busy"), _FakeResponse(text=SAMPLE_ICS)], calls):
        calendar, name = await fetch_calendar("https://cal.example.com/feed.ics")
    assert calendar is not None and name == "Team Kalender"
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_fetch_calendar_falls_back_to_the_last_good_copy():
    """A feed nobody can reach must not quietly turn "on vacation" into "not on vacation"."""
    calls = []
    with _patch_http(_FakeResponse(text=SAMPLE_ICS), calls):
        calendar, name = await fetch_calendar("https://cal.example.com/feed.ics")
    with _patch_http(_FakeResponse(status=404, text="gone"), calls), \
         patch('hutbot.calendarfeed._CALENDAR_TTL', 0):
        again, again_name = await fetch_calendar("https://cal.example.com/feed.ics")
    assert again is calendar and again_name == name


def _age_the_calendar_cache(url, seconds):
    """Push a cached feed past its TTL without shortening the TTL itself."""
    fetched_at, calendar, name = hutbot.state._calendar_cache[url]
    hutbot.state._calendar_cache[url] = (fetched_at - seconds, calendar, name)


@pytest.mark.asyncio
async def test_a_feed_that_just_failed_is_not_asked_again_by_the_next_message():
    """Three attempts per TTL against a host that is down, not three per message."""
    url = "https://cal.example.com/feed.ics"
    calls = []
    with _patch_http(_FakeResponse(text=SAMPLE_ICS), calls):
        await fetch_calendar(url)
    _age_the_calendar_cache(url, 1000)
    with _patch_http(_FakeResponse(status=503, text="busy"), calls):
        await fetch_calendar(url)
        attempted = len(calls)
        # The very next evaluation answers from the last copy without touching the network.
        calendar, _ = await fetch_calendar(url)
    assert calendar is not None
    assert len(calls) == attempted


@pytest.mark.asyncio
async def test_a_feed_that_comes_back_is_fetched_again():
    calls = []
    with _patch_http(_FakeResponse(status=503, text="busy"), calls):
        assert await fetch_calendar("https://cal.example.com/feed.ics") == (None, "")
    assert hutbot.state._calendar_failures
    with _patch_http(_FakeResponse(text=SAMPLE_ICS), calls), \
         patch('hutbot.calendarfeed._CALENDAR_TTL', 0):
        calendar, _ = await fetch_calendar("https://cal.example.com/feed.ics")
    assert calendar is not None
    assert hutbot.state._calendar_failures == {}


@pytest.mark.asyncio
async def test_the_stale_grace_is_counted_past_the_ttl():
    """`staleGraceSeconds` is extra time on top of the TTL, not the whole life of the copy."""
    url = "https://cal.example.com/feed.ics"
    calls = []
    with _patch_http(_FakeResponse(text=SAMPLE_ICS), calls):
        await fetch_calendar(url)
    with patch('hutbot.calendarfeed._CALENDAR_TTL', 3600), \
         patch('hutbot.calendarfeed._CALENDAR_STALE_GRACE', 300):
        # An hour and a minute old: past the TTL, inside the grace.
        _age_the_calendar_cache(url, 3660)
        with _patch_http(_FakeResponse(status=503, text="busy"), calls):
            calendar, _ = await fetch_calendar(url)
        assert calendar is not None
        # An hour and seven minutes: past both.
        hutbot.state._calendar_failures.clear()
        _age_the_calendar_cache(url, 360)
        with _patch_http(_FakeResponse(status=503, text="busy"), calls):
            assert await fetch_calendar(url) == (None, "")
    assert hutbot.state._calendar_cache == {}


@pytest.mark.asyncio
async def test_a_calendar_nobody_has_reached_for_a_day_is_dropped():
    calls = []
    with _patch_http(_FakeResponse(text=SAMPLE_ICS), calls):
        await fetch_calendar("https://cal.example.com/feed.ics")
    with _patch_http(_FakeResponse(status=404, text="gone"), calls), \
         patch('hutbot.calendarfeed._CALENDAR_TTL', 0), \
         patch('hutbot.calendarfeed._CALENDAR_STALE_GRACE', 0):
        assert await fetch_calendar("https://cal.example.com/feed.ics") == (None, "")
    assert hutbot.state._calendar_cache == {}


@pytest.mark.asyncio
async def test_fetch_calendar_without_a_url_does_nothing():
    assert await fetch_calendar("") == (None, "")
    assert await fetch_calendar("   ") == (None, "")


@pytest.mark.asyncio
async def test_resolve_calendar_context_without_a_feed():
    context = await hutbot.calendarfeed.resolve_calendar_context({})
    assert context.name == "" and context.event is None


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
    assert "outlook.office365.com/…" in confirmation
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


def _patch_show_calendar(name, events):
    """Fake what `show calendar` resolves: a feed name and its (before, now, next) events."""
    return patch('hutbot.calendarfeed.resolve_calendar_events',
                 new=AsyncMock(return_value=(name, events)))


@pytest.mark.asyncio
async def test_show_calendar_prints_the_neighbouring_events(cal):
    """The live command resolves against the real clock, so pin the events, not the time."""
    app = AsyncMock()
    config = {**copy.deepcopy(DEFAULT_CONFIG), **CONFIG}
    channel = _mk_channel({"default": config})
    user = User("U1", "dave", "Dave", "T")
    previous_event = _event_at(cal, config, NOW, -1)
    current, next_event = _current_and_next(cal, config, NOW)
    with _patch_show_calendar("Team Kalender", [previous_event, current, next_event]), \
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
    with _patch_show_calendar("Team Kalender", [None, None, None]), \
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
    assert "outlook.office365.com/…" in text
    assert "secret-guid" not in text


@pytest.mark.asyncio
async def test_calendar_patterns_are_recognised_as_commands():
    for text in ("set calendar https://x/y.ics", "set calendar rota", "clear calendar",
                 "show calendar", "calendar", "list calendars", "list calendar"):
        assert hutbot.commands.dispatch.matches_a_command(text), text


# ----- lazy fetching -----

@pytest.mark.asyncio
async def test_calendar_is_not_fetched_when_no_variable_references_it():
    app = AsyncMock()
    config = {**copy.deepcopy(DEFAULT_CONFIG), **CONFIG, "reply_message": "Anybody?"}
    channel = _mk_channel({"plain": config})
    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(None, ""))) as fetch, \
         patch('hutbot.slackcache.get_message_permalink', new=AsyncMock(return_value="")):
        await hutbot.actions.render_action_text(app, OPSGENIE_TOKENS, channel, config, "plain", {"channel_id": "C12345"})
    fetch.assert_not_awaited()


@pytest.mark.asyncio
async def test_calendar_is_fetched_once_when_a_variable_references_it(live_cal):
    _seed_user_caches()
    app = AsyncMock()
    config = {**copy.deepcopy(DEFAULT_CONFIG), **CONFIG, "reply_message": "Now: {{calendar_summary}}"}
    channel = _mk_channel({"cal": config})
    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(live_cal, "Team Kalender"))) as fetch, \
         patch('hutbot.slackcache.get_message_permalink', new=AsyncMock(return_value="")):
        text = await hutbot.actions.render_action_text(app, OPSGENIE_TOKENS, channel, config, "cal", {"channel_id": "C12345"})
    assert fetch.await_count == 1
    assert "Composerbereitstellung" in text


@pytest.mark.asyncio
async def test_calendar_condition_gates_a_rule(live_cal):
    """The whole point: a rule that only runs while a matching event is on."""
    _seed_user_caches()
    app = AsyncMock()
    config = {**copy.deepcopy(DEFAULT_CONFIG), **CONFIG, "reply_message": "standup time"}
    config["conditions"] = [{"variable": "calendar_summary", "operator": "contains",
                             "value": "composer", "case_sensitive": False}]
    channel = _mk_channel({"gated": config})
    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(live_cal, "Team Kalender"))), \
         patch('hutbot.slackcache.get_message_permalink', new=AsyncMock(return_value="")), \
         patch('hutbot.messaging._post_message', new=AsyncMock(return_value={"channel": "C12345", "ts": "9.1"})) as post:
        posted, reason = await hutbot.actions.run_action_with_reason(
            app, OPSGENIE_TOKENS, channel, config, "gated", context={"channel_id": "C12345"})
    assert posted is not None and reason == ""
    assert post.await_count == 1


@pytest.mark.asyncio
async def test_calendar_condition_blocks_when_no_event_matches(live_cal):
    _seed_user_caches()
    app = AsyncMock()
    config = {**copy.deepcopy(DEFAULT_CONFIG), **CONFIG, "reply_message": "standup time"}
    config["conditions"] = [{"variable": "calendar_summary", "operator": "contains",
                             "value": "no such meeting", "case_sensitive": False}]
    channel = _mk_channel({"gated": config})
    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(live_cal, "Team Kalender"))), \
         patch('hutbot.slackcache.get_message_permalink', new=AsyncMock(return_value="")), \
         patch('hutbot.messaging._post_message', new=AsyncMock()) as post:
        posted, reason = await hutbot.actions.run_action_with_reason(
            app, OPSGENIE_TOKENS, channel, config, "gated", context={"channel_id": "C12345"})
    assert posted is None and "did not match" in reason
    post.assert_not_awaited()


# ----- organizer and attendees, from a real on-call feed -----

# An Outlook-bridge rota entry: the organizer is a room mailbox with no usable address
# (`invalid:nomail`), and there are two attendees, one folded across lines.
ONCALL_ICS = "\r\n".join([
    "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//mittwald//outlook-bridge//EN",
    "CALSCALE:GREGORIAN", "METHOD:PUBLISH", "X-WR-CALNAME:N@mittwald.de",
    "X-WR-TIMEZONE:Europe/Berlin",
    "BEGIN:VEVENT",
    "UID:040000008200E00074C5B7101A82E00800000000C048C877C107DD01000000000000000",
    " 010000000B1DB35434DF24349826253ACE907D346-20260819T160000Z",
    "DTSTAMP:20260819T140015Z", "DTSTART:20260819T160000Z", "DTEND:20260820T060000Z",
    "SUMMARY:Rufbereitschaft - Engelbracht\\, Nico", "LOCATION:Rufbereitschaft",
    'ORGANIZER;CN="Notfallhotline":invalid:nomail',
    'ATTENDEE;CN="Notfallhotline";ROLE=REQ-PARTICIPANT:mailto:N@mittwald.de',
    'ATTENDEE;CN="Nico Engelbrecht";ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED:mailt',
    " o:N.Engelbrecht@mittwald.de",
    "STATUS:CONFIRMED", "TRANSP:OPAQUE", "LAST-MODIFIED:20260630T064802Z",
    "END:VEVENT", "END:VCALENDAR",
])
ONCALL_NOW = datetime.datetime(2026, 8, 19, 20, 0, tzinfo=datetime.timezone.utc)


@pytest.fixture
def oncall_cal():
    return icalendar.Calendar.from_ical(ONCALL_ICS)


def _oncall_event(calendar):
    current, _ = _current_and_next(calendar, CONFIG, ONCALL_NOW)
    return current


def test_escaped_comma_in_the_summary_is_decoded(oncall_cal):
    assert _oncall_event(oncall_cal).summary == "Rufbereitschaft - Engelbracht, Nico"


def test_attendees_are_collected_with_names_and_emails(oncall_cal):
    event = _oncall_event(oncall_cal)
    assert event.attendees == ["Notfallhotline", "Nico Engelbrecht"]
    assert event.attendee_emails == ["N@mittwald.de", "N.Engelbrecht@mittwald.de"]


def test_a_single_attendee_is_not_treated_as_characters(oncall_cal):
    """icalendar returns a bare value for one ATTENDEE and a list for several."""
    ics = ONCALL_ICS.replace(
        'ATTENDEE;CN="Nico Engelbrecht";ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED:mailt\r\n o:N.Engelbrecht@mittwald.de\r\n', "")
    event = _oncall_event(icalendar.Calendar.from_ical(ics))
    assert event.attendees == ["Notfallhotline"]
    assert event.attendee_emails == ["N@mittwald.de"]


def test_no_attendees_at_all(oncall_cal):
    event = _oncall_event(icalendar.Calendar.from_ical(ONCALL_ICS.replace("ATTENDEE", "X-WAS-ATTENDEE")))
    assert event.attendees == [] and event.attendee_emails == []


def test_an_unusable_organizer_address_is_dropped_but_the_name_kept(oncall_cal):
    """`invalid:nomail` is a room mailbox with no address; the CN is still worth showing."""
    event = _oncall_event(oncall_cal)
    assert event.organizer == "Notfallhotline"
    assert event.organizer_email == ""


def test_a_real_organizer_address_is_exposed():
    ics = ONCALL_ICS.replace('ORGANIZER;CN="Notfallhotline":invalid:nomail',
                             'ORGANIZER;CN="Notfallhotline":mailto:hotline@example.com')
    event = _oncall_event(icalendar.Calendar.from_ical(ics))
    assert event.organizer == "Notfallhotline"
    assert event.organizer_email == "hotline@example.com"


def test_an_attendee_without_a_cn_falls_back_to_its_address():
    ics = ONCALL_ICS.replace('ATTENDEE;CN="Notfallhotline";ROLE=REQ-PARTICIPANT:mailto:N@mittwald.de',
                             'ATTENDEE;ROLE=REQ-PARTICIPANT:mailto:plain@example.com')
    event = _oncall_event(icalendar.Calendar.from_ical(ics))
    assert "plain@example.com" in event.attendees


def test_an_attendee_with_an_x500_address_keeps_its_name_but_has_no_email():
    ics = ONCALL_ICS.replace(
        'ATTENDEE;CN="Notfallhotline";ROLE=REQ-PARTICIPANT:mailto:N@mittwald.de',
        'ATTENDEE;CN="Room 1":mailto:/O=EXCHANGELABS/OU=EXCHANGE ADMINISTRATIVE GROUP/CN=RECIPIENTS/CN=ABC')
    event = _oncall_event(icalendar.Calendar.from_ical(ics))
    assert event.attendees == ["Room 1", "Nico Engelbrecht"]
    # Aligned: the room holds position 1 with a blank address, so position 2 is still Nico.
    assert event.attendee_emails == ["", "N.Engelbrecht@mittwald.de"]


@pytest.mark.asyncio
async def test_attendee_variables_render_as_a_comma_separated_list(oncall_cal):
    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(oncall_cal, "N@mittwald.de"))):
        variables = await hutbot.calendarfeed.get_calendar_template_variables(None, CONFIG, ONCALL_NOW)
    assert variables["calendar_attendees"] == "Notfallhotline, Nico Engelbrecht"
    assert variables["calendar_attendee_emails"] == "N@mittwald.de, N.Engelbrecht@mittwald.de"
    assert variables["calendar_attendee_count"] == "2"
    assert variables["calendar_organizer_email"] == ""
    # The items a condition matches against ride along beside the joined form.
    assert variables["__calendar_attendee_emails_items"] == [
        "N@mittwald.de", "N.Engelbrecht@mittwald.de"]


@pytest.mark.asyncio
async def test_conditions_on_attendee_emails(oncall_cal):
    """A list operator matches any entry; its `not_` form requires that none does."""
    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(oncall_cal, "N@mittwald.de"))):
        variables = await hutbot.calendarfeed.get_calendar_template_variables(None, CONFIG, ONCALL_NOW)

    def judge(operator, value, variable="calendar_attendee_emails", case_sensitive=False):
        condition = {"variable": variable, "operator": operator, "value": value,
                     "case_sensitive": case_sensitive}
        return hutbot.conditionutil.evaluate_conditions({"conditions": [condition]}, variables)[0]

    # Membership, case-insensitively by default.
    assert judge("equals", "n.engelbrecht@mittwald.de") is True
    assert judge("equals", "N.Engelbrecht@mittwald.de") is True
    assert judge("equals", "someone.else@mittwald.de") is False
    # `not_equals` means "not among them", not "some entry differs".
    assert judge("not_equals", "someone.else@mittwald.de") is True
    assert judge("not_equals", "n.engelbrecht@mittwald.de") is False
    # Substring and regex apply per entry.
    assert judge("contains", "@mittwald.de") is True
    assert judge("not_contains", "@example.com") is True
    assert judge("not_contains", "@mittwald.de") is False
    assert judge("regex", r"^n\.\w+@mittwald\.de$") is True
    assert judge("starts_with", "n.engelbrecht") is True
    assert judge("ends_with", "@mittwald.de") is True
    # Emptiness is about the list, not about any entry.
    assert judge("not_empty", "") is True
    assert judge("empty", "") is False
    # Names work the same way.
    assert judge("contains", "Nico", variable="calendar_attendees") is True
    # And the case flag still applies per entry.
    assert judge("equals", "n.engelbrecht@mittwald.de", case_sensitive=True) is False
    assert judge("equals", "N.Engelbrecht@mittwald.de", case_sensitive=True) is True


def test_an_empty_list_is_empty_and_matches_nothing():
    variables = get_calendar_placeholder_variables({})
    def judge(operator, value=""):
        condition = {"variable": "calendar_attendee_emails", "operator": operator,
                     "value": value, "case_sensitive": False}
        return hutbot.conditionutil.evaluate_conditions({"conditions": [condition]}, variables)[0]
    assert judge("empty") is True
    assert judge("not_empty") is False
    assert judge("equals", "anyone@example.com") is False
    # Nothing is among an empty list, so a `not_` operator holds.
    assert judge("not_equals", "anyone@example.com") is True


def test_a_bad_regex_on_a_list_still_fails_closed():
    variables = {"calendar_attendee_emails": "a@b.de",
                 "__calendar_attendee_emails_items": ["a@b.de"]}
    for operator in ("regex", "not_regex"):
        condition = {"variable": "calendar_attendee_emails", "operator": operator,
                     "value": "[unclosed", "case_sensitive": False}
        met, reason = hutbot.conditionutil.evaluate_conditions({"conditions": [condition]}, variables)
        assert met is False and "invalid pattern" in reason


def test_a_list_variable_falls_back_to_splitting_the_joined_form():
    """A hand-built variable dict without the items still behaves sensibly."""
    variables = {"calendar_attendee_emails": "a@b.de, c@d.de"}
    condition = {"variable": "calendar_attendee_emails", "operator": "equals",
                 "value": "c@d.de", "case_sensitive": False}
    assert hutbot.conditionutil.evaluate_conditions({"conditions": [condition]}, variables)[0] is True


@pytest.mark.asyncio
async def test_show_calendar_lists_the_attendees(oncall_cal):
    app = AsyncMock()
    config = {**copy.deepcopy(DEFAULT_CONFIG), **CONFIG}
    channel = _mk_channel({"default": config})
    current, next_event = _current_and_next(oncall_cal, config, ONCALL_NOW)
    with _patch_show_calendar("N@mittwald.de", [None, current, next_event]), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, "show calendar", channel, User("U1", "dave", "Dave", "T"))
    text = send.call_args.args[3]
    # The organizer has its own line, so it is not repeated under Attendees.
    assert "*Organizer*: Notfallhotline" in text
    assert "*Attendees*: Nico Engelbrecht" in text


def test_the_organizer_is_dropped_from_the_other_attendees(oncall_cal):
    """A shared mailbox invites itself, which buries the person actually on call."""
    event = _oncall_event(oncall_cal)
    assert event.attendees == ["Notfallhotline", "Nico Engelbrecht"]
    assert event.other_attendees == ["Nico Engelbrecht"]
    assert event.other_attendee_emails == ["N.Engelbrecht@mittwald.de"]


def test_the_organizer_is_matched_by_address_when_it_has_one():
    ics = ONCALL_ICS.replace('ORGANIZER;CN="Notfallhotline":invalid:nomail',
                             'ORGANIZER;CN="Something Else":mailto:N@mittwald.de')
    event = _oncall_event(icalendar.Calendar.from_ical(ics))
    # Matched on the address even though the names differ.
    assert event.other_attendees == ["Nico Engelbrecht"]


def test_an_event_without_an_organizer_keeps_every_attendee():
    ics = ONCALL_ICS.replace('ORGANIZER;CN="Notfallhotline":invalid:nomail', "X-NO-ORGANIZER:none")
    event = _oncall_event(icalendar.Calendar.from_ical(ics))
    assert event.other_attendees == event.attendees == ["Notfallhotline", "Nico Engelbrecht"]


def test_an_organizer_who_is_not_an_attendee_changes_nothing():
    ics = ONCALL_ICS.replace('ORGANIZER;CN="Notfallhotline":invalid:nomail',
                             'ORGANIZER;CN="Someone Outside":mailto:outside@example.com')
    event = _oncall_event(icalendar.Calendar.from_ical(ics))
    assert event.other_attendees == ["Notfallhotline", "Nico Engelbrecht"]


@pytest.mark.asyncio
async def test_other_attendee_variables_and_conditions(oncall_cal):
    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(oncall_cal, "N@mittwald.de"))):
        variables = await hutbot.calendarfeed.get_calendar_template_variables(None, CONFIG, ONCALL_NOW)
    assert variables["calendar_other_attendees"] == "Nico Engelbrecht"
    assert variables["calendar_other_attendee_emails"] == "N.Engelbrecht@mittwald.de"
    assert variables["__calendar_other_attendee_emails_items"] == ["N.Engelbrecht@mittwald.de"]

    def judge(operator, value, variable="calendar_other_attendee_emails"):
        condition = {"variable": variable, "operator": operator, "value": value, "case_sensitive": False}
        return hutbot.conditionutil.evaluate_conditions({"conditions": [condition]}, variables)[0]

    # The shared mailbox is an attendee, but not one of the "other" attendees.
    assert judge("equals", "n@mittwald.de") is False
    assert judge("equals", "n@mittwald.de", variable="calendar_attendee_emails") is True
    assert judge("equals", "n.engelbrecht@mittwald.de") is True
    assert judge("not_empty", "") is True


# ----- picking one entry out of a list variable -----

@pytest.mark.asyncio
async def test_nth_picks_one_attendee(oncall_cal):
    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(oncall_cal, "N@mittwald.de"))):
        variables = await hutbot.calendarfeed.get_calendar_template_variables(None, CONFIG, ONCALL_NOW)

    def render(template):
        return hutbot.templating.render_reply_message_template(template, variables, CONFIG)

    assert render("{{calendar_attendees(nth=1)}}") == "Notfallhotline"
    assert render("{{calendar_attendees(nth=2)}}") == "Nico Engelbrecht"
    assert render("{{calendar_attendee_emails(nth=2)}}") == "N.Engelbrecht@mittwald.de"
    # `n` is the short spelling.
    assert render("{{calendar_attendees(n=2)}}") == "Nico Engelbrecht"
    # Without it, the whole list still renders comma-separated.
    assert render("{{calendar_attendees}}") == "Notfallhotline, Nico Engelbrecht"
    # The `other_*` lists are indexed the same way.
    assert render("{{calendar_other_attendees(nth=1)}}") == "Nico Engelbrecht"


@pytest.mark.asyncio
async def test_nth_beyond_the_end_renders_empty(oncall_cal):
    """A message written for two attendees still reads when there is only one."""
    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(oncall_cal, "N@mittwald.de"))):
        variables = await hutbot.calendarfeed.get_calendar_template_variables(None, CONFIG, ONCALL_NOW)

    def render(template):
        return hutbot.templating.render_reply_message_template(template, variables, CONFIG)

    # Two attendees, so the third is empty rather than an error or a placeholder.
    assert render("[{{calendar_attendees(nth=3)}}]") == "[]"
    # Only one non-organizer attendee.
    assert render("[{{calendar_other_attendees(nth=2)}}]") == "[]"
    # No next event at all, so every entry is out of range.
    assert render("[{{calendar_attendees(offset=next, nth=1)}}]") == "[]"


def test_nth_on_an_empty_list_renders_empty():
    variables = get_calendar_placeholder_variables({})
    assert hutbot.templating.render_reply_message_template(
        "[{{calendar_attendees(nth=1)}}]", variables, {}) == "[]"


@pytest.mark.asyncio
async def test_nth_reads_a_real_on_call_message(oncall_cal):
    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(oncall_cal, "N@mittwald.de"))):
        variables = await hutbot.calendarfeed.get_calendar_template_variables(None, CONFIG, ONCALL_NOW)
    template = ("On call: {{calendar_other_attendees(nth=1)}} "
                "<{{calendar_other_attendee_emails(nth=1)}}> until {{calendar_end_time}}")
    assert hutbot.templating.render_reply_message_template(template, variables, CONFIG) == (
        "On call: Nico Engelbrecht <N.Engelbrecht@mittwald.de> until 08:00")


@pytest.mark.parametrize("template,expected", [
    ("{{calendar_attendees(nth=1)}}", ""),
    ("{{calendar_attendees(n=12)}}", ""),
    ("{{calendar_attendees(nth=0)}}", "counts from 1"),
    ("{{calendar_attendees(nth=-1)}}", "counts from 1"),
    ("{{calendar_attendees(nth=abc)}}", "must be a whole number"),
    # A list variable takes nothing else.
    ("{{calendar_attendees(fmt='x')}}", "takes only `nth`"),
    ("{{calendar_attendees(tz='UTC')}}", "takes only `nth`"),
    # And `nth` is meaningless on anything that is not a list.
    ("{{message(nth=1)}}", "is not a list"),
    ("{{calendar_summary(nth=1)}}", "is not a list"),
    ("{{calendar_start_time(nth=1)}}", "is not a list"),
    # The date/time arguments still work where they belong.
    ("{{calendar_start_time(tz='UTC')}}", ""),
])
def test_nth_validation(template, expected):
    error = hutbot.templating.validate_template_expressions(template)
    if expected:
        assert expected in error
    else:
        assert error == ""


@pytest.mark.asyncio
async def test_set_message_accepts_and_rejects_nth():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")
    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, "set message On call: {{calendar_other_attendees(nth=1)}}", channel, user)
        assert channel.configs["default"]["reply_message"] == "On call: {{calendar_other_attendees(nth=1)}}"
        await process_command(app, "set message Nope: {{calendar_attendees(nth=0)}}", channel, user)
    assert "counts from 1" in send.call_args.args[3]


# ----- mapping calendar addresses to Slack users -----

# The hotline mailbox has no Slack account; Nico does. Graceful failure means the first is
# simply absent from the mapped lists rather than breaking the rule.
_SLACK_DIRECTORY = {"n.engelbrecht@mittwald.de": User("U777", "nico", "Nico Engelbrecht", "Platform")}


async def _fake_by_email(app, email):
    return _SLACK_DIRECTORY.get((email or "").lower(), User(None, email, "", "T"))


async def _fake_by_id(app, user_id):
    return User(user_id, "nico", "Nico Engelbrecht", "Platform")


async def _no_such_usergroup(app, handle):
    return Usergroup(None, handle, handle)


def _live_oncall_ics(now=None):
    """The rota entry, anchored to the caller's clock so it is always the current event."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    fmt = "%Y%m%dT%H%M%SZ"
    return "\r\n".join([
        "BEGIN:VCALENDAR", "VERSION:2.0", "X-WR-CALNAME:N@mittwald.de",
        "BEGIN:VEVENT", "UID:oncall-live", f"DTSTAMP:{now.strftime(fmt)}",
        f"DTSTART:{(now - datetime.timedelta(hours=1)).strftime(fmt)}",
        f"DTEND:{(now + datetime.timedelta(hours=13)).strftime(fmt)}",
        "SUMMARY:Rufbereitschaft - Engelbracht\\, Nico", "LOCATION:Rufbereitschaft",
        'ORGANIZER;CN="Notfallhotline":invalid:nomail',
        'ATTENDEE;CN="Notfallhotline";ROLE=REQ-PARTICIPANT:mailto:N@mittwald.de',
        'ATTENDEE;CN="Nico Engelbrecht";ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED:mailto:N.Engelbrecht@mittwald.de',
        "STATUS:CONFIRMED", "END:VEVENT", "END:VCALENDAR",
    ])


@pytest.fixture
def live_oncall_cal():
    return icalendar.Calendar.from_ical(_live_oncall_ics())


@pytest.mark.asyncio
async def test_attendee_addresses_are_mapped_to_slack_users(oncall_cal):
    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(oncall_cal, "N@mittwald.de"))), \
         patch('hutbot.slackcache.get_user_by_email', new=_fake_by_email):
        variables = await hutbot.calendarfeed.get_calendar_template_variables(AsyncMock(), CONFIG, ONCALL_NOW)
    # The joined form a message renders leaves out the mailbox that maps to nobody...
    assert variables["calendar_attendee_users"] == "<@U777>"
    assert variables["calendar_other_attendee_users"] == "<@U777>"
    # ...while the entries keep its position, so `nth` lines up with the other lists.
    assert variables["__calendar_attendee_users_items"] == ["", "<@U777>"]
    assert variables["__calendar_attendees_items"] == ["Notfallhotline", "Nico Engelbrecht"]
    # The organizer maps to nobody, so it keeps the placeholder rather than inventing a user.
    assert variables["calendar_organizer_user"] == "<no-user-set>"


@pytest.mark.asyncio
async def test_an_unmapped_address_keeps_its_position(oncall_cal):
    """Two attendees, one Slack account: the entry is blank, not missing.

    Compacting it would shift everyone after it, so `attendees(nth=2)` and
    `attendee_users(nth=2)` would stop describing the same participant.
    """
    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(oncall_cal, "N@mittwald.de"))), \
         patch('hutbot.slackcache.get_user_by_email', new=_fake_by_email):
        variables = await hutbot.calendarfeed.get_calendar_template_variables(AsyncMock(), CONFIG, ONCALL_NOW)
    for name in ("attendees", "attendee_emails", "attendee_users"):
        assert len(variables[f"__calendar_{name}_items"]) == 2, name
    assert variables["__calendar_attendee_users_items"] == ["", "<@U777>"]
    # Nico is entry 2 of every list.
    render = lambda t: hutbot.templating.render_reply_message_template(t, variables, CONFIG)
    assert render("{{calendar_attendees(nth=2)}}") == "Nico Engelbrecht"
    assert render("{{calendar_attendee_emails(nth=2)}}") == "N.Engelbrecht@mittwald.de"
    assert render("{{calendar_attendee_users(nth=2)}}") == "<@U777>"
    # And a condition still ignores the blank.
    condition = {"variable": "calendar_attendee_users", "operator": "not_empty",
                 "value": "", "case_sensitive": False}
    assert hutbot.conditionutil.evaluate_conditions({"conditions": [condition]}, variables)[0] is True


@pytest.mark.asyncio
async def test_no_app_means_no_mapping_attempted(oncall_cal):
    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(oncall_cal, "N@mittwald.de"))):
        variables = await hutbot.calendarfeed.get_calendar_template_variables(None, CONFIG, ONCALL_NOW)
    assert variables["calendar_attendee_users"] == ""
    assert variables["calendar_organizer_user"] == "<no-user-set>"


@pytest.mark.asyncio
async def test_a_mapped_user_variable_mentions_the_person(oncall_cal):
    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(oncall_cal, "N@mittwald.de"))), \
         patch('hutbot.slackcache.get_user_by_email', new=_fake_by_email):
        variables = await hutbot.calendarfeed.get_calendar_template_variables(AsyncMock(), CONFIG, ONCALL_NOW)
    rendered = hutbot.templating.render_reply_message_template(
        "On call: {{calendar_other_attendee_users(nth=1)}}", variables, CONFIG)
    assert rendered == "On call: <@U777>"


# ----- sending to people named by a variable -----

async def _run_with_target(action, target, calendar):
    app = AsyncMock()
    app.client.conversations_open = AsyncMock(return_value={"channel": {"id": "D1"}})
    config = {**copy.deepcopy(DEFAULT_CONFIG), **CONFIG, "reply_message": "ping",
              "action": action, "action_target": target}
    channel = _mk_channel({"oncall": config})
    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(calendar, "N@mittwald.de"))), \
         patch('hutbot.slackcache.get_user_by_email', new=_fake_by_email), \
         patch('hutbot.slackcache.get_user_by_id', new=_fake_by_id), \
         patch('hutbot.slackcache.get_usergroup_by_handle', new=_no_such_usergroup), \
         patch('hutbot.slackcache.get_message_permalink', new=AsyncMock(return_value="")), \
         patch('hutbot.messaging._post_message', new=AsyncMock(return_value={"channel": "D1", "ts": "1"})):
        posted, reason = await hutbot.actions.run_action_with_reason(
            app, OPSGENIE_TOKENS, channel, config, "oncall", context={"channel_id": "C12345"})
    opened = (app.client.conversations_open.await_args.kwargs.get("users")
              if app.client.conversations_open.await_count else None)
    return bool(posted), opened


@pytest.mark.asyncio
@pytest.mark.parametrize("action,target", [
    ("dm_user", "{{calendar_other_attendee_users(nth=1)}}"),
    ("dm_user", "{{calendar_other_attendee_emails(nth=1)}}"),
    ("group_dm", "{{calendar_attendee_users}}"),
    ("group_dm", "{{calendar_attendee_emails}}"),
    ("group_dm", "{{calendar_other_attendee_emails}}"),
])
async def test_a_variable_target_reaches_the_person_on_call(action, target, live_oncall_cal):
    posted, opened = await _run_with_target(action, target, live_oncall_cal)
    assert posted is True
    assert opened == ["U777"]


@pytest.mark.asyncio
async def test_a_variable_target_that_maps_to_nobody_sends_nothing(live_oncall_cal):
    """The organizer has no Slack account, so its placeholder must not be looked up."""
    posted, opened = await _run_with_target("dm_user", "{{calendar_organizer_user}}", live_oncall_cal)
    assert posted is False and opened is None


@pytest.mark.asyncio
async def test_a_variable_target_with_no_event_sends_nothing(live_oncall_cal):
    posted, opened = await _run_with_target(
        "dm_user", "{{calendar_other_attendee_users(offset=next, nth=1)}}", live_oncall_cal)
    assert posted is False and opened is None


@pytest.mark.asyncio
async def test_a_plain_target_still_works(live_oncall_cal):
    posted, opened = await _run_with_target("dm_user", "<@U777>", live_oncall_cal)
    assert posted is True and opened == ["U777"]


@pytest.mark.asyncio
async def test_group_dm_still_treats_a_bare_handle_as_a_usergroup(live_oncall_cal):
    """An unresolvable handle must report itself, not quietly match a same-named user."""
    posted, opened = await _run_with_target("group_dm", "@sre", live_oncall_cal)
    assert posted is False and opened is None


@pytest.mark.asyncio
async def test_a_templated_target_is_accepted_and_validated():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")
    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as send:
        # A channel target that is a template cannot be checked now, so it is taken on trust.
        await process_command(app, "set action dm-user {{calendar_other_attendee_users(nth=1)}}", channel, user)
        assert channel.configs["default"]["action_target"] == "{{calendar_other_attendee_users(nth=1)}}"
        # The template itself is still checked.
        await process_command(app, "set action dm-user {{nope_not_a_variable}}", channel, user)
    assert "Invalid *target*" in send.call_args.args[3]
    assert channel.configs["default"]["action_target"] == "{{calendar_other_attendee_users(nth=1)}}"


# ----- fetching safely -----

@pytest.mark.asyncio
async def test_a_redirect_is_followed_only_after_the_target_is_checked():
    """aiohttp would follow a public URL to the metadata address without a word."""
    calls = []
    responses = [
        _FakeResponse(status=302, headers={"Location": "https://cal.example.com/real.ics"}),
        _FakeResponse(text=SAMPLE_ICS),
    ]
    with _patch_http(responses, calls):
        calendar, name = await fetch_calendar("https://cal.example.com/feed.ics")
    assert calendar is not None and name == "Team Kalender"
    assert calls == ["https://cal.example.com/feed.ics", "https://cal.example.com/real.ics"]


@pytest.mark.asyncio
async def test_a_redirect_to_an_internal_address_is_refused():
    calls = []
    responses = [_FakeResponse(status=302, headers={"Location": "http://169.254.169.254/latest/meta-data"})]
    with _patch_http(responses, calls):
        assert await fetch_calendar("https://cal.example.com/feed.ics") == (None, "")
    # The metadata address was never requested.
    assert calls == ["https://cal.example.com/feed.ics"]


@pytest.mark.asyncio
async def test_a_redirect_to_a_private_host_is_refused():
    calls = []
    responses = [_FakeResponse(status=302, headers={"Location": "https://10.0.0.1/feed.ics"})]
    with _patch_http(responses, calls):
        assert await fetch_calendar("https://cal.example.com/feed.ics") == (None, "")
    assert calls == ["https://cal.example.com/feed.ics"]


@pytest.mark.asyncio
async def test_a_redirect_loop_gives_up():
    calls = []
    responses = [_FakeResponse(status=302, headers={"Location": "https://cal.example.com/again.ics"})]
    with _patch_http(responses, calls):
        assert await fetch_calendar("https://cal.example.com/feed.ics") == (None, "")
    assert len(calls) == 4  # the first request plus _MAX_REDIRECTS hops


@pytest.mark.asyncio
async def test_a_host_resolving_to_an_internal_address_is_refused():
    """The URL text is public; what it resolves to is not."""
    calls = []
    with _patch_http([_FakeResponse(text=SAMPLE_ICS)], calls, resolves=False):
        assert await fetch_calendar("https://evil.example.com/feed.ics") == (None, "")
    assert calls == []


@pytest.mark.asyncio
async def test_an_allow_listed_host_is_fetched_without_the_address_check():
    """The internal feed the allow-list exists for: refused by address, named by the operator."""
    calls = []
    with _patch_http([_FakeResponse(text=SAMPLE_ICS)], calls, resolves=False), \
         patch('hutbot.calendarfeed._CALENDAR_ALLOWED_HOSTS', frozenset({"bridge.internal.example"})):
        calendar, name = await fetch_calendar("https://bridge.internal.example/feed.ics")
    assert calendar is not None and name == "Team Kalender"
    assert calls == ["https://bridge.internal.example/feed.ics"]


@pytest.mark.asyncio
async def test_an_oversized_body_is_abandoned_while_streaming():
    """A feed can omit Content-Length, or be a compression bomb."""
    calls = []
    huge = ("BEGIN:VCALENDAR\r\n" + "X-PAD:" + "a" * 1024 + "\r\n") * 8000
    response = _FakeResponse(text=huge, content_length=None)
    response.content_length = 10  # understated, as a hostile feed would
    with _patch_http([response], calls):
        assert await fetch_calendar("https://cal.example.com/feed.ics") == (None, "")


@pytest.mark.asyncio
async def test_a_body_within_the_cap_is_read_whole():
    calls = []
    with _patch_http([_FakeResponse(text=SAMPLE_ICS, content_length=None)], calls):
        calendar, name = await fetch_calendar("https://cal.example.com/feed.ics")
    assert calendar is not None and name == "Team Kalender"


@pytest.mark.asyncio
@pytest.mark.parametrize("host,expected", [
    ("10.0.0.1", "internal"),
    ("100.64.0.1", "internal"),
    ("169.254.169.254", "internal"),
    ("127.0.0.1", "internal"),
    ("no-such-host.invalid", "could not resolve"),
])
async def test_resolve_public_host_rejects_internal_targets(host, expected):
    assert expected in await hutbot.calendarfeed._resolve_public_host(host)


@pytest.mark.parametrize("url", [
    "https://0.0.0.0/feed.ics",
    "https://100.64.0.1/feed.ics",
    "https://224.0.0.1/feed.ics",
    "https://192.0.0.170/feed.ics",
])
def test_validate_calendar_url_rejects_more_reserved_ranges(url):
    with pytest.raises(ValueError):
        validate_calendar_url(url)


# ----- `at` and `offset` -----

# The sample feed on 2026-08-19, in UTC: Composerbereitstellung 07:35-08:30, m3 daily
# 09:00-09:30, Mit Dauer 12:00-12:45, Ohne Ende at 14:00, plus the all-day Betriebsausflug and
# the multi-day Mehrtagskonferenz.
# The sample feed on 2026-08-19, in UTC: Composerbereitstellung 07:35-08:30, m3 daily
# 09:00-09:30, Mit Dauer 12:00-12:45.
INSIDE_COMPOSER = datetime.datetime(2026, 8, 19, 8, 0, tzinfo=datetime.timezone.utc)
# Four timed events with a gap between the second and third, and nothing else to disambiguate:
# SAMPLE_ICS deliberately carries all-day, transparent, tentative and multi-day entries, which
# make it the wrong fixture for counting neighbours.
OFFSET_ICS = "\r\n".join([
    "BEGIN:VCALENDAR", "VERSION:2.0", "X-WR-CALNAME:Rota",
    *[line
      for uid, start, end in (("first", "0600", "0700"), ("second", "0900", "1000"),
                              ("third", "1200", "1300"), ("fourth", "1500", "1600"))
      for line in ("BEGIN:VEVENT", f"UID:{uid}", f"SUMMARY:{uid}",
                   f"DTSTART:20260819T{start}00Z", f"DTEND:20260819T{end}00Z", "END:VEVENT")],
    "END:VCALENDAR", "",
])


@pytest.fixture
def offset_cal():
    return icalendar.Calendar.from_ical(OFFSET_ICS)


def _at(hour, minute=0):
    return datetime.datetime(2026, 8, 19, hour, minute, tzinfo=datetime.timezone.utc)


@pytest.mark.parametrize("offset,expected", [
    (0, "second"), (1, "third"), (2, "fourth"), (-1, "first"),
])
def test_offset_counts_events_from_the_running_one(offset_cal, offset, expected):
    """`-1`/`+1` are the neighbours of the event running at that moment."""
    assert _event_at(offset_cal, CONFIG, _at(9, 30), offset).summary == expected


@pytest.mark.parametrize("offset,expected", [
    (0, None), (-1, "second"), (1, "third"), (-2, "first"), (2, "fourth"),
])
def test_in_a_gap_the_neighbours_are_the_events_either_side(offset_cal, offset, expected):
    event = _event_at(offset_cal, CONFIG, _at(11, 0), offset)
    assert (event.summary if event else None) == expected


def test_an_offset_past_the_last_event_resolves_to_nothing(offset_cal):
    assert _event_at(offset_cal, CONFIG, _at(9, 30), 20) is None
    assert _event_at(offset_cal, CONFIG, _at(5, 0), -1) is None
    assert _event_at(offset_cal, CONFIG, _at(5, 0), 1).summary == "first"


# A rota-shaped feed: an evening entry on the 19th, nothing at all on the 20th, and a daytime
# entry on the 21st. Berlin is +02:00 here, so 16:00Z is 18:00 local.
ROTA_ICS = "\r\n".join([
    "BEGIN:VCALENDAR", "VERSION:2.0", "X-WR-CALNAME:Notfallhotline",
    "BEGIN:VEVENT", "UID:evening", "SUMMARY:evening",
    "DTSTART:20260819T160000Z", "DTEND:20260819T200000Z", "END:VEVENT",
    "BEGIN:VEVENT", "UID:daytime", "SUMMARY:daytime",
    "DTSTART:20260821T060000Z", "DTEND:20260821T160000Z", "END:VEVENT",
    "END:VCALENDAR", "",
])


@pytest.fixture
def rota_cal():
    return icalendar.Calendar.from_ical(ROTA_ICS)


@pytest.mark.parametrize("day,hour,expected", [
    # 10:00 Berlin on the 19th: nothing is running, but the day's entry starts at 18:00.
    (19, 8, "evening"),
    # 19:00 Berlin: that entry is running.
    (19, 17, "evening"),
    # 10:00 Berlin on the 20th: nobody has the hotline that day at all.
    (20, 8, None),
    # 10:00 Berlin on the 21st, inside an entry that started at 08:00.
    (21, 8, "daytime"),
])
def test_same_day_reads_the_running_entry_or_the_next_one_that_day(rota_cal, day, hour, expected):
    moment = datetime.datetime(2026, 8, day, hour, tzinfo=datetime.timezone.utc)

    event = _event_at(rota_cal, CONFIG, moment, EVENT_OFFSET_SAME_DAY)

    assert (event.summary if event else None) == expected


@pytest.mark.asyncio
async def test_a_same_day_selector_gets_its_own_slice(rota_cal):
    """The whole path: a selector the templates name, resolved into `event(...;offset=same_day)`."""
    uncovered = datetime.datetime(2026, 8, 20, 8, tzinfo=datetime.timezone.utc)

    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(rota_cal, "Notfallhotline"))):
        variables = await hutbot.calendarfeed.get_calendar_template_variables(
            None, CONFIG, uncovered, selectors=[("", "same-day"), ("", "next")])

    # Nobody has the hotline that day, while `next` reports the entry two days on.
    assert variables[f"__{event_slice_name('calendar_summary', '', 'same-day')}"] == "<no-event>"
    assert variables[f"__{event_slice_name('calendar_summary', '', 'next')}"] == "daytime"


def test_same_day_is_what_next_cannot_answer(rota_cal):
    """`offset=next` reports the entry two days on, hiding the day that has none."""
    uncovered = datetime.datetime(2026, 8, 20, 8, tzinfo=datetime.timezone.utc)

    assert _event_at(rota_cal, CONFIG, uncovered, 1).summary == "daytime"
    assert _event_at(rota_cal, CONFIG, uncovered, EVENT_OFFSET_SAME_DAY) is None


def test_same_day_counts_the_day_in_the_config_timezone(rota_cal):
    """22:30 UTC on the 20th is already the 21st in Berlin, so that day's entry is the answer."""
    late = datetime.datetime(2026, 8, 20, 22, 30, tzinfo=datetime.timezone.utc)

    assert _event_at(rota_cal, CONFIG, late, EVENT_OFFSET_SAME_DAY).summary == "daytime"
    assert _event_at(rota_cal, {"datetime_timezone": "UTC"}, late, EVENT_OFFSET_SAME_DAY) is None


# Two entries whose UTC date is not their Berlin date: 23:00Z on the 19th is 01:00 on the 20th
# locally, and 22:00Z on the 20th is 00:00 on the 21st.
MIDNIGHT_ICS = "\r\n".join([
    "BEGIN:VCALENDAR", "VERSION:2.0", "X-WR-CALNAME:Notfallhotline",
    "BEGIN:VEVENT", "UID:after-midnight", "SUMMARY:after-midnight",
    "DTSTART:20260819T230000Z", "DTEND:20260820T010000Z", "END:VEVENT",
    "BEGIN:VEVENT", "UID:next-local-day", "SUMMARY:next-local-day",
    "DTSTART:20260820T220000Z", "DTEND:20260821T020000Z", "END:VEVENT",
    "END:VCALENDAR", "",
])


@pytest.fixture
def midnight_cal():
    return icalendar.Calendar.from_ical(MIDNIGHT_ICS)


def test_same_day_dates_a_utc_dtstart_by_the_configured_day(midnight_cal):
    """The day is the config's, on both sides of the comparison — not the feed's UTC date."""
    # 00:30 on the 20th in Berlin. The 01:00 entry is later that *local* day, though its
    # DTSTART is dated the 19th in UTC.
    just_after_midnight = datetime.datetime(2026, 8, 19, 22, 30, tzinfo=datetime.timezone.utc)
    assert _event_at(midnight_cal, CONFIG, just_after_midnight, EVENT_OFFSET_SAME_DAY).summary == "after-midnight"

    # 10:00 on the 20th in Berlin. The 22:00Z entry is 00:00 on the 21st locally, so the 20th
    # has nothing left — even though its DTSTART is dated the 20th in UTC.
    morning = datetime.datetime(2026, 8, 20, 8, tzinfo=datetime.timezone.utc)
    assert _event_at(midnight_cal, CONFIG, morning, EVENT_OFFSET_SAME_DAY) is None
    # Same feed read in UTC: there the 22:00Z entry *is* the rest of that day.
    assert _event_at(midnight_cal, {"datetime_timezone": "UTC"}, morning,
                     EVENT_OFFSET_SAME_DAY).summary == "next-local-day"


@pytest.mark.parametrize("spelling", ["same-day", "same_day", "SAME DAY", "that-day", "today", "day"])
def test_the_same_day_offset_has_one_canonical_form(spelling):
    """Every spelling shares a slice key, so one selection serves them all."""
    assert parse_event_offset(spelling) == EVENT_OFFSET_SAME_DAY
    assert event_slice_name("calendar_summary", "+2w", spelling) == \
        "event(at=+2w;offset=same_day)_calendar_summary"


def test_the_offset_error_names_same_day(offset_cal):
    with pytest.raises(ValueError) as e:
        parse_event_offset("2h")
    assert "`same-day`" in str(e.value)


def test_a_previous_event_beyond_the_lookback_window_is_not_found(offset_cal):
    """The ICS library has no `before()`, so the search is bounded — and finds nothing past it."""
    much_later = datetime.datetime(2026, 11, 1, 12, 0, tzinfo=datetime.timezone.utc)

    with patch('hutbot.calendarfeed._CALENDAR_LOOKBACK_DAYS', 1):
        assert _event_at(offset_cal, CONFIG, much_later, -1) is None
    with patch('hutbot.calendarfeed._CALENDAR_LOOKBACK_DAYS', 120):
        assert _event_at(offset_cal, CONFIG, much_later, -1).summary == "fourth"


def test_one_occurrence_of_a_series_is_never_counted_twice(cal):
    """`m3 daily` recurs; two backward steps must not land on the same occurrence."""
    friday = datetime.datetime(2026, 8, 21, 10, 0, tzinfo=datetime.timezone.utc)
    starts = [event.start for event in
              (_event_at(cal, CONFIG, friday, -1), _event_at(cal, CONFIG, friday, -2))
              if event is not None]

    assert len(starts) == len(set(starts))


@pytest.mark.asyncio
async def test_a_selector_reads_the_calendar_at_another_moment(cal):
    """The default keys describe now; a slice describes the moment it was asked about."""
    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(cal, "Team Kalender"))):
        variables = await hutbot.calendarfeed.get_calendar_template_variables(
            None, CONFIG, INSIDE_COMPOSER, selectors=[("2026-08-19T12:15:00Z", ""), ("", "prev")])

    assert variables["calendar_summary"] == "Composerbereitstellung"
    assert variables[f"__{event_slice_name('calendar_summary', '2026-08-19T12:15:00Z', '')}"] == "Mit Dauer"
    # Every selection travels with the variables it filled, so `test` can report the moment it
    # resolved to — and the event behind it — without a clock or a second fetch.
    selections = variables[CALENDAR_SELECTIONS_KEY]
    assert [(selection.at, selection.offset) for selection in selections] == [
        ("", ""), ("2026-08-19T12:15:00Z", ""), ("", "prev")]
    assert selections[0].event.summary == "Composerbereitstellung"
    assert selections[1].event.summary == "Mit Dauer"
    assert selections[1].instant.isoformat().startswith("2026-08-19T14:15")
    assert selections[1].prefix == event_slice_prefix("2026-08-19T12:15:00Z", "")


@pytest.mark.asyncio
async def test_a_selector_the_calendar_cannot_answer_keeps_its_placeholders(cal):
    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(cal, "Team Kalender"))):
        variables = await hutbot.calendarfeed.get_calendar_template_variables(
            None, CONFIG, INSIDE_COMPOSER, selectors=[("2027-06-01", "")])

    stem = event_slice_name("calendar_summary", "2027-06-01", "")
    assert variables[f"__{stem}"] == "<no-event>"
    assert variables[f"__{event_slice_name('calendar_start_time', '2027-06-01', '')}"] == "<unknown>"


@pytest.mark.asyncio
async def test_an_unusable_selector_is_ignored_rather_than_answered_about_now(cal):
    """Only a hand-edited config gets here; it must not quietly describe the present."""
    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(cal, "Team Kalender"))), \
         patch('hutbot.calendarfeed.log_warning') as log_warning:
        variables = await hutbot.calendarfeed.get_calendar_template_variables(
            None, CONFIG, INSIDE_COMPOSER, selectors=[("tomorrow", ""), ("", "soon")])

    assert variables["calendar_summary"] == "Composerbereitstellung"
    assert variables[f"__{event_slice_name('calendar_summary', 'tomorrow', '')}"] == "<no-event>"
    assert log_warning.call_count == 2


@pytest.mark.asyncio
async def test_every_selector_shares_one_fetch_and_one_index(cal):
    """Two fetches straddling the cache TTL could answer one message from two documents."""
    indexings = []
    real_index = hutbot.calendarfeed.index_calendar

    def counting_index(calendar):
        indexings.append(calendar)
        return real_index(calendar)

    calls = []
    with _patch_http(_FakeResponse(text=SAMPLE_ICS), calls), \
         patch('hutbot.calendarfeed.index_calendar', counting_index):
        await hutbot.calendarfeed.get_calendar_template_variables(
            None, CONFIG, INSIDE_COMPOSER,
            selectors=[("+1d", ""), ("", "next"), ("2026-08-19", "prev")])

    assert len(calls) == 1
    assert len(indexings) == 1


@pytest.mark.asyncio
async def test_two_spellings_of_one_moment_share_a_slice(cal):
    """`at=" +1D "` and `at="+1d"` are one request, so they cost one selection."""
    selectors = hutbot.templating.find_calendar_selectors(
        '{{calendar_summary(at="+1d")}} {{calendar_location(at=" +1D ")}}')

    assert selectors == [("+1d", "")]


@pytest.mark.asyncio
async def test_the_placeholders_of_a_slice_are_internal_only(cal):
    """No new public key, ever: the public set is what `test` and the web UI enumerate."""
    plain = get_calendar_placeholder_variables(CONFIG)
    with_slices = get_calendar_placeholder_variables(CONFIG, [("+1d", "next")])

    public = {key for key in with_slices if not key.startswith("__")}
    assert public == {key for key in plain if not key.startswith("__")}
    assert public == CALENDAR_TEMPLATE_VARIABLES
    # The feed's name does not depend on a moment, so no slice carries one.
    assert not any(key.endswith("calendar_name") for key in with_slices if key.startswith("__event"))


@pytest.mark.asyncio
async def test_a_gated_rule_reads_its_condition_and_its_message_at_one_moment(cal):
    """The condition's selector must be resolved by the same build the message uses."""
    config = {**copy.deepcopy(DEFAULT_CONFIG), **CONFIG,
              "reply_message": "next: {{calendar_summary(offset=next)}}",
              "conditions": [{"variable": "calendar_summary", "operator": "not_empty", "offset": "next"}]}
    channel = _mk_channel({"default": config})
    calls = []

    _seed_user_caches()
    with _patch_http(_FakeResponse(text=SAMPLE_ICS), calls):
        met, reason, variables = await hutbot.actions.evaluate_conditions(
            _ui_app(), OpsGenieTokens(), channel, config, "default", {"channel_id": channel.id})

    assert met is True, reason
    assert len(calls) == 1
    rendered = hutbot.templating.render_reply_message_template(config["reply_message"], variables, config)
    assert rendered.startswith("next: ") and "<no-event>" not in rendered

@pytest.mark.asyncio
async def test_the_test_command_names_what_each_moment_resolved_to(cal):
    """A relative `at` is a different instant in the preview than at the firing, so say which."""
    app = _ui_app()
    _seed_user_caches()
    config = {**copy.deepcopy(DEFAULT_CONFIG), **CONFIG,
              "reply_message": 'tomorrow: {{calendar_summary(at="+1d")}}'}
    channel = _mk_channel({"default": config})
    user = User("U1", "dave", "Dave", "T")

    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(cal, "Team Kalender"))), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, "test", channel, user)

    text = sent_messages(send)
    # The moment the selector resolved to, beside the event it found there.
    assert re.search(r'\*Event\* `at="\+1d"`, read at \w', text)


@pytest.mark.asyncio
async def test_the_test_command_reads_the_neighbouring_events_too(cal):
    """A rule that names no moment still gets the previous and next event, to compare against."""
    app = _ui_app()
    _seed_user_caches()
    config = {**copy.deepcopy(DEFAULT_CONFIG), **CONFIG, "reply_message": "now: {{calendar_summary}}"}
    channel = _mk_channel({"default": config})
    user = User("U1", "dave", "Dave", "T")

    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(cal, "Team Kalender"))), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, "test", channel, user)

    text = sent_messages(send)
    assert "*Event* now, read at" in text
    assert "*Event* `offset=next`, read at" in text
    assert "*Event* `offset=prev`, read at" in text
    # And the whole namespace at those two moments, which is the reference half of `test`.
    assert "*Calendar variables at `offset=next`:*" in text
    assert "`{{calendar_summary(offset=prev)}}`: " in text


def test_an_invalid_selector_renders_a_placeholder_not_the_current_event():
    """A malformed argument must never answer about now — the expression named another moment."""
    render = hutbot.templating.render_reply_message_template
    variables = {"calendar_summary": "Running now", "calendar_start_time": "09:00"}

    assert render("{{calendar_summary(offset=soon)}}", variables) == "<no-event>"
    assert render("{{calendar_summary(at=tomorrow)}}", variables) == "<no-event>"
    assert render("{{calendar_start_time(offset=soon)}}", variables) == "<unknown>"
    # The plain form is untouched.
    assert render("{{calendar_summary}}", variables) == "Running now"


@pytest.mark.parametrize("condition", [
    {"variable": "calendar_summary", "operator": "contains", "value": "Running", "offset": "soon"},
    {"variable": "calendar_summary", "operator": "empty", "at": "tomorrow"},
])
def test_a_condition_with_an_invalid_selector_fails_closed(condition):
    """Including `empty`, which would otherwise pass on the missing value."""
    met, reason = hutbot.conditionutil.evaluate_conditions(
        {"conditions": [condition]}, {"calendar_summary": "Running now"})

    assert met is False
    assert "cannot be read" in reason


def test_the_selectors_cover_every_field_of_the_config():
    """Nothing is dropped: a config may read as many moments as it likes."""
    config = {
        "reply_message": " ".join(f'{{{{calendar_summary(at="+{hour}h")}}}}' for hour in range(1, 8)),
        "action_target": '{{calendar_other_attendee_users(at="+9h", nth=1)}}',
        "opsgenie_message": '{{calendar_summary(at="+10h")}}',
        "conditions": [{"variable": "calendar_summary", "operator": "not_empty", "at": "+11h"}],
    }

    selectors = hutbot.templating.config_calendar_selectors(config)

    # Message, then alert, then target, then the conditions — every one of them resolved.
    assert [at for at, _ in selectors] == ["+1h", "+2h", "+3h", "+4h", "+5h", "+6h", "+7h",
                                           "+10h", "+9h", "+11h"]


def test_the_config_selectors_include_the_conditions():
    """A rule whose only selector is in a condition still gets a slice built for it."""
    config = {"reply_message": "{{calendar_summary}}",
              "conditions": [{"variable": "calendar_summary", "operator": "contains",
                              "value": "x", "at": "+1d", "offset": "next"}]}

    assert hutbot.templating.config_calendar_selectors(config) == [("+1d", "next")]


@pytest.mark.asyncio
async def test_the_test_command_judges_a_condition_against_its_own_moment(cal):
    """The preview and the firing must reach the same verdict, selector or not."""
    app = _ui_app()
    _seed_user_caches()
    config = {**copy.deepcopy(DEFAULT_CONFIG), **CONFIG,
              "reply_message": "checked",
              "conditions": [{"variable": "calendar_summary", "operator": "contains",
                              "value": "daily", "at": "2026-08-19T11:15:00+02:00"}]}
    channel = _mk_channel({"default": config})

    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(cal, "Team Kalender"))), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, "test", channel, User("U1", "dave", "Dave", "T"))

    text = sent_messages(send)
    # `m3 daily` runs at 11:15 Berlin, so the gate passes — it would fail against "now".
    assert ":white_check_mark:" in text and "would run" in text


# ----- built-in calendars -----

def _current_and_next(calendar, config=None, now=None):
    """The event running at `now` and the next one, over one shared index.

    Most of these tests want both, and asking for `offset=0` and `offset=+1` is how that pair
    is expressed now that one variable set covers every event.
    """
    now = now or datetime.datetime.now(datetime.timezone.utc)
    query = index_calendar(calendar)
    return select_event(query, config, now, 0), select_event(query, config, now, 1)


def _event_at(calendar, config=None, now=None, offset=0):
    """One event, `offset` places from the one running at `now`."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return select_event(index_calendar(calendar), config, now, offset)


def builtin_names(calendars):
    return [calendar.name for calendar in calendars]


BUILTIN_JSON = json.dumps([
    {"name": "rota", "title": "Platform on-call rota", "url": "https://cal.example.com/SECRETTOKEN/rota.ics"},
    {"name": "holidays", "title": "Company holidays", "url": "https://cal.example.com/OTHERTOKEN/holidays.ics"},
])


def test_parse_builtin_calendars_reads_name_title_and_url():
    calendars = parse_builtin_calendars(BUILTIN_JSON)
    assert [(c.name, c.title) for c in calendars] == [
        ("rota", "Platform on-call rota"), ("holidays", "Company holidays")]
    assert calendars[0].url.endswith("/SECRETTOKEN/rota.ics")


def test_load_builtin_calendars_reads_plain_json_from_the_environment(monkeypatch):
    """`get_env_var` base64-decodes what it can; a JSON array must survive untouched."""
    monkeypatch.setenv("HUTBOT_BUILTIN_CALENDARS", BUILTIN_JSON)
    assert builtin_names(load_builtin_calendars()) == ["rota", "holidays"]


def test_load_builtin_calendars_reads_a_base64_payload(monkeypatch):
    monkeypatch.setenv("HUTBOT_BUILTIN_CALENDARS", base64.b64encode(BUILTIN_JSON.encode()).decode())
    assert builtin_names(load_builtin_calendars()) == ["rota", "holidays"]


def test_load_builtin_calendars_prefers_the_file(monkeypatch, tmp_path):
    path = tmp_path / "builtin-calendars.json"
    path.write_text(BUILTIN_JSON + "\n")
    monkeypatch.setenv("HUTBOT_BUILTIN_CALENDARS", "[]")
    monkeypatch.setenv("HUTBOT_BUILTIN_CALENDARS_FILE", str(path))
    assert builtin_names(load_builtin_calendars()) == ["rota", "holidays"]


def test_load_builtin_calendars_survives_a_missing_file(monkeypatch, tmp_path):
    """An instance with no built-in calendars has no file, and that is not a failure.

    The chart sets the path whenever the Secret is mounted, but the volume projects the key
    only when the deployment actually has one.
    """
    monkeypatch.delenv("HUTBOT_BUILTIN_CALENDARS", raising=False)
    monkeypatch.setenv("HUTBOT_BUILTIN_CALENDARS_FILE", str(tmp_path / "gone.json"))
    with patch('hutbot.calendarfeed.log_error') as log_error:
        assert load_builtin_calendars() == []
    assert not log_error.called


def test_a_missing_file_falls_back_to_the_variable(monkeypatch, tmp_path):
    monkeypatch.setenv("HUTBOT_BUILTIN_CALENDARS", BUILTIN_JSON)
    monkeypatch.setenv("HUTBOT_BUILTIN_CALENDARS_FILE", str(tmp_path / "gone.json"))
    assert builtin_names(load_builtin_calendars()) == ["rota", "holidays"]


def test_an_unreadable_file_is_still_an_error(monkeypatch, tmp_path):
    """A path that exists but cannot be read is a misconfiguration, not an empty list."""
    directory = tmp_path / "builtin-calendars.json"
    directory.mkdir()
    monkeypatch.setenv("HUTBOT_BUILTIN_CALENDARS", BUILTIN_JSON)
    monkeypatch.setenv("HUTBOT_BUILTIN_CALENDARS_FILE", str(directory))
    with patch('hutbot.calendarfeed.log_error') as log_error:
        assert load_builtin_calendars() == []
    assert log_error.called


@pytest.mark.parametrize("raw", ["", "   ", "[]"])
def test_parse_builtin_calendars_is_empty_by_default(raw):
    assert parse_builtin_calendars(raw) == []


@pytest.mark.parametrize("raw", ['{"rota": "…"}', "not json at all", '"a string"'])
def test_parse_builtin_calendars_refuses_anything_but_an_array(raw):
    with patch('hutbot.calendarfeed.log_error') as log_error:
        assert parse_builtin_calendars(raw) == []
    assert log_error.called


@pytest.mark.parametrize("entry", [
    {"title": "No name", "url": "https://cal.example.com/a.ics"},
    {"name": "", "title": "Blank", "url": "https://cal.example.com/a.ics"},
    {"name": "Has Space", "title": "Bad name", "url": "https://cal.example.com/a.ics"},
    {"name": "-leading", "title": "Bad name", "url": "https://cal.example.com/a.ics"},
    {"name": "a/b", "title": "URL-shaped name", "url": "https://cal.example.com/a.ics"},
    {"name": "rota", "title": "", "url": "https://cal.example.com/a.ics"},
    {"name": "rota", "title": "No URL"},
    {"name": "rota", "title": "Plain http", "url": "http://cal.example.com/a.ics"},
    {"name": "rota", "title": "Internal", "url": "https://10.0.0.1/a.ics"},
    "not an object",
])
def test_parse_builtin_calendars_skips_an_unusable_entry(entry):
    with patch('hutbot.calendarfeed.log_warning') as log_warning:
        assert parse_builtin_calendars(json.dumps([entry])) == []
    assert log_warning.called


def test_parse_builtin_calendars_casefolds_the_name_and_keeps_the_first_duplicate():
    calendars = parse_builtin_calendars(json.dumps([
        {"name": "Rota", "title": "First", "url": "https://cal.example.com/1.ics"},
        {"name": "rota", "title": "Second", "url": "https://cal.example.com/2.ics"},
    ]))
    assert [(c.name, c.title) for c in calendars] == [("rota", "First")]


def test_parse_builtin_calendars_never_logs_a_token():
    """Every failure path reports a name or a position, never the payload or a raw URL."""
    payloads = [
        '{"broken": ',
        json.dumps({"name": "rota", "url": "https://cal.example.com/SECRETTOKEN/rota.ics"}),
        json.dumps([{"name": "rota", "url": "http://cal.example.com/SECRETTOKEN/rota.ics"}]),
        json.dumps([{"title": "No name", "url": "https://cal.example.com/SECRETTOKEN/rota.ics"}]),
    ]
    for payload in payloads:
        with patch('hutbot.calendarfeed.log_warning') as log_warning, \
             patch('hutbot.calendarfeed.log_error') as log_error:
            parse_builtin_calendars(payload)
        logged = " ".join(str(arg) for call in log_warning.call_args_list + log_error.call_args_list
                          for arg in call.args)
        assert "SECRETTOKEN" not in logged, payload


@pytest.mark.parametrize("value,expected", [
    ("rota", "rota"), ("ROTA", "rota"), ("  Rota  ", "rota"), ("platform.rota", "platform.rota"),
    ("a_b-c", "a_b-c"), ("", ""), ("has space", ""), ("a/b", ""), ("https://x/y.ics", ""), ("-x", ""),
])
def test_normalize_builtin_calendar_name(value, expected):
    assert normalize_builtin_calendar_name(value) == expected


def test_lookup_and_list_builtin_calendars():
    with _patch_builtin_calendars():
        assert lookup_builtin_calendar("ROTA").title == "Platform on-call rota"
        assert lookup_builtin_calendar("nope") is None
        assert lookup_builtin_calendar("https://cal.example.com/x.ics") is None
        assert builtin_calendar_names() == ["holidays", "rota"]


def test_state_reset_clears_the_builtin_calendars():
    hutbot.state.builtin_calendars = list(BUILTIN_CALENDARS)
    hutbot.state.reset()
    assert hutbot.state.builtin_calendars == []


def test_resolve_calendar_feed_resolves_a_builtin_and_prefers_it_over_a_stored_url():
    with _patch_builtin_calendars():
        feed = resolve_calendar_feed({"calendar_builtin": "Rota", "calendar_url": "https://other.example.com/x.ics"})
    assert feed.builtin == "rota" and feed.title == "Platform on-call rota"
    assert feed.url.endswith("/SECRETTOKEN/rota.ics") and feed.missing is False


def test_resolve_calendar_feed_reports_a_builtin_this_instance_lost():
    with _patch_builtin_calendars([]):
        feed = resolve_calendar_feed({"calendar_builtin": "rota"})
    assert feed.missing is True and feed.url == "" and feed.builtin == "rota"


def test_resolve_calendar_feed_falls_back_to_the_url_and_to_nothing():
    feed = resolve_calendar_feed({"calendar_url": "https://cal.example.com/a/b/feed.ics"})
    assert feed.builtin == "" and feed.url.endswith("feed.ics")
    assert feed.title == "cal.example.com/…"
    assert resolve_calendar_feed({}) == hutbot.models.CalendarFeed("", "", "", False)


def test_describe_calendar_feed_never_shows_a_builtin_url():
    with _patch_builtin_calendars():
        feed = resolve_calendar_feed({"calendar_builtin": "rota"})
    label = describe_calendar_feed(feed)
    assert label == "Platform on-call rota"
    assert "cal.example.com" not in label and "SECRETTOKEN" not in label


@pytest.mark.asyncio
async def test_a_builtin_is_fetched_from_its_resolved_url_and_shared_between_configs():
    calls = []
    with _patch_builtin_calendars(), _patch_http(_FakeResponse(text=SAMPLE_ICS), calls):
        first = await hutbot.calendarfeed.resolve_calendar_context({"calendar_builtin": "rota"}, NOW)
        # A second config on the same built-in resolves to the same URL, so the cache keyed by
        # URL answers it without another fetch.
        await hutbot.calendarfeed.resolve_calendar_context({"calendar_builtin": "ROTA"}, NOW)
    assert calls == ["https://cal.example.com/SECRETTOKEN/rota.ics"]
    # The curated title wins over the feed's own `X-WR-CALNAME` ("Team Kalender").
    assert first.name == "Platform on-call rota"
    assert first.event is not None


@pytest.mark.asyncio
async def test_a_missing_builtin_fetches_nothing():
    calls = []
    with _patch_builtin_calendars([]), _patch_http(_FakeResponse(text=SAMPLE_ICS), calls):
        context = await hutbot.calendarfeed.resolve_calendar_context({"calendar_builtin": "rota"}, NOW)
        variables = await hutbot.calendarfeed.get_calendar_template_variables(None, {"calendar_builtin": "rota"}, NOW)
    assert calls == []
    assert context.name == "" and context.event is None
    assert variables["calendar_name"] == UNKNOWN_CALENDAR_BUILTIN_PLACEHOLDER
    assert variables["calendar_summary"] == "<no-event>"


def test_placeholder_variables_name_a_builtin_by_its_title():
    with _patch_builtin_calendars():
        variables = get_calendar_placeholder_variables({"calendar_builtin": "rota"})
    assert variables["calendar_name"] == "Platform on-call rota"
    assert get_calendar_placeholder_variables({})["calendar_name"] == UNKNOWN_CALENDAR_PLACEHOLDER


@pytest.mark.asyncio
async def test_a_builtin_never_leaks_its_url_into_the_variables():
    calls = []
    with _patch_builtin_calendars(), _patch_http(_FakeResponse(text=SAMPLE_ICS), calls):
        variables = await hutbot.calendarfeed.get_calendar_template_variables(None, {"calendar_builtin": "rota"}, NOW)
    assert "SECRETTOKEN" not in json.dumps(variables, default=str)


def test_the_missing_builtin_placeholder_counts_as_empty_for_a_condition():
    assert UNKNOWN_CALENDAR_BUILTIN_PLACEHOLDER in hutbot.constants.UNKNOWN_PLACEHOLDERS


# ----- the calendar bridge -----

# The listing endpoint as a deployment writes it: a path the calendars hang off, and a token in
# the query string. BRIDGETOKEN is the marker a leak test looks for.
BRIDGE_URL = "https://bridge.example.com/calendars/?token=BRIDGETOKEN"
BRIDGE_ICS_URL = "https://bridge.example.com/calendars/{name}.ics?token=BRIDGETOKEN"


def _bridge_listing(*names) -> str:
    return json.dumps({"feeds": list(names)})


def _bridge_ics(title: str = "") -> str:
    """The smallest document `fetch_calendar` accepts, named or anonymous."""
    return "\r\n".join([
        "BEGIN:VCALENDAR", "VERSION:2.0",
        *([f"X-WR-CALNAME:{title}"] if title else []),
        "END:VCALENDAR", "",
    ])


class _MapSession:
    """A fake transport keyed by URL rather than by call order.

    The title fetches run concurrently, so which one asks first is not fixed — an
    order-indexed `_FakeSession` would answer the wrong document half the time.
    """

    def __init__(self, pages, requests):
        self._pages = pages
        self.requests = requests

    def get(self, url, **kwargs):
        self.requests.append(url)
        page = self._pages.get(url)
        return page if page is not None else _FakeResponse(status=404, text="")

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


@contextlib.contextmanager
def _patch_bridge_http(pages, requests):
    """Fake the transport for the listing and every ICS beside it, and skip real DNS."""
    with patch('hutbot.calendarfeed.aiohttp.ClientSession',
               lambda *a, **k: _MapSession(pages, requests)), \
         patch('hutbot.calendarfeed._resolve_public_host', new=AsyncMock(return_value="")):
        yield


def _bridge_pages(listing, titles=None, listing_status=200):
    """The documents a refresh reads: the listing, plus one ICS per calendar in `titles`."""
    pages = {BRIDGE_URL: _FakeResponse(status=listing_status, text=listing)}
    for name, title in (titles or {}).items():
        pages[BRIDGE_ICS_URL.format(name=name)] = _FakeResponse(text=_bridge_ics(title))
    return pages


async def _refresh_bridge(pages, requests=None):
    requests = requests if requests is not None else []
    with _patch_bridge_http(pages, requests):
        await hutbot.calendarfeed.refresh_bridge_calendars()
    return requests


def test_the_listing_url_gains_the_trailing_slash_its_names_hang_off(monkeypatch):
    monkeypatch.setenv('HUTBOT_CALENDAR_BRIDGE_URL', "https://bridge.example.com/calendars?token=BRIDGETOKEN")
    assert hutbot.calendarfeed.calendar_bridge_listing_url() == BRIDGE_URL
    monkeypatch.setenv('HUTBOT_CALENDAR_BRIDGE_URL', BRIDGE_URL)
    assert hutbot.calendarfeed.calendar_bridge_listing_url() == BRIDGE_URL


def test_the_listing_url_is_empty_when_no_bridge_is_configured(monkeypatch):
    monkeypatch.delenv('HUTBOT_CALENDAR_BRIDGE_URL', raising=False)
    assert hutbot.calendarfeed.calendar_bridge_listing_url() == ""
    monkeypatch.setenv('HUTBOT_CALENDAR_BRIDGE_URL', "   ")
    assert hutbot.calendarfeed.calendar_bridge_listing_url() == ""


def test_a_bridge_url_that_is_not_usable_is_ignored_without_echoing_its_token(monkeypatch):
    monkeypatch.setenv('HUTBOT_CALENDAR_BRIDGE_URL', "http://bridge.example.com/calendars/?token=BRIDGETOKEN")
    with patch('hutbot.calendarfeed.log_error') as log_error:
        assert hutbot.calendarfeed.calendar_bridge_listing_url() == ""
    logged = " ".join(str(arg) for call in log_error.call_args_list for arg in call.args)
    assert "BRIDGETOKEN" not in logged and "HUTBOT_CALENDAR_BRIDGE_URL" in logged


def test_a_listing_url_without_a_token_is_used_but_reported(monkeypatch):
    monkeypatch.setenv('HUTBOT_CALENDAR_BRIDGE_URL', "https://bridge.example.com/calendars/")
    with patch('hutbot.calendarfeed.log_warning') as log_warning:
        assert hutbot.calendarfeed.calendar_bridge_listing_url() == "https://bridge.example.com/calendars/"
    assert log_warning.called


@pytest.mark.parametrize("raw,expected", [
    (None, 60), ("", 60), ("  ", 60), ("15", 15), (" 15 ", 15), ("0", 0), ("-5", 60), ("hourly", 60),
])
def test_the_refresh_interval_falls_back_to_the_default(monkeypatch, raw, expected):
    if raw is None:
        monkeypatch.delenv('HUTBOT_CALENDAR_BRIDGE_REFRESH', raising=False)
    else:
        monkeypatch.setenv('HUTBOT_CALENDAR_BRIDGE_REFRESH', raw)
    assert hutbot.calendarfeed.calendar_bridge_refresh_minutes() == expected


def test_a_calendar_hangs_off_the_listing_path_with_the_same_token():
    assert hutbot.calendarfeed.calendar_bridge_ics_url(BRIDGE_URL, "notfallhotline") == \
        "https://bridge.example.com/calendars/notfallhotline.ics?token=BRIDGETOKEN"
    # A fragment on the listing is not part of a calendar's URL.
    assert hutbot.calendarfeed.calendar_bridge_ics_url(
        "https://bridge.example.com/calendars/?token=T#frag", "rota") == \
        "https://bridge.example.com/calendars/rota.ics?token=T"


@pytest.mark.parametrize("raw,expected", [
    ('{"feeds": ["rota", "holidays"]}', ["rota", "holidays"]),
    ('{"feeds": ["Rota", "rota"]}', ["rota"]),
    ('{"feeds": ["rota", "../secret", 42, null, "has space"]}', ["rota"]),
    ('{"feeds": []}', []),
    ('{"broken": ', None),
    ('["rota"]', None),
    ('{"calendars": ["rota"]}', None),
])
def test_a_listing_is_read_or_refused_as_a_whole(raw, expected):
    with patch('hutbot.calendarfeed.log_warning'), patch('hutbot.calendarfeed.log_error'):
        assert hutbot.calendarfeed.parse_calendar_bridge_listing(raw) == expected


@pytest.mark.asyncio
async def test_the_bridge_listing_becomes_the_builtin_calendars(monkeypatch):
    monkeypatch.setenv('HUTBOT_CALENDAR_BRIDGE_URL', BRIDGE_URL)
    pages = _bridge_pages(_bridge_listing("rota", "holidays"),
                          {"rota": "Platform on-call rota", "holidays": "Company holidays"})
    requests = await _refresh_bridge(pages)
    assert [(c.name, c.title, c.bridge) for c in hutbot.state.builtin_calendars] == [
        ("holidays", "Company holidays", True),
        ("rota", "Platform on-call rota", True),
    ]
    # The listing plus one ICS per calendar, and nothing else.
    assert sorted(requests) == sorted([BRIDGE_URL,
                                       BRIDGE_ICS_URL.format(name="rota"),
                                       BRIDGE_ICS_URL.format(name="holidays")])


@pytest.mark.asyncio
async def test_a_builtin_from_the_bridge_resolves_to_the_url_beside_the_listing(monkeypatch):
    monkeypatch.setenv('HUTBOT_CALENDAR_BRIDGE_URL', BRIDGE_URL)
    await _refresh_bridge(_bridge_pages(_bridge_listing("rota"), {"rota": "Platform on-call rota"}))
    feed = resolve_calendar_feed({"calendar_builtin": "rota"})
    assert feed.url == BRIDGE_ICS_URL.format(name="rota")
    assert describe_calendar_feed(feed) == "Platform on-call rota"


@pytest.mark.asyncio
async def test_a_calendar_without_a_title_of_its_own_is_shown_by_name(monkeypatch):
    monkeypatch.setenv('HUTBOT_CALENDAR_BRIDGE_URL', BRIDGE_URL)
    await _refresh_bridge(_bridge_pages(_bridge_listing("rota"), {"rota": ""}))
    calendar = lookup_builtin_calendar("rota")
    assert calendar.title == "" and calendar.display_title == "rota"
    assert describe_calendar_feed(resolve_calendar_feed({"calendar_builtin": "rota"})) == "rota"


@pytest.mark.asyncio
async def test_a_title_is_read_once_and_kept_across_refreshes(monkeypatch):
    monkeypatch.setenv('HUTBOT_CALENDAR_BRIDGE_URL', BRIDGE_URL)
    pages = _bridge_pages(_bridge_listing("rota"), {"rota": "Platform on-call rota"})
    await _refresh_bridge(pages)
    # The parsed-calendar cache expires; the title must not go with it.
    hutbot.state._calendar_cache.clear()
    requests = await _refresh_bridge(pages)
    assert requests == [BRIDGE_URL]
    assert lookup_builtin_calendar("rota").title == "Platform on-call rota"


@pytest.mark.asyncio
async def test_a_bridge_that_cannot_be_read_keeps_the_calendars_from_the_last_listing(monkeypatch):
    monkeypatch.setenv('HUTBOT_CALENDAR_BRIDGE_URL', BRIDGE_URL)
    await _refresh_bridge(_bridge_pages(_bridge_listing("rota"), {"rota": "Platform on-call rota"}))
    with patch('hutbot.calendarfeed.log_warning') as log_warning, \
         patch('hutbot.calendarfeed.log_error'):
        await _refresh_bridge(_bridge_pages("", listing_status=503))
    assert builtin_calendar_names() == ["rota"]
    assert log_warning.called


@pytest.mark.asyncio
async def test_a_calendar_the_bridge_stops_serving_goes_away(monkeypatch):
    monkeypatch.setenv('HUTBOT_CALENDAR_BRIDGE_URL', BRIDGE_URL)
    await _refresh_bridge(_bridge_pages(_bridge_listing("rota", "holidays"),
                                        {"rota": "Rota", "holidays": "Holidays"}))
    # An empty listing is an answer, not a failure: it really serves nothing now.
    await _refresh_bridge(_bridge_pages(_bridge_listing()))
    assert builtin_calendar_names() == []


@pytest.mark.asyncio
async def test_the_registry_adds_to_what_the_bridge_serves(monkeypatch):
    monkeypatch.setenv('HUTBOT_CALENDAR_BRIDGE_URL', BRIDGE_URL)
    monkeypatch.setenv('HUTBOT_BUILTIN_CALENDARS', json.dumps([
        {"name": "extra", "title": "Behind another bridge", "url": "https://cal.example.com/OTHER/extra.ics"},
    ]))
    load_builtin_calendars()
    await _refresh_bridge(_bridge_pages(_bridge_listing("rota"), {"rota": "Rota"}))
    assert builtin_calendar_names() == ["extra", "rota"]
    assert lookup_builtin_calendar("extra").bridge is False
    assert lookup_builtin_calendar("rota").bridge is True


@pytest.mark.asyncio
async def test_a_configured_calendar_overrides_the_bridge_and_is_never_fetched_for_a_title(monkeypatch):
    monkeypatch.setenv('HUTBOT_CALENDAR_BRIDGE_URL', BRIDGE_URL)
    monkeypatch.setenv('HUTBOT_BUILTIN_CALENDARS', json.dumps([
        {"name": "rota", "title": "The curated one", "url": "https://cal.example.com/OTHER/rota.ics"},
    ]))
    load_builtin_calendars()
    requests = await _refresh_bridge(_bridge_pages(_bridge_listing("rota"), {"rota": "Whatever the bridge says"}))
    calendar = lookup_builtin_calendar("rota")
    assert calendar.title == "The curated one" and calendar.bridge is False
    assert calendar.url == "https://cal.example.com/OTHER/rota.ics"
    # Only the listing: the overridden name's document is never read.
    assert requests == [BRIDGE_URL]


@pytest.mark.asyncio
async def test_a_refresh_never_logs_the_bridge_token(monkeypatch):
    monkeypatch.setenv('HUTBOT_CALENDAR_BRIDGE_URL', BRIDGE_URL)
    with patch('hutbot.calendarfeed.log') as log_, \
         patch('hutbot.calendarfeed.log_warning') as log_warning, \
         patch('hutbot.calendarfeed.log_error') as log_error:
        await _refresh_bridge(_bridge_pages(_bridge_listing("rota"), {"rota": "Rota"}))
        await _refresh_bridge(_bridge_pages("", listing_status=503))
    logged = " ".join(str(arg) for mock in (log_, log_warning, log_error)
                      for call in mock.call_args_list for arg in call.args)
    assert "BRIDGETOKEN" not in logged
    assert "Calendar bridge serves: rota." in logged


@pytest.mark.asyncio
async def test_a_roster_that_does_not_change_is_logged_once(monkeypatch):
    monkeypatch.setenv('HUTBOT_CALENDAR_BRIDGE_URL', BRIDGE_URL)
    pages = _bridge_pages(_bridge_listing("rota"), {"rota": "Rota"})
    with patch('hutbot.calendarfeed.log') as log_:
        await _refresh_bridge(pages)
        await _refresh_bridge(pages)
    assert [call.args[0] for call in log_.call_args_list] == ["Calendar bridge serves: rota."]


@pytest.mark.asyncio
async def test_removing_the_bridge_empties_its_half_of_the_list(monkeypatch):
    monkeypatch.setenv('HUTBOT_CALENDAR_BRIDGE_URL', BRIDGE_URL)
    monkeypatch.setenv('HUTBOT_BUILTIN_CALENDARS', json.dumps([
        {"name": "extra", "title": "Behind another bridge", "url": "https://cal.example.com/OTHER/extra.ics"},
    ]))
    load_builtin_calendars()
    await _refresh_bridge(_bridge_pages(_bridge_listing("rota"), {"rota": "Rota"}))
    monkeypatch.delenv('HUTBOT_CALENDAR_BRIDGE_URL')
    await _refresh_bridge({})
    assert builtin_calendar_names() == ["extra"]


@pytest.mark.asyncio
async def test_the_roster_stands_before_a_single_title_is_read(monkeypatch):
    """A listed calendar is usable at once: nothing but its printed label needs the ICS."""
    monkeypatch.setenv('HUTBOT_CALENDAR_BRIDGE_URL', BRIDGE_URL)
    reading = asyncio.Event()
    release = asyncio.Event()

    async def hanging_fetch(url):
        reading.set()
        await release.wait()
        return None, "Platform on-call rota"

    pages = _bridge_pages(_bridge_listing("rota"))
    with _patch_bridge_http(pages, []), patch('hutbot.calendarfeed.fetch_calendar', new=hanging_fetch):
        refresh = asyncio.create_task(hutbot.calendarfeed.refresh_bridge_calendars())
        await asyncio.wait_for(reading.wait(), 1)
        # Mid-title-fetch: the calendar is already there, named after itself.
        assert builtin_calendar_names() == ["rota"]
        assert lookup_builtin_calendar("rota").display_title == "rota"
        assert resolve_calendar_feed({"calendar_builtin": "rota"}).missing is False
        release.set()
        await asyncio.wait_for(refresh, 1)
    # And the title lands once the document has been read.
    assert lookup_builtin_calendar("rota").title == "Platform on-call rota"


@pytest.mark.asyncio
async def test_a_hanging_title_endpoint_does_not_hold_back_a_listing_change(monkeypatch):
    """A calendar the bridge dropped goes at once, even while titles are still being fetched."""
    monkeypatch.setenv('HUTBOT_CALENDAR_BRIDGE_URL', BRIDGE_URL)
    await _refresh_bridge(_bridge_pages(_bridge_listing("rota", "holidays"),
                                        {"rota": "Rota", "holidays": "Holidays"}))
    reading = asyncio.Event()
    release = asyncio.Event()

    async def hanging_fetch(url):
        reading.set()
        await release.wait()
        return None, ""

    with _patch_bridge_http(_bridge_pages(_bridge_listing("holidays", "newcomer")), []), \
         patch('hutbot.calendarfeed.fetch_calendar', new=hanging_fetch):
        refresh = asyncio.create_task(hutbot.calendarfeed.refresh_bridge_calendars())
        await asyncio.wait_for(reading.wait(), 1)
        assert builtin_calendar_names() == ["holidays", "newcomer"]
        release.set()
        await asyncio.wait_for(refresh, 1)


@pytest.mark.asyncio
async def test_the_roster_wait_returns_at_once_without_a_bridge(monkeypatch):
    monkeypatch.delenv('HUTBOT_CALENDAR_BRIDGE_URL', raising=False)
    # No refresh has run, so the event is unset: an instance with no bridge must not wait for it.
    await asyncio.wait_for(hutbot.calendarfeed.wait_for_bridge_roster(), 1)


@pytest.mark.asyncio
async def test_the_roster_wait_ends_with_the_first_listing(monkeypatch):
    monkeypatch.setenv('HUTBOT_CALENDAR_BRIDGE_URL', BRIDGE_URL)
    waiting = asyncio.create_task(hutbot.calendarfeed.wait_for_bridge_roster(5))
    await asyncio.sleep(0)
    assert not waiting.done()
    await _refresh_bridge(_bridge_pages(_bridge_listing("rota"), {"rota": "Rota"}))
    await asyncio.wait_for(waiting, 1)


@pytest.mark.asyncio
@pytest.mark.parametrize("pages", [
    # A listing that cannot be read, and a URL that is refused before it is dialled, both end the
    # wait: coming up with what this instance has beats holding the bot at the gate.
    _bridge_pages("", listing_status=503),
    {},
])
async def test_the_roster_wait_ends_even_when_the_listing_fails(monkeypatch, pages):
    monkeypatch.setenv('HUTBOT_CALENDAR_BRIDGE_URL', BRIDGE_URL)
    with patch('hutbot.calendarfeed.log_warning'), patch('hutbot.calendarfeed.log_error'):
        await _refresh_bridge(pages)
        await asyncio.wait_for(hutbot.calendarfeed.wait_for_bridge_roster(5), 1)


@pytest.mark.asyncio
async def test_the_roster_wait_gives_up_rather_than_holding_up_startup(monkeypatch):
    monkeypatch.setenv('HUTBOT_CALENDAR_BRIDGE_URL', BRIDGE_URL)
    with patch('hutbot.calendarfeed.log_warning') as log_warning:
        await asyncio.wait_for(hutbot.calendarfeed.wait_for_bridge_roster(0.01), 1)
    assert log_warning.called


@pytest.mark.asyncio
async def test_the_refresh_loop_returns_at_once_without_a_bridge(monkeypatch):
    monkeypatch.delenv('HUTBOT_CALENDAR_BRIDGE_URL', raising=False)
    with patch('hutbot.calendarfeed.refresh_bridge_calendars', new=AsyncMock()) as refresh:
        await hutbot.calendarfeed.run_bridge_refresh_loop()
    refresh.assert_not_called()


@pytest.mark.asyncio
async def test_the_refresh_loop_reads_the_listing_once_at_zero_minutes(monkeypatch):
    monkeypatch.setenv('HUTBOT_CALENDAR_BRIDGE_URL', BRIDGE_URL)
    monkeypatch.setenv('HUTBOT_CALENDAR_BRIDGE_REFRESH', '0')
    with patch('hutbot.calendarfeed.refresh_bridge_calendars', new=AsyncMock()) as refresh, \
         patch('hutbot.calendarfeed.asyncio.sleep', new=AsyncMock()) as sleep:
        await hutbot.calendarfeed.run_bridge_refresh_loop()
    assert refresh.await_count == 1
    sleep.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_failed_refresh_does_not_end_the_loop(monkeypatch):
    monkeypatch.setenv('HUTBOT_CALENDAR_BRIDGE_URL', BRIDGE_URL)
    monkeypatch.setenv('HUTBOT_CALENDAR_BRIDGE_REFRESH', '15')
    turns = []

    async def refresh():
        turns.append(len(turns))
        if len(turns) == 1:
            raise RuntimeError("bridge on fire")
        # Second turn: stop the loop the way the interval would.
        os.environ['HUTBOT_CALENDAR_BRIDGE_REFRESH'] = '0'

    with patch('hutbot.calendarfeed.refresh_bridge_calendars', new=refresh), \
         patch('hutbot.calendarfeed.asyncio.sleep', new=AsyncMock()), \
         patch('hutbot.calendarfeed.log_error') as log_error:
        await hutbot.calendarfeed.run_bridge_refresh_loop()
    assert len(turns) == 2 and log_error.called


def test_state_reset_clears_the_bridge_calendars():
    hutbot.state.bridge_calendars = list(BUILTIN_CALENDARS)
    hutbot.state.configured_calendars = list(BUILTIN_CALENDARS)
    hutbot.state.bridge_calendar_titles['rota'] = "Rota"
    hutbot.state._logged_bridge_roster = "rota"
    hutbot.state._bridge_roster_ready.set()
    hutbot.state.reset()
    assert hutbot.state.bridge_calendars == [] and hutbot.state.configured_calendars == []
    assert hutbot.state.bridge_calendar_titles == {} and hutbot.state._logged_bridge_roster is None
    # A fresh Event, not the one a previous run may have bound to another loop.
    assert not hutbot.state._bridge_roster_ready.is_set()


# ----- built-in calendar commands -----

@pytest.mark.asyncio
@pytest.mark.parametrize("command", ["set calendar rota", "calendar ROTA", "set calendar  rota "])
async def test_set_calendar_accepts_a_builtin_name(command):
    app = AsyncMock()
    channel = _mk_channel({"default": {**copy.deepcopy(DEFAULT_CONFIG), "calendar_url": "https://old.example.com/x.ics"}})
    user = User("U1", "dave", "Dave", "T")
    with _patch_builtin_calendars(), patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, command, channel, user)
    config = channel.configs["default"]
    assert config["calendar_builtin"] == "rota"
    # Never both: the stored URL is cleared, so what `show config` says is what gets fetched.
    assert config["calendar_url"] == ""
    confirmation = send.call_args.args[3]
    assert "Platform on-call rota" in confirmation and "`rota`" in confirmation
    assert "SECRETTOKEN" not in confirmation and "cal.example.com" not in confirmation


@pytest.mark.asyncio
async def test_set_calendar_confirms_an_untitled_builtin_by_its_name():
    """A bridge calendar can be set before its ICS has been read for a title."""
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")
    untitled = [BuiltinCalendar("rota", "", "https://cal.example.com/SECRETTOKEN/rota.ics", True)]
    with _patch_builtin_calendars(untitled), patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, "set calendar rota", channel, user)
    assert channel.configs["default"]["calendar_builtin"] == "rota"
    confirmation = send.call_args.args[3]
    assert "*rota* (`rota`)" in confirmation and "SECRETTOKEN" not in confirmation


@pytest.mark.asyncio
async def test_set_calendar_with_a_url_clears_a_stored_builtin():
    app = AsyncMock()
    channel = _mk_channel({"default": {**copy.deepcopy(DEFAULT_CONFIG), "calendar_builtin": "rota"}})
    user = User("U1", "dave", "Dave", "T")
    with _patch_builtin_calendars(), patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message'):
        await process_command(app, "set calendar https://cal.example.com/feed.ics", channel, user)
    config = channel.configs["default"]
    assert config["calendar_url"] == "https://cal.example.com/feed.ics" and config["calendar_builtin"] == ""


@pytest.mark.asyncio
async def test_set_calendar_rejects_an_unknown_name_and_lists_the_available_ones():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")
    with _patch_builtin_calendars(), patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, "set calendar rotta", channel, user)
    text = send.call_args.args[3]
    assert "Unknown *calendar* `rotta`" in text and "`rota`" in text and "`holidays`" in text
    assert channel.configs["default"]["calendar_builtin"] == ""


@pytest.mark.asyncio
async def test_set_calendar_without_any_builtins_points_at_a_url():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")
    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, "set calendar rota", channel, user)
    assert "no built-in calendars" in send.call_args.args[3]


@pytest.mark.asyncio
async def test_set_calendar_with_a_url_shaped_value_still_gets_the_url_error():
    """`cal.example.com/x.ics` was meant as a URL, so it must not read as a bad name."""
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")
    with _patch_builtin_calendars(), patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, "set calendar cal.example.com/x.ics", channel, user)
    assert "Invalid *calendar URL*" in send.call_args.args[3]


@pytest.mark.asyncio
async def test_clear_calendar_clears_both_keys():
    app = AsyncMock()
    channel = _mk_channel({"default": {**copy.deepcopy(DEFAULT_CONFIG),
                                       "calendar_builtin": "rota", "calendar_url": "https://cal.example.com/x.ics"}})
    user = User("U1", "dave", "Dave", "T")
    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message'):
        await process_command(app, "clear calendar", channel, user)
    config = channel.configs["default"]
    assert config["calendar_builtin"] == "" and config["calendar_url"] == ""


@pytest.mark.asyncio
async def test_show_calendar_labels_a_builtin_by_its_title():
    app = AsyncMock()
    config = {**copy.deepcopy(DEFAULT_CONFIG), **CONFIG, "calendar_url": "", "calendar_builtin": "rota"}
    channel = _mk_channel({"default": config})
    user = User("U1", "dave", "Dave", "T")
    with _patch_builtin_calendars(), \
         _patch_show_calendar("", [None, None, None]), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, "show calendar", channel, user)
    text = send.call_args.args[3]
    assert "No current or upcoming events in the calendar `Platform on-call rota`" in text
    assert "cal.example.com" not in text


@pytest.mark.asyncio
async def test_show_calendar_reports_a_builtin_this_instance_lost():
    app = AsyncMock()
    config = {**copy.deepcopy(DEFAULT_CONFIG), "calendar_builtin": "rota"}
    channel = _mk_channel({"default": config})
    user = User("U1", "dave", "Dave", "T")
    with _patch_builtin_calendars([]), patch('hutbot.messaging.send_message') as send:
        await process_command(app, "show calendar", channel, user)
    text = send.call_args.args[3]
    assert "built-in calendar `rota`" in text and "does not offer" in text


@pytest.mark.asyncio
async def test_show_config_names_a_builtin_by_its_title_not_its_host():
    app = _ui_app()
    _seed_user_caches()
    channel = _mk_channel({"default": {**copy.deepcopy(DEFAULT_CONFIG), "calendar_builtin": "rota"}})
    user = User("U1", "dave", "Dave", "T")
    with _patch_builtin_calendars(), patch('hutbot.messaging.send_message') as send:
        await show_config(app, channel, user, "")
    text = sent_messages(send)
    assert "Platform on-call rota (built-in: rota)" in text
    assert "cal.example.com" not in text and "SECRETTOKEN" not in text


@pytest.mark.asyncio
async def test_show_config_flags_a_builtin_this_instance_lost():
    app = _ui_app()
    _seed_user_caches()
    channel = _mk_channel({"default": {**copy.deepcopy(DEFAULT_CONFIG), "calendar_builtin": "rota"}})
    user = User("U1", "dave", "Dave", "T")
    with _patch_builtin_calendars([]), patch('hutbot.messaging.send_message') as send:
        await show_config(app, channel, user, "")
    assert "built-in: rota (not available on this instance)" in sent_messages(send)


@pytest.mark.asyncio
async def test_a_builtin_calendar_url_never_reaches_bot_json(tmp_path):
    """The whole point of storing the name: the token stays out of the state volume."""
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")
    config_file = tmp_path / "bot.json"
    hutbot.state.channel_config[channel.id] = channel.configs
    with _patch_builtin_calendars(), patch('hutbot.constants.CONFIG_FILE_NAME', str(config_file)), \
         patch('hutbot.messaging.send_message'):
        await process_command(app, "set calendar rota", channel, user)
    written = config_file.read_text()
    assert '"calendar_builtin": "rota"' in written
    assert "SECRETTOKEN" not in written and "cal.example.com" not in written
