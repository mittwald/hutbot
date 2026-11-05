"""A calendar feed cannot stall the bot: its expansion is bounded and runs off the event loop."""

import datetime
import threading
import time

from tests._common import *  # noqa: F401,F403

import icalendar

import hutbot.calendarfeed as calendarfeed
from hutbot.calendarfeed import bound_recurrences, resolve_calendar_events

URL = "https://cal.example.com/a/b/calendar.ics"
CONFIG = {"datetime_timezone": "Europe/Berlin", "calendar_url": URL}
NOW = datetime.datetime(2026, 8, 19, 9, 0, tzinfo=datetime.timezone.utc)


def _vevent(uid, rrule=None, start="20260819T083000Z", recurrence_id=None):
    lines = ["BEGIN:VEVENT", f"UID:{uid}", "DTSTAMP:20260801T000000Z", f"DTSTART:{start}",
             "DURATION:PT1H", f"SUMMARY:{uid}"]
    if rrule:
        lines.append(f"RRULE:{rrule}")
    if recurrence_id:
        lines.append(f"RECURRENCE-ID:{recurrence_id}")
    return lines + ["END:VEVENT"]


def _calendar(*events):
    lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//test//EN"]
    for event in events:
        lines += event
    return icalendar.Calendar.from_ical("\r\n".join(lines + ["END:VCALENDAR"]))


def _uids(calendar):
    return [str(event.get("UID")) for event in calendar.walk("VEVENT")]


def _calendar_threads():
    return [t for t in threading.enumerate() if t.name == "hutbot-calendar" and t.is_alive()]


# ----- what a feed may make the bot expand -----

def test_series_finer_than_hourly_are_dropped_with_their_overrides():
    calendar = _calendar(
        _vevent("secondly", "FREQ=SECONDLY", start="19700101T000000Z"),
        _vevent("secondly", recurrence_id="19700101T000005Z", start="19700101T000006Z"),
        _vevent("minutely", "FREQ=MINUTELY;INTERVAL=5"),
        _vevent("half-hourly", "FREQ=DAILY;BYHOUR=0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23;BYMINUTE=0,30"),
        _vevent("hourly", "FREQ=HOURLY"),
        _vevent("every-hour-as-minutes", "FREQ=MINUTELY;INTERVAL=60"),
        _vevent("daily", "FREQ=DAILY;BYDAY=MO,TU,WE,TH,FR"),
        _vevent("single"),
    )

    assert bound_recurrences(calendar) == 4
    assert _uids(calendar) == ["hourly", "every-hour-as-minutes", "daily", "single"]


def test_series_past_the_cap_are_dropped():
    calendar = _calendar(*(_vevent(f"s{i}", "FREQ=WEEKLY") for i in range(5)), _vevent("single"))

    with patch.object(calendarfeed, "_MAX_RECURRING_SERIES", 3):
        assert bound_recurrences(calendar) == 2

    assert _uids(calendar) == ["s0", "s1", "s2", "single"]


def test_an_ordinary_feed_is_left_alone():
    calendar = _calendar(_vevent("weekly", "FREQ=WEEKLY;BYDAY=MO"), _vevent("single"))

    assert bound_recurrences(calendar) == 0
    assert _uids(calendar) == ["weekly", "single"]


@pytest.mark.asyncio
async def test_a_secondly_feed_is_answered_quickly_instead_of_expanded():
    """The reported attack: one `FREQ=SECONDLY` event from 1970 used to pin the loop for days."""
    text = "\r\n".join(["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//test//EN",
                        *_vevent("dos", "FREQ=SECONDLY", start="19700101T000000Z"),
                        *_vevent("real"), "END:VCALENDAR"])
    with patch('hutbot.calendarfeed._get_calendar_document', new=AsyncMock(return_value=text)), \
         patch('hutbot.calendarfeed.log_warning') as warning:
        started = time.monotonic()
        name, (event,) = await resolve_calendar_events(CONFIG, [(NOW, 0)])

    assert time.monotonic() - started < 5
    assert event is not None and event.summary == "real"
    assert "left out 1 event(s)" in warning.call_args.args[0]


# ----- evaluation runs off the loop and under a deadline -----

def _spin_forever(*args, **kwargs):
    while True:
        pass


@pytest.mark.asyncio
async def test_a_runaway_evaluation_is_stopped_and_the_feed_skipped_for_a_while():
    calendar = _calendar(_vevent("single"))
    ticks = 0

    async def ticker():
        nonlocal ticks
        while True:
            ticks += 1
            await asyncio.sleep(0.01)

    tick_task = asyncio.create_task(ticker())
    try:
        with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(calendar, "Feed"))), \
             patch.object(calendarfeed, "_CALENDAR_EVALUATION_TIMEOUT", 0.3), \
             patch.object(calendarfeed, "_select_events", side_effect=_spin_forever) as select, \
             patch('hutbot.calendarfeed.log_error') as error:
            name, events = await resolve_calendar_events(CONFIG, [(NOW, 0), (NOW, 1)])
            # Within the TTL the same feed is not evaluated again.
            again_name, again = await resolve_calendar_events(CONFIG, [(NOW, 0)])
    finally:
        tick_task.cancel()

    assert (name, events) == ("Feed", [None, None])
    assert (again_name, again) == ("Feed", [None])
    assert select.call_count == 1
    assert "skipped" in error.call_args.args[0]
    assert URL in hutbot.state._calendar_evaluation_failures
    # The event loop kept running while the evaluation spun.
    assert ticks >= 5
    # And the runaway thread was stopped, not just abandoned.
    for _ in range(100):
        if not _calendar_threads():
            break
        await asyncio.sleep(0.02)
    assert _calendar_threads() == []


@pytest.mark.asyncio
async def test_a_failing_evaluation_degrades_without_raising():
    calendar = _calendar(_vevent("single"))
    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(calendar, "Feed"))), \
         patch.object(calendarfeed, "_select_events", side_effect=RuntimeError("boom")), \
         patch('hutbot.calendarfeed.log_error') as error:
        name, events = await resolve_calendar_events(CONFIG, [(NOW, 0)])

    assert (name, events) == ("Feed", [None])
    assert "Failed to evaluate" in error.call_args.args[0]
    # An ordinary failure is not a timeout, so the feed is tried again next time.
    assert hutbot.state._calendar_evaluation_failures == {}


@pytest.mark.asyncio
async def test_evaluations_wait_for_a_free_slot():
    calendar = _calendar(_vevent("single"))
    release = threading.Event()
    running = 0
    peak = 0
    lock = threading.Lock()

    def slow(*args, **kwargs):
        nonlocal running, peak
        with lock:
            running += 1
            peak = max(peak, running)
        release.wait(2)
        with lock:
            running -= 1
        return [None]

    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(calendar, "Feed"))), \
         patch.object(calendarfeed, "_select_events", side_effect=slow):
        lookups = [asyncio.create_task(resolve_calendar_events(CONFIG, [(NOW, 0)])) for _ in range(5)]
        await asyncio.sleep(0.2)
        release.set()
        results = await asyncio.gather(*lookups)

    assert peak == calendarfeed._CALENDAR_EVALUATION_SLOTS
    assert results == [("Feed", [None])] * 5


@pytest.mark.asyncio
async def test_the_selection_itself_still_finds_the_event():
    calendar = _calendar(_vevent("weekly", "FREQ=WEEKLY", start="20260805T083000Z"))
    with patch('hutbot.calendarfeed.fetch_calendar', new=AsyncMock(return_value=(calendar, "Feed"))):
        name, (current, upcoming) = await resolve_calendar_events(CONFIG, [(NOW, 0), (NOW, 1)])

    assert name == "Feed"
    assert current.summary == "weekly" and current.start.startswith("2026-08-19T08:30")
    assert upcoming.start.startswith("2026-08-26T08:30")
