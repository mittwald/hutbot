"""Calendar integration: read an ICS feed from a URL, resolve the current/next event.

Named `calendarfeed` rather than `calendar` so nothing in the package can shadow the
standard library's `calendar` module (the same reason `datetimefmt` is not `datetime`).

Layered like ``opsgenie``: pure parsers and selectors, a thin cached HTTP wrapper, one
aggregator, and one template-variable builder. The pure half needs no network, so most of
it is directly testable.
"""

import asyncio
import datetime
import ipaddress
import itertools
import os
import time
import urllib.parse

import aiohttp
import icalendar
import recurring_ical_events

from employee_list import log, log_error

from . import datetimefmt
from . import messaging
from . import slackcache
from . import state
from .constants import (
    CALENDAR_DATETIME_TEMPLATE_VARIABLES,
    CALENDAR_LIST_TEMPLATE_VARIABLES,
    UNKNOWN_USER_ONCALL_PLACEHOLDER,
    UNKNOWN_CALENDAR_EVENT_PLACEHOLDER,
    UNKNOWN_CALENDAR_PLACEHOLDER,
    UNKNOWN_PERIOD_PLACEHOLDER,
)
from .models import CalendarContext, CalendarEvent

# How long a fetched calendar stays usable. Matches slackcache's channel-member TTL, but
# is env-tunable because it trades freshness against a host we do not control, and
# conditions can make this path hot. Read at import; tests patch the module attribute.
_CALENDAR_TTL = float(os.environ.get('HUTBOT_CALENDAR_TTL', '300'))
# Safety valve for `find_next_event`: `after()` is a lazy generator over possibly infinite
# recurrences, so bound how many occurrences we are willing to skip. Not a time horizon —
# a calendar whose only future entry is months away is still found.
_CALENDAR_LOOKAHEAD_EVENTS = 200
# A feed that is not a calendar (an HTML sign-in page) or is absurdly large is rejected
# before it reaches the parser.
_MAX_ICS_BYTES = 5 * 1024 * 1024
_HTTP_TIMEOUT = 10
_MAX_REDIRECTS = 3


# ----- pure helpers -----


def _text(event, key: str) -> str:
    """A calendar property as a plain string.

    icalendar returns `vText`, which subclasses `str` but whose repr is `vText(b'...')`;
    without `str()` that representation leaks into logs and JSON. Missing keys are `None`.
    """
    value = event.get(key)
    return "" if value is None else str(value).strip()


def _properties(event, key: str) -> list:
    """Every occurrence of a repeatable property.

    icalendar returns a bare value for one `ATTENDEE` and a list for several, so callers
    would otherwise have to branch on the type.
    """
    value = event.get(key)
    if value is None:
        return []
    return list(value) if isinstance(value, list) else [value]


def _address(value) -> str:
    """The email address of a CAL-ADDRESS, or "" when it does not carry one.

    Real feeds put all sorts of things here: Exchange writes an X.500 distinguished name
    (`mailto:/O=EXCHANGELABS/OU=.../CN=...`) and a room mailbox can be `invalid:nomail`.
    Better empty than gibberish.
    """
    address = str(value if value is not None else "").strip()
    if address.lower().startswith("mailto:"):
        address = address[len("mailto:"):]
    return address if "@" in address and "/" not in address else ""


def _common_name(value) -> str:
    return str((getattr(value, 'params', None) or {}).get('CN') or "").strip()


def _display_name(value) -> str:
    """What to call a participant: their `CN`, else their address."""
    return _common_name(value) or _address(value)


def _participants(values: list) -> list[tuple[str, str]]:
    """`(display name, address)` per participant, dropping only the entries with neither.

    Kept as pairs so the name and address lists stay index-aligned: an attendee with a name
    but no usable address still occupies a position, with "" for the address.
    """
    pairs = []
    for value in values:
        name, email = _display_name(value), _address(value)
        if name or email:
            pairs.append((name, email))
    return pairs


def _is_organizer(attendee, organizer_email: str, organizer_name: str) -> bool:
    """Whether this attendee is the event's organizer, invited to their own event.

    Matched on the address first, and on the display name when the organizer has no usable
    address — which is exactly the case for a shared mailbox published as `invalid:nomail`.
    """
    email = _address(attendee)
    if organizer_email and email and email.casefold() == organizer_email.casefold():
        return True
    name = _display_name(attendee)
    return bool(organizer_name and name and name.casefold() == organizer_name.casefold())


def _organizer(event) -> str:
    """A human-readable organizer, or "" when there is none worth showing.

    Exchange publishes `ORGANIZER;CN="Real Name":mailto:/O=EXCHANGELABS/OU=.../CN=...`,
    where the mailto value is useless as a display value. So the `CN` parameter wins, and the
    address is only used when it actually looks like one.
    """
    value = event.get("ORGANIZER")
    return _display_name(value) if value is not None else ""


def _aware(value, timezone: datetime.tzinfo) -> datetime.datetime:
    """An aware datetime for any DTSTART/DTEND icalendar hands back.

    All-day events come back as `date`, which cannot be compared with a `datetime` at all,
    so they are anchored at midnight in the config's timezone — an all-day event means
    "that calendar day where the reader is". Floating (naive) times get the same treatment.
    """
    if isinstance(value, datetime.datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone)
    return datetime.datetime.combine(value, datetime.time.min, tzinfo=timezone)


def _is_all_day(event) -> bool:
    return not isinstance(event.start, datetime.datetime)


def _is_usable(event) -> bool:
    """False for events that are not happening.

    Only `CANCELLED` is dropped. `TENTATIVE` is kept — it is on the calendar, and
    `{{calendar_current_status}}` lets a template say so. A missing STATUS is normal in
    Outlook feeds and means confirmed.
    """
    return _text(event, "STATUS").upper() != "CANCELLED"


def _is_busy(event) -> bool:
    """Whether the event occupies the owner's time (`TRANSP` is not `TRANSPARENT`).

    A free block is still an event, so it is never filtered out — it just loses to a real
    meeting when both cover this instant (see `_current_rank`). Exposed as its own predicate
    so an "is this person available" check has it ready.
    """
    return _text(event, "TRANSP").upper() != "TRANSPARENT"


def _current_rank(event, timezone: datetime.tzinfo) -> tuple:
    """Sort key deciding which of several overlapping events is "happening now".

    A feed routinely has an all-day marker, a multi-day conference, a free/busy block and
    the actual meeting all covering this instant, so "earliest start" picks the wrong one.
    Preference order: a timed event over an all-day one, then one that occupies the owner
    over a `TRANSP:TRANSPARENT` free block, then the most recently started (the thing you
    just walked into), then the shortest — a session beats the conference containing it —
    and finally the UID so ties are stable.
    """
    start = _aware(event.start, timezone)
    end = _aware(event.end, timezone)
    return (
        1 if _is_all_day(event) else 0,
        0 if _is_busy(event) else 1,
        -start.timestamp(),
        (end - start).total_seconds(),
        _text(event, "UID"),
    )


def build_calendar_event(event, config: dict | None = None) -> CalendarEvent:
    """Convert an icalendar event into the flat, JSON-friendly shape templates see."""
    timezone = datetimefmt.get_config_timezone(config)
    all_day = _is_all_day(event)
    start = _aware(event.start, timezone)
    end = _aware(event.end, timezone)
    # An all-day DTEND is exclusive per RFC 5545 (a one-day event on the 19th ends on the
    # 20th). Overlap maths wants that, but a reader does not, so the stored end is the
    # inclusive last day. Guard against a zero-length all-day event going backwards.
    if all_day and end - start >= datetime.timedelta(days=1):
        end -= datetime.timedelta(days=1)
    attendees = _properties(event, "ATTENDEE")
    organizer_name, organizer_email = _organizer(event), _address(event.get("ORGANIZER"))
    others = [a for a in attendees if not _is_organizer(a, organizer_email, organizer_name)]
    return CalendarEvent(
        uid=_text(event, "UID"),
        summary=_text(event, "SUMMARY"),
        location=_text(event, "LOCATION"),
        description=_text(event, "DESCRIPTION"),
        organizer=organizer_name,
        organizer_email=organizer_email,
        # Positionally aligned: entry *n* of every attendee list is the same participant, so
        # `attendees(nth=2)` and `attendee_emails(nth=2)` cannot describe two different
        # people. A participant missing one of the two contributes "" there rather than
        # being skipped, which would shift everyone after them.
        attendees=[name for name, _ in _participants(attendees)],
        attendee_emails=[email for _, email in _participants(attendees)],
        other_attendees=[name for name, _ in _participants(others)],
        other_attendee_emails=[email for _, email in _participants(others)],
        status=_text(event, "STATUS").upper() or "CONFIRMED",
        start=start.isoformat(),
        end=end.isoformat(),
        all_day=all_day,
    )


def find_current_and_next_events(calendar, config: dict | None = None, now: datetime.datetime | None = None) -> tuple[CalendarEvent | None, CalendarEvent | None]:
    """The event covering `now` and the soonest one starting after it.

    Takes `now` so callers (and tests) never depend on the wall clock, like
    ``opsgenie.find_opsgenie_on_call_period``.
    """
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=datetime.timezone.utc)
    timezone = datetimefmt.get_config_timezone(config)
    # Ask in the config's timezone. The library compares a `DTSTART;VALUE=DATE` against the
    # date of the instant it is given, so querying in UTC would use the wrong calendar day
    # either side of midnight: at 01:00 on the 2nd in Tokyo a whole-day event on the 2nd is
    # still "tomorrow" in UTC, and in Los Angeles it turns current before local midnight.
    local_now = now.astimezone(timezone)

    try:
        # Malformed RRULEs are common in real Outlook feeds; without skip_bad_series a
        # single broken series would take the whole calendar down with it.
        query = recurring_ical_events.of(calendar, skip_bad_series=True)
    except Exception as e:
        log_error("Failed to index calendar events:", e)
        return None, None

    current = None
    try:
        candidates = [event for event in query.at(local_now) if _is_usable(event)]
        candidates.sort(key=lambda event: _current_rank(event, timezone))
        if candidates:
            current = build_calendar_event(candidates[0], config)
    except Exception as e:
        log_error("Failed to resolve the current calendar event:", e)

    next_event = None
    try:
        # `after()` deliberately yields events that are *ongoing* at `now` before future
        # ones, so the start filter is what keeps "next" from echoing "current".
        for event in itertools.islice(query.after(local_now), _CALENDAR_LOOKAHEAD_EVENTS):
            if _aware(event.start, timezone) > now and _is_usable(event):
                next_event = build_calendar_event(event, config)
                break
    except Exception as e:
        log_error("Failed to resolve the next calendar event:", e)

    return current, next_event


# ----- URL validation and display -----


def _is_forbidden_address(address: ipaddress._BaseAddress) -> bool:
    """Whether an address is one the bot must not be talked into reaching."""
    return bool(address.is_private or address.is_loopback or address.is_link_local
                or address.is_reserved or address.is_multicast or address.is_unspecified)


async def _resolve_public_host(host: str) -> str:
    """The host's addresses, or a reason it must not be fetched.

    `validate_calendar_url` can only judge the text of a URL. A public name that resolves to
    `10.0.0.1`, or to the cloud metadata address, reaches the internal target all the same —
    so the addresses behind the name are checked too, at every redirect hop.

    This narrows the window rather than closing it: the name is resolved again by the
    connector, so a record that changes between the two lookups (DNS rebinding) is still
    possible. The NetworkPolicy egress allow-list is the control that actually closes it.
    """
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None)
    except Exception as e:
        return f"could not resolve `{host}`: {e}"
    for info in infos:
        raw = info[4][0]
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if _is_forbidden_address(address):
            return f"`{host}` resolves to the internal address {raw}"
    return ""


def _is_loopback_host(host: str) -> bool:
    """Whether a host can only ever mean this machine.

    RFC 6761 reserves `localhost` and everything under `.localhost` for loopback, and the
    loopback ranges (`127.0.0.0/8`, `::1`) speak for themselves.
    """
    host = (host or "").lower()
    if host in ("localhost", "localhost.localdomain") or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_calendar_url(url: str) -> str:
    """Return a usable feed URL, or raise ``ValueError`` explaining why it is not.

    The bot fetches this URL on a user's word, from inside the cluster in production, so a
    remote feed has to be https and the addresses that make SSRF worth attempting — the
    private ranges and the cloud metadata endpoint — are refused. The NetworkPolicy egress
    allow-list is the real control; this is the readable first line of defence.

    Loopback is the exception, over http as well: serving a feed from a local file server is
    how this gets developed, and `127.0.0.1` is not a target worth reaching through the bot
    that anyone who can set a config could not already reach directly.
    """
    url = (url or "").strip()
    if not url:
        raise ValueError("calendar URL must be non-empty")
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError as e:
        raise ValueError(f"calendar URL could not be parsed: {e}")
    if not parts.hostname:
        raise ValueError("calendar URL has no host")

    scheme = parts.scheme.lower()
    loopback = _is_loopback_host(parts.hostname)
    if scheme not in ("https", "http"):
        raise ValueError("calendar URL must start with `https://`")
    if scheme == "http" and not loopback:
        raise ValueError("calendar URL must start with `https://` (plain `http://` is only allowed for localhost)")
    if parts.username or parts.password:
        raise ValueError("calendar URL must not embed credentials")

    if not loopback:
        try:
            address = ipaddress.ip_address(parts.hostname)
        except ValueError:
            address = None
        if address is not None and _is_forbidden_address(address):
            raise ValueError("calendar URL must not point at an internal address")
    return url


def describe_calendar_url(url: str) -> str:
    """A safe-to-echo form of the feed URL.

    A published-calendar link needs no credentials, so possession of it *is* access. It is
    stored per config and anyone in the channel can run `show config`, so only the host and
    the last path segment are ever printed back.
    """
    url = (url or "").strip()
    if not url:
        return ""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return "<unprintable URL>"
    host = parts.hostname or ""
    tail = parts.path.rsplit("/", 1)[-1] if parts.path else ""
    if not host:
        return "<unprintable URL>"
    return f"{host}/…/{tail}" if tail else f"{host}/…"


# ----- fetching -----


async def _read_capped(response) -> str | None:
    """The response body, or ``None`` when it runs past ``_MAX_ICS_BYTES``.

    Read in chunks rather than with `response.text()`, which would pull the whole body into
    memory before any size check: a feed can omit `Content-Length`, use chunked transfer, or
    be a compression bomb. `response.content` yields *decompressed* bytes, so the cap counts
    what a gzip bomb actually expands to.
    """
    chunks, total = [], 0
    async for chunk in response.content.iter_chunked(64 * 1024):
        total += len(chunk)
        if total > _MAX_ICS_BYTES:
            return None
        chunks.append(chunk)
    body = b"".join(chunks)
    try:
        return body.decode(response.get_encoding(), errors="replace")
    except (LookupError, RuntimeError):
        return body.decode("utf-8", errors="replace")


async def _get_calendar_document(url: str) -> str | None:
    """Fetch the feed, checking every hop, or return ``None`` with the reason logged.

    Redirects are followed by hand so each target is validated before it is requested —
    aiohttp would otherwise follow a public HTTPS URL to `http://169.254.169.254` without
    another word.
    """
    timeout = aiohttp.ClientTimeout(total=_HTTP_TIMEOUT)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        for _ in range(_MAX_REDIRECTS + 1):
            try:
                url = validate_calendar_url(url)
            except ValueError as e:
                log_error(f"Refusing to fetch the calendar feed {describe_calendar_url(url)}: {e}.")
                return None
            host = urllib.parse.urlsplit(url).hostname or ""
            if not _is_loopback_host(host):
                problem = await _resolve_public_host(host)
                if problem:
                    log_error(f"Refusing to fetch the calendar feed {describe_calendar_url(url)}: {problem}.")
                    return None

            async with session.get(url, allow_redirects=False) as response:
                if response.status in (301, 302, 303, 307, 308):
                    location = response.headers.get("Location", "")
                    if not location:
                        log_error(f"Calendar feed {describe_calendar_url(url)} redirected without a target.")
                        return None
                    url = urllib.parse.urljoin(url, location)
                    continue
                if response.status != 200:
                    log_error(f"Failed to fetch the calendar feed {describe_calendar_url(url)}: {response.status}")
                    return None
                if response.content_length and response.content_length > _MAX_ICS_BYTES:
                    log_error(f"Calendar feed {describe_calendar_url(url)} is too large ({response.content_length} bytes).")
                    return None
                text = await _read_capped(response)
                if text is None:
                    log_error(f"Calendar feed {describe_calendar_url(url)} is larger than {_MAX_ICS_BYTES} bytes.")
                return text

    log_error(f"Calendar feed {describe_calendar_url(url)} redirected more than {_MAX_REDIRECTS} times.")
    return None


async def fetch_calendar(url: str) -> tuple[object | None, str]:
    """Fetch and parse a feed, returning ``(calendar, display_name)``.

    Never raises: a failure logs and returns ``(None, "")`` so a broken feed degrades a
    rule instead of taking down the event loop, matching the OpsGenie helpers.
    Successful parses are cached per URL for ``_CALENDAR_TTL`` seconds.
    """
    url = (url or "").strip()
    if not url:
        return None, ""

    cached = state._calendar_cache.get(url)
    if cached and (time.monotonic() - cached[0]) < _CALENDAR_TTL:
        return cached[1], cached[2]

    try:
        text = await _get_calendar_document(url)
    except Exception as e:
        log_error(f"Failed to fetch the calendar feed {describe_calendar_url(url)}:", e)
        return None, ""
    if text is None:
        return None, ""

    if "BEGIN:VCALENDAR" not in text:
        # Usually an HTML sign-in page: say so instead of reporting an empty calendar.
        log_error(f"Calendar feed {describe_calendar_url(url)} did not return an iCalendar document.")
        return None, ""

    try:
        # Parsing a real feed takes tens of milliseconds, which is long enough to be worth
        # keeping off the event loop while Slack events are queueing.
        calendar = await asyncio.to_thread(icalendar.Calendar.from_ical, text)
    except Exception as e:
        log_error(f"Failed to parse the calendar feed {describe_calendar_url(url)}:", e)
        return None, ""

    name = ""
    try:
        name = str(calendar.get("X-WR-CALNAME") or "").strip()
    except Exception:
        name = ""

    state._calendar_cache[url] = (time.monotonic(), calendar, name)
    return calendar, name


async def resolve_calendar_context(config: dict, now: datetime.datetime | None = None) -> CalendarContext:
    """The configured feed's name plus its current and next event."""
    url = (config or {}).get('calendar_url', '').strip()
    if not url:
        return CalendarContext("", None, None)
    calendar, name = await fetch_calendar(url)
    if calendar is None:
        return CalendarContext("", None, None)
    current, next_event = find_current_and_next_events(calendar, config, now)
    return CalendarContext(name, current, next_event)


# ----- template variables -----


def get_calendar_placeholder_variables(config: dict | None = None) -> dict[str, str]:
    """Every calendar variable, filled with placeholders.

    Mirrors ``opsgenie.get_opsgenie_placeholder_variables``: a template referencing a
    calendar variable renders a visible placeholder rather than an empty string when
    there is no feed, no event, or a failed fetch.
    """
    url = (config or {}).get('calendar_url', '').strip()
    variables = {
        "calendar_name": describe_calendar_url(url) or UNKNOWN_CALENDAR_PLACEHOLDER,
    }
    for prefix in ("current", "next"):
        for field in ("summary", "location", "description", "organizer", "organizer_email",
                      "attendee_count", "uid", "status"):
            variables[f"calendar_{prefix}_{field}"] = UNKNOWN_CALENDAR_EVENT_PLACEHOLDER
        # Same placeholder OpsGenie uses for an unmapped person, so `empty` works on it.
        variables[f"calendar_{prefix}_organizer_user"] = UNKNOWN_USER_ONCALL_PLACEHOLDER
    for variable in CALENDAR_LIST_TEMPLATE_VARIABLES:
        variables[variable] = UNKNOWN_CALENDAR_EVENT_PLACEHOLDER
        # The items a condition matches against, beside the joined form a message renders.
        variables[f"__{variable}_items"] = []
    for variable in CALENDAR_DATETIME_TEMPLATE_VARIABLES:
        variables[variable] = UNKNOWN_PERIOD_PLACEHOLDER
        variables[f"__{variable}_raw"] = ""
    return variables


def _set_list_variable(variables: dict, variable: str, items: list) -> None:
    """Store a list variable: the aligned entries, plus the joined form a message renders.

    The joined form leaves out the blanks — a reader wants "Nico Engelbrecht", not a stray
    comma for the room mailbox that has no address — while the entries keep them so `nth`
    lines up across the parallel lists.
    """
    variables[f"__{variable}_items"] = list(items)
    variables[variable] = ", ".join(item for item in items if item)


def fill_calendar_event_variables(variables: dict[str, str], config: dict | None, prefix: str, event: CalendarEvent | None) -> None:
    """Overwrite one period's placeholders from a resolved event."""
    if event is None:
        return
    variables[f"calendar_{prefix}_summary"] = event.summary
    variables[f"calendar_{prefix}_location"] = event.location
    variables[f"calendar_{prefix}_description"] = event.description
    variables[f"calendar_{prefix}_organizer"] = event.organizer
    variables[f"calendar_{prefix}_organizer_email"] = event.organizer_email
    variables[f"calendar_{prefix}_uid"] = event.uid
    variables[f"calendar_{prefix}_status"] = event.status
    variables[f"calendar_{prefix}_attendee_count"] = str(len(event.attendees))
    for field, items in (("attendees", event.attendees),
                         ("attendee_emails", event.attendee_emails),
                         ("other_attendees", event.other_attendees),
                         ("other_attendee_emails", event.other_attendee_emails)):
        _set_list_variable(variables, f"calendar_{prefix}_{field}", items)

    for bound, value in (("start", event.start), ("end", event.end)):
        for part in ("date", "time", "datetime"):
            variable = f"calendar_{prefix}_{bound}_{part}"
            variables[f"__{variable}_raw"] = value or ""
            variables[variable] = datetimefmt.format_template_datetime(value, variable, config)


async def _mention(app, email: str) -> str:
    """`<@U…>` for an address, or "" when it maps to no Slack user."""
    # `is None` rather than a truth test: an app object should never be asked for its
    # truthiness (on an AsyncMock that even orphans a coroutine).
    if app is None or not email:
        return ""
    try:
        user = await slackcache.get_user_by_email(app, email)
    except Exception as e:
        log_error(f"Failed to map the calendar address '{email}' to a Slack user:", e)
        return ""
    return f"<@{user.id}>" if user and user.id else ""


async def _mentions(app, emails: list) -> list[str]:
    """One entry per address, "" where it maps to no Slack user.

    Aligned rather than compacted so `attendees(nth=2)` and `attendee_users(nth=2)` stay the
    same participant; the joined form a message renders drops the blanks.
    """
    return [await _mention(app, email) for email in emails or []]


async def fill_calendar_user_variables(app, variables: dict, prefix: str, event: CalendarEvent | None) -> None:
    """Map the event's addresses to Slack users, for @mentions and DM targets."""
    if event is None:
        return
    organizer = await _mention(app, event.organizer_email)
    if organizer:
        variables[f"calendar_{prefix}_organizer_user"] = organizer
    for field, emails in (("attendee_users", event.attendee_emails),
                          ("other_attendee_users", event.other_attendee_emails)):
        _set_list_variable(variables, f"calendar_{prefix}_{field}", await _mentions(app, emails))


async def get_calendar_template_variables(app, config: dict, now: datetime.datetime | None = None) -> dict[str, str]:
    """The `{{calendar_*}}` values for one config.

    `app` is only used to map attendee addresses to Slack users; pass ``None`` to skip that.
    """
    variables = get_calendar_placeholder_variables(config)
    url = (config or {}).get('calendar_url', '').strip()
    if not url:
        return variables

    context = await resolve_calendar_context(config, now)
    if context.name:
        variables["calendar_name"] = context.name
    for prefix, event in (("current", context.current), ("next", context.next)):
        fill_calendar_event_variables(variables, config, prefix, event)
        await fill_calendar_user_variables(app, variables, prefix, event)
    return variables


# ----- the read command -----


def _describe_event(config: dict, label: str, event: CalendarEvent | None) -> str:
    if event is None:
        return f"*{label}*: _none_"
    lines = [f"*{label}*: {event.summary or UNKNOWN_CALENDAR_EVENT_PLACEHOLDER}"]
    if event.location:
        lines.append(f"*Location*: {event.location}")
    if event.organizer:
        organizer = event.organizer
        # Only worth printing the address when it says something the name does not.
        if event.organizer_email and event.organizer_email != organizer:
            organizer += f" ({event.organizer_email})"
        lines.append(f"*Organizer*: {organizer}")
    attendees = event.other_attendees or event.other_attendee_emails or event.attendees or event.attendee_emails
    if attendees:
        lines.append(f"*Attendees*: {', '.join(attendees)}")
    part = "date" if event.all_day else "datetime"
    lines.append(f"*Start*: `{datetimefmt.format_datetime_value(event.start, part, config)}`")
    lines.append(f"*End*: `{datetimefmt.format_datetime_value(event.end, part, config)}`")
    if event.status and event.status != "CONFIRMED":
        lines.append(f"*Status*: `{event.status}`")
    return "\n".join(lines)


async def send_current_calendar_event(app, channel, config_name: str, user, thread_ts: str = "") -> None:
    """`show calendar` — print the event running now and the next one."""
    config = channel.configs.get(config_name) or {}
    url = (config.get('calendar_url') or '').strip()
    if not url:
        await messaging.send_message(app, channel, user, f"No calendar configured. Use `{state.slash_command} [config] set calendar <url>`.", thread_ts)
        return

    context = await resolve_calendar_context(config)
    if context.current is None and context.next is None:
        await messaging.send_message(app, channel, user, f"No current or upcoming events in the calendar `{describe_calendar_url(url)}`.", thread_ts)
        return

    header = f"*Calendar*: `{context.name or describe_calendar_url(url)}`"
    message = "\n\n".join([
        header,
        _describe_event(config, "Now", context.current),
        _describe_event(config, "Next", context.next),
    ])
    log(f"Reporting calendar events for config '{config_name}' in #{channel.name}.")
    await messaging.send_message(app, channel, user, message, thread_ts)
