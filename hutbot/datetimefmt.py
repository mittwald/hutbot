"""Date/time parsing, formatting, locale handling, and work-hours helpers."""

import locale as locale_module
import os
import re
import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from employee_list import log_error, log_warning

from . import state
from .constants import (
    DEFAULT_DATE_FORMAT,
    DEFAULT_TIME_FORMAT,
    TIME_HOUR_PATTERN,
    UNKNOWN_PERIOD_PLACEHOLDER,
)


def parse_time(time_str) -> datetime.time | None:
    if TIME_HOUR_PATTERN.match(time_str):
        time_str = f"{time_str}:00"

    time = None
    try:
        time = datetime.datetime.strptime(time_str, "%H:%M").time()
    except ValueError:
        pass

    return time


def is_work_day(config: dict | None = None) -> bool:
    # Work days are counted in the config's timezone, so a rule set to
    # Asia/Tokyo rolls over to the next day when Tokyo does, not when the
    # server does.
    today = datetime.datetime.now(get_config_timezone(config)).date()
    # TODO: add holidays
    return today.weekday() < 5


def is_work_time(start_time_str: str, end_time_str: str, config: dict | None = None) -> bool:
    # Work hours are wall-clock times in the config's timezone; without one they
    # fall back to the server's, which is what this did before timezones existed.
    now = datetime.datetime.now(get_config_timezone(config))
    start = parse_time(start_time_str)
    end = parse_time(end_time_str)
    if not start or not end:
        log_error(f"Invalid time format {start_time_str} - {end_time_str}")
        return True
    start_today = datetime.datetime.combine(now.date(), start, tzinfo=now.tzinfo)
    end_today = datetime.datetime.combine(now.date(), end, tzinfo=now.tzinfo)
    return start_today < now < end_today


def normalize_locale_name(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("locale must be non-empty")
    match = re.fullmatch(r"([A-Za-z]{2,3})(?:[-_]([A-Za-z]{2}|\d{3}))?", value)
    if not match:
        raise ValueError("locale must look like `en`, `en-US`, or `de_DE`")

    language = match.group(1).lower()
    region = match.group(2)
    if not region:
        return language
    return f"{language}_{region.upper()}"


def validate_timezone_name(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("timezone must be non-empty")
    try:
        ZoneInfo(value)
    except ZoneInfoNotFoundError:
        raise ValueError(f"unknown timezone `{value}`")
    return value


def get_local_timezone() -> datetime.tzinfo:
    """The server's timezone, transition-aware where possible.

    `astimezone().tzinfo` is only the offset in force *right now* (a fixed `CEST` +02:00),
    so formatting a January instant with it while the process runs in August would be an
    hour late. Resolving the IANA name to a ZoneInfo keeps the DST rules; the fixed offset
    remains the fallback for a host that exposes no zone name.
    """
    name = get_local_timezone_name()
    if name:
        try:
            return ZoneInfo(name)
        except (ZoneInfoNotFoundError, ValueError):
            pass
    return datetime.datetime.now().astimezone().tzinfo or datetime.timezone.utc


def get_local_timezone_name() -> str:
    """Best-effort zone name of the server, e.g. ``Europe/Berlin`` or ``Etc/UTC``.

    Python only exposes the current abbreviation ("CEST"), so the IANA name is
    read from the places the host keeps it. Falls back to the abbreviation when
    none of them is available.
    """
    tz_env = os.environ.get("TZ", "").strip()
    if tz_env:
        return tz_env
    try:
        with open("/etc/timezone", encoding="utf-8") as f:
            name = f.read().strip()
        if name:
            return name
    except OSError:
        pass
    try:
        target = os.path.realpath("/etc/localtime")
    except OSError:
        target = ""
    marker = "/zoneinfo/"
    if marker in target:
        return target.split(marker, 1)[1]
    return datetime.datetime.now().astimezone().tzname() or "UTC"


def describe_timezone(timezone_name: str = "") -> str:
    """``Europe/Berlin (CEST, UTC+02:00)`` — the zone plus its offset right now.

    An empty ``timezone_name`` describes the server's own timezone and says so.
    """
    if timezone_name:
        try:
            tz = ZoneInfo(validate_timezone_name(timezone_name))
        except ValueError:
            return f"{timezone_name} (unknown timezone)"
        name = timezone_name
    else:
        tz = get_local_timezone()
        name = get_local_timezone_name()

    now = datetime.datetime.now(tz)
    abbreviation = now.tzname() or ""
    offset = now.strftime("%z")
    details = []
    # "Etc/UTC (UTC, UTC+00:00)" says the same thing three times; keep the
    # abbreviation only when the zone name does not already carry it.
    if abbreviation and not name.split("/")[-1].startswith(abbreviation):
        details.append(abbreviation)
    details.append(f"UTC{offset[:3]}:{offset[3:]}" if offset else "UTC+00:00")
    if not timezone_name:
        details.append("server local time")
    return f"{name} ({', '.join(details)})"


def get_server_locale_name() -> str:
    """The server's own locale as ``de_DE``, or empty when it has none set.

    Only informational: the bot never applies it — date/time names come from
    :data:`LOCALIZED_DATE_NAMES` and only when a config sets a locale.
    """
    candidates = list(locale_module.getlocale(locale_module.LC_TIME) or ())
    candidates.append(os.environ.get("LC_ALL", ""))
    candidates.append(os.environ.get("LC_TIME", ""))
    candidates.append(os.environ.get("LANG", ""))
    for candidate in candidates:
        candidate = (candidate or "").split(".", 1)[0].strip()
        if not candidate or candidate in ("C", "POSIX"):
            continue
        try:
            return normalize_locale_name(candidate)
        except ValueError:
            continue
    return ""


def get_config_timezone(config: dict | None, timezone_name: str = "", local_tz: datetime.tzinfo | None = None) -> datetime.tzinfo:
    if local_tz is not None:
        return local_tz

    configured_timezone = timezone_name or (config or {}).get("datetime_timezone", "")
    if configured_timezone:
        try:
            return ZoneInfo(validate_timezone_name(configured_timezone))
        except ValueError as e:
            log_warning("Ignoring invalid datetime timezone in configuration:", e)

    return get_local_timezone()


def get_config_locale(config: dict | None, locale_name: str = "") -> str:
    configured_locale = locale_name or (config or {}).get("datetime_locale", "")
    if not configured_locale:
        # Instance-wide fallback (HUTBOT_DEFAULT_DATETIME_LOCALE), empty unless set.
        return state.default_datetime_locale
    try:
        return normalize_locale_name(configured_locale)
    except ValueError as e:
        log_warning("Ignoring invalid datetime locale in configuration:", e)
        return state.default_datetime_locale


def resolve_default_locale(value: str) -> str:
    """Normalize the instance-wide default locale, warning about a bad value."""
    value = (value or "").strip()
    if not value:
        return ""
    try:
        return normalize_locale_name(value)
    except ValueError as e:
        log_error("Ignoring invalid HUTBOT_DEFAULT_DATETIME_LOCALE:", e)
        return ""


GO_LAYOUT_TOKENS = [
    ("Monday", "%A"),
    ("January", "%B"),
    ("Mon", "%a"),
    ("Jan", "%b"),
    ("2006", "%Y"),
    ("Z07:00", "%z"),
    ("Z0700", "%z"),
    ("-07:00", "%z"),
    ("-0700", "%z"),
    ("15", "%H"),
    ("03", "%I"),
    ("04", "%M"),
    ("05", "%S"),
    ("02", "%d"),
    ("01", "%m"),
    ("06", "%y"),
    ("PM", "%p"),
    ("pm", "%p"),
    ("MST", "%Z"),
]


def go_layout_to_strftime(layout: str) -> str:
    converted = []
    i = 0
    while i < len(layout):
        for token, directive in GO_LAYOUT_TOKENS:
            if layout.startswith(token, i):
                converted.append(directive)
                i += len(token)
                break
        else:
            converted.append(layout[i])
            i += 1
    return "".join(converted)


LOCALIZED_DATE_NAMES = {
    "de": {
        "Monday": "Montag",
        "Tuesday": "Dienstag",
        "Wednesday": "Mittwoch",
        "Thursday": "Donnerstag",
        "Friday": "Freitag",
        "Saturday": "Samstag",
        "Sunday": "Sonntag",
        "Mon": "Mo",
        "Tue": "Di",
        "Wed": "Mi",
        "Thu": "Do",
        "Fri": "Fr",
        "Sat": "Sa",
        "Sun": "So",
        "January": "Januar",
        "February": "Februar",
        "March": "Maerz",
        "April": "April",
        "May": "Mai",
        "June": "Juni",
        "July": "Juli",
        "August": "August",
        "September": "September",
        "October": "Oktober",
        "November": "November",
        "December": "Dezember",
        "Jan": "Jan",
        "Feb": "Feb",
        "Mar": "Mrz",
        "Apr": "Apr",
        "Jun": "Jun",
        "Jul": "Jul",
        "Aug": "Aug",
        "Sep": "Sep",
        "Oct": "Okt",
        "Nov": "Nov",
        "Dec": "Dez",
    }
}


def localize_formatted_datetime(value: str, locale_name: str) -> str:
    if not locale_name:
        return value

    language = locale_name.split("_", 1)[0].lower()
    replacements = LOCALIZED_DATE_NAMES.get(language)
    if not replacements:
        return value

    for source in sorted(replacements, key=len, reverse=True):
        value = re.sub(rf"\b{re.escape(source)}\b", replacements[source], value)
    return value


def describe_locale(locale_name: str = "") -> str:
    """What day/month names a config actually gets, and why.

    Takes the config's own locale; empty falls back to the instance default
    (HUTBOT_DEFAULT_DATETIME_LOCALE) and, failing that, to English. The server's
    own locale is never applied and is only named for orientation. A locale
    without a translation table (only `de` has one) also ends up English.
    """
    notes = []
    if locale_name:
        try:
            effective = normalize_locale_name(locale_name)
        except ValueError:
            return f"{locale_name} (invalid locale, English names)"
    elif state.default_datetime_locale:
        effective = state.default_datetime_locale
        notes.append("instance default")
    else:
        server_locale = get_server_locale_name()
        if server_locale:
            return f"English names (server locale {server_locale} not applied)"
        return "English names (no server locale set)"

    if effective.split("_", 1)[0].lower() not in LOCALIZED_DATE_NAMES:
        notes.append("no translations, English names")
    return f"{effective} ({', '.join(notes)})" if notes else effective


def parse_opsgenie_datetime(value: str) -> datetime.datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed


def parse_slack_timestamp(value: str) -> datetime.datetime | None:
    """Slack message timestamps are epoch seconds, e.g. "1786453297.645799"."""
    if not value:
        return None
    try:
        return datetime.datetime.fromtimestamp(float(value), datetime.timezone.utc)
    except (TypeError, ValueError, OSError, OverflowError):
        return None


# ----- the `at` template argument -----

# Only the spellings the help text names. Bare `fromisoformat` would also swallow `20260827`,
# `2026-W35-4` and `2026-08-27T09`; nobody means any of those, so the shape is fixed here and
# only the field values are left to the stdlib.
AT_ABSOLUTE_PATTERN = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2})"
    r"(?:[Tt ]\s?(?P<time>\d{2}:\d{2}(?::\d{2})?)"
    r"\s?(?P<offset>[Zz]|[+-]\d{2}:?\d{2})?)?")
AT_OFFSET_PATTERN = re.compile(r"(?P<sign>[+-])(?P<count>\d{1,6})\s?(?P<unit>[A-Za-z]+)")
# `2h` is the likeliest slip, so it gets its own message rather than the generic shape error.
AT_UNSIGNED_OFFSET_PATTERN = re.compile(r"\d{1,6}\s?[A-Za-z]+")
AT_TIME_OF_DAY_PATTERN = re.compile(r"\d{1,2}(?::\d{2})?")
AT_OFFSET_UNITS = {
    "m": "m", "min": "m", "mins": "m", "minute": "m", "minutes": "m",
    "h": "h", "hr": "h", "hrs": "h", "hour": "h", "hours": "h",
    "d": "d", "day": "d", "days": "d",
    "w": "w", "week": "w", "weeks": "w",
}
AT_OFFSET_MINUTES = {"m": 1, "h": 60, "d": 1440, "w": 10080}
# Clock-free and zone-free bounds, so a template that validates today validates forever. Wide
# enough to refuse nothing anyone means, tight enough that the ICS query is never asked to
# expand centuries of recurrences.
AT_MIN_YEAR, AT_MAX_YEAR = 1970, 2100
AT_MAX_OFFSET_MINUTES = 3653 * 1440


def _at_shape_error(value: str, text: str) -> str:
    """The shape message, with a nudge for the two near-misses people actually type."""
    if AT_UNSIGNED_OFFSET_PATTERN.fullmatch(text):
        return f"`at` offsets need a sign, so write `+{text}` or `-{text}`, not `{value}`"
    return ("`at` must look like `2026-08-27 09:00`, `2026-08-27`, `09:00`, "
            f"or an offset such as `+2h`, not `{value}`")


def _parse_at_value(value: str) -> tuple[str, object]:
    """What kind of `at=` expression this is and its parts, or a ``ValueError`` saying why not.

    ``("absolute", datetime)`` — naive when the text carried no offset, aware when it did —
    ``("time", time)`` for a bare time of day, or ``("offset", (unit, count))``. Deliberately
    clock-free and zone-free, so `templating.validate_template_expressions` can judge a value
    at set time, where there is neither a config nor a meaningful "now".
    """
    text = " ".join((value or "").split())
    if not text:
        raise ValueError("`at` must be non-empty")
    # A slice key is built from this text, and those characters are what keep the encoding
    # unambiguous (see `constants.event_slice_name`). No legal spelling needs them.
    if any(character in text for character in "();"):
        raise ValueError(f"`at` must not contain `(`, `)` or `;`, so `{value}` cannot be used")

    match = AT_ABSOLUTE_PATTERN.fullmatch(text)
    if match:
        offset = (match.group("offset") or "").upper()
        # Canonicalized before `fromisoformat` because the pattern is deliberately kinder than
        # it is: a space separator, a lower-case `t` and a lower-case `z` are all things people
        # type, and only the first two would survive untouched.
        canonical = f"{match.group('date')}T{match.group('time') or '00:00'}"
        canonical += "+00:00" if offset == "Z" else offset
        try:
            parsed = datetime.datetime.fromisoformat(canonical)
        except ValueError:
            raise ValueError(f"`at` must be a real date and time, not `{value}`")
        if not AT_MIN_YEAR <= parsed.year <= AT_MAX_YEAR:
            raise ValueError(f"`at` must name a year between {AT_MIN_YEAR} and {AT_MAX_YEAR}, not `{value}`")
        return "absolute", parsed

    match = AT_OFFSET_PATTERN.fullmatch(text)
    if match:
        unit = AT_OFFSET_UNITS.get(match.group("unit").lower())
        if not unit:
            raise ValueError("`at` offsets are counted in `m`, `h`, `d` or `w`, "
                             f"not `{match.group('unit')}`")
        count = int(match.group("count")) * (-1 if match.group("sign") == "-" else 1)
        if abs(count) * AT_OFFSET_MINUTES[unit] > AT_MAX_OFFSET_MINUTES:
            raise ValueError(f"`at` must stay within 10 years of now, not `{value}`")
        return "offset", (unit, count)

    if AT_TIME_OF_DAY_PATTERN.fullmatch(text):
        # The `set work-hours` spelling: `9` and `09:00` both mean today at that hour.
        parsed_time = parse_time(text)
        if parsed_time is None:
            raise ValueError(f"`at` must be a real date and time, not `{value}`")
        return "time", parsed_time

    raise ValueError(_at_shape_error(value, text))


def validate_at_time(value: str) -> str:
    """The canonical form of an `at=` value, or a ``ValueError`` explaining why it is not one.

    Shaped like `validate_timezone_name` so a caller can report `str(e)` unchanged. What it
    cannot judge without a clock and a config: whether the instant exists in the config's
    timezone (a skipped or repeated hour needs the zone), whether it is in the past, and
    whether the calendar reaches that far.
    """
    _parse_at_value(value)
    return " ".join((value or "").split())


def resolve_at_time(
    value: str,
    config: dict | None = None,
    now: datetime.datetime | None = None,
    local_tz: datetime.tzinfo | None = None,
) -> datetime.datetime | None:
    """The instant an `at=` expression names, aware and in the config's timezone.

    In the config's timezone because that is what the calendar query needs: the ICS library
    anchors an all-day `DATE` in the tzinfo of the instant it is handed, so a naive or UTC
    instant picks the wrong calendar day either side of midnight (see
    `calendarfeed.select_event`). A value carrying no offset is therefore a wall clock *here*,
    which is the one place this deliberately disagrees with `parse_opsgenie_datetime`: that one
    reads machine-generated OpsGenie values, documented UTC, while this one is typed by a
    person who means their own clock.

    `now` is a parameter rather than a call to the clock, so one render resolves every `at` in
    a message — and the default selection — against a single instant. Returns ``None`` for a
    value that does not parse; callers must **not** fall back to "now", because silently
    answering about the present when someone named a time is the worst thing this can do.
    """
    timezone = get_config_timezone(config, "", local_tz)
    try:
        kind, parts = _parse_at_value(value)
    except ValueError:
        return None

    if now is None:
        now = datetime.datetime.now(timezone)
    elif now.tzinfo is None:
        # Same convention as the calendar selection: a naive instant is UTC.
        now = now.replace(tzinfo=datetime.timezone.utc)
    try:
        anchor = now.astimezone(timezone)
    except (OverflowError, ValueError, OSError):
        # An instant so far out that moving it into the config's zone leaves the range
        # `datetime` can hold. No instant to report, and nothing to fall back to.
        return None

    if kind == "absolute":
        # An hour the clock skipped resolves to the instant it would have been; an hour that
        # happens twice takes `fold=0`, the earlier pass, which is what "02:30" means to a
        # reader.
        return parts.replace(tzinfo=timezone) if parts.tzinfo is None else parts.astimezone(timezone)
    if kind == "time":
        return datetime.datetime.combine(anchor.date(), parts, tzinfo=timezone)

    unit, count = parts
    try:
        if unit in ("m", "h"):
            # Minutes and hours are elapsed time, so they are added to the *instant*: `+2h`
            # over a spring-forward is two real hours, 01:30+01:00 -> 04:30+02:00.
            delta = datetime.timedelta(minutes=count) if unit == "m" else datetime.timedelta(hours=count)
            return (anchor.astimezone(datetime.timezone.utc) + delta).astimezone(timezone)
        # Days and weeks are wall clock: `+1d` is this time tomorrow. Aware arithmetic with one
        # tzinfo already works in local wall time, so both the hour and the calendar day survive
        # a transition -- where `+24h` from 23:30 would land on the day *after* the one meant.
        return anchor + datetime.timedelta(days=count * (7 if unit == "w" else 1))
    except (OverflowError, ValueError):
        return None


def format_datetime_value(
    value: str,
    part: str = "datetime",
    config: dict | None = None,
    args: dict[str, str] | None = None,
    local_tz: datetime.tzinfo | None = None,
) -> str:
    parsed = parse_opsgenie_datetime(value)
    if not parsed:
        return UNKNOWN_PERIOD_PLACEHOLDER
    return render_datetime(parsed, part, config, args, local_tz)


def render_datetime(
    parsed: datetime.datetime,
    part: str = "datetime",
    config: dict | None = None,
    args: dict[str, str] | None = None,
    local_tz: datetime.tzinfo | None = None,
) -> str:
    """Format an instant with the config's date/time format, timezone, and locale."""
    args = args or {}
    timezone = get_config_timezone(config, args.get("tz", ""), local_tz)
    local_time = parsed.astimezone(timezone)

    date_format = (config or {}).get("date_format") or DEFAULT_DATE_FORMAT
    time_format = (config or {}).get("time_format") or DEFAULT_TIME_FORMAT
    default_format = {
        "date": date_format,
        "time": time_format,
        "datetime": f"{date_format} {time_format}",
    }.get(part, f"{date_format} {time_format}")

    fmt = args.get("fmt") or default_format
    if "%" not in fmt:
        fmt = go_layout_to_strftime(fmt)

    locale_name = get_config_locale(config, args.get("lc", ""))
    return localize_formatted_datetime(local_time.strftime(fmt), locale_name)


def format_timestamp_value(value: str, part: str = "datetime", config: dict | None = None, args: dict[str, str] | None = None) -> str:
    """Render a Slack message timestamp for `{{date}}` / `{{time}}` / `{{datetime}}`.

    An `at=` argument moves the instant: `{{date(at="+2w")}}` is two weeks from the one the
    plain variable reports, and `{{date(at="2026-09-01")}}` is that day whatever fired the
    rule. It is anchored on the message's timestamp rather than the clock so every variable in
    one message describes one moment -- and so a `+1d` in a reply sent from a queue is a day
    after the message it answers, not a day after the send.
    """
    args = args or {}
    parsed = parse_slack_timestamp(value)
    at = args.get("at", "")
    if at:
        # `None` for an `at` that does not parse or lands outside `datetime`'s range. Rendering
        # "now" instead would answer about the present when someone named another moment, so
        # this reports the same placeholder an unresolved date/time variable does. A missing
        # timestamp leaves the anchor to `resolve_at_time`, which reads the clock -- an absolute
        # `at` then still renders, and a relative one still means what it says.
        moved = resolve_at_time(at, config, now=parsed)
        if moved is None:
            return UNKNOWN_PERIOD_PLACEHOLDER
        return render_datetime(moved, part, config, args)
    if not parsed:
        return ""
    return render_datetime(parsed, part, config, args)


def format_template_datetime(value: str, variable: str, config: dict | None = None, args: dict[str, str] | None = None) -> str:
    """Render one of the `_date`/`_time`/`_datetime` template variables.

    The part to render is the variable's last segment, so this serves every provider
    (`opsgenie_current_start_time`, `calendar_end_date`, ...) unchanged.
    """
    part = variable.rsplit("_", 1)[-1]
    return format_datetime_value(value, part, config, args)


def format_opsgenie_datetime(value: str, local_tz: datetime.tzinfo | None = None) -> str:
    return format_datetime_value(value, "datetime", local_tz=local_tz)
