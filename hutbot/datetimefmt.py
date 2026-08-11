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
    UNKNOWN_ONCALL_PERIOD_PLACEHOLDER,
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


def format_datetime_value(
    value: str,
    part: str = "datetime",
    config: dict | None = None,
    args: dict[str, str] | None = None,
    local_tz: datetime.tzinfo | None = None,
) -> str:
    parsed = parse_opsgenie_datetime(value)
    if not parsed:
        return UNKNOWN_ONCALL_PERIOD_PLACEHOLDER

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


def format_opsgenie_template_datetime(value: str, variable: str, config: dict | None = None, args: dict[str, str] | None = None) -> str:
    part = variable.rsplit("_", 1)[-1]
    return format_datetime_value(value, part, config, args)


def format_opsgenie_datetime(value: str, local_tz: datetime.tzinfo | None = None) -> str:
    return format_datetime_value(value, "datetime", local_tz=local_tz)
