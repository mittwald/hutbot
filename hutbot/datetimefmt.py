"""Date/time parsing, formatting, locale handling, and work-hours helpers."""

import re
import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from employee_list import log_error, log_warning

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


def is_work_day() -> bool:
    today = datetime.date.today()
    # TODO: add holidays
    return today.weekday() < 5


def is_work_time(start_time_str: str, end_time_str: str) -> bool:
    now = datetime.datetime.now()
    start = parse_time(start_time_str)
    end = parse_time(end_time_str)
    if not start or not end:
        log_error(f"Invalid time format {start_time_str} - {end_time_str}")
        return True
    start_today = datetime.datetime.combine(now.date(), start)
    end_today = datetime.datetime.combine(now.date(), end)
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
        return ""
    try:
        return normalize_locale_name(configured_locale)
    except ValueError as e:
        log_warning("Ignoring invalid datetime locale in configuration:", e)
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
