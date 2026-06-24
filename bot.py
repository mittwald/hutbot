import os
import re
import sys
import copy
import time
import collections
import asyncio
import json
import urllib.parse
import aiofiles
import datetime
import aiohttp  # Added for making HTTP requests
from dataclasses import dataclass
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from slack_bolt.async_app import AsyncApp
from slack_bolt.adapter.socket_mode.aiohttp import AsyncSocketModeHandler
from slack_sdk.errors import SlackApiError
from employee_list import (
    get_env_var,
    load_employee_mappings,
    load_employees,
    load_env_file,
    log,
    log_error,
    log_warning,
    normalize_id,
    normalize_real_name,
    normalize_real_name_with_diagraphs,
    normalize_user_name,
)
import outlook

try:
    from croniter import croniter
except ImportError:  # pragma: no cover - dependency optional at runtime
    croniter = None

ScheduledReply = collections.namedtuple('ScheduledReply', ['task', 'user_id'])
User = collections.namedtuple('User', ['id', 'name', 'real_name', 'team'])
Usergroup = collections.namedtuple('Usergroup', ['id', 'handle', 'name'])
Channel = collections.namedtuple('Channel', ['id', 'name', 'configs'])
OpsGeniePeriod = collections.namedtuple('OpsGeniePeriod', ['recipient_email', 'slack_user', 'start', 'end'])
OpsGenieContext = collections.namedtuple('OpsGenieContext', ['schedule_name', 'current', 'next'])

DEFAULT_CONFIG_NAME = 'default'
DEFAULT_DATE_FORMAT = "%a, %d %b %Y"
DEFAULT_TIME_FORMAT = "%H:%M"
DEFAULT_OPSGENIE_PRIORITY = "P4"
OPSGENIE_PRIORITIES = {"P1", "P2", "P3", "P4", "P5"}
TRIGGER_MESSAGE = "message"
TRIGGER_SCHEDULE = "schedule"
TRIGGER_MANUAL = "manual"
TRIGGERS = {TRIGGER_MESSAGE, TRIGGER_SCHEDULE, TRIGGER_MANUAL}

CONDITION_NONE = ""
CONDITION_OUTLOOK = "outlook_calendar"
CONDITIONS = {CONDITION_NONE, CONDITION_OUTLOOK}

ACTION_REPLY = "reply"
ACTION_DM_USER = "dm_user"
ACTION_GROUP_DM = "group_dm"
ACTION_POST_CHANNEL = "post_channel"
ACTIONS = {ACTION_REPLY, ACTION_DM_USER, ACTION_GROUP_DM, ACTION_POST_CHANNEL}

BUTTON_ACTION_PREFIX = "hutbot_btn"

# What a button does when pressed.
BUTTON_ACTION_CONFIG = "config"    # run another named config (an OpsGenie alert is just such a config)
BUTTON_ACTION_ACK = "ack"          # acknowledge/dismiss (cancel escalation), optional ack text
BUTTON_ACTION_MESSAGE = "message"  # post a fixed inline message
BUTTON_ACTION_DELAY = "delay"      # delay the pending escalation by N minutes
BUTTON_ACTIONS = {BUTTON_ACTION_CONFIG, BUTTON_ACTION_ACK, BUTTON_ACTION_MESSAGE, BUTTON_ACTION_DELAY}

# What a buttoned message escalates to if no button is pressed within the timeout.
ESCALATION_NONE = "none"
ESCALATION_CONFIG = "config"
ESCALATION_BUTTON = "button"  # auto-press a named button (the "default" button)

DEFAULT_CONFIG = {
    "wait_time": 30 * 60,
    "reply_message": "Anybody?",
    "opsgenie": False,
    "opsgenie_schedule_name": "",
    "opsgenie_priority": DEFAULT_OPSGENIE_PRIORITY,
    "opsgenie_message": "",  # optional template for the alert text; empty = original message
    "date_format": "",
    "time_format": "",
    "datetime_timezone": "",
    "datetime_locale": "",
    "debug": False,
    "include_bots": False,
    "excluded_teams": [],
    "included_teams": [],
    "only_work_days": False,
    "hours": [],
    "pattern": None,
    "pattern_case_sensitive": False,
    "forward_channel": "",
    "enabled": True,
    # Trigger: how the rule starts. "message" keeps the classic behavior.
    "trigger": TRIGGER_MESSAGE,
    "schedule_cron": "",
    "schedule_timezone": "",
    # Condition: optional gate evaluated when a schedule trigger fires.
    "condition": CONDITION_NONE,
    "condition_negate": False,
    "outlook_subject_pattern": "",
    "outlook_body_pattern": "",
    # Action: what the rule does when it fires.
    "action": ACTION_REPLY,
    "action_target": "",
    # Buttons: interactive buttons attached to the sent message.
    "buttons": [],
    "button_timeout": 0,
    "button_timeout_target": "",
    "default_button": "",  # label of the button to auto-press if none is pressed in time
}

CONFIG_FILE_NAME = os.environ.get('HUTBOT_CONFIG_FILE', 'bot.json')
SCHEDULED_REPLIES_CACHE_FILE = os.environ.get('HUTBOT_SCHEDULED_REPLIES_CACHE_FILE', 'scheduled_replies.json')
BUTTON_CACHE_FILE = os.environ.get('HUTBOT_BUTTON_CACHE_FILE', 'button_states.json')
SCHEDULER_INTERVAL = int(os.environ.get('HUTBOT_SCHEDULER_INTERVAL', '30'))
TEAM_UNKNOWN = '<unknown>'

IGNORED_MESSAGE_SUBTYPES = set(['channel_join',
                                'channel_leave',
                                'channel_archived',
                                'channel_unarchived',
                                'channel_convert_to_private',
                                'channel_convert_to_public',
                                'channel_name',
                                'channel_posting_permissions',
                                'channel_purpose',
                                'channel_topic' ])

channel_config = {}
scheduled_messages = {}
_scheduled_replies_cache: dict[tuple, dict] = {}

# Pending interactive-button messages awaiting a press, keyed by (channel_id, message_ts).
# Value: {'task': asyncio.Task, 'channel_id', 'message_ts', 'config_name', 'target', 'run_at'}.
pending_buttons: dict[tuple, dict] = {}
_button_states_cache: dict[tuple, dict] = {}

# Timestamp of the scheduler's previous tick; cron occurrences in (last tick, now] fire.
_scheduler_last_check: datetime.datetime | None = None

user_id_cache = {}
user_email_cache = {}
id_user_cache = {}
usergroup_id_cache = {}
id_usergroup_cache = {}
team_cache = set()

bot_user_id = None

opsgenie_configured = False

MENTION_PATTERN = re.compile(r'(?<![|<])@([a-z0-9-_.]+)(?!>)')
ID_PATTERN = re.compile(r'<([#@!][a-zA-Z0-9^]+)([|]([^>]*))?>')
TIME_HOUR_PATTERN = re.compile(r"^[0-9]{1,2}$")
CONFIG_NAME_PATTERN = re.compile(r"^[A-Za-z0-9-_\.:/]+$")
TEMPLATE_VARIABLE_NAME_PATTERN = re.compile(r'[a-z_][a-z0-9_]*')
TEMPLATE_ARGUMENT_NAME_PATTERN = re.compile(r'[a-z_][a-z0-9_]*')
TEMPLATE_ARGUMENT_ALIASES = {
    "fmt": "fmt",
    "format": "fmt",
    "tz": "tz",
    "timezone": "tz",
    "lc": "lc",
    "locale": "lc",
}
OPSGENIE_DATETIME_TEMPLATE_VARIABLES = {
    f"opsgenie_{period}_{bound}_{part}"
    for period in ("current", "next")
    for bound in ("start", "end")
    for part in ("date", "time", "datetime")
}
OPSGENIE_TEMPLATE_VARIABLES = {
    "opsgenie_schedule_name",
    "opsgenie_current_email",
    "opsgenie_current_name",
    "opsgenie_current_user",
    "opsgenie_next_email",
    "opsgenie_next_name",
    "opsgenie_next_user",
    *OPSGENIE_DATETIME_TEMPLATE_VARIABLES,
}
SUPPORTED_TEMPLATE_VARIABLES = {
    "channel",
    "channel_name",
    "config",
    "message",
    "message_link",
    *OPSGENIE_TEMPLATE_VARIABLES,
    "team",
    "timestamp",
    "user",
    "user_name",
    "wait_minutes",
}
UNKNOWN_EMAIL_ONCALL_PLACEHOLDER = "<no-email-set>"
UNKNOWN_NAME_ONCALL_PLACEHOLDER = "<no-name-set>"
UNKNOWN_USER_ONCALL_PLACEHOLDER = "<no-user-set>"
UNKNOWN_ONCALL_PERIOD_PLACEHOLDER = "<unknown>"
UNKNOWN_OPSGENIE_SCHEDULE_PLACEHOLDER = "<no-schedule-set>"

@dataclass(frozen=True)
class TemplateExpression:
    variable: str
    args: dict[str, str]

class TemplateExpressionError(ValueError):
    pass

# Regex patterns for command parsing
def create_command_pattern(command_regex: str) -> re.Pattern:
    return re.compile(f'^{command_regex}', re.IGNORECASE)

HELP_PATTERN = re.compile(r'help', re.IGNORECASE)
WHATSNEW_PATTERN = re.compile(r'news', re.IGNORECASE)
TEST_PATTERN = re.compile(r'^test$', re.IGNORECASE)
TEST_WITH_MESSAGE_PATTERN = re.compile(r'^test(?:\s+(?P<message>.*))?$', re.IGNORECASE)
SET_WAIT_TIME_PATTERN = create_command_pattern(r'(set\s+)?wait([_ -]?time)?\s+(?P<wait_time>.+)')
SET_REPLY_MESSAGE_PATTERN = create_command_pattern(r'(set\s+)?(message|reply)\s+(?P<message>.+)')
SET_OPSGENIE_SCHEDULE_PATTERN = create_command_pattern(r'set\s+opsgenie[_ -]?schedule\s+(?P<schedule>.+)')
SET_OPSGENIE_PRIORITY_PATTERN = create_command_pattern(r'set\s+opsgenie[_ -]?priority\s+(?P<priority>.+)')
CLEAR_OPSGENIE_MESSAGE_PATTERN = create_command_pattern(r'(clear|unset|remove)\s+opsgenie[_ -]?message')
SET_OPSGENIE_MESSAGE_PATTERN = create_command_pattern(r'set\s+opsgenie[_ -]?message\s+(?P<message>.+)')
SET_DATETIME_FORMAT_PATTERN = create_command_pattern(r'(set\s+)?(datetime[_ -]?format|date[_ -]?format|datefmt)\s+(?P<values>.+)')
SET_PATTERN_PATTERN = create_command_pattern(r'set\s+pattern\s+(?P<pattern>"[^"]*"|\'[^\']*\'|[^\r\n\t\f\v\s"\']+)(?:\s+(?P<case_sensitive>true|false|1|0))?')
ADD_EXCLUDED_TEAM_PATTERN = create_command_pattern(r'(add\s+)?excluded?([_ -]?teams?)?\s+(?P<team>.+)')
CLEAR_EXCLUDED_TEAM_PATTERN = create_command_pattern(r'clear\s+excluded?([_ -]?teams?)?')
ADD_INCLUDED_TEAM_PATTERN = create_command_pattern(r'(add\s+)?included?([_ -]?teams?)?\s+(?P<team>.+)')
CLEAR_INCLUDED_TEAM_PATTERN = create_command_pattern(r'clear\s+included?([_ -]?teams?)?')
LIST_TEAMS_PATTERN = re.compile(r'^(list\s+)?teams?$', re.IGNORECASE)
EMPLOYEE_TEAM_PATTERN = re.compile(r'^team(\s+of)?\s+(?P<user>.+)$', re.IGNORECASE)
LIST_OPSGENIE_SCHEDULES_PATTERN = re.compile(r'^list\s+opsgenie[_ -]?schedules$', re.IGNORECASE)
ON_CALL_PATTERN = create_command_pattern(r'on[_ -]?call(?:\s+(?P<schedule>.+))?$')
ENABLE_OPSGENIE_PATTERN = create_command_pattern(r'enable\s+(opsgenie|alerts?)')
DISABLE_OPSGENIE_PATTERN = create_command_pattern(r'disable\s+(opsgenie|alerts?)')
ENABLE_BOTS_PATTERN = create_command_pattern(r'(enable|include|set)?\s+bots?')
DISABLE_BOTS_PATTERN = create_command_pattern(r'(disable|exclude)\s+bots?')
SET_WORK_HOURS_PATTERN = create_command_pattern(r'(set\s+)?(work[_ -]?)?hours\s+(?P<start>.+)\s+(?P<end>.+)')
ENABLE_ONLY_WORK_DAYS_PATTERN = create_command_pattern(r'enable\s+(only[_ -]?)?work[_ -]?days')
DISABLE_ONLY_WORK_DAYS_PATTERN = create_command_pattern(r'disable\s+(only[_ -]?)?work[_ -]?days')
SHOW_CONFIG_PATTERN = re.compile(r'^(show\s+)?config(uration)?$', re.IGNORECASE)
DELETE_CONFIG_PATTERN = create_command_pattern(r'delete\s+config\s+(?P<name>.+)')
SET_FORWARD_CHANNEL_PATTERN = create_command_pattern(r'set\s+forward[_ -]?channel\s+(?P<channel>.+)')
CLEAR_FORWARD_CHANNEL_PATTERN = create_command_pattern(r'(clear|unset|remove)\s+forward[_ -]?channel')
ENABLE_REPLIES_PATTERN = create_command_pattern(r'enable$')
DISABLE_REPLIES_PATTERN = create_command_pattern(r'disable$')
SET_TRIGGER_PATTERN = create_command_pattern(r'set\s+trigger\s+(?P<trigger>.+)')
SET_CRON_PATTERN = create_command_pattern(r'set\s+(schedule[_ -]?)?cron\s+(?P<cron>.+)')
SET_SCHEDULE_TIMEZONE_PATTERN = create_command_pattern(r'set\s+schedule[_ -]?(time)?zone\s+(?P<tz>.+)')
SET_CONDITION_PATTERN = create_command_pattern(r'set\s+condition\s+(?P<condition>.+)')
SET_OUTLOOK_SUBJECT_PATTERN = create_command_pattern(r'set\s+outlook[_ -]?subject\s+(?P<pattern>.+)')
SET_OUTLOOK_BODY_PATTERN = create_command_pattern(r'set\s+outlook[_ -]?body\s+(?P<pattern>.+)')
ENABLE_CONDITION_NEGATE_PATTERN = create_command_pattern(r'enable\s+(condition[_ -]?)?negate')
DISABLE_CONDITION_NEGATE_PATTERN = create_command_pattern(r'disable\s+(condition[_ -]?)?negate')
SET_ACTION_PATTERN = create_command_pattern(r'set\s+action\s+(?P<action>.+)')
SET_TARGET_PATTERN = create_command_pattern(r'set\s+target\s+(?P<target>.+)')
ADD_BUTTON_PATTERN = create_command_pattern(r'add\s+button\s+(?P<label>"[^"]*"|\'[^\']*\'|\S+)\s+(?P<spec>.+)')
CLEAR_BUTTONS_PATTERN = create_command_pattern(r'clear\s+buttons?')
SET_BUTTON_TIMEOUT_TARGET_PATTERN = create_command_pattern(r'set\s+button[_ -]?timeout[_ -]?target\s+(?P<target>.+)')
SET_BUTTON_TIMEOUT_PATTERN = create_command_pattern(r'set\s+button[_ -]?timeout\s+(?P<minutes>.+)')
CLEAR_DEFAULT_BUTTON_PATTERN = create_command_pattern(r'(clear|unset|remove)\s+default[_ -]?button')
SET_DEFAULT_BUTTON_PATTERN = create_command_pattern(r'set\s+default[_ -]?button\s+(?P<label>.+)')
RUN_PATTERN = re.compile(r'^(run|fire)$', re.IGNORECASE)

def log_debug(channel: Channel | None, *args: object) -> None:
    if channel and any(c.get('debug') for c in channel.configs.values()):
        __log(sys.stderr, 'DEBUG', *args)

def __log(file, prefix, *args: object) -> None:
    parts = []
    for arg in args:
        part = str(arg)
        if isinstance(arg, BaseException):
            error_type = type(arg).__name__
            error_message = str(arg)
            part = f"{error_type}{': ' + error_message if error_message else ''}"
        parts.append(part)
    message = ' '.join(parts)
    prefix = f"{datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')} {prefix}:"
    print(prefix, message, flush=True, file=file)

def strip_quotes(text: str) -> str:
    if text and ((text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'"))):
        text = text[1:-1]

    return text

def parse_quoted_tokens(text: str) -> tuple[list[str], str]:
    tokens = []
    i = 0
    while i < len(text):
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            break

        if text[i] in ("'", '"'):
            quote = text[i]
            i += 1
            value = []
            while i < len(text):
                if text[i] == "\\" and i + 1 < len(text) and text[i + 1] in (quote, "\\"):
                    value.append(text[i + 1])
                    i += 2
                    continue
                if text[i] == quote:
                    i += 1
                    break
                value.append(text[i])
                i += 1
            else:
                return [], "unterminated quoted value"
            if i < len(text) and not text[i].isspace():
                return [], "quoted values must be separated by whitespace"
            tokens.append("".join(value))
        else:
            start = i
            while i < len(text) and not text[i].isspace():
                i += 1
            tokens.append(text[start:i])

    return tokens, ""

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

def iter_template_expression_parts(message: str):
    pos = 0
    while pos < len(message):
        next_open = message.find("{{", pos)
        next_close = message.find("}}", pos)
        if next_close != -1 and (next_open == -1 or next_close < next_open):
            raise TemplateExpressionError("unexpected `}}`")
        if next_open == -1:
            break

        close = message.find("}}", next_open + 2)
        if close == -1:
            raise TemplateExpressionError("missing closing `}}`")
        yield next_open, close + 2, message[next_open + 2:close].strip()
        pos = close + 2

def parse_template_expression(content: str) -> TemplateExpression:
    i = 0
    match = TEMPLATE_VARIABLE_NAME_PATTERN.match(content, i)
    if not match:
        raise TemplateExpressionError("missing variable name")
    variable = match.group(0)
    i = match.end()

    while i < len(content) and content[i].isspace():
        i += 1
    if i == len(content):
        return TemplateExpression(variable, {})
    if content[i] != "(":
        raise TemplateExpressionError("expected `(` after variable name")
    i += 1

    args = {}
    while True:
        while i < len(content) and content[i].isspace():
            i += 1
        if i < len(content) and content[i] == ")":
            i += 1
            break
        if i >= len(content):
            raise TemplateExpressionError("missing closing `)`")

        name_match = TEMPLATE_ARGUMENT_NAME_PATTERN.match(content, i)
        if not name_match:
            raise TemplateExpressionError("missing argument name")
        arg_name = name_match.group(0)
        i = name_match.end()
        canonical_arg_name = TEMPLATE_ARGUMENT_ALIASES.get(arg_name)
        if not canonical_arg_name:
            raise TemplateExpressionError(f"unknown argument `{arg_name}`")
        if canonical_arg_name in args:
            raise TemplateExpressionError(f"duplicate argument `{arg_name}`")

        while i < len(content) and content[i].isspace():
            i += 1
        if i >= len(content) or content[i] != "=":
            raise TemplateExpressionError(f"missing `=` after argument `{arg_name}`")
        i += 1
        while i < len(content) and content[i].isspace():
            i += 1
        if i >= len(content) or content[i] in ",)":
            raise TemplateExpressionError(f"missing value for argument `{arg_name}`")

        if content[i] in ("'", '"'):
            quote = content[i]
            i += 1
            value = []
            while i < len(content):
                if content[i] == "\\" and i + 1 < len(content) and content[i + 1] in (quote, "\\"):
                    value.append(content[i + 1])
                    i += 2
                    continue
                if content[i] == quote:
                    i += 1
                    break
                value.append(content[i])
                i += 1
            else:
                raise TemplateExpressionError(f"unterminated quoted value for argument `{arg_name}`")
            arg_value = "".join(value)
        else:
            start = i
            while i < len(content) and content[i] not in ",)":
                i += 1
            arg_value = content[start:i].strip()

        if not arg_value:
            raise TemplateExpressionError(f"missing value for argument `{arg_name}`")
        args[canonical_arg_name] = arg_value

        while i < len(content) and content[i].isspace():
            i += 1
        if i < len(content) and content[i] == ",":
            i += 1
            j = i
            while j < len(content) and content[j].isspace():
                j += 1
            if j < len(content) and content[j] == ")":
                raise TemplateExpressionError("missing argument after `,`")
            continue
        if i < len(content) and content[i] == ")":
            i += 1
            break
        if i >= len(content):
            raise TemplateExpressionError("missing closing `)`")
        raise TemplateExpressionError("expected `,` or `)` after argument value")

    while i < len(content) and content[i].isspace():
        i += 1
    if i != len(content):
        raise TemplateExpressionError("unexpected text after closing `)`")

    return TemplateExpression(variable, args)

def parse_template_expressions(message: str) -> list[TemplateExpression]:
    return [parse_template_expression(content) for _, _, content in iter_template_expression_parts(message)]

def validate_template_expressions(message: str) -> str:
    try:
        expressions = parse_template_expressions(message)
    except TemplateExpressionError as e:
        return f"malformed template expression: {e}"

    unknown_variables = sorted({expr.variable for expr in expressions if expr.variable not in SUPPORTED_TEMPLATE_VARIABLES})
    if unknown_variables:
        return (
            "unsupported template variable(s) "
            + ", ".join(f"`{{{{{variable}}}}}`" for variable in unknown_variables)
            + ". Supported variables: "
            + ", ".join(f"`{{{{{variable}}}}}`" for variable in sorted(SUPPORTED_TEMPLATE_VARIABLES))
            + "."
        )

    for expr in expressions:
        if expr.args and expr.variable not in OPSGENIE_DATETIME_TEMPLATE_VARIABLES:
            return f"template variable `{{{{{expr.variable}}}}}` does not support arguments"
        if "tz" in expr.args:
            try:
                validate_timezone_name(expr.args["tz"])
            except ValueError as e:
                return str(e)
        if "lc" in expr.args:
            try:
                normalize_locale_name(expr.args["lc"])
            except ValueError as e:
                return str(e)

    return ""

async def migrate_and_apply_defaults(app: AsyncApp, config: dict) -> dict:
    for channel_id, channel_data in config.items():
        # Migration for old format
        # old format: "C1234": { "wait_time": 60, ... }
        # new format: "C1234": { "default": { "wait_time": 60, ... } }
        is_flat_config = any(k in DEFAULT_CONFIG for k in channel_data.keys())
        if is_flat_config:
            # This looks like an old, flat config. Let's wrap it.
            log(f"Migrating old configuration for channel {channel_id}")
            channel_data = {DEFAULT_CONFIG_NAME: channel_data}
            config[channel_id] = channel_data

        for config_name, single_config in channel_data.items():
            for key, value in DEFAULT_CONFIG.items():
                if key not in single_config:
                    single_config[key] = value
            # Normalize legacy {label, target} buttons to {label, action, value}.
            buttons = single_config.get('buttons')
            if isinstance(buttons, list):
                normalized = []
                for button in buttons:
                    if not isinstance(button, dict):
                        continue
                    action, value = normalize_button(button)
                    normalized.append({'label': button.get('label', ''), 'action': action, 'value': value})
                single_config['buttons'] = normalized
    return config


async def load_configuration(app: AsyncApp) -> None:
    global channel_config
    try:
        async with aiofiles.open(CONFIG_FILE_NAME, 'r') as f:
            content = await f.read()
            loaded_config = json.loads(content)
            channel_config = await migrate_and_apply_defaults(app, loaded_config)
            log("Configuration loaded from disk.")
    except FileNotFoundError:
        log_warning("No configuration file found. Using default settings.")
        channel_config = {}
    except json.JSONDecodeError as e:
        log_error(f"Failed to decode JSON configuration:", e)
        channel_config = {}

async def save_configuration() -> None:
    try:
        async with aiofiles.open(CONFIG_FILE_NAME, 'w') as f:
            content = json.dumps(channel_config, indent=2)
            await f.write(content)
    except Exception as e:
        log_error("Failed to save configuration:", e)

async def load_replies_cache() -> None:
    global _scheduled_replies_cache
    try:
        async with aiofiles.open(SCHEDULED_REPLIES_CACHE_FILE, 'r') as f:
            content = await f.read()
            entries = json.loads(content)
            _scheduled_replies_cache = {
                (e['channel_id'], e['ts'], e['config_name']): e
                for e in entries
            }
            log(f"Loaded {len(_scheduled_replies_cache)} pending scheduled replies from cache.")
    except FileNotFoundError:
        _scheduled_replies_cache = {}
    except Exception as e:
        log_error("Failed to load scheduled replies cache:", e)
        _scheduled_replies_cache = {}

async def flush_replies_cache() -> None:
    try:
        async with aiofiles.open(SCHEDULED_REPLIES_CACHE_FILE, 'w') as f:
            await f.write(json.dumps(list(_scheduled_replies_cache.values()), indent=2))
    except Exception as e:
        log_error("Failed to flush scheduled replies cache:", e)

async def get_channel_by_id(app: AsyncApp, channel_id: str) -> Channel:
    global channel_config
    if channel_id not in channel_config:
        channel_config[channel_id] = {}

    name = await get_channel_name(app, channel_id)
    configs = channel_config[channel_id]

    return Channel(id=channel_id, name=name, configs=configs)

async def get_channel_name(app: AsyncApp, channel_id: str) -> str:
    try:
        response = await app.client.conversations_info(channel=channel_id)
        channel_name = response.get('channel', {}).get('name', '')
        if channel_name:
            return channel_name
    except SlackApiError as e:
        log_error(f"Failed to get channel name for {channel_id}", e)

    return channel_id

async def get_message_permalink(app: AsyncApp, channel: Channel, ts: str) -> str:
    permalink = ""
    try:
        response = await app.client.chat_getPermalink(
            channel=channel.id,
            message_ts=ts
        )

        permalink = response.get('permalink', '')
    except SlackApiError as e:
        log_error(f"Failed to get permalink for message {ts} in channel #{channel.name}:", e)

    return permalink

async def update_usergroup_cache(app: AsyncApp) -> None:
  global usergroup_id_cache, id_usergroup_cache
  if not usergroup_id_cache or not id_usergroup_cache:
      try:
          response = await app.client.usergroups_list()
          usergroups = response['usergroups']
          for usergroup in usergroups:
              if usergroup.get('date_deleted', 0) == 0:
                  usergroup_id = usergroup.get('id', '')
                  usergroup_handle = usergroup.get('handle', '')
                  usergroup_name = usergroup.get('name', '')
                  usergroup_id_cache[usergroup_handle] = Usergroup(id=usergroup_id, handle=usergroup_handle, name=usergroup_name)
                  id_usergroup_cache[usergroup_id] = Usergroup(id=usergroup_id, handle=usergroup_handle, name=usergroup_name)
      except SlackApiError as e:
          log_error(f"Failed to fetch usergroup list:", e)

def build_user(user: dict, employees: dict, mappings: dict) -> tuple[str, User]:
    user_id = user.get('id', '')
    user_name = normalize_id(user.get('name', ''))
    if user_name in mappings:
        log(f"Applying employee mapping: {user_name} -> {mappings[user_name]}")
        user_name = mappings[user_name]
    user_name_normalized = normalize_user_name(user_name)
    user_email = normalize_id(user.get('profile', {}).get('email', ''))
    user_email_alias = normalize_id(user_email.split('@')[0])
    user_email_alias_normalized = normalize_user_name(user_email_alias)
    user_real_name = user.get('real_name', '').strip()
    user_real_name_normalized = normalize_real_name(user_real_name)
    user_team = TEAM_UNKNOWN

    if len(employees) > 0:
        # Try different variations of the username to find a match in employees
        user_key_candidates = [
            user_name,
            user_name_normalized,
            user_email_alias,
            user_email_alias_normalized
        ]
        user_key = next((k for k in user_key_candidates if k in employees), None)

        if not user_key:
            # loop through all employees and try to match some form of the real name
            for employee_key, employee in employees.items():
                employee_real_name = employee.get('fullname', '').strip()
                employee_real_name_normalized = normalize_real_name(employee_real_name)
                employee_real_name_super_normalized = normalize_real_name_with_diagraphs(employee_real_name)
                user_real_name_super_normalized = normalize_real_name_with_diagraphs(user_real_name)
                if employee_real_name_normalized == user_real_name_normalized or \
                employee_real_name_super_normalized == user_real_name_normalized or \
                employee_real_name_super_normalized == user_real_name_super_normalized:
                    user_key = employee_key
                    # finally!
                    break
            if not user_key:
                user_json = json.dumps(user)
                if len(user_json) > 100:
                    user_json = user_json[:97] + '...'
                log_warning(f"Failed to map user @{user_name} to a employee: {user_json}")

        if user_key:
            user_team = employees[user_key].get('group', '').strip()

    return user_email, User(id=user_id, name=user_name, team=user_team, real_name=user_real_name)

def cache_user(user_email: str, u: User) -> None:
    user_id_cache[u.name] = u
    if user_email:
        user_email_cache[user_email] = u
    id_user_cache[u.id] = u
    if u.team not in team_cache:
        team_cache.add(u.team)

async def update_user_cache(app: AsyncApp) -> None:
    global user_id_cache, user_email_cache, id_user_cache
    if not user_id_cache or not user_email_cache or not id_user_cache:
        employees = await load_employees()
        mappings = load_employee_mappings()
        try:
            cursor = None
            while True:
                response = await app.client.users_list(cursor=cursor, limit=200)
                for user in response['members']:
                    if not user.get('deleted') and \
                       not user.get('is_bot', False) and \
                       not user.get('is_restricted', False) and \
                       user.get('id', '') != 'USLACKBOT':
                        cache_user(*build_user(user, employees, mappings))
                cursor = response.get('response_metadata', {}).get('next_cursor')
                if not cursor:
                    break
        except SlackApiError as e:
            log_error(f"Failed to fetch user list:", e)

async def fetch_user_by_id(app: AsyncApp, id: str, channel: Channel | None = None) -> User | None:
    try:
        response = await app.client.users_info(user=id)
    except SlackApiError as e:
        log_error(f"Failed to fetch user `{id}`:", e)
        return None
    slack_user = response.get('user')
    if not slack_user:
        return None
    log_debug(channel, f"Retrieved user not in cache from Slack API: {json.dumps(slack_user)}")
    employees = await load_employees()
    mappings = load_employee_mappings()
    user_email, user = build_user(slack_user, employees, mappings)
    cache_user(user_email, user)
    return user

async def get_user_by_id(app: AsyncApp, id: str, channel: Channel | None = None) -> User:
    await update_user_cache(app)
    user = id_user_cache.get(id, None)
    if not user:
        user = await fetch_user_by_id(app, id, channel)
    if not user:
        user = User(id=id, name=id, team=TEAM_UNKNOWN, real_name='')
    return user

async def get_user_by_name(app: AsyncApp, name: str) -> User:
    await update_user_cache(app)
    user = user_id_cache.get(name, None)
    if not user:
        user = User(id=None, name=name, team=TEAM_UNKNOWN, real_name='')
    return user

async def get_user_by_email(app: AsyncApp, email: str) -> User:
    await update_user_cache(app)
    normalized_email = normalize_id(email)
    user = user_email_cache.get(normalized_email, None)
    if user:
        return user

    user_alias = normalized_email.split('@')[0]
    return await get_user_by_name(app, user_alias)

async def get_usergroup_by_id(app: AsyncApp, id: str) -> Usergroup:
    await update_usergroup_cache(app)
    usergroup = id_usergroup_cache.get(id, None)
    if not usergroup:
        usergroup = Usergroup(id=id, handle=id, name=id)
    return usergroup

async def get_usergroup_by_handle(app: AsyncApp, handle: str) -> Usergroup:
    await update_usergroup_cache(app)
    usergroup = usergroup_id_cache.get(handle, None)
    if not usergroup:
        usergroup = Usergroup(id=None, handle=handle, name=handle)
    return usergroup

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

def is_command(text: str) -> bool:
    return f"<@{bot_user_id}>" in text

async def parse_and_execute_command(app: AsyncApp, command_text: str, channel: Channel, config_name: str, user: User, thread_ts: str = "", opsgenie_token: str = "", allow_test_message: bool = False, command_ts: str = "") -> bool:
    """Parses and executes a command, returns True if a command was matched."""
    if (match := (TEST_WITH_MESSAGE_PATTERN if allow_test_message else TEST_PATTERN).match(command_text)):
        test_message = match.group("message") if allow_test_message and match.groupdict().get("message") is not None else ""
        await test_reply_message(app, opsgenie_token, channel, config_name, user, test_message, command_ts, thread_ts)
    elif (match := SET_WAIT_TIME_PATTERN.match(command_text)):
        wait_time_minutes = int(strip_quotes(match.group("wait_time")))
        await set_wait_time(app, channel, config_name, wait_time_minutes, user, thread_ts)
    elif (match := SET_REPLY_MESSAGE_PATTERN.match(command_text)):
        message = strip_quotes(match.group("message"))
        await set_reply_message(app, channel, config_name, message, user, thread_ts)
    elif (match := SET_OPSGENIE_SCHEDULE_PATTERN.match(command_text)):
        schedule_name = strip_quotes(match.group("schedule"))
        await set_opsgenie_schedule_name(app, channel, config_name, schedule_name, user, thread_ts)
    elif (match := SET_OPSGENIE_PRIORITY_PATTERN.match(command_text)):
        priority = strip_quotes(match.group("priority"))
        await set_opsgenie_priority(app, channel, config_name, priority, user, thread_ts)
    elif CLEAR_OPSGENIE_MESSAGE_PATTERN.match(command_text):
        await clear_opsgenie_message(app, channel, config_name, user, thread_ts)
    elif (match := SET_OPSGENIE_MESSAGE_PATTERN.match(command_text)):
        await set_opsgenie_message(app, channel, config_name, strip_quotes(match.group("message")), user, thread_ts)
    elif (match := SET_DATETIME_FORMAT_PATTERN.match(command_text)):
        await set_datetime_format(app, channel, config_name, match.group("values"), user, thread_ts)
    elif (match := SET_PATTERN_PATTERN.match(command_text)):
        pattern = match.group("pattern")
        case_sensitive = match.group("case_sensitive")
        await set_pattern(app, channel, config_name, pattern, case_sensitive, user, thread_ts)
    elif (match := ENABLE_OPSGENIE_PATTERN.match(command_text)):
        await set_opsgenie(app, channel, config_name, True, user, thread_ts)
    elif (match := DISABLE_OPSGENIE_PATTERN.match(command_text)):
        await set_opsgenie(app, channel, config_name, False, user, thread_ts)
    elif (match := ENABLE_BOTS_PATTERN.match(command_text)):
        await set_bots(app, channel, config_name, True, user, thread_ts)
    elif (match := DISABLE_BOTS_PATTERN.match(command_text)):
        await set_bots(app, channel, config_name, False, user, thread_ts)
    elif (match := ENABLE_ONLY_WORK_DAYS_PATTERN.match(command_text)):
        await set_only_work_days(app, channel, config_name, True, user, thread_ts)
    elif (match := DISABLE_ONLY_WORK_DAYS_PATTERN.match(command_text)):
        await set_only_work_days(app, channel, config_name, False, user, thread_ts)
    elif (match := SET_WORK_HOURS_PATTERN.match(command_text)):
        start = strip_quotes(match.group("start"))
        end = strip_quotes(match.group("end"))
        await set_work_hours(app, channel, config_name, start, end, user, thread_ts)
    elif LIST_TEAMS_PATTERN.match(command_text):
        await list_teams(app, channel, user, thread_ts)
    elif LIST_OPSGENIE_SCHEDULES_PATTERN.match(command_text):
        await list_opsgenie_schedules(app, channel, user, thread_ts)
    elif (match := ON_CALL_PATTERN.match(command_text)):
        schedule_name = strip_quotes(match.group("schedule") or "")
        await send_current_on_call(app, opsgenie_token, channel, config_name, schedule_name, user, thread_ts)
    elif (match := EMPLOYEE_TEAM_PATTERN.match(command_text)):
        username = strip_quotes(match.group("user"))
        await get_team_of(app, channel, username, user, thread_ts)
    elif (match := ADD_EXCLUDED_TEAM_PATTERN.match(command_text)):
        team = strip_quotes(match.group("team"))
        await add_excluded_team(app, channel, config_name, team, user, thread_ts)
    elif (match := CLEAR_EXCLUDED_TEAM_PATTERN.match(command_text)):
        await clear_excluded_team(app, channel, config_name, user, thread_ts)
    elif (match := ADD_INCLUDED_TEAM_PATTERN.match(command_text)):
        team = strip_quotes(match.group("team"))
        await add_included_team(app, channel, config_name, team, user, thread_ts)
    elif (match := CLEAR_INCLUDED_TEAM_PATTERN.match(command_text)):
        await clear_included_team(app, channel, config_name, user, thread_ts)
    elif (match := SET_FORWARD_CHANNEL_PATTERN.match(command_text)):
        channel_ref = strip_quotes(match.group("channel"))
        await set_forward_channel(app, channel, config_name, channel_ref, user, thread_ts)
    elif CLEAR_FORWARD_CHANNEL_PATTERN.match(command_text):
        await clear_forward_channel(app, channel, config_name, user, thread_ts)
    elif (match := SET_TRIGGER_PATTERN.match(command_text)):
        await set_trigger(app, channel, config_name, match.group("trigger"), user, thread_ts)
    elif (match := SET_CRON_PATTERN.match(command_text)):
        await set_schedule_cron(app, channel, config_name, match.group("cron"), user, thread_ts)
    elif (match := SET_SCHEDULE_TIMEZONE_PATTERN.match(command_text)):
        await set_schedule_timezone(app, channel, config_name, match.group("tz"), user, thread_ts)
    elif (match := SET_CONDITION_PATTERN.match(command_text)):
        await set_condition(app, channel, config_name, match.group("condition"), user, thread_ts)
    elif (match := SET_OUTLOOK_SUBJECT_PATTERN.match(command_text)):
        await set_outlook_pattern(app, channel, config_name, "outlook_subject_pattern", match.group("pattern"), user, thread_ts)
    elif (match := SET_OUTLOOK_BODY_PATTERN.match(command_text)):
        await set_outlook_pattern(app, channel, config_name, "outlook_body_pattern", match.group("pattern"), user, thread_ts)
    elif ENABLE_CONDITION_NEGATE_PATTERN.match(command_text):
        await set_condition_negate(app, channel, config_name, True, user, thread_ts)
    elif DISABLE_CONDITION_NEGATE_PATTERN.match(command_text):
        await set_condition_negate(app, channel, config_name, False, user, thread_ts)
    elif (match := SET_ACTION_PATTERN.match(command_text)):
        await set_action(app, channel, config_name, match.group("action"), user, thread_ts)
    elif (match := SET_TARGET_PATTERN.match(command_text)):
        await set_action_target(app, channel, config_name, match.group("target"), user, thread_ts)
    elif (match := ADD_BUTTON_PATTERN.match(command_text)):
        await add_button(app, channel, config_name, match.group("label"), match.group("spec"), user, thread_ts)
    elif CLEAR_BUTTONS_PATTERN.match(command_text):
        await clear_buttons(app, channel, config_name, user, thread_ts)
    elif CLEAR_DEFAULT_BUTTON_PATTERN.match(command_text):
        await clear_default_button(app, channel, config_name, user, thread_ts)
    elif (match := SET_DEFAULT_BUTTON_PATTERN.match(command_text)):
        await set_default_button(app, channel, config_name, match.group("label"), user, thread_ts)
    elif (match := SET_BUTTON_TIMEOUT_TARGET_PATTERN.match(command_text)):
        await set_button_timeout_target(app, channel, config_name, match.group("target"), user, thread_ts)
    elif (match := SET_BUTTON_TIMEOUT_PATTERN.match(command_text)):
        await set_button_timeout(app, channel, config_name, match.group("minutes"), user, thread_ts)
    elif RUN_PATTERN.match(command_text):
        await run_config_now(app, opsgenie_token, channel, config_name, user, thread_ts)
    elif ENABLE_REPLIES_PATTERN.match(command_text):
        await set_replies_enabled(app, channel, config_name, True, user, thread_ts)
    elif DISABLE_REPLIES_PATTERN.match(command_text):
        await set_replies_enabled(app, channel, config_name, False, user, thread_ts)
    elif (match := DELETE_CONFIG_PATTERN.match(command_text)):
        name = strip_quotes(match.group("name"))
        await delete_config(app, channel, name, user, thread_ts)
    elif SHOW_CONFIG_PATTERN.match(command_text):
        await show_config(app, channel, user, thread_ts)
    elif HELP_PATTERN.match(command_text):
        await send_help_message(app, channel, user, thread_ts)
    elif WHATSNEW_PATTERN.match(command_text):
        await send_news_message(app, channel, user, thread_ts)
    else:
        return False
    return True

async def process_command(app: AsyncApp, text: str, channel: Channel, user: User, thread_ts: str = "", opsgenie_token: str = "", allow_test_message: bool = False, command_ts: str = "") -> None:
    text = text.replace(f"<@{bot_user_id}>", "").strip()
    log_debug(channel, f"Received command for channel #{channel.name}: {text}")
    command_ts = command_ts or thread_ts

    # First, try to parse the command with the default config.
    if await parse_and_execute_command(app, text, channel, DEFAULT_CONFIG_NAME, user, thread_ts, opsgenie_token, allow_test_message, command_ts):
        return

    # If that fails, assume the first part is a config name.
    parts = text.split()
    if len(parts) > 1:
        config_name = parts[0]
        command_text = " ".join(parts[1:])

        if not CONFIG_NAME_PATTERN.match(config_name):
            await send_message(app, channel, user, f"Invalid config name: `{config_name}`. Only characters `A-Z`, `a-z`, `0-9`, `.`, `:`, `/`, `-`, `_` are allowed.", thread_ts)
            return

        if await parse_and_execute_command(app, command_text, channel, config_name, user, thread_ts, opsgenie_token, allow_test_message, command_ts):
            return

    await send_message(app, channel, user, "Huh? :thinking_face: Maybe type `/hutbot help` for a list of commands.", thread_ts)

async def set_bots(app: AsyncApp, channel: Channel, config_name: str, enabled: bool, user: User, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    channel.configs[config_name]['include_bots'] = enabled
    await save_configuration()
    await send_message(app, channel, user, f"*Bot messages* will {'also be *handled*' if enabled else 'be *ignored*'} in configuration `{config_name}`.", thread_ts)

async def set_only_work_days(app: AsyncApp, channel: Channel, config_name: str, enabled: bool, user: User, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    channel.configs[config_name]['only_work_days'] = enabled
    await save_configuration()
    await send_message(app, channel, user, f"Messages will be handled {'*only on work days*' if enabled else '*on all days*'} in configuration `{config_name}`.", thread_ts)

async def set_replies_enabled(app: AsyncApp, channel: Channel, config_name: str, enabled: bool, user: User, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    channel.configs[config_name]['enabled'] = enabled
    await save_configuration()
    await send_message(app, channel, user, f"Replies are now *{'enabled' if enabled else 'disabled'}* in configuration `{config_name}`.", thread_ts)

def parse_time(time_str) -> datetime.time | None:
    if TIME_HOUR_PATTERN.match(time_str):
        time_str = f"{time_str}:00"

    time = None
    try:
        time = datetime.datetime.strptime(time_str, "%H:%M").time()
    except ValueError:
        pass

    return time

async def set_work_hours(app: AsyncApp, channel: Channel, config_name: str, start: str, end: str, user: User, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    start_time = parse_time(start)
    end_time = parse_time(end)
    if not start_time:
        await send_message(app, channel, user, f"Invalid time format `{start}`.", thread_ts)
        return
    if not end_time:
        await send_message(app, channel, user, f"Invalid time format `{end}`.", thread_ts)
        return
    hours = [start_time.strftime("%H:%M"), end_time.strftime("%H:%M")]
    if hours[0] == "00:00" and hours[1] == "00:00":
        hours = []
    channel.configs[config_name]['hours'] = hours
    await save_configuration()
    await send_message(app, channel, user, f"*Work hours* set to {f'`{hours[0]}` - `{hours[1]}`' if len(hours) == 2 else 'all day'} in configuration `{config_name}`", thread_ts)

async def set_forward_channel(app: AsyncApp, channel: Channel, config_name: str, channel_ref: str, user: User, thread_ts: str = "") -> None:
    channel_id = None
    for match in ID_PATTERN.finditer(channel_ref):
        id = match.group(1)
        if id and id[0] == '#':
            channel_id = id[1:]
            break
    if not channel_id:
        stripped = channel_ref.strip()
        if re.match(r'^C[A-Z0-9]+$', stripped):
            channel_id = stripped

    if not channel_id:
        await send_message(app, channel, user, f"Invalid channel: `{channel_ref}`. Use a #channel mention.", thread_ts)
        return

    try:
        confirmation = (
            f"Reply messages from #{channel.name} (config `{config_name}`) "
            f"will now be forwarded here by Hutbot :palm_up_hand::tophat:"
        )
        await app.client.chat_postMessage(channel=channel_id, text=confirmation, mrkdwn=True)
    except SlackApiError as e:
        await send_message(app, channel, user, f"Cannot post to <#{channel_id}>: `{e.response['error']}`.", thread_ts)
        return

    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    channel.configs[config_name]['forward_channel'] = channel_id
    await save_configuration()
    await send_message(app, channel, user, f"*Forward channel* set to <#{channel_id}> in configuration `{config_name}`.", thread_ts)

async def clear_forward_channel(app: AsyncApp, channel: Channel, config_name: str, user: User, thread_ts: str = "") -> None:
    if config_name in channel.configs:
        channel.configs[config_name].pop('forward_channel', None)
        await save_configuration()
    await send_message(app, channel, user, f"*Forward channel* cleared in configuration `{config_name}`.", thread_ts)

async def set_opsgenie(app: AsyncApp, channel: Channel, config_name: str, enabled: bool, user: User, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    channel.configs[config_name]['opsgenie'] = enabled
    await save_configuration()
    await send_message(app, channel, user, f"*OpsGenie integration* {'*enabled*' if enabled else '*disabled*'}{', but not configured' if enabled and not opsgenie_configured else ''} in configuration `{config_name}`.", thread_ts)

async def set_opsgenie_schedule_name(app: AsyncApp, channel: Channel, config_name: str, schedule_name: str, user: User, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    if not schedule_name.strip():
        await send_message(app, channel, user, "Invalid *OpsGenie schedule name*. Must be non-empty.", thread_ts)
        return

    schedule_name = schedule_name.strip()
    channel.configs[config_name]['opsgenie_schedule_name'] = schedule_name
    await save_configuration()
    await send_message(app, channel, user, f"*OpsGenie schedule* set to `{schedule_name}` in configuration `{config_name}`.", thread_ts)

async def set_opsgenie_priority(app: AsyncApp, channel: Channel, config_name: str, priority: str, user: User, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()

    priority = priority.strip().upper()
    if priority not in OPSGENIE_PRIORITIES:
        supported = ", ".join(f"`{p}`" for p in sorted(OPSGENIE_PRIORITIES))
        await send_message(app, channel, user, f"Invalid *OpsGenie priority*. Must be one of {supported}.", thread_ts)
        return

    channel.configs[config_name]['opsgenie_priority'] = priority
    await save_configuration()
    await send_message(app, channel, user, f"*OpsGenie priority* set to `{priority}` in configuration `{config_name}`.", thread_ts)

async def set_opsgenie_message(app: AsyncApp, channel: Channel, config_name: str, message: str, user: User, thread_ts: str = "") -> None:
    message = message.strip()
    validation_error = validate_template_expressions(message)
    if validation_error:
        await send_message(app, channel, user, "Invalid *OpsGenie message*: " + validation_error, thread_ts)
        return
    _ensure_config(channel, config_name)['opsgenie_message'] = message
    await save_configuration()
    await send_message(app, channel, user, f"*OpsGenie message* set to: {message} in configuration `{config_name}`.", thread_ts)

async def clear_opsgenie_message(app: AsyncApp, channel: Channel, config_name: str, user: User, thread_ts: str = "") -> None:
    _ensure_config(channel, config_name)['opsgenie_message'] = ''
    await save_configuration()
    await send_message(app, channel, user, f"*OpsGenie message* cleared (using the original message) in configuration `{config_name}`.", thread_ts)

async def set_datetime_format(app: AsyncApp, channel: Channel, config_name: str, values: str, user: User, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()

    tokens, error = parse_quoted_tokens(values)
    if error:
        await send_message(app, channel, user, f"Invalid *date/time format*: {error}.", thread_ts)
        return
    if len(tokens) < 2 or len(tokens) > 4:
        await send_message(app, channel, user, "Invalid *date/time format*. Use `/hutbot [config] set datetime-format <date> <time> [<timezone> <locale>]`.", thread_ts)
        return

    date_format = tokens[0]
    time_format = tokens[1]
    if not date_format.strip() or not time_format.strip():
        await send_message(app, channel, user, "Invalid *date/time format*. Date and time formats must be non-empty.", thread_ts)
        return

    timezone_name = tokens[2] if len(tokens) >= 3 else ""
    locale_name = tokens[3] if len(tokens) >= 4 else ""
    normalized_locale = ""
    if timezone_name:
        try:
            validate_timezone_name(timezone_name)
        except ValueError as e:
            await send_message(app, channel, user, f"Invalid *date/time format*: {e}.", thread_ts)
            return
    if locale_name:
        try:
            normalized_locale = normalize_locale_name(locale_name)
        except ValueError as e:
            await send_message(app, channel, user, f"Invalid *date/time format*: {e}.", thread_ts)
            return

    config = channel.configs[config_name]
    config["date_format"] = date_format
    config["time_format"] = time_format
    config["datetime_timezone"] = timezone_name
    config["datetime_locale"] = normalized_locale

    await save_configuration()

    details = f"*Date/time format* set to date `{date_format}` and time `{time_format}`"
    if timezone_name:
        details += f", timezone `{timezone_name}`"
    if locale_name:
        details += f", locale `{normalized_locale}`"
    details += f" in configuration `{config_name}`."
    await send_message(app, channel, user, details, thread_ts)

async def set_wait_time(app: AsyncApp, channel: Channel, config_name: str, wait_time_minutes: int, user: User, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    # check if number and in range 0-1440
    if not wait_time_minutes or wait_time_minutes < 0 or wait_time_minutes > 1440:
        await send_message(app, channel, user, "Invalid wait time. Must be a number between 0 and 1440.", thread_ts)
        return

    channel.configs[config_name]['wait_time'] = wait_time_minutes * 60  # Convert to seconds
    log_debug(channel, f"Wait time for #{channel.name} set to {wait_time_minutes} minutes for configuration `{config_name}`")
    await save_configuration()
    await send_message(app, channel, user, f"*Wait time* set to `{wait_time_minutes}` minutes in configuration `{config_name}`.", thread_ts)

def find_unknown_template_variables(message: str) -> list[str]:
    try:
        variables = {expr.variable for expr in parse_template_expressions(message)}
    except TemplateExpressionError:
        return []
    return sorted(variable for variable in variables if variable not in SUPPORTED_TEMPLATE_VARIABLES)

def find_template_variables(message: str) -> set[str]:
    try:
        return {expr.variable for expr in parse_template_expressions(message)}
    except TemplateExpressionError:
        return set()

def render_reply_message_template(message: str, variables: dict[str, str], config: dict | None = None) -> str:
    try:
        spans = list(iter_template_expression_parts(message))
    except TemplateExpressionError:
        return message

    rendered = []
    last_index = 0
    for start, end, content in spans:
        rendered.append(message[last_index:start])
        try:
            expr = parse_template_expression(content)
        except TemplateExpressionError:
            rendered.append(message[start:end])
            last_index = end
            continue

        if expr.variable in OPSGENIE_DATETIME_TEMPLATE_VARIABLES:
            raw_value = variables.get(f"__{expr.variable}_raw", "")
            if raw_value or expr.args:
                rendered.append(format_opsgenie_template_datetime(raw_value, expr.variable, config, expr.args))
            else:
                rendered.append(variables.get(expr.variable, UNKNOWN_ONCALL_PERIOD_PLACEHOLDER))
        else:
            rendered.append(variables.get(expr.variable, message[start:end]))
        last_index = end

    rendered.append(message[last_index:])
    return "".join(rendered)

async def build_reply_template_variables(app: AsyncApp, opsgenie_token: str, channel: Channel, config: dict, config_name: str, user: User, text: str, ts: str, permalink: str, include_opsgenie: bool = False) -> dict[str, str]:
    wait_time = config.get('wait_time')
    opsgenie_template_variables = {}
    if include_opsgenie:
        opsgenie_template_variables = await get_opsgenie_template_variables(app, opsgenie_token, config)

    return {
        "channel": f"#{channel.name}",
        "channel_name": channel.name,
        "config": config_name,
        "message": text,
        "message_link": permalink,
        **opsgenie_template_variables,
        "team": user.team if user.team else TEAM_UNKNOWN,
        "timestamp": ts,
        "user": f"<@{user.id}>",
        "user_name": user.real_name if user.real_name else user.name,
        "wait_minutes": str(wait_time // 60),
    }

async def set_reply_message(app: AsyncApp, channel: Channel, config_name: str, message: str, user: User, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    # check message
    if not message or message.strip() == "":
        await send_message(app, channel, user, "Invalid *reply message*. Must be non-empty.", thread_ts)
        return
    ok, error, message = await process_mentions(app, message)
    if not ok:
        await send_message(app, channel, user, "Invalid *reply message*: " + error + ".", thread_ts)
        return

    validation_error = validate_template_expressions(message)
    if validation_error:
        await send_message(
            app,
            channel,
            user,
            "Invalid *reply message*: " + validation_error,
            thread_ts
        )
        return

    channel.configs[config_name]['reply_message'] = message
    await save_configuration()
    await send_message(app, channel, user, f"*Reply message* set to: {message} in configuration `{config_name}`.", thread_ts)

async def test_reply_message(app: AsyncApp, opsgenie_token: str, channel: Channel, config_name: str, user: User, text: str = "", ts: str = "", thread_ts: str = "") -> None:
    config = channel.configs.get(config_name, DEFAULT_CONFIG.copy())
    reply_message_template = config.get('reply_message')
    permalink = await get_message_permalink(app, channel, ts) if ts else ""
    template_variables = await build_reply_template_variables(
        app,
        opsgenie_token,
        channel,
        config,
        config_name,
        user,
        text,
        ts,
        permalink,
        include_opsgenie=True,
    )
    reply_message = render_reply_message_template(reply_message_template, template_variables, config)
    variable_lines = [
        f"`{{{{{variable}}}}}`: {template_variables.get(variable, '')}"
        for variable in sorted(SUPPORTED_TEMPLATE_VARIABLES)
    ]
    message = (
        f"*Reply preview for configuration `{config_name}`:*\n"
        f"{reply_message}\n\n"
        "*Template variables:*\n"
        + "\n".join(variable_lines)
    )
    await send_message(app, channel, user, message, thread_ts)

async def set_pattern(app: AsyncApp, channel: Channel, config_name: str, pattern_str: str, case_sensitive_str: str | None, user: User, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()

    pattern_str = strip_quotes(pattern_str)

    # Validate the regex pattern
    try:
        re.compile(pattern_str)
    except re.error as e:
        await send_message(app, channel, user, f"Invalid pattern: `{e}`", thread_ts)
        return

    case_sensitive = case_sensitive_str is not None and case_sensitive_str.lower() in ['true', '1']

    channel.configs[config_name]['pattern'] = pattern_str
    channel.configs[config_name]['pattern_case_sensitive'] = case_sensitive
    await save_configuration()

    message = f"Pattern set to `{pattern_str}` for configuration `{config_name}`."
    if case_sensitive:
        message += " (case-sensitive)"
    else:
        message += " (case-insensitive)"
    await send_message(app, channel, user, message, thread_ts)

async def delete_config(app: AsyncApp, channel: Channel, config_name: str, user: User, thread_ts: str = "") -> None:
    if config_name == DEFAULT_CONFIG_NAME:
        await send_message(app, channel, user, f"The `{DEFAULT_CONFIG_NAME}` configuration cannot be deleted.", thread_ts)
        return

    if config_name not in channel.configs:
        await send_message(app, channel, user, f"Configuration `{config_name}` not found.", thread_ts)
        return

    del channel.configs[config_name]
    await save_configuration()
    await send_message(app, channel, user, f"Configuration `{config_name}` has been deleted.", thread_ts)

# ----- Setters for trigger / condition / action / button fields -----

def _ensure_config(channel: Channel, config_name: str) -> dict:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    return channel.configs[config_name]

async def set_trigger(app: AsyncApp, channel: Channel, config_name: str, value: str, user: User, thread_ts: str = "") -> None:
    value = strip_quotes(value).strip().lower()
    value = {'msg': TRIGGER_MESSAGE, 'cron': TRIGGER_SCHEDULE, 'scheduled': TRIGGER_SCHEDULE}.get(value, value)
    if value not in TRIGGERS:
        supported = ", ".join(f"`{t}`" for t in sorted(TRIGGERS))
        await send_message(app, channel, user, f"Invalid *trigger*. Must be one of {supported}.", thread_ts)
        return
    _ensure_config(channel, config_name)['trigger'] = value
    await save_configuration()
    await send_message(app, channel, user, f"*Trigger* set to `{value}` in configuration `{config_name}`.", thread_ts)

async def set_schedule_cron(app: AsyncApp, channel: Channel, config_name: str, cron_expr: str, user: User, thread_ts: str = "") -> None:
    cron_expr = strip_quotes(cron_expr).strip()
    if not cron_expr:
        await send_message(app, channel, user, "Invalid *cron* expression. Must be non-empty.", thread_ts)
        return
    if croniter is not None and not croniter.is_valid(cron_expr):
        await send_message(app, channel, user, f"Invalid *cron* expression: `{cron_expr}`. Use 5-field cron, e.g. `0 9 * * 1-5`.", thread_ts)
        return
    _ensure_config(channel, config_name)['schedule_cron'] = cron_expr
    await save_configuration()
    note = "" if croniter is not None else " (not validated — `croniter` not installed)"
    await send_message(app, channel, user, f"*Cron schedule* set to `{cron_expr}` in configuration `{config_name}`{note}.", thread_ts)

async def set_schedule_timezone(app: AsyncApp, channel: Channel, config_name: str, tz_name: str, user: User, thread_ts: str = "") -> None:
    tz_name = strip_quotes(tz_name).strip()
    if tz_name:
        try:
            ZoneInfo(tz_name)
        except ZoneInfoNotFoundError:
            await send_message(app, channel, user, f"Unknown timezone: `{tz_name}`. Use an IANA name, e.g. `Europe/Berlin`.", thread_ts)
            return
    _ensure_config(channel, config_name)['schedule_timezone'] = tz_name
    await save_configuration()
    await send_message(app, channel, user, f"*Schedule timezone* set to `{tz_name or '<server local>'}` in configuration `{config_name}`.", thread_ts)

async def set_condition(app: AsyncApp, channel: Channel, config_name: str, value: str, user: User, thread_ts: str = "") -> None:
    value = strip_quotes(value).strip().lower()
    value = {'none': CONDITION_NONE, 'off': CONDITION_NONE, '': CONDITION_NONE,
             'outlook': CONDITION_OUTLOOK, 'calendar': CONDITION_OUTLOOK, 'outlook_calendar': CONDITION_OUTLOOK}.get(value, value)
    if value not in CONDITIONS:
        await send_message(app, channel, user, "Invalid *condition*. Must be `none` or `outlook`.", thread_ts)
        return
    _ensure_config(channel, config_name)['condition'] = value
    await save_configuration()
    label = value or 'none'
    await send_message(app, channel, user, f"*Condition* set to `{label}` in configuration `{config_name}`.", thread_ts)

async def set_outlook_pattern(app: AsyncApp, channel: Channel, config_name: str, field: str, pattern_str: str, user: User, thread_ts: str = "") -> None:
    pattern_str = strip_quotes(pattern_str)
    try:
        re.compile(pattern_str)
    except re.error as e:
        await send_message(app, channel, user, f"Invalid pattern: `{e}`", thread_ts)
        return
    _ensure_config(channel, config_name)[field] = pattern_str
    await save_configuration()
    which = "subject" if field == "outlook_subject_pattern" else "body"
    await send_message(app, channel, user, f"*Outlook {which} pattern* set to `{pattern_str}` in configuration `{config_name}`.", thread_ts)

async def set_condition_negate(app: AsyncApp, channel: Channel, config_name: str, enabled: bool, user: User, thread_ts: str = "") -> None:
    _ensure_config(channel, config_name)['condition_negate'] = enabled
    await save_configuration()
    await send_message(app, channel, user, f"*Condition negation* {'*enabled*' if enabled else '*disabled*'} in configuration `{config_name}`.", thread_ts)

async def set_action(app: AsyncApp, channel: Channel, config_name: str, value: str, user: User, thread_ts: str = "") -> None:
    value = strip_quotes(value).strip().lower().replace('-', '_')
    if value not in ACTIONS:
        supported = ", ".join(f"`{a}`" for a in sorted(ACTIONS))
        await send_message(app, channel, user, f"Invalid *action*. Must be one of {supported}.", thread_ts)
        return
    _ensure_config(channel, config_name)['action'] = value
    await save_configuration()
    await send_message(app, channel, user, f"*Action* set to `{value}` in configuration `{config_name}`.", thread_ts)

async def set_action_target(app: AsyncApp, channel: Channel, config_name: str, target: str, user: User, thread_ts: str = "") -> None:
    target = strip_quotes(target).strip()
    if not target:
        await send_message(app, channel, user, "Invalid *target*. Must be non-empty.", thread_ts)
        return
    _ensure_config(channel, config_name)['action_target'] = target
    await save_configuration()
    await send_message(app, channel, user, f"*Action target* set to `{target}` in configuration `{config_name}`.", thread_ts)

async def add_button(app: AsyncApp, channel: Channel, config_name: str, label: str, spec: str, user: User, thread_ts: str = "") -> None:
    label = strip_quotes(label).strip()
    if not label:
        await send_message(app, channel, user, "Invalid *button label*. Must be non-empty.", thread_ts)
        return

    # spec is either "<action> [arg]" or a bare config name (back-compat).
    spec = spec.strip()
    parts = spec.split(None, 1)
    first = parts[0].lower() if parts else ""
    if first in BUTTON_ACTIONS:
        action = first
        value = strip_quotes(parts[1]).strip() if len(parts) > 1 else ""
    else:
        action = BUTTON_ACTION_CONFIG
        value = strip_quotes(spec).strip()

    if action in (BUTTON_ACTION_CONFIG, BUTTON_ACTION_MESSAGE) and not value:
        what = "a configuration name" if action == BUTTON_ACTION_CONFIG else "a message"
        await send_message(app, channel, user, f"Invalid *button*. `{action}` needs {what}.", thread_ts)
        return
    if action == BUTTON_ACTION_DELAY:
        try:
            minutes = int(value)
        except ValueError:
            await send_message(app, channel, user, "Invalid *button*. `delay` needs a number of minutes.", thread_ts)
            return
        if minutes <= 0 or minutes > 1440:
            await send_message(app, channel, user, "Invalid *button*. `delay` minutes must be between 1 and 1440.", thread_ts)
            return
        value = str(minutes)

    config = _ensure_config(channel, config_name)
    # Copy-on-write so we never mutate a shared default list.
    config['buttons'] = list(config.get('buttons') or []) + [{'label': label, 'action': action, 'value': value}]
    await save_configuration()

    warning = ""
    if action == BUTTON_ACTION_CONFIG and value not in channel.configs:
        warning = f" :warning: (configuration `{value}` does not exist yet)"
    descriptor = f"`{action}`" + (f" → `{value}`" if value else "")
    await send_message(app, channel, user, f"Added button `{label}` ({descriptor}) in configuration `{config_name}`{warning}.", thread_ts)

async def clear_buttons(app: AsyncApp, channel: Channel, config_name: str, user: User, thread_ts: str = "") -> None:
    _ensure_config(channel, config_name)['buttons'] = []
    await save_configuration()
    await send_message(app, channel, user, f"Cleared *buttons* in configuration `{config_name}`.", thread_ts)

async def set_default_button(app: AsyncApp, channel: Channel, config_name: str, label: str, user: User, thread_ts: str = "") -> None:
    label = strip_quotes(label).strip()
    if not label:
        await send_message(app, channel, user, "Invalid *default button*. Must reference a button label.", thread_ts)
        return
    config = _ensure_config(channel, config_name)
    config['default_button'] = label
    await save_configuration()
    warning = "" if _find_button_index(config, label) is not None else f" :warning: (no button labelled `{label}` yet)"
    await send_message(app, channel, user, f"*Default button* (auto-pressed on timeout) set to `{label}` in configuration `{config_name}`{warning}.", thread_ts)

async def clear_default_button(app: AsyncApp, channel: Channel, config_name: str, user: User, thread_ts: str = "") -> None:
    _ensure_config(channel, config_name)['default_button'] = ''
    await save_configuration()
    await send_message(app, channel, user, f"Cleared *default button* in configuration `{config_name}`.", thread_ts)

async def set_button_timeout(app: AsyncApp, channel: Channel, config_name: str, minutes_str: str, user: User, thread_ts: str = "") -> None:
    try:
        minutes = int(strip_quotes(minutes_str).strip())
    except ValueError:
        await send_message(app, channel, user, "Invalid *button timeout*. Must be a number of minutes between 0 and 1440.", thread_ts)
        return
    if minutes < 0 or minutes > 1440:
        await send_message(app, channel, user, "Invalid *button timeout*. Must be between 0 and 1440 minutes.", thread_ts)
        return
    _ensure_config(channel, config_name)['button_timeout'] = minutes * 60
    await save_configuration()
    label = f"`{minutes}` minutes" if minutes else "disabled"
    await send_message(app, channel, user, f"*Button timeout* set to {label} in configuration `{config_name}`.", thread_ts)

async def set_button_timeout_target(app: AsyncApp, channel: Channel, config_name: str, target: str, user: User, thread_ts: str = "") -> None:
    target = strip_quotes(target).strip()
    if not target:
        await send_message(app, channel, user, "Invalid *button timeout target*. Must reference a configuration name.", thread_ts)
        return
    _ensure_config(channel, config_name)['button_timeout_target'] = target
    await save_configuration()
    warning = "" if target in channel.configs else f" :warning: (configuration `{target}` does not exist yet)"
    await send_message(app, channel, user, f"*Button timeout target* set to `{target}` in configuration `{config_name}`{warning}.", thread_ts)

async def run_config_now(app: AsyncApp, opsgenie_token: str, channel: Channel, config_name: str, user: User, thread_ts: str = "") -> None:
    config = channel.configs.get(config_name)
    if not config:
        await send_message(app, channel, user, f"Configuration `{config_name}` not found.", thread_ts)
        return
    await send_message(app, channel, user, f"Running configuration `{config_name}` now…", thread_ts)
    await run_action(app, opsgenie_token, channel, config, config_name, context={'channel_id': channel.id, 'user': user})

async def process_mentions(app: AsyncApp, message: str) -> tuple[bool, str, str]:
    # Regular expression to find @username patterns
    matches = MENTION_PATTERN.findall(message)
    if matches:
        for user_match in matches:
            user = await get_user_by_name(app, user_match)
            if user.id:
                message = message.replace(f"@{user_match}", f"<@{user.id}>")
            else:
                log_error(f"Invalid *reply message*: username `{user_match}` not found")
                return False, f"{user_match} not found", ""
    return True, "", message

async def add_excluded_team(app: AsyncApp, channel: Channel, config_name: str, team: str, user: User, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    config = channel.configs[config_name]
    await update_user_cache(app)
    if team not in team_cache:
        await send_message(app, channel, user, f"Unknown team: `{team}`.", thread_ts)
        return
    if team in config['excluded_teams']:
        await send_message(app, channel, user, f"`{team}` is already excluded in configuration `{config_name}`.", thread_ts)
        return

    if len(config['included_teams']) > 0:
        await send_message(app, channel, user, f"Either set *included teams* or *excluded teams*, not both, in configuration `{config_name}`.", thread_ts)
        return

    config['excluded_teams'].append(team)
    await save_configuration()
    await send_message(app, channel, user, f"Added `{team}` to *excluded teams* in configuration `{config_name}`.", thread_ts)

async def clear_excluded_team(app: AsyncApp, channel: Channel, config_name: str, user: User, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    channel.configs[config_name]['excluded_teams'] = []
    await save_configuration()
    await send_message(app, channel, user, f"Cleared *excluded teams* in configuration `{config_name}`.", thread_ts)

async def add_included_team(app: AsyncApp, channel: Channel, config_name: str, team: str, user: User, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    config = channel.configs[config_name]
    await update_user_cache(app)
    if team not in team_cache:
        await send_message(app, channel, user, f"Unknown team: `{team}`.", thread_ts)
        return
    if team in config['included_teams']:
        await send_message(app, channel, user, f"`{team}` is already included in configuration `{config_name}`.", thread_ts)
        return

    if len(config['excluded_teams']) > 0:
        await send_message(app, channel, user, f"Either set *included teams* or *excluded teams*, not both, in configuration `{config_name}`.", thread_ts)
        return

    config['included_teams'].append(team)
    await save_configuration()
    await send_message(app, channel, user, f"Added `{team}` to *included teams* in configuration `{config_name}`.", thread_ts)

async def clear_included_team(app: AsyncApp, channel: Channel, config_name: str, user: User, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    channel.configs[config_name]['included_teams'] = []
    await save_configuration()
    await send_message(app, channel, user, f"Cleared *included teams* in configuration `{config_name}`.", thread_ts)

async def list_teams(app: AsyncApp, channel: Channel, user: User, thread_ts: str = "") -> None:
    await update_user_cache(app)
    message = f"*Available teams*:\n{'\n'.join(sorted(team_cache, key=lambda v: v.upper()))}"
    await send_message(app, channel, user, message, thread_ts)

async def list_opsgenie_schedules(app: AsyncApp, channel: Channel, user: User, thread_ts: str = "") -> None:
    opsgenie_token = get_env_var("OPSGENIE_TOKEN")
    if not opsgenie_token:
        await send_message(app, channel, user, "OpsGenie is not configured. Missing `OPSGENIE_TOKEN`.", thread_ts)
        return

    url = "https://api.opsgenie.com/v2/schedules"
    headers = {
        "Authorization": f"GenieKey {opsgenie_token}",
    }

    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            async with session.get(url, headers=headers) as response:
                if response.status != 200:
                    log_error(f"Failed to list OpsGenie schedules: {response.status}")
                    await send_message(app, channel, user, f"Failed to list OpsGenie schedules: HTTP {response.status}.", thread_ts)
                    return

                payload = await response.json()
    except Exception as e:
        log_error("Failed to list OpsGenie schedules:", e)
        await send_message(app, channel, user, "Failed to list OpsGenie schedules.", thread_ts)
        return

    schedules = payload.get("data", [])
    if not schedules:
        await send_message(app, channel, user, "No OpsGenie schedules found.", thread_ts)
        return

    schedule_names = sorted(
        (schedule.get("name", "").strip() for schedule in schedules if schedule.get("name")),
        key=str.casefold
    )
    if not schedule_names:
        await send_message(app, channel, user, "No OpsGenie schedules found.", thread_ts)
        return

    message = "*OpsGenie schedules*:\n" + "\n".join(f"`{name}`" for name in schedule_names)
    await send_message(app, channel, user, message, thread_ts)

async def get_team_of(app: AsyncApp, channel: Channel, username: str, user: User, thread_ts: str = "") -> None:
    message = None
    log_debug(channel, f"Looking up users from message `{username}`...")
    for match in ID_PATTERN.finditer(username):
        full_match = match.group(0)
        log_debug(channel, f"Found ID match: {full_match}...")
        id = match.group(1)
        if id and id[0] == '@':
            user_id = id[1:]
            log_debug(channel, f"Looking up user with ID {user_id}...")
            u = await get_user_by_id(app, user_id, channel)
            if u.id:
                log_debug(channel, f"Found user {u}")
                display_name = u.real_name if u.real_name else u.name
                msg = f"*{display_name}* (<@{u.id}>): `{u.team}`"
                if message is None:
                    message = msg
                else:
                    message += f"\n{msg}"
            else:
                log_error(f"Invalid request: username `{full_match}` not found")
    if message:
        await send_message(app, channel, user, message, thread_ts)
    else:
        await send_message(app, channel, user, f"Unknown user: `{username}`.", thread_ts)

async def show_config(app: AsyncApp, channel: Channel, user: User, thread_ts: str = "") -> None:
    if not channel.configs:
        message = f"There is no configuration for #{channel.name}."
        await send_message(app, channel, user, message, thread_ts)
        return

    def format_table_value(value, key_width: int) -> str:
        if isinstance(value, list):
            if not value:
                return '<None>'
            return f"\n{' ' * (key_width + 2)}".join(value)
        return value

    message = f"This is the configuration for #{channel.name}:"
    for config_name, config in sorted(channel.configs.items()):
        opsgenie_enabled = config.get('opsgenie')
        wait_time_minutes = config.get('wait_time') // 60
        included_teams = config.get('included_teams')
        excluded_teams = config.get('excluded_teams')
        include_bots = config.get('include_bots')
        only_work_days = config.get('only_work_days')
        hours = config.get('hours')
        pattern = config.get('pattern')
        pattern_case_sensitive = config.get('pattern_case_sensitive')
        reply_message = config.get('reply_message')
        forward_channel_id = config.get('forward_channel') or ''
        opsgenie_schedule_name = config.get('opsgenie_schedule_name')
        date_format = config.get('date_format') or DEFAULT_DATE_FORMAT
        time_format = config.get('time_format') or DEFAULT_TIME_FORMAT
        datetime_timezone = config.get('datetime_timezone') or '<server local>'
        datetime_locale = config.get('datetime_locale') or '<default>'
        opsgenie_priority = get_opsgenie_priority(config)
        replies_enabled = config.get('enabled', True)
        trigger = config.get('trigger', TRIGGER_MESSAGE)
        action = config.get('action', ACTION_REPLY)

        rows = [
            ("Trigger",            trigger),
            ("OpsGenie",           ('enabled' if opsgenie_enabled else 'disabled') + ('' if opsgenie_configured else ' (not configured)')),
            ("OpsGenie schedule",  opsgenie_schedule_name),
            ("OpsGenie priority",  opsgenie_priority),
            ("OpsGenie message",   config.get('opsgenie_message') or '<original message>'),
            ("Date format",        date_format),
            ("Time format",        time_format),
            ("Date/time timezone", datetime_timezone),
            ("Date/time locale",   datetime_locale),
            ("Wait time",          f"{wait_time_minutes} minutes"),
            ("Included teams",     included_teams),
            ("Excluded teams",     excluded_teams),
            ("Include bots",       'enabled' if include_bots else 'disabled'),
            ("Only work days",     'enabled' if only_work_days else 'disabled'),
            ("Work hours",         f"{hours[0]} - {hours[1]}" if len(hours) == 2 else 'all day'),
            ("Pattern",            f"{pattern} ({'case-sensitive' if pattern_case_sensitive else 'case-insensitive'})" if pattern else '<None>'),
        ]

        if trigger == TRIGGER_SCHEDULE:
            rows.append(("Cron", config.get('schedule_cron') or '<None>'))
            rows.append(("Schedule timezone", config.get('schedule_timezone') or '<server local>'))
        condition = config.get('condition') or ''
        if condition:
            negate = ' (negated)' if config.get('condition_negate') else ''
            rows.append(("Condition", f"{condition}{negate}"))
            if config.get('outlook_subject_pattern'):
                rows.append(("Outlook subject", config.get('outlook_subject_pattern')))
            if config.get('outlook_body_pattern'):
                rows.append(("Outlook body", config.get('outlook_body_pattern')))
        if action != ACTION_REPLY:
            rows.append(("Action", action))
            rows.append(("Action target", config.get('action_target') or '<None>'))
        buttons = config.get('buttons') or []
        if buttons:
            def _button_label(b):
                action, value = normalize_button(b)
                return f"{b.get('label')} → {action}" + (f":{value}" if value else "")
            rows.append(("Buttons", [_button_label(b) for b in buttons]))
            button_timeout_minutes = (config.get('button_timeout') or 0) // 60
            if button_timeout_minutes:
                kind, target = _escalation_kind(config)
                if kind == ESCALATION_BUTTON:
                    escalates_to = f"auto-press `{target}`"
                elif kind == ESCALATION_CONFIG:
                    escalates_to = f"run `{target}`"
                else:
                    escalates_to = "nothing"
                rows.append(("Button timeout", f"{button_timeout_minutes} minutes → {escalates_to}"))
            if config.get('default_button'):
                rows.append(("Default button", config.get('default_button')))
        key_width = max(len(label) for label, _ in rows)
        config_block = "\n".join(f"{label:<{key_width}}  {format_table_value(value, key_width)}" for label, value in rows)
        forward_channel_line = f"*Forward channel*: {f'<#{forward_channel_id}>' if forward_channel_id else '<None>'}"
        reply_line = f"*Reply message*:\n{reply_message}" if reply_message else "*Reply message*: <None>"
        enabled_label = 'enabled' if replies_enabled else 'disabled'
        quoted_block = (
            f"> {reply_line.replace('\n', '\n> ')}\n"
            f">\n"
            f"> {forward_channel_line}\n"
            f">\n"
            f"> *Settings*:\n"
        )
        message += (
            f"\n\n*Configuration*: `{config_name}` ({enabled_label})\n"
            f"{quoted_block}"
            f"```\n{config_block}\n```"
        )
    await send_message(app, channel, user, message, thread_ts)

async def send_message(app: AsyncApp, channel: Channel, user: User, text: str, thread_ts: str = "") -> None:
    log_debug(channel, f"Attempting to send message to #{channel.name}, user @{user.name}: {text.replace('\n', '\\n')}")
    retries = 3
    delay = 1
    for attempt in range(retries):
        try:
            if thread_ts:
                await app.client.chat_postMessage(
                    channel=channel.id,
                    thread_ts=thread_ts,
                    text=text,
                    mrkdwn=True
                )
            else:
                await app.client.chat_postEphemeral(
                    channel=channel.id,
                    user=user.id,
                    text=text,
                    mrkdwn=True
                )
            log_debug(channel, f"Successfully sent message to #{channel.name}, user @{user.name}")
            return  # Exit if successful
        except SlackApiError as e:
            if attempt < retries - 1:
                log_warning(f"Failed to send message in channel #{channel.name}, user @{user.name}, retrying in {delay} seconds ({attempt + 1}/{retries})...", e)
                await asyncio.sleep(delay)
                delay *= 2  # Exponential backoff
            else:
                log_error(f"Failed to send message in channel #{channel.name}, user @{user.name} after {retries} attempts:", e)

async def send_news_message(app: AsyncApp, channel: Channel, user: User, thread_ts: str = "") -> None:
    update_text = (
        "Hi! :wave: I am *Hutbot* :palm_up_hand::tophat: Here's what's :new::\n\n"
        "> :robot_face: *Triggers, actions & buttons*\n>\n"
        "> Rules can now run on a `schedule` (cron), DM a user or group, post to a channel, and carry interactive buttons (with an auto-press default + timeout escalation). See `/hutbot help`.\n>\n"
        "> :calendar: *OpsGenie date/time template variables and defaults*\n>\n"
        "> OpsGenie templates can now include current and next on-call start/end dates, times, and datetimes. Use `/hutbot [config] set datetime-format \"<date>\" \"<time>\" [<timezone> <locale>]` to set the defaults.\n>\n"
        "> :pencil: *Customize reply messages with `{{placeholders}}`*\n>\n"
        "> That means Hutbot can include details like the `{{user}}`, `{{team}}`, `{{channel}}` or `{{wait_minutes}}`, or even mention the person who is currently on-call `{{opsgenie_current_user}}` in the reply message :exploding_head:.\n>\n"
        "> :sparkles: Just configure an Opsgenie schedule and you are good to go.\n>\n"
        "> :list-item: *List available Opsgenie schedules*\n>\n"
        "> :telephone_receiver: *Print the current on-call user*\n"
        "> Use `/hutbot [config] on-call [schedule name]` to get the current OpsGenie on-call user as a Slack mention.\n>\n"
        "> :test_tube: *Preview your configured reply*\n"
        "> Use `/hutbot [config] test` or mention me with `@Hutbot [config] test <message>` to test reply templates and variables.\n>\n"
        "> :bug: *Hutbot now ONLY cancels replying, when the _expected_ team(s) have already replied* :lightbulb:\n>\n"
        "> Issue was:\n>\n"
        "> 1. Team *A* sends a message intended for Team *B*\n"
        "> 2. Someone else from Team *A* adds additional information\n"
        "> 3. Hutbot cancels the reply and does NOT remind Team *B* anymore :fail:\n"
    )
    await send_message(app, channel, user, update_text, thread_ts)

async def send_help_message(app: AsyncApp, channel: Channel, user: User, thread_ts: str = "") -> None:
    supported_template_variables = ", ".join(f"`{{{{{variable}}}}}`" for variable in sorted(SUPPORTED_TEMPLATE_VARIABLES))
    command_rows = [
        ("/hutbot show config", "Show all configurations."),
        ("/hutbot [config] enable opsgenie", "Enable OpsGenie alerts."),
        ("/hutbot [config] disable opsgenie", "Disable OpsGenie alerts."),
        ("/hutbot [config] set opsgenie-schedule <name>", "Set the OpsGenie schedule name."),
        ("/hutbot [config] set opsgenie-priority <P1-P5>", "Set the OpsGenie alert priority."),
        ("/hutbot [config] set opsgenie-message <text>", "Template for the alert text (default: the message)."),
        ("/hutbot [config] set datetime-format \"<date>\" \"<time>\" [<tz> <locale>]", "Set date/time formats."),
        ("/hutbot [config] set wait-time <minutes>", "Set reminder delay."),
        ("/hutbot list teams", "List available teams."),
        ("/hutbot list opsgenie-schedules", "List OpsGenie schedules."),
        ("/hutbot [config] on-call [schedule]", "Show current on-call user."),
        ("/hutbot team of <@user>", "Show a user's team."),
        ("/hutbot [config] add excluded-team <team>", "Add an ignored team."),
        ("/hutbot [config] clear excluded-teams", "Clear ignored teams."),
        ("/hutbot [config] add included-team <team>", "Add an allowed team."),
        ("/hutbot [config] clear included-teams", "Clear allowed teams."),
        ("/hutbot [config] enable bots", "Respond to bot messages."),
        ("/hutbot [config] disable bots", "Ignore bot messages."),
        ("/hutbot [config] enable only-work-days", "Respond only on work days."),
        ("/hutbot [config] disable only-work-days", "Respond on all days."),
        ("/hutbot [config] enable", "Enable sending replies for this config."),
        ("/hutbot [config] disable", "Disable sending replies for this config."),
        ("/hutbot [config] set work-hours <start> <end>", "Set active hours; 0:00 0:00 means all day."),
        ("/hutbot [config] set pattern \"<regex>\" [0|1]", "Set message pattern; 1 means case sensitive."),
        ("/hutbot [config] set message \"<reply message>\"", "Set reminder message."),
        ("/hutbot [config] set forward-channel <#channel>", "Forward replies to another channel."),
        ("/hutbot [config] clear forward-channel", "Remove the forward channel."),
        ("/hutbot [config] set trigger <message|schedule|manual>", "Set how the rule starts."),
        ("/hutbot [config] set cron <expr>", "Set the cron schedule, e.g. 0 9 * * 1-5."),
        ("/hutbot [config] set schedule-timezone <tz>", "Set the cron timezone (IANA name)."),
        ("/hutbot [config] set condition <none|outlook>", "Gate a schedule on a condition."),
        ("/hutbot [config] set outlook-subject <regex>", "Match Outlook event subject (stub)."),
        ("/hutbot [config] set outlook-body <regex>", "Match Outlook event body (stub)."),
        ("/hutbot [config] enable negate", "Invert the condition (e.g. no matching event)."),
        ("/hutbot [config] disable negate", "Stop inverting the condition."),
        ("/hutbot [config] set action <reply|dm-user|group-dm|post-channel>", "Set what the rule does."),
        ("/hutbot [config] set target <@user|@group|#channel>", "Set the action recipient."),
        ("/hutbot [config] add button \"<label>\" config <config>", "Button runs another config (e.g. an alert config)."),
        ("/hutbot [config] add button \"<label>\" ack [text]", "Button acknowledges/dismisses (stops escalation)."),
        ("/hutbot [config] add button \"<label>\" message <text>", "Button posts a fixed message."),
        ("/hutbot [config] add button \"<label>\" delay <minutes>", "Button delays the escalation."),
        ("/hutbot [config] clear buttons", "Remove all buttons."),
        ("/hutbot [config] set button-timeout <minutes>", "Escalate if no button is pressed in time."),
        ("/hutbot [config] set button-timeout-target <config>", "Config to run on button timeout."),
        ("/hutbot [config] set default-button \"<label>\"", "Auto-press this button on timeout."),
        ("/hutbot [config] run", "Run this configuration's action now."),
        ("/hutbot [config] test", "Preview configured reply."),
        ("@Hutbot [config] test <message>", "Preview reply with <message> as {{message}}."),
        ("/hutbot delete config <name>", "Delete a configuration."),
        ("/hutbot news", "Show what's new."),
        ("/hutbot help", "Show this help."),
    ]
    command_width = max(len(command) for command, _ in command_rows)
    command_usage = "\n".join(f"{command:<{command_width}}  {description}" for command, description in command_rows)
    help_text = (
        "Hi! :wave: I am *Hutbot* :palm_up_hand::tophat: Here's what I can do:\n\n"
        "*Show All Configurations:*\n"
        "> Either use the command `/hutbot` or just `@Hutbot` me.\n"
        "```/hutbot show config\n"
        "@Hutbot show config```\n"
        f"Displays all configurations for `#{channel.name}`.\n\n"
        "*Commands:*\n"
        f"```\n{command_usage}\n```\n\n"
        "`[config]` is optional; omitted commands use `default`.\n\n"
        f"Supported reply variables: {supported_template_variables}."
    )
    await send_message(app, channel, user, help_text, thread_ts)

def get_opsgenie_placeholder_variables(config: dict | None = None) -> dict[str, str]:
    schedule_name = (config or {}).get("opsgenie_schedule_name", "").strip()
    variables = {
        "opsgenie_schedule_name": schedule_name or UNKNOWN_OPSGENIE_SCHEDULE_PLACEHOLDER,
        "opsgenie_current_email": UNKNOWN_EMAIL_ONCALL_PLACEHOLDER,
        "opsgenie_current_name": UNKNOWN_NAME_ONCALL_PLACEHOLDER,
        "opsgenie_current_user": UNKNOWN_USER_ONCALL_PLACEHOLDER,
        "opsgenie_next_email": UNKNOWN_EMAIL_ONCALL_PLACEHOLDER,
        "opsgenie_next_name": UNKNOWN_NAME_ONCALL_PLACEHOLDER,
        "opsgenie_next_user": UNKNOWN_USER_ONCALL_PLACEHOLDER,
    }
    for variable in OPSGENIE_DATETIME_TEMPLATE_VARIABLES:
        variables[variable] = UNKNOWN_ONCALL_PERIOD_PLACEHOLDER
        variables[f"__{variable}_raw"] = ""
    return variables

def fill_opsgenie_period_variables(variables: dict[str, str], config: dict, prefix: str, period: OpsGeniePeriod) -> None:
    if not period.recipient_email:
        return

    variables[f"opsgenie_{prefix}_email"] = period.recipient_email
    variables[f"opsgenie_{prefix}_name"] = period.recipient_email
    if period.slack_user:
        variables[f"opsgenie_{prefix}_user"] = f"<@{period.slack_user.id}>"
        variables[f"opsgenie_{prefix}_name"] = period.slack_user.real_name if period.slack_user.real_name else period.slack_user.name

    for bound, value in (("start", period.start), ("end", period.end)):
        for part in ("date", "time", "datetime"):
            variable = f"opsgenie_{prefix}_{bound}_{part}"
            variables[f"__{variable}_raw"] = value or ""
            variables[variable] = format_opsgenie_template_datetime(value, variable, config)

async def resolve_slack_user_for_opsgenie_recipient(app: AsyncApp, recipient_email: str) -> User | None:
    slack_user = await get_user_by_email(app, recipient_email)
    if not slack_user.id:
        log_warning(f"Failed to map OpsGenie recipient '{recipient_email}' to a Slack user.")
        return None
    return slack_user

async def resolve_opsgenie_on_call(app: AsyncApp, opsgenie_token: str, schedule_name: str) -> tuple[str, User | None]:
    schedule_name = schedule_name.strip()
    if not opsgenie_token:
        log_warning(f"Cannot resolve OpsGenie schedule '{schedule_name}': missing token.")
        return "", None

    encoded_schedule_name = urllib.parse.quote(schedule_name, safe="")
    url = f"https://api.opsgenie.com/v2/schedules/{encoded_schedule_name}/on-calls"
    headers = {
        "Authorization": f"GenieKey {opsgenie_token}",
    }
    params = {
        "scheduleIdentifierType": "name",
        "flat": "true",
    }

    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            async with session.get(url, headers=headers, params=params) as response:
                if response.status != 200:
                    log_error(f"Failed to retrieve on-call recipients for OpsGenie schedule '{schedule_name}': {response.status}")
                    return "", None
                payload = await response.json()
    except Exception as e:
        log_error(f"Failed to retrieve on-call recipients for OpsGenie schedule '{schedule_name}':", e)
        return "", None

    recipients = payload.get("data", {}).get("onCallRecipients", [])
    if not recipients:
        log_warning(f"OpsGenie schedule '{schedule_name}' returned no current on-call recipients.")
        return "", None

    recipient_email = recipients[0].strip()
    if not recipient_email:
        return "", None

    return recipient_email, await resolve_slack_user_for_opsgenie_recipient(app, recipient_email)

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

def format_opsgenie_datetime(value: str, local_tz: datetime.tzinfo | None = None) -> str:
    return format_datetime_value(value, "datetime", local_tz=local_tz)

def merge_opsgenie_periods(periods: list[dict], current_index: int) -> tuple[str, str]:
    current_period = periods[current_index]
    recipient_name = current_period.get("recipient", {}).get("name", "").strip().casefold()
    merged_start = parse_opsgenie_datetime(current_period.get("startDate", ""))
    merged_end = parse_opsgenie_datetime(current_period.get("endDate", ""))
    if not recipient_name or merged_start is None or merged_end is None:
        return current_period.get("startDate", ""), current_period.get("endDate", "")

    first_period = current_period
    last_period = current_period

    for period in reversed(periods[:current_index]):
        period_recipient = period.get("recipient", {}).get("name", "").strip().casefold()
        period_start = parse_opsgenie_datetime(period.get("startDate", ""))
        period_end = parse_opsgenie_datetime(period.get("endDate", ""))
        if period_recipient != recipient_name or period_start is None or period_end is None or period_end != merged_start:
            break
        merged_start = period_start
        first_period = period

    for period in periods[current_index + 1:]:
        period_recipient = period.get("recipient", {}).get("name", "").strip().casefold()
        period_start = parse_opsgenie_datetime(period.get("startDate", ""))
        period_end = parse_opsgenie_datetime(period.get("endDate", ""))
        if period_recipient != recipient_name or period_start is None or period_end is None or period_start != merged_end:
            break
        merged_end = period_end
        last_period = period

    return first_period.get("startDate", ""), last_period.get("endDate", "")

def merge_opsgenie_periods_forward(periods: list[dict], current_index: int) -> tuple[str, str]:
    current_period = periods[current_index]
    recipient_name = current_period.get("recipient", {}).get("name", "").strip().casefold()
    merged_end = parse_opsgenie_datetime(current_period.get("endDate", ""))
    if not recipient_name or merged_end is None:
        return current_period.get("startDate", ""), current_period.get("endDate", "")

    last_period = current_period
    for period in periods[current_index + 1:]:
        period_recipient = period.get("recipient", {}).get("name", "").strip().casefold()
        period_start = parse_opsgenie_datetime(period.get("startDate", ""))
        period_end = parse_opsgenie_datetime(period.get("endDate", ""))
        if period_recipient != recipient_name or period_start is None or period_end is None or period_start != merged_end:
            break
        merged_end = period_end
        last_period = period

    return current_period.get("startDate", ""), last_period.get("endDate", "")

def find_opsgenie_on_call_period(data: dict, recipient_email: str, now: datetime.datetime | None = None) -> tuple[str, str]:
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=datetime.timezone.utc)

    rotations = []
    for timeline_name in ("finalTimeline", "baseTimeline"):
        rotations.extend(data.get(timeline_name, {}).get("rotations", []))

    periods = [period for rotation in rotations for period in rotation.get("periods", [])]
    if not periods:
        return "", ""

    recipient_email = recipient_email.casefold()

    for rotation in rotations:
        rotation_periods = sorted(
            rotation.get("periods", []),
            key=lambda period: parse_opsgenie_datetime(period.get("startDate", "")) or datetime.datetime.min.replace(tzinfo=datetime.timezone.utc),
        )
        for index, period in enumerate(rotation_periods):
            start = parse_opsgenie_datetime(period.get("startDate", ""))
            end = parse_opsgenie_datetime(period.get("endDate", ""))
            is_current = start is not None and end is not None and start <= now < end
            recipient_name = period.get("recipient", {}).get("name", "").strip().casefold()
            matches_recipient = bool(recipient_email and recipient_name == recipient_email)
            if is_current and matches_recipient:
                return merge_opsgenie_periods(rotation_periods, index)

    return "", ""

def find_opsgenie_upcoming_on_call_period(data: dict, now: datetime.datetime | None = None) -> tuple[str, str, str]:
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=datetime.timezone.utc)

    best_candidate = None
    for timeline_name in ("finalTimeline", "baseTimeline"):
        rotations = data.get(timeline_name, {}).get("rotations", [])
        for rotation in rotations:
            rotation_periods = sorted(
                rotation.get("periods", []),
                key=lambda period: parse_opsgenie_datetime(period.get("startDate", "")) or datetime.datetime.min.replace(tzinfo=datetime.timezone.utc),
            )
            threshold = now
            include_threshold = False
            for index, period in enumerate(rotation_periods):
                start = parse_opsgenie_datetime(period.get("startDate", ""))
                end = parse_opsgenie_datetime(period.get("endDate", ""))
                if start is not None and end is not None and start <= now < end:
                    _, merged_end = merge_opsgenie_periods(rotation_periods, index)
                    threshold = parse_opsgenie_datetime(merged_end) or end
                    include_threshold = True
                    break

            for index, period in enumerate(rotation_periods):
                start = parse_opsgenie_datetime(period.get("startDate", ""))
                end = parse_opsgenie_datetime(period.get("endDate", ""))
                recipient_email = period.get("recipient", {}).get("name", "").strip()
                if start is None or end is None or not recipient_email:
                    continue
                if start < threshold or (start == threshold and not include_threshold):
                    continue

                candidate = (start, rotation_periods, index, recipient_email)
                if best_candidate is None or candidate[0] < best_candidate[0]:
                    best_candidate = candidate

    if best_candidate is None:
        return "", "", ""

    _, rotation_periods, index, recipient_email = best_candidate
    start, end = merge_opsgenie_periods_forward(rotation_periods, index)
    return recipient_email, start, end

async def resolve_opsgenie_on_call_period(opsgenie_token: str, schedule_name: str, recipient_email: str) -> tuple[str, str]:
    schedule_name = schedule_name.strip()
    if not opsgenie_token:
        return "", ""

    encoded_schedule_name = urllib.parse.quote(schedule_name, safe="")
    url = f"https://api.opsgenie.com/v2/schedules/{encoded_schedule_name}/timeline"
    headers = {
        "Authorization": f"GenieKey {opsgenie_token}",
    }
    timeline_start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=90)
    params = {
        "identifierType": "name",
        "date": timeline_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "interval": "6",
        "intervalUnit": "months",
    }

    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            async with session.get(url, headers=headers, params=params) as response:
                if response.status != 200:
                    log_error(f"Failed to retrieve timeline for OpsGenie schedule '{schedule_name}': {response.status}")
                    return "", ""
                payload = await response.json()
    except Exception as e:
        log_error(f"Failed to retrieve timeline for OpsGenie schedule '{schedule_name}':", e)
        return "", ""

    return find_opsgenie_on_call_period(payload.get("data", {}), recipient_email)

async def resolve_opsgenie_upcoming_on_call_period(opsgenie_token: str, schedule_name: str) -> tuple[str, str, str]:
    schedule_name = schedule_name.strip()
    if not opsgenie_token:
        return "", "", ""

    encoded_schedule_name = urllib.parse.quote(schedule_name, safe="")
    url = f"https://api.opsgenie.com/v2/schedules/{encoded_schedule_name}/timeline"
    headers = {
        "Authorization": f"GenieKey {opsgenie_token}",
    }
    timeline_start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=90)
    params = {
        "identifierType": "name",
        "date": timeline_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "interval": "6",
        "intervalUnit": "months",
    }

    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            async with session.get(url, headers=headers, params=params) as response:
                if response.status != 200:
                    log_error(f"Failed to retrieve timeline for OpsGenie schedule '{schedule_name}': {response.status}")
                    return "", "", ""
                payload = await response.json()
    except Exception as e:
        log_error(f"Failed to retrieve timeline for OpsGenie schedule '{schedule_name}':", e)
        return "", "", ""

    return find_opsgenie_upcoming_on_call_period(payload.get("data", {}))

async def resolve_opsgenie_on_call_context(app: AsyncApp, opsgenie_token: str, schedule_name: str, include_next: bool = True) -> OpsGenieContext:
    schedule_name = schedule_name.strip()
    empty_period = OpsGeniePeriod("", None, "", "")
    current_period = empty_period
    next_period = empty_period

    recipient_email, slack_user = await resolve_opsgenie_on_call(app, opsgenie_token, schedule_name)
    if recipient_email:
        start, end = await resolve_opsgenie_on_call_period(opsgenie_token, schedule_name, recipient_email)
        current_period = OpsGeniePeriod(recipient_email, slack_user, start, end)

    if include_next:
        next_email, next_start, next_end = await resolve_opsgenie_upcoming_on_call_period(opsgenie_token, schedule_name)
        next_slack_user = await resolve_slack_user_for_opsgenie_recipient(app, next_email) if next_email else None
        next_period = OpsGeniePeriod(next_email, next_slack_user, next_start, next_end)

    return OpsGenieContext(schedule_name, current_period, next_period)

async def get_opsgenie_template_variables(app: AsyncApp, opsgenie_token: str, config: dict) -> dict[str, str]:
    schedule_name = config.get("opsgenie_schedule_name", "").strip()
    variables = get_opsgenie_placeholder_variables(config)
    if not schedule_name:
        return variables

    context = await resolve_opsgenie_on_call_context(app, opsgenie_token, schedule_name, include_next=True)
    fill_opsgenie_period_variables(variables, config, "current", context.current)
    fill_opsgenie_period_variables(variables, config, "next", context.next)

    return variables

async def send_current_on_call(app: AsyncApp, opsgenie_token: str, channel: Channel, config_name: str, schedule_name: str, user: User, thread_ts: str = "") -> None:
    config = channel.configs.get(config_name, DEFAULT_CONFIG.copy())
    schedule_name = schedule_name.strip() or config.get("opsgenie_schedule_name", "").strip()
    if not schedule_name:
        await send_message(app, channel, user, "No OpsGenie schedule configured. Use `/hutbot [config] set opsgenie-schedule <name>` or `/hutbot [config] on-call <schedule name>`.", thread_ts)
        return
    if not opsgenie_token:
        await send_message(app, channel, user, "OpsGenie is not configured. Missing `OPSGENIE_TOKEN`.", thread_ts)
        return

    recipient_email, slack_user = await resolve_opsgenie_on_call(app, opsgenie_token, schedule_name)
    if recipient_email:
        start, end = await resolve_opsgenie_on_call_period(opsgenie_token, schedule_name, recipient_email)
    else:
        recipient_email, start, end = await resolve_opsgenie_upcoming_on_call_period(opsgenie_token, schedule_name)
        if recipient_email:
            slack_user = await resolve_slack_user_for_opsgenie_recipient(app, recipient_email)

    if not recipient_email:
        await send_message(app, channel, user, f"Failed to resolve on-call user for OpsGenie schedule `{schedule_name}`.", thread_ts)
        return

    mention = f"<@{slack_user.id}>" if slack_user else recipient_email
    message = (
        f"*Schedule*: `{schedule_name}`\n"
        f"*On-call*: {mention}\n"
        f"*Start*: `{format_datetime_value(start, 'datetime', config)}`\n"
        f"*End*: `{format_datetime_value(end, 'datetime', config)}`"
    )
    await send_message(app, channel, user, message, thread_ts)

async def schedule_reply(app: AsyncApp, opsgenie_token: str, channel: Channel, config: dict, config_name: str, user: User, text: str, ts: str, wait_time_override: float | None = None) -> None:
    opsgenie_enabled = config.get('opsgenie')
    wait_time = config.get('wait_time')
    reply_message_template = config.get('reply_message')
    scheduled_message_key = (channel.id, ts, config_name)
    actual_wait = wait_time_override if wait_time_override is not None else wait_time
    log(f"Scheduling reply for message {ts} in channel #{channel.name} for config '{config_name}', user @{user.name}, wait time {wait_time // 60} mins, opsgenie {'enabled' if opsgenie_enabled else 'disabled'}{', but not configured' if opsgenie_enabled and not opsgenie_configured else ''}")
    try:
        await asyncio.sleep(actual_wait)
        permalink = await get_message_permalink(app, channel, ts)
        # Single unified send path: the reply (and any configured action/buttons)
        # goes through the action engine. The message context lets the reply thread
        # on the original message and reuse its template variables.
        posted = await run_action(app, opsgenie_token, channel, config, config_name, context={
            'user': user,
            'text': text,
            'ts': ts,
            'thread_ts': ts,
            'channel_id': channel.id,
            'permalink': permalink,
        })
        reply_message = (posted or {}).get('text', '')
        forward_channel_id = config.get('forward_channel')
        if forward_channel_id and reply_message:
            try:
                forward_text = f"{reply_message}\n\n*Original message in #{channel.name}:* {permalink}"
                await app.client.chat_postMessage(channel=forward_channel_id, text=forward_text, mrkdwn=True)
            except SlackApiError as e:
                log_error(f"Failed to forward reply to channel {forward_channel_id}:", e)
        # OpsGenie is fired inside run_action when this config has it enabled. To
        # button-gate an alert, put OpsGenie on a separate (manual) config and run
        # it from a button / button-timeout instead of on the reply config itself.
    except asyncio.CancelledError as e:
        log(f"Cancelling scheduled reply for message {ts} in channel #{channel.name} for config '{config_name}', user @{user.name}:", e)
    except Exception as e:
        log_error(f"Failed to send scheduled reply for message {ts} in channel #{channel.name} for config '{config_name}', user @{user.name}:", e)
    finally:
        scheduled_messages.pop(scheduled_message_key, None)
        _scheduled_replies_cache.pop(scheduled_message_key, None)
        await flush_replies_cache()

async def replace_ids(app: AsyncApp, channel: Channel | None, text: str) -> str:
    for match in ID_PATTERN.finditer(text):
        full_match = match.group(0)
        log_debug(channel, f"Found ID match: {full_match}...")
        id = match.group(1)
        handled = False
        if id and id[0] == '@':
            user_id = id[1:]
            log_debug(channel, f"Looking up user with ID {user_id}...")
            user = await get_user_by_id(app, user_id)
            if user.id:
                log_debug(channel, f"Found user {user}")
                text = text.replace(full_match, user.real_name)
                handled = True
        elif id and id[0] == '#':
            ch_id = id[1:]
            log_debug(channel, f"Looking up channel with ID {ch_id}...")
            ch = await get_channel_by_id(app, ch_id)
            if ch.id:
                log_debug(channel, f"Found channel {ch}")
                text = text.replace(full_match, f"#{ch.name}")
                handled = True
        elif id and id.startswith('!subteam^'):
            ug_id = id[9:]
            log_debug(channel, f"Looking up usergroup with ID {ug_id}...")
            ug = await get_usergroup_by_id(app, ug_id)
            if ug.id:
                log_debug(channel, f"Found usergroup {ug}")
                text = text.replace(full_match, f"@{ug.handle}")
                handled = True
        if not handled:
            alias = match.group(3)
            if alias:
                log_debug(channel, f"Fallback, replacing {full_match} with alias {alias}.")
                text = text.replace(full_match, alias)
            else:
                log_debug(channel, f"Fallback, replacing {full_match} with {id}.")
                text = text.replace(full_match, id)
    return text

async def clean_slack_text(app: AsyncApp, channel: Channel, text: str):
    # replace all kinds of <@ID> mentions
    text = await replace_ids(app, channel, text)

    # unescape any escaped formatting characters (like \*, \_, etc.)
    text = re.sub(r'\\([*_~`])', r'\1', text)

    # process all <...> elements to extract display text or URL
    def replace_link(match):
        parts = match.group(1).split('|', 1)
        if len(parts) == 1 and parts[0].startswith('http'):
            return "[URL]"
        return parts[1] if len(parts) > 1 and len(parts[1]) > 0 else parts[0]

    text = re.sub(r'<([^>]+)>', replace_link, text)

    # remove all remaining formatting characters and new lines
    text = re.sub(r'[*_~`]', '', text).replace('\n', ' ')

    # reduce duplicate spaces and trim
    text = re.sub(r'\s{2,}', ' ', text).strip()

    return text

def get_opsgenie_priority(config: dict | None) -> str:
    priority = (config or {}).get('opsgenie_priority', DEFAULT_OPSGENIE_PRIORITY)
    priority = priority.strip().upper() if isinstance(priority, str) else ""
    return priority if priority in OPSGENIE_PRIORITIES else DEFAULT_OPSGENIE_PRIORITY

async def post_opsgenie_alert(app: AsyncApp, opsgenie_token: str, channel: Channel, config: dict | None, user: User, text: str, ts: str, permalink: str) -> None:
    log_debug(channel, f"> {text.replace('\n', '\\n')}")
    text = await clean_slack_text(app, channel, text)
    log_debug(channel, f"< {text}")
    user_name = user.real_name if user.real_name else user.name
    priority = get_opsgenie_priority(config)
    url = 'https://api.opsgenie.com/v2/alerts'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'GenieKey {opsgenie_token}'
    }
    async with aiohttp.ClientSession() as session:
        try:
            data = {
                "message": f"#{channel.name}: {text}",
                "alias": f"hutbot: {user_name} in #{channel.name} {ts}",
                "description": f"{user_name} in #{channel.name}: {text}",
                "tags": ["Hutbot"],
                "details": {
                    "channel": f"#{channel.name}",
                    "sender": user_name,
                    "bot": "hutbot",
                    "permalink": permalink,
                },
                "priority": priority,
            }
            async with session.post(url, headers=headers, data=json.dumps(data)) as response:
                if response.status != 202:
                    log_error(f"Failed to send alert for message {ts} in channel #{channel.name}, user @{user.name}: {response.status}")
                else:
                    log(f"Successfully sent OpsGenie alert for message {ts} in channel #{channel.name}, user @{user.name} with status code {response.status}")
        except Exception as e:
            log_error(f"Failed to send alert for message {ts} in channel #{channel.name}, user @{user.name}:", e)

def extract_message_text(event: dict) -> str:
    text = event.get('text', '')
    if isinstance(text, str) and text.strip():
        return text

    attachment_texts = []
    fallback_texts = []
    for attachment in event.get('attachments', []):
        if not isinstance(attachment, dict):
            continue

        for field in ('pretext', 'title', 'text'):
            value = attachment.get(field, '')
            if isinstance(value, str) and value.strip():
                attachment_texts.append(value)

        fallback = attachment.get('fallback', '')
        if isinstance(fallback, str) and fallback.strip():
            fallback_texts.append(fallback)

    if attachment_texts:
        return "\n".join(attachment_texts).strip()

    return "\n".join(fallback_texts).strip()

async def route_message(app: AsyncApp, opsgenie_token: str, event: dict) -> None:
    subtype = event.get('subtype')
    previous_message = event.get('previous_message', {})
    channel_id = event.get('channel', '')
    user_id = event.get('user', '')
    bot_id = event.get('bot_id', '')
    ts = event.get('ts', '')
    thread_ts = event.get('thread_ts', '')
    text = extract_message_text(event)

    channel = await get_channel_by_id(app, channel_id)
    log_debug(channel, f"Received message event from #{channel.name}: {json.dumps(event)}")

    # Ignore messages from the bot itself
    if user_id == bot_user_id or bot_id == bot_user_id:
        log(f"Ignoring message from the bot from channel #{channel.name}.")
        return

    if subtype in IGNORED_MESSAGE_SUBTYPES:
        log(f"Ignoring message with subtype '{subtype}' for channel #{channel.name}.")
        return

    actor_is_bot = False
    user = None
    if user_id:
        user = await get_user_by_id(app, user_id)
        actor_is_bot = user_id == 'USLACKBOT'
    elif bot_id and (thread_ts or any(c.get('include_bots', False) for c in channel.configs.values())):
        actor_is_bot = True
        user = await get_user_by_id(app, bot_id)

    if subtype == 'message_deleted' and previous_message:
        # deleted message
        previous_user = await get_user_by_id(app, previous_message.get('user'))
        await handle_message_deletion(app, channel, previous_user, previous_message.get('ts'))
    elif user and is_command(text):
        # command
        await process_command(app, text, channel, user, ts, opsgenie_token, allow_test_message=True, command_ts=ts)
    elif user and thread_ts:
        # thread
        await handle_thread_response(app, channel, user, thread_ts, actor_is_bot)
    elif user and ts:
        # channel message
        await handle_channel_message(app, opsgenie_token, channel, user, text, ts, actor_is_bot)

def user_matches_actor_criteria(config: dict | None, user: User, actor_is_bot: bool = False) -> bool:
    if not config:
        return False

    if actor_is_bot and not config.get('include_bots', False):
        return False

    included_teams = config.get('included_teams', [])
    if included_teams and user.team not in included_teams:
        return False

    excluded_teams = config.get('excluded_teams', [])
    if excluded_teams and user.team in excluded_teams:
        return False

    return True

def get_actor_mismatch_reason(config: dict | None, user: User, actor_is_bot: bool = False) -> str:
    if not config:
        return "the configuration no longer exists"
    if actor_is_bot and not config.get('include_bots', False):
        return "bots are not included"
    included_teams = config.get('included_teams', [])
    if included_teams and user.team not in included_teams:
        return f"team '{user.team}' is not included"
    excluded_teams = config.get('excluded_teams', [])
    if excluded_teams and user.team in excluded_teams:
        return f"team '{user.team}' is excluded"
    return "the actor does not match the configuration"

async def handle_thread_response(app: AsyncApp, channel: Channel, reply_user: User, thread_ts: str, actor_is_bot: bool = False):
    keys_to_cancel = []
    for key, scheduled_reply in scheduled_messages.items():
        if key[0] != channel.id or key[1] != thread_ts:
            continue

        config = channel.configs.get(key[2])
        no_restrictions = (
            config is not None
            and not config.get('included_teams')
            and not config.get('excluded_teams')
            and (not actor_is_bot or not config.get('include_bots', False))
        )
        if no_restrictions or not user_matches_actor_criteria(config, reply_user, actor_is_bot):
            keys_to_cancel.append(key)

    if not keys_to_cancel:
        return

    message_user_id = scheduled_messages[keys_to_cancel[0]].user_id
    message_user = await get_user_by_id(app, message_user_id)
    log(f"Thread reply by user @{reply_user.name} detected. Cancelling {len(keys_to_cancel)} reminder(s) for message {thread_ts} in channel #{channel.name}, user @{message_user.name}")

    for key in keys_to_cancel:
        scheduled_messages[key].task.cancel()
        del scheduled_messages[key]

async def handle_channel_message(app: AsyncApp, opsgenie_token: str, channel: Channel, user: User, text: str, ts: str, actor_is_bot: bool = False):
    for config_name, config in channel.configs.items():
        if config.get('trigger', TRIGGER_MESSAGE) != TRIGGER_MESSAGE:
            # Schedule/manual rules are driven by the scheduler or buttons, not messages.
            continue
        if not config.get('enabled', True):
            log(f"Message from user @{user.name} in #{channel.name} will be ignored for config '{config_name}' because replies are disabled.")
            continue

        only_work_days = config.get('only_work_days')
        hours = config.get('hours')
        pattern = config.get('pattern')
        pattern_case_sensitive = config.get('pattern_case_sensitive')

        if only_work_days and not is_work_day():
            log(f"Message from user @{user.name} in #{channel.name} will be ignored for config '{config_name}' because of a non work day.")
            continue
        if len(hours) == 2 and not is_work_time(hours[0], hours[1]):
            log(f"Message from user @{user.name} in #{channel.name} will be ignored for config '{config_name}' because it was sent outside work time.")
            continue
        if not user_matches_actor_criteria(config, user, actor_is_bot):
            log(f"Message from user @{user.name} in #{channel.name} will be ignored for config '{config_name}' because {get_actor_mismatch_reason(config, user, actor_is_bot)}.")
            continue

        if pattern:
            flags = 0 if pattern_case_sensitive else re.IGNORECASE
            if not re.search(pattern, text, flags):
                log(f"Message from user @{user.name} in #{channel.name} will be ignored for config '{config_name}' because it does not match pattern '{pattern}'.")
                continue

        task = asyncio.create_task(schedule_reply(app, opsgenie_token, channel, config, config_name, user, text, ts))
        scheduled_messages[(channel.id, ts, config_name)] = ScheduledReply(task, user.id)
        send_at = datetime.datetime.now() + datetime.timedelta(seconds=config['wait_time'])
        _scheduled_replies_cache[(channel.id, ts, config_name)] = {
            'channel_id': channel.id,
            'ts': ts,
            'config_name': config_name,
            'user_id': user.id,
            'text': text,
            'send_at': send_at.isoformat(),
        }
        await flush_replies_cache()

async def handle_reaction_added(app: AsyncApp, event):
    item = event.get('item', {})
    channel_id = item.get('channel', '')
    user_id = event.get('user', '')
    ts = item.get('ts')
    channel = await get_channel_by_id(app, channel_id)
    reaction_user = await get_user_by_id(app, user_id)

    keys_to_cancel = []
    for key, scheduled_reply in scheduled_messages.items():
        if key[0] != channel_id or key[1] != ts:
            continue

        config = channel.configs.get(key[2])
        no_restrictions = config is not None and not config.get('included_teams') and not config.get('excluded_teams')
        if no_restrictions or not user_matches_actor_criteria(config, reaction_user):
            keys_to_cancel.append(key)

    if not keys_to_cancel:
        return

    message_user_id = scheduled_messages[keys_to_cancel[0]].user_id
    message_user = await get_user_by_id(app, message_user_id)
    log(f"Reaction added by user @{reaction_user.name}. Cancelling {len(keys_to_cancel)} reminder(s) for message {ts} in channel #{channel.name}, user @{message_user.name}")

    for key in keys_to_cancel:
        scheduled_messages[key].task.cancel()
        del scheduled_messages[key]

async def handle_message_deletion(app: AsyncApp, channel: Channel, previous_message_user: User, previous_message_ts: str):
    if previous_message_user.id == bot_user_id:
        log(f"Ignoring message deletion by bot from channel #{channel.name}.")
        return

    keys_to_cancel = []
    for key in scheduled_messages.keys():
        if key[0] == channel.id and key[1] == previous_message_ts:
            keys_to_cancel.append(key)

    if not keys_to_cancel:
        return

    log(f"Message deleted. Cancelling {len(keys_to_cancel)} reply/replies for message {previous_message_ts} in channel #{channel.name}, user @{previous_message_user.name}")
    for key in keys_to_cancel:
        scheduled_messages[key].task.cancel()
        del scheduled_messages[key]

async def handle_command_event(app: AsyncApp, command: dict, opsgenie_token: str = ""):
    text = command.get('text', '')
    channel_id = command.get('channel_id', '')
    user_id = command.get('user_id', '')

    channel = await get_channel_by_id(app, channel_id)
    user = await get_user_by_id(app, user_id)
    await process_command(app, text, channel, user, opsgenie_token=opsgenie_token)

# ---------------------------------------------------------------------------
# Trigger / condition / action engine
#
# A "rule" is a named channel config. Its `trigger` decides how it starts
# (message | schedule | manual), its `condition` optionally gates it, and its
# `action` decides what it does. Buttons and button-timeouts reference other
# named configs (trigger == manual) in the same channel as their targets.
# ---------------------------------------------------------------------------

def parse_channel_ref(channel_ref: str) -> str | None:
    """Resolve a `#channel` mention or raw `Cxxxx` id to a channel id."""
    for match in ID_PATTERN.finditer(channel_ref):
        ident = match.group(1)
        if ident and ident[0] == '#':
            return ident[1:]
    stripped = channel_ref.strip()
    if re.match(r'^[CGD][A-Z0-9]+$', stripped):
        return stripped
    return None

async def resolve_user_target(app: AsyncApp, target: str) -> User | None:
    target = target.strip()
    if not target:
        return None
    for match in ID_PATTERN.finditer(target):
        ident = match.group(1)
        if ident and ident[0] == '@':
            return await get_user_by_id(app, ident[1:])
    if re.match(r'^[UW][A-Z0-9]+$', target):
        return await get_user_by_id(app, target)
    if target.startswith('@'):
        return await get_user_by_name(app, normalize_id(target[1:]))
    if '@' in target:
        return await get_user_by_email(app, target)
    return await get_user_by_name(app, normalize_id(target))

async def resolve_usergroup_target(app: AsyncApp, target: str) -> Usergroup | None:
    target = target.strip()
    if not target:
        return None
    for match in re.finditer(r'<!subteam\^([A-Z0-9]+)', target):
        return await get_usergroup_by_id(app, match.group(1))
    if re.match(r'^S[A-Z0-9]+$', target):
        return await get_usergroup_by_id(app, target)
    handle = target[1:] if target.startswith('@') else target
    return await get_usergroup_by_handle(app, handle)

async def get_usergroup_members(app: AsyncApp, usergroup_id: str) -> list[str]:
    try:
        response = await app.client.usergroups_users_list(usergroup=usergroup_id)
        return response.get('users', [])
    except SlackApiError as e:
        log_error(f"Failed to fetch members of usergroup {usergroup_id}:", e)
        return []

def normalize_button(button: dict) -> tuple[str, str]:
    """Return (action, value) for a button, tolerating the legacy {label, target} form."""
    action = button.get('action') or BUTTON_ACTION_CONFIG
    if action == BUTTON_ACTION_CONFIG:
        value = button.get('value') or button.get('target') or ''
    else:
        value = button.get('value', '') or ''
    return action, value

def _find_button_index(config: dict | None, label: str) -> int | None:
    """Index of the first button matching `label` (case-insensitive), or None."""
    if not config or not label:
        return None
    target = label.strip().casefold()
    for i, button in enumerate(config.get('buttons') or []):
        if (button.get('label') or '').strip().casefold() == target:
            return i
    return None

def build_button_blocks(config: dict, def_channel_id: str, config_name: str, text: str) -> list | None:
    buttons = config.get('buttons') or []
    if not buttons:
        return None
    elements = []
    for i, button in enumerate(buttons):
        label = (button.get('label') or f'Button {i + 1}')[:75]
        # The button definition is resolved server-side from the originating config
        # by index, so the payload only needs to locate it (avoids Slack's 2000-char
        # value cap for long inline-message buttons).
        value = json.dumps({"channel": def_channel_id, "config": config_name, "index": i})
        elements.append({
            "type": "button",
            "text": {"type": "plain_text", "text": label, "emoji": True},
            "action_id": f"{BUTTON_ACTION_PREFIX}:{i}",
            "value": value[:2000],
        })
    return [
        {"type": "section", "text": {"type": "mrkdwn", "text": text}},
        {"type": "actions", "block_id": f"{BUTTON_ACTION_PREFIX}:{config_name}", "elements": elements},
    ]

async def _render_template(app: AsyncApp, opsgenie_token: str, channel: Channel, config: dict, config_name: str, context: dict | None, template: str) -> str:
    template = template or ''
    context = context or {}
    user = context.get('user')
    if user is None:
        user = User(id=bot_user_id or '', name='hutbot', real_name='Hutbot', team=TEAM_UNKNOWN)
    text = context.get('text', '')
    ts = context.get('ts', '')
    permalink = context.get('permalink')
    if permalink is None:
        permalink = await get_message_permalink(app, channel, ts) if ts else ""
    template_variables = find_template_variables(template)
    variables = await build_reply_template_variables(
        app, opsgenie_token, channel, config, config_name, user, text, ts, permalink,
        include_opsgenie=bool(OPSGENIE_TEMPLATE_VARIABLES.intersection(template_variables)),
    )
    return render_reply_message_template(template, variables, config)

async def render_action_text(app: AsyncApp, opsgenie_token: str, channel: Channel, config: dict, config_name: str, context: dict | None) -> str:
    return await _render_template(app, opsgenie_token, channel, config, config_name, context, config.get('reply_message') or '')

async def maybe_post_opsgenie_alert(app: AsyncApp, opsgenie_token: str, channel: Channel, config: dict, config_name: str, context: dict | None) -> None:
    """Fire an OpsGenie alert when a config that just ran has OpsGenie enabled.

    The alert text defaults to the (original) message in context; a non-empty
    `opsgenie_message` template overrides it. This makes OpsGenie a property of
    any config — buttons/timeouts that run an OpsGenie-enabled config alert, with
    no OpsGenie-specific escalation machinery.
    """
    if not (opsgenie_configured and config.get('opsgenie')):
        return
    context = context or {}
    user = context.get('user') or User(id='', name='hutbot', real_name='Hutbot', team=TEAM_UNKNOWN)
    template = config.get('opsgenie_message') or ''
    alert_text = await _render_template(app, opsgenie_token, channel, config, config_name, context, template) if template else context.get('text', '')
    log(f"Sending OpsGenie alert for config '{config_name}' in #{channel.name}.")
    await post_opsgenie_alert(app, opsgenie_token, channel, config, user, alert_text, context.get('ts', ''), context.get('permalink', ''))

async def _post_message(app: AsyncApp, channel_id: str, text: str, blocks: list | None, thread_ts: str = "") -> dict | None:
    kwargs = {"channel": channel_id, "text": text, "mrkdwn": True}
    if blocks:
        kwargs["blocks"] = blocks
    if thread_ts:
        kwargs["thread_ts"] = thread_ts
    retries = 3
    delay = 1
    for attempt in range(retries):
        try:
            response = await app.client.chat_postMessage(**kwargs)
            return {"channel": channel_id, "ts": response.get("ts")}
        except SlackApiError as e:
            if attempt < retries - 1:
                log_warning(f"Failed to post message to {channel_id}, retrying in {delay} seconds ({attempt + 1}/{retries})...", e)
                await asyncio.sleep(delay)
                delay *= 2
            else:
                log_error(f"Failed to post message to {channel_id} after {retries} attempts:", e)
                return None

async def action_reply(app: AsyncApp, channel: Channel, config: dict, context: dict | None, text: str, blocks: list | None) -> dict | None:
    context = context or {}
    candidate = context.get('thread_ts', '') or context.get('message_ts', '')
    # Only thread when the timestamp belongs to the channel we post to. A button
    # on a message sent to another conversation (DM/mpim/other channel) carries a
    # message_ts that is invalid as a thread_ts here, and Slack would reject it.
    ctx_channel = context.get('channel_id')
    thread_ts = candidate if candidate and (ctx_channel is None or ctx_channel == channel.id) else ""
    return await _post_message(app, channel.id, text, blocks, thread_ts)

async def action_dm_user(app: AsyncApp, channel: Channel, config: dict, text: str, blocks: list | None) -> dict | None:
    target = (config.get('action_target') or '').strip()
    user = await resolve_user_target(app, target)
    if not user or not user.id:
        log_error(f"Action dm_user: cannot resolve user target '{target}'.")
        return None
    try:
        opened = await app.client.conversations_open(users=[user.id])
        dm_id = opened['channel']['id']
    except SlackApiError as e:
        log_error(f"Action dm_user: failed to open DM with {target}:", e)
        return None
    return await _post_message(app, dm_id, text, blocks)

async def action_group_dm(app: AsyncApp, channel: Channel, config: dict, text: str, blocks: list | None) -> dict | None:
    target = (config.get('action_target') or '').strip()
    usergroup = await resolve_usergroup_target(app, target)
    if not usergroup or not usergroup.id:
        log_error(f"Action group_dm: cannot resolve usergroup '{target}'.")
        return None
    members = await get_usergroup_members(app, usergroup.id)
    if not members:
        log_error(f"Action group_dm: usergroup '{target}' has no members.")
        return None
    # Slack multi-person DMs allow at most 8 members besides the bot.
    if len(members) > 8:
        log_warning(f"Action group_dm: usergroup '{target}' has {len(members)} members; using first 8 (Slack mpim limit).")
        members = members[:8]
    try:
        opened = await app.client.conversations_open(users=members)
        mpim_id = opened['channel']['id']
    except SlackApiError as e:
        log_error(f"Action group_dm: failed to open group DM for '{target}':", e)
        return None
    return await _post_message(app, mpim_id, text, blocks)

async def action_post_channel(app: AsyncApp, channel: Channel, config: dict, text: str, blocks: list | None) -> dict | None:
    target = (config.get('action_target') or '').strip() or (config.get('forward_channel') or '')
    channel_id = parse_channel_ref(target)
    if not channel_id:
        log_error(f"Action post_channel: invalid channel target '{target}'.")
        return None
    return await _post_message(app, channel_id, text, blocks)

async def run_action(app: AsyncApp, opsgenie_token: str, channel: Channel, config: dict, config_name: str, context: dict | None = None, _depth: int = 0) -> dict | None:
    if _depth > 5:
        log_warning(f"Action chain too deep at config '{config_name}'; aborting to avoid loops.")
        return None
    action = config.get('action', ACTION_REPLY)
    text = await render_action_text(app, opsgenie_token, channel, config, config_name, context)
    blocks = build_button_blocks(config, channel.id, config_name, text)
    log(f"Running action '{action}' for config '{config_name}' in #{channel.name}.")
    if action == ACTION_REPLY:
        posted = await action_reply(app, channel, config, context, text, blocks)
    elif action == ACTION_DM_USER:
        posted = await action_dm_user(app, channel, config, text, blocks)
    elif action == ACTION_GROUP_DM:
        posted = await action_group_dm(app, channel, config, text, blocks)
    elif action == ACTION_POST_CHANNEL:
        posted = await action_post_channel(app, channel, config, text, blocks)
    else:
        log_error(f"Unknown action '{action}' for config '{config_name}'.")
        return None
    if not posted:
        return None
    if posted.get('ts') and config.get('buttons'):
        await register_escalation(app, opsgenie_token, posted['channel'], posted['ts'], channel.id, config_name, config, context)
    # OpsGenie is just a config property: any config that runs and has it enabled alerts.
    await maybe_post_opsgenie_alert(app, opsgenie_token, channel, config, config_name, context)
    return {**posted, 'text': text}

async def evaluate_condition(app: AsyncApp, config: dict) -> bool:
    condition = config.get('condition', CONDITION_NONE)
    if not condition:
        return True
    if condition == CONDITION_OUTLOOK:
        return await outlook.calendar_condition_met(
            config.get('outlook_subject_pattern', ''),
            config.get('outlook_body_pattern', ''),
            bool(config.get('condition_negate', False)),
        )
    log_warning(f"Unknown condition '{condition}'; treating as met.")
    return True

# ----- Button-press timeout tracking + persistence (mirrors scheduled replies) -----

async def load_button_cache() -> None:
    global _button_states_cache
    try:
        async with aiofiles.open(BUTTON_CACHE_FILE, 'r') as f:
            entries = json.loads(await f.read())
            _button_states_cache = {
                (e['posted_channel_id'], e['message_ts']): e for e in entries
            }
            log(f"Loaded {len(_button_states_cache)} pending button states from cache.")
    except FileNotFoundError:
        _button_states_cache = {}
    except Exception as e:
        log_error("Failed to load button states cache:", e)
        _button_states_cache = {}

async def flush_button_cache() -> None:
    try:
        async with aiofiles.open(BUTTON_CACHE_FILE, 'w') as f:
            await f.write(json.dumps(list(_button_states_cache.values()), indent=2))
    except Exception as e:
        log_error("Failed to flush button states cache:", e)

def _escalation_kind(config: dict) -> tuple[str, str]:
    """Decide what a buttoned message escalates to if no button is pressed in time."""
    default_button = config.get('default_button') or ''
    if default_button and _find_button_index(config, default_button) is not None:
        return ESCALATION_BUTTON, default_button
    target = config.get('button_timeout_target') or ''
    if target:
        return ESCALATION_CONFIG, target
    return ESCALATION_NONE, ''

async def register_escalation(app: AsyncApp, opsgenie_token: str, posted_channel_id: str, message_ts: str, def_channel_id: str, config_name: str, config: dict, context: dict | None = None) -> None:
    """Record a buttoned message so ack/delay/timeout can act on it later.

    A record is stored for every buttoned message (it carries the original message
    context that buttons/timeout pass on to the config they run); an escalation
    timer is started only when a timeout is set and there is something to escalate to.
    """
    if not message_ts or not posted_channel_id:
        return
    context = context or {}
    user = context.get('user')
    timeout = config.get('button_timeout') or 0
    kind, target = _escalation_kind(config)
    key = (posted_channel_id, message_ts)
    has_timer = timeout > 0 and kind != ESCALATION_NONE
    entry = {
        'posted_channel_id': posted_channel_id,
        'message_ts': message_ts,
        'def_channel_id': def_channel_id,
        'config_name': config_name,
        'escalation_kind': kind,
        'escalation_target': target,
        'timeout': timeout,
        'run_at': (datetime.datetime.now() + datetime.timedelta(seconds=timeout)).isoformat() if has_timer else '',
        'orig': {
            'user_id': user.id if user else context.get('user_id', ''),
            'text': context.get('text', ''),
            'ts': context.get('ts', ''),
            'permalink': context.get('permalink', ''),
        },
    }
    task = asyncio.create_task(_escalation_task(app, opsgenie_token, key, timeout)) if has_timer else None
    pending_buttons[key] = {'task': task, **entry}
    _button_states_cache[key] = entry
    await flush_button_cache()

async def _escalation_context(app: AsyncApp, entry: dict | None, posted_channel_id: str, message_ts: str, presser: User | None = None) -> dict:
    """Build a run_action context from the stored original-message context.

    A config run by a button/timeout sees the *original* message (text/ts/permalink/
    sender), so its templates and any OpsGenie alert reference it; the target's reply
    threads under the buttoned message.
    """
    orig = (entry or {}).get('orig', {})
    user = presser
    if user is None and orig.get('user_id'):
        user = await get_user_by_id(app, orig['user_id'])
    return {
        'channel_id': posted_channel_id,
        'thread_ts': message_ts,
        'user': user,
        'text': orig.get('text', ''),
        'ts': orig.get('ts', ''),
        'permalink': orig.get('permalink', ''),
    }

async def dispatch_button_action(app: AsyncApp, opsgenie_token: str, channel: Channel, posted_channel_id: str, message_ts: str, button: dict, run_context: dict) -> None:
    """Run a button's action. Shared by a real press and an auto-press on timeout.

    `delay` is handled by the caller (it is only meaningful for a live press).
    """
    action, value = normalize_button(button)
    if action == BUTTON_ACTION_CONFIG:
        target_config = channel.configs.get(value)
        if not target_config:
            log_warning(f"Button target config '{value}' not found in #{channel.name}.")
            return
        await run_action(app, opsgenie_token, channel, target_config, value, context=run_context)
    elif action in (BUTTON_ACTION_MESSAGE, BUTTON_ACTION_ACK):
        # message posts the configured text; ack just dismisses (optional text).
        if value:
            await _post_message(app, posted_channel_id, value, None, message_ts)
    else:
        log_warning(f"Unsupported button action '{action}' in #{channel.name}.")

async def _run_escalation(app: AsyncApp, opsgenie_token: str, entry: dict) -> None:
    kind = entry.get('escalation_kind', ESCALATION_NONE)
    channel = await get_channel_by_id(app, entry['def_channel_id'])
    posted_channel_id, message_ts = entry['posted_channel_id'], entry['message_ts']
    run_context = await _escalation_context(app, entry, posted_channel_id, message_ts)
    if kind == ESCALATION_BUTTON:
        # Auto-press the configured default button.
        src_config = channel.configs.get(entry.get('config_name'))
        idx = _find_button_index(src_config, entry.get('escalation_target', ''))
        if idx is None:
            log_warning(f"Default button '{entry.get('escalation_target')}' not found in #{channel.name}.")
            return
        log(f"No button pressed on message {message_ts}: auto-pressing '{entry.get('escalation_target')}' in #{channel.name}.")
        await dispatch_button_action(app, opsgenie_token, channel, posted_channel_id, message_ts, src_config['buttons'][idx], run_context)
    elif kind == ESCALATION_CONFIG:
        target = entry.get('escalation_target', '')
        target_config = channel.configs.get(target)
        if target_config:
            log(f"Escalating message {message_ts}: running '{target}' in #{channel.name}.")
            await run_action(app, opsgenie_token, channel, target_config, target, context=run_context)
        else:
            log_warning(f"Escalation target '{target}' not found in #{channel.name}.")

async def _escalation_task(app: AsyncApp, opsgenie_token: str, key: tuple, timeout: float) -> None:
    try:
        await asyncio.sleep(timeout)
        entry = pending_buttons.get(key)
        if entry:
            log(f"No button pressed on message {key[1]} within timeout; escalating.")
            await _run_escalation(app, opsgenie_token, entry)
    except asyncio.CancelledError:
        return
    except Exception as e:
        log_error(f"Escalation task failed for message {key[1]}:", e)
    finally:
        pending_buttons.pop(key, None)
        _button_states_cache.pop(key, None)
        await flush_button_cache()

async def cancel_pending_button(posted_channel_id: str, message_ts: str) -> None:
    key = (posted_channel_id, message_ts)
    entry = pending_buttons.pop(key, None)
    _button_states_cache.pop(key, None)
    if entry:
        if entry.get('task'):
            entry['task'].cancel()
        await flush_button_cache()

async def reschedule_escalation(app: AsyncApp, opsgenie_token: str, posted_channel_id: str, message_ts: str, minutes: int) -> bool:
    key = (posted_channel_id, message_ts)
    entry = pending_buttons.get(key)
    if not entry:
        log_warning(f"No pending escalation to delay for message {message_ts}.")
        return False
    if entry.get('task'):
        entry['task'].cancel()
    extra = minutes * 60
    record = {k: v for k, v in entry.items() if k != 'task'}
    record['timeout'] = extra
    record['run_at'] = (datetime.datetime.now() + datetime.timedelta(seconds=extra)).isoformat()
    task = asyncio.create_task(_escalation_task(app, opsgenie_token, key, extra))
    pending_buttons[key] = {'task': task, **record}
    _button_states_cache[key] = record
    await flush_button_cache()
    return True

async def restore_pending_buttons(app: AsyncApp, opsgenie_token: str) -> None:
    entries = list(_button_states_cache.items())
    invalid_keys = []
    restored = 0
    log(f"Restoring {len(entries)} pending button escalations from cache...")
    for key, entry in entries:
        def_channel_id = entry.get('def_channel_id')
        if not def_channel_id or def_channel_id not in channel_config:
            log_warning(f"Skipping cached button state for message {entry.get('message_ts')}: channel {def_channel_id} no longer configured.")
            invalid_keys.append(key)
            continue
        run_at = entry.get('run_at')
        if run_at:
            remaining = max(0.0, (datetime.datetime.fromisoformat(run_at) - datetime.datetime.now()).total_seconds())
            task = asyncio.create_task(_escalation_task(app, opsgenie_token, key, remaining))
        else:
            task = None
        pending_buttons[key] = {'task': task, **entry}
        restored += 1
    for key in invalid_keys:
        _button_states_cache.pop(key, None)
    if invalid_keys:
        await flush_button_cache()
    log(f"Restored {restored} pending button escalations.")

# ----- Scheduler (cron triggers) -----

def _resolve_schedule_timezone(config: dict):
    tz_name = config.get('schedule_timezone') or config.get('datetime_timezone') or ''
    if tz_name:
        try:
            return ZoneInfo(tz_name)
        except ZoneInfoNotFoundError:
            log_warning(f"Unknown schedule timezone '{tz_name}'; using server local time.")
    return None

def _cron_due(cron_expr: str, config: dict, last: datetime.datetime, now: datetime.datetime) -> bool:
    tz = _resolve_schedule_timezone(config)
    base = last.astimezone(tz) if tz else last.astimezone()
    current = now.astimezone(tz) if tz else now.astimezone()
    try:
        nxt = croniter(cron_expr, base).get_next(datetime.datetime)
    except (ValueError, KeyError) as e:
        log_warning(f"Invalid cron expression '{cron_expr}': {e}")
        return False
    return nxt <= current

async def run_scheduler(app: AsyncApp, opsgenie_token: str) -> None:
    global _scheduler_last_check
    if croniter is None:
        log_warning("croniter is not installed; scheduled triggers are disabled.")
        return
    _scheduler_last_check = datetime.datetime.now(datetime.timezone.utc)
    log(f"Scheduler started (interval {SCHEDULER_INTERVAL}s).")
    while True:
        await asyncio.sleep(SCHEDULER_INTERVAL)
        try:
            await scheduler_tick(app, opsgenie_token)
        except Exception as e:
            log_error("Scheduler tick failed:", e)

async def scheduler_tick(app: AsyncApp, opsgenie_token: str) -> None:
    global _scheduler_last_check
    now = datetime.datetime.now(datetime.timezone.utc)
    last = _scheduler_last_check or now
    _scheduler_last_check = now
    for channel_id, configs in list(channel_config.items()):
        for config_name, config in list(configs.items()):
            if config.get('trigger') != TRIGGER_SCHEDULE:
                continue
            if not config.get('enabled', True):
                continue
            cron_expr = config.get('schedule_cron') or ''
            if not cron_expr:
                continue
            if croniter is not None and not croniter.is_valid(cron_expr):
                log_warning(f"Schedule '{config_name}' in channel {channel_id} has invalid cron '{cron_expr}'.")
                continue
            if not _cron_due(cron_expr, config, last, now):
                continue
            channel = await get_channel_by_id(app, channel_id)
            if not await evaluate_condition(app, config):
                log(f"Schedule '{config_name}' in #{channel.name} fired but condition not met.")
                continue
            log(f"Schedule '{config_name}' in #{channel.name} firing.")
            try:
                await run_action(app, opsgenie_token, channel, config, config_name, context={'channel_id': channel_id})
            except Exception as e:
                log_error(f"Schedule '{config_name}' action failed:", e)

async def handle_button_press(app: AsyncApp, opsgenie_token: str, body: dict, action: dict) -> None:
    container = body.get('container', {}) or {}
    message = body.get('message', {}) or {}
    posted_channel_id = (body.get('channel', {}) or {}).get('id') or container.get('channel_id', '')
    message_ts = container.get('message_ts') or message.get('ts', '')

    payload = {}
    raw_value = action.get('value', '')
    if raw_value:
        try:
            payload = json.loads(raw_value)
        except json.JSONDecodeError:
            payload = {}
    def_channel_id = payload.get('channel') or posted_channel_id
    src_config_name = payload.get('config') or ''
    index = payload.get('index')

    presser_id = (body.get('user', {}) or {}).get('id', '')
    presser = await get_user_by_id(app, presser_id) if presser_id else None
    presser_name = presser.name if presser else '?'

    channel = await get_channel_by_id(app, def_channel_id)
    src_config = channel.configs.get(src_config_name)
    buttons = (src_config or {}).get('buttons') or []
    if index is None or not isinstance(index, int) or index < 0 or index >= len(buttons):
        log_warning(f"Button pressed by @{presser_name} could not be resolved (config '{src_config_name}', index {index}).")
        return
    btn_action, btn_value = normalize_button(buttons[index])
    entry = pending_buttons.get((posted_channel_id, message_ts))
    log(f"Button '{buttons[index].get('label')}' ({btn_action}) pressed by @{presser_name} in #{channel.name}.")

    if btn_action == BUTTON_ACTION_DELAY:
        try:
            minutes = int(btn_value)
        except ValueError:
            minutes = 0
        if minutes > 0:
            await reschedule_escalation(app, opsgenie_token, posted_channel_id, message_ts, minutes)
        return

    # Every other button stops the pending escalation, then runs its action.
    run_context = await _escalation_context(app, entry, posted_channel_id, message_ts, presser)
    await cancel_pending_button(posted_channel_id, message_ts)
    await dispatch_button_action(app, opsgenie_token, channel, posted_channel_id, message_ts, buttons[index], run_context)

def register_app_handlers(app: AsyncApp, opsgenie_token: str = "") -> None:

    @app.event("message")
    async def handle_message_events(body, logger):
        await route_message(app, opsgenie_token, body.get('event', {}) if body else {})

    @app.event("reaction_added")
    async def handle_reaction_added_events(body, logger):
        await handle_reaction_added(app, body.get('event', {}) if body else {})

    @app.command("/hutbot")
    async def handle_command(ack, body, logger):
        await ack()
        await handle_command_event(app, body, opsgenie_token)

    @app.action(re.compile(rf"^{BUTTON_ACTION_PREFIX}:"))
    async def handle_button_action(ack, body, action, logger):
        await ack()
        await handle_button_press(app, opsgenie_token, body, action)

async def restore_scheduled_replies(app: AsyncApp, opsgenie_token: str) -> None:
    entries = list(_scheduled_replies_cache.items())
    invalid_keys = []
    restored = 0
    log(f"Restoring {len(entries)} scheduled replies from cache...")
    for key, entry in entries:
        channel_id = entry['channel_id']
        ts = entry['ts']
        config_name = entry['config_name']
        if channel_id not in channel_config or config_name not in channel_config[channel_id]:
            log_warning(f"Skipping cached reply for message {ts}: channel {channel_id} / config '{config_name}' no longer configured.")
            invalid_keys.append(key)
            continue
        config = channel_config[channel_id][config_name]
        channel = await get_channel_by_id(app, channel_id)
        user = await get_user_by_id(app, entry['user_id'])
        send_at = datetime.datetime.fromisoformat(entry['send_at'])
        remaining = max(0.0, (send_at - datetime.datetime.now()).total_seconds())
        log(f"Restoring reply for message {ts} in channel #{channel.name} for config '{config_name}', user @{user.name}, remaining {remaining:.0f}s.")
        task = asyncio.create_task(schedule_reply(app, opsgenie_token, channel, config, config_name, user, entry['text'], ts, wait_time_override=remaining))
        scheduled_messages[(channel.id, ts, config_name)] = ScheduledReply(task, user.id)
        restored += 1
    for key in invalid_keys:
        _scheduled_replies_cache.pop(key, None)
    if invalid_keys:
        await flush_replies_cache()
    log(f"Restored {restored} scheduled replies.")

async def send_heartbeat(opsgenie_token: str, opsgenie_heartbeat_name: str) -> None:
    url = 'https://api.opsgenie.com/v2/heartbeats/' + opsgenie_heartbeat_name + '/ping'
    headers = {
        'Authorization': f'GenieKey {opsgenie_token}'
    }
    log(f"Starting to send heartbeat to {url}...")
    async with aiohttp.ClientSession() as session:
        while True:
            try:
                async with session.get(url, headers=headers) as response:
                    if response.status != 202:
                        log_error(f"Failed to send heartbeat: {response.status}")
            except Exception as e:
                log_error(f"Exception while sending heartbeat:", e)
            await asyncio.sleep(60)

# ===================================================================
# Web UI backend — channel membership, validation, and config writes.
# The aiohttp server itself lives in webui.py; these helpers are the
# bridge to the live bot state and reuse the same validation as the
# slash-command setters above.
# ===================================================================

# Slack member ids per channel, cached briefly so listing a user's
# channels doesn't hammer conversations.members on every UI request.
_channel_members_cache: dict[str, tuple[float, set]] = {}
_CHANNEL_MEMBERS_TTL = 300.0

# Serializes UI config writes (mutate channel_config + save_configuration).
_config_write_lock = asyncio.Lock()


async def get_channel_members(app: AsyncApp, channel_id: str) -> set:
    """Set of Slack member ids for a channel, cached for _CHANNEL_MEMBERS_TTL seconds."""
    now = time.monotonic()
    cached = _channel_members_cache.get(channel_id)
    if cached and (now - cached[0]) < _CHANNEL_MEMBERS_TTL:
        return cached[1]
    members: set = set()
    cursor = None
    try:
        while True:
            response = await app.client.conversations_members(channel=channel_id, cursor=cursor, limit=200)
            members.update(response.get('members', []) or [])
            cursor = response.get('response_metadata', {}).get('next_cursor')
            if not cursor:
                break
    except SlackApiError as e:
        log_error(f"Failed to fetch members for channel {channel_id}:", e)
        return cached[1] if cached else set()
    _channel_members_cache[channel_id] = (now, members)
    return members


async def is_user_in_channel(app: AsyncApp, channel_id: str, user_id: str) -> bool:
    if not user_id:
        return False
    return user_id in await get_channel_members(app, channel_id)


async def list_user_config_channels(app: AsyncApp, user: User) -> list[dict]:
    """Channels that have a Hutbot config and that `user` belongs to, sorted by name."""
    channels = []
    for channel_id in list(channel_config.keys()):
        if await is_user_in_channel(app, channel_id, user.id):
            channels.append({'id': channel_id, 'name': await get_channel_name(app, channel_id)})
    channels.sort(key=lambda c: c['name'].lower())
    return channels


def _ui_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in ('1', 'true', 'yes', 'on')
    return False


def _ui_team_list(value) -> list[str]:
    if not isinstance(value, list):
        return []
    cleaned = []
    for team in value:
        team = str(team).strip()
        if team and team not in cleaned:
            cleaned.append(team)
    return cleaned


async def validate_config_payload(payload: dict, app: AsyncApp, channel_id: str = "") -> tuple[dict | None, dict]:
    """Validate a config dict from the web UI, mirroring the slash-command setters.

    Returns ``(clean_config, {})`` on success or ``(None, {field: message})`` on failure.
    Values use the persisted shape: ``wait_time`` and ``button_timeout`` are in seconds.
    """
    if not isinstance(payload, dict):
        return None, {'_': "Expected a configuration object."}

    errors: dict[str, str] = {}
    cfg = copy.deepcopy(DEFAULT_CONFIG)

    def get(key):
        return payload.get(key, DEFAULT_CONFIG.get(key))

    for key in ('enabled', 'include_bots', 'only_work_days', 'debug',
                'opsgenie', 'condition_negate', 'pattern_case_sensitive'):
        cfg[key] = _ui_bool(get(key))

    # wait_time (stored as seconds; 1..1440 minutes)
    try:
        wait_time = int(get('wait_time'))
    except (TypeError, ValueError):
        errors['wait_time'] = "Reminder delay must be a number."
    else:
        if wait_time < 60 or wait_time > 86400:
            errors['wait_time'] = "Reminder delay must be between 1 and 1440 minutes."
        else:
            cfg['wait_time'] = wait_time

    # button_timeout (stored as seconds; 0..1440 minutes, 0 = disabled)
    try:
        button_timeout = int(get('button_timeout'))
    except (TypeError, ValueError):
        errors['button_timeout'] = "Button timeout must be a number."
    else:
        if button_timeout < 0 or button_timeout > 86400:
            errors['button_timeout'] = "Button timeout must be between 0 and 1440 minutes."
        else:
            cfg['button_timeout'] = button_timeout

    # reply_message — resolve @mentions and validate template variables
    reply_message = get('reply_message')
    if not isinstance(reply_message, str) or not reply_message.strip():
        errors['reply_message'] = "Reply message can't be empty."
    else:
        ok, mention_error, processed = await process_mentions(app, reply_message)
        if not ok:
            errors['reply_message'] = f"Unknown user mention: {mention_error}."
        else:
            template_error = validate_template_expressions(processed)
            if template_error:
                errors['reply_message'] = template_error
            else:
                cfg['reply_message'] = processed

    # opsgenie_message — template only (empty = original message)
    opsgenie_message = get('opsgenie_message') or ""
    if not isinstance(opsgenie_message, str):
        errors['opsgenie_message'] = "OpsGenie message must be text."
    else:
        opsgenie_message = opsgenie_message.strip()
        template_error = validate_template_expressions(opsgenie_message) if opsgenie_message else ""
        if template_error:
            errors['opsgenie_message'] = template_error
        else:
            cfg['opsgenie_message'] = opsgenie_message

    cfg['opsgenie_schedule_name'] = str(get('opsgenie_schedule_name') or "").strip()

    priority = str(get('opsgenie_priority') or DEFAULT_OPSGENIE_PRIORITY).strip().upper()
    if priority not in OPSGENIE_PRIORITIES:
        errors['opsgenie_priority'] = "Priority must be one of " + ", ".join(sorted(OPSGENIE_PRIORITIES)) + "."
    else:
        cfg['opsgenie_priority'] = priority

    cfg['date_format'] = str(get('date_format') or "")
    cfg['time_format'] = str(get('time_format') or "")

    tz_name = str(get('datetime_timezone') or "").strip()
    if tz_name:
        try:
            validate_timezone_name(tz_name)
            cfg['datetime_timezone'] = tz_name
        except ValueError as e:
            errors['datetime_timezone'] = str(e)
    else:
        cfg['datetime_timezone'] = ""

    locale_value = str(get('datetime_locale') or "").strip()
    if locale_value:
        try:
            cfg['datetime_locale'] = normalize_locale_name(locale_value)
        except ValueError as e:
            errors['datetime_locale'] = str(e)
    else:
        cfg['datetime_locale'] = ""

    sched_tz = str(get('schedule_timezone') or "").strip()
    if sched_tz:
        try:
            ZoneInfo(sched_tz)
            cfg['schedule_timezone'] = sched_tz
        except ZoneInfoNotFoundError:
            errors['schedule_timezone'] = f"Unknown timezone `{sched_tz}`. Use an IANA name, e.g. Europe/Berlin."
    else:
        cfg['schedule_timezone'] = ""

    cron_expr = str(get('schedule_cron') or "").strip()
    if cron_expr and croniter is not None and not croniter.is_valid(cron_expr):
        errors['schedule_cron'] = "Invalid cron expression. Use 5 fields, e.g. `0 9 * * 1-5`."
    else:
        cfg['schedule_cron'] = cron_expr

    trigger = str(get('trigger') or TRIGGER_MESSAGE).strip().lower()
    trigger = {'msg': TRIGGER_MESSAGE, 'cron': TRIGGER_SCHEDULE, 'scheduled': TRIGGER_SCHEDULE}.get(trigger, trigger)
    if trigger not in TRIGGERS:
        errors['trigger'] = "Trigger must be one of " + ", ".join(sorted(TRIGGERS)) + "."
    else:
        cfg['trigger'] = trigger

    condition = str(get('condition') or CONDITION_NONE).strip().lower()
    condition = {'none': CONDITION_NONE, 'off': CONDITION_NONE, '': CONDITION_NONE,
                 'outlook': CONDITION_OUTLOOK, 'calendar': CONDITION_OUTLOOK,
                 'outlook_calendar': CONDITION_OUTLOOK}.get(condition, condition)
    if condition not in CONDITIONS:
        errors['condition'] = "Condition must be `none` or `outlook`."
    else:
        cfg['condition'] = condition

    for field in ('outlook_subject_pattern', 'outlook_body_pattern'):
        value = str(get(field) or "")
        if value:
            try:
                re.compile(value)
            except re.error as e:
                errors[field] = f"Invalid pattern: {e}"
                continue
        cfg[field] = value

    action = str(get('action') or ACTION_REPLY).strip().lower().replace('-', '_')
    if action not in ACTIONS:
        errors['action'] = "Action must be one of " + ", ".join(sorted(ACTIONS)) + "."
    else:
        cfg['action'] = action

    action_target = str(get('action_target') or "").strip()
    if action in (ACTION_DM_USER, ACTION_GROUP_DM, ACTION_POST_CHANNEL) and not action_target:
        errors['action_target'] = "This action needs a target (a user, user group, or channel)."
    else:
        cfg['action_target'] = action_target

    pattern = get('pattern')
    if pattern in (None, ""):
        cfg['pattern'] = None
    elif not isinstance(pattern, str):
        errors['pattern'] = "Pattern must be text."
    else:
        try:
            re.compile(pattern)
            cfg['pattern'] = pattern
        except re.error as e:
            errors['pattern'] = f"Invalid pattern: {e}"

    forward_channel = str(get('forward_channel') or "").strip()
    if forward_channel and not re.match(r'^C[A-Z0-9]+$', forward_channel):
        errors['forward_channel'] = "Use a Slack channel ID like `C0123ABCD`."
    else:
        cfg['forward_channel'] = forward_channel

    await update_user_cache(app)
    included = _ui_team_list(get('included_teams'))
    excluded = _ui_team_list(get('excluded_teams'))
    if included and excluded:
        errors['included_teams'] = "Set included teams or excluded teams, not both."
    unknown_included = [team for team in included if team not in team_cache]
    unknown_excluded = [team for team in excluded if team not in team_cache]
    if unknown_included:
        errors['included_teams'] = "Unknown team(s): " + ", ".join(unknown_included) + "."
    if unknown_excluded:
        errors['excluded_teams'] = "Unknown team(s): " + ", ".join(unknown_excluded) + "."
    if 'included_teams' not in errors:
        cfg['included_teams'] = included
    if 'excluded_teams' not in errors:
        cfg['excluded_teams'] = excluded

    hours_value = get('hours')
    if hours_value in (None, "", []):
        cfg['hours'] = []
    elif isinstance(hours_value, list) and len(hours_value) == 2:
        start_time = parse_time(str(hours_value[0]))
        end_time = parse_time(str(hours_value[1]))
        if not start_time or not end_time:
            errors['hours'] = "Use times like `09:00` and `17:00`."
        else:
            normalized = [start_time.strftime("%H:%M"), end_time.strftime("%H:%M")]
            cfg['hours'] = [] if normalized == ["00:00", "00:00"] else normalized
    else:
        errors['hours'] = "Work hours need a start and an end time."

    buttons_value = get('buttons')
    if buttons_value in (None, ""):
        buttons_value = []
    clean_buttons = []
    if not isinstance(buttons_value, list):
        errors['buttons'] = "Buttons must be a list."
    else:
        for i, button in enumerate(buttons_value):
            if not isinstance(button, dict):
                errors[f'buttons.{i}'] = "Each button needs a label and an action."
                continue
            label = str(button.get('label') or "").strip()
            button_action = str(button.get('action') or BUTTON_ACTION_CONFIG).strip().lower()
            value = str(button.get('value') or "").strip()
            if not label:
                errors[f'buttons.{i}'] = "Button label can't be empty."
                continue
            if button_action not in BUTTON_ACTIONS:
                errors[f'buttons.{i}'] = "Button action must be one of " + ", ".join(sorted(BUTTON_ACTIONS)) + "."
                continue
            if button_action in (BUTTON_ACTION_CONFIG, BUTTON_ACTION_MESSAGE) and not value:
                what = "a configuration name" if button_action == BUTTON_ACTION_CONFIG else "a message"
                errors[f'buttons.{i}'] = f"`{button_action}` button needs {what}."
                continue
            if button_action == BUTTON_ACTION_DELAY:
                try:
                    minutes = int(value)
                except ValueError:
                    errors[f'buttons.{i}'] = "Delay button needs a number of minutes."
                    continue
                if minutes <= 0 or minutes > 1440:
                    errors[f'buttons.{i}'] = "Delay minutes must be between 1 and 1440."
                    continue
                value = str(minutes)
            clean_buttons.append({'label': label, 'action': button_action, 'value': value})
    if not any(key == 'buttons' or key.startswith('buttons.') for key in errors):
        cfg['buttons'] = clean_buttons

    cfg['button_timeout_target'] = str(get('button_timeout_target') or "").strip()
    cfg['default_button'] = str(get('default_button') or "").strip()

    if errors:
        return None, errors
    return cfg, {}


async def ui_apply_config(app: AsyncApp, channel_id: str, config_name: str, payload: dict) -> tuple[bool, dict]:
    """Validate and persist a single config (rule). Returns (ok, errors)."""
    clean, errors = await validate_config_payload(payload, app, channel_id)
    if errors:
        return False, errors
    async with _config_write_lock:
        channel_config.setdefault(channel_id, {})[config_name] = clean
        await save_configuration()
    log(f"Config UI: applied rule `{config_name}` in channel {channel_id}.")
    return True, {}


async def ui_create_config(app: AsyncApp, channel_id: str, config_name: str) -> tuple[bool, str]:
    config_name = (config_name or "").strip()
    if not CONFIG_NAME_PATTERN.match(config_name):
        return False, "Names may use letters, numbers, and - _ . : / only."
    async with _config_write_lock:
        configs = channel_config.setdefault(channel_id, {})
        if config_name in configs:
            return False, f"A rule named `{config_name}` already exists."
        configs[config_name] = copy.deepcopy(DEFAULT_CONFIG)
        await save_configuration()
    log(f"Config UI: created rule `{config_name}` in channel {channel_id}.")
    return True, ""


async def ui_delete_config(app: AsyncApp, channel_id: str, config_name: str) -> tuple[bool, str]:
    if config_name == DEFAULT_CONFIG_NAME:
        return False, f"The `{DEFAULT_CONFIG_NAME}` rule can't be deleted."
    async with _config_write_lock:
        configs = channel_config.get(channel_id, {})
        if config_name not in configs:
            return False, "That rule no longer exists."
        del configs[config_name]
        await save_configuration()
    log(f"Config UI: deleted rule `{config_name}` in channel {channel_id}.")
    return True, ""


def ui_snapshot_configs(channel_id: str) -> dict:
    """A deep copy of a channel's configs for read-only display."""
    return copy.deepcopy(channel_config.get(channel_id, {}))


def ui_meta() -> dict:
    """Option lists and defaults the editor needs, sourced from the live constants."""
    return {
        'triggers': sorted(TRIGGERS),
        'conditions': sorted(CONDITIONS),
        'actions': sorted(ACTIONS),
        'button_actions': sorted(BUTTON_ACTIONS),
        'opsgenie_priorities': sorted(OPSGENIE_PRIORITIES),
        'teams': sorted((t for t in team_cache if t and t != TEAM_UNKNOWN), key=lambda v: v.upper()),
        'template_variables': sorted(SUPPORTED_TEMPLATE_VARIABLES),
        'opsgenie_configured': opsgenie_configured,
        'default_config': copy.deepcopy(DEFAULT_CONFIG),
        'default_config_name': DEFAULT_CONFIG_NAME,
    }


async def maybe_start_web_ui(app: AsyncApp):
    """Start the config web UI if HUTBOT_UI_ENABLED is set. Returns the aiohttp runner or None."""
    if os.environ.get('HUTBOT_UI_ENABLED', '').strip().lower() not in ('1', 'true', 'yes', 'on'):
        return None
    try:
        from webui import WebUIContext, start_web_ui
    except Exception as e:
        log_error("Web UI is enabled but the webui module failed to import:", e)
        return None
    host = os.environ.get('HUTBOT_UI_HOST', '0.0.0.0')
    try:
        port = int(os.environ.get('HUTBOT_UI_PORT', '8080'))
    except ValueError:
        port = 8080
    ctx = WebUIContext(
        user_header=os.environ.get('HUTBOT_UI_USER_HEADER', 'X-Forwarded-Email'),
        resolve_user=lambda email: get_user_by_email(app, email),
        list_channels=lambda user: list_user_config_channels(app, user),
        is_member=lambda channel_id, user_id: is_user_in_channel(app, channel_id, user_id),
        get_configs=ui_snapshot_configs,
        apply_config=lambda channel_id, name, payload: ui_apply_config(app, channel_id, name, payload),
        create_config=lambda channel_id, name: ui_create_config(app, channel_id, name),
        delete_config=lambda channel_id, name: ui_delete_config(app, channel_id, name),
        meta=ui_meta,
    )
    return await start_web_ui(ctx, host, port)


async def main() -> None:
    load_env_file()
    slack_app_token = get_env_var("SLACK_APP_TOKEN")
    slack_bot_token = get_env_var("SLACK_BOT_TOKEN")
    opsgenie_token = get_env_var("OPSGENIE_TOKEN")
    opsgenie_heartbeat_name = get_env_var("OPSGENIE_HEARTBEAT_NAME")
    if slack_app_token is None or slack_bot_token is None:
        log_error("Environment variables SLACK_APP_TOKEN and SLACK_BOT_TOKEN must be set to run this app")
        exit(1)

    handler = None
    heartbeat_task = None
    scheduler_task = None
    web_runner = None
    try:
        app = AsyncApp(token=slack_bot_token)
        await load_configuration(app)
        global bot_user_id
        bot_user_id = (await app.client.auth_test())["user_id"]
        await update_user_cache(app)
        await load_replies_cache()
        await restore_scheduled_replies(app, opsgenie_token)
        await load_button_cache()
        await restore_pending_buttons(app, opsgenie_token)
        register_app_handlers(app, opsgenie_token=opsgenie_token)
        handler = AsyncSocketModeHandler(app, slack_app_token)
        if opsgenie_token and opsgenie_heartbeat_name:
            global opsgenie_configured
            opsgenie_configured = True
            heartbeat_task = asyncio.create_task(send_heartbeat(opsgenie_token, opsgenie_heartbeat_name))
        scheduler_task = asyncio.create_task(run_scheduler(app, opsgenie_token))
        web_runner = await maybe_start_web_ui(app)
        await handler.start_async()
    except asyncio.CancelledError:
        pass
    except KeyboardInterrupt:
        pass
    except Exception as e:
        log_error(e)
        exit(1)
    finally:
        try:
            if web_runner:
                await web_runner.cleanup()
            if handler:
                await handler.close_async()
            for background_task in (heartbeat_task, scheduler_task):
                if background_task:
                    background_task.cancel()
                    try:
                        await background_task
                    except asyncio.CancelledError:
                        pass
        except BaseException as e:
            pass

if __name__ == "__main__":
    asyncio.run(main())
