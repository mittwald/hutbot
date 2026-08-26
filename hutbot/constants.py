"""Constants, defaults, and the non-command regexes.

Command-parsing regexes live in ``hutbot/commands/patterns.py`` because only the
commands sub-package consumes them.
"""

import os
import re

DEFAULT_CONFIG_NAME = 'default'
# Slash command the bot registers with Slack. A second instance (e.g. the dev
# deployment) runs behind its own Slack app and therefore its own command, so
# this is configurable via HUTBOT_SLASH_COMMAND. The live value is kept in
# ``state.slash_command`` because the environment is only loaded at startup.
DEFAULT_SLASH_COMMAND = '/hutbot'
# Name the bot calls itself in user-facing text. A second instance (e.g. the dev
# deployment) sets HUTBOT_BOT_NAME to something like "Hutbot (DEV)" so users can
# tell the two apart. The live value is in ``state.bot_name``.
DEFAULT_BOT_NAME = 'Hutbot'
DEFAULT_DATE_FORMAT = "%a, %d %b %Y"
DEFAULT_TIME_FORMAT = "%H:%M"
DEFAULT_OPSGENIE_PRIORITY = "P4"
OPSGENIE_PRIORITIES = {"P1", "P2", "P3", "P4", "P5"}

TRIGGER_MESSAGE = "message"
TRIGGER_CRON = "cron"
TRIGGER_MANUAL = "manual"
TRIGGERS = {TRIGGER_MESSAGE, TRIGGER_CRON, TRIGGER_MANUAL}

# Conditions: a chain of `{{variable}} <operator> [value]` tests that gate a rule.
CONDITION_OP_EMPTY = "empty"
CONDITION_OP_NOT_EMPTY = "not_empty"
CONDITION_OP_EQUALS = "equals"
CONDITION_OP_NOT_EQUALS = "not_equals"
CONDITION_OP_STARTS_WITH = "starts_with"
CONDITION_OP_NOT_STARTS_WITH = "not_starts_with"
CONDITION_OP_ENDS_WITH = "ends_with"
CONDITION_OP_NOT_ENDS_WITH = "not_ends_with"
CONDITION_OP_CONTAINS = "contains"
CONDITION_OP_NOT_CONTAINS = "not_contains"
CONDITION_OP_REGEX = "regex"
CONDITION_OP_NOT_REGEX = "not_regex"
# Ordered so each operator sits next to its negation in help text and the web UI's
# dropdown. Never sort this — alphabetical order splits the pairs apart.
CONDITION_OPERATORS_ORDERED = (
    CONDITION_OP_EMPTY,
    CONDITION_OP_NOT_EMPTY,
    CONDITION_OP_EQUALS,
    CONDITION_OP_NOT_EQUALS,
    CONDITION_OP_CONTAINS,
    CONDITION_OP_NOT_CONTAINS,
    CONDITION_OP_STARTS_WITH,
    CONDITION_OP_NOT_STARTS_WITH,
    CONDITION_OP_ENDS_WITH,
    CONDITION_OP_NOT_ENDS_WITH,
    CONDITION_OP_REGEX,
    CONDITION_OP_NOT_REGEX,
)
CONDITION_OPERATORS = set(CONDITION_OPERATORS_ORDERED)
# Spellings accepted on the command line, resolved to the canonical name. A leading
# `not`/`!` is stripped and re-applied around these, so `not has` reaches `not_contains`.
# No `<>` alias: Slack HTML-escapes `<` and `>` in command text.
CONDITION_OPERATOR_ALIASES = {
    "is": CONDITION_OP_EQUALS,
    "=": CONDITION_OP_EQUALS,
    "==": CONDITION_OP_EQUALS,
    "eq": CONDITION_OP_EQUALS,
    "equal": CONDITION_OP_EQUALS,
    "!=": CONDITION_OP_NOT_EQUALS,
    "ne": CONDITION_OP_NOT_EQUALS,
    "isnt": CONDITION_OP_NOT_EQUALS,
    "is_not": CONDITION_OP_NOT_EQUALS,
    "has": CONDITION_OP_CONTAINS,
    "contain": CONDITION_OP_CONTAINS,
    "includes": CONDITION_OP_CONTAINS,
    "include": CONDITION_OP_CONTAINS,
    "excludes": CONDITION_OP_NOT_CONTAINS,
    "lacks": CONDITION_OP_NOT_CONTAINS,
    "matches": CONDITION_OP_REGEX,
    "match": CONDITION_OP_REGEX,
    "~": CONDITION_OP_REGEX,
    "=~": CONDITION_OP_REGEX,
    "!~": CONDITION_OP_NOT_REGEX,
    "prefix": CONDITION_OP_STARTS_WITH,
    "startswith": CONDITION_OP_STARTS_WITH,
    "begins_with": CONDITION_OP_STARTS_WITH,
    "begins": CONDITION_OP_STARTS_WITH,
    "suffix": CONDITION_OP_ENDS_WITH,
    "endswith": CONDITION_OP_ENDS_WITH,
    "blank": CONDITION_OP_EMPTY,
    "unset": CONDITION_OP_EMPTY,
    "none": CONDITION_OP_EMPTY,
    "is_empty": CONDITION_OP_EMPTY,
    "set": CONDITION_OP_NOT_EMPTY,
    "present": CONDITION_OP_NOT_EMPTY,
}
# These read the variable only, so a value (and a case flag) would do nothing.
CONDITION_OPERATORS_WITHOUT_VALUE = {CONDITION_OP_EMPTY, CONDITION_OP_NOT_EMPTY}
# An empty value here is vacuous — every string contains "" — so it is rejected instead of
# being stored as a condition that can never fail. `equals ""` stays legal.
CONDITION_OPERATORS_REQUIRING_NONEMPTY_VALUE = {
    CONDITION_OP_CONTAINS,
    CONDITION_OP_NOT_CONTAINS,
    CONDITION_OP_STARTS_WITH,
    CONDITION_OP_NOT_STARTS_WITH,
    CONDITION_OP_ENDS_WITH,
    CONDITION_OP_NOT_ENDS_WITH,
    CONDITION_OP_REGEX,
    CONDITION_OP_NOT_REGEX,
}
CONDITION_MODE_ALL = "all"
CONDITION_MODE_ANY = "any"
CONDITION_MODES = {CONDITION_MODE_ALL, CONDITION_MODE_ANY}
CONDITION_MODE_ALIASES = {
    "and": CONDITION_MODE_ALL,
    "every": CONDITION_MODE_ALL,
    "or": CONDITION_MODE_ANY,
    "some": CONDITION_MODE_ANY,
}

ACTION_REPLY = "reply"
ACTION_DM_USER = "dm_user"
ACTION_GROUP_DM = "group_dm"
ACTION_POST_CHANNEL = "post_channel"
ACTIONS = {ACTION_REPLY, ACTION_DM_USER, ACTION_GROUP_DM, ACTION_POST_CHANNEL}

# Actions that go somewhere other than the channel the rule lives in, and what a
# usable target looks like. `reply` is the only action that needs none.
ACTION_TARGET_HINTS = {
    ACTION_DM_USER: "<@user>",
    ACTION_GROUP_DM: "@usergroup",
    ACTION_POST_CHANNEL: "<#channel>",
}
ACTIONS_REQUIRING_TARGET = set(ACTION_TARGET_HINTS)

BUTTON_ACTION_PREFIX = "hutbot_btn"

# Marker written to a config's ``disabled_reason`` when the bot disabled it by
# itself (instead of a user running `disable`). Removing the bot from a channel
# disables that channel's configs; the marker lets the bot point them out when
# it is added back.
DISABLED_REASON_REMOVED = "removed_from_channel"

# What a button does when pressed.
BUTTON_ACTION_CONFIG = "config"    # run another named config (an OpsGenie alert is just such a config)
# Acknowledge/dismiss: cancels a pending escalation, and posts its text if it has
# one. Posting and dismissing were two keywords for one behavior; this is it.
BUTTON_ACTION_ACK = "ack"
BUTTON_ACTION_DELAY = "delay"      # delay the pending escalation by N minutes
BUTTON_ACTIONS = {BUTTON_ACTION_CONFIG, BUTTON_ACTION_ACK, BUTTON_ACTION_DELAY}

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
    # Calendar: one ICS feed per config, the counterpart of `opsgenie_schedule_name`. Either
    # `calendar_builtin` — the name of one of the instance's built-in calendars, resolved to its
    # URL at fetch time so no token is ever stored here — or `calendar_url`, which is a bearer
    # capability (an Outlook published-calendar link needs no auth) and is therefore redacted
    # wherever it is echoed back. Never both: setting one clears the other.
    "calendar_builtin": "",
    "calendar_url": "",
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
    "enabled": True,
    # Why the bot disabled this config on its own; empty for a user-made change.
    "disabled_reason": "",
    # Trigger: how the rule starts. "message" keeps the classic behavior; "cron"
    # carries its expression in `cron`.
    "trigger": TRIGGER_MESSAGE,
    "cron": "",
    # Conditions: `{{variable}} <operator> [value]` tests that gate every trigger. An
    # empty list always passes.
    "conditions": [],
    "conditions_mode": CONDITION_MODE_ALL,
    # Action: what the rule does when it fires.
    "action": ACTION_REPLY,
    "action_target": "",
    # Buttons: interactive buttons attached to the sent message.
    "buttons": [],
    # Escalation: what happens when nobody presses a button in time. The timeout and
    # its target are one setting, so a timer can never exist with nothing to fire.
    "escalation_timeout": 0,           # seconds; 0 = never escalate
    "escalation_kind": ESCALATION_NONE,  # "none" | "button" | "config"
    "escalation_target": "",           # a button label, or a config name
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
                                'channel_topic'])


def bot_slug(name: str) -> str:
    """Machine-safe form of the bot name, e.g. "Hutbot (DEV)" -> "hutbot-dev".

    Used where a stable identifier is needed instead of a display name (the
    OpsGenie alert alias, which is the dedup key). "Hutbot" maps to "hutbot",
    so the production alias is unchanged.
    """
    slug = re.sub(r'[^a-z0-9]+', '-', (name or "").lower()).strip('-')
    return slug or DEFAULT_BOT_NAME.lower()


def normalize_version(value: str) -> str:
    """Display form of a version, e.g. "1.0.9" or "v1.0.9" -> "v1.0.9"."""
    value = (value or "").strip()
    if not value:
        return ""
    return value if value.startswith("v") else f"v{value}"


def normalize_slash_command(value: str) -> str:
    """Return a usable Slack slash command, defaulting when unset."""
    value = (value or "").strip()
    if not value:
        return DEFAULT_SLASH_COMMAND
    return value if value.startswith("/") else f"/{value}"


MENTION_PATTERN = re.compile(r'(?<![|<])@([a-z0-9-_.]+)(?!>)')
# `@someone@example.com` in a message: an address is mapped to its Slack user the same way a
# `@username` is. Tried before MENTION_PATTERN, whose character class stops at the second `@`
# and would otherwise resolve the local part as a username.
EMAIL_MENTION_PATTERN = re.compile(r'(?<![|<\w])@([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})(?![\w>])', re.IGNORECASE)
ID_PATTERN = re.compile(r'<([#@!][a-zA-Z0-9^]+)([|]([^>]*))?>')
TIME_HOUR_PATTERN = re.compile(r"^[0-9]{1,2}$")
CONFIG_NAME_PATTERN = re.compile(r"^[A-Za-z0-9-_\.:/]+$")
# Words that start a command. A config may not be named after one, or
# `set enable` would create a config called "set" instead of failing.
RESERVED_CONFIG_NAMES = {
    "set", "clear", "unset", "remove", "add", "enable", "disable",
    "show", "delete", "list", "run", "fire", "test", "help", "news",
}
TEMPLATE_VARIABLE_NAME_PATTERN = re.compile(r'[a-z_][a-z0-9_]*')
TEMPLATE_ARGUMENT_NAME_PATTERN = re.compile(r'[a-z_][a-z0-9_]*')
TEMPLATE_ARGUMENT_ALIASES = {
    "fmt": "fmt",
    "format": "fmt",
    "tz": "tz",
    "timezone": "tz",
    "lc": "lc",
    "locale": "lc",
    # Picks one entry out of a list variable, counting from 1: `nth=2` is the second.
    "nth": "nth",
    "n": "nth",
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
CALENDAR_DATETIME_TEMPLATE_VARIABLES = {
    f"calendar_{period}_{bound}_{part}"
    for period in ("current", "next")
    for bound in ("start", "end")
    for part in ("date", "time", "datetime")
}
# Attendee names and emails: several per event, so these hold a list. A condition on one
# matches when *any* item matches, and a `not_` operator when *none* does.
CALENDAR_LIST_TEMPLATE_VARIABLES = {
    f"calendar_{period}_{field}"
    for period in ("current", "next")
    # `other_*` drops the organizer, which a shared mailbox invites itself to — so a rota
    # entry organized by "Notfallhotline" leaves just the person actually on call.
    # `*_users` are the addresses mapped to Slack users, ready to @mention or DM.
    for field in ("attendees", "attendee_emails", "attendee_users",
                  "other_attendees", "other_attendee_emails", "other_attendee_users")
}
LIST_TEMPLATE_VARIABLES = CALENDAR_LIST_TEMPLATE_VARIABLES
CALENDAR_TEMPLATE_VARIABLES = {
    "calendar_name",
    *(
        f"calendar_{period}_{field}"
        for period in ("current", "next")
        for field in ("summary", "location", "description", "organizer", "organizer_email",
                      "organizer_user", "attendee_count", "uid", "status")
    ),
    *CALENDAR_LIST_TEMPLATE_VARIABLES,
    *CALENDAR_DATETIME_TEMPLATE_VARIABLES,
}
# Every variable that renders an instant and therefore accepts `fmt`/`tz`/`lc`
# arguments. Both providers store their raw ISO value under `__<variable>_raw`.
TEMPLATE_DATETIME_VARIABLES = OPSGENIE_DATETIME_TEMPLATE_VARIABLES | CALENDAR_DATETIME_TEMPLATE_VARIABLES
# Variables whose value is not settled until a rule actually fires: the two providers that
# have to be fetched, plus the permalink, which would cost a Slack call per message to
# resolve early. Everything else follows from the message, its sender, and the config, so a
# condition on it can be judged the moment the message arrives.
FIRE_TIME_TEMPLATE_VARIABLES = OPSGENIE_TEMPLATE_VARIABLES | CALENDAR_TEMPLATE_VARIABLES | {"message_link"}
# Formatted renderings of ``{{timestamp}}``: the triggering message's time, or the
# time the rule ran when there is no message behind it. Like the OpsGenie date/time
# variables they take `fmt`/`tz`/`lc` arguments.
DATETIME_TEMPLATE_VARIABLES = {"date", "time", "datetime"}
SUPPORTED_TEMPLATE_VARIABLES = {
    *DATETIME_TEMPLATE_VARIABLES,
    "channel",
    "channel_name",
    "config",
    "message",
    "message_link",
    *OPSGENIE_TEMPLATE_VARIABLES,
    *CALENDAR_TEMPLATE_VARIABLES,
    "team",
    "timestamp",
    "user",
    "user_name",
    "wait_minutes",
}
UNKNOWN_EMAIL_ONCALL_PLACEHOLDER = "<no-email-set>"
UNKNOWN_NAME_ONCALL_PLACEHOLDER = "<no-name-set>"
UNKNOWN_USER_ONCALL_PLACEHOLDER = "<no-user-set>"
# Shared by the OpsGenie and calendar date/time variables.
UNKNOWN_PERIOD_PLACEHOLDER = "<unknown>"
UNKNOWN_OPSGENIE_SCHEDULE_PLACEHOLDER = "<no-schedule-set>"
UNKNOWN_CALENDAR_PLACEHOLDER = "<no-calendar-set>"
# A config naming a built-in calendar this instance does not offer, because it was renamed or
# taken out of HUTBOT_BUILTIN_CALENDARS. Distinct from "no calendar set" so a rule that went
# quiet for that reason says so in `test` output and in whatever it renders.
UNKNOWN_CALENDAR_BUILTIN_PLACEHOLDER = "<unknown-calendar>"
UNKNOWN_CALENDAR_EVENT_PLACEHOLDER = "<no-event>"
# Every "nothing resolved" stand-in. A condition's `empty`/`not_empty` treats these as
# empty, because the providers never hand back a bare "" and `opsgenie_current_user empty`
# is the natural way to ask "is anyone on call?".
UNKNOWN_PLACEHOLDERS = {
    UNKNOWN_EMAIL_ONCALL_PLACEHOLDER,
    UNKNOWN_NAME_ONCALL_PLACEHOLDER,
    UNKNOWN_USER_ONCALL_PLACEHOLDER,
    UNKNOWN_PERIOD_PLACEHOLDER,
    UNKNOWN_OPSGENIE_SCHEDULE_PLACEHOLDER,
    UNKNOWN_CALENDAR_PLACEHOLDER,
    UNKNOWN_CALENDAR_BUILTIN_PLACEHOLDER,
    UNKNOWN_CALENDAR_EVENT_PLACEHOLDER,
}
