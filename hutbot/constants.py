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

CONDITION_NONE = ""
CONDITION_OUTLOOK = "outlook_calendar"
CONDITIONS = {CONDITION_NONE, CONDITION_OUTLOOK}

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
    "enabled": True,
    # Why the bot disabled this config on its own; empty for a user-made change.
    "disabled_reason": "",
    # Trigger: how the rule starts. "message" keeps the classic behavior; "cron"
    # carries its expression in `cron`.
    "trigger": TRIGGER_MESSAGE,
    "cron": "",
    # Condition: optional gate evaluated when a cron trigger fires.
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
