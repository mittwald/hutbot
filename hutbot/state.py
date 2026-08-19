"""Shared mutable process state.

Every cache, the live channel configuration, and the scheduler/heartbeat flags
live here so that the rest of the package can share them without import cycles.

IMPORTANT: always read and write these through the module (``state.channel_config``),
never ``from .state import channel_config`` — several of these names are *rebound*
(not just mutated) at runtime, and a ``from`` import would freeze a stale reference
(and would also be invisible to ``unittest.mock.patch('hutbot.state.<name>')``).
"""

import asyncio
import datetime

from . import __version__
from .constants import DEFAULT_BOT_NAME, DEFAULT_SLASH_COMMAND, normalize_version

# Slash command this instance listens on; set from HUTBOT_SLASH_COMMAND at startup.
slash_command = DEFAULT_SLASH_COMMAND

# Version shown in `help` / `news`; set from HUTBOT_VERSION (the deployed image
# tag) at startup, falling back to the package version.
version = normalize_version(__version__)

# Name the bot uses for itself in user-facing text; set from HUTBOT_BOT_NAME at startup.
bot_name = DEFAULT_BOT_NAME

# Date/time locale used by configs that set none; set from
# HUTBOT_DEFAULT_DATETIME_LOCALE at startup and already normalized ("de_DE").
# There is no timezone counterpart: the container's TZ is the server local
# timezone, which is what a config without its own timezone already uses.
default_datetime_locale = ""

# Live configuration: {channel_id: {config_name: config_dict}}.
channel_config: dict = {}

# In-flight scheduled replies: {(channel_id, ts, config_name): ScheduledReply}.
scheduled_messages: dict = {}
# Persisted mirror of the above: {(channel_id, ts, config_name): entry_dict}.
_scheduled_replies_cache: dict[tuple, dict] = {}

# Pending interactive-button messages awaiting a press, keyed by (channel_id, message_ts).
pending_buttons: dict[tuple, dict] = {}
_button_states_cache: dict[tuple, dict] = {}

# Timestamp of the scheduler's previous tick; cron occurrences in (last tick, now] fire.
_scheduler_last_check: datetime.datetime | None = None

# Slack user/usergroup/team caches.
user_id_cache: dict = {}
user_email_cache: dict = {}
id_user_cache: dict = {}
usergroup_id_cache: dict = {}
id_usergroup_cache: dict = {}
team_cache: set = set()

# Resolved on startup from auth.test.
bot_user_id = None
# The bot's Slack handle from auth.test; used for the `@mention` examples in the help text.
bot_user_name = DEFAULT_BOT_NAME

# True once an OpsGenie token + heartbeat name are configured.
opsgenie_configured = False

# Slack member ids per channel, cached briefly (see slackcache.get_channel_members).
_channel_members_cache: dict[str, tuple[float, set]] = {}

# Parsed ICS calendars per feed URL, cached briefly (see calendarfeed.fetch_calendar).
# The parsed calendar is cached rather than the raw text (parsing is the expensive part)
# or the derived context (which would go stale at every event boundary).
# Values are (monotonic_fetched_at, icalendar.Calendar, display_name).
_calendar_cache: dict[str, tuple[float, object, str]] = {}

# Serializes web-UI config writes (mutate channel_config + save_configuration).
_config_write_lock = asyncio.Lock()


def reset() -> None:
    """Reset all shared state to its initial values (used by the test suite)."""
    global _scheduler_last_check, bot_user_id, bot_user_name, opsgenie_configured, slash_command, bot_name, default_datetime_locale, version
    channel_config.clear()
    scheduled_messages.clear()
    _scheduled_replies_cache.clear()
    pending_buttons.clear()
    _button_states_cache.clear()
    user_id_cache.clear()
    user_email_cache.clear()
    id_user_cache.clear()
    usergroup_id_cache.clear()
    id_usergroup_cache.clear()
    team_cache.clear()
    _channel_members_cache.clear()
    _calendar_cache.clear()
    _scheduler_last_check = None
    bot_user_id = None
    bot_user_name = DEFAULT_BOT_NAME
    opsgenie_configured = False
    slash_command = DEFAULT_SLASH_COMMAND
    bot_name = DEFAULT_BOT_NAME
    default_datetime_locale = ""
    version = normalize_version(__version__)
