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
from contextvars import ContextVar

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

# The instance's built-in calendars (models.BuiltinCalendar): what the calendar bridge serves
# plus what HUTBOT_BUILTIN_CALENDARS adds, rebuilt by `calendarfeed.rebuild_builtin_calendars`
# and empty when neither source has any. Every entry's URL carries a secret token: nothing
# outside `calendarfeed` reads `.url`, and nothing serializes this list — only `name` and
# `title` are ever echoed or handed to the web UI. Read synchronously on hot paths, so it is
# rebound as a whole rather than mutated in place.
builtin_calendars: list = []

# The calendars the bridge listing named at the last successful refresh (see
# `calendarfeed.refresh_bridge_calendars`). Kept apart from the list above so a bridge that is
# briefly unreachable can leave them standing.
bridge_calendars: list = []

# The calendars HUTBOT_BUILTIN_CALENDARS adds on top, read once from the environment at startup.
configured_calendars: list = []

# Bridge calendar name -> what its ICS calls itself (`X-WR-CALNAME`). The listing carries names
# only, so the title is read from the document once and kept for the life of the process: the
# parsed-calendar cache below expires every few minutes and the titles must not go with it.
bridge_calendar_titles: dict[str, str] = {}

# The roster the last refresh logged, so an hourly refresh that changes nothing stays silent.
_logged_bridge_roster: str | None = None

# Set once the first bridge refresh has published a roster — or established that it cannot. What
# startup waits for before restoring the timers it persisted, so a reminder that came due during a
# restart is not evaluated against an empty calendar list (see `calendarfeed.wait_for_bridge_roster`).
# Both users reach it through this module, so `reset()` can hand out a fresh one: an Event binds to
# the loop that first waits on it, and the test suite runs a loop per test.
_bridge_roster_ready: asyncio.Event = asyncio.Event()

# Slack member ids per channel, cached briefly (see slackcache.get_channel_members).
_channel_members_cache: dict[str, tuple[float, set]] = {}

# Parsed ICS calendars per feed URL, cached briefly (see calendarfeed.fetch_calendar).
# The parsed calendar is cached rather than the raw text (parsing is the expensive part)
# or the derived context (which would go stale at every event boundary).
# Values are (monotonic_fetched_at, icalendar.Calendar, display_name). Keyed by the *resolved*
# URL, which is what lets every config on the same built-in calendar share one fetch — and
# what makes these keys secret material, since a built-in's URL is an operator's token.
_calendar_cache: dict[str, tuple[float, object, str]] = {}

# Serializes web-UI config writes (mutate channel_config + save_configuration).
_config_write_lock = asyncio.Lock()

# The command currently being handled, already normalized to its `/hutbot …` form, so every
# reply can say what it was answering. Per-task (a ContextVar, not a global) because several
# commands can be in flight at once.
current_command: ContextVar[str] = ContextVar('current_command', default='')


def reset() -> None:
    """Reset all shared state to its initial values (used by the test suite)."""
    global _scheduler_last_check, bot_user_id, bot_user_name, opsgenie_configured, builtin_calendars, bridge_calendars, configured_calendars, _logged_bridge_roster, _bridge_roster_ready, slash_command, bot_name, default_datetime_locale, version
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
    bridge_calendar_titles.clear()
    current_command.set('')
    _scheduler_last_check = None
    bot_user_id = None
    bot_user_name = DEFAULT_BOT_NAME
    opsgenie_configured = False
    builtin_calendars = []
    bridge_calendars = []
    configured_calendars = []
    _logged_bridge_roster = None
    # A new Event rather than `clear()`: this one may have bound to the loop of an earlier test.
    _bridge_roster_ready = asyncio.Event()
    slash_command = DEFAULT_SLASH_COMMAND
    bot_name = DEFAULT_BOT_NAME
    default_datetime_locale = ""
    version = normalize_version(__version__)
