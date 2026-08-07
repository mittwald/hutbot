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

from .constants import DEFAULT_SLASH_COMMAND

# Slash command this instance listens on; set from HUTBOT_SLASH_COMMAND at startup.
slash_command = DEFAULT_SLASH_COMMAND

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

# True once an OpsGenie token + heartbeat name are configured.
opsgenie_configured = False

# Slack member ids per channel, cached briefly (see slackcache.get_channel_members).
_channel_members_cache: dict[str, tuple[float, set]] = {}

# Serializes web-UI config writes (mutate channel_config + save_configuration).
_config_write_lock = asyncio.Lock()


def reset() -> None:
    """Reset all shared state to its initial values (used by the test suite)."""
    global _scheduler_last_check, bot_user_id, opsgenie_configured, slash_command
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
    _scheduler_last_check = None
    bot_user_id = None
    opsgenie_configured = False
    slash_command = DEFAULT_SLASH_COMMAND
