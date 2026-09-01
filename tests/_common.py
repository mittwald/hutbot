"""Shared imports, helpers, and hutbot module aliases for the test suite."""

import contextlib
import os
import re
import json
import base64
import tempfile
import asyncio
import datetime
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import pytest
from unittest.mock import ANY, AsyncMock, MagicMock, mock_open, patch, call

from slack_sdk.errors import SlackApiError
import employee_list
from employee_list import get_env_var
import fileutil
import logutil

from hutbot.models import BuiltinCalendar, Channel, OpsGenieTokens, User, Usergroup, ScheduledReply
from hutbot.constants import (
    ACTION_DM_USER,
    ACTION_GROUP_DM,
    ACTION_POST_CHANNEL,
    ACTION_REPLY,
    CALENDAR_TEMPLATE_VARIABLES,
    CONDITION_MODE_ALL,
    CONDITION_MODE_ANY,
    CONDITION_OPERATORS_ORDERED,
    CONDITION_OPERATORS_WITHOUT_VALUE,
    DEFAULT_CONFIG,
    DISABLED_REASON_REMOVED,
    ESCALATION_NONE,
    SUPPORTED_TEMPLATE_VARIABLES,
    TEAM_UNKNOWN,
    TRIGGER_CRON,
    bot_slug,
    normalize_slash_command,
)
from hutbot.textutil import channel_label, decode_escaped_newlines, describe_message_event, extract_message_text, parse_quoted_tokens, strip_quotes, unwrap_slack_link
from hutbot.datetimefmt import parse_time, is_work_day, is_work_time
from hutbot.persistence import migrate_and_apply_defaults, load_replies_cache, flush_replies_cache
from hutbot.slackcache import get_channel_members, is_user_in_channel
from hutbot.messaging import replace_ids, clean_slack_text, send_message
from hutbot.scheduling import schedule_reply, restore_scheduled_replies
from hutbot.routing import (
    route_message, handle_channel_message, handle_thread_response,
    handle_reaction_added, handle_message_deletion, register_app_handlers,
    handle_bot_added_to_channel, handle_bot_removed_from_channel,
    cancel_channel_scheduled_replies, is_bot_membership_event,
)
from hutbot.webui_backend import (
    validate_config_payload, list_user_config_channels, ui_create_config, ui_delete_config,
    ui_rename_config, ui_meta,
    ui_snapshot_configs,
)
from hutbot.commands.dispatch import process_command
from hutbot.commands.setters import (
    set_work_hours, set_pattern, set_reply_message,
    set_replies_enabled,
)
from hutbot.commands.info import get_team_of, show_config

import hutbot
import hutbot.state
import hutbot.constants
import hutbot.models
import hutbot.datetimefmt
import hutbot.persistence
import hutbot.slackcache
import hutbot.messaging
import hutbot.templating
import hutbot.opsgenie
import hutbot.calendarfeed
import hutbot.conditionutil
import hutbot.actions
import hutbot.buttons
import hutbot.buttonutil
import hutbot.scheduling
import hutbot.routing
import hutbot.webui_backend
import hutbot.commands.dispatch
import hutbot.commands.preview
import hutbot.commands.setters
import hutbot.commands.info
import hutbot.apphome.fields

# The two Opsgenie keys a run carries. The halves differ on purpose, so a test can tell which
# endpoint a call reached: alerts and the heartbeat take `.alert`, on-call lookups take `.api`.
OPSGENIE_TOKENS = OpsGenieTokens("alert-token", "api-token")

# The instance's built-in calendars, as a test fixture. Every URL carries the marker
# SECRETTOKEN, so a leak test can look for it by name wherever a token must not appear.
BUILTIN_CALENDARS = [
    BuiltinCalendar("rota", "Platform on-call rota", "https://cal.example.com/SECRETTOKEN/rota.ics"),
    BuiltinCalendar("holidays", "Company holidays", "https://cal.example.com/OTHERTOKEN/holidays.ics"),
]


@contextlib.contextmanager
def _patch_builtin_calendars(entries=None):
    """Fake the instance's built-in calendars, the way the suite fakes every other lookup.

    Without this the list is empty — the shipped default — because `state.reset()` runs
    around every test.
    """
    with patch.object(hutbot.state, 'builtin_calendars',
                      list(BUILTIN_CALENDARS if entries is None else entries)):
        yield


def _mk_channel(configs=None):
    return Channel(id="C12345", name="general", configs=configs if configs is not None else {"default": DEFAULT_CONFIG.copy()})

def _seed_user_caches():
    """Pre-seed module caches so update_user_cache short-circuits (no Slack calls)."""
    hutbot.state.team_cache = {"Platform", "Support"}
    hutbot.state.user_id_cache = {"someuser": hutbot.models.User(id="U1", name="someuser", real_name="X", team="Platform")}
    hutbot.state.user_email_cache = {"x@example.com": hutbot.models.User(id="U1", name="someuser", real_name="X", team="Platform")}
    hutbot.state.id_user_cache = {"U1": hutbot.models.User(id="U1", name="someuser", real_name="X", team="Platform")}

def _ui_app():
    """A MagicMock app whose .client is an AsyncMock (won't be called if caches are seeded)."""
    app = MagicMock()
    app.client = AsyncMock()
    return app


def sent_messages(mock) -> str:
    """Every text a patched `send_message` received, joined.

    Long replies (help, `show config` for many configs) are split into several
    messages, so assertions have to look at all of them.
    """
    return "\n".join(call.args[3] for call in mock.call_args_list)


__all__ = [name for name in list(globals()) if not name.startswith('__')]
