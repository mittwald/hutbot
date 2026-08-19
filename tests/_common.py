"""Shared imports, helpers, and hutbot module aliases for the test suite."""

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
from unittest.mock import AsyncMock, MagicMock, mock_open, patch, call

from slack_sdk.errors import SlackApiError
from employee_list import get_env_var

from hutbot.models import Channel, User, Usergroup, ScheduledReply
from hutbot.constants import (
    ACTION_DM_USER,
    ACTION_GROUP_DM,
    ACTION_POST_CHANNEL,
    ACTION_REPLY,
    CALENDAR_TEMPLATE_VARIABLES,
    CONDITION_MATCH_ALL,
    CONDITION_MATCH_ANY,
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
from hutbot.textutil import extract_message_text, unwrap_slack_link
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
    validate_config_payload, list_user_config_channels, ui_create_config, ui_delete_config, ui_meta,
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
import hutbot.commands.setters
import hutbot.commands.info

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
