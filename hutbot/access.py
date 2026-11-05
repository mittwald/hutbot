"""Who may run commands: the full members of the bot's own workspace.

A command — `/hutbot …` or an @mention — rewrites a channel's rules, makes the bot message other
people and channels, pages the on-call engineer through the instance's OpsGenie key, or reads
instance-wide data: who is on call, who is in which team, what an internal calendar holds. That is
for the people of this workspace. Guests (single- and multi-channel), members of another
organization in a Slack Connect channel, and bots or integrations whose message mentions the bot
are refused before a command is even parsed.

Fails closed: a sender whose account cannot be looked up is refused, not waved through.
"""

import os
import time

from slack_bolt.async_app import AsyncApp

from logutil import log_error
import retryutil

from . import state
from .constants import SLACK_SYSTEM_USER_IDS

# Lets guest accounts run commands. Off by default; Slack Connect members and bots stay refused
# whatever this says.
ALLOW_GUEST_COMMANDS_ENV = 'HUTBOT_ALLOW_GUEST_COMMANDS'
# How long a looked-up account is trusted before it is looked up again, so a member who is turned
# into a guest (or deactivated) loses access within minutes rather than at the next restart.
_ACTOR_TTL = 300.0

REFUSAL_BOT = "bots and integrations cannot run commands"
REFUSAL_UNVERIFIED = "the sender's Slack account could not be verified"
REFUSAL_DEACTIVATED = "the sender's Slack account is deactivated"
REFUSAL_EXTERNAL = "the sender is not a member of this workspace"
REFUSAL_GUEST = "guest accounts cannot run commands"


def guests_allowed() -> bool:
    return os.environ.get(ALLOW_GUEST_COMMANDS_ENV, '').strip().lower() in ('1', 'true', 'yes', 'on')


async def _fetch_account(app: AsyncApp, user_id: str) -> dict | None:
    """The sender's `users.info` record, cached for `_ACTOR_TTL`, or ``None`` when unavailable."""
    now = time.monotonic()
    cached = state._command_actor_cache.get(user_id)
    if cached and (now - cached[0]) < _ACTOR_TTL:
        return cached[1]
    try:
        response = await retryutil.retry_async(
            lambda: app.client.users_info(user=user_id),
            what=f"Checking whether Slack user {user_id} may run commands")
    except Exception as e:
        log_error(f"Failed to look up Slack user `{user_id}` for a command:", e)
        return None
    account = response.get('user') if response else None
    if not isinstance(account, dict) or account.get('id') != user_id:
        return None
    state._command_actor_cache[user_id] = (now, account)
    return account


def _in_this_organization(account: dict) -> bool:
    """Whether the account belongs to the bot's own workspace (or Enterprise Grid organization)."""
    if not state.bot_team_id:
        # Unknown only before `auth.test` has answered; nothing can be compared yet.
        return False
    if account.get('team_id') == state.bot_team_id:
        return True
    enterprise_id = state.bot_enterprise_id
    member_of = (account.get('enterprise_user') or {}).get('enterprise_id') or account.get('enterprise_id')
    return bool(enterprise_id) and member_of == enterprise_id


async def command_refusal(app: AsyncApp, user_id: str, actor_is_bot: bool = False) -> str:
    """Why `user_id` may not run commands, or "" when they may."""
    if actor_is_bot or (user_id or '').startswith('B') or user_id in SLACK_SYSTEM_USER_IDS:
        return REFUSAL_BOT
    if not user_id:
        return REFUSAL_UNVERIFIED
    account = await _fetch_account(app, user_id)
    if account is None:
        return REFUSAL_UNVERIFIED
    if account.get('deleted'):
        return REFUSAL_DEACTIVATED
    if account.get('is_bot') or account.get('is_app_user'):
        return REFUSAL_BOT
    if account.get('is_stranger') or not _in_this_organization(account):
        return REFUSAL_EXTERNAL
    if (account.get('is_restricted') or account.get('is_ultra_restricted')) and not guests_allowed():
        return REFUSAL_GUEST
    return ""
