"""Slack channel/user/usergroup lookups backed by the in-memory caches in ``state``."""

import json
import time

from slack_bolt.async_app import AsyncApp
from slack_sdk.errors import SlackApiError

from employee_list import (
    load_employee_mappings,
    load_employees,
    log,
    log_error,
    normalize_id,
    normalize_real_name,
    normalize_real_name_with_diagraphs,
    normalize_user_name,
    log_warning,
)

from . import state
from .constants import TEAM_UNKNOWN
from .models import Channel, User, Usergroup
from .textutil import log_debug

# Slack member ids per channel, cached briefly so listing a user's
# channels doesn't hammer conversations.members on every UI request.
_CHANNEL_MEMBERS_TTL = 300.0


async def get_channel_by_id(app: AsyncApp, channel_id: str) -> Channel:
    if channel_id not in state.channel_config:
        state.channel_config[channel_id] = {}

    name = await get_channel_name(app, channel_id)
    configs = state.channel_config[channel_id]

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
    if not state.usergroup_id_cache or not state.id_usergroup_cache:
        try:
            response = await app.client.usergroups_list()
            usergroups = response['usergroups']
            for usergroup in usergroups:
                if usergroup.get('date_deleted', 0) == 0:
                    usergroup_id = usergroup.get('id', '')
                    usergroup_handle = usergroup.get('handle', '')
                    usergroup_name = usergroup.get('name', '')
                    state.usergroup_id_cache[usergroup_handle] = Usergroup(id=usergroup_id, handle=usergroup_handle, name=usergroup_name)
                    state.id_usergroup_cache[usergroup_id] = Usergroup(id=usergroup_id, handle=usergroup_handle, name=usergroup_name)
        except SlackApiError as e:
            log_error("Failed to fetch usergroup list:", e)


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
    state.user_id_cache[u.name] = u
    if user_email:
        state.user_email_cache[user_email] = u
    state.id_user_cache[u.id] = u
    if u.team not in state.team_cache:
        state.team_cache.add(u.team)


async def update_user_cache(app: AsyncApp) -> None:
    if not state.user_id_cache or not state.user_email_cache or not state.id_user_cache:
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
            log_error("Failed to fetch user list:", e)


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


async def fetch_bot_handle(app: AsyncApp, bot_user_id: str) -> str:
    """The handle people actually type to mention the bot, e.g. "Hutbot_DEV".

    ``auth.test`` only reports the bot user's username, which Slack derives from
    the app name by lowercasing it and dropping punctuation ("hutbotdev"). The
    handle shown in the mention autocomplete is the profile display name.
    """
    if not bot_user_id:
        return ""
    try:
        response = await app.client.users_info(user=bot_user_id)
    except SlackApiError as e:
        log_error(f"Failed to fetch the bot user `{bot_user_id}`:", e)
        return ""
    slack_user = response.get('user') or {}
    profile = slack_user.get('profile') or {}
    # Bot users usually have no display name; their `real_name` carries the app's
    # display name ("Hutbot_DEV"), which is what the mention autocomplete offers.
    # `name` is the flattened username and only a last resort.
    candidates = (
        profile.get('display_name'),
        profile.get('display_name_normalized'),
        slack_user.get('real_name'),
        profile.get('real_name'),
        slack_user.get('name'),
    )
    for candidate in candidates:
        if candidate and candidate.strip():
            return candidate.strip()
    return ""


async def get_user_by_id(app: AsyncApp, id: str, channel: Channel | None = None) -> User:
    await update_user_cache(app)
    user = state.id_user_cache.get(id, None)
    if not user:
        user = await fetch_user_by_id(app, id, channel)
    if not user:
        user = User(id=id, name=id, team=TEAM_UNKNOWN, real_name='')
    return user


async def get_user_by_name(app: AsyncApp, name: str) -> User:
    await update_user_cache(app)
    user = state.user_id_cache.get(name, None)
    if not user:
        user = User(id=None, name=name, team=TEAM_UNKNOWN, real_name='')
    return user


async def get_user_by_email(app: AsyncApp, email: str) -> User:
    await update_user_cache(app)
    normalized_email = normalize_id(email)
    user = state.user_email_cache.get(normalized_email, None)
    if user:
        return user

    user_alias = normalized_email.split('@')[0]
    return await get_user_by_name(app, user_alias)


async def get_user_by_email_strict(app: AsyncApp, email: str) -> User:
    """Exact-email lookup only — no username fallback.

    Used for web-UI authentication: the lenient ``get_user_by_email`` falls back
    to matching a Slack *username* from the email local-part, which would let a
    proxy-authenticated address like ``alice@external.example`` be authorized as
    Slack user ``alice``. This resolver returns an id-less User on no exact match
    so the UI gate rejects it.
    """
    await update_user_cache(app)
    user = state.user_email_cache.get(normalize_id(email), None)
    if user:
        return user
    return User(id=None, name=email, team=TEAM_UNKNOWN, real_name='')


async def get_usergroup_by_id(app: AsyncApp, id: str) -> Usergroup:
    await update_usergroup_cache(app)
    usergroup = state.id_usergroup_cache.get(id, None)
    if not usergroup:
        usergroup = Usergroup(id=id, handle=id, name=id)
    return usergroup


async def get_usergroup_by_handle(app: AsyncApp, handle: str) -> Usergroup:
    await update_usergroup_cache(app)
    usergroup = state.usergroup_id_cache.get(handle, None)
    if not usergroup:
        usergroup = Usergroup(id=None, handle=handle, name=handle)
    return usergroup


async def get_usergroup_members(app: AsyncApp, usergroup_id: str) -> list[str]:
    try:
        response = await app.client.usergroups_users_list(usergroup=usergroup_id)
        return response.get('users', [])
    except SlackApiError as e:
        log_error(f"Failed to fetch members of usergroup {usergroup_id}:", e)
        return []


async def get_channel_members(app: AsyncApp, channel_id: str) -> set:
    """Set of Slack member ids for a channel, cached for _CHANNEL_MEMBERS_TTL seconds."""
    now = time.monotonic()
    cached = state._channel_members_cache.get(channel_id)
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
    state._channel_members_cache[channel_id] = (now, members)
    return members


async def is_user_in_channel(app: AsyncApp, channel_id: str, user_id: str) -> bool:
    if not user_id:
        return False
    return user_id in await get_channel_members(app, channel_id)
