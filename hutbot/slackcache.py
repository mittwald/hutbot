"""Slack channel/user/usergroup lookups backed by the in-memory caches in ``state``."""

import json
import time

from slack_bolt.async_app import AsyncApp

from employee_list import (
    EMPLOYEE_MAPPING_IGNORE,
    load_employee_mappings,
    load_employees,
    normalize_id,
    normalize_real_name,
    normalize_real_name_with_diagraphs,
    normalize_user_name,
)
from logutil import log, log_error, log_warning
import retryutil

from . import state
from .constants import SLACK_SYSTEM_USER_IDS, TEAM_UNKNOWN
from .models import Channel, User, Usergroup
from .textutil import log_debug

# Slack member ids per channel, cached briefly so listing a user's
# channels doesn't hammer conversations.members on every UI request.
_CHANNEL_MEMBERS_TTL = 300.0

# Channel names, on the same footing and for the same reason: a rule list needs one name per
# channel, and a rename is cosmetic, so serving a slightly stale one costs nothing.
_CHANNEL_NAME_TTL = 300.0


async def get_channel_by_id(app: AsyncApp, channel_id: str) -> Channel:
    if channel_id not in state.channel_config:
        state.channel_config[channel_id] = {}

    name = await get_channel_name(app, channel_id)
    configs = state.channel_config[channel_id]

    return Channel(id=channel_id, name=name, configs=configs)


async def get_channel_name(app: AsyncApp, channel_id: str) -> str:
    """A channel's name, cached for _CHANNEL_NAME_TTL seconds.

    Falls back to the id, which is what every caller prints when the lookup fails. A failed
    lookup is not cached, so a channel the bot momentarily could not read is asked again
    rather than being called by its id for the next five minutes.
    """
    now = time.monotonic()
    cached = state._channel_name_cache.get(channel_id)
    if cached and (now - cached[0]) < _CHANNEL_NAME_TTL:
        return cached[1]
    try:
        response = await retryutil.retry_async(
            lambda: app.client.conversations_info(channel=channel_id),
            what=f"Reading the name of channel {channel_id}")
        channel_name = response.get('channel', {}).get('name', '')
        if channel_name:
            state._channel_name_cache[channel_id] = (now, channel_name)
            return channel_name
    except Exception as e:
        log_error(f"Failed to get channel name for {channel_id}", e)

    return channel_id


async def get_message_permalink(app: AsyncApp, channel: Channel, ts: str) -> str:
    permalink = ""
    try:
        response = await retryutil.retry_async(
            lambda: app.client.chat_getPermalink(channel=channel.id, message_ts=ts),
            what=f"Reading the permalink of message {ts} in #{channel.name}")

        permalink = response.get('permalink', '')
    except Exception as e:
        log_error(f"Failed to get permalink for message {ts} in channel #{channel.name}:", e)

    return permalink


async def update_usergroup_cache(app: AsyncApp) -> None:
    if not state.usergroup_id_cache or not state.id_usergroup_cache:
        try:
            response = await retryutil.retry_async(
                lambda: app.client.usergroups_list(),
                what="Fetching the Slack usergroup list")
            usergroups = response['usergroups']
            for usergroup in usergroups:
                if usergroup.get('date_deleted', 0) == 0:
                    usergroup_id = usergroup.get('id', '')
                    usergroup_handle = usergroup.get('handle', '')
                    usergroup_name = usergroup.get('name', '')
                    state.usergroup_id_cache[usergroup_handle] = Usergroup(id=usergroup_id, handle=usergroup_handle, name=usergroup_name)
                    state.id_usergroup_cache[usergroup_id] = Usergroup(id=usergroup_id, handle=usergroup_handle, name=usergroup_name)
        except Exception as e:
            log_error("Failed to fetch usergroup list:", e)


def build_user(user: dict, employees: dict, mappings: dict) -> tuple[str, User]:
    user_id = user.get('id', '')
    user_name = normalize_id(user.get('name', ''))
    mapped_name = mappings.get(user_name, '')
    # The ignore sentinel is not a name: renaming the user to it would key the caches in
    # `cache_user` under "-" and make `get_user_by_name` lose them.
    user_is_ignored = mapped_name == EMPLOYEE_MAPPING_IGNORE
    if mapped_name and not user_is_ignored:
        log(f"Applying employee mapping: {user_name} -> {mapped_name}")
        user_name = mapped_name
    user_name_normalized = normalize_user_name(user_name)
    user_email = normalize_id(user.get('profile', {}).get('email', ''))
    user_email_alias = normalize_id(user_email.split('@')[0])
    user_email_alias_normalized = normalize_user_name(user_email_alias)
    user_real_name = user.get('real_name', '').strip()
    user_real_name_normalized = normalize_real_name(user_real_name)
    user_is_bot = bool(user.get('is_bot')) or user_id in SLACK_SYSTEM_USER_IDS
    user_team = TEAM_UNKNOWN

    if len(employees) > 0 and not user_is_bot:
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
            if not user_key and not user_is_ignored:
                user_json = json.dumps(user)
                if len(user_json) > 100:
                    user_json = user_json[:97] + '...'
                log_warning(f"Failed to map user @{user_name} to a employee: {user_json}")

        if user_key:
            user_team = employees[user_key].get('group', '').strip()

    return user_email, User(id=user_id, name=user_name, team=user_team, real_name=user_real_name, is_bot=user_is_bot)


def cache_user(user_email: str, u: User) -> None:
    state.user_id_cache[u.name] = u
    if user_email:
        state.user_email_cache[user_email] = u
    state.id_user_cache[u.id] = u
    if u.team not in state.team_cache:
        state.team_cache.add(u.team)


async def update_user_cache(app: AsyncApp) -> None:
    """Fill the user caches from `users.list`, or leave them as they were.

    `users.list` is paginated and rate limited, and the caches are only refilled while they
    are empty — so a page that fails has to leave them empty too. Writing each page as it
    arrives would leave a half-filled cache that looks filled, and the process would run out
    its life resolving half the workspace to bare ids with no way to notice or repair it.
    Everything is therefore collected first and committed in one go, once every page is in.
    """
    if not state.user_id_cache or not state.user_email_cache or not state.id_user_cache:
        employees = await load_employees()
        mappings = load_employee_mappings()
        fetched: list[tuple[str, User]] = []
        try:
            cursor = None
            while True:
                response = await retryutil.retry_async(
                    lambda cursor=cursor: app.client.users_list(cursor=cursor, limit=200),
                    what="Fetching the Slack user list")
                for user in response['members']:
                    if not user.get('deleted') and \
                       not user.get('is_bot', False) and \
                       not user.get('is_restricted', False) and \
                       user.get('id', '') != 'USLACKBOT':
                        fetched.append(build_user(user, employees, mappings))
                cursor = response.get('response_metadata', {}).get('next_cursor')
                if not cursor:
                    break
        except Exception as e:
            # Nothing has been written yet, so the caches stay empty and the next lookup
            # runs this again rather than settling for what one page happened to carry.
            log_error("Failed to fetch user list:", e)
            return
        for user_email, user in fetched:
            cache_user(user_email, user)


async def fetch_user_by_id(app: AsyncApp, id: str, channel: Channel | None = None) -> User | None:
    try:
        response = await retryutil.retry_async(
            lambda: app.client.users_info(user=id),
            what=f"Fetching Slack user {id}")
    except Exception as e:
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


def is_bot_id(id: str) -> bool:
    """Whether an id is an app's bot id (`Bxxxx`) rather than a user id (`Uxxxx`/`Wxxxx`)."""
    return bool(id) and id[0] == 'B'


async def fetch_bot_by_id(app: AsyncApp, bot_id: str, channel: Channel | None = None) -> User | None:
    """Resolve a `Bxxxx` bot id, which `users.info` does not accept.

    A message posted by an app carries `bot_id`, and — unless the app posts through a bot user
    — no `user` field at all. That id reaches every lookup that a human sender's would, and
    `users.info` answers `user_not_found` for it, because a bot id is not a user id. `bots.info`
    is the endpoint that takes it.

    An app that *does* have a bot user is resolved to that user, which carries the profile and
    the `is_bot` flag the rest of the code already understands; the answer is then filed under
    the bot id as well, so the next message from the same app is a cache hit either way. An app
    without one (an incoming webhook, a workflow) has nothing but a name, so a user is built
    from it: no email, no employee, no team — the same shape `build_user` gives any bot.
    """
    try:
        response = await retryutil.retry_async(
            lambda: app.client.bots_info(bot=bot_id),
            what=f"Fetching Slack bot {bot_id}")
    except Exception as e:
        log_error(f"Failed to fetch bot `{bot_id}`:", e)
        return None
    bot = response.get('bot') or {}
    log_debug(channel, f"Retrieved bot not in cache from Slack API: {json.dumps(bot)}")

    bot_user_id = bot.get('user_id', '')
    if bot_user_id:
        user = state.id_user_cache.get(bot_user_id) or await fetch_user_by_id(app, bot_user_id, channel)
        if user:
            state.id_user_cache[bot_id] = user
            return user

    bot_name = (bot.get('name') or '').strip()
    if not bot_name:
        log_warning(f"Slack knows bot `{bot_id}` but gave it no name.")
        return None
    # `name` is what `@mentions` and `{{user_name}}` fall back to, so it gets the same
    # normalization a user's handle gets; `real_name` keeps the app's name as it is written.
    user = User(id=bot_id, name=normalize_id(bot_name), real_name=bot_name, team=TEAM_UNKNOWN, is_bot=True)
    cache_user('', user)
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
        response = await retryutil.retry_async(
            lambda: app.client.users_info(user=bot_user_id),
            what=f"Fetching the bot user {bot_user_id}")
    except Exception as e:
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
        # `users.list` carries no bot ids, so a bot is always a miss here on the first message
        # from it — and asking `users.info` about one only ever answers `user_not_found`.
        user = await fetch_bot_by_id(app, id, channel) if is_bot_id(id) else await fetch_user_by_id(app, id, channel)
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
        response = await retryutil.retry_async(
            lambda: app.client.usergroups_users_list(usergroup=usergroup_id),
            what=f"Fetching the members of usergroup {usergroup_id}")
        return response.get('users', [])
    except Exception as e:
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
            response = await retryutil.retry_async(
                lambda cursor=cursor: app.client.conversations_members(channel=channel_id, cursor=cursor, limit=200),
                what=f"Fetching the members of channel {channel_id}")
            members.update(response.get('members', []) or [])
            cursor = response.get('response_metadata', {}).get('next_cursor')
            if not cursor:
                break
    except Exception as e:
        log_error(f"Failed to fetch members for channel {channel_id}:", e)
        return cached[1] if cached else set()
    state._channel_members_cache[channel_id] = (now, members)
    return members


async def is_user_in_channel(app: AsyncApp, channel_id: str, user_id: str) -> bool:
    if not user_id:
        return False
    return user_id in await get_channel_members(app, channel_id)
