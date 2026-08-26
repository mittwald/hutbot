"""Resolve `#channel` / `@user` / `@usergroup` references to ids and objects."""

import re

from slack_bolt.async_app import AsyncApp

from employee_list import normalize_id

from . import slackcache
from .constants import ID_PATTERN, UNKNOWN_PLACEHOLDERS
from .models import Usergroup, User


def parse_channel_ref(channel_ref: str) -> str | None:
    """Resolve a `#channel` mention or raw `Cxxxx` id to a channel id."""
    for match in ID_PATTERN.finditer(channel_ref):
        ident = match.group(1)
        if ident and ident[0] == '#':
            return ident[1:]
    stripped = channel_ref.strip()
    if re.match(r'^[CGD][A-Z0-9]+$', stripped):
        return stripped
    return None


async def resolve_user_target(app: AsyncApp, target: str) -> User | None:
    target = target.strip()
    if not target:
        return None
    for match in ID_PATTERN.finditer(target):
        ident = match.group(1)
        if ident and ident[0] == '@':
            return await slackcache.get_user_by_id(app, ident[1:])
    if re.match(r'^[UW][A-Z0-9]+$', target):
        return await slackcache.get_user_by_id(app, target)
    if target.startswith('@'):
        return await slackcache.get_user_by_name(app, normalize_id(target[1:]))
    if '@' in target:
        return await slackcache.get_user_by_email(app, target)
    return await slackcache.get_user_by_name(app, normalize_id(target))


async def resolve_user_targets(app: AsyncApp, target: str) -> list[User]:
    """Every user a target names, in order and without duplicates.

    A target can name several people once it comes from a variable —
    `{{calendar_other_attendee_users}}` renders as `<@U1>, <@U2>`. Each entry may be a
    mention, a raw id, an address, or a name; entries that resolve to nobody are dropped, so a
    calendar listing someone without a Slack account still works.
    """
    users: list[User] = []
    seen = set()
    for token in re.split(r'[,;\s]+', (target or "").strip()):
        # A variable that resolved to nobody renders its placeholder (`<no-user-set>`), and an
        # unknown one renders as itself. Neither names a person, so neither is worth a lookup.
        if not token or token in UNKNOWN_PLACEHOLDERS or token.startswith('{{'):
            continue
        user = await resolve_user_target(app, token)
        if user and user.id and user.id not in seen:
            seen.add(user.id)
            users.append(user)
    return users


# A `<@U…>` mention or an email address names a person; a bare handle like `@sre` names a
# user group. Used to decide which of the two a `group_dm` target is, so an unresolvable
# handle keeps reporting itself instead of quietly matching a same-named user.
_NAMES_PEOPLE_PATTERN = re.compile(r'<@[A-Z0-9]+|[\w.%+-]+@[\w.-]+\.\w+')


def names_people(target: str) -> bool:
    """Whether a target spells out individual users rather than a user group."""
    return bool(_NAMES_PEOPLE_PATTERN.search(target or ""))


async def resolve_usergroup_target(app: AsyncApp, target: str) -> Usergroup | None:
    target = target.strip()
    if not target:
        return None
    for match in re.finditer(r'<!subteam\^([A-Z0-9]+)', target):
        return await slackcache.get_usergroup_by_id(app, match.group(1))
    if re.match(r'^S[A-Z0-9]+$', target):
        return await slackcache.get_usergroup_by_id(app, target)
    handle = target[1:] if target.startswith('@') else target
    return await slackcache.get_usergroup_by_handle(app, handle)
