"""Resolve `#channel` / `@user` / `@usergroup` references to ids and objects."""

import re

from slack_bolt.async_app import AsyncApp

from employee_list import normalize_id

from . import slackcache
from .constants import ID_PATTERN
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
