"""Inbound Slack event routing, message handlers, and handler registration."""

import re
import json
import asyncio
import datetime

from slack_bolt.async_app import AsyncApp

from employee_list import log

from . import state
from . import slackcache
from . import datetimefmt
from . import scheduling
from . import persistence
from . import buttons
from . import commands
from .constants import BUTTON_ACTION_PREFIX, IGNORED_MESSAGE_SUBTYPES, TRIGGER_MESSAGE
from .models import ScheduledReply
from .textutil import extract_message_text, log_debug


def is_command(text: str) -> bool:
    return f"<@{state.bot_user_id}>" in text


async def route_message(app: AsyncApp, opsgenie_token: str, event: dict) -> None:
    subtype = event.get('subtype')
    previous_message = event.get('previous_message', {})
    channel_id = event.get('channel', '')
    user_id = event.get('user', '')
    bot_id = event.get('bot_id', '')
    ts = event.get('ts', '')
    thread_ts = event.get('thread_ts', '')
    text = extract_message_text(event)

    channel = await slackcache.get_channel_by_id(app, channel_id)
    log_debug(channel, f"Received message event from #{channel.name}: {json.dumps(event)}")

    # Ignore messages from the bot itself
    if user_id == state.bot_user_id or bot_id == state.bot_user_id:
        log(f"Ignoring message from the bot from channel #{channel.name}.")
        return

    if subtype in IGNORED_MESSAGE_SUBTYPES:
        log(f"Ignoring message with subtype '{subtype}' for channel #{channel.name}.")
        return

    actor_is_bot = False
    user = None
    if user_id:
        user = await slackcache.get_user_by_id(app, user_id)
        actor_is_bot = user_id == 'USLACKBOT'
    elif bot_id and (thread_ts or any(c.get('include_bots', False) for c in channel.configs.values())):
        actor_is_bot = True
        user = await slackcache.get_user_by_id(app, bot_id)

    if subtype == 'message_deleted' and previous_message:
        # deleted message
        previous_user = await slackcache.get_user_by_id(app, previous_message.get('user'))
        await handle_message_deletion(app, channel, previous_user, previous_message.get('ts'))
    elif user and is_command(text):
        # command
        await commands.process_command(app, text, channel, user, ts, opsgenie_token, allow_test_message=True, command_ts=ts)
    elif user and thread_ts:
        # thread
        await handle_thread_response(app, channel, user, thread_ts, actor_is_bot)
    elif user and ts:
        # channel message
        await handle_channel_message(app, opsgenie_token, channel, user, text, ts, actor_is_bot)


def user_matches_actor_criteria(config: dict | None, user, actor_is_bot: bool = False) -> bool:
    if not config:
        return False

    if actor_is_bot and not config.get('include_bots', False):
        return False

    included_teams = config.get('included_teams', [])
    if included_teams and user.team not in included_teams:
        return False

    excluded_teams = config.get('excluded_teams', [])
    if excluded_teams and user.team in excluded_teams:
        return False

    return True


def get_actor_mismatch_reason(config: dict | None, user, actor_is_bot: bool = False) -> str:
    if not config:
        return "the configuration no longer exists"
    if actor_is_bot and not config.get('include_bots', False):
        return "bots are not included"
    included_teams = config.get('included_teams', [])
    if included_teams and user.team not in included_teams:
        return f"team '{user.team}' is not included"
    excluded_teams = config.get('excluded_teams', [])
    if excluded_teams and user.team in excluded_teams:
        return f"team '{user.team}' is excluded"
    return "the actor does not match the configuration"


async def handle_thread_response(app: AsyncApp, channel, reply_user, thread_ts: str, actor_is_bot: bool = False):
    keys_to_cancel = []
    for key, scheduled_reply in state.scheduled_messages.items():
        if key[0] != channel.id or key[1] != thread_ts:
            continue

        config = channel.configs.get(key[2])
        no_restrictions = (
            config is not None
            and not config.get('included_teams')
            and not config.get('excluded_teams')
            and (not actor_is_bot or not config.get('include_bots', False))
        )
        if no_restrictions or not user_matches_actor_criteria(config, reply_user, actor_is_bot):
            keys_to_cancel.append(key)

    if not keys_to_cancel:
        return

    message_user_id = state.scheduled_messages[keys_to_cancel[0]].user_id
    message_user = await slackcache.get_user_by_id(app, message_user_id)
    log(f"Thread reply by user @{reply_user.name} detected. Cancelling {len(keys_to_cancel)} reminder(s) for message {thread_ts} in channel #{channel.name}, user @{message_user.name}")

    for key in keys_to_cancel:
        state.scheduled_messages[key].task.cancel()
        del state.scheduled_messages[key]


async def handle_channel_message(app: AsyncApp, opsgenie_token: str, channel, user, text: str, ts: str, actor_is_bot: bool = False):
    for config_name, config in channel.configs.items():
        if config.get('trigger', TRIGGER_MESSAGE) != TRIGGER_MESSAGE:
            # Schedule/manual rules are driven by the scheduler or buttons, not messages.
            continue
        if not config.get('enabled', True):
            log(f"Message from user @{user.name} in #{channel.name} will be ignored for config '{config_name}' because replies are disabled.")
            continue

        only_work_days = config.get('only_work_days')
        hours = config.get('hours')
        pattern = config.get('pattern')
        pattern_case_sensitive = config.get('pattern_case_sensitive')

        if only_work_days and not datetimefmt.is_work_day():
            log(f"Message from user @{user.name} in #{channel.name} will be ignored for config '{config_name}' because of a non work day.")
            continue
        if len(hours) == 2 and not datetimefmt.is_work_time(hours[0], hours[1]):
            log(f"Message from user @{user.name} in #{channel.name} will be ignored for config '{config_name}' because it was sent outside work time.")
            continue
        if not user_matches_actor_criteria(config, user, actor_is_bot):
            log(f"Message from user @{user.name} in #{channel.name} will be ignored for config '{config_name}' because {get_actor_mismatch_reason(config, user, actor_is_bot)}.")
            continue

        if pattern:
            flags = 0 if pattern_case_sensitive else re.IGNORECASE
            if not re.search(pattern, text, flags):
                log(f"Message from user @{user.name} in #{channel.name} will be ignored for config '{config_name}' because it does not match pattern '{pattern}'.")
                continue

        task = asyncio.create_task(scheduling.schedule_reply(app, opsgenie_token, channel, config, config_name, user, text, ts))
        state.scheduled_messages[(channel.id, ts, config_name)] = ScheduledReply(task, user.id)
        send_at = datetime.datetime.now() + datetime.timedelta(seconds=config['wait_time'])
        state._scheduled_replies_cache[(channel.id, ts, config_name)] = {
            'channel_id': channel.id,
            'ts': ts,
            'config_name': config_name,
            'user_id': user.id,
            'text': text,
            'send_at': send_at.isoformat(),
        }
        await persistence.flush_replies_cache()


async def handle_reaction_added(app: AsyncApp, event):
    item = event.get('item', {})
    channel_id = item.get('channel', '')
    user_id = event.get('user', '')
    ts = item.get('ts')
    channel = await slackcache.get_channel_by_id(app, channel_id)
    reaction_user = await slackcache.get_user_by_id(app, user_id)

    keys_to_cancel = []
    for key, scheduled_reply in state.scheduled_messages.items():
        if key[0] != channel_id or key[1] != ts:
            continue

        config = channel.configs.get(key[2])
        no_restrictions = config is not None and not config.get('included_teams') and not config.get('excluded_teams')
        if no_restrictions or not user_matches_actor_criteria(config, reaction_user):
            keys_to_cancel.append(key)

    if not keys_to_cancel:
        return

    message_user_id = state.scheduled_messages[keys_to_cancel[0]].user_id
    message_user = await slackcache.get_user_by_id(app, message_user_id)
    log(f"Reaction added by user @{reaction_user.name}. Cancelling {len(keys_to_cancel)} reminder(s) for message {ts} in channel #{channel.name}, user @{message_user.name}")

    for key in keys_to_cancel:
        state.scheduled_messages[key].task.cancel()
        del state.scheduled_messages[key]


async def handle_message_deletion(app: AsyncApp, channel, previous_message_user, previous_message_ts: str):
    if previous_message_user.id == state.bot_user_id:
        log(f"Ignoring message deletion by bot from channel #{channel.name}.")
        return

    keys_to_cancel = []
    for key in state.scheduled_messages.keys():
        if key[0] == channel.id and key[1] == previous_message_ts:
            keys_to_cancel.append(key)

    if not keys_to_cancel:
        return

    log(f"Message deleted. Cancelling {len(keys_to_cancel)} reply/replies for message {previous_message_ts} in channel #{channel.name}, user @{previous_message_user.name}")
    for key in keys_to_cancel:
        state.scheduled_messages[key].task.cancel()
        del state.scheduled_messages[key]


async def handle_command_event(app: AsyncApp, command: dict, opsgenie_token: str = ""):
    text = command.get('text', '')
    channel_id = command.get('channel_id', '')
    user_id = command.get('user_id', '')

    channel = await slackcache.get_channel_by_id(app, channel_id)
    user = await slackcache.get_user_by_id(app, user_id)
    await commands.process_command(app, text, channel, user, opsgenie_token=opsgenie_token)


def register_app_handlers(app: AsyncApp, opsgenie_token: str = "") -> None:

    @app.event("message")
    async def handle_message_events(body, logger):
        await route_message(app, opsgenie_token, body.get('event', {}) if body else {})

    @app.event("reaction_added")
    async def handle_reaction_added_events(body, logger):
        await handle_reaction_added(app, body.get('event', {}) if body else {})

    @app.command(state.slash_command)
    async def handle_command(ack, body, logger):
        await ack()
        await handle_command_event(app, body, opsgenie_token)

    @app.action(re.compile(rf"^{BUTTON_ACTION_PREFIX}:"))
    async def handle_button_action(ack, body, action, logger):
        await ack()
        await buttons.handle_button_press(app, opsgenie_token, body, action)
