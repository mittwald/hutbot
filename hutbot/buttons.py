"""Interactive buttons + timeout escalation (mirrors scheduled-reply persistence)."""

import json
import asyncio
import datetime

from slack_bolt.async_app import AsyncApp

from employee_list import log, log_error, log_warning

from . import state
from . import slackcache
from . import messaging
from . import persistence
from . import actions
from .buttonutil import normalize_button, _find_button_index
from .constants import (
    BUTTON_ACTION_ACK,
    BUTTON_ACTION_CONFIG,
    BUTTON_ACTION_DELAY,
    BUTTON_ACTION_MESSAGE,
    BUTTON_ACTION_PREFIX,
    ESCALATION_BUTTON,
    ESCALATION_CONFIG,
    ESCALATION_NONE,
)
from .models import User


def build_button_blocks(config: dict, def_channel_id: str, config_name: str, text: str) -> list | None:
    buttons = config.get('buttons') or []
    if not buttons:
        return None
    elements = []
    for i, button in enumerate(buttons):
        label = (button.get('label') or f'Button {i + 1}')[:75]
        # The button definition is resolved server-side from the originating config
        # by index, so the payload only needs to locate it (avoids Slack's 2000-char
        # value cap for long inline-message buttons).
        value = json.dumps({"channel": def_channel_id, "config": config_name, "index": i})
        elements.append({
            "type": "button",
            "text": {"type": "plain_text", "text": label, "emoji": True},
            "action_id": f"{BUTTON_ACTION_PREFIX}:{i}",
            "value": value[:2000],
        })
    return [
        {"type": "section", "text": {"type": "mrkdwn", "text": text}},
        {"type": "actions", "block_id": f"{BUTTON_ACTION_PREFIX}:{config_name}", "elements": elements},
    ]


def _escalation_kind(config: dict) -> tuple[str, str]:
    """Decide what a buttoned message escalates to if no button is pressed in time."""
    default_button = config.get('default_button') or ''
    if default_button and _find_button_index(config, default_button) is not None:
        return ESCALATION_BUTTON, default_button
    target = config.get('button_timeout_target') or ''
    if target:
        return ESCALATION_CONFIG, target
    return ESCALATION_NONE, ''


async def register_escalation(app: AsyncApp, opsgenie_token: str, posted_channel_id: str, message_ts: str, def_channel_id: str, config_name: str, config: dict, context: dict | None = None) -> None:
    """Record a buttoned message so ack/delay/timeout can act on it later.

    A record is stored for every buttoned message (it carries the original message
    context that buttons/timeout pass on to the config they run); an escalation
    timer is started only when a timeout is set and there is something to escalate to.
    """
    if not message_ts or not posted_channel_id:
        return
    context = context or {}
    user = context.get('user')
    timeout = config.get('button_timeout') or 0
    kind, target = _escalation_kind(config)
    key = (posted_channel_id, message_ts)
    has_timer = timeout > 0 and kind != ESCALATION_NONE
    entry = {
        'posted_channel_id': posted_channel_id,
        'message_ts': message_ts,
        'def_channel_id': def_channel_id,
        'config_name': config_name,
        'escalation_kind': kind,
        'escalation_target': target,
        'timeout': timeout,
        'run_at': (datetime.datetime.now() + datetime.timedelta(seconds=timeout)).isoformat() if has_timer else '',
        'orig': {
            'user_id': user.id if user else context.get('user_id', ''),
            'text': context.get('text', ''),
            'ts': context.get('ts', ''),
            'permalink': context.get('permalink', ''),
        },
    }
    task = asyncio.create_task(_escalation_task(app, opsgenie_token, key, timeout)) if has_timer else None
    state.pending_buttons[key] = {'task': task, **entry}
    state._button_states_cache[key] = entry
    await persistence.flush_button_cache()


async def _escalation_context(app: AsyncApp, entry: dict | None, posted_channel_id: str, message_ts: str, presser: User | None = None) -> dict:
    """Build a run_action context from the stored original-message context.

    A config run by a button/timeout sees the *original* message (text/ts/permalink/
    sender), so its templates and any OpsGenie alert reference it; the target's reply
    threads under the buttoned message.
    """
    orig = (entry or {}).get('orig', {})
    user = presser
    if user is None and orig.get('user_id'):
        user = await slackcache.get_user_by_id(app, orig['user_id'])
    return {
        'channel_id': posted_channel_id,
        'thread_ts': message_ts,
        'user': user,
        'text': orig.get('text', ''),
        'ts': orig.get('ts', ''),
        'permalink': orig.get('permalink', ''),
    }


async def dispatch_button_action(app: AsyncApp, opsgenie_token: str, channel, posted_channel_id: str, message_ts: str, button: dict, run_context: dict) -> None:
    """Run a button's action. Shared by a real press and an auto-press on timeout.

    `delay` is handled by the caller (it is only meaningful for a live press).
    """
    action, value = normalize_button(button)
    if action == BUTTON_ACTION_CONFIG:
        target_config = channel.configs.get(value)
        if not target_config:
            log_warning(f"Button target config '{value}' not found in #{channel.name}.")
            return
        await actions.run_action(app, opsgenie_token, channel, target_config, value, context=run_context)
    elif action in (BUTTON_ACTION_MESSAGE, BUTTON_ACTION_ACK):
        # message posts the configured text; ack just dismisses (optional text).
        if value:
            await messaging._post_message(app, posted_channel_id, value, None, message_ts)
    else:
        log_warning(f"Unsupported button action '{action}' in #{channel.name}.")


async def _run_escalation(app: AsyncApp, opsgenie_token: str, entry: dict) -> None:
    kind = entry.get('escalation_kind', ESCALATION_NONE)
    channel = await slackcache.get_channel_by_id(app, entry['def_channel_id'])
    posted_channel_id, message_ts = entry['posted_channel_id'], entry['message_ts']
    run_context = await _escalation_context(app, entry, posted_channel_id, message_ts)
    if kind == ESCALATION_BUTTON:
        # Auto-press the configured default button.
        src_config = channel.configs.get(entry.get('config_name'))
        idx = _find_button_index(src_config, entry.get('escalation_target', ''))
        if idx is None:
            log_warning(f"Default button '{entry.get('escalation_target')}' not found in #{channel.name}.")
            return
        log(f"No button pressed on message {message_ts}: auto-pressing '{entry.get('escalation_target')}' in #{channel.name}.")
        await dispatch_button_action(app, opsgenie_token, channel, posted_channel_id, message_ts, src_config['buttons'][idx], run_context)
    elif kind == ESCALATION_CONFIG:
        target = entry.get('escalation_target', '')
        target_config = channel.configs.get(target)
        if target_config:
            log(f"Escalating message {message_ts}: running '{target}' in #{channel.name}.")
            await actions.run_action(app, opsgenie_token, channel, target_config, target, context=run_context)
        else:
            log_warning(f"Escalation target '{target}' not found in #{channel.name}.")


async def _escalation_task(app: AsyncApp, opsgenie_token: str, key: tuple, timeout: float) -> None:
    try:
        await asyncio.sleep(timeout)
        entry = state.pending_buttons.get(key)
        if entry:
            log(f"No button pressed on message {key[1]} within timeout; escalating.")
            await _run_escalation(app, opsgenie_token, entry)
    except asyncio.CancelledError:
        return
    except Exception as e:
        log_error(f"Escalation task failed for message {key[1]}:", e)
    finally:
        state.pending_buttons.pop(key, None)
        state._button_states_cache.pop(key, None)
        await persistence.flush_button_cache()


async def cancel_pending_button(posted_channel_id: str, message_ts: str) -> None:
    key = (posted_channel_id, message_ts)
    entry = state.pending_buttons.pop(key, None)
    state._button_states_cache.pop(key, None)
    if entry:
        if entry.get('task'):
            entry['task'].cancel()
        await persistence.flush_button_cache()


async def reschedule_escalation(app: AsyncApp, opsgenie_token: str, posted_channel_id: str, message_ts: str, minutes: int) -> bool:
    key = (posted_channel_id, message_ts)
    entry = state.pending_buttons.get(key)
    if not entry:
        log_warning(f"No pending escalation to delay for message {message_ts}.")
        return False
    if entry.get('task'):
        entry['task'].cancel()
    extra = minutes * 60
    record = {k: v for k, v in entry.items() if k != 'task'}
    record['timeout'] = extra
    record['run_at'] = (datetime.datetime.now() + datetime.timedelta(seconds=extra)).isoformat()
    task = asyncio.create_task(_escalation_task(app, opsgenie_token, key, extra))
    state.pending_buttons[key] = {'task': task, **record}
    state._button_states_cache[key] = record
    await persistence.flush_button_cache()
    return True


async def restore_pending_buttons(app: AsyncApp, opsgenie_token: str) -> None:
    entries = list(state._button_states_cache.items())
    invalid_keys = []
    restored = 0
    log(f"Restoring {len(entries)} pending button escalations from cache...")
    for key, entry in entries:
        def_channel_id = entry.get('def_channel_id')
        if not def_channel_id or def_channel_id not in state.channel_config:
            log_warning(f"Skipping cached button state for message {entry.get('message_ts')}: channel {def_channel_id} no longer configured.")
            invalid_keys.append(key)
            continue
        run_at = entry.get('run_at')
        if run_at:
            remaining = max(0.0, (datetime.datetime.fromisoformat(run_at) - datetime.datetime.now()).total_seconds())
            task = asyncio.create_task(_escalation_task(app, opsgenie_token, key, remaining))
        else:
            task = None
        state.pending_buttons[key] = {'task': task, **entry}
        restored += 1
    for key in invalid_keys:
        state._button_states_cache.pop(key, None)
    if invalid_keys:
        await persistence.flush_button_cache()
    log(f"Restored {restored} pending button escalations.")


async def handle_button_press(app: AsyncApp, opsgenie_token: str, body: dict, action: dict) -> None:
    container = body.get('container', {}) or {}
    message = body.get('message', {}) or {}
    posted_channel_id = (body.get('channel', {}) or {}).get('id') or container.get('channel_id', '')
    message_ts = container.get('message_ts') or message.get('ts', '')

    payload = {}
    raw_value = action.get('value', '')
    if raw_value:
        try:
            payload = json.loads(raw_value)
        except json.JSONDecodeError:
            payload = {}
    def_channel_id = payload.get('channel') or posted_channel_id
    src_config_name = payload.get('config') or ''
    index = payload.get('index')

    presser_id = (body.get('user', {}) or {}).get('id', '')
    presser = await slackcache.get_user_by_id(app, presser_id) if presser_id else None
    presser_name = presser.name if presser else '?'

    channel = await slackcache.get_channel_by_id(app, def_channel_id)
    src_config = channel.configs.get(src_config_name)
    buttons = (src_config or {}).get('buttons') or []
    if index is None or not isinstance(index, int) or index < 0 or index >= len(buttons):
        log_warning(f"Button pressed by @{presser_name} could not be resolved (config '{src_config_name}', index {index}).")
        return
    btn_action, btn_value = normalize_button(buttons[index])
    entry = state.pending_buttons.get((posted_channel_id, message_ts))
    log(f"Button '{buttons[index].get('label')}' ({btn_action}) pressed by @{presser_name} in #{channel.name}.")

    if btn_action == BUTTON_ACTION_DELAY:
        try:
            minutes = int(btn_value)
        except ValueError:
            minutes = 0
        if minutes > 0:
            await reschedule_escalation(app, opsgenie_token, posted_channel_id, message_ts, minutes)
        return

    # Every other button stops the pending escalation, then runs its action.
    run_context = await _escalation_context(app, entry, posted_channel_id, message_ts, presser)
    await cancel_pending_button(posted_channel_id, message_ts)
    await dispatch_button_action(app, opsgenie_token, channel, posted_channel_id, message_ts, buttons[index], run_context)
