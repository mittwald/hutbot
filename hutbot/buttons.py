"""Interactive buttons + timeout escalation (mirrors scheduled-reply persistence)."""

import json
import asyncio
import datetime

from slack_bolt.async_app import AsyncApp
from slack_sdk.errors import SlackApiError

from employee_list import log, log_error, log_warning

from . import state
from . import slackcache
from . import messaging
from . import persistence
from . import actions
from .buttonutil import normalize_button, _find_button_index
from .conditionutil import snapshot_conditions
from .constants import (
    BUTTON_ACTION_ACK,
    BUTTON_ACTION_CONFIG,
    BUTTON_ACTION_DELAY,
    BUTTON_ACTION_PREFIX,
    ESCALATION_BUTTON,
    ESCALATION_CONFIG,
    ESCALATION_NONE,
)
from .models import User


SLACK_SECTION_TEXT_LIMIT = 3000
SLACK_ACTIONS_ELEMENT_LIMIT = 25


def _section_blocks(text: str) -> list[dict]:
    """Split message text into Slack-valid section blocks."""
    text = text or ' '
    return [
        {"type": "section", "text": {"type": "mrkdwn", "text": text[offset:offset + SLACK_SECTION_TEXT_LIMIT]}}
        for offset in range(0, len(text), SLACK_SECTION_TEXT_LIMIT)
    ]


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
    action_blocks = []
    for offset in range(0, len(elements), SLACK_ACTIONS_ELEMENT_LIMIT):
        chunk_number = offset // SLACK_ACTIONS_ELEMENT_LIMIT
        suffix = f":{chunk_number}"
        block_id = f"{BUTTON_ACTION_PREFIX}:{config_name}"[:255 - len(suffix)] + suffix
        action_blocks.append({
            "type": "actions",
            "block_id": block_id,
            "elements": elements[offset:offset + SLACK_ACTIONS_ELEMENT_LIMIT],
        })
    return _section_blocks(text) + action_blocks


def _escalation_kind(config: dict) -> tuple[str, str]:
    """What a buttoned message escalates to if no button is pressed in time.

    Stored as set: `set escalation` writes the kind and target together and
    rejects a target it cannot resolve, so there is nothing to decide here.
    """
    kind = config.get('escalation_kind') or ESCALATION_NONE
    target = config.get('escalation_target') or ''
    if kind in (ESCALATION_BUTTON, ESCALATION_CONFIG) and target:
        return kind, target
    return ESCALATION_NONE, ''


def _reachable_config_names(config: dict) -> set[str]:
    """Every config a buttoned message could run — from its buttons or its escalation."""
    names = set()
    for button in config.get('buttons') or []:
        action, value = normalize_button(button)
        if action == BUTTON_ACTION_CONFIG and value:
            names.add(value)
    kind, target = _escalation_kind(config)
    if kind == ESCALATION_CONFIG and target:
        names.add(target)
    return names


def rename_config_references(config: dict, old_name: str, new_name: str) -> bool:
    """Point one config's button and escalation targets at a renamed config.

    The counterpart to `_reachable_config_names`: those are the two places a config writes
    another config's name down, so these are the two a rename has to rewrite. Returns whether
    anything changed, so a caller can report how many rules it touched.
    """
    changed = False
    for button in config.get('buttons') or []:
        action, value = normalize_button(button)
        if action == BUTTON_ACTION_CONFIG and value == old_name:
            button['value'] = new_name
            changed = True
    kind, target = _escalation_kind(config)
    if kind == ESCALATION_CONFIG and target == old_name:
        config['escalation_target'] = new_name
        changed = True
    return changed


def rename_pending_buttons(channel_id: str, old_name: str, new_name: str) -> int:
    """Point already-posted buttoned messages at a renamed config; returns how many changed.

    A buttoned message can sit unpressed for as long as a reminder waits, and its record names
    the config that posted it, the configs its buttons can run, and the conditions frozen for
    each of those — all by name. A press or a timeout resolves those names against the live
    channel, so a rename that skipped these would strand every message already out there.

    The live record and its persisted mirror are separate dicts that share their nested
    objects, so both are walked; rewriting a shared list or dict twice is a no-op the second
    time round.

    Synchronous on purpose: a press claims a record between any two awaits, so the caller
    rewrites every reference before it yields and flushes the mirror afterwards.
    """
    touched_messages = set()
    for records in (state.pending_buttons, state._button_states_cache):
        for key, entry in records.items():
            if entry.get('def_channel_id') != channel_id:
                continue
            touched = rename_config_references(entry, old_name, new_name)
            if entry.get('config_name') == old_name:
                entry['config_name'] = new_name
                touched = True
            conditions = entry.get('target_conditions')
            if isinstance(conditions, dict) and old_name in conditions:
                conditions[new_name] = conditions.pop(old_name)
                touched = True
            if touched:
                # Keyed by the message, so a record held in both dicts counts once.
                touched_messages.add(key)
    return len(touched_messages)


def _target_conditions(def_channel_id: str, config: dict) -> dict:
    """The conditions of each reachable config, frozen when the message is posted.

    A buttoned message can sit unpressed for as long as a reminder waits, so the same rule
    applies: editing a target config must not retroactively change what an already-posted
    message does when someone finally presses. Stored with the record, so it survives a
    restart alongside the button definitions.
    """
    channel_configs = state.channel_config.get(def_channel_id, {})
    return {
        name: snapshot_conditions(channel_configs[name])
        for name in _reachable_config_names(config)
        if name in channel_configs
    }


def _with_snapshotted_conditions(config: dict, target_conditions: dict | None, name: str) -> dict:
    """A target config judged by the conditions captured when the message was posted."""
    snapshot = (target_conditions or {}).get(name)
    return {**config, **snapshot} if snapshot else config


async def register_escalation(app: AsyncApp, opsgenie_token: str, posted_channel_id: str, message_ts: str, def_channel_id: str, config_name: str, config: dict, context: dict | None = None, posted_text: str = '', parent: dict | None = None) -> None:
    """Record a buttoned message so ack/delay/timeout can act on it later.

    A record is stored for every buttoned message (it carries the original message
    context that buttons/timeout pass on to the config they run); an escalation
    timer is started only when a timeout is set and there is something to escalate to.
    """
    if not message_ts or not posted_channel_id:
        return
    context = context or {}
    user = context.get('user')
    timeout = config.get('escalation_timeout') or 0
    kind, target = _escalation_kind(config)
    key = (posted_channel_id, message_ts)
    has_timer = timeout > 0 and kind != ESCALATION_NONE
    entry = {
        'posted_channel_id': posted_channel_id,
        'message_ts': message_ts,
        'def_channel_id': def_channel_id,
        'config_name': config_name,
        # Snapshot the button defs + rendered text with the posted message, so a press
        # is resolved against what was posted (not a since-edited config) and the
        # message can be de-buttoned once handled.
        'buttons': [dict(b) for b in (config.get('buttons') or [])],
        'posted_text': posted_text,
        # What the run that posted this message did, for the `{{parent_*}}` variables of whatever
        # a press or the timeout goes on to run. Only the facts the record does not already
        # carry: the name, the text and the ts are read back from `config_name`, `posted_text`
        # and `message_ts`, which is what lets a record written before this answer them too.
        'parent': parent or {},
        # The conditions of the configs this message can run, frozen like the buttons above.
        'target_conditions': _target_conditions(def_channel_id, config),
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


def _parent_facts(entry: dict | None) -> dict:
    """The triggering run's facts, as this record can answer them.

    The button cache has no migration — `persistence.flush_button_cache` dumps it wholesale — so
    a record written by an older version has to degrade rather than fail. It already stores the
    three facts that matter most under their own names, so those are read from there for *every*
    record and never duplicated into `parent`: an older record answers `{{parent_config}}`,
    `{{parent_message}}`, `{{parent_timestamp}}` and the three date/time forms in full. The rest
    render empty rather than `<no-parent>` — there *was* a parent, this record just never
    recorded that much about it.
    """
    entry = entry or {}
    return {
        **(entry.get('parent') or {}),
        'config_name': entry.get('config_name', ''),
        'message': entry.get('posted_text', ''),
        # The posted message's own Slack ts *is* when the parent ran, and it is on every record
        # ever written — so the date/time variables need no field of their own.
        'timestamp': entry.get('message_ts', ''),
    }


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
        'parent': _parent_facts(entry),
    }


async def dispatch_button_action(app: AsyncApp, opsgenie_token: str, channel, posted_channel_id: str, message_ts: str, button: dict, run_context: dict, src_config: dict | None = None, src_config_name: str = '', target_conditions: dict | None = None) -> bool:
    """Run a button's action. Shared by a real press and an auto-press on timeout.

    Returns whether the action actually happened. The caller has already consumed the
    pending record by this point and goes on to strip the buttons and post a note, so it
    needs to know: a target config whose own conditions declined must not be reported as
    having run.

    `delay` is handled by the caller (it is only meaningful for a live press).

    `ack` is deliberately not condition-gated. Its text belongs to the *source* config,
    whose conditions were already evaluated when the buttoned message was posted;
    re-checking them minutes later could swallow a person's acknowledgement.
    """
    action, value = normalize_button(button)
    if action == BUTTON_ACTION_CONFIG:
        target_config = channel.configs.get(value)
        if not target_config:
            log_warning(f"Button target config '{value}' not found in #{channel.name}.")
            return False
        # `run_action` already logs why it declined, and the note only needs to know that
        # it did — so this stays on the plain entry point the rest of the code uses.
        target_config = _with_snapshotted_conditions(target_config, target_conditions, value)
        return bool(await actions.run_action(app, opsgenie_token, channel, target_config, value, context=run_context))
    elif action == BUTTON_ACTION_ACK:
        # Dismissing posts the ack text when there is one. The text is a template
        # like a config's reply message, rendered against the original message with
        # the defining config's date/time settings.
        if value:
            text = await actions.render_template_text(app, opsgenie_token, channel, src_config or {}, src_config_name, run_context, value)
            await messaging._post_message(app, posted_channel_id, text, None, message_ts)
        # Nothing to post is still a successful "handled".
        return True
    else:
        log_warning(f"Unsupported button action '{action}' in #{channel.name}.")
        return False


async def _run_escalation(app: AsyncApp, opsgenie_token: str, entry: dict) -> None:
    kind = entry.get('escalation_kind', ESCALATION_NONE)
    channel = await slackcache.get_channel_by_id(app, entry['def_channel_id'])
    posted_channel_id, message_ts = entry['posted_channel_id'], entry['message_ts']
    run_context = await _escalation_context(app, entry, posted_channel_id, message_ts)
    if kind == ESCALATION_BUTTON:
        # Auto-press the configured default button, resolved against the snapshot
        # taken when the message was posted (falling back to the live config).
        snapshot = entry.get('buttons')
        src_config = channel.configs.get(entry.get('config_name'))
        lookup = {'buttons': snapshot} if snapshot is not None else src_config
        idx = _find_button_index(lookup, entry.get('escalation_target', ''))
        if idx is None:
            log_warning(f"Default button '{entry.get('escalation_target')}' not found in #{channel.name}.")
            # The pending record is already consumed, so a later press would be ignored.
            # Take the buttons away rather than leave dead ones on the message.
            await _strip_buttons(app, posted_channel_id, message_ts, entry,
                                 _timeout_note(entry.get('timeout', 0), entry.get('escalation_target', ''), ok=False))
            return
        buttons = snapshot if snapshot is not None else (src_config or {}).get('buttons') or []
        log(f"No button pressed on message {message_ts}: auto-pressing '{entry.get('escalation_target')}' in #{channel.name}.")
        ok = await dispatch_button_action(app, opsgenie_token, channel, posted_channel_id, message_ts, buttons[idx], run_context, src_config, entry.get('config_name', ''), entry.get('target_conditions'))
        await _strip_buttons(app, posted_channel_id, message_ts, entry, _timeout_note(entry.get('timeout', 0), _ran_config(buttons[idx]), ok))
    elif kind == ESCALATION_CONFIG:
        target = entry.get('escalation_target', '')
        target_config = channel.configs.get(target)
        if target_config:
            log(f"Escalating message {message_ts}: running '{target}' in #{channel.name}.")
            target_config = _with_snapshotted_conditions(target_config, entry.get('target_conditions'), target)
            posted = await actions.run_action(app, opsgenie_token, channel, target_config, target, context=run_context)
            await _strip_buttons(app, posted_channel_id, message_ts, entry, _timeout_note(entry.get('timeout', 0), target, bool(posted)))
        else:
            log_warning(f"Escalation target '{target}' not found in #{channel.name}.")
            await _strip_buttons(app, posted_channel_id, message_ts, entry,
                                 _timeout_note(entry.get('timeout', 0), target, ok=False))


async def _escalation_task(app: AsyncApp, opsgenie_token: str, key: tuple, timeout: float) -> None:
    try:
        await asyncio.sleep(timeout)
        entry = _claim_pending_button(key, owner=asyncio.current_task())
        if entry:
            await persistence.flush_button_cache()
            log(f"No button pressed on message {key[1]} within timeout; escalating.")
            await _run_escalation(app, opsgenie_token, entry)
    except asyncio.CancelledError:
        # Cancellation alone means shutdown or timer replacement. The caller that
        # explicitly consumed/replaced this record owns cache updates; shutdown must
        # leave the persisted entry available for restoration in the next process.
        return
    except Exception as e:
        log_error(f"Escalation task failed for message {key[1]}:", e)


def _claim_pending_button(key: tuple, owner: asyncio.Task | None = None) -> dict | None:
    """Synchronously claim a pending record so only one consumer can dispatch it."""
    entry = state.pending_buttons.get(key)
    if entry is None:
        return None
    task = entry.get('task')
    if owner is not None and task is not None and task is not owner and not task.done():
        return None
    state.pending_buttons.pop(key, None)
    state._button_states_cache.pop(key, None)
    if task is not None and task is not asyncio.current_task():
        task.cancel()
    return entry


async def cancel_pending_button(posted_channel_id: str, message_ts: str) -> None:
    key = (posted_channel_id, message_ts)
    entry = _claim_pending_button(key)
    if entry:
        await persistence.flush_button_cache()


async def cancel_channel_pending_buttons(channel_id: str) -> int:
    """Drop every pending button record tied to a channel; returns how many were dropped.

    Used when the bot is removed from a channel: a message posted there can no
    longer be updated or replied to, and a record defined by one of that
    channel's (now disabled) configs would escalate into a config the bot is no
    longer running.
    """
    if not channel_id:
        return 0

    def belongs(entry: dict) -> bool:
        return entry.get('posted_channel_id') == channel_id or entry.get('def_channel_id') == channel_id

    keys = {key for key, entry in state.pending_buttons.items() if belongs(entry)}
    keys |= {key for key, entry in state._button_states_cache.items() if belongs(entry)}
    for key in keys:
        # Cancels the escalation timer and drops the live record; the pop also
        # covers a cached record that has no live counterpart.
        _claim_pending_button(key)
        state._button_states_cache.pop(key, None)
    if keys:
        await persistence.flush_button_cache()
    return len(keys)


async def reschedule_escalation(app: AsyncApp, opsgenie_token: str, posted_channel_id: str, message_ts: str, minutes: int, *, _entry: dict | None = None) -> bool:
    key = (posted_channel_id, message_ts)
    entry = _entry if _entry is not None else _claim_pending_button(key)
    if not entry:
        log_warning(f"No pending escalation to delay for message {message_ts}.")
        return False
    record = {k: v for k, v in entry.items() if k != 'task'}
    if record.get('escalation_kind', ESCALATION_NONE) == ESCALATION_NONE:
        # Nothing to postpone. Put the record back (unchanged, no timer) so the
        # other buttons on the message keep working.
        log_warning(f"Nothing to delay for message {message_ts}: this config has no escalation.")
        state.pending_buttons[key] = {'task': None, **record}
        state._button_states_cache[key] = record
        await persistence.flush_button_cache()
        return False
    extra = minutes * 60
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


def _ran_config(button: dict) -> str:
    """The config a button runs, if it runs one."""
    action, value = normalize_button(button)
    return value if action == BUTTON_ACTION_CONFIG and value else ""


def _ran_suffix(ran: str, ok: bool = True) -> str:
    """The config a press or a timeout ran, if any.

    Marked `(skipped)` when that config declined to run — its conditions were not met, or
    its action had nowhere to send. The message is consumed either way, so the note has to
    say which of the two happened.
    """
    if not ran:
        return ""
    return f" ▶︎ {ran}" if ok else f" ▶︎ {ran} (skipped)"


def _press_note(button: dict, presser: User | None, ok: bool = True) -> str:
    """What the message says in place of its buttons after somebody pressed one."""
    who = (presser.real_name or presser.name or '?') if presser else 'Someone'
    return f"_{who}: [{button.get('label') or '?'}]{_ran_suffix(_ran_config(button), ok)}_"


def _timeout_note(timeout: float, ran: str = "", ok: bool = True) -> str:
    """…and what it says when the escalation acted instead of a person."""
    return f"_⌛︎ {int((timeout or 0) // 60)}m{_ran_suffix(ran, ok)}_"


async def _strip_buttons(app: AsyncApp, posted_channel_id: str, message_ts: str, entry: dict | None, note: str = "") -> None:
    """Remove the interactive buttons from a handled message so a stale later click
    can't fire an action against a since-edited config, leaving a note of what was
    done in their place (already formatted by `_press_note`/`_timeout_note`).
    Best-effort."""
    posted_text = (entry or {}).get('posted_text')
    if not posted_text or not posted_channel_id or not message_ts:
        return
    # A plain rule separates the note from the message it belongs to.
    text = f"{posted_text}\n\n---\n{note}" if note else posted_text
    try:
        await app.client.chat_update(
            channel=posted_channel_id,
            ts=message_ts,
            text=text,
            blocks=_section_blocks(text),
        )
    except SlackApiError as e:
        log_warning(f"Failed to remove buttons from message {message_ts} in {posted_channel_id}:", e)


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

    key = (posted_channel_id, message_ts)
    entry = _claim_pending_button(key)
    if entry is None:
        log_warning(f"Ignoring button press for message {message_ts}: no pending button record.")
        return
    # Persist the claim before any dispatch-related await. A concurrent handler now
    # sees no entry, and a restart cannot resurrect an already-consumed button.
    await persistence.flush_button_cache()

    presser_id = (body.get('user', {}) or {}).get('id', '')
    presser = await slackcache.get_user_by_id(app, presser_id) if presser_id else None
    presser_name = presser.name if presser else '?'

    channel = await slackcache.get_channel_by_id(app, def_channel_id)
    # The payload was baked into the Slack message when it was posted, so a rename since then
    # left the name in it stale. The record is rewritten by the rename, so it is the authority
    # on which config posted this; the payload only stands in for a record without the field.
    src_config_name = entry.get('config_name') or src_config_name
    src_config = channel.configs.get(src_config_name)
    # Resolve the pressed button from the snapshot taken when the message was posted
    # (falling back to the live config for messages predating the snapshot), so an
    # edit to the config after posting can't make an old click run the wrong action.
    snapshot = (entry or {}).get('buttons')
    buttons = snapshot if snapshot is not None else ((src_config or {}).get('buttons') or [])
    if index is None or not isinstance(index, int) or index < 0 or index >= len(buttons):
        log_warning(f"Button pressed by @{presser_name} could not be resolved (config '{src_config_name}', index {index}).")
        return
    btn_action, btn_value = normalize_button(buttons[index])
    log(f"Button '{buttons[index].get('label')}' ({btn_action}) pressed by @{presser_name} in #{channel.name}.")

    if btn_action == BUTTON_ACTION_DELAY:
        try:
            minutes = int(btn_value)
        except ValueError:
            minutes = 0
        if minutes > 0:
            await reschedule_escalation(app, opsgenie_token, posted_channel_id, message_ts, minutes, _entry=entry)
        return

    # Every other button has already claimed the pending record, then runs its action. A config
    # run is attributed to the *original* author (presser=None ⇒ orig.user_id), matching
    # the timeout-escalation path; the presser is only used for the log line above.
    run_context = await _escalation_context(app, entry, posted_channel_id, message_ts)
    ok = await dispatch_button_action(app, opsgenie_token, channel, posted_channel_id, message_ts, buttons[index], run_context, src_config, src_config_name, entry.get('target_conditions'))
    await _strip_buttons(app, posted_channel_id, message_ts, entry, _press_note(buttons[index], presser, ok))
