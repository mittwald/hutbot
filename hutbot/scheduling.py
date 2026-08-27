"""Deferred message reminders and the cron-trigger scheduler."""

import asyncio
import datetime

from slack_bolt.async_app import AsyncApp

from employee_list import log, log_error, log_warning

from . import state
from . import datetimefmt
from . import slackcache
from . import actions
from . import persistence
from .conditionutil import snapshot_conditions
from .constants import CONDITION_MODE_ALL, SCHEDULER_INTERVAL, TRIGGER_CRON
from .models import ScheduledReply

try:
    from croniter import croniter
except ImportError:  # pragma: no cover - dependency optional at runtime
    croniter = None


def format_minutes(seconds: float) -> str:
    minutes = int(seconds // 60)
    return f"{minutes} min" if minutes == 1 else f"{minutes} mins"


def _current_config_name(channel_id: str, config: dict, started_as: str) -> str:
    """The name this config is filed under now, which a rename may have changed.

    A rename moves the *key*; the config dict itself is the same object a waiting reply was
    handed, so identity finds it again under whatever it is now called. Falling back to the
    name the reply started with covers a config that was deleted rather than renamed, whose
    records are still filed under the old key.
    """
    for name, candidate in (state.channel_config.get(channel_id) or {}).items():
        if candidate is config:
            return name
    return started_as


def rename_scheduled_replies(channel_id: str, old_name: str, new_name: str) -> int:
    """Move a renamed config's pending reminders onto the new name; returns how many moved.

    Re-keying is all it takes — a waiting task holds the config *object*, which the rename
    moves intact, so the reminder still fires with the right settings and still cleans up after
    itself. The name in the key is what `routing` reads back to decide whether a thread reply
    cancels this reminder, and what `restore_scheduled_replies` looks up after a restart, so
    leaving it stale would quietly change what an already-queued reminder does.

    Synchronous on purpose, like `buttons.rename_pending_buttons`: the caller rewrites every
    reference before it yields, and flushes the persisted mirror afterwards.
    """
    moved = set()
    for key in [key for key in state.scheduled_messages if key[0] == channel_id and key[2] == old_name]:
        state.scheduled_messages[(channel_id, key[1], new_name)] = state.scheduled_messages.pop(key)
        moved.add(key[1])
    for key in [key for key in state._scheduled_replies_cache if key[0] == channel_id and key[2] == old_name]:
        entry = state._scheduled_replies_cache.pop(key)
        entry['config_name'] = new_name
        state._scheduled_replies_cache[(channel_id, key[1], new_name)] = entry
        moved.add(key[1])
    return len(moved)


async def schedule_reply(app: AsyncApp, opsgenie_token: str, channel, config: dict, config_name: str, user, text: str, ts: str, wait_time_override: float | None = None, original_wait_time: float | None = None, conditions_snapshot: dict | None = None) -> None:
    # Captured before the wait so an edit during it cannot retroactively cancel this
    # reminder; a restored reply brings its original snapshot along.
    frozen_conditions = conditions_snapshot if conditions_snapshot is not None else snapshot_conditions(config)
    opsgenie_enabled = config.get('opsgenie')
    wait_time = config.get('wait_time')
    scheduled_message_key = (channel.id, ts, config_name)
    actual_wait = wait_time_override if wait_time_override is not None else wait_time
    if wait_time_override is None:
        verb = "Scheduling"
        timing = f"wait time {format_minutes(wait_time)}"
    else:
        # A restored reply keeps the deadline it was scheduled with, so log what it
        # is actually waiting for — and name the wait time it started with, which
        # the config may since have changed.
        verb = "Rescheduling"
        timing = f"{actual_wait:.0f}s remaining"
        if original_wait_time is not None:
            timing += f" of the original {format_minutes(original_wait_time)}"
            if int(original_wait_time) != int(wait_time):
                timing += f", config now {format_minutes(wait_time)}"
    log(f"{verb} reply for message {ts} in channel #{channel.name} for config '{config_name}', user @{user.name}, {timing}, opsgenie {'enabled' if opsgenie_enabled else 'disabled'}{', but not configured' if opsgenie_enabled and not state.opsgenie_configured else ''}")
    try:
        await asyncio.sleep(actual_wait)
        permalink = await slackcache.get_message_permalink(app, channel, ts)
        # Single unified send path: the reply (and any configured action/buttons)
        # goes through the action engine. The message context lets the reply thread
        # on the original message and reuse its template variables.
        # Everything except the conditions is read live, so a changed message or action
        # still applies; the conditions are the ones this reply was scheduled with.
        run_config = {**config, **frozen_conditions}
        # A rename during the wait moved this config, and the reply belongs to whatever it is
        # called now — that is the name `{{config}}` renders, and the name any buttons this
        # reply posts record as theirs.
        posted = await actions.run_action(app, opsgenie_token, channel, run_config, _current_config_name(channel.id, config, config_name), context={
            'user': user,
            'text': text,
            'ts': ts,
            'thread_ts': ts,
            'channel_id': channel.id,
            'permalink': permalink,
        })
        # OpsGenie is fired inside run_action when this config has it enabled. To
        # button-gate an alert, put OpsGenie on a separate (manual) config and run
        # it from a button / button-timeout instead of on the reply config itself.
    except asyncio.CancelledError as e:
        log(f"Cancelling scheduled reply for message {ts} in channel #{channel.name} for config '{config_name}', user @{user.name}:", e)
    except Exception as e:
        log_error(f"Failed to send scheduled reply for message {ts} in channel #{channel.name} for config '{config_name}', user @{user.name}:", e)
    finally:
        # Not `scheduled_message_key`: a rename during the wait moved this reply onto a new
        # name, and the records to drop are the ones filed under it now.
        cleanup_key = (channel.id, ts, _current_config_name(channel.id, config, config_name))
        state.scheduled_messages.pop(cleanup_key, None)
        state._scheduled_replies_cache.pop(cleanup_key, None)
        await persistence.flush_replies_cache()


def _cron_due(cron_expr: str, config: dict, last: datetime.datetime, now: datetime.datetime) -> bool:
    # A cron fires in the config's date/time timezone (server local without one),
    # the same timezone its work hours and date/time output use.
    tz = datetimefmt.get_config_timezone(config)
    base = last.astimezone(tz)
    current = now.astimezone(tz)
    try:
        nxt = croniter(cron_expr, base).get_next(datetime.datetime)
    except (ValueError, KeyError) as e:
        log_warning(f"Invalid cron expression '{cron_expr}': {e}")
        return False
    return nxt <= current


async def run_scheduler(app: AsyncApp, opsgenie_token: str) -> None:
    if croniter is None:
        log_warning("croniter is not installed; scheduled triggers are disabled.")
        return
    state._scheduler_last_check = datetime.datetime.now(datetime.timezone.utc)
    log(f"Scheduler started (interval {SCHEDULER_INTERVAL}s).")
    while True:
        await asyncio.sleep(SCHEDULER_INTERVAL)
        try:
            await scheduler_tick(app, opsgenie_token)
        except Exception as e:
            log_error("Scheduler tick failed:", e)


async def scheduler_tick(app: AsyncApp, opsgenie_token: str) -> None:
    now = datetime.datetime.now(datetime.timezone.utc)
    last = state._scheduler_last_check or now
    state._scheduler_last_check = now
    for channel_id, configs in list(state.channel_config.items()):
        for config_name, config in list(configs.items()):
            if config.get('trigger') != TRIGGER_CRON:
                continue
            if not config.get('enabled', True):
                continue
            cron_expr = config.get('cron') or ''
            if not cron_expr:
                continue
            if croniter is not None and not croniter.is_valid(cron_expr):
                log_warning(f"Cron config '{config_name}' in channel {channel_id} has an invalid expression '{cron_expr}'.")
                continue
            if not _cron_due(cron_expr, config, last, now):
                continue
            channel = await slackcache.get_channel_by_id(app, channel_id)
            # Conditions are not checked here: `run_action` gates every trigger, so the
            # cron path cannot drift out of step with the message and button paths.
            log(f"Cron config '{config_name}' in #{channel.name} firing.")
            try:
                await actions.run_action(app, opsgenie_token, channel, config, config_name, context={'channel_id': channel_id})
            except Exception as e:
                log_error(f"Cron config '{config_name}' action failed:", e)


async def restore_scheduled_replies(app: AsyncApp, opsgenie_token: str) -> None:
    entries = list(state._scheduled_replies_cache.items())
    invalid_keys = []
    restored = 0
    log(f"Restoring {len(entries)} scheduled replies from cache...")
    for key, entry in entries:
        channel_id = entry['channel_id']
        ts = entry['ts']
        config_name = entry['config_name']
        if channel_id not in state.channel_config or config_name not in state.channel_config[channel_id]:
            log_warning(f"Skipping cached reply for message {ts}: channel {channel_id} / config '{config_name}' no longer configured.")
            invalid_keys.append(key)
            continue
        config = state.channel_config[channel_id][config_name]
        channel = await slackcache.get_channel_by_id(app, channel_id)
        user = await slackcache.get_user_by_id(app, entry['user_id'])
        send_at = datetime.datetime.fromisoformat(entry['send_at'])
        remaining = max(0.0, (send_at - datetime.datetime.now()).total_seconds())
        # Written since the cache gained the field; older entries have no original.
        original_wait_time = entry.get('wait_time')
        # Written since the cache gained the conditions snapshot; older entries fall back
        # to the config as it is now, which is the best that can be reconstructed.
        cached_conditions = (
            {'conditions': entry['conditions'], 'conditions_mode': entry.get('conditions_mode') or CONDITION_MODE_ALL}
            if isinstance(entry.get('conditions'), list) else None
        )
        log(f"Restoring reply for message {ts} in channel #{channel.name} for config '{config_name}', user @{user.name}, due {send_at.isoformat(timespec='seconds')}.")
        task = asyncio.create_task(schedule_reply(app, opsgenie_token, channel, config, config_name, user, entry['text'], ts, wait_time_override=remaining, original_wait_time=original_wait_time, conditions_snapshot=cached_conditions))
        state.scheduled_messages[(channel.id, ts, config_name)] = ScheduledReply(task, user.id)
        restored += 1
    for key in invalid_keys:
        state._scheduled_replies_cache.pop(key, None)
    if invalid_keys:
        await persistence.flush_replies_cache()
    log(f"Restored {restored} scheduled replies.")
