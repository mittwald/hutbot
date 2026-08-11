"""Scheduled replies (deferred message reminders) and the cron-trigger scheduler."""

import asyncio
import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from slack_bolt.async_app import AsyncApp
from slack_sdk.errors import SlackApiError

from employee_list import log, log_error, log_warning

from . import state
from . import slackcache
from . import actions
from . import persistence
from .constants import ACTION_REPLY, SCHEDULER_INTERVAL, TRIGGER_SCHEDULE
from .models import ScheduledReply

try:
    from croniter import croniter
except ImportError:  # pragma: no cover - dependency optional at runtime
    croniter = None


async def schedule_reply(app: AsyncApp, opsgenie_token: str, channel, config: dict, config_name: str, user, text: str, ts: str, wait_time_override: float | None = None) -> None:
    opsgenie_enabled = config.get('opsgenie')
    wait_time = config.get('wait_time')
    scheduled_message_key = (channel.id, ts, config_name)
    actual_wait = wait_time_override if wait_time_override is not None else wait_time
    log(f"Scheduling reply for message {ts} in channel #{channel.name} for config '{config_name}', user @{user.name}, wait time {wait_time // 60} mins, opsgenie {'enabled' if opsgenie_enabled else 'disabled'}{', but not configured' if opsgenie_enabled and not state.opsgenie_configured else ''}")
    try:
        await asyncio.sleep(actual_wait)
        permalink = await slackcache.get_message_permalink(app, channel, ts)
        # Single unified send path: the reply (and any configured action/buttons)
        # goes through the action engine. The message context lets the reply thread
        # on the original message and reuse its template variables.
        posted = await actions.run_action(app, opsgenie_token, channel, config, config_name, context={
            'user': user,
            'text': text,
            'ts': ts,
            'thread_ts': ts,
            'channel_id': channel.id,
            'permalink': permalink,
        })
        reply_message = (posted or {}).get('text', '')
        forward_channel_id = config.get('forward_channel')
        if config.get('action', ACTION_REPLY) == ACTION_REPLY and forward_channel_id and reply_message:
            try:
                forward_text = f"{reply_message}\n\n*Original message in #{channel.name}:* {permalink}"
                await app.client.chat_postMessage(channel=forward_channel_id, text=forward_text, mrkdwn=True)
            except SlackApiError as e:
                log_error(f"Failed to forward reply to channel {forward_channel_id}:", e)
        # OpsGenie is fired inside run_action when this config has it enabled. To
        # button-gate an alert, put OpsGenie on a separate (manual) config and run
        # it from a button / button-timeout instead of on the reply config itself.
    except asyncio.CancelledError as e:
        log(f"Cancelling scheduled reply for message {ts} in channel #{channel.name} for config '{config_name}', user @{user.name}:", e)
    except Exception as e:
        log_error(f"Failed to send scheduled reply for message {ts} in channel #{channel.name} for config '{config_name}', user @{user.name}:", e)
    finally:
        state.scheduled_messages.pop(scheduled_message_key, None)
        state._scheduled_replies_cache.pop(scheduled_message_key, None)
        await persistence.flush_replies_cache()


def _resolve_schedule_timezone(config: dict):
    tz_name = config.get('schedule_timezone') or config.get('datetime_timezone') or ''
    if tz_name:
        try:
            return ZoneInfo(tz_name)
        except ZoneInfoNotFoundError:
            log_warning(f"Unknown schedule timezone '{tz_name}'; using server local time.")
    return None


def _cron_due(cron_expr: str, config: dict, last: datetime.datetime, now: datetime.datetime) -> bool:
    tz = _resolve_schedule_timezone(config)
    base = last.astimezone(tz) if tz else last.astimezone()
    current = now.astimezone(tz) if tz else now.astimezone()
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
            if config.get('trigger') != TRIGGER_SCHEDULE:
                continue
            if not config.get('enabled', True):
                continue
            cron_expr = config.get('schedule_cron') or ''
            if not cron_expr:
                continue
            if croniter is not None and not croniter.is_valid(cron_expr):
                log_warning(f"Schedule '{config_name}' in channel {channel_id} has invalid cron '{cron_expr}'.")
                continue
            if not _cron_due(cron_expr, config, last, now):
                continue
            channel = await slackcache.get_channel_by_id(app, channel_id)
            if not await actions.evaluate_condition(app, config):
                log(f"Schedule '{config_name}' in #{channel.name} fired but condition not met.")
                continue
            log(f"Schedule '{config_name}' in #{channel.name} firing.")
            try:
                await actions.run_action(app, opsgenie_token, channel, config, config_name, context={'channel_id': channel_id})
            except Exception as e:
                log_error(f"Schedule '{config_name}' action failed:", e)


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
        log(f"Restoring reply for message {ts} in channel #{channel.name} for config '{config_name}', user @{user.name}, remaining {remaining:.0f}s.")
        task = asyncio.create_task(schedule_reply(app, opsgenie_token, channel, config, config_name, user, entry['text'], ts, wait_time_override=remaining))
        state.scheduled_messages[(channel.id, ts, config_name)] = ScheduledReply(task, user.id)
        restored += 1
    for key in invalid_keys:
        state._scheduled_replies_cache.pop(key, None)
    if invalid_keys:
        await persistence.flush_replies_cache()
    log(f"Restored {restored} scheduled replies.")
