"""Read-only slash-command handlers: lists, team lookup, and config display."""

import aiohttp
from slack_bolt.async_app import AsyncApp

from employee_list import get_env_var, log_error

from .. import state
from .. import messaging
from .. import slackcache
from .. import opsgenie
from .. import buttons
from ..buttonutil import normalize_button
from ..constants import (
    ACTION_REPLY,
    DEFAULT_DATE_FORMAT,
    DEFAULT_TIME_FORMAT,
    ESCALATION_BUTTON,
    ESCALATION_CONFIG,
    ID_PATTERN,
    TRIGGER_MESSAGE,
    TRIGGER_SCHEDULE,
)
from ..textutil import log_debug


async def list_teams(app: AsyncApp, channel, user, thread_ts: str = "") -> None:
    await slackcache.update_user_cache(app)
    message = f"*Available teams*:\n{'\n'.join(sorted(state.team_cache, key=lambda v: v.upper()))}"
    await messaging.send_message(app, channel, user, message, thread_ts)


async def list_opsgenie_schedules(app: AsyncApp, channel, user, thread_ts: str = "") -> None:
    opsgenie_token = get_env_var("OPSGENIE_TOKEN")
    if not opsgenie_token:
        await messaging.send_message(app, channel, user, "OpsGenie is not configured. Missing `OPSGENIE_TOKEN`.", thread_ts)
        return

    url = "https://api.opsgenie.com/v2/schedules"
    headers = {
        "Authorization": f"GenieKey {opsgenie_token}",
    }

    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            async with session.get(url, headers=headers) as response:
                if response.status != 200:
                    log_error(f"Failed to list OpsGenie schedules: {response.status}")
                    await messaging.send_message(app, channel, user, f"Failed to list OpsGenie schedules: HTTP {response.status}.", thread_ts)
                    return

                payload = await response.json()
    except Exception as e:
        log_error("Failed to list OpsGenie schedules:", e)
        await messaging.send_message(app, channel, user, "Failed to list OpsGenie schedules.", thread_ts)
        return

    schedules = payload.get("data", [])
    if not schedules:
        await messaging.send_message(app, channel, user, "No OpsGenie schedules found.", thread_ts)
        return

    schedule_names = sorted(
        (schedule.get("name", "").strip() for schedule in schedules if schedule.get("name")),
        key=str.casefold
    )
    if not schedule_names:
        await messaging.send_message(app, channel, user, "No OpsGenie schedules found.", thread_ts)
        return

    message = "*OpsGenie schedules*:\n" + "\n".join(f"`{name}`" for name in schedule_names)
    await messaging.send_message(app, channel, user, message, thread_ts)


async def get_team_of(app: AsyncApp, channel, username: str, user, thread_ts: str = "") -> None:
    message = None
    log_debug(channel, f"Looking up users from message `{username}`...")
    for match in ID_PATTERN.finditer(username):
        full_match = match.group(0)
        log_debug(channel, f"Found ID match: {full_match}...")
        id = match.group(1)
        if id and id[0] == '@':
            user_id = id[1:]
            log_debug(channel, f"Looking up user with ID {user_id}...")
            u = await slackcache.get_user_by_id(app, user_id, channel)
            if u.id:
                log_debug(channel, f"Found user {u}")
                display_name = u.real_name if u.real_name else u.name
                msg = f"*{display_name}* (<@{u.id}>): `{u.team}`"
                if message is None:
                    message = msg
                else:
                    message += f"\n{msg}"
            else:
                log_error(f"Invalid request: username `{full_match}` not found")
    if message:
        await messaging.send_message(app, channel, user, message, thread_ts)
    else:
        await messaging.send_message(app, channel, user, f"Unknown user: `{username}`.", thread_ts)


async def show_config(app: AsyncApp, channel, user, thread_ts: str = "") -> None:
    if not channel.configs:
        message = f"There is no configuration for #{channel.name}."
        await messaging.send_message(app, channel, user, message, thread_ts)
        return

    def format_table_value(value, key_width: int) -> str:
        if isinstance(value, list):
            if not value:
                return '<None>'
            return f"\n{' ' * (key_width + 2)}".join(value)
        return value

    message = f"This is the configuration for #{channel.name}:"
    for config_name, config in sorted(channel.configs.items()):
        opsgenie_enabled = config.get('opsgenie')
        wait_time_minutes = config.get('wait_time') // 60
        included_teams = config.get('included_teams')
        excluded_teams = config.get('excluded_teams')
        include_bots = config.get('include_bots')
        only_work_days = config.get('only_work_days')
        hours = config.get('hours')
        pattern = config.get('pattern')
        pattern_case_sensitive = config.get('pattern_case_sensitive')
        reply_message = config.get('reply_message')
        forward_channel_id = config.get('forward_channel') or ''
        opsgenie_schedule_name = config.get('opsgenie_schedule_name')
        date_format = config.get('date_format') or DEFAULT_DATE_FORMAT
        time_format = config.get('time_format') or DEFAULT_TIME_FORMAT
        datetime_timezone = config.get('datetime_timezone') or '<server local>'
        datetime_locale = config.get('datetime_locale') or '<default>'
        opsgenie_priority = opsgenie.get_opsgenie_priority(config)
        replies_enabled = config.get('enabled', True)
        trigger = config.get('trigger', TRIGGER_MESSAGE)
        action = config.get('action', ACTION_REPLY)

        rows = [
            ("Trigger",            trigger),
            ("OpsGenie",           ('enabled' if opsgenie_enabled else 'disabled') + ('' if state.opsgenie_configured else ' (not configured)')),
            ("OpsGenie schedule",  opsgenie_schedule_name),
            ("OpsGenie priority",  opsgenie_priority),
            ("OpsGenie message",   config.get('opsgenie_message') or '<original message>'),
            ("Date format",        date_format),
            ("Time format",        time_format),
            ("Date/time timezone", datetime_timezone),
            ("Date/time locale",   datetime_locale),
            ("Wait time",          f"{wait_time_minutes} minutes"),
            ("Included teams",     included_teams),
            ("Excluded teams",     excluded_teams),
            ("Include bots",       'enabled' if include_bots else 'disabled'),
            ("Only work days",     'enabled' if only_work_days else 'disabled'),
            ("Work hours",         f"{hours[0]} - {hours[1]}" if len(hours) == 2 else 'all day'),
            ("Pattern",            f"{pattern} ({'case-sensitive' if pattern_case_sensitive else 'case-insensitive'})" if pattern else '<None>'),
        ]

        if trigger == TRIGGER_SCHEDULE:
            rows.append(("Cron", config.get('schedule_cron') or '<None>'))
            rows.append(("Schedule timezone", config.get('schedule_timezone') or '<server local>'))
        condition = config.get('condition') or ''
        if condition:
            negate = ' (negated)' if config.get('condition_negate') else ''
            rows.append(("Condition", f"{condition}{negate}"))
            if config.get('outlook_subject_pattern'):
                rows.append(("Outlook subject", config.get('outlook_subject_pattern')))
            if config.get('outlook_body_pattern'):
                rows.append(("Outlook body", config.get('outlook_body_pattern')))
        if action != ACTION_REPLY:
            rows.append(("Action", action))
            rows.append(("Action target", config.get('action_target') or '<None>'))
        config_buttons = config.get('buttons') or []
        if config_buttons:
            def _button_label(b):
                action, value = normalize_button(b)
                return f"{b.get('label')} → {action}" + (f":{value}" if value else "")
            rows.append(("Buttons", [_button_label(b) for b in config_buttons]))
            button_timeout_minutes = (config.get('button_timeout') or 0) // 60
            if button_timeout_minutes:
                kind, target = buttons._escalation_kind(config)
                if kind == ESCALATION_BUTTON:
                    escalates_to = f"auto-press `{target}`"
                elif kind == ESCALATION_CONFIG:
                    escalates_to = f"run `{target}`"
                else:
                    escalates_to = "nothing"
                rows.append(("Button timeout", f"{button_timeout_minutes} minutes → {escalates_to}"))
            if config.get('default_button'):
                rows.append(("Default button", config.get('default_button')))
        key_width = max(len(label) for label, _ in rows)
        config_block = "\n".join(f"{label:<{key_width}}  {format_table_value(value, key_width)}" for label, value in rows)
        forward_channel_line = f"*Forward channel*: {f'<#{forward_channel_id}>' if forward_channel_id else '<None>'}"
        reply_line = f"*Reply message*:\n{reply_message}" if reply_message else "*Reply message*: <None>"
        enabled_label = 'enabled' if replies_enabled else 'disabled'
        quoted_block = (
            f"> {reply_line.replace('\n', '\n> ')}\n"
            f">\n"
            f"> {forward_channel_line}\n"
            f">\n"
            f"> *Settings*:\n"
        )
        message += (
            f"\n\n*Configuration*: `{config_name}` ({enabled_label})\n"
            f"{quoted_block}"
            f"```\n{config_block}\n```"
        )
    await messaging.send_message(app, channel, user, message, thread_ts)
