"""Read-only slash-command handlers: lists, team lookup, and config display."""

import re

import aiohttp
from slack_bolt.async_app import AsyncApp

from employee_list import get_env_var, log_error

from .. import state
from .. import messaging
from .. import slackcache
from .. import opsgenie
from .. import buttons
from .. import datetimefmt
from ..buttonutil import normalize_button
from .. import targets
from ..constants import (
    ACTION_DM_USER,
    ACTION_GROUP_DM,
    ACTION_POST_CHANNEL,
    ACTION_REPLY,
    DEFAULT_DATE_FORMAT,
    DEFAULT_TIME_FORMAT,
    DISABLED_REASON_REMOVED,
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
                return '<none>'
            return f"\n{' ' * (key_width + 2)}".join(value)
        return value

    def format_target(target: str) -> str:
        """Render an action target as a Slack mention when it looks like an id."""
        target = (target or '').strip()
        if not target:
            return '<none>'
        channel_id = targets.parse_channel_ref(target)
        if channel_id:
            return f"<#{channel_id}>"
        if ID_PATTERN.fullmatch(target) or re.fullmatch(r'<!subteam\^[A-Z0-9]+(\|[^>]*)?>', target):
            return target
        if re.fullmatch(r'[UW][A-Z0-9]+', target):
            return f"<@{target}>"
        if re.fullmatch(r'S[A-Z0-9]+', target):
            return f"<!subteam^{target}>"
        return f"`{target}`"

    def destination_lines(config: dict, action: str, trigger: str, forward_channel_id: str) -> list[str]:
        """Where the message ends up, phrased per action instead of as raw fields."""
        action_target = config.get('action_target') or ''
        if action == ACTION_REPLY:
            # A reply threads on the triggering message; schedule/manual runs have
            # no message to thread on and land in the channel itself.
            thread = ' (in thread)' if trigger == TRIGGER_MESSAGE else ''
            lines = [f"*Replied in* <#{channel.id}>{thread}"]
            if forward_channel_id:
                lines.append(f"*Forwarded to* <#{forward_channel_id}>")
            return lines
        if action == ACTION_POST_CHANNEL:
            return [f"*Posted in* {format_target(action_target or forward_channel_id)}"]
        if action == ACTION_DM_USER:
            return [f"*Sent to* {format_target(action_target)} (direct message)"]
        if action == ACTION_GROUP_DM:
            return [f"*Sent to* {format_target(action_target)} (group message)"]
        return [f"*Action* `{action}`, target {format_target(action_target)}"]

    message = f"This is the configuration for #{channel.name}:"
    config_sections = []
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
        datetime_timezone = datetimefmt.describe_timezone(config.get('datetime_timezone') or '')
        datetime_locale = datetimefmt.describe_locale(config.get('datetime_locale') or '')
        opsgenie_priority = opsgenie.get_opsgenie_priority(config)
        replies_enabled = config.get('enabled', True)
        trigger = config.get('trigger', TRIGGER_MESSAGE)
        action = config.get('action', ACTION_REPLY)

        # Settings are grouped by topic, in the order a rule runs: when it fires,
        # what gates it, what it matches, timing, buttons, alerting, formatting.
        # Each group becomes a blank-line-separated block in the code block.
        groups: list[list[tuple]] = []

        if trigger == TRIGGER_SCHEDULE:
            # Same fallback chain the scheduler uses: own timezone, then the
            # date/time one, then the server's.
            schedule_timezone = config.get('schedule_timezone') or config.get('datetime_timezone') or ''
            groups.append([
                ("Cron",              config.get('schedule_cron') or '<none>'),
                ("Schedule timezone", datetimefmt.describe_timezone(schedule_timezone)),
            ])

        condition = config.get('condition') or ''
        if condition:
            negate = ' (negated)' if config.get('condition_negate') else ''
            condition_rows = [("Condition", f"{condition}{negate}")]
            if config.get('outlook_subject_pattern'):
                condition_rows.append(("Outlook subject", config.get('outlook_subject_pattern')))
            if config.get('outlook_body_pattern'):
                condition_rows.append(("Outlook body", config.get('outlook_body_pattern')))
            groups.append(condition_rows)

        groups.append([
            ("Pattern",        f"{pattern} ({'case-sensitive' if pattern_case_sensitive else 'case-insensitive'})" if pattern else '<none>'),
            ("Included teams", included_teams),
            ("Excluded teams", excluded_teams),
            ("Include bots",   'enabled' if include_bots else 'disabled'),
        ])

        groups.append([
            ("Wait time",      f"{wait_time_minutes} minutes"),
            ("Only work days", 'enabled' if only_work_days else 'disabled'),
            ("Work hours",     f"{hours[0]} - {hours[1]}" if len(hours) == 2 else 'all day'),
        ])

        config_buttons = config.get('buttons') or []
        if config_buttons:
            def _button_label(b):
                button_action, value = normalize_button(b)
                return f"{b.get('label')} → {button_action}" + (f":{value}" if value else "")
            button_rows = [("Buttons", [_button_label(b) for b in config_buttons])]
            button_timeout_minutes = (config.get('button_timeout') or 0) // 60
            if button_timeout_minutes:
                kind, target = buttons._escalation_kind(config)
                if kind == ESCALATION_BUTTON:
                    escalates_to = f"auto-press `{target}`"
                elif kind == ESCALATION_CONFIG:
                    escalates_to = f"run `{target}`"
                else:
                    escalates_to = "nothing"
                button_rows.append(("Button timeout", f"{button_timeout_minutes} minutes → {escalates_to}"))
            if config.get('default_button'):
                button_rows.append(("Default button", config.get('default_button')))
            groups.append(button_rows)

        groups.append([
            ("OpsGenie",          ('enabled' if opsgenie_enabled else 'disabled') + ('' if state.opsgenie_configured else ' (not configured)')),
            ("OpsGenie schedule", opsgenie_schedule_name or '<none>'),
            ("OpsGenie priority", opsgenie_priority),
            ("OpsGenie message",  config.get('opsgenie_message') or '<original message>'),
        ])

        groups.append([
            ("Date format",        date_format),
            ("Time format",        time_format),
            ("Date/time timezone", datetime_timezone),
            ("Date/time locale",   datetime_locale),
        ])

        key_width = max(len(label) for group in groups for label, _ in group)
        config_block = "\n\n".join(
            "\n".join(f"{label:<{key_width}}  {format_table_value(value, key_width)}" for label, value in group)
            for group in groups
        )
        message_label = 'Reply message' if action == ACTION_REPLY else 'Message'
        reply_line = f"*{message_label}*:\n{reply_message}" if reply_message else f"*{message_label}*: <none>"
        destinations = "\n".join(destination_lines(config, action, trigger, forward_channel_id))
        if replies_enabled:
            enabled_label = 'enabled'
        elif config.get('disabled_reason') == DISABLED_REASON_REMOVED:
            enabled_label = f'disabled, because {state.bot_name} was removed from this channel'
        else:
            enabled_label = 'disabled'
        quoted_block = (
            f"> *Trigger*: `{trigger}`\n"
            f">\n"
            f"> {reply_line.replace('\n', '\n> ')}\n"
            f">\n"
            f"> {destinations.replace('\n', '\n> ')}\n"
            f">\n"
            f"> *Settings*:\n"
        )
        config_sections.append(
            f"*Configuration*: `{config_name}` ({enabled_label})\n"
            f"{quoted_block}"
            f"```\n{config_block}\n```"
        )
    # Slack splits an oversized message wherever the break lands, cutting the code
    # fence in half, so a channel with several configs is sent as several messages.
    for chunk in messaging.pack_message_chunks([message, *config_sections]):
        await messaging.send_message(app, channel, user, chunk, thread_ts)
