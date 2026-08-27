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
from .. import templating
from .. import calendarfeed
from .. import conditionutil
from ..buttonutil import normalize_button
from .. import targets
from ..constants import (
    BUTTON_ACTION_ACK,
    CONDITION_MODE_ALL,
    ACTION_DM_USER,
    DATETIME_TEMPLATE_VARIABLES,
    TEMPLATE_DATETIME_VARIABLES,
    ACTION_GROUP_DM,
    ACTION_POST_CHANNEL,
    ACTION_REPLY,
    DEFAULT_DATE_FORMAT,
    DEFAULT_TIME_FORMAT,
    DISABLED_REASON_REMOVED,
    ESCALATION_BUTTON,
    ESCALATION_NONE,
    ID_PATTERN,
    TRIGGER_MESSAGE,
    TRIGGER_CRON,
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


async def list_calendars(app: AsyncApp, channel, user, thread_ts: str = "") -> None:
    """`list calendars` — the built-in calendars this instance offers.

    Name and title only. A built-in's URL is an instance-wide secret and this reply goes to
    whoever asked in the channel, so it is never printed — not even in its redacted form.
    """
    calendars = sorted(state.builtin_calendars, key=lambda calendar: calendar.name)
    if not calendars:
        await messaging.send_message(app, channel, user, f"No built-in calendars are configured. Point a configuration at a published `.ics` URL with `{state.slash_command} [config] set calendar <url>`.", thread_ts)
        return

    rows = "\n".join(f"`{calendar.name}` — {calendar.title}" for calendar in calendars)
    message = (f"*Built-in calendars*:\n{rows}\n"
               f"Point a configuration at one with `{state.slash_command} [config] set calendar <name>`.")
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

    def destination_lines(config: dict, action: str, trigger: str) -> list[str]:
        """Where the message ends up, phrased per action instead of as raw fields."""
        action_target = config.get('action_target') or ''
        if action == ACTION_REPLY:
            # A reply threads on the triggering message; schedule/manual runs have
            # no message to thread on and land in the channel itself.
            thread = ' (in thread)' if trigger == TRIGGER_MESSAGE else ''
            return [f"*Replied in* <#{channel.id}>{thread}"]
        if action == ACTION_POST_CHANNEL:
            return [f"*Posted in* {format_target(action_target)}"]
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
        #
        # A group is printed only where it has an effect: message matching and the
        # reminder delay mean nothing to a `cron`/`manual` rule, a condition gates
        # only a cron, and the date/time settings matter only to something that
        # renders a date. Printing them anyway invites configuring a field that is
        # never read.
        groups: list[list[tuple]] = []
        reacts_to_messages = trigger == TRIGGER_MESSAGE
        template_variables = (
            templating.find_template_variables(reply_message or '')
            | templating.find_template_variables(config.get('opsgenie_message') or '')
            | conditionutil.condition_variables(config)
        )
        renders_datetime = bool(template_variables & (DATETIME_TEMPLATE_VARIABLES | TEMPLATE_DATETIME_VARIABLES))

        # Conditions gate every trigger, so this block is not tied to `cron` any more.
        conditions = config.get('conditions') or []
        if conditions:
            condition_rows = [("Conditions", [conditionutil.describe_condition(c) for c in conditions])]
            if len(conditions) > 1:
                mode = config.get('conditions_mode') or CONDITION_MODE_ALL
                condition_rows.append(("Condition mode", "all must apply" if mode == CONDITION_MODE_ALL else "any may apply"))
            groups.append(condition_rows)

        if reacts_to_messages:
            groups.append([
                ("Pattern",        f"{pattern} ({'case-sensitive' if pattern_case_sensitive else 'case-insensitive'})" if pattern else '<none>'),
                ("Included teams", included_teams),
                ("Excluded teams", excluded_teams),
                ("Include bots",   'enabled' if include_bots else 'disabled'),
            ])

            groups.append([
                ("Wait time",      f"{wait_time_minutes} minutes"),
                ("Only work days", 'enabled' if only_work_days else 'disabled'),
                ("Work hours",     f"{hours[0]} - {hours[1]}" if len(hours) == 2 else 'any hour'),
            ])

        config_buttons = config.get('buttons') or []
        if config_buttons:
            def _button_label(b):
                button_action, value = normalize_button(b)
                return f"{b.get('label')} → {button_action}" + (f":{value}" if value else "")
            button_rows = [("Buttons", [_button_label(b) for b in config_buttons])]
            # An `ack` text is a public thread reply, not a private confirmation for whoever
            # pressed — said here because the button list alone reads like the text belongs to
            # the press. Where the buttoned message went is printed above, as *Replied in* /
            # *Posted in* / *Sent to*, and the ack follows it into that conversation.
            def _posts_ack_text(b):
                button_action, value = normalize_button(b)
                return button_action == BUTTON_ACTION_ACK and bool(value)
            if any(_posts_ack_text(b) for b in config_buttons):
                button_rows.append(("Ack text", "posted in a thread under the buttoned message, for everyone there"))
            escalation_minutes = (config.get('escalation_timeout') or 0) // 60
            kind, target = buttons._escalation_kind(config)
            if escalation_minutes and kind != ESCALATION_NONE:
                escalates_to = f"auto-press `{target}`" if kind == ESCALATION_BUTTON else f"run `{target}`"
                button_rows.append(("Escalation", f"after {escalation_minutes} minutes, {escalates_to}"))
            else:
                button_rows.append(("Escalation", "none, buttons stay open until pressed"))
            groups.append(button_rows)

        opsgenie_rows = [("OpsGenie", ('enabled' if opsgenie_enabled else 'disabled') + ('' if state.opsgenie_configured else ' (not configured)'))]
        if opsgenie_enabled:
            opsgenie_rows += [
                ("OpsGenie schedule", opsgenie_schedule_name or '<none>'),
                ("OpsGenie priority", opsgenie_priority),
                ("OpsGenie message",  config.get('opsgenie_message') or '<original message>'),
            ]
        groups.append(opsgenie_rows)

        feed = calendarfeed.resolve_calendar_feed(config)
        if feed.builtin:
            # Named by its title, never by its URL: this print is readable by every channel
            # member, and a built-in's URL belongs to the instance, not to this channel.
            label = (f"built-in: {feed.builtin} (not available on this instance)" if feed.missing
                     else f"{feed.title} (built-in: {feed.builtin})")
            groups.append([("Calendar", label)])
        elif feed.url:
            groups.append([("Calendar", calendarfeed.describe_calendar_url(feed.url))])

        # The timezone also decides when a cron fires and when work hours are, so it
        # is shown for those even when nothing renders a date.
        timezone_matters = trigger == TRIGGER_CRON or (reacts_to_messages and (only_work_days or len(hours) == 2))
        if renders_datetime:
            groups.append([
                ("Date format",        date_format),
                ("Time format",        time_format),
                ("Date/time timezone", datetime_timezone),
                ("Date/time locale",   datetime_locale),
            ])
        elif timezone_matters:
            groups.append([("Date/time timezone", datetime_timezone)])

        key_width = max(len(label) for group in groups for label, _ in group)
        config_block = "\n\n".join(
            "\n".join(f"{label:<{key_width}}  {format_table_value(value, key_width)}" for label, value in group)
            for group in groups
        )
        message_label = 'Reply message' if action == ACTION_REPLY else 'Message'
        reply_line = f"*{message_label}*:\n{reply_message}" if reply_message else f"*{message_label}*: <none>"
        destinations = "\n".join(destination_lines(config, action, trigger))
        if replies_enabled:
            enabled_label = 'enabled'
        elif config.get('disabled_reason') == DISABLED_REASON_REMOVED:
            enabled_label = f'disabled, because {state.bot_name} was removed from this channel'
        else:
            enabled_label = 'disabled'
        trigger_line = f"*Trigger*: `{trigger}`"
        if trigger == TRIGGER_CRON:
            # The expression is part of the trigger, and it fires in the
            # Date/time timezone printed with the settings below.
            trigger_line += f" `{config.get('cron') or '<none>'}`"
        quoted_block = (
            f"> {trigger_line}\n"
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
    # Say that the print is filtered, so a missing row does not read as a lost setting.
    footer = "_Only the settings that apply to each configuration are shown._"
    # Slack splits an oversized message wherever the break lands, cutting the code
    # fence in half, so a channel with several configs is sent as several messages.
    chunks = messaging.pack_message_chunks([message, *config_sections, footer])
    for index, chunk in enumerate(chunks):
        await messaging.send_message(app, channel, user, chunk, thread_ts, footer=index == len(chunks) - 1)
