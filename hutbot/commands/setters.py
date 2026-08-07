"""Slash-command handlers that mutate configuration (and run/test commands)."""

import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from slack_bolt.async_app import AsyncApp
from slack_sdk.errors import SlackApiError

from .. import state
from .. import messaging
from .. import persistence
from .. import templating
from .. import datetimefmt
from .. import slackcache
from .. import actions
from ..buttonutil import _find_button_index
from ..constants import (
    ACTIONS,
    BUTTON_ACTION_CONFIG,
    BUTTON_ACTION_DELAY,
    BUTTON_ACTION_MESSAGE,
    BUTTON_ACTIONS,
    CONDITION_NONE,
    CONDITION_OUTLOOK,
    CONDITIONS,
    DEFAULT_CONFIG,
    DEFAULT_CONFIG_NAME,
    ID_PATTERN,
    OPSGENIE_PRIORITIES,
    SUPPORTED_TEMPLATE_VARIABLES,
    TRIGGER_MESSAGE,
    TRIGGER_SCHEDULE,
    TRIGGERS,
)
from ..textutil import log_debug, parse_quoted_tokens, strip_quotes

try:
    from croniter import croniter
except ImportError:  # pragma: no cover - dependency optional at runtime
    croniter = None


def _ensure_config(channel, config_name: str) -> dict:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    return channel.configs[config_name]


async def set_bots(app: AsyncApp, channel, config_name: str, enabled: bool, user, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    channel.configs[config_name]['include_bots'] = enabled
    await persistence.save_configuration()
    await messaging.send_message(app, channel, user, f"*Bot messages* will {'also be *handled*' if enabled else 'be *ignored*'} in configuration `{config_name}`.", thread_ts)


async def set_only_work_days(app: AsyncApp, channel, config_name: str, enabled: bool, user, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    channel.configs[config_name]['only_work_days'] = enabled
    await persistence.save_configuration()
    await messaging.send_message(app, channel, user, f"Messages will be handled {'*only on work days*' if enabled else '*on all days*'} in configuration `{config_name}`.", thread_ts)


async def set_replies_enabled(app: AsyncApp, channel, config_name: str, enabled: bool, user, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    channel.configs[config_name]['enabled'] = enabled
    await persistence.save_configuration()
    await messaging.send_message(app, channel, user, f"Replies are now *{'enabled' if enabled else 'disabled'}* in configuration `{config_name}`.", thread_ts)


async def set_work_hours(app: AsyncApp, channel, config_name: str, start: str, end: str, user, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    start_time = datetimefmt.parse_time(start)
    end_time = datetimefmt.parse_time(end)
    if not start_time:
        await messaging.send_message(app, channel, user, f"Invalid time format `{start}`.", thread_ts)
        return
    if not end_time:
        await messaging.send_message(app, channel, user, f"Invalid time format `{end}`.", thread_ts)
        return
    hours = [start_time.strftime("%H:%M"), end_time.strftime("%H:%M")]
    if hours[0] == "00:00" and hours[1] == "00:00":
        hours = []
    channel.configs[config_name]['hours'] = hours
    await persistence.save_configuration()
    await messaging.send_message(app, channel, user, f"*Work hours* set to {f'`{hours[0]}` - `{hours[1]}`' if len(hours) == 2 else 'all day'} in configuration `{config_name}`", thread_ts)


async def set_forward_channel(app: AsyncApp, channel, config_name: str, channel_ref: str, user, thread_ts: str = "") -> None:
    channel_id = None
    for match in ID_PATTERN.finditer(channel_ref):
        id = match.group(1)
        if id and id[0] == '#':
            channel_id = id[1:]
            break
    if not channel_id:
        stripped = channel_ref.strip()
        if re.match(r'^C[A-Z0-9]+$', stripped):
            channel_id = stripped

    if not channel_id:
        await messaging.send_message(app, channel, user, f"Invalid channel: `{channel_ref}`. Use a #channel mention.", thread_ts)
        return

    try:
        confirmation = (
            f"Reply messages from #{channel.name} (config `{config_name}`) "
            f"will now be forwarded here by {state.bot_name} :palm_up_hand::tophat:"
        )
        await app.client.chat_postMessage(channel=channel_id, text=confirmation, mrkdwn=True)
    except SlackApiError as e:
        await messaging.send_message(app, channel, user, f"Cannot post to <#{channel_id}>: `{e.response['error']}`.", thread_ts)
        return

    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    channel.configs[config_name]['forward_channel'] = channel_id
    await persistence.save_configuration()
    await messaging.send_message(app, channel, user, f"*Forward channel* set to <#{channel_id}> in configuration `{config_name}`.", thread_ts)


async def clear_forward_channel(app: AsyncApp, channel, config_name: str, user, thread_ts: str = "") -> None:
    if config_name in channel.configs:
        channel.configs[config_name].pop('forward_channel', None)
        await persistence.save_configuration()
    await messaging.send_message(app, channel, user, f"*Forward channel* cleared in configuration `{config_name}`.", thread_ts)


async def set_opsgenie(app: AsyncApp, channel, config_name: str, enabled: bool, user, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    channel.configs[config_name]['opsgenie'] = enabled
    await persistence.save_configuration()
    await messaging.send_message(app, channel, user, f"*OpsGenie integration* {'*enabled*' if enabled else '*disabled*'}{', but not configured' if enabled and not state.opsgenie_configured else ''} in configuration `{config_name}`.", thread_ts)


async def set_opsgenie_schedule_name(app: AsyncApp, channel, config_name: str, schedule_name: str, user, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    if not schedule_name.strip():
        await messaging.send_message(app, channel, user, "Invalid *OpsGenie schedule name*. Must be non-empty.", thread_ts)
        return

    schedule_name = schedule_name.strip()
    channel.configs[config_name]['opsgenie_schedule_name'] = schedule_name
    await persistence.save_configuration()
    await messaging.send_message(app, channel, user, f"*OpsGenie schedule* set to `{schedule_name}` in configuration `{config_name}`.", thread_ts)


async def set_opsgenie_priority(app: AsyncApp, channel, config_name: str, priority: str, user, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()

    priority = priority.strip().upper()
    if priority not in OPSGENIE_PRIORITIES:
        supported = ", ".join(f"`{p}`" for p in sorted(OPSGENIE_PRIORITIES))
        await messaging.send_message(app, channel, user, f"Invalid *OpsGenie priority*. Must be one of {supported}.", thread_ts)
        return

    channel.configs[config_name]['opsgenie_priority'] = priority
    await persistence.save_configuration()
    await messaging.send_message(app, channel, user, f"*OpsGenie priority* set to `{priority}` in configuration `{config_name}`.", thread_ts)


async def set_opsgenie_message(app: AsyncApp, channel, config_name: str, message: str, user, thread_ts: str = "") -> None:
    message = message.strip()
    validation_error = templating.validate_template_expressions(message)
    if validation_error:
        await messaging.send_message(app, channel, user, "Invalid *OpsGenie message*: " + validation_error, thread_ts)
        return
    _ensure_config(channel, config_name)['opsgenie_message'] = message
    await persistence.save_configuration()
    await messaging.send_message(app, channel, user, f"*OpsGenie message* set to: {message} in configuration `{config_name}`.", thread_ts)


async def clear_opsgenie_message(app: AsyncApp, channel, config_name: str, user, thread_ts: str = "") -> None:
    _ensure_config(channel, config_name)['opsgenie_message'] = ''
    await persistence.save_configuration()
    await messaging.send_message(app, channel, user, f"*OpsGenie message* cleared (using the original message) in configuration `{config_name}`.", thread_ts)


async def set_datetime_format(app: AsyncApp, channel, config_name: str, values: str, user, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()

    tokens, error = parse_quoted_tokens(values)
    if error:
        await messaging.send_message(app, channel, user, f"Invalid *date/time format*: {error}.", thread_ts)
        return
    if len(tokens) < 2 or len(tokens) > 4:
        await messaging.send_message(app, channel, user, f"Invalid *date/time format*. Use `{state.slash_command} [config] set datetime-format <date> <time> [<timezone> <locale>]`.", thread_ts)
        return

    date_format = tokens[0]
    time_format = tokens[1]
    if not date_format.strip() or not time_format.strip():
        await messaging.send_message(app, channel, user, "Invalid *date/time format*. Date and time formats must be non-empty.", thread_ts)
        return

    timezone_name = tokens[2] if len(tokens) >= 3 else ""
    locale_name = tokens[3] if len(tokens) >= 4 else ""
    normalized_locale = ""
    if timezone_name:
        try:
            datetimefmt.validate_timezone_name(timezone_name)
        except ValueError as e:
            await messaging.send_message(app, channel, user, f"Invalid *date/time format*: {e}.", thread_ts)
            return
    if locale_name:
        try:
            normalized_locale = datetimefmt.normalize_locale_name(locale_name)
        except ValueError as e:
            await messaging.send_message(app, channel, user, f"Invalid *date/time format*: {e}.", thread_ts)
            return

    config = channel.configs[config_name]
    config["date_format"] = date_format
    config["time_format"] = time_format
    config["datetime_timezone"] = timezone_name
    config["datetime_locale"] = normalized_locale

    await persistence.save_configuration()

    details = f"*Date/time format* set to date `{date_format}` and time `{time_format}`"
    if timezone_name:
        details += f", timezone `{timezone_name}`"
    if locale_name:
        details += f", locale `{normalized_locale}`"
    details += f" in configuration `{config_name}`."
    await messaging.send_message(app, channel, user, details, thread_ts)


async def set_wait_time(app: AsyncApp, channel, config_name: str, wait_time_minutes: int, user, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    # check if number and in range 0-1440
    if not wait_time_minutes or wait_time_minutes < 0 or wait_time_minutes > 1440:
        await messaging.send_message(app, channel, user, "Invalid wait time. Must be a number between 0 and 1440.", thread_ts)
        return

    channel.configs[config_name]['wait_time'] = wait_time_minutes * 60  # Convert to seconds
    log_debug(channel, f"Wait time for #{channel.name} set to {wait_time_minutes} minutes for configuration `{config_name}`")
    await persistence.save_configuration()
    await messaging.send_message(app, channel, user, f"*Wait time* set to `{wait_time_minutes}` minutes in configuration `{config_name}`.", thread_ts)


async def set_reply_message(app: AsyncApp, channel, config_name: str, message: str, user, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    # check message
    if not message or message.strip() == "":
        await messaging.send_message(app, channel, user, "Invalid *reply message*. Must be non-empty.", thread_ts)
        return
    ok, error, message = await messaging.process_mentions(app, message)
    if not ok:
        await messaging.send_message(app, channel, user, "Invalid *reply message*: " + error + ".", thread_ts)
        return

    validation_error = templating.validate_template_expressions(message)
    if validation_error:
        await messaging.send_message(
            app,
            channel,
            user,
            "Invalid *reply message*: " + validation_error,
            thread_ts
        )
        return

    channel.configs[config_name]['reply_message'] = message
    await persistence.save_configuration()
    await messaging.send_message(app, channel, user, f"*Reply message* set to: {message} in configuration `{config_name}`.", thread_ts)


async def test_reply_message(app: AsyncApp, opsgenie_token: str, channel, config_name: str, user, text: str = "", ts: str = "", thread_ts: str = "") -> None:
    config = channel.configs.get(config_name, DEFAULT_CONFIG.copy())
    reply_message_template = config.get('reply_message')
    permalink = await slackcache.get_message_permalink(app, channel, ts) if ts else ""
    template_variables = await templating.build_reply_template_variables(
        app,
        opsgenie_token,
        channel,
        config,
        config_name,
        user,
        text,
        ts,
        permalink,
        include_opsgenie=True,
    )
    reply_message = templating.render_reply_message_template(reply_message_template, template_variables, config)
    variable_lines = [
        f"`{{{{{variable}}}}}`: {template_variables.get(variable, '')}"
        for variable in sorted(SUPPORTED_TEMPLATE_VARIABLES)
    ]
    message = (
        f"*Reply preview for configuration `{config_name}`:*\n"
        f"{reply_message}\n\n"
        "*Template variables:*\n"
        + "\n".join(variable_lines)
    )
    await messaging.send_message(app, channel, user, message, thread_ts)


async def set_pattern(app: AsyncApp, channel, config_name: str, pattern_str: str, case_sensitive_str: str | None, user, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()

    pattern_str = strip_quotes(pattern_str)

    # Validate the regex pattern
    try:
        re.compile(pattern_str)
    except re.error as e:
        await messaging.send_message(app, channel, user, f"Invalid pattern: `{e}`", thread_ts)
        return

    case_sensitive = case_sensitive_str is not None and case_sensitive_str.lower() in ['true', '1']

    channel.configs[config_name]['pattern'] = pattern_str
    channel.configs[config_name]['pattern_case_sensitive'] = case_sensitive
    await persistence.save_configuration()

    message = f"Pattern set to `{pattern_str}` for configuration `{config_name}`."
    if case_sensitive:
        message += " (case-sensitive)"
    else:
        message += " (case-insensitive)"
    await messaging.send_message(app, channel, user, message, thread_ts)


async def delete_config(app: AsyncApp, channel, config_name: str, user, thread_ts: str = "") -> None:
    if config_name == DEFAULT_CONFIG_NAME:
        await messaging.send_message(app, channel, user, f"The `{DEFAULT_CONFIG_NAME}` configuration cannot be deleted.", thread_ts)
        return

    if config_name not in channel.configs:
        await messaging.send_message(app, channel, user, f"Configuration `{config_name}` not found.", thread_ts)
        return

    del channel.configs[config_name]
    await persistence.save_configuration()
    await messaging.send_message(app, channel, user, f"Configuration `{config_name}` has been deleted.", thread_ts)


async def set_trigger(app: AsyncApp, channel, config_name: str, value: str, user, thread_ts: str = "") -> None:
    value = strip_quotes(value).strip().lower()
    value = {'msg': TRIGGER_MESSAGE, 'cron': TRIGGER_SCHEDULE, 'scheduled': TRIGGER_SCHEDULE}.get(value, value)
    if value not in TRIGGERS:
        supported = ", ".join(f"`{t}`" for t in sorted(TRIGGERS))
        await messaging.send_message(app, channel, user, f"Invalid *trigger*. Must be one of {supported}.", thread_ts)
        return
    _ensure_config(channel, config_name)['trigger'] = value
    await persistence.save_configuration()
    await messaging.send_message(app, channel, user, f"*Trigger* set to `{value}` in configuration `{config_name}`.", thread_ts)


async def set_schedule_cron(app: AsyncApp, channel, config_name: str, cron_expr: str, user, thread_ts: str = "") -> None:
    cron_expr = strip_quotes(cron_expr).strip()
    if not cron_expr:
        await messaging.send_message(app, channel, user, "Invalid *cron* expression. Must be non-empty.", thread_ts)
        return
    if croniter is not None and not croniter.is_valid(cron_expr):
        await messaging.send_message(app, channel, user, f"Invalid *cron* expression: `{cron_expr}`. Use 5-field cron, e.g. `0 9 * * 1-5`.", thread_ts)
        return
    _ensure_config(channel, config_name)['schedule_cron'] = cron_expr
    await persistence.save_configuration()
    note = "" if croniter is not None else " (not validated — `croniter` not installed)"
    await messaging.send_message(app, channel, user, f"*Cron schedule* set to `{cron_expr}` in configuration `{config_name}`{note}.", thread_ts)


async def set_schedule_timezone(app: AsyncApp, channel, config_name: str, tz_name: str, user, thread_ts: str = "") -> None:
    tz_name = strip_quotes(tz_name).strip()
    if tz_name:
        try:
            ZoneInfo(tz_name)
        except ZoneInfoNotFoundError:
            await messaging.send_message(app, channel, user, f"Unknown timezone: `{tz_name}`. Use an IANA name, e.g. `Europe/Berlin`.", thread_ts)
            return
    _ensure_config(channel, config_name)['schedule_timezone'] = tz_name
    await persistence.save_configuration()
    await messaging.send_message(app, channel, user, f"*Schedule timezone* set to `{tz_name or '<server local>'}` in configuration `{config_name}`.", thread_ts)


async def set_condition(app: AsyncApp, channel, config_name: str, value: str, user, thread_ts: str = "") -> None:
    value = strip_quotes(value).strip().lower()
    value = {'none': CONDITION_NONE, 'off': CONDITION_NONE, '': CONDITION_NONE,
             'outlook': CONDITION_OUTLOOK, 'calendar': CONDITION_OUTLOOK, 'outlook_calendar': CONDITION_OUTLOOK}.get(value, value)
    if value not in CONDITIONS:
        await messaging.send_message(app, channel, user, "Invalid *condition*. Must be `none` or `outlook`.", thread_ts)
        return
    _ensure_config(channel, config_name)['condition'] = value
    await persistence.save_configuration()
    label = value or 'none'
    await messaging.send_message(app, channel, user, f"*Condition* set to `{label}` in configuration `{config_name}`.", thread_ts)


async def set_outlook_pattern(app: AsyncApp, channel, config_name: str, field: str, pattern_str: str, user, thread_ts: str = "") -> None:
    pattern_str = strip_quotes(pattern_str)
    try:
        re.compile(pattern_str)
    except re.error as e:
        await messaging.send_message(app, channel, user, f"Invalid pattern: `{e}`", thread_ts)
        return
    _ensure_config(channel, config_name)[field] = pattern_str
    await persistence.save_configuration()
    which = "subject" if field == "outlook_subject_pattern" else "body"
    await messaging.send_message(app, channel, user, f"*Outlook {which} pattern* set to `{pattern_str}` in configuration `{config_name}`.", thread_ts)


async def set_condition_negate(app: AsyncApp, channel, config_name: str, enabled: bool, user, thread_ts: str = "") -> None:
    _ensure_config(channel, config_name)['condition_negate'] = enabled
    await persistence.save_configuration()
    await messaging.send_message(app, channel, user, f"*Condition negation* {'*enabled*' if enabled else '*disabled*'} in configuration `{config_name}`.", thread_ts)


async def set_action(app: AsyncApp, channel, config_name: str, value: str, user, thread_ts: str = "") -> None:
    value = strip_quotes(value).strip().lower().replace('-', '_')
    if value not in ACTIONS:
        supported = ", ".join(f"`{a}`" for a in sorted(ACTIONS))
        await messaging.send_message(app, channel, user, f"Invalid *action*. Must be one of {supported}.", thread_ts)
        return
    _ensure_config(channel, config_name)['action'] = value
    await persistence.save_configuration()
    await messaging.send_message(app, channel, user, f"*Action* set to `{value}` in configuration `{config_name}`.", thread_ts)


async def set_action_target(app: AsyncApp, channel, config_name: str, target: str, user, thread_ts: str = "") -> None:
    target = strip_quotes(target).strip()
    if not target:
        await messaging.send_message(app, channel, user, "Invalid *target*. Must be non-empty.", thread_ts)
        return
    _ensure_config(channel, config_name)['action_target'] = target
    await persistence.save_configuration()
    await messaging.send_message(app, channel, user, f"*Action target* set to `{target}` in configuration `{config_name}`.", thread_ts)


async def add_button(app: AsyncApp, channel, config_name: str, label: str, spec: str, user, thread_ts: str = "") -> None:
    label = strip_quotes(label).strip()
    if not label:
        await messaging.send_message(app, channel, user, "Invalid *button label*. Must be non-empty.", thread_ts)
        return

    # spec is either "<action> [arg]" or a bare config name (back-compat).
    spec = spec.strip()
    parts = spec.split(None, 1)
    first = parts[0].lower() if parts else ""
    if first in BUTTON_ACTIONS:
        action = first
        value = strip_quotes(parts[1]).strip() if len(parts) > 1 else ""
    else:
        action = BUTTON_ACTION_CONFIG
        value = strip_quotes(spec).strip()

    if action in (BUTTON_ACTION_CONFIG, BUTTON_ACTION_MESSAGE) and not value:
        what = "a configuration name" if action == BUTTON_ACTION_CONFIG else "a message"
        await messaging.send_message(app, channel, user, f"Invalid *button*. `{action}` needs {what}.", thread_ts)
        return
    if action == BUTTON_ACTION_DELAY:
        try:
            minutes = int(value)
        except ValueError:
            await messaging.send_message(app, channel, user, "Invalid *button*. `delay` needs a number of minutes.", thread_ts)
            return
        if minutes <= 0 or minutes > 1440:
            await messaging.send_message(app, channel, user, "Invalid *button*. `delay` minutes must be between 1 and 1440.", thread_ts)
            return
        value = str(minutes)

    config = _ensure_config(channel, config_name)
    # Copy-on-write so we never mutate a shared default list.
    config['buttons'] = list(config.get('buttons') or []) + [{'label': label, 'action': action, 'value': value}]
    await persistence.save_configuration()

    warning = ""
    if action == BUTTON_ACTION_CONFIG and value not in channel.configs:
        warning = f" :warning: (configuration `{value}` does not exist yet)"
    descriptor = f"`{action}`" + (f" → `{value}`" if value else "")
    await messaging.send_message(app, channel, user, f"Added button `{label}` ({descriptor}) in configuration `{config_name}`{warning}.", thread_ts)


async def clear_buttons(app: AsyncApp, channel, config_name: str, user, thread_ts: str = "") -> None:
    _ensure_config(channel, config_name)['buttons'] = []
    await persistence.save_configuration()
    await messaging.send_message(app, channel, user, f"Cleared *buttons* in configuration `{config_name}`.", thread_ts)


async def set_default_button(app: AsyncApp, channel, config_name: str, label: str, user, thread_ts: str = "") -> None:
    label = strip_quotes(label).strip()
    if not label:
        await messaging.send_message(app, channel, user, "Invalid *default button*. Must reference a button label.", thread_ts)
        return
    config = _ensure_config(channel, config_name)
    config['default_button'] = label
    await persistence.save_configuration()
    warning = "" if _find_button_index(config, label) is not None else f" :warning: (no button labelled `{label}` yet)"
    await messaging.send_message(app, channel, user, f"*Default button* (auto-pressed on timeout) set to `{label}` in configuration `{config_name}`{warning}.", thread_ts)


async def clear_default_button(app: AsyncApp, channel, config_name: str, user, thread_ts: str = "") -> None:
    _ensure_config(channel, config_name)['default_button'] = ''
    await persistence.save_configuration()
    await messaging.send_message(app, channel, user, f"Cleared *default button* in configuration `{config_name}`.", thread_ts)


async def set_button_timeout(app: AsyncApp, channel, config_name: str, minutes_str: str, user, thread_ts: str = "") -> None:
    try:
        minutes = int(strip_quotes(minutes_str).strip())
    except ValueError:
        await messaging.send_message(app, channel, user, "Invalid *button timeout*. Must be a number of minutes between 0 and 1440.", thread_ts)
        return
    if minutes < 0 or minutes > 1440:
        await messaging.send_message(app, channel, user, "Invalid *button timeout*. Must be between 0 and 1440 minutes.", thread_ts)
        return
    _ensure_config(channel, config_name)['button_timeout'] = minutes * 60
    await persistence.save_configuration()
    label = f"`{minutes}` minutes" if minutes else "disabled"
    await messaging.send_message(app, channel, user, f"*Button timeout* set to {label} in configuration `{config_name}`.", thread_ts)


async def set_button_timeout_target(app: AsyncApp, channel, config_name: str, target: str, user, thread_ts: str = "") -> None:
    target = strip_quotes(target).strip()
    if not target:
        await messaging.send_message(app, channel, user, "Invalid *button timeout target*. Must reference a configuration name.", thread_ts)
        return
    _ensure_config(channel, config_name)['button_timeout_target'] = target
    await persistence.save_configuration()
    warning = "" if target in channel.configs else f" :warning: (configuration `{target}` does not exist yet)"
    await messaging.send_message(app, channel, user, f"*Button timeout target* set to `{target}` in configuration `{config_name}`{warning}.", thread_ts)


async def run_config_now(app: AsyncApp, opsgenie_token: str, channel, config_name: str, user, thread_ts: str = "") -> None:
    config = channel.configs.get(config_name)
    if not config:
        await messaging.send_message(app, channel, user, f"Configuration `{config_name}` not found.", thread_ts)
        return
    await messaging.send_message(app, channel, user, f"Running configuration `{config_name}` now…", thread_ts)
    await actions.run_action(app, opsgenie_token, channel, config, config_name, context={'channel_id': channel.id, 'user': user})


async def add_excluded_team(app: AsyncApp, channel, config_name: str, team: str, user, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    config = channel.configs[config_name]
    await slackcache.update_user_cache(app)
    if team not in state.team_cache:
        await messaging.send_message(app, channel, user, f"Unknown team: `{team}`.", thread_ts)
        return
    if team in config['excluded_teams']:
        await messaging.send_message(app, channel, user, f"`{team}` is already excluded in configuration `{config_name}`.", thread_ts)
        return

    if len(config['included_teams']) > 0:
        await messaging.send_message(app, channel, user, f"Either set *included teams* or *excluded teams*, not both, in configuration `{config_name}`.", thread_ts)
        return

    config['excluded_teams'].append(team)
    await persistence.save_configuration()
    await messaging.send_message(app, channel, user, f"Added `{team}` to *excluded teams* in configuration `{config_name}`.", thread_ts)


async def clear_excluded_team(app: AsyncApp, channel, config_name: str, user, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    channel.configs[config_name]['excluded_teams'] = []
    await persistence.save_configuration()
    await messaging.send_message(app, channel, user, f"Cleared *excluded teams* in configuration `{config_name}`.", thread_ts)


async def add_included_team(app: AsyncApp, channel, config_name: str, team: str, user, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    config = channel.configs[config_name]
    await slackcache.update_user_cache(app)
    if team not in state.team_cache:
        await messaging.send_message(app, channel, user, f"Unknown team: `{team}`.", thread_ts)
        return
    if team in config['included_teams']:
        await messaging.send_message(app, channel, user, f"`{team}` is already included in configuration `{config_name}`.", thread_ts)
        return

    if len(config['excluded_teams']) > 0:
        await messaging.send_message(app, channel, user, f"Either set *included teams* or *excluded teams*, not both, in configuration `{config_name}`.", thread_ts)
        return

    config['included_teams'].append(team)
    await persistence.save_configuration()
    await messaging.send_message(app, channel, user, f"Added `{team}` to *included teams* in configuration `{config_name}`.", thread_ts)


async def clear_included_team(app: AsyncApp, channel, config_name: str, user, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    channel.configs[config_name]['included_teams'] = []
    await persistence.save_configuration()
    await messaging.send_message(app, channel, user, f"Cleared *included teams* in configuration `{config_name}`.", thread_ts)
