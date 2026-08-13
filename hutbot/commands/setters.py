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
from .. import targets
from ..buttonutil import _find_button_index
from ..constants import (
    ACTION_POST_CHANNEL,
    ESCALATION_BUTTON,
    ESCALATION_CONFIG,
    ESCALATION_NONE,
    BUTTON_ACTION_ACK,
    ACTION_REPLY,
    ACTION_TARGET_HINTS,
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
    TRIGGER_CRON,
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


def _set_action_hint(config_name: str, config: dict) -> str:
    """The command that gives this config's action a usable target."""
    action = config.get('action', ACTION_REPLY)
    hint = ACTION_TARGET_HINTS.get(action, '<target>')
    return f"`{state.slash_command} {config_name} set action {action.replace('_', '-')} {hint}`"


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
    # An explicit enable/disable supersedes an automatic one (see DISABLED_REASON_REMOVED).
    channel.configs[config_name]['disabled_reason'] = ""
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


async def set_wait_time(app: AsyncApp, channel, config_name: str, wait_time_str: str, user, thread_ts: str = "") -> None:
    # check if number and in range 0-1440
    try:
        wait_time_minutes = int(strip_quotes(wait_time_str or "").strip())
    except (TypeError, ValueError):
        await messaging.send_message(app, channel, user, "Invalid wait time. Must be a number between 0 and 1440.", thread_ts)
        return
    if not wait_time_minutes or wait_time_minutes < 0 or wait_time_minutes > 1440:
        await messaging.send_message(app, channel, user, "Invalid wait time. Must be a number between 0 and 1440.", thread_ts)
        return
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()

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


async def clear_pattern(app: AsyncApp, channel, config_name: str, user, thread_ts: str = "") -> None:
    config = _ensure_config(channel, config_name)
    config['pattern'] = None
    config['pattern_case_sensitive'] = False
    await persistence.save_configuration()
    await messaging.send_message(app, channel, user, f"*Pattern* cleared in configuration `{config_name}`; every message matches now.", thread_ts)


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


async def set_trigger(app: AsyncApp, channel, config_name: str, value: str, expression: str, user, thread_ts: str = "") -> None:
    """`set trigger <trigger> [<expression>]` — the cron trigger carries its cron.

    A cron trigger without an expression never fires and the scheduler skips it
    without a word, so the expression is part of choosing the trigger.
    """
    value = strip_quotes(value).strip().lower()
    value = {'msg': TRIGGER_MESSAGE, 'schedule': TRIGGER_CRON, 'scheduled': TRIGGER_CRON}.get(value, value)
    if value not in TRIGGERS:
        supported = ", ".join(f"`{t}`" for t in sorted(TRIGGERS))
        await messaging.send_message(app, channel, user, f"Invalid *trigger*. Must be one of {supported}.", thread_ts)
        return
    expression = strip_quotes(expression or "").strip()

    if value == TRIGGER_CRON:
        if not expression:
            await messaging.send_message(app, channel, user, f"Trigger `{TRIGGER_CRON}` needs an expression: `{state.slash_command} {config_name} set trigger cron \"0 9 * * 1-5\"`.", thread_ts)
            return
        if croniter is not None and not croniter.is_valid(expression):
            await messaging.send_message(app, channel, user, f"Invalid *cron* expression: `{expression}`. Use 5-field cron, e.g. `0 9 * * 1-5`.", thread_ts)
            return
    elif expression:
        await messaging.send_message(app, channel, user, f"Trigger `{value}` takes no expression; only `{TRIGGER_CRON}` does.", thread_ts)
        return

    config = _ensure_config(channel, config_name)
    config['trigger'] = value
    config['cron'] = expression
    await persistence.save_configuration()
    if value == TRIGGER_CRON:
        note = "" if croniter is not None else " (not validated — `croniter` not installed)"
        await messaging.send_message(app, channel, user, f"*Trigger* set to `{value}` running `{expression}` in configuration `{config_name}`{note}.", thread_ts)
    else:
        await messaging.send_message(app, channel, user, f"*Trigger* set to `{value}` in configuration `{config_name}`.", thread_ts)


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


async def set_action(app: AsyncApp, channel, config_name: str, value: str, target: str, user, thread_ts: str = "") -> None:
    """`set action <action> [<target>]` — the target is part of choosing the action.

    Every action except `reply` sends somewhere else, so it is only a complete
    instruction together with its recipient. Requiring both in one command means a
    config can never be left in a state that fails when the rule fires.
    """
    value = strip_quotes(value).strip().lower().replace('-', '_')
    if value not in ACTIONS:
        supported = ", ".join(f"`{a}`" for a in sorted(ACTIONS))
        await messaging.send_message(app, channel, user, f"Invalid *action*. Must be one of {supported}.", thread_ts)
        return
    target = strip_quotes(target or "").strip()

    if value == ACTION_REPLY:
        if target:
            await messaging.send_message(app, channel, user, f"Action `{ACTION_REPLY}` posts in this channel and takes no target.", thread_ts)
            return
    elif not target:
        await messaging.send_message(app, channel, user, f"Action `{value}` needs a target: `{state.slash_command} {config_name} set action {value.replace('_', '-')} {ACTION_TARGET_HINTS[value]}`.", thread_ts)
        return
    elif value == ACTION_POST_CHANNEL and not targets.parse_channel_ref(target):
        await messaging.send_message(app, channel, user, f"Invalid *target* `{target}` for action `{value}`. Pick the channel from Slack's autocomplete so it becomes a link, or pass its `C…` id.", thread_ts)
        return

    config = _ensure_config(channel, config_name)
    config['action'] = value
    config['action_target'] = target
    await persistence.save_configuration()
    if target:
        await messaging.send_message(app, channel, user, f"*Action* set to `{value}` sending to `{target}` in configuration `{config_name}`.", thread_ts)
    else:
        await messaging.send_message(app, channel, user, f"*Action* set to `{value}` in configuration `{config_name}`.", thread_ts)


async def add_button(app: AsyncApp, channel, config_name: str, label: str, spec: str, user, thread_ts: str = "") -> None:
    label = strip_quotes(label).strip()
    if not label:
        await messaging.send_message(app, channel, user, "Invalid *button label*. Must be non-empty.", thread_ts)
        return

    # spec is "<action> [arg]". The action keyword is required: without it a config
    # named after one (`ack`, `message`, `delay`) could never be attached.
    parts = spec.strip().split(None, 1)
    action = parts[0].lower() if parts else ""
    if action not in BUTTON_ACTIONS:
        supported = ", ".join(f"`{a}`" for a in sorted(BUTTON_ACTIONS))
        await messaging.send_message(app, channel, user, f"Invalid *button action* `{parts[0] if parts else ''}`. Must be one of {supported}.", thread_ts)
        return
    value = strip_quotes(parts[1]).strip() if len(parts) > 1 else ""

    if action in (BUTTON_ACTION_CONFIG, BUTTON_ACTION_MESSAGE) and not value:
        what = "a configuration name" if action == BUTTON_ACTION_CONFIG else "a message"
        await messaging.send_message(app, channel, user, f"Invalid *button*. `{action}` needs {what}.", thread_ts)
        return
    if action in (BUTTON_ACTION_MESSAGE, BUTTON_ACTION_ACK) and value:
        # A button's text is a template too, so it gets the same treatment as
        # `set message`: @mentions resolved to ids, variables checked.
        ok, mention_error, value = await messaging.process_mentions(app, value)
        if not ok:
            await messaging.send_message(app, channel, user, f"Invalid *button* message: {mention_error}.", thread_ts)
            return
        template_error = templating.validate_template_expressions(value)
        if template_error:
            await messaging.send_message(app, channel, user, f"Invalid *button* message: {template_error}", thread_ts)
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


async def set_escalation(app: AsyncApp, channel, config_name: str, minutes_str: str, kind: str | None, target: str | None, user, thread_ts: str = "") -> None:
    """`set escalation <minutes> <button|config> <target>` — one setting, not three.

    A timeout with nothing to escalate to silently does nothing, and a target with
    no timeout never fires, so both halves are set together or not at all.
    """
    minutes_str = strip_quotes(minutes_str or "").strip().lower()
    kind = strip_quotes(kind or "").strip().lower()
    target = strip_quotes(target or "").strip()
    usage = f'`{state.slash_command} {config_name} set escalation <minutes> <button "<label>"|config <name>>`, or `set escalation none`'

    if minutes_str in ("none", "off", "no", "0"):
        if kind or target:
            await messaging.send_message(app, channel, user, f"`set escalation {minutes_str}` takes nothing else.", thread_ts)
            return
        config = _ensure_config(channel, config_name)
        config['escalation_timeout'] = 0
        config['escalation_kind'] = ESCALATION_NONE
        config['escalation_target'] = ''
        await persistence.save_configuration()
        await messaging.send_message(app, channel, user, f"*Escalation* disabled in configuration `{config_name}`; buttons stay open until pressed.", thread_ts)
        return

    try:
        minutes = int(minutes_str)
    except ValueError:
        await messaging.send_message(app, channel, user, f"Invalid *escalation*. Use {usage}.", thread_ts)
        return
    if minutes < 1 or minutes > 1440:
        await messaging.send_message(app, channel, user, "Invalid *escalation*. Minutes must be between 1 and 1440, or `none`.", thread_ts)
        return

    if kind not in (ESCALATION_BUTTON, ESCALATION_CONFIG):
        await messaging.send_message(app, channel, user, f"*Escalation* needs what to escalate to: {usage}.", thread_ts)
        return
    if not target:
        what = "a button label" if kind == ESCALATION_BUTTON else "a configuration name"
        await messaging.send_message(app, channel, user, f"*Escalation* `{kind}` needs {what}: {usage}.", thread_ts)
        return

    config = _ensure_config(channel, config_name)
    warning = ""
    if kind == ESCALATION_BUTTON:
        # An unknown label would otherwise only surface as a warning at escalation time.
        if _find_button_index(config, target) is None:
            labels = ", ".join(f"`{b.get('label')}`" for b in (config.get('buttons') or [])) or "none yet"
            await messaging.send_message(app, channel, user, f"No button labelled `{target}` in configuration `{config_name}` (buttons: {labels}).", thread_ts)
            return
    elif target not in channel.configs:
        # A target config is often created afterwards, so this is only a warning.
        warning = f" :warning: (configuration `{target}` does not exist yet)"

    config['escalation_timeout'] = minutes * 60
    config['escalation_kind'] = kind
    config['escalation_target'] = target
    await persistence.save_configuration()
    does = f"auto-press `{target}`" if kind == ESCALATION_BUTTON else f"run `{target}`"
    await messaging.send_message(app, channel, user, f"*Escalation* set: after `{minutes}` minutes without a press, {does} in configuration `{config_name}`{warning}.", thread_ts)


async def run_config_now(app: AsyncApp, opsgenie_token: str, channel, config_name: str, user, thread_ts: str = "") -> None:
    config = channel.configs.get(config_name)
    if not config:
        await messaging.send_message(app, channel, user, f"Configuration `{config_name}` not found.", thread_ts)
        return
    reason = actions.missing_target_reason(config)
    if reason:
        await messaging.send_message(app, channel, user, f"Cannot run configuration `{config_name}`: {reason}. Set one with {_set_action_hint(config_name, config)}.", thread_ts)
        return
    await messaging.send_message(app, channel, user, f"Running configuration `{config_name}` now…", thread_ts)
    posted = await actions.run_action(app, opsgenie_token, channel, config, config_name, context={'channel_id': channel.id, 'user': user})
    if not posted:
        await messaging.send_message(app, channel, user, f"Configuration `{config_name}` did not send anything. Check its action and target with `{state.slash_command} show config`.", thread_ts)


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
