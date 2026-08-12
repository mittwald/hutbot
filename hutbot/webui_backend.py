"""Web-UI backend: channel membership, payload validation, and config writes.

The aiohttp server itself lives in ``webui.py``; these helpers bridge it to the
live bot state and reuse the same validation as the slash-command setters.
"""

import os
import re
import copy
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from slack_bolt.async_app import AsyncApp

from employee_list import log, log_error

from . import state
from . import slackcache
from . import messaging
from . import templating
from . import datetimefmt
from . import persistence
from .constants import (
    ACTION_DM_USER,
    ACTION_GROUP_DM,
    ACTION_POST_CHANNEL,
    ACTION_REPLY,
    ACTIONS,
    BUTTON_ACTION_CONFIG,
    BUTTON_ACTION_DELAY,
    BUTTON_ACTION_MESSAGE,
    BUTTON_ACTIONS,
    CONDITION_NONE,
    CONDITION_OUTLOOK,
    CONDITIONS,
    CONFIG_NAME_PATTERN,
    DEFAULT_CONFIG,
    DEFAULT_CONFIG_NAME,
    DEFAULT_OPSGENIE_PRIORITY,
    DISABLED_REASON_REMOVED,
    OPSGENIE_PRIORITIES,
    SUPPORTED_TEMPLATE_VARIABLES,
    TEAM_UNKNOWN,
    TRIGGER_MESSAGE,
    TRIGGER_SCHEDULE,
    TRIGGERS,
)
from .models import User

try:
    from croniter import croniter
except ImportError:  # pragma: no cover - dependency optional at runtime
    croniter = None


async def list_user_config_channels(app: AsyncApp, user: User) -> list[dict]:
    """Channels that have a Hutbot config and that `user` belongs to, sorted by name."""
    channels = []
    for channel_id in list(state.channel_config.keys()):
        if await slackcache.is_user_in_channel(app, channel_id, user.id):
            channels.append({'id': channel_id, 'name': await slackcache.get_channel_name(app, channel_id)})
    channels.sort(key=lambda c: c['name'].lower())
    return channels


def _ui_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in ('1', 'true', 'yes', 'on')
    return False


def _ui_team_list(value) -> list[str]:
    if not isinstance(value, list):
        return []
    cleaned = []
    for team in value:
        team = str(team).strip()
        if team and team not in cleaned:
            cleaned.append(team)
    return cleaned


async def validate_config_payload(payload: dict, app: AsyncApp, channel_id: str = "") -> tuple[dict | None, dict]:
    """Validate a config dict from the web UI, mirroring the slash-command setters.

    Returns ``(clean_config, {})`` on success or ``(None, {field: message})`` on failure.
    Values use the persisted shape: ``wait_time`` and ``button_timeout`` are in seconds.
    """
    if not isinstance(payload, dict):
        return None, {'_': "Expected a configuration object."}

    errors: dict[str, str] = {}
    cfg = copy.deepcopy(DEFAULT_CONFIG)

    def get(key):
        return payload.get(key, DEFAULT_CONFIG.get(key))

    for key in ('enabled', 'include_bots', 'only_work_days', 'debug',
                'opsgenie', 'condition_negate', 'pattern_case_sensitive'):
        cfg[key] = _ui_bool(get(key))

    # wait_time (stored as seconds; 1..1440 minutes)
    try:
        wait_time = int(get('wait_time'))
    except (TypeError, ValueError):
        errors['wait_time'] = "Reminder delay must be a number."
    else:
        if wait_time < 60 or wait_time > 86400:
            errors['wait_time'] = "Reminder delay must be between 1 and 1440 minutes."
        else:
            cfg['wait_time'] = wait_time

    # button_timeout (stored as seconds; 0..1440 minutes, 0 = disabled)
    try:
        button_timeout = int(get('button_timeout'))
    except (TypeError, ValueError):
        errors['button_timeout'] = "Button timeout must be a number."
    else:
        if button_timeout < 0 or button_timeout > 86400:
            errors['button_timeout'] = "Button timeout must be between 0 and 1440 minutes."
        else:
            cfg['button_timeout'] = button_timeout

    # reply_message — resolve @mentions and validate template variables
    reply_message = get('reply_message')
    if not isinstance(reply_message, str) or not reply_message.strip():
        errors['reply_message'] = "Reply message can't be empty."
    else:
        ok, mention_error, processed = await messaging.process_mentions(app, reply_message)
        if not ok:
            errors['reply_message'] = f"Unknown user mention: {mention_error}."
        else:
            template_error = templating.validate_template_expressions(processed)
            if template_error:
                errors['reply_message'] = template_error
            else:
                cfg['reply_message'] = processed

    # opsgenie_message — template only (empty = original message)
    opsgenie_message = get('opsgenie_message') or ""
    if not isinstance(opsgenie_message, str):
        errors['opsgenie_message'] = "OpsGenie message must be text."
    else:
        opsgenie_message = opsgenie_message.strip()
        template_error = templating.validate_template_expressions(opsgenie_message) if opsgenie_message else ""
        if template_error:
            errors['opsgenie_message'] = template_error
        else:
            cfg['opsgenie_message'] = opsgenie_message

    cfg['opsgenie_schedule_name'] = str(get('opsgenie_schedule_name') or "").strip()

    priority = str(get('opsgenie_priority') or DEFAULT_OPSGENIE_PRIORITY).strip().upper()
    if priority not in OPSGENIE_PRIORITIES:
        errors['opsgenie_priority'] = "Priority must be one of " + ", ".join(sorted(OPSGENIE_PRIORITIES)) + "."
    else:
        cfg['opsgenie_priority'] = priority

    cfg['date_format'] = str(get('date_format') or "")
    cfg['time_format'] = str(get('time_format') or "")

    tz_name = str(get('datetime_timezone') or "").strip()
    if tz_name:
        try:
            datetimefmt.validate_timezone_name(tz_name)
            cfg['datetime_timezone'] = tz_name
        except ValueError as e:
            errors['datetime_timezone'] = str(e)
    else:
        cfg['datetime_timezone'] = ""

    locale_value = str(get('datetime_locale') or "").strip()
    if locale_value:
        try:
            cfg['datetime_locale'] = datetimefmt.normalize_locale_name(locale_value)
        except ValueError as e:
            errors['datetime_locale'] = str(e)
    else:
        cfg['datetime_locale'] = ""

    cron_expr = str(get('schedule_cron') or "").strip()
    if cron_expr and croniter is not None and not croniter.is_valid(cron_expr):
        errors['schedule_cron'] = "Invalid cron expression. Use 5 fields, e.g. `0 9 * * 1-5`."
    else:
        cfg['schedule_cron'] = cron_expr

    trigger = str(get('trigger') or TRIGGER_MESSAGE).strip().lower()
    trigger = {'msg': TRIGGER_MESSAGE, 'cron': TRIGGER_SCHEDULE, 'scheduled': TRIGGER_SCHEDULE}.get(trigger, trigger)
    if trigger not in TRIGGERS:
        errors['trigger'] = "Trigger must be one of " + ", ".join(sorted(TRIGGERS)) + "."
    else:
        cfg['trigger'] = trigger

    condition = str(get('condition') or CONDITION_NONE).strip().lower()
    condition = {'none': CONDITION_NONE, 'off': CONDITION_NONE, '': CONDITION_NONE,
                 'outlook': CONDITION_OUTLOOK, 'calendar': CONDITION_OUTLOOK,
                 'outlook_calendar': CONDITION_OUTLOOK}.get(condition, condition)
    if condition not in CONDITIONS:
        errors['condition'] = "Condition must be `none` or `outlook`."
    else:
        cfg['condition'] = condition

    for field in ('outlook_subject_pattern', 'outlook_body_pattern'):
        value = str(get(field) or "")
        if value:
            try:
                re.compile(value)
            except re.error as e:
                errors[field] = f"Invalid pattern: {e}"
                continue
        cfg[field] = value

    action = str(get('action') or ACTION_REPLY).strip().lower().replace('-', '_')
    if action not in ACTIONS:
        errors['action'] = "Action must be one of " + ", ".join(sorted(ACTIONS)) + "."
    else:
        cfg['action'] = action

    action_target = str(get('action_target') or "").strip()
    if action in (ACTION_DM_USER, ACTION_GROUP_DM, ACTION_POST_CHANNEL) and not action_target:
        errors['action_target'] = "This action needs a target (a user, user group, or channel)."
    else:
        cfg['action_target'] = action_target

    pattern = get('pattern')
    if pattern in (None, ""):
        cfg['pattern'] = None
    elif not isinstance(pattern, str):
        errors['pattern'] = "Pattern must be text."
    else:
        try:
            re.compile(pattern)
            cfg['pattern'] = pattern
        except re.error as e:
            errors['pattern'] = f"Invalid pattern: {e}"


    await slackcache.update_user_cache(app)
    included = _ui_team_list(get('included_teams'))
    excluded = _ui_team_list(get('excluded_teams'))
    if included and excluded:
        errors['included_teams'] = "Set included teams or excluded teams, not both."
    unknown_included = [team for team in included if team not in state.team_cache]
    unknown_excluded = [team for team in excluded if team not in state.team_cache]
    if unknown_included:
        errors['included_teams'] = "Unknown team(s): " + ", ".join(unknown_included) + "."
    if unknown_excluded:
        errors['excluded_teams'] = "Unknown team(s): " + ", ".join(unknown_excluded) + "."
    if 'included_teams' not in errors:
        cfg['included_teams'] = included
    if 'excluded_teams' not in errors:
        cfg['excluded_teams'] = excluded

    hours_value = get('hours')
    if hours_value in (None, "", []):
        cfg['hours'] = []
    elif isinstance(hours_value, list) and len(hours_value) == 2:
        start_time = datetimefmt.parse_time(str(hours_value[0]))
        end_time = datetimefmt.parse_time(str(hours_value[1]))
        if not start_time or not end_time:
            errors['hours'] = "Use times like `09:00` and `17:00`."
        else:
            normalized = [start_time.strftime("%H:%M"), end_time.strftime("%H:%M")]
            cfg['hours'] = [] if normalized == ["00:00", "00:00"] else normalized
    else:
        errors['hours'] = "Work hours need a start and an end time."

    buttons_value = get('buttons')
    if buttons_value in (None, ""):
        buttons_value = []
    clean_buttons = []
    if not isinstance(buttons_value, list):
        errors['buttons'] = "Buttons must be a list."
    else:
        for i, button in enumerate(buttons_value):
            if not isinstance(button, dict):
                errors[f'buttons.{i}'] = "Each button needs a label and an action."
                continue
            label = str(button.get('label') or "").strip()
            button_action = str(button.get('action') or BUTTON_ACTION_CONFIG).strip().lower()
            value = str(button.get('value') or "").strip()
            if not label:
                errors[f'buttons.{i}'] = "Button label can't be empty."
                continue
            if button_action not in BUTTON_ACTIONS:
                errors[f'buttons.{i}'] = "Button action must be one of " + ", ".join(sorted(BUTTON_ACTIONS)) + "."
                continue
            if button_action in (BUTTON_ACTION_CONFIG, BUTTON_ACTION_MESSAGE) and not value:
                what = "a configuration name" if button_action == BUTTON_ACTION_CONFIG else "a message"
                errors[f'buttons.{i}'] = f"`{button_action}` button needs {what}."
                continue
            if button_action == BUTTON_ACTION_DELAY:
                try:
                    minutes = int(value)
                except ValueError:
                    errors[f'buttons.{i}'] = "Delay button needs a number of minutes."
                    continue
                if minutes <= 0 or minutes > 1440:
                    errors[f'buttons.{i}'] = "Delay minutes must be between 1 and 1440."
                    continue
                value = str(minutes)
            clean_buttons.append({'label': label, 'action': button_action, 'value': value})
    if not any(key == 'buttons' or key.startswith('buttons.') for key in errors):
        cfg['buttons'] = clean_buttons

    cfg['button_timeout_target'] = str(get('button_timeout_target') or "").strip()
    cfg['default_button'] = str(get('default_button') or "").strip()

    if errors:
        return None, errors
    return cfg, {}


async def ui_apply_config(app: AsyncApp, channel_id: str, config_name: str, payload: dict) -> tuple[bool, dict]:
    """Validate and persist a single config (rule). Returns (ok, errors)."""
    config_name = (config_name or "").strip()
    if not CONFIG_NAME_PATTERN.fullmatch(config_name):
        return False, {'name': "Names may use letters, numbers, and - _ . : / only."}
    clean, errors = await validate_config_payload(payload, app, channel_id)
    if errors:
        return False, errors
    async with state._config_write_lock:
        configs = state.channel_config.get(channel_id, {})
        if config_name not in configs:
            return False, {'name': "That rule no longer exists."}
        previous = configs[config_name]
        if (not previous.get('enabled', True)
                and previous.get('disabled_reason') == DISABLED_REASON_REMOVED):
            # A draft loaded before the bot left still says enabled and has no
            # marker. Do not let an unrelated stale edit undo the automatic
            # disable. A draft loaded after removal carries the marker, which
            # distinguishes its explicit enable toggle from that stale save.
            explicit_reenable = (
                clean['enabled']
                and payload.get('disabled_reason') == DISABLED_REASON_REMOVED
            )
            if not explicit_reenable:
                clean['enabled'] = False
                clean['disabled_reason'] = DISABLED_REASON_REMOVED
        configs[config_name] = clean
        await persistence.save_configuration()
    log(f"Config UI: applied rule `{config_name}` in channel {channel_id}.")
    return True, {}


async def ui_create_config(app: AsyncApp, channel_id: str, config_name: str) -> tuple[bool, str]:
    config_name = (config_name or "").strip()
    if not CONFIG_NAME_PATTERN.fullmatch(config_name):
        return False, "Names may use letters, numbers, and - _ . : / only."
    async with state._config_write_lock:
        configs = state.channel_config.setdefault(channel_id, {})
        if config_name in configs:
            return False, f"A rule named `{config_name}` already exists."
        configs[config_name] = copy.deepcopy(DEFAULT_CONFIG)
        await persistence.save_configuration()
    log(f"Config UI: created rule `{config_name}` in channel {channel_id}.")
    return True, ""


async def ui_delete_config(app: AsyncApp, channel_id: str, config_name: str) -> tuple[bool, str]:
    if config_name == DEFAULT_CONFIG_NAME:
        return False, f"The `{DEFAULT_CONFIG_NAME}` rule can't be deleted."
    async with state._config_write_lock:
        configs = state.channel_config.get(channel_id, {})
        if config_name not in configs:
            return False, "That rule no longer exists."
        del configs[config_name]
        await persistence.save_configuration()
    log(f"Config UI: deleted rule `{config_name}` in channel {channel_id}.")
    return True, ""


def ui_snapshot_configs(channel_id: str) -> dict:
    """A deep copy of a channel's configs for read-only display."""
    return copy.deepcopy(state.channel_config.get(channel_id, {}))


def ui_meta() -> dict:
    """Option lists and defaults the editor needs, sourced from the live constants."""
    return {
        'triggers': sorted(TRIGGERS),
        'conditions': sorted(CONDITIONS),
        'actions': sorted(ACTIONS),
        'button_actions': sorted(BUTTON_ACTIONS),
        'opsgenie_priorities': sorted(OPSGENIE_PRIORITIES),
        'teams': sorted((t for t in state.team_cache if t and t != TEAM_UNKNOWN), key=lambda v: v.upper()),
        'template_variables': sorted(SUPPORTED_TEMPLATE_VARIABLES),
        'opsgenie_configured': state.opsgenie_configured,
        'default_config': copy.deepcopy(DEFAULT_CONFIG),
        'default_config_name': DEFAULT_CONFIG_NAME,
        # Lets the UI brand itself per instance (e.g. "Hutbot (DEV)").
        'bot_name': state.bot_name,
        'slash_command': state.slash_command,
    }


async def maybe_start_web_ui(app: AsyncApp):
    """Start the config web UI if HUTBOT_UI_ENABLED is set. Returns the aiohttp runner or None."""
    if os.environ.get('HUTBOT_UI_ENABLED', '').strip().lower() not in ('1', 'true', 'yes', 'on'):
        return None
    try:
        from webui import WebUIContext, start_web_ui
    except Exception as e:
        log_error("Web UI is enabled but the webui module failed to import:", e)
        return None
    host = os.environ.get('HUTBOT_UI_HOST', '0.0.0.0')
    try:
        port = int(os.environ.get('HUTBOT_UI_PORT', '8080'))
    except ValueError:
        port = 8080
    ctx = WebUIContext(
        user_header=os.environ.get('HUTBOT_UI_USER_HEADER', 'X-Forwarded-Email'),
        resolve_user=lambda email: slackcache.get_user_by_email_strict(app, email),
        list_channels=lambda user: list_user_config_channels(app, user),
        is_member=lambda channel_id, user_id: slackcache.is_user_in_channel(app, channel_id, user_id),
        get_configs=ui_snapshot_configs,
        apply_config=lambda channel_id, name, payload: ui_apply_config(app, channel_id, name, payload),
        create_config=lambda channel_id, name: ui_create_config(app, channel_id, name),
        delete_config=lambda channel_id, name: ui_delete_config(app, channel_id, name),
        meta=ui_meta,
        bot_name=state.bot_name,
    )
    return await start_web_ui(ctx, host, port)
