"""Web-UI backend: channel membership, payload validation, and config writes.

The aiohttp server itself lives in ``webui.py``; these helpers bridge it to the
live bot state and reuse the same validation as the slash-command setters.
"""

import os
import re
import copy
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from slack_bolt.async_app import AsyncApp

from logutil import log, log_error

from . import state
from . import slackcache
from . import messaging
from . import templating
from . import calendarfeed
from . import conditionutil
from . import datetimefmt
from . import persistence
from . import renaming
from .buttonutil import format_config_list, parse_config_list
from .constants import (
    ACTION_DM_USER,
    ACTION_GROUP_DM,
    ACTION_POST_CHANNEL,
    ACTION_REPLY,
    ACTIONS,
    BUTTON_ACTION_CONFIG,
    BUTTON_ACTION_ACK,
    ESCALATION_BUTTON,
    ESCALATION_CONFIG,
    ESCALATION_NONE,
    BUTTON_ACTION_DELAY,
    BUTTON_ACTIONS,
    CONDITION_MODE_ALL,
    CONDITION_MODES,
    CONDITION_OPERATORS_ORDERED,
    CONDITION_OPERATORS_REQUIRING_NONEMPTY_VALUE,
    CONDITION_OPERATORS_WITHOUT_VALUE,
    CONFIG_NAME_PATTERN,
    DEFAULT_CONFIG,
    DEFAULT_CONFIG_NAME,
    RESERVED_CONFIG_NAMES,
    DEFAULT_OPSGENIE_PRIORITY,
    DISABLED_REASON_REMOVED,
    OPSGENIE_PRIORITIES,
    SUPPORTED_TEMPLATE_VARIABLES,
    TEAM_UNKNOWN,
    TRIGGER_MESSAGE,
    TRIGGER_CRON,
    TRIGGERS,
    CALENDAR_EVENT_TEMPLATE_VARIABLES,
    DATETIME_TEMPLATE_VARIABLES,
    parse_event_offset,
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


async def validate_config_payload(payload: dict, app: AsyncApp, channel_id: str = "", existing: dict | None = None) -> tuple[dict | None, dict]:
    """Validate a config dict from the web UI, mirroring the slash-command setters.

    Returns ``(clean_config, {})`` on success or ``(None, {field: message})`` on failure.
    Values use the persisted shape: ``wait_time`` and ``escalation_timeout`` are in seconds.
    """
    if not isinstance(payload, dict):
        return None, {'_': "Expected a configuration object."}

    errors: dict[str, str] = {}
    cfg = copy.deepcopy(DEFAULT_CONFIG)

    def get(key):
        return payload.get(key, DEFAULT_CONFIG.get(key))

    for key in ('enabled', 'include_bots', 'only_work_days', 'debug',
                'opsgenie', 'pattern_case_sensitive'):
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

    # escalation_timeout (stored as seconds; 1..1440 minutes, 0 = never escalate) and
    # what it escalates to. Both halves are validated together.
    try:
        escalation_timeout = int(get('escalation_timeout'))
    except (TypeError, ValueError):
        errors['escalation_timeout'] = "Escalation timeout must be a number."
    else:
        escalation_kind = str(get('escalation_kind') or ESCALATION_NONE).strip().lower() or ESCALATION_NONE
        escalation_target = str(get('escalation_target') or "").strip()
        if escalation_timeout < 0 or escalation_timeout > 86400:
            errors['escalation_timeout'] = "Escalation timeout must be between 0 and 1440 minutes."
        elif escalation_kind not in (ESCALATION_NONE, ESCALATION_BUTTON, ESCALATION_CONFIG):
            errors['escalation_kind'] = "Escalation must be none, button or config."
        elif escalation_kind == ESCALATION_NONE or not escalation_timeout:
            # Half a setting escalates nothing, so store it as switched off.
            cfg['escalation_timeout'] = 0
            cfg['escalation_kind'] = ESCALATION_NONE
            cfg['escalation_target'] = ""
        elif not escalation_target:
            errors['escalation_target'] = "Pick a button label or a rule to escalate to."
        else:
            if escalation_kind == ESCALATION_CONFIG:
                # Several rules, comma-separated, run one after the other when the timeout
                # comes; normalized to the one spelling the setters write.
                names = parse_config_list(escalation_target)
                if not names:
                    errors['escalation_target'] = "Name a rule to run, or several separated by commas."
                escalation_target = format_config_list(names)
            cfg['escalation_timeout'] = escalation_timeout
            cfg['escalation_kind'] = escalation_kind
            cfg['escalation_target'] = escalation_target

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

    cron_expr = str(get('cron') or "").strip()
    if cron_expr and croniter is not None and not croniter.is_valid(cron_expr):
        errors['cron'] = "Invalid cron expression. Use 5 fields, e.g. `0 9 * * 1-5`."
    else:
        cfg['cron'] = cron_expr

    trigger = str(get('trigger') or TRIGGER_MESSAGE).strip().lower()
    trigger = {'msg': TRIGGER_MESSAGE, 'schedule': TRIGGER_CRON, 'scheduled': TRIGGER_CRON}.get(trigger, trigger)
    if trigger not in TRIGGERS:
        errors['trigger'] = "Trigger must be one of " + ", ".join(sorted(TRIGGERS)) + "."
    else:
        cfg['trigger'] = trigger
        # The expression is part of choosing the cron trigger, exactly as `set trigger`
        # requires: without it the scheduler skips the rule and it looks active but can
        # never fire.
        if trigger == TRIGGER_CRON and not cron_expr and 'cron' not in errors:
            errors['cron'] = "A schedule trigger needs a cron expression, e.g. `0 9 * * 1-5`."

    # Conditions: a list of {variable, operator, value, case_sensitive}, validated
    # per-row like buttons so the editor can mark the offending row.
    conditions_value = get('conditions')
    if conditions_value is None:
        conditions_value = []
    clean_conditions = []
    if not isinstance(conditions_value, list):
        errors['conditions'] = "Conditions must be a list."
    else:
        for i, condition in enumerate(conditions_value):
            if not isinstance(condition, dict):
                errors[f'conditions.{i}'] = "Each condition needs a variable and an operator."
                continue
            variable = conditionutil.normalize_variable(str(condition.get('variable') or ""))
            operator = conditionutil.canonical_operator(str(condition.get('operator') or ""))
            value = condition.get('value')
            value = "" if value is None else str(value)
            case_sensitive = _ui_bool(condition.get('case_sensitive'))
            at = str(condition.get('at') or "").strip()
            offset = str(condition.get('offset') or "").strip()
            if variable not in SUPPORTED_TEMPLATE_VARIABLES:
                errors[f'conditions.{i}'] = "Pick a supported template variable."
                continue
            reads_a_clock = variable in DATETIME_TEMPLATE_VARIABLES
            if (at or offset) and variable not in CALENDAR_EVENT_TEMPLATE_VARIABLES and not reads_a_clock:
                errors[f'conditions.{i}'] = "Only a calendar event or a date/time variable takes a moment, and only a calendar event an offset."
                continue
            if offset and reads_a_clock:
                errors[f'conditions.{i}'] = "A date/time variable has no events to count, so it takes a moment but no offset."
                continue
            if at:
                try:
                    datetimefmt.validate_at_time(at)
                except ValueError as e:
                    errors[f'conditions.{i}'] = str(e)
                    continue
            if offset:
                try:
                    parse_event_offset(offset)
                except ValueError as e:
                    errors[f'conditions.{i}'] = str(e)
                    continue
            if not operator:
                errors[f'conditions.{i}'] = "Operator must be one of " + ", ".join(CONDITION_OPERATORS_ORDERED) + "."
                continue
            if operator in CONDITION_OPERATORS_WITHOUT_VALUE:
                # Nothing to compare, so a value and a case flag would both be dead weight.
                value, case_sensitive = "", False
            elif operator in CONDITION_OPERATORS_REQUIRING_NONEMPTY_VALUE and not value:
                errors[f'conditions.{i}'] = f"`{operator}` needs a value."
                continue
            if operator in ('regex', 'not_regex'):
                try:
                    re.compile(value)
                except re.error as e:
                    errors[f'conditions.{i}'] = f"Invalid pattern: {e}"
                    continue
            clean = {'variable': variable, 'operator': operator, 'value': value, 'case_sensitive': case_sensitive}
            if at:
                clean['at'] = at
            if offset:
                clean['offset'] = offset
            clean_conditions.append(clean)
    if not any(key == 'conditions' or key.startswith('conditions.') for key in errors):
        cfg['conditions'] = clean_conditions

    conditions_mode = conditionutil.canonical_condition_mode(str(get('conditions_mode') or CONDITION_MODE_ALL))
    if not conditions_mode:
        errors['conditions_mode'] = "Condition mode must be " + " or ".join(sorted(CONDITION_MODES)) + "."
    else:
        cfg['conditions_mode'] = conditions_mode

    # Calendar: a built-in calendar's name or a feed URL, never both. Rejecting the
    # combination rather than quietly preferring one means a save can never ignore what the
    # editor showed; `resolve_calendar_feed` still has to tie-break for a hand-edited file.
    raw_calendar_builtin = str(get('calendar_builtin') or "").strip()
    calendar_builtin = calendarfeed.normalize_builtin_calendar_name(raw_calendar_builtin)
    calendar_url = str(get('calendar_url') or "").strip()
    stored_calendar_url = str((existing or {}).get('calendar_url') or "").strip()
    if raw_calendar_builtin and calendar_url:
        errors['calendar_builtin'] = "Pick a built-in calendar or enter a URL, not both."
    elif raw_calendar_builtin and not calendar_builtin:
        errors['calendar_builtin'] = "Pick one of the built-in calendars."
    elif calendar_builtin and calendarfeed.lookup_builtin_calendar(calendar_builtin) is None:
        errors['calendar_builtin'] = f"`{raw_calendar_builtin}` is not a built-in calendar on this instance."
    elif calendar_builtin:
        cfg['calendar_builtin'] = calendar_builtin
        cfg['calendar_url'] = ""
    elif calendar_url and stored_calendar_url and calendar_url == calendarfeed.describe_calendar_url(stored_calendar_url):
        # The editor only ever saw the redacted form, so getting it back means "unchanged".
        # Clearing the field still clears the URL, and a real one still replaces it.
        cfg['calendar_url'] = stored_calendar_url
    elif calendar_url:
        try:
            cfg['calendar_url'] = calendarfeed.validate_calendar_url(calendar_url)
        except ValueError as e:
            errors['calendar_url'] = str(e)
    else:
        cfg['calendar_url'] = ""

    action = str(get('action') or ACTION_REPLY).strip().lower().replace('-', '_')
    if action not in ACTIONS:
        errors['action'] = "Action must be one of " + ", ".join(sorted(ACTIONS)) + "."
    else:
        cfg['action'] = action

    action_target = str(get('action_target') or "").strip()
    target_template_error = templating.validate_template_expressions(action_target) if "{{" in action_target else ""
    if action in (ACTION_DM_USER, ACTION_GROUP_DM, ACTION_POST_CHANNEL) and not action_target:
        errors['action_target'] = "This action needs a target (a user, user group, or channel)."
    elif target_template_error:
        errors['action_target'] = target_template_error
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
            if button_action == BUTTON_ACTION_CONFIG:
                # As for the escalation above: a comma-separated list runs each rule in turn.
                names = parse_config_list(value)
                if not names:
                    errors[f'buttons.{i}'] = "`config` button needs a rule name, or several separated by commas."
                    continue
                value = format_config_list(names)
            if button_action == BUTTON_ACTION_ACK and value:
                # Same treatment as reply_message: mentions resolved, variables checked.
                ok, mention_error, value = await messaging.process_mentions(app, value)
                if not ok:
                    errors[f'buttons.{i}'] = f"Unknown user mention: {mention_error}."
                    continue
                template_error = templating.validate_template_expressions(value)
                if template_error:
                    errors[f'buttons.{i}'] = template_error
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
        # Cross-checks the setters make, which no single field can: a `delay` button needs
        # an escalation to postpone, and an escalation that auto-presses needs that button
        # to exist. Either half alone leaves a press or a timeout doing nothing at all.
        escalates = cfg.get('escalation_timeout') and cfg.get('escalation_kind') != ESCALATION_NONE
        for i, button in enumerate(clean_buttons):
            if button['action'] == BUTTON_ACTION_DELAY and not escalates:
                errors[f'buttons.{i}'] = "A delay button needs an escalation to postpone."
        if cfg.get('escalation_kind') == ESCALATION_BUTTON and escalates:
            labels = {button['label'] for button in clean_buttons}
            if cfg.get('escalation_target') not in labels:
                errors['escalation_target'] = "Pick one of this rule's button labels."

    if errors:
        return None, errors
    return cfg, {}


async def ui_apply_config(app: AsyncApp, channel_id: str, config_name: str, payload: dict) -> tuple[bool, dict]:
    """Validate and persist a single config (rule). Returns (ok, errors)."""
    config_name = (config_name or "").strip()
    if not CONFIG_NAME_PATTERN.fullmatch(config_name):
        return False, {'name': "Names may use letters, numbers, and - _ . : / only."}
    existing = state.channel_config.get(channel_id, {}).get(config_name)
    clean, errors = await validate_config_payload(payload, app, channel_id, existing)
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
        # Mutated in place rather than replaced: a queued reminder and a pending buttoned
        # message hold this dict object, which is how an edit reaches work already in flight
        # (see `scheduling.schedule_reply`) and how a rename can still find it by identity.
        # `clean` starts from a full `DEFAULT_CONFIG`, so this drops nothing.
        previous.clear()
        previous.update(clean)
        await persistence.save_configuration()
    log(f"Config UI: applied rule `{config_name}` in channel {channel_id}.")
    return True, {}


async def ui_create_config(app: AsyncApp, channel_id: str, config_name: str) -> tuple[bool, str]:
    config_name = (config_name or "").strip()
    if not CONFIG_NAME_PATTERN.fullmatch(config_name):
        return False, "Names may use letters, numbers, and - _ . : / only."
    if config_name.lower() in RESERVED_CONFIG_NAMES:
        # A rule named after a command word would swallow that command: with a rule called
        # `set`, `/hutbot set message …` addresses the rule instead of the default one.
        return False, f"`{config_name}` cannot be a rule name; it starts a command."
    async with state._config_write_lock:
        configs = state.channel_config.setdefault(channel_id, {})
        if config_name in configs:
            return False, f"A rule named `{config_name}` already exists."
        configs[config_name] = copy.deepcopy(DEFAULT_CONFIG)
        await persistence.save_configuration()
    log(f"Config UI: created rule `{config_name}` in channel {channel_id}.")
    return True, ""


async def ui_rename_config(app: AsyncApp, channel_id: str, config_name: str, new_name: str) -> tuple[bool, str]:
    """Rename a rule and every reference to it. The rules live in `renaming.rename_error`, so
    the UI and the slash command cannot disagree about what may be renamed."""
    ok, error, _ = await renaming.rename_config(channel_id, config_name, (new_name or "").strip())
    if not ok:
        return False, error
    log(f"Config UI: renamed rule `{config_name}` to `{new_name}` in channel {channel_id}.")
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
    """A deep copy of a channel's configs for read-only display.

    The calendar URL is redacted, the same way `show config` redacts it: a published-calendar
    link needs no login, so handing the full one to every channel member through the API
    would give away read access to that calendar. Saving the redacted value back keeps the
    stored URL (see `validate_config_payload`).
    """
    snapshot = copy.deepcopy(state.channel_config.get(channel_id, {}))
    for config in snapshot.values():
        if isinstance(config, dict) and config.get('calendar_url'):
            config['calendar_url'] = calendarfeed.describe_calendar_url(config['calendar_url'])
    return snapshot


def ui_meta() -> dict:
    """Option lists and defaults the editor needs, sourced from the live constants."""
    return {
        'triggers': sorted(TRIGGERS),
        # Deliberately unsorted: each operator sits next to its negation.
        'condition_operators': list(CONDITION_OPERATORS_ORDERED),
        'condition_operators_without_value': sorted(CONDITION_OPERATORS_WITHOUT_VALUE),
        'condition_modes': sorted(CONDITION_MODES),
        'actions': sorted(ACTIONS),
        'button_actions': sorted(BUTTON_ACTIONS),
        'opsgenie_priorities': sorted(OPSGENIE_PRIORITIES),
        'teams': sorted((t for t in state.team_cache if t and t != TEAM_UNKNOWN), key=lambda v: v.upper()),
        # Name and title only, spelled out rather than handed over as the namedtuple: this
        # dict is JSON-dumped verbatim, and a BuiltinCalendar would serialize as a
        # three-element array *including the URL* — every feed token, to every viewer.
        'calendars': [{'name': calendar.name, 'title': calendar.display_title}
                      for calendar in sorted(state.builtin_calendars, key=lambda c: c.name)],
        'template_variables': sorted(SUPPORTED_TEMPLATE_VARIABLES),
        # Which variables the editor may offer a moment and an offset for.
        'template_variables_with_selector': sorted(CALENDAR_EVENT_TEMPLATE_VARIABLES),
        # Which variables take a moment: the calendar events, plus the clock family, whose
        # `at` moves the instant it reports rather than picking an event.
        'template_variables_with_moment': sorted(CALENDAR_EVENT_TEMPLATE_VARIABLES | DATETIME_TEMPLATE_VARIABLES),
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
        rename_config=lambda channel_id, name, new_name: ui_rename_config(app, channel_id, name, new_name),
        meta=ui_meta,
        bot_name=state.bot_name,
    )
    return await start_web_ui(ctx, host, port)
