"""Load/save of the configuration and the scheduled-reply / button-state caches.

File paths come from ``constants`` (read qualified so tests can patch them).
"""

import copy
import json

import aiofiles
from slack_bolt.async_app import AsyncApp

from employee_list import log, log_error, log_warning

from . import state
from . import constants
from .buttonutil import normalize_button
from .calendarfeed import describe_calendar_url, normalize_builtin_calendar_name
from .conditionutil import canonical_condition_mode, normalize_condition
from .constants import SUPPORTED_TEMPLATE_VARIABLES


async def migrate_and_apply_defaults(app: AsyncApp, config: dict) -> dict:
    for channel_id, channel_data in config.items():
        # Migration for old format
        # old format: "C1234": { "wait_time": 60, ... }
        # new format: "C1234": { "default": { "wait_time": 60, ... } }
        # A nested configuration may legitimately use a field name as its
        # configuration name (for example, ``trigger`` or ``action``). New
        # fields added to DEFAULT_CONFIG must not make those existing configs
        # look like the legacy flat format. Flat fields hold scalar/list
        # values; nested configuration names hold dictionaries.
        is_flat_config = any(
            key in constants.DEFAULT_CONFIG and not isinstance(value, dict)
            for key, value in channel_data.items()
        )
        if is_flat_config:
            # This looks like an old, flat config. Let's wrap it.
            log(f"Migrating old configuration for channel {channel_id}")
            channel_data = {constants.DEFAULT_CONFIG_NAME: channel_data}
            config[channel_id] = channel_data

        for config_name, single_config in channel_data.items():
            for key, value in constants.DEFAULT_CONFIG.items():
                if key not in single_config:
                    # Deep-copied: a plain assignment would give every config that is
                    # missing a list-valued default (`hours`, `excluded_teams`,
                    # `conditions`, ...) the very same list object, so an in-place
                    # append in one channel would show up in all the others.
                    single_config[key] = copy.deepcopy(value)
            # `forward_channel` was replaced by the `post_channel` action. Drop it
            # instead of silently keeping a field nothing reads any more.
            legacy_forward_channel = single_config.pop('forward_channel', '')
            if legacy_forward_channel:
                log_warning(
                    f"Dropping the forward channel {legacy_forward_channel} of config '{config_name}' in channel {channel_id}. "
                    f"To keep forwarding, add a second config with `set trigger message`, "
                    f"`set action post-channel <#{legacy_forward_channel}>` and a message using {{{{message_link}}}}."
                )
            # Crons now fire in the config's date/time timezone. Carry a separate
            # schedule timezone over so the cron keeps its wall-clock time; if the
            # two disagree, the date/time one wins and the cron shifts.
            legacy_schedule_timezone = single_config.pop('schedule_timezone', '')
            if legacy_schedule_timezone:
                datetime_timezone = single_config.get('datetime_timezone') or ''
                if not datetime_timezone:
                    single_config['datetime_timezone'] = legacy_schedule_timezone
                    log_warning(
                        f"Config '{config_name}' in channel {channel_id}: moved the schedule timezone "
                        f"{legacy_schedule_timezone} to the date/time timezone, which the cron now uses."
                    )
                elif datetime_timezone != legacy_schedule_timezone:
                    log_warning(
                        f"Config '{config_name}' in channel {channel_id}: dropping the schedule timezone "
                        f"{legacy_schedule_timezone}; its cron now fires in {datetime_timezone}."
                    )
            # The pre-release outlook-era condition fields. Nothing reads them any more,
            # so drop them instead of carrying dead keys in bot.json forever.
            for dead_key in ('condition', 'condition_negate', 'outlook_subject_pattern', 'outlook_body_pattern'):
                single_config.pop(dead_key, None)
            # Keep conditions to {variable, operator, value, case_sensitive} and drop
            # anything unusable, so a hand-edited file cannot make a rule un-evaluable.
            conditions = single_config.get('conditions')
            if isinstance(conditions, list):
                normalized_conditions = []
                for condition in conditions:
                    variable, operator, value, case_sensitive, at, offset = normalize_condition(condition)
                    if not variable or not operator:
                        log_warning(f"Dropping an unusable condition of config '{config_name}' in channel {channel_id}.")
                        continue
                    if variable not in SUPPORTED_TEMPLATE_VARIABLES:
                        log_warning(f"Dropping condition on unknown variable '{variable}' of config '{config_name}' in channel {channel_id}.")
                        continue
                    entry = {'variable': variable, 'operator': operator, 'value': value,
                             'case_sensitive': case_sensitive}
                    # Only stored when set, so a config without a calendar selector keeps the
                    # shape it had.
                    if at:
                        entry['at'] = at
                    if offset:
                        entry['offset'] = offset
                    normalized_conditions.append(entry)
                single_config['conditions'] = normalized_conditions
            else:
                single_config['conditions'] = []
            if not canonical_condition_mode(str(single_config.get('conditions_mode') or '')):
                single_config['conditions_mode'] = constants.CONDITION_MODE_ALL
            # Keep buttons to {label, action, value} and drop anything unusable.
            buttons = single_config.get('buttons')
            if isinstance(buttons, list):
                normalized = []
                for button in buttons:
                    if not isinstance(button, dict):
                        continue
                    action, value = normalize_button(button)
                    normalized.append({'label': button.get('label', ''), 'action': action, 'value': value})
                single_config['buttons'] = normalized
            # A hand-edited built-in calendar name may carry capitals; the parsed list is
            # casefolded, so normalize here rather than at every lookup.
            builtin = single_config.get('calendar_builtin')
            if builtin:
                single_config['calendar_builtin'] = normalize_builtin_calendar_name(str(builtin))
            if single_config.get('calendar_builtin') and single_config.get('calendar_url'):
                # Only a hand-edited file reaches this: the setters and the web UI clear one
                # when they set the other. Both values are kept — dropping a URL someone
                # typed because a stray name appeared beside it would be destructive — but
                # the built-in is what actually gets fetched.
                log_warning(f"Config '{config_name}' in channel {channel_id} names both the built-in calendar "
                            f"'{single_config['calendar_builtin']}' and the feed URL "
                            f"{describe_calendar_url(single_config['calendar_url'])}; the built-in wins.")
    return config


async def load_configuration(app: AsyncApp) -> None:
    try:
        async with aiofiles.open(constants.CONFIG_FILE_NAME, 'r') as f:
            content = await f.read()
            loaded_config = json.loads(content)
            state.channel_config = await migrate_and_apply_defaults(app, loaded_config)
            log("Configuration loaded from disk.")
    except FileNotFoundError:
        log_warning("No configuration file found. Using default settings.")
        state.channel_config = {}
    except json.JSONDecodeError as e:
        log_error("Failed to decode JSON configuration:", e)
        state.channel_config = {}


async def save_configuration() -> None:
    try:
        async with aiofiles.open(constants.CONFIG_FILE_NAME, 'w') as f:
            content = json.dumps(state.channel_config, indent=2)
            await f.write(content)
    except Exception as e:
        log_error("Failed to save configuration:", e)


async def load_replies_cache() -> None:
    try:
        async with aiofiles.open(constants.SCHEDULED_REPLIES_CACHE_FILE, 'r') as f:
            content = await f.read()
            entries = json.loads(content)
            state._scheduled_replies_cache.clear()
            state._scheduled_replies_cache.update({
                (e['channel_id'], e['ts'], e['config_name']): e
                for e in entries
            })
            log(f"Loaded {len(state._scheduled_replies_cache)} pending scheduled replies from cache.")
    except FileNotFoundError:
        state._scheduled_replies_cache.clear()
    except Exception as e:
        log_error("Failed to load scheduled replies cache:", e)
        state._scheduled_replies_cache.clear()


async def flush_replies_cache() -> None:
    try:
        async with aiofiles.open(constants.SCHEDULED_REPLIES_CACHE_FILE, 'w') as f:
            await f.write(json.dumps(list(state._scheduled_replies_cache.values()), indent=2))
    except Exception as e:
        log_error("Failed to flush scheduled replies cache:", e)


async def load_button_cache() -> None:
    try:
        async with aiofiles.open(constants.BUTTON_CACHE_FILE, 'r') as f:
            entries = json.loads(await f.read())
            state._button_states_cache.clear()
            state._button_states_cache.update({
                (e['posted_channel_id'], e['message_ts']): e for e in entries
            })
            log(f"Loaded {len(state._button_states_cache)} pending button states from cache.")
    except FileNotFoundError:
        state._button_states_cache.clear()
    except Exception as e:
        log_error("Failed to load button states cache:", e)
        state._button_states_cache.clear()


async def flush_button_cache() -> None:
    try:
        async with aiofiles.open(constants.BUTTON_CACHE_FILE, 'w') as f:
            await f.write(json.dumps(list(state._button_states_cache.values()), indent=2))
    except Exception as e:
        log_error("Failed to flush button states cache:", e)
