"""Load/save of the configuration and the scheduled-reply / button-state caches.

File paths come from ``constants`` (read qualified so tests can patch them).
"""

import json

import aiofiles
from slack_bolt.async_app import AsyncApp

from employee_list import log, log_error, log_warning

from . import state
from . import constants
from .buttonutil import normalize_button


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
                    single_config[key] = value
            # Normalize legacy {label, target} buttons to {label, action, value}.
            buttons = single_config.get('buttons')
            if isinstance(buttons, list):
                normalized = []
                for button in buttons:
                    if not isinstance(button, dict):
                        continue
                    action, value = normalize_button(button)
                    normalized.append({'label': button.get('label', ''), 'action': action, 'value': value})
                single_config['buttons'] = normalized
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
