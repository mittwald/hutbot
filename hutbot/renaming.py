"""Renaming a config: every place its name is written down, moved in one step.

A config has no `name` field — the name *is* the key it is filed under, in
``state.channel_config[channel_id]``. That makes a rename a rewrite rather than an edit, and
the name is written down in five places:

* the key in the channel's config dict;
* the `buttons` targets and `escalation_target` of every config in the channel (including the
  renamed one, which may escalate to itself);
* the records of buttoned messages already posted and still waiting for a press;
* the keys of pending scheduled reminders, live and persisted;
* nothing else — `{{parent_*}}` reads the name back out of the button record, and the
  scheduled-reply tasks hold the config object rather than its name.

Both entry points (the slash command and the web UI) go through :func:`rename_config`, so the
rules about what may be renamed cannot drift between them.
"""

from logutil import log

from . import buttons
from . import persistence
from . import scheduling
from . import state
from .constants import CONFIG_NAME_PATTERN, DEFAULT_CONFIG_NAME, RESERVED_CONFIG_NAMES


def rename_error(configs: dict, old_name: str, new_name: str) -> str:
    """Why this rename cannot happen, or "" when it can.

    Shared by both entry points so they cannot disagree; the wording is user-facing.
    """
    if old_name == DEFAULT_CONFIG_NAME:
        return f"The `{DEFAULT_CONFIG_NAME}` configuration cannot be renamed."
    if old_name not in configs:
        return f"Configuration `{old_name}` not found."
    if not new_name:
        return f"Give the new name, e.g. `{state.slash_command} rename config old new`."
    if new_name == old_name:
        return f"Configuration `{old_name}` is already called that."
    if not CONFIG_NAME_PATTERN.fullmatch(new_name):
        return f"Invalid config name: `{new_name}`. Only characters `A-Z`, `a-z`, `0-9`, `.`, `:`, `/`, `-`, `_` are allowed."
    if new_name.lower() in RESERVED_CONFIG_NAMES:
        # A config named after a command word would swallow that command: with one called
        # `set`, `/hutbot set message …` addresses that config instead of the default one.
        return f"`{new_name}` cannot be a configuration name; it starts a command."
    if new_name in configs:
        return f"A configuration named `{new_name}` already exists."
    return ""


async def rename_config(channel_id: str, old_name: str, new_name: str) -> tuple[bool, str, dict]:
    """Rename a config and move every reference to it. `(ok, error, what_changed)`.

    `what_changed` counts the *other* things that moved with it — referring configs, posted
    buttoned messages, queued reminders — so a caller can say what a rename touched beyond the
    config itself.
    """
    async with state._config_write_lock:
        configs = state.channel_config.get(channel_id) or {}
        error = rename_error(configs, old_name, new_name)
        if error:
            return False, error, {}

        # Every reference moves before this coroutine yields, and only then are the three
        # persisted mirrors written. Yielding half-way would leave the live config without
        # `old_name` while a posted message still pointed at it — and a press landing in that
        # window claims the record, finds no such target, and consumes the message for nothing.
        #
        # Rebuilt in place rather than popped and re-added: `channel.configs` is this same dict
        # object, and keeping the original position keeps `show config`, the UI list and the
        # saved file in the order the channel already knows.
        renamed = {(new_name if name == old_name else name): config for name, config in configs.items()}
        configs.clear()
        configs.update(renamed)

        # The renamed config is in here too, so a config that escalates to itself follows.
        referring = sum(buttons.rename_config_references(config, old_name, new_name)
                        for config in configs.values() if isinstance(config, dict))
        messages = buttons.rename_pending_buttons(channel_id, old_name, new_name)
        reminders = scheduling.rename_scheduled_replies(channel_id, old_name, new_name)

        await persistence.save_configuration()
        if messages:
            await persistence.flush_button_cache()
        if reminders:
            await persistence.flush_replies_cache()

    changed = {'configs': referring, 'messages': messages, 'reminders': reminders}
    log(f"Renamed config '{old_name}' to '{new_name}' in channel {channel_id}: {changed}.")
    return True, "", changed


def describe_changes(changed: dict) -> str:
    """"; also updated 2 rules and 1 pending message" — or "" when nothing else moved."""
    parts = [
        (changed.get('configs') or 0, "rule", "rules"),
        (changed.get('messages') or 0, "posted message", "posted messages"),
        (changed.get('reminders') or 0, "queued reminder", "queued reminders"),
    ]
    said = [f"{count} {singular if count == 1 else plural}" for count, singular, plural in parts if count]
    if not said:
        return ""
    if len(said) > 1:
        said[-1] = f"and {said[-1]}"
    return "; also updated " + (", ".join(said) if len(said) > 2 else " ".join(said))
