"""The `config export` payload: what goes into one, and how to read one back.

One rule — or every rule of a channel — as JSON, moved between channels or between
instances. Shared by three callers that must agree byte for byte about the format —
`config export`, `config import`, and the export and import modals of the App Home — so the
envelope, the skipped fields and the fence handling live here rather than in whichever of
them was written first.

A leaf: `constants` and `textutil` only.
"""

import copy
import json

from .constants import CONFIG_EXPORT_FORMAT, DEFAULT_CONFIG
from .textutil import unwrap_slack_link

# Left out of an export on purpose: the calendar URL is a bearer secret that must never be
# printed to a channel or shown in a modal (the exporter says so when one is set), and
# `disabled_reason` is the bot's own bookkeeping, not a setting the exporter made.
SKIPPED_FIELDS = {'calendar_url', 'disabled_reason'}


def exported_settings(config: dict) -> dict:
    """Only the fields that differ from the defaults.

    Keeps the JSON readable, and keeps an import from changing anything the exporter did not
    actually set: a field missing from `settings` takes the default.
    """
    return {
        key: copy.deepcopy(value)
        for key, value in (config or {}).items()
        if key in DEFAULT_CONFIG and key not in SKIPPED_FIELDS and value != DEFAULT_CONFIG[key]
    }


def build_payload(config_name: str, config: dict) -> dict:
    """The envelope around one config."""
    return {"format": CONFIG_EXPORT_FORMAT, "name": config_name,
            "settings": exported_settings(config)}


def build_multi_payload(configs: dict) -> dict:
    """The envelope around several configs, in the order `configs` lists them.

    A whole channel travels in a single paste this way, and `read_entries` reads it back into
    the same order.
    """
    return {"format": CONFIG_EXPORT_FORMAT,
            "configs": [{"name": name, "settings": exported_settings(config)}
                        for name, config in configs.items()]}


def dump_payload(payload: dict) -> str:
    """The JSON as it is printed, with every backtick escaped.

    A backtick can only occur inside a JSON string, so escaping them all keeps the JSON valid
    (and round-tripping) while a value containing ``` cannot close the code fence early the
    way `show config` has to guard against.
    """
    return json.dumps(payload, indent=2, ensure_ascii=False).replace("`", "\\u0060")


def strip_json_block(text: str) -> str:
    """The pasted JSON without the code fence or backticks Slack pastes tend to wrap it in."""
    text = (text or "").strip()
    if text.startswith("```") and text.endswith("```") and len(text) > 6:
        text = text[3:-3]
        # A fence may open with a language word (```json); that word belongs to the fence.
        first_line, _, rest = text.partition("\n")
        if first_line.strip().lower() in ("", "json"):
            text = rest
    else:
        text = text.strip('`')
    return text.strip()


def read_entries(text: str, command: str = "") -> tuple[list[tuple[str, dict]] | None, str]:
    """`(entries, error)` for a pasted export: `(exported name, settings)` per config in it.

    In the order the export lists them, so an all-configs export and a single one take the
    same path from here on. A bare settings object without the envelope is accepted too, for
    a hand-written import. `command` is the instance's slash command, named in the two errors
    that suggest what to paste instead.
    """
    try:
        payload = json.loads(strip_json_block(text))
    except json.JSONDecodeError as e:
        return None, (f"That is not valid JSON ({e}). Paste an export made with "
                      f"`{command} [config] config export`.")
    if not isinstance(payload, dict):
        return None, ("The import must be a JSON object, like the one "
                      f"`{command} config export` prints.")

    if 'settings' in payload or 'configs' in payload or 'format' in payload:
        format_value = str(payload.get('format') or "")
        if format_value != CONFIG_EXPORT_FORMAT:
            return None, (f"Unsupported export format `{format_value}`; this bot reads "
                          f"`{CONFIG_EXPORT_FORMAT}`.")
        if 'configs' in payload:
            listed = payload.get('configs')
            if not isinstance(listed, list) or not listed:
                return None, "The export's `configs` must be a non-empty JSON array."
            entries: list[tuple[str, dict]] = []
            for entry in listed:
                if not isinstance(entry, dict) or not isinstance(entry.get('settings'), dict):
                    return None, ("Every entry in the export's `configs` needs a `name` and "
                                  "a `settings` object.")
                entries.append((str(entry.get('name') or "").strip(), entry['settings']))
            return entries, ""
        settings = payload.get('settings')
        if not isinstance(settings, dict):
            return None, "The export's `settings` must be a JSON object."
        return [(str(payload.get('name') or "").strip(), settings)], ""
    return [("", payload)], ""


def read_payload(text: str, command: str = "") -> tuple[dict | None, str, str]:
    """`(settings, name_from_the_envelope, error)` for a pasted export of a single config.

    For the callers that import into one named config — the App Home's import modal — where
    an all-configs export has nowhere to go and is refused rather than half-applied.
    """
    entries, error = read_entries(text, command)
    if error:
        return None, "", error
    if len(entries) > 1:
        return None, "", (f"That export holds {len(entries)} configurations; import it with "
                          f"`{command} config import <json>`.")
    envelope_name, settings = entries[0]
    return settings, envelope_name, ""


def unknown_settings(settings: dict) -> list[str]:
    """Keys that are not settings at all, so a typo is named rather than silently ignored."""
    return sorted(key for key in (settings or {}) if key not in DEFAULT_CONFIG)


def normalized_settings(settings: dict) -> dict:
    """The settings with a Slack-wrapped URL unwrapped; Slack writes `<…>` around one."""
    if isinstance((settings or {}).get('calendar_url'), str):
        settings = dict(settings)
        settings['calendar_url'] = unwrap_slack_link(settings['calendar_url'])
    return settings
