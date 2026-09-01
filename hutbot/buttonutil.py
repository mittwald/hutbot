"""Pure helpers over button/config dicts.

Kept as a leaf (depends only on constants) so both ``persistence`` (config
migration) and ``buttons`` can use them without an import cycle.
"""

from .constants import BUTTON_ACTION_CONFIG
from .textutil import split_comma_list


def normalize_button(button: dict) -> tuple[str, str]:
    """Return (action, value) for a button, defaulting a missing action to `config`."""
    return button.get('action') or BUTTON_ACTION_CONFIG, button.get('value', '') or ''


def parse_config_list(value: str) -> list[str]:
    """The config names a `config` button or a `config` escalation runs, in the written order.

    One press or one timeout may run several configs, written comma-separated. A comma is a
    safe separator because `CONFIG_NAME_PATTERN` does not allow one inside a name, so nothing
    here is ambiguous; `split_comma_list` handles the trimming, the blanks and the repeats the
    same way for every command that takes a list.
    """
    return split_comma_list(value)


def format_config_list(names) -> str:
    """…and back into the single stored string, in the spelling the setters normalize to."""
    return ", ".join(names)


def button_config_names(button: dict) -> list[str]:
    """The configs one button runs — empty for an `ack` or a `delay` button."""
    action, value = normalize_button(button)
    return parse_config_list(value) if action == BUTTON_ACTION_CONFIG else []


def rename_in_config_list(value: str, old_name: str, new_name: str) -> tuple[str, bool]:
    """`value` with one config name replaced; also whether it was in there at all.

    A stored value may name several configs, so a rename rewrites one entry of a list rather
    than the whole field. The list is re-joined in the normalized spelling, which is what the
    setters and the web UI write anyway.
    """
    names = parse_config_list(value)
    if old_name not in names:
        return value, False
    renamed = [new_name if name == old_name else name for name in names]
    # `dict.fromkeys` rather than a set: order is what the note and the run sequence follow,
    # and renaming `a` to `b` in `a,b` must leave one `b`, not two.
    return format_config_list(list(dict.fromkeys(renamed))), True


def _find_button_index(config: dict | None, label: str) -> int | None:
    """Index of the first button matching `label` (case-insensitive), or None."""
    if not config or not label:
        return None
    target = label.strip().casefold()
    for i, button in enumerate(config.get('buttons') or []):
        if (button.get('label') or '').strip().casefold() == target:
            return i
    return None
