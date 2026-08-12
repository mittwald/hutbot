"""Pure helpers over button/config dicts.

Kept as a leaf (depends only on constants) so both ``persistence`` (config
migration) and ``buttons`` can use them without an import cycle.
"""

from .constants import BUTTON_ACTION_CONFIG


def normalize_button(button: dict) -> tuple[str, str]:
    """Return (action, value) for a button, defaulting a missing action to `config`."""
    return button.get('action') or BUTTON_ACTION_CONFIG, button.get('value', '') or ''


def _find_button_index(config: dict | None, label: str) -> int | None:
    """Index of the first button matching `label` (case-insensitive), or None."""
    if not config or not label:
        return None
    target = label.strip().casefold()
    for i, button in enumerate(config.get('buttons') or []):
        if (button.get('label') or '').strip().casefold() == target:
            return i
    return None
