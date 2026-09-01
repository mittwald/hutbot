"""The contract the config UI's views and its submit handlers share.

A modal reports a validation error by `block_id`, and `webui_backend.validate_config_payload`
reports one by config field name. This module is the single place those two namings meet: a
field's block is always ``f:<field name>``, so an error key becomes a block id by
concatenation. Keeping the mapping here rather than inside the view builders means the code
that renders a form and the code that reads it back cannot drift apart unnoticed — the same
argument `conditionutil` makes for itself.

Depends on `constants` and `buttonutil`, both leaves, so it is testable with plain dicts and
no Slack payloads.
"""

import json

from ..buttonutil import format_config_list
from ..constants import (
    CONDITION_OPERATORS_WITHOUT_VALUE,
    CONFIG_UI_BLOCK_PREFIX,
)

# Which fields each modal owns. A section's submit sends a whole config document (see
# `handlers`), so this is only about which values that submit reads out of the view — but it
# doubles as the map of where every setting can be reached, which is why the test suite
# asserts it covers `DEFAULT_CONFIG`.
SECTIONS: dict[str, tuple[str, ...]] = {
    "trigger": ("trigger", "cron", "wait_time"),
    "message": ("action", "action_target", "reply_message"),
    "filters": ("pattern", "pattern_case_sensitive", "include_bots",
                "only_work_days", "hours", "included_teams", "excluded_teams"),
    # Escalation lives with the buttons, not beside them: `actions.run_action` only registers
    # an escalation for a config that has buttons, and the two cross-check each other in
    # `validate_config_payload`. Editing them together is what keeps those checks local.
    "escalation": ("escalation_kind", "escalation_timeout", "escalation_target"),
    "opsgenie": ("opsgenie", "opsgenie_schedule_name", "opsgenie_priority", "opsgenie_message"),
    "calendar": ("calendar_builtin", "calendar_url"),
    "formatting": ("date_format", "time_format", "datetime_timezone", "datetime_locale", "debug"),
}

# Sections whose rows are edited one at a time, in a pushed modal of their own, rather than
# through input blocks of the list view itself.
LIST_SECTIONS: dict[str, tuple[str, ...]] = {
    "conditions": ("conditions", "conditions_mode"),
    "buttons": ("buttons",),
}

# Toggled straight from the rule hub, which has no submit button of its own.
HUB_FIELDS: tuple[str, ...] = ("enabled",)

# Stored in seconds, entered in minutes — the unit every slash command already uses, so the
# two ways of setting the same field cannot disagree about what "30" means.
MINUTE_FIELDS: tuple[str, ...] = ("wait_time", "escalation_timeout")

BOOLEAN_FIELDS: tuple[str, ...] = ("enabled", "opsgenie", "include_bots", "only_work_days",
                                   "debug", "pattern_case_sensitive")

# Non-field blocks: a value that needs a second element, or an input that is not a config
# field at all. Kept out of the `f:<field>` contract's way but inside the same namespace so a
# view's block ids are uniform.
BLOCK_HOURS_END = "hours_end"
BLOCK_TEAM_MODE = "team_mode"
BLOCK_NAME = "name"
# Ticked, the action target renders as free text for a `{{template}}` instead of as a channel
# or user select. Either element carries `block_id("action_target")`, so the value reads back
# the same way and an error about it always has a block to sit on.
BLOCK_TARGET_TEMPLATE = "action_target_template"
NON_FIELD_BLOCKS: tuple[str, ...] = (BLOCK_HOURS_END, BLOCK_TEAM_MODE, BLOCK_NAME,
                                     BLOCK_TARGET_TEMPLATE)

TEAM_MODE_ALL = "all"
TEAM_MODE_ONLY = "only"
TEAM_MODE_EXCEPT = "except"

# Row fields, for the two pushed row forms.
CONDITION_ROW_FIELDS: tuple[str, ...] = ("variable", "operator", "value", "case_sensitive",
                                         "at", "offset")
BUTTON_ROW_FIELDS: tuple[str, ...] = ("label", "action", "value")

# One label per field, used both for a form's input label and as the prefix on an error that
# belongs to a field the current modal does not show. Sourcing both from one dict is what
# stops a prefix from naming a field differently than the form that owns it.
FIELD_LABELS: dict[str, str] = {
    "wait_time": "Reminder delay",
    "reply_message": "Reply message",
    "opsgenie": "OpsGenie alert",
    "opsgenie_schedule_name": "OpsGenie schedule",
    "opsgenie_priority": "OpsGenie priority",
    "opsgenie_message": "OpsGenie message",
    "calendar_builtin": "Built-in calendar",
    "calendar_url": "Calendar feed URL",
    "date_format": "Date format",
    "time_format": "Time format",
    "datetime_timezone": "Time zone",
    "datetime_locale": "Locale",
    "debug": "Debug logging",
    "include_bots": "Include bots",
    "excluded_teams": "Excluded teams",
    "included_teams": "Included teams",
    "only_work_days": "Only on work days",
    "hours": "Work hours",
    "pattern": "Message pattern",
    "pattern_case_sensitive": "Pattern is case sensitive",
    "enabled": "Enabled",
    "trigger": "Trigger",
    "cron": "Schedule",
    "conditions": "Conditions",
    "conditions_mode": "Condition mode",
    "action": "Action",
    "action_target": "Action target",
    "buttons": "Buttons",
    "escalation_timeout": "Escalation timeout",
    "escalation_kind": "Escalation",
    "escalation_target": "Escalation target",
    # Row fields.
    "variable": "Variable",
    "operator": "Operator",
    "value": "Value",
    "case_sensitive": "Case sensitive",
    "at": "Moment",
    "offset": "Event offset",
    "label": "Button label",
    # Non-field blocks and the keys `ui_apply_config` reports outside the schema.
    BLOCK_HOURS_END: "Work hours end",
    BLOCK_TEAM_MODE: "Team filter",
    BLOCK_NAME: "Name",
    BLOCK_TARGET_TEMPLATE: "Action target is a template",
}

# An error attached to a block Slack no longer shows is an error the user never reads, so
# leftovers are folded into one block. Slack silently drops an over-long error text.
LEFTOVER_LIMIT = 1500


def block_id(field: str) -> str:
    """The block id a field's input lives in."""
    return f"{CONFIG_UI_BLOCK_PREFIX}:{field}"


def field_of(block: str) -> str:
    """The field a block id belongs to, or `""` for a block outside the namespace."""
    prefix = f"{CONFIG_UI_BLOCK_PREFIX}:"
    return block[len(prefix):] if block.startswith(prefix) else ""


def all_ui_fields() -> set[str]:
    """Every config field the UI can reach, from all three kinds of view."""
    reachable: set[str] = set(HUB_FIELDS)
    for fields in SECTIONS.values():
        reachable.update(fields)
    for fields in LIST_SECTIONS.values():
        reachable.update(fields)
    return reachable


def encode_meta(channel_id: str, config_name: str = "", section: str = "", row: int | None = None,
                extra: dict | None = None) -> str:
    """`private_metadata` for a view: what it edits, in short keys.

    Short keys because Slack caps `private_metadata` at 3000 characters and a rule name may
    be long; everything the handlers need has to fit with room to spare.
    """
    meta: dict = {"c": channel_id}
    if config_name:
        meta["n"] = config_name
    if section:
        meta["s"] = section
    if row is not None:
        meta["i"] = row
    if extra:
        meta.update(extra)
    return json.dumps(meta, separators=(',', ':'))


def decode_meta(raw: str) -> dict:
    """The long-named form of `encode_meta`'s payload.

    Always the same keys, blank when the metadata was missing or unreadable, so a handler
    reads them without asking first whether there was any. A blank channel id is what the
    handlers check, and it fails the membership check like any other unknown channel.
    """
    try:
        meta = json.loads(raw or "{}")
    except (TypeError, ValueError):
        meta = {}
    if not isinstance(meta, dict):
        meta = {}
    decoded = {
        "channel_id": str(meta.get("c") or ""),
        "config_name": str(meta.get("n") or ""),
        "section": str(meta.get("s") or ""),
    }
    row = meta.get("i")
    decoded["row"] = row if isinstance(row, int) else None
    return decoded


_MULTI_KEYS = ("selected_conversations", "selected_users", "selected_channels")
_SINGLE_KEYS = ("value", "selected_time", "selected_date", "selected_date_time",
                "selected_conversation", "selected_user", "selected_channel")


def _element_value(payload: dict):
    """The value out of one element's `view.state.values` entry, whatever its type."""
    if not isinstance(payload, dict):
        return None
    if 'selected_option' in payload:
        chosen = payload['selected_option']
        return chosen.get('value') if isinstance(chosen, dict) else None
    if 'selected_options' in payload:
        chosen = payload['selected_options'] or []
        return [option.get('value') for option in chosen if isinstance(option, dict)]
    for key in _MULTI_KEYS:
        if key in payload:
            return list(payload[key] or [])
    for key in _SINGLE_KEYS:
        if key in payload:
            return payload[key]
    return None


def read_block(values: dict, block: str):
    """The value submitted in one block, or `None` when the view had no such block."""
    entry = (values or {}).get(block)
    if not isinstance(entry, dict):
        return None
    for payload in entry.values():
        return _element_value(payload)
    return None


def _text(values: dict, block: str) -> str:
    """One block's value as the string the config stores.

    A multi-select answers with a list, and the two fields edited that way — an escalation's
    rules and a `config` button's — are stored as one comma-separated string. Joining it here
    with `format_config_list` keeps that spelling the same as the one the setters write.
    """
    raw = read_block(values, block)
    if isinstance(raw, list):
        return format_config_list(str(item).strip() for item in raw if str(item).strip())
    return "" if raw is None else str(raw).strip()


def _flag(values: dict, block: str) -> bool:
    # A checkbox group with nothing ticked comes back as an empty list, which is the only
    # way Slack has of saying "off".
    return bool(read_block(values, block))


def _minutes(values: dict, field: str):
    """Minutes as seconds — or the raw text, so the backend words the error, not this."""
    raw = read_block(values, block_id(field))
    text = "" if raw is None else str(raw).strip()
    try:
        return int(text) * 60
    except ValueError:
        return text


def _read_hours(values: dict) -> dict:
    if block_id("hours") not in (values or {}):
        return {}
    start = _text(values, block_id("hours"))
    end = _text(values, block_id(BLOCK_HOURS_END))
    # Both empty is how the UI says "all day"; one empty is a half-filled setting and has to
    # reach the backend so it can say so.
    return {"hours": [] if not start and not end else [start, end]}


def _read_teams(values: dict) -> dict:
    if block_id(BLOCK_TEAM_MODE) not in (values or {}):
        return {}
    mode = _text(values, block_id(BLOCK_TEAM_MODE)) or TEAM_MODE_ALL
    chosen = read_block(values, block_id("included_teams")) or []
    chosen = [str(team) for team in chosen] if isinstance(chosen, list) else []
    if mode == TEAM_MODE_ONLY:
        return {"included_teams": chosen, "excluded_teams": []}
    if mode == TEAM_MODE_EXCEPT:
        return {"included_teams": [], "excluded_teams": chosen}
    return {"included_teams": [], "excluded_teams": []}


def _read_pattern(values: dict) -> dict:
    if block_id("pattern") not in (values or {}):
        return {}
    text = _text(values, block_id("pattern"))
    # `None`, not `""`: the stored shape for "no pattern" (`validate_config_payload`).
    return {"pattern": text or None}


_FIELD_READERS = {
    "hours": _read_hours,
    "included_teams": _read_teams,
    "excluded_teams": lambda values: {},  # written by `_read_teams`, from the same control
    "pattern": _read_pattern,
}


def read_section_values(values: dict, section: str) -> dict:
    """The fields of one section, in the shape `validate_config_payload` expects.

    A field whose input the form did not render is left out rather than read as empty: the
    forms hide what does not apply (no reminder delay under a cron trigger, no schedule under
    a message one), and the submit overlays this onto the stored config, so leaving a field
    out is what keeps its stored value. Reading it as empty would blank it on every save.
    """
    submitted: dict = {}
    for field in SECTIONS[section]:
        reader = _FIELD_READERS.get(field)
        if reader is not None:
            submitted.update(reader(values))
            continue
        if block_id(field) not in (values or {}):
            continue
        if field in MINUTE_FIELDS:
            submitted[field] = _minutes(values, field)
        elif field in BOOLEAN_FIELDS:
            submitted[field] = _flag(values, block_id(field))
        else:
            submitted[field] = _text(values, block_id(field))
    return submitted


def read_condition_row(values: dict) -> dict:
    """One condition row, as `validate_config_payload` reads a `conditions` entry."""
    row = {
        "variable": _text(values, block_id("variable")),
        "operator": _text(values, block_id("operator")),
        "value": _text(values, block_id("value")),
        "case_sensitive": _flag(values, block_id("case_sensitive")),
    }
    # Left out entirely when unset, so a row keeps the shape the setters write.
    for optional in ("at", "offset"):
        text = _text(values, block_id(optional))
        if text:
            row[optional] = text
    return row


def read_button_row(values: dict) -> dict:
    """One button row, as `validate_config_payload` reads a `buttons` entry."""
    return {
        "label": _text(values, block_id("label")),
        "action": _text(values, block_id("action")),
        "value": _text(values, block_id("value")),
    }


def condition_row_error_block(block_ids, operator: str = "") -> str:
    """Which block of a condition row form an error about that row should land on.

    The backend reports one message per row, but a row form has several inputs. The value is
    where a row goes wrong most of the time; for the two operators that take no value the
    form has no value input at all, and every remaining message is about the variable or the
    moment.
    """
    present = set(block_ids)
    order = ("value", "offset", "at", "operator", "variable")
    if operator in CONDITION_OPERATORS_WITHOUT_VALUE:
        order = ("offset", "at", "variable", "operator")
    for field in order:
        if block_id(field) in present:
            return block_id(field)
    return ""


def button_row_error_block(block_ids, label: str = "") -> str:
    """Which block of a button row form an error about that row should land on."""
    present = set(block_ids)
    # The one row error that names the label is the empty one, and it is about the label.
    order = ("label", "value", "action") if not label else ("value", "label", "action")
    for field in order:
        if block_id(field) in present:
            return block_id(field)
    return ""


def _leftover_prefix(key: str) -> str:
    """`Condition 3: `, `Escalation target: ` — what an error is about, when its own block is
    not on screen to say so."""
    kind, _, index = key.partition('.')
    if index.isdigit() and kind in LIST_SECTIONS:
        # 1-based, because that is how the list view numbers the rows.
        singular = FIELD_LABELS.get(kind, kind).rstrip('s')
        return f"{singular} {int(index) + 1}: "
    label = FIELD_LABELS.get(key, "")
    return f"{label}: " if label else ""


def map_errors(errors: dict, block_ids, fallback_block_id: str = "",
               row_key: str = "", row_block_id: str = "") -> dict:
    """`{block_id: message}` for a `response_action: "errors"` ack.

    Validation is whole-document, so a section's save can be refused over a field that
    section does not show — a dangling `escalation_target`, or a condition row a hand-edited
    `bot.json` left broken. Those are folded into `fallback_block_id` with a prefix naming
    what they are about, because an error with no block to sit on is an error the user never
    sees and a save that silently does nothing.
    """
    present = set(block_ids)
    mapped: dict[str, str] = {}
    leftovers: list[str] = []
    for key, message in sorted((errors or {}).items()):
        message = str(message)
        candidate = row_block_id if (row_key and key == row_key) else block_id(key)
        if candidate and candidate in present:
            # Two errors on one block (a row error plus that field's own) read as one line.
            mapped[candidate] = f"{mapped[candidate]} {message}" if candidate in mapped else message
        else:
            leftovers.append(f"{_leftover_prefix(key)}{message}")
    if leftovers and fallback_block_id:
        folded = " ".join([mapped.get(fallback_block_id, ""), *leftovers]).strip()
        mapped[fallback_block_id] = folded[:LEFTOVER_LIMIT]
    return mapped
