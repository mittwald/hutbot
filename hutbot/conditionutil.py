"""Normalization and evaluation of a rule's condition chain.

A leaf module, like ``buttonutil``: it imports only ``re`` and ``constants``, so every
consumer (``persistence``, ``actions``, the setters, ``info``, ``webui_backend``) can use it
without touching the ``actions`` <-> ``buttons`` import cycle.

``evaluate_conditions`` is deliberately pure and synchronous. It takes an already-resolved
variable dict so the gate, the message render, and any OpsGenie alert all judge the same
snapshot; two independent async resolutions could disagree on a time-dependent condition,
which is exactly the race the gate exists to prevent.
"""

import re

from .constants import (
    CONDITION_MODE_ALIASES,
    CONDITION_MODE_ALL,
    CONDITION_MODE_ANY,
    CONDITION_MODES,
    CONDITION_OP_CONTAINS,
    CONDITION_OP_EMPTY,
    CONDITION_OP_ENDS_WITH,
    CONDITION_OP_EQUALS,
    CONDITION_OP_NOT_CONTAINS,
    CONDITION_OP_NOT_EMPTY,
    CONDITION_OP_NOT_ENDS_WITH,
    CONDITION_OP_NOT_EQUALS,
    CONDITION_OP_NOT_REGEX,
    CONDITION_OP_NOT_STARTS_WITH,
    CONDITION_OP_REGEX,
    CONDITION_OP_STARTS_WITH,
    CONDITION_OPERATOR_ALIASES,
    CONDITION_OPERATORS,
    CONDITION_OPERATORS_WITHOUT_VALUE,
    FIRE_TIME_TEMPLATE_VARIABLES,
    LIST_TEMPLATE_VARIABLES,
    UNKNOWN_PLACEHOLDERS,
    CALENDAR_EVENT_TEMPLATE_VARIABLES,
    event_slice_name,
    normalize_selector,
)

# A condition's value may be followed by a case-sensitivity flag, but only after a quoted
# value or a single bare token — the same rule `set pattern "<regex>" [0|1]` uses, which is
# what keeps `contains "deploy to prod"` from swallowing a trailing flag ambiguously.
#
# This lives here rather than in `commands/patterns.py` on purpose: `matches_a_command`
# reflects over every `*_PATTERN` name in that module and would treat this as a command
# matcher, making ordinary text like `foo 1` look like a command.
CONDITION_VALUE_PATTERN = re.compile(
    r'^(?P<value>"[^"]*"|\'[^\']*\'|`[^`]*`|\S+)\s+'
    r'(?P<flag>true|false|1|0|yes|no|on|off|case[_-]?sensitive|case[_-]?insensitive)$',
    re.IGNORECASE,
)
_TRUTHY_CASE_FLAGS = {'true', '1', 'yes', 'on', 'case_sensitive'}


def canonical_operator(text: str) -> str:
    """The canonical operator name for what a user typed, or "" when unknown.

    Handles the aliases, `-`/space separators, and a leading `not`/`!`, so `not contains`,
    `not-contains`, `!contains` and `not_contains` all arrive at the same place.
    """
    value = (text or "").strip().lower().replace('-', '_')
    value = re.sub(r'\s+', '_', value)
    value = re.sub(r'_+', '_', value).strip('_')
    if not value:
        return ""

    negated = False
    if value.startswith('!') and len(value) > 1 and value != '!=' and value != '!~':
        negated, value = True, value[1:].strip('_')
    elif value.startswith('not_'):
        negated, value = True, value[len('not_'):]

    resolved = value if value in CONDITION_OPERATORS else CONDITION_OPERATOR_ALIASES.get(value, "")
    if not resolved:
        return ""
    if not negated:
        return resolved
    # `not not_x` folds back to `x`, and `not x` becomes `not_x`.
    flipped = resolved[len('not_'):] if resolved.startswith('not_') else f'not_{resolved}'
    return flipped if flipped in CONDITION_OPERATORS else ""


def canonical_condition_mode(text: str) -> str:
    """`all`/`any` (with aliases) or "" when the value is not a known mode."""
    value = (text or "").strip().lower().replace('-', '_')
    value = CONDITION_MODE_ALIASES.get(value, value)
    return value if value in CONDITION_MODES else ""


def split_case_flag(text: str) -> tuple[str, bool]:
    """Peel an optional trailing case-sensitivity flag off a condition's value."""
    text = (text or "").strip()
    match = CONDITION_VALUE_PATTERN.match(text)
    if not match:
        return _strip_quotes(text), False
    flag = match.group('flag').lower().replace('-', '_')
    return _strip_quotes(match.group('value')), flag in _TRUTHY_CASE_FLAGS


def _strip_quotes(text: str) -> str:
    # Local copy so this module stays dependency-free (textutil imports models). Kept in step
    # with textutil.QUOTE_CHARACTERS.
    if text and len(text) > 1 and text[0] == text[-1] and text[0] in ('"', "'", '`'):
        return text[1:-1]
    return text


def normalize_variable(text: str) -> str:
    """`{{message}}` and `MESSAGE` both name the `message` variable."""
    value = (text or "").strip()
    if value.startswith('{{') and value.endswith('}}'):
        value = value[2:-2].strip()
    return value.lower()


def normalize_condition(condition) -> tuple[str, str, str, bool, str, str]:
    """A stored condition reduced to `(variable, operator, value, case_sensitive, at, offset)`.

    Returns an empty operator for anything unusable, so callers can drop it. `at` and `offset`
    are the calendar selector: they name which event the condition reads, and are their own
    fields rather than part of `variable`, so every name check and the web UI's dropdown keep
    working on a bare variable name.
    """
    if not isinstance(condition, dict):
        return "", "", "", False, "", ""
    variable = normalize_variable(str(condition.get('variable') or ''))
    operator = canonical_operator(str(condition.get('operator') or ''))
    value = condition.get('value')
    value = '' if value is None else str(value)
    case_sensitive = bool(condition.get('case_sensitive', False))
    at = str(condition.get('at') or '').strip()
    offset = str(condition.get('offset') or '').strip()
    if variable not in CALENDAR_EVENT_TEMPLATE_VARIABLES:
        # Only a calendar event has neighbours or another moment to read it at.
        at, offset = '', ''
    if operator in CONDITION_OPERATORS_WITHOUT_VALUE:
        # Nothing to compare against, so neither a value nor a case flag can matter.
        value, case_sensitive = '', False
    return variable, operator, value, case_sensitive, at, offset


def condition_variable_stem(condition) -> str:
    """The namespace key a condition reads: the variable, or its selector slice.

    The same name `templating` builds for `{{calendar_summary(at="+1d")}}`, so a condition and
    a message asking about one moment read one resolved value.
    """
    variable, _, _, _, at, offset = normalize_condition(condition)
    if not (at or offset):
        return variable
    try:
        return event_slice_name(variable, at, offset)
    except ValueError:
        return variable


def condition_variables(config: dict | None) -> set[str]:
    """Every variable name the config's conditions read."""
    variables = set()
    for condition in (config or {}).get('conditions') or []:
        variable, operator, _, _, _, _ = normalize_condition(condition)
        if variable and operator:
            variables.add(variable)
    return variables


def condition_calendar_selectors(config: dict | None) -> list[tuple[str, str]]:
    """The distinct `(at, offset)` pairs the config's conditions ask the calendar about."""
    selectors = []
    seen = set()
    for condition in (config or {}).get('conditions') or []:
        variable, operator, _, _, at, offset = normalize_condition(condition)
        if not (variable and operator) or not (at or offset):
            continue
        try:
            key = normalize_selector(at, offset)
        except ValueError:
            continue
        if key in seen:
            continue
        seen.add(key)
        selectors.append((at, offset))
    return selectors


def describe_condition(condition, code: bool = False) -> str:
    """`{{message}} contains "urgent" (case-insensitive)` — for `show config` and replies.

    `code` wraps the variable in backticks, for a chat reply. `show config` prints inside a
    code fence, where backticks would show up literally, so it leaves them off.

    The casing is always stated, so nobody has to remember which way the default goes. The
    wording matches how `show config` already labels `set pattern`. Operators that read the
    variable without comparing anything (`empty`, `not_empty`) say nothing, because for them
    there is no casing to apply.
    """
    variable, operator, value, case_sensitive, at, offset = normalize_condition(condition)
    if not variable or not operator:
        return "<invalid condition>"
    arguments = ", ".join(part for part in (f'at="{at}"' if at else "",
                                           f"offset={offset}" if offset else "") if part)
    expression = f"{variable}({arguments})" if arguments else variable
    name = f"`{{{{{expression}}}}}`" if code else f"{{{{{expression}}}}}"
    text = f"{name} {operator}"
    if operator not in CONDITION_OPERATORS_WITHOUT_VALUE:
        text += f' "{value}"'
        text += " (case-sensitive)" if case_sensitive else " (case-insensitive)"
    return text


def _resolved_is_empty(value: str) -> bool:
    """Whether a resolved value counts as empty.

    The OpsGenie placeholders (`<no-user-set>` and friends) are never the empty string, so
    without this `opsgenie_current_user empty` — the natural "is anyone on call?" check —
    could never be true. Only `empty`/`not_empty` get this treatment; the comparison
    operators still see the raw placeholder.
    """
    return value == "" or value in UNKNOWN_PLACEHOLDERS


def _test_condition(operator: str, resolved: str, value: str, case_sensitive: bool) -> tuple[bool, str]:
    """Apply one operator. Returns `(result, error)`; a non-empty error means fail closed."""
    if operator == CONDITION_OP_EMPTY:
        return _resolved_is_empty(resolved), ""
    if operator == CONDITION_OP_NOT_EMPTY:
        return not _resolved_is_empty(resolved), ""

    if operator in (CONDITION_OP_REGEX, CONDITION_OP_NOT_REGEX):
        try:
            matched = re.search(value, resolved, 0 if case_sensitive else re.IGNORECASE) is not None
        except re.error as e:
            return False, f"invalid pattern `{value}`: {e}"
        return (matched if operator == CONDITION_OP_REGEX else not matched), ""

    left, right = (resolved, value) if case_sensitive else (resolved.casefold(), value.casefold())
    if operator == CONDITION_OP_EQUALS:
        return left == right, ""
    if operator == CONDITION_OP_NOT_EQUALS:
        return left != right, ""
    if operator == CONDITION_OP_CONTAINS:
        return right in left, ""
    if operator == CONDITION_OP_NOT_CONTAINS:
        return right not in left, ""
    if operator == CONDITION_OP_STARTS_WITH:
        return left.startswith(right), ""
    if operator == CONDITION_OP_NOT_STARTS_WITH:
        return not left.startswith(right), ""
    if operator == CONDITION_OP_ENDS_WITH:
        return left.endswith(right), ""
    if operator == CONDITION_OP_NOT_ENDS_WITH:
        return not left.endswith(right), ""
    return False, f"unknown operator `{operator}`"


def snapshot_conditions(config: dict) -> dict:
    """The condition chain as it stands, frozen for work that will run later.

    A reminder can wait a day before its conditions are judged, and a buttoned message can
    sit unpressed just as long. Reading the chain live at that point would let an edit made in
    the meantime silently cancel work that was already committed to — so the chain travels
    with the pending record, the same way a message's buttons are snapshotted when it is
    posted.

    Only the rules are frozen. What they are judged against (the calendar, who is on call, the
    time) is still resolved when the work runs, which is the whole point of gating on it, and
    every other setting stays live too.
    """
    return {
        'conditions': [dict(c) for c in (config.get('conditions') or []) if isinstance(c, dict)],
        'conditions_mode': config.get('conditions_mode') or CONDITION_MODE_ALL,
    }


def list_items(variables: dict, variable: str) -> list[str]:
    """The entries of a list variable.

    The provider stores them under ``__<variable>_items`` beside the comma-joined form a
    message renders; splitting that form is the fallback for a hand-built variable dict.
    """
    items = variables.get(f"__{variable}_items")
    if items is None:
        return [part.strip() for part in (variables.get(variable) or "").split(",") if part.strip()]
    return list(items)


def condition_needs_fire_time(condition) -> bool:
    """Whether this condition reads something that is only known once the rule fires."""
    variable, operator, _, _, _, _ = normalize_condition(condition)
    return bool(operator) and variable in FIRE_TIME_TEMPLATE_VARIABLES


def settled_condition_variables(config: dict | None) -> set[str]:
    """The variables of the conditions that can already be judged when a message arrives."""
    variables = set()
    for condition in (config or {}).get('conditions') or []:
        if condition_needs_fire_time(condition):
            continue
        variable, operator, _, _, _, _ = normalize_condition(condition)
        if variable and operator:
            variables.add(variable)
    return variables


def _judge_list(operator: str, items: list, value: str, case_sensitive: bool) -> tuple[bool, str]:
    """Apply an operator across the items of a list variable.

    A positive operator passes when **any** item matches; a `not_` operator passes when
    **none** does. Negating item-by-item instead would make `not_equals` true for any list
    with two different entries, which is never what someone means by "X is not an attendee".
    """
    # The parallel calendar lists keep a blank where a participant has no address or no
    # Slack account, so positions line up across them. Those blanks are placeholders, not
    # entries, so a condition never sees them.
    items = [item for item in items if item]
    if operator == CONDITION_OP_EMPTY:
        return not items, ""
    if operator == CONDITION_OP_NOT_EMPTY:
        return bool(items), ""

    negated = operator.startswith('not_')
    positive = operator[len('not_'):] if negated else operator
    matched = False
    for item in items:
        met, error = _test_condition(positive, item, value, case_sensitive)
        if error:
            return False, error
        matched = matched or met
    return (not matched) if negated else matched, ""


def _judge(condition, variables: dict[str, str]) -> tuple[bool, str]:
    """One condition against resolved variables: `(met, reason_when_not_met)`."""
    variable, operator, value, case_sensitive, at, offset = normalize_condition(condition)
    label = describe_condition(condition, code=True)
    if not variable or not operator:
        return False, f"{label} is not a usable condition"
    # A selector reads its own slice of the namespace, the same one the identical expression in
    # a message reads — so a condition and the text it gates describe one moment.
    stem = condition_variable_stem(condition)
    value_key = f"__{stem}" if stem != variable else variable
    if variable not in variables:
        return False, f"{label} refers to an unknown variable `{{{{{variable}}}}}`"
    if variable in LIST_TEMPLATE_VARIABLES:
        met, error = _judge_list(operator, list_items(variables, stem), value, case_sensitive)
    else:
        met, error = _test_condition(operator, variables.get(value_key) or "", value, case_sensitive)
    return met, error or ("" if met else f"{label} did not match")

def conditions_ruled_out(config: dict | None, variables: dict[str, str]) -> tuple[bool, str]:
    """Whether the chain already cannot pass, judging only the settled conditions.

    Lets a message-triggered rule skip queueing a reminder that could never fire. Under
    `all`, one settled condition failing settles the whole chain. Under `any`, a condition
    still to be resolved at fire time could carry it, so nothing is decided while one exists.
    """
    conditions = (config or {}).get('conditions') or []
    if not conditions:
        return False, ""
    settled = [c for c in conditions if not condition_needs_fire_time(c)]
    if not settled:
        return False, ""

    mode = canonical_condition_mode(str((config or {}).get('conditions_mode') or '')) or CONDITION_MODE_ALL
    if mode == CONDITION_MODE_ALL:
        for condition in settled:
            met, reason = _judge(condition, variables)
            if not met:
                return True, reason
        return False, ""

    if len(settled) != len(conditions):
        return False, ""
    results = [_judge(condition, variables) for condition in settled]
    if any(met for met, _ in results):
        return False, ""
    reasons = "; ".join(reason for met, reason in results if not met)
    return True, f"none of the conditions matched ({reasons})"


def evaluate_conditions(config: dict | None, variables: dict[str, str]) -> tuple[bool, str]:
    """Whether a rule's conditions allow it to run, and why not when they do not.

    An empty chain always passes — checked before the match mode, because `any` over an
    empty list must not mean "never".

    A condition that cannot be judged (unknown variable, invalid regex) is **not met**
    whatever its operator: treating a vanished variable as satisfying `not_equals` would let
    a broken config page someone. So `not_*` is not a pure negation in that one case.
    """
    conditions = (config or {}).get('conditions') or []
    if not conditions:
        return True, ""

    match_mode = canonical_condition_mode(str((config or {}).get('conditions_mode') or '')) or CONDITION_MODE_ALL
    results = [_judge(condition, variables) for condition in conditions]

    if match_mode == CONDITION_MODE_ANY:
        if any(met for met, _ in results):
            return True, ""
        reasons = "; ".join(reason for met, reason in results if not met)
        return False, f"none of the conditions matched ({reasons})"

    for met, reason in results:
        if not met:
            return False, reason
    return True, ""
