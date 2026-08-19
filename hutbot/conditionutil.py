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
    CONDITION_MATCH_ALIASES,
    CONDITION_MATCH_ALL,
    CONDITION_MATCH_ANY,
    CONDITION_MATCHES,
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
    UNKNOWN_PLACEHOLDERS,
)

# A condition's value may be followed by a case-sensitivity flag, but only after a quoted
# value or a single bare token — the same rule `set pattern "<regex>" [0|1]` uses, which is
# what keeps `contains "deploy to prod"` from swallowing a trailing flag ambiguously.
#
# This lives here rather than in `commands/patterns.py` on purpose: `matches_a_command`
# reflects over every `*_PATTERN` name in that module and would treat this as a command
# matcher, making ordinary text like `foo 1` look like a command.
CONDITION_VALUE_PATTERN = re.compile(
    r'^(?P<value>"[^"]*"|\'[^\']*\'|\S+)\s+'
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


def canonical_match_mode(text: str) -> str:
    """`all`/`any` (with aliases) or "" when the value is not a known mode."""
    value = (text or "").strip().lower().replace('-', '_')
    value = CONDITION_MATCH_ALIASES.get(value, value)
    return value if value in CONDITION_MATCHES else ""


def split_case_flag(text: str) -> tuple[str, bool]:
    """Peel an optional trailing case-sensitivity flag off a condition's value."""
    text = (text or "").strip()
    match = CONDITION_VALUE_PATTERN.match(text)
    if not match:
        return _strip_quotes(text), False
    flag = match.group('flag').lower().replace('-', '_')
    return _strip_quotes(match.group('value')), flag in _TRUTHY_CASE_FLAGS


def _strip_quotes(text: str) -> str:
    # Local copy so this module stays dependency-free (textutil imports models).
    if text and ((text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'"))):
        return text[1:-1]
    return text


def normalize_variable(text: str) -> str:
    """`{{message}}` and `MESSAGE` both name the `message` variable."""
    value = (text or "").strip()
    if value.startswith('{{') and value.endswith('}}'):
        value = value[2:-2].strip()
    return value.lower()


def normalize_condition(condition) -> tuple[str, str, str, bool]:
    """A stored condition reduced to `(variable, operator, value, case_sensitive)`.

    Returns an empty operator for anything unusable, so callers can drop it.
    """
    if not isinstance(condition, dict):
        return "", "", "", False
    variable = normalize_variable(str(condition.get('variable') or ''))
    operator = canonical_operator(str(condition.get('operator') or ''))
    value = condition.get('value')
    value = '' if value is None else str(value)
    case_sensitive = bool(condition.get('case_sensitive', False))
    if operator in CONDITION_OPERATORS_WITHOUT_VALUE:
        # Nothing to compare against, so neither a value nor a case flag can matter.
        value, case_sensitive = '', False
    return variable, operator, value, case_sensitive


def condition_variables(config: dict | None) -> set[str]:
    """Every variable name the config's conditions read."""
    variables = set()
    for condition in (config or {}).get('conditions') or []:
        variable, operator, _, _ = normalize_condition(condition)
        if variable and operator:
            variables.add(variable)
    return variables


def describe_condition(condition) -> str:
    """`{{message}} contains "urgent" (case-sensitive)` — for `show config` and help."""
    variable, operator, value, case_sensitive = normalize_condition(condition)
    if not variable or not operator:
        return "<invalid condition>"
    text = f"{{{{{variable}}}}} {operator}"
    if operator not in CONDITION_OPERATORS_WITHOUT_VALUE:
        text += f' "{value}"'
    if case_sensitive:
        text += " (case-sensitive)"
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

    match_mode = canonical_match_mode(str((config or {}).get('conditions_match') or '')) or CONDITION_MATCH_ALL
    results = []
    for condition in conditions:
        variable, operator, value, case_sensitive = normalize_condition(condition)
        label = describe_condition(condition)
        if not variable or not operator:
            results.append((False, f"{label} is not a usable condition"))
            continue
        if variable not in variables:
            results.append((False, f"{label} refers to an unknown variable `{{{{{variable}}}}}`"))
            continue
        met, error = _test_condition(operator, variables.get(variable) or "", value, case_sensitive)
        results.append((met, error or ("" if met else f"{label} did not match")))

    if match_mode == CONDITION_MATCH_ANY:
        if any(met for met, _ in results):
            return True, ""
        reasons = "; ".join(reason for met, reason in results if not met)
        return False, f"none of the conditions matched ({reasons})"

    for met, reason in results:
        if not met:
            return False, reason
    return True, ""
