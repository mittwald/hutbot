"""Parsing and rendering of ``{{variable}}`` reply-message templates."""

import datetime

from slack_bolt.async_app import AsyncApp

from employee_list import log_warning

from . import calendarfeed
from . import conditionutil
from . import datetimefmt
from . import opsgenie
from .constants import (
    CALENDAR_EVENT_TEMPLATE_VARIABLES,
    DATETIME_TEMPLATE_VARIABLES,
    LIST_TEMPLATE_VARIABLES,
    MAX_CALENDAR_SELECTORS,
    SUPPORTED_TEMPLATE_VARIABLES,
    TEAM_UNKNOWN,
    TEMPLATE_ARGUMENT_ALIASES,
    TEMPLATE_ARGUMENT_NAME_PATTERN,
    TEMPLATE_DATETIME_VARIABLES,
    TEMPLATE_VARIABLE_NAME_PATTERN,
    UNKNOWN_PERIOD_PLACEHOLDER,
    event_slice_name,
    invalid_slice_name,
    normalize_selector,
    parse_event_offset,
)
from .models import Channel, TemplateExpression, TemplateExpressionError, User


def iter_template_expression_parts(message: str):
    pos = 0
    while pos < len(message):
        next_open = message.find("{{", pos)
        next_close = message.find("}}", pos)
        if next_close != -1 and (next_open == -1 or next_close < next_open):
            raise TemplateExpressionError("unexpected `}}`")
        if next_open == -1:
            break

        close = message.find("}}", next_open + 2)
        if close == -1:
            raise TemplateExpressionError("missing closing `}}`")
        yield next_open, close + 2, message[next_open + 2:close].strip()
        pos = close + 2


def parse_template_expression(content: str) -> TemplateExpression:
    i = 0
    match = TEMPLATE_VARIABLE_NAME_PATTERN.match(content, i)
    if not match:
        raise TemplateExpressionError("missing variable name")
    variable = match.group(0)
    i = match.end()

    while i < len(content) and content[i].isspace():
        i += 1
    if i == len(content):
        return TemplateExpression(variable, {})
    if content[i] != "(":
        raise TemplateExpressionError("expected `(` after variable name")
    i += 1

    args = {}
    while True:
        while i < len(content) and content[i].isspace():
            i += 1
        if i < len(content) and content[i] == ")":
            i += 1
            break
        if i >= len(content):
            raise TemplateExpressionError("missing closing `)`")

        name_match = TEMPLATE_ARGUMENT_NAME_PATTERN.match(content, i)
        if not name_match:
            raise TemplateExpressionError("missing argument name")
        arg_name = name_match.group(0)
        i = name_match.end()
        canonical_arg_name = TEMPLATE_ARGUMENT_ALIASES.get(arg_name)
        if not canonical_arg_name:
            raise TemplateExpressionError(f"unknown argument `{arg_name}`")
        if canonical_arg_name in args:
            raise TemplateExpressionError(f"duplicate argument `{arg_name}`")

        while i < len(content) and content[i].isspace():
            i += 1
        if i >= len(content) or content[i] != "=":
            raise TemplateExpressionError(f"missing `=` after argument `{arg_name}`")
        i += 1
        while i < len(content) and content[i].isspace():
            i += 1
        if i >= len(content) or content[i] in ",)":
            raise TemplateExpressionError(f"missing value for argument `{arg_name}`")

        if content[i] in ("'", '"'):
            quote = content[i]
            i += 1
            value = []
            while i < len(content):
                if content[i] == "\\" and i + 1 < len(content) and content[i + 1] in (quote, "\\"):
                    value.append(content[i + 1])
                    i += 2
                    continue
                if content[i] == quote:
                    i += 1
                    break
                value.append(content[i])
                i += 1
            else:
                raise TemplateExpressionError(f"unterminated quoted value for argument `{arg_name}`")
            arg_value = "".join(value)
        else:
            start = i
            while i < len(content) and content[i] not in ",)":
                i += 1
            arg_value = content[start:i].strip()

        if not arg_value:
            raise TemplateExpressionError(f"missing value for argument `{arg_name}`")
        args[canonical_arg_name] = arg_value

        while i < len(content) and content[i].isspace():
            i += 1
        if i < len(content) and content[i] == ",":
            i += 1
            j = i
            while j < len(content) and content[j].isspace():
                j += 1
            if j < len(content) and content[j] == ")":
                raise TemplateExpressionError("missing argument after `,`")
            continue
        if i < len(content) and content[i] == ")":
            i += 1
            break
        if i >= len(content):
            raise TemplateExpressionError("missing closing `)`")
        raise TemplateExpressionError("expected `,` or `)` after argument value")

    while i < len(content) and content[i].isspace():
        i += 1
    if i != len(content):
        raise TemplateExpressionError("unexpected text after closing `)`")

    return TemplateExpression(variable, args)


def parse_template_expressions(message: str) -> list[TemplateExpression]:
    return [parse_template_expression(content) for _, _, content in iter_template_expression_parts(message)]


def validate_template_expressions(message: str) -> str:
    try:
        expressions = parse_template_expressions(message)
    except TemplateExpressionError as e:
        return f"malformed template expression: {e}"

    unknown_variables = sorted({expr.variable for expr in expressions if expr.variable not in SUPPORTED_TEMPLATE_VARIABLES})
    if unknown_variables:
        return (
            "unsupported template variable(s) "
            + ", ".join(f"`{{{{{variable}}}}}`" for variable in unknown_variables)
            + ". Supported variables: "
            + ", ".join(f"`{{{{{variable}}}}}`" for variable in sorted(SUPPORTED_TEMPLATE_VARIABLES))
            + "."
        )

    for expr in expressions:
        renders_datetime = expr.variable in TEMPLATE_DATETIME_VARIABLES | DATETIME_TEMPLATE_VARIABLES
        holds_a_list = expr.variable in LIST_TEMPLATE_VARIABLES
        reads_an_event = expr.variable in CALENDAR_EVENT_TEMPLATE_VARIABLES
        for argument in expr.args:
            if argument in ("at", "offset"):
                if not reads_an_event:
                    return (f"template variable `{{{{{expr.variable}}}}}` does not read a calendar "
                            f"event, so it does not take `{argument}`")
            elif argument == "nth":
                if not holds_a_list:
                    return f"template variable `{{{{{expr.variable}}}}}` is not a list, so it does not take `nth`"
            elif holds_a_list:
                return f"template variable `{{{{{expr.variable}}}}}` takes only `nth`, `at` and `offset`"
            elif reads_an_event and not renders_datetime:
                return f"template variable `{{{{{expr.variable}}}}}` takes only `at` and `offset`"
            elif not renders_datetime:
                return f"template variable `{{{{{expr.variable}}}}}` does not support arguments"
        if "nth" in expr.args:
            try:
                position = int(expr.args["nth"])
            except ValueError:
                return f"`nth` must be a whole number, not `{expr.args['nth']}`"
            if position < 1:
                return "`nth` counts from 1, so it must be 1 or more"
        if "at" in expr.args:
            try:
                datetimefmt.validate_at_time(expr.args["at"])
            except ValueError as e:
                return str(e)
        if "offset" in expr.args:
            try:
                parse_event_offset(expr.args["offset"])
            except ValueError as e:
                return str(e)
        if "tz" in expr.args:
            try:
                datetimefmt.validate_timezone_name(expr.args["tz"])
            except ValueError as e:
                return str(e)
        if "lc" in expr.args:
            try:
                datetimefmt.normalize_locale_name(expr.args["lc"])
            except ValueError as e:
                return str(e)

    # Uncapped here: the count is what the user is told about, and the cap in the collector is
    # only a backstop for a config that was edited by hand.
    selectors = find_calendar_selectors(message, limit=None)
    if len(selectors) > MAX_CALENDAR_SELECTORS:
        return (f"a message may read the calendar at up to {MAX_CALENDAR_SELECTORS} different "
                f"moments; this one names {len(selectors)}")

    return ""


def find_template_expressions(message: str) -> list[TemplateExpression]:
    """Every parsed expression in `message`, or none when it does not parse.

    The counterpart of `find_template_variables`, which throws the arguments away.
    """
    try:
        return parse_template_expressions(message)
    except TemplateExpressionError:
        return []


def config_templates(config: dict | None) -> tuple[str, ...]:
    """Every template string a run of this config renders.

    One definition, so the variable collector, the selector collector and the `test` preview
    can never disagree about which fields are templates.
    """
    config = config or {}
    return ((config.get('reply_message') or ''),
            (config.get('opsgenie_message') or ''),
            (config.get('action_target') or ''))


def find_calendar_selectors(*messages: str, limit: int | None = MAX_CALENDAR_SELECTORS) -> list[tuple[str, str]]:
    """The distinct `(at, offset)` pairs the calendar variables in these templates ask for.

    First-seen order, deduped on the normalised pair, so a message reading the same moment
    five times costs one calendar selection. Capped, because each pair costs a selection and a
    template naming dozens is a mistake — validation reports that; here it is a backstop for a
    hand-edited config.
    """
    selectors: list[tuple[str, str]] = []
    seen = set()
    for message in messages:
        for expr in find_template_expressions(message):
            if expr.variable not in CALENDAR_EVENT_TEMPLATE_VARIABLES:
                continue
            at, offset = expr.args.get("at", ""), expr.args.get("offset", "")
            if not at and not offset:
                continue
            try:
                key = normalize_selector(at, offset)
            except ValueError:
                continue
            if key in seen:
                continue
            seen.add(key)
            selectors.append((at, offset))
    return selectors if limit is None else selectors[:limit]


def config_calendar_selectors(config: dict | None) -> list[tuple[str, str]]:
    """Every moment a run of this config reads the calendar at: templates and conditions.

    The one definition of that union, because everything that resolves a namespace has to
    agree on it — the gate, the message, the alert, the action target and the `test` preview.
    A preview that scanned fewer fields than the firing would report the opposite verdict.

    The cap is applied once, here, to the complete union rather than per field: each field is
    validated on its own, so eight moments in the message and a ninth in the target both pass
    validation and only the union is too long. Truncating is a last resort and says so in the
    log; the dropped slices render placeholders.
    """
    selectors = find_calendar_selectors(*config_templates(config), limit=None)
    seen = {normalize_selector(at, offset) for at, offset in selectors}
    for at, offset in conditionutil.condition_calendar_selectors(config):
        key = normalize_selector(at, offset)
        if key not in seen:
            seen.add(key)
            selectors.append((at, offset))
    if len(selectors) > MAX_CALENDAR_SELECTORS:
        dropped = ", ".join(f"at={at!r} offset={offset!r}"
                            for at, offset in selectors[MAX_CALENDAR_SELECTORS:])
        log_warning(f"A configuration reads the calendar at {len(selectors)} different moments; "
                    f"only {MAX_CALENDAR_SELECTORS} are resolved. Not read: {dropped}")
    return selectors[:MAX_CALENDAR_SELECTORS]

def find_unknown_template_variables(message: str) -> list[str]:
    try:
        variables = {expr.variable for expr in parse_template_expressions(message)}
    except TemplateExpressionError:
        return []
    return sorted(variable for variable in variables if variable not in SUPPORTED_TEMPLATE_VARIABLES)


def find_template_variables(message: str) -> set[str]:
    try:
        return {expr.variable for expr in parse_template_expressions(message)}
    except TemplateExpressionError:
        return set()


def _nth_list_item(variables: dict[str, str], stem: str, expr: TemplateExpression) -> str:
    """One entry of a list variable, counting from 1.

    Asking for an entry the list does not have renders empty rather than failing, so a
    message written for two attendees still reads when there is only one.
    """
    try:
        position = int(expr.args.get("nth", ""))
    except ValueError:
        return ""
    items = conditionutil.list_items(variables, stem)
    return items[position - 1] if 1 <= position <= len(items) else ""


def _expression_stem(expr: TemplateExpression) -> tuple[str, str]:
    """`(stem, value_key)` for one expression: the plain variable, or its selector slice.

    A slice's name is a pure function of the expression's own text, which is what lets this
    stay synchronous — nothing here resolves a clock, a feed or a Slack lookup.
    """
    at, offset = expr.args.get("at", ""), expr.args.get("offset", "")
    if (at or offset) and expr.variable in CALENDAR_EVENT_TEMPLATE_VARIABLES:
        try:
            stem = event_slice_name(expr.variable, at, offset)
        except ValueError:
            # Not the base variable: that value describes *now*, and this expression asked
            # about something else. A key nothing writes renders the placeholder instead.
            stem = invalid_slice_name(expr.variable)
        return stem, f"__{stem}"
    return expr.variable, expr.variable


def render_reply_message_template(message: str, variables: dict[str, str], config: dict | None = None) -> str:
    try:
        spans = list(iter_template_expression_parts(message))
    except TemplateExpressionError:
        return message

    rendered = []
    last_index = 0
    for start, end, content in spans:
        rendered.append(message[last_index:start])
        try:
            expr = parse_template_expression(content)
        except TemplateExpressionError:
            rendered.append(message[start:end])
            last_index = end
            continue

        stem, value_key = _expression_stem(expr)
        if expr.variable in DATETIME_TEMPLATE_VARIABLES:
            rendered.append(datetimefmt.format_timestamp_value(variables.get("__timestamp_raw", ""), expr.variable, config, expr.args))
        elif expr.variable in TEMPLATE_DATETIME_VARIABLES:
            raw_value = variables.get(f"__{stem}_raw", "")
            if raw_value or expr.args:
                rendered.append(datetimefmt.format_template_datetime(raw_value, expr.variable, config, expr.args))
            else:
                rendered.append(variables.get(value_key, UNKNOWN_PERIOD_PLACEHOLDER))
        elif expr.variable in LIST_TEMPLATE_VARIABLES and "nth" in expr.args:
            rendered.append(_nth_list_item(variables, stem, expr))
        elif value_key in variables:
            rendered.append(variables[value_key])
        elif stem != expr.variable:
            # A selector slice nothing resolved: render this variable's usual placeholder.
            # Never the default selection's value, which would answer about the wrong moment,
            # and never the raw `{{…}}`, which would put braces in a user-visible message.
            rendered.append(calendarfeed.calendar_event_placeholder(expr.variable))
        else:
            rendered.append(message[start:end])
        last_index = end

    rendered.append(message[last_index:])
    return "".join(rendered)


async def build_reply_template_variables(app: AsyncApp, opsgenie_token: str, channel: Channel, config: dict, config_name: str, user: User, text: str, ts: str, permalink: str, include_opsgenie: bool = False, include_calendar: bool = False, calendar_selectors: list[tuple[str, str]] | None = None) -> dict[str, str]:
    wait_time = config.get('wait_time') or 0
    opsgenie_template_variables = {}
    if include_opsgenie:
        opsgenie_template_variables = await opsgenie.get_opsgenie_template_variables(app, opsgenie_token, config)
    # Both providers cost a network round-trip, so they are only resolved when something
    # actually references one of their variables (see `actions._build_variables`).
    calendar_template_variables = {}
    if include_calendar:
        calendar_template_variables = await calendarfeed.get_calendar_template_variables(
            app, config, selectors=calendar_selectors or ())

    # `test`, `run`, and schedule/manual triggers have no message behind them, so
    # there is no Slack timestamp to report. Stand in the current time instead of
    # rendering the time variables empty.
    ts = ts or f"{datetime.datetime.now(datetime.timezone.utc).timestamp():.6f}"

    return {
        "date": datetimefmt.format_timestamp_value(ts, "date", config),
        "time": datetimefmt.format_timestamp_value(ts, "time", config),
        "datetime": datetimefmt.format_timestamp_value(ts, "datetime", config),
        # The raw timestamp, so `{{date(tz=...)}}` and friends can re-render it.
        "__timestamp_raw": ts,
        "channel": f"#{channel.name}",
        "channel_name": channel.name,
        "config": config_name,
        "message": text,
        "message_link": permalink,
        **opsgenie_template_variables,
        **calendar_template_variables,
        "team": user.team if user.team else TEAM_UNKNOWN,
        "timestamp": ts,
        "user": f"<@{user.id}>",
        "user_name": user.real_name if user.real_name else user.name,
        "wait_minutes": str(wait_time // 60),
    }
