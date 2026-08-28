"""Parsing and rendering of ``{{variable}}`` reply-message templates."""

import datetime

from slack_bolt.async_app import AsyncApp

from . import calendarfeed
from . import conditionutil
from . import datetimefmt
from . import opsgenie
from .constants import (
    CALENDAR_EVENT_TEMPLATE_VARIABLES,
    DATETIME_TEMPLATE_VARIABLES,
    LIST_TEMPLATE_VARIABLES,
    NO_PARENT_PLACEHOLDER,
    NO_PRESS_PLACEHOLDER,
    PARENT_DATETIME_TEMPLATE_VARIABLES,
    PARENT_LIST_TEMPLATE_VARIABLES,
    PARENT_VARIABLE_NAMES_KEY,
    PARENT_VARIABLES_TEMPLATE_VARIABLE,
    PRESS_DATETIME_TEMPLATE_VARIABLES,
    SUPPORTED_TEMPLATE_VARIABLES,
    TEAM_UNKNOWN,
    TEMPLATE_ARGUMENT_ALIASES,
    TEMPLATE_ARGUMENT_NAME_PATTERN,
    TEMPLATE_DATETIME_VARIABLES,
    TEMPLATE_VARIABLE_NAME_PATTERN,
    UNKNOWN_PERIOD_PLACEHOLDER,
    clock_slice_name,
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
        names_the_parents_variables = expr.variable == PARENT_VARIABLES_TEMPLATE_VARIABLE
        reads_an_event = expr.variable in CALENDAR_EVENT_TEMPLATE_VARIABLES
        renders_the_clock = expr.variable in DATETIME_TEMPLATE_VARIABLES
        for argument in expr.args:
            if argument == "at":
                # On a clock variable `at` moves the instant that is rendered; on a calendar
                # variable it picks which event is read. Nothing else holds a moment to move.
                if not (reads_an_event or renders_the_clock):
                    return (f"template variable `{{{{{expr.variable}}}}}` does not read a calendar "
                            f"event, so it does not take `at`")
            elif argument == "offset":
                # Counting events only means something where there are events to count.
                if not reads_an_event:
                    return (f"template variable `{{{{{expr.variable}}}}}` does not read a calendar "
                            f"event, so it does not take `offset`")
            elif argument == "nth":
                if not holds_a_list:
                    return f"template variable `{{{{{expr.variable}}}}}` is not a list, so it does not take `nth`"
            elif argument == "of":
                if not names_the_parents_variables:
                    return (f"template variable `{{{{{expr.variable}}}}}` does not hold the parent's "
                            f"variables, so it does not take `of`")
            elif holds_a_list:
                return (f"template variable `{{{{{expr.variable}}}}}` takes only "
                        + ("`nth` and `of`" if names_the_parents_variables
                           else "`nth`" if expr.variable in PARENT_LIST_TEMPLATE_VARIABLES
                           else "`nth`, `at` and `offset`"))
            elif reads_an_event and not renders_datetime:
                return f"template variable `{{{{{expr.variable}}}}}` takes only `at` and `offset`"
            elif not renders_datetime:
                return f"template variable `{{{{{expr.variable}}}}}` does not support arguments"
        if "nth" in expr.args and "of" in expr.args:
            # Both resolve to one entry, and the renderer answers `of` first — so accepting the
            # pair would quietly ignore whichever the writer meant second.
            return (f"template variable `{{{{{expr.variable}}}}}` takes `nth` or `of`, not both: "
                    f"`nth` counts to one of the parent's variables, `of` names it")
        if "nth" in expr.args:
            try:
                position = int(expr.args["nth"])
            except ValueError:
                return f"`nth` must be a whole number, not `{expr.args['nth']}`"
            if position < 1:
                return "`nth` counts from 1, so it must be 1 or more"
        if "of" in expr.args and expr.args["of"] not in SUPPORTED_TEMPLATE_VARIABLES:
            return (f"`of` names a template variable, and `{{{{{expr.args['of']}}}}}` is not one. "
                    f"It is the variable the parent's message used, such as "
                    f"`{{{{{PARENT_VARIABLES_TEMPLATE_VARIABLE}(of=\"user\")}}}}`.")
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

    return ""


def find_template_expressions(message: str) -> list[TemplateExpression]:
    """Every parsed expression in `message`, or none when it does not parse.

    The counterpart of `find_template_variables`, which throws the arguments away.
    """
    try:
        return parse_template_expressions(message)
    except TemplateExpressionError:
        return []


def config_templates(config: dict | None, include_alert: bool = True) -> tuple[str, ...]:
    """Every template string a run of this config renders.

    One definition, so the variable collector, the selector collector and the `test` preview
    can never disagree about which fields are templates.

    `include_alert=False` leaves out the OpsGenie alert text, for a run that cannot send one —
    see `actions._referenced_variables`. The slot stays, because an empty template references
    nothing and callers read the whole tuple.
    """
    config = config or {}
    return ((config.get('reply_message') or ''),
            (config.get('opsgenie_message') or '') if include_alert else '',
            (config.get('action_target') or ''))


def find_calendar_selectors(*messages: str) -> list[tuple[str, str]]:
    """The distinct `(at, offset)` pairs the calendar variables in these templates ask for.

    First-seen order, deduped on the normalised pair, so a message reading the same moment
    five times costs one calendar selection. Deliberately unbounded: the feed is fetched and
    expanded once per run regardless, and each additional moment is one more query over that
    index — cheap enough that a limit would only get in the way of a legitimate template.
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
    return selectors


def config_calendar_selectors(config: dict | None, include_alert: bool = True) -> list[tuple[str, str]]:
    """Every moment a run of this config reads the calendar at: templates and conditions.

    The one definition of that union, because everything that resolves a namespace has to
    agree on it — the gate, the message, the alert, the action target and the `test` preview.
    A preview that scanned fewer fields than the firing would report the opposite verdict.
    """
    selectors = find_calendar_selectors(*config_templates(config, include_alert))
    seen = {normalize_selector(at, offset) for at, offset in selectors}
    for at, offset in conditionutil.condition_calendar_selectors(config):
        key = normalize_selector(at, offset)
        if key not in seen:
            seen.add(key)
            selectors.append((at, offset))
    return selectors


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


def _named_list_item(variables: dict[str, str], expr: TemplateExpression) -> str:
    """The parent's value for one *named* variable, rather than for a position.

    `nth` shifts the moment somebody edits the parent's message, so naming the variable is the
    stable way to ask for one. A name the parent's message never used renders empty, like an
    out-of-range `nth`: a template written for a richer parent still reads.

    Read straight from the internal names key rather than through `conditionutil.list_items`,
    whose fallback splits a public joined form — and there is no public variable that renders
    the names.
    """
    names = list(variables.get(PARENT_VARIABLE_NAMES_KEY) or ())
    try:
        position = names.index(expr.args.get("of", ""))
    except ValueError:
        # Not a variable the parent used. Its own values are the only thing this can answer.
        return ""
    items = conditionutil.list_items(variables, expr.variable)
    return items[position] if position < len(items) else ""


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


def render_template_expression(expr: TemplateExpression, variables: dict[str, str], config: dict | None = None) -> str | None:
    """What one expression renders, or `None` when nothing in the namespace resolved it.

    `None` rather than the raw `{{…}}` because only a caller holding the original span knows
    what the literal looked like — and a caller collecting *values* has no use for a literal at
    all. Its own function so a collector cannot judge an expression differently from the way the
    message it appears in renders it.
    """
    stem, value_key = _expression_stem(expr)
    if expr.variable in DATETIME_TEMPLATE_VARIABLES:
        return datetimefmt.format_timestamp_value(variables.get("__timestamp_raw", ""), expr.variable, config, expr.args)
    if expr.variable in TEMPLATE_DATETIME_VARIABLES:
        raw_value = variables.get(f"__{stem}_raw", "")
        if raw_value or expr.args:
            return datetimefmt.format_template_datetime(raw_value, expr.variable, config, expr.args)
        return variables.get(value_key, UNKNOWN_PERIOD_PLACEHOLDER)
    if expr.variable == PARENT_VARIABLES_TEMPLATE_VARIABLE and "of" in expr.args:
        return _named_list_item(variables, expr)
    if expr.variable in LIST_TEMPLATE_VARIABLES and "nth" in expr.args:
        return _nth_list_item(variables, stem, expr)
    if value_key in variables:
        return variables[value_key]
    if stem != expr.variable:
        # A selector slice nothing resolved: render this variable's usual placeholder.
        # Never the default selection's value, which would answer about the wrong moment,
        # and never the raw `{{…}}`, which would put braces in a user-visible message.
        return calendarfeed.calendar_event_placeholder(expr.variable)
    return None


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

        value = render_template_expression(expr, variables, config)
        rendered.append(value if value is not None else message[start:end])
        last_index = end

    rendered.append(message[last_index:])
    return "".join(rendered)


def rendered_template_values(message: str, variables: dict[str, str], config: dict | None = None) -> tuple[list[str], list[str]]:
    """Every `{{…}}` of a template rendered on its own: `(names, values)`, in reading order.

    One entry per expression the reader sees, so `nth=1` is literally the first variable in the
    message. An unparseable or unresolved expression keeps its slot and contributes its literal,
    because a shifted index is worse than a visibly wrong entry. A template whose braces do not
    balance renders unchanged, so it contributes nothing here either.
    """
    try:
        spans = list(iter_template_expression_parts(message))
    except TemplateExpressionError:
        return [], []

    names, values = [], []
    for start, end, content in spans:
        try:
            expr = parse_template_expression(content)
        except TemplateExpressionError:
            names.append("")
            values.append(message[start:end])
            continue
        value = render_template_expression(expr, variables, config)
        names.append(expr.variable)
        values.append(value if value is not None else message[start:end])
    return names, values


def parent_template_variables(parent: dict | None, config: dict | None = None) -> dict[str, str]:
    """The `{{parent_*}}` slice: what the run that triggered this one did.

    Always present, even when nothing triggered this run, for two reasons. A template reading
    one then renders a visible `<no-parent>` instead of a literal `{{…}}`, and a condition on one
    can be judged at all — `conditionutil._judge` fails closed on a variable the namespace does
    not carry, which is a confusing way to say "no parent".

    Synchronous and network-free: `parent` is already plain strings, rebuilt from the pending
    button record by `buttons._parent_facts`. `config` is the *consuming* config, because its
    date/time settings are what print these — the rule every other date/time variable follows.
    """
    parent = parent or {}
    config_name = parent.get('config_name') or ''

    def present(value: str) -> str:
        """A parent that simply has nothing here renders empty; no parent at all says so."""
        return value or ('' if config_name else NO_PARENT_PLACEHOLDER)

    # The posted message's Slack ts *is* when the parent ran. Converted once to an ISO instant
    # because `TEMPLATE_DATETIME_VARIABLES` re-render from ISO, not from a Slack epoch.
    instant = datetimefmt.parse_slack_timestamp(parent.get('timestamp') or '')
    raw = instant.isoformat() if instant else ''

    variables = {
        "parent_config": config_name or NO_PARENT_PLACEHOLDER,
        "parent_message": present(parent.get('message') or ''),
        "parent_timestamp": parent.get('timestamp') or '',
        "parent_action": present(parent.get('action') or ''),
        "parent_target": present(parent.get('target') or ''),
    }
    for variable in PARENT_DATETIME_TEMPLATE_VARIABLES:
        variables[f"__{variable}_raw"] = raw
        variables[variable] = (datetimefmt.format_template_datetime(raw, variable, config)
                               if raw else UNKNOWN_PERIOD_PLACEHOLDER)
    names, values = list(parent.get('variable_names') or ()), list(parent.get('variables') or ())
    variables[PARENT_VARIABLE_NAMES_KEY] = names
    conditionutil.set_list_variable(variables, PARENT_VARIABLES_TEMPLATE_VARIABLE,
                                    f"__{PARENT_VARIABLES_TEMPLATE_VARIABLE}_items", values)
    conditionutil.set_list_variable(variables, "parent_recipients", "__parent_recipients_items",
                                    list(parent.get('recipients') or ()))
    for variable in PARENT_LIST_TEMPLATE_VARIABLES:
        variables[variable] = present(variables[variable])
    return variables


def press_template_variables(press: dict | None = None, config: dict | None = None) -> dict[str, str]:
    """The `{{press_*}}` slice: which button ran this, who pressed it, and when.

    Always present, for the same two reasons as `parent_template_variables`: a template reading
    one renders a visible `<no-press>` rather than a literal `{{…}}`, and a condition on one can
    be judged instead of failing closed.

    A timeout auto-press has a button and a time but nobody behind it, so its `press_user`/
    `press_user_name` render empty while `press_kind` says `timeout` — which is what lets an ack
    text distinguish "nobody answered in time" from "somebody dismissed this". No press at all
    renders `<no-press>` throughout.

    Synchronous and network-free: `press` is already plain strings, built by `buttons._press_facts`
    where the pressing user is in hand. `config` is the *consuming* config, whose date/time
    settings print the three date/time forms, like every other date/time variable.
    """
    press = press or {}
    kind = press.get('kind') or ''

    def present(value: str) -> str:
        """A press that simply has nothing here renders empty; no press at all says so."""
        return value or ('' if kind else NO_PRESS_PLACEHOLDER)

    # A press is not a Slack message, so its time is stamped as a Slack-style epoch when it
    # happens — that way `{{press_timestamp}}` reads like `{{timestamp}}` and the date/time
    # forms re-render from ISO the way `TEMPLATE_DATETIME_VARIABLES` expects.
    instant = datetimefmt.parse_slack_timestamp(press.get('timestamp') or '')
    raw = instant.isoformat() if instant else ''

    variables = {
        "press_kind": kind or NO_PRESS_PLACEHOLDER,
        "press_label": present(press.get('label') or ''),
        "press_timestamp": press.get('timestamp') or '',
        "press_user": present(press.get('user') or ''),
        "press_user_name": present(press.get('user_name') or ''),
    }
    for variable in PRESS_DATETIME_TEMPLATE_VARIABLES:
        variables[f"__{variable}_raw"] = raw
        variables[variable] = (datetimefmt.format_template_datetime(raw, variable, config)
                               if raw else UNKNOWN_PERIOD_PLACEHOLDER)
    return variables


def clock_slice_variables(config: dict | None, ts: str) -> dict[str, str]:
    """The `clock(at=...)_<variable>` slices this config's conditions are judged against.

    A template needs none of these — `render_template_expression` moves the instant itself —
    but a condition reads the namespace, and only the namespace build knows the config whose
    date/time format the value has to be written in. Resolving them here is what keeps
    `{{date(at="+2w")}}` in a message and the condition gating it on one value.
    """
    values = {}
    for variable, at in conditionutil.condition_clock_moments(config):
        values[f"__{clock_slice_name(variable, at)}"] = datetimefmt.format_timestamp_value(
            ts, variable, config, {"at": at})
    return values


async def build_reply_template_variables(app: AsyncApp, opsgenie_token: str, channel: Channel, config: dict, config_name: str, user: User, text: str, ts: str, permalink: str, include_opsgenie: bool = False, include_calendar: bool = False, calendar_selectors: list[tuple[str, str]] | None = None, parent: dict | None = None, press: dict | None = None) -> dict[str, str]:
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
        **clock_slice_variables(config, ts),
        "channel": f"#{channel.name}",
        "channel_name": channel.name,
        "config": config_name,
        "message": text,
        "message_link": permalink,
        **opsgenie_template_variables,
        **calendar_template_variables,
        **parent_template_variables(parent, config),
        **press_template_variables(press, config),
        "team": user.team if user.team else TEAM_UNKNOWN,
        "timestamp": ts,
        "user": f"<@{user.id}>",
        "user_name": user.real_name if user.real_name else user.name,
        "wait_minutes": str(wait_time // 60),
    }
