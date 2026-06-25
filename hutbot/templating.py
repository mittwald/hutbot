"""Parsing and rendering of ``{{variable}}`` reply-message templates."""

from slack_bolt.async_app import AsyncApp

from . import datetimefmt
from . import opsgenie
from .constants import (
    OPSGENIE_DATETIME_TEMPLATE_VARIABLES,
    SUPPORTED_TEMPLATE_VARIABLES,
    TEAM_UNKNOWN,
    TEMPLATE_ARGUMENT_ALIASES,
    TEMPLATE_ARGUMENT_NAME_PATTERN,
    TEMPLATE_VARIABLE_NAME_PATTERN,
    UNKNOWN_ONCALL_PERIOD_PLACEHOLDER,
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
        if expr.args and expr.variable not in OPSGENIE_DATETIME_TEMPLATE_VARIABLES:
            return f"template variable `{{{{{expr.variable}}}}}` does not support arguments"
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

        if expr.variable in OPSGENIE_DATETIME_TEMPLATE_VARIABLES:
            raw_value = variables.get(f"__{expr.variable}_raw", "")
            if raw_value or expr.args:
                rendered.append(datetimefmt.format_opsgenie_template_datetime(raw_value, expr.variable, config, expr.args))
            else:
                rendered.append(variables.get(expr.variable, UNKNOWN_ONCALL_PERIOD_PLACEHOLDER))
        else:
            rendered.append(variables.get(expr.variable, message[start:end]))
        last_index = end

    rendered.append(message[last_index:])
    return "".join(rendered)


async def build_reply_template_variables(app: AsyncApp, opsgenie_token: str, channel: Channel, config: dict, config_name: str, user: User, text: str, ts: str, permalink: str, include_opsgenie: bool = False) -> dict[str, str]:
    wait_time = config.get('wait_time')
    opsgenie_template_variables = {}
    if include_opsgenie:
        opsgenie_template_variables = await opsgenie.get_opsgenie_template_variables(app, opsgenie_token, config)

    return {
        "channel": f"#{channel.name}",
        "channel_name": channel.name,
        "config": config_name,
        "message": text,
        "message_link": permalink,
        **opsgenie_template_variables,
        "team": user.team if user.team else TEAM_UNKNOWN,
        "timestamp": ts,
        "user": f"<@{user.id}>",
        "user_name": user.real_name if user.real_name else user.name,
        "wait_minutes": str(wait_time // 60),
    }
