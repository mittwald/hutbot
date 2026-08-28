"""The `test` command: render one configuration and report everything it resolved.

A preview is a diagnostic, not a dry run, so it resolves the widest set: every template the
config carries (message, alert, target, button texts), every condition, and the calendar at
every moment any of them names — plus `offset=next` and `offset=prev`, which is what somebody
debugging a rota rule reaches for first. A real run resolves less, because it skips what it
cannot use.

The report is ordered the way a rule is read: what it says, where that goes and when, whether
it would run at all, which variables its own text used, which events the calendar answered
with, and finally the whole namespace.
"""

import copy
import datetime
import re

from slack_bolt.async_app import AsyncApp

from .. import actions
from .. import buttons
from .. import calendarfeed
from .. import conditionutil
from .. import datetimefmt
from .. import messaging
from .. import opsgenie
from .. import routing
from .. import slackcache
from .. import state
from .. import targets
from .. import templating
from ..buttonutil import normalize_button
from ..constants import (
    ACTION_DM_USER,
    ACTION_GROUP_DM,
    ACTION_POST_CHANNEL,
    ACTION_REPLY,
    BUTTON_ACTION_ACK,
    BUTTON_ACTION_CONFIG,
    BUTTON_ACTION_DELAY,
    CALENDAR_EVENT_TEMPLATE_VARIABLES,
    CALENDAR_SELECTIONS_KEY,
    CONDITION_MODE_ALL,
    DEFAULT_CONFIG,
    DISABLED_REASON_REMOVED,
    ESCALATION_BUTTON,
    ESCALATION_CONFIG,
    ESCALATION_NONE,
    GROUP_DM_MEMBER_LIMIT,
    SUPPORTED_TEMPLATE_VARIABLES,
    TRIGGER_CRON,
    TRIGGER_MANUAL,
    TRIGGER_MESSAGE,
    normalize_selector,
)
from ..models import TemplateExpression
from ..textutil import escape_newlines

try:
    from croniter import croniter
except ImportError:  # pragma: no cover - dependency optional at runtime
    croniter = None

# The two moments a preview always reads, on top of the ones the config names itself: the
# neighbouring events are what tells a rota rule that resolved to nothing apart from one that
# resolved to the wrong entry.
_EXTRA_SELECTORS = (("", "next"), ("", "prev"))
# Arguments whose value is a number or a keyword, so quoting it would only add noise. Every
# other argument is quoted, the way `describe_condition` prints an `at`.
_BARE_ARGUMENTS = {"nth", "offset"}
# A variable the namespace does not carry at all — only a hand-edited config can reference
# one, and rendering it as an empty value would hide that.
_UNKNOWN_VARIABLE = "<unknown-variable>"
# What a variable that renders to nothing prints as. A bare colon at the end of a line reads
# like the report ran out, and "renders empty" is a real answer — an `nth` past the end of a
# list, a `test` with no message behind it.
_EMPTY_VALUE = "_(empty)_"


# ----- expressions and their values -----


def _expression_literal(expr: TemplateExpression) -> str:
    """`{{calendar_summary(offset=next)}}` — one expression as it would be written."""
    parts = []
    for name, value in expr.args.items():
        if name in _BARE_ARGUMENTS:
            parts.append(f"{name}={value}")
        else:
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            parts.append(f'{name}="{escaped}"')
    arguments = ", ".join(parts)
    return f"{{{{{expr.variable}({arguments})}}}}" if arguments else f"{{{{{expr.variable}}}}}"


def _expression_line(expr: TemplateExpression, variables: dict, config: dict) -> str:
    """One `` `{{expression}}`: value `` line, rendered exactly as the message renders it.

    Through `render_template_expression`, so a preview can never disagree with what the rule
    would actually post — the arguments, the placeholders and the date/time formatting are the
    renderer's, not a second implementation of them.
    """
    value = templating.render_template_expression(expr, variables, config)
    if value is None:
        rendered = _UNKNOWN_VARIABLE
    else:
        rendered = escape_newlines(str(value)) or _EMPTY_VALUE
    return f"`{_expression_literal(expr)}`: {rendered}"


def _distinct_expressions(template: str) -> list[TemplateExpression]:
    """The expressions of one template, first-seen order, one entry per distinct spelling."""
    seen, distinct = set(), []
    for expr in templating.find_template_expressions(template or ''):
        key = _expression_literal(expr)
        if key in seen:
            continue
        seen.add(key)
        distinct.append(expr)
    return distinct


def _condition_expressions(config: dict) -> list[TemplateExpression]:
    """The variable each condition reads, as the expression that reads it."""
    expressions = []
    for condition in (config.get('conditions') or []):
        variable, operator, _, _, at, offset = conditionutil.normalize_condition(condition)
        if not (variable and operator):
            continue
        args = {name: value for name, value in (("at", at), ("offset", offset)) if value}
        expressions.append(TemplateExpression(variable, args))
    return expressions


def _button_templates(config: dict) -> list[tuple[str, str]]:
    """`(label, template)` for every button text this config renders — the `ack` texts."""
    templates = []
    for button in (config.get('buttons') or []):
        action, value = normalize_button(button)
        if action == BUTTON_ACTION_ACK and value:
            templates.append((str(button.get('label') or ''), value))
    return templates


def _button_summary(channel, button: dict) -> str:
    """One button as what pressing it does, rather than as its stored `action:value` pair."""
    action, value = normalize_button(button)
    label = str(button.get('label') or '')
    if action == BUTTON_ACTION_CONFIG:
        return f"`{label}` runs `{value}`{_missing_config_note(channel, value)}"
    if action == BUTTON_ACTION_DELAY:
        return f"`{label}` delays the escalation by {value} minutes"
    return f"`{label}` acknowledges" + (" and posts its text" if value else "")


def _preview_selectors(config: dict) -> list[tuple[str, str]]:
    """Every `(at, offset)` the preview reads the calendar at, deduped on the normalised pair.

    Wider than a run's: it adds the button texts, which a run only resolves once somebody
    presses, and the two neighbouring events. One selection each, so the extra moments cost
    queries over the one index, not another fetch.
    """
    candidates = list(templating.config_calendar_selectors(config))
    candidates += templating.find_calendar_selectors(*(template for _, template in _button_templates(config)))
    candidates += _EXTRA_SELECTORS
    seen, selectors = set(), []
    for at, offset in candidates:
        try:
            key = normalize_selector(at, offset)
        except ValueError:
            continue
        if key in seen:
            continue
        seen.add(key)
        selectors.append((at, offset))
    return selectors


# ----- the sections -----


def _message_section(config: dict, config_name: str, variables: dict) -> str:
    action = config.get('action', ACTION_REPLY)
    label = "Reply preview" if action == ACTION_REPLY else "Message preview"
    rendered = templating.render_reply_message_template(config.get('reply_message') or '', variables, config)
    return f"*{label} for configuration `{config_name}`:*\n{rendered}"


def _user_label(user) -> str:
    return f"<@{user.id}>" if user.id else f"`{user.name}`"


async def _destination_line(app: AsyncApp, channel, config: dict, target: str) -> str:
    """Where this run would actually land, with the target resolved to real people.

    Resolved rather than echoed, because a target is usually a variable by the time a rota
    rule is interesting: `show config` can only print `{{calendar_other_attendee_users(nth=1)}}`,
    and the whole question a preview answers is who that turned out to be.
    """
    action = config.get('action', ACTION_REPLY)
    trigger = config.get('trigger', TRIGGER_MESSAGE)
    if action == ACTION_REPLY:
        # A reply threads on the triggering message; schedule/manual runs have no message to
        # thread on and land in the channel itself.
        thread = " (in thread)" if trigger == TRIGGER_MESSAGE else ""
        return f"*Replied in* <#{channel.id}>{thread}"
    if action == ACTION_POST_CHANNEL:
        channel_id = targets.parse_channel_ref(target)
        if not channel_id:
            return f"*Posted in* nowhere: `{target or '<none>'}` is not a channel"
        return f"*Posted in* <#{channel_id}>"
    if action == ACTION_DM_USER:
        users = await targets.resolve_user_targets(app, target)
        if not users:
            return f"*Sent to* nobody: `{target or '<none>'}` names no Slack user"
        line = f"*Sent to* {_user_label(users[0])} (direct message)"
        if len(users) > 1:
            # What `action_dm_user` does with a multi-person target, said before it happens.
            line += (f" — `{target}` names {len(users)} people, and `dm-user` reaches the first;"
                     f" `group-dm` reaches all of them")
        return line
    if action == ACTION_GROUP_DM:
        # Both branches end at the same trim in `actions.action_group_dm`, so both are trimmed
        # here: the preview has to name the people the conversation will actually be opened
        # with, not the ones the target resolved to.
        if targets.names_people(target):
            users = await targets.resolve_user_targets(app, target)
            if not users:
                return f"*Sent to* nobody: `{target or '<none>'}` names no Slack user"
            members = [_user_label(user) for user in users]
        else:
            usergroup = await targets.resolve_usergroup_target(app, target)
            if not usergroup or not usergroup.id:
                return f"*Sent to* nobody: `{target or '<none>'}` names no user group"
            member_ids = await slackcache.get_usergroup_members(app, usergroup.id)
            if not member_ids:
                return f"*Sent to* nobody: the user group `{target}` has no members"
            members = [f"<@{member}>" for member in member_ids]
        dropped = len(members) - GROUP_DM_MEMBER_LIMIT
        return (f"*Sent to* {', '.join(members[:GROUP_DM_MEMBER_LIMIT])} (group message)"
                + (f" — {', '.join(members[GROUP_DM_MEMBER_LIMIT:])} "
                   f"{'is' if dropped == 1 else 'are'} left out by Slack's "
                   f"{GROUP_DM_MEMBER_LIMIT}-member limit" if dropped > 0 else ""))
    return f"*Action* `{action}`, target `{target or '<none>'}`"


def _next_cron_run(config: dict) -> str:
    """When the cron expression fires next, in the timezone it fires in."""
    expression = config.get('cron') or ''
    if not expression or croniter is None or not croniter.is_valid(expression):
        return ""
    timezone = datetimefmt.get_config_timezone(config)
    try:
        instant = croniter(expression, datetime.datetime.now(timezone)).get_next(datetime.datetime)
    except (ValueError, KeyError):
        return ""
    return datetimefmt.render_datetime(instant, "datetime", config)


def _trigger_line(config: dict, channel) -> str:
    trigger = config.get('trigger', TRIGGER_MESSAGE)
    if trigger == TRIGGER_CRON:
        expression = config.get('cron') or '<none>'
        line = f"*Trigger*: `cron` `{expression}`"
        next_run = _next_cron_run(config)
        timezone_name = config.get('datetime_timezone') or datetimefmt.get_local_timezone_name()
        return f"{line}, next run {next_run} ({timezone_name})" if next_run else f"{line} (never fires)"
    if trigger == TRIGGER_MANUAL:
        # Not "only `run`": a `config` button and a `config` escalation reach it too — see
        # `buttons.dispatch_button_action` and `buttons._run_escalation` — and that is the
        # whole point of a manual rule.
        return (f"*Trigger*: `manual`, so nothing fires it on its own — "
                f"`{state.slash_command} [config] run`, a `config` button or an escalation runs it")
    pattern = config.get('pattern')
    matching = (f" matching `{pattern}` "
                f"({'case-sensitive' if config.get('pattern_case_sensitive') else 'case-insensitive'})"
                if pattern else "")
    return (f"*Trigger*: `message` in <#{channel.id}>{matching}, "
            f"{(config.get('wait_time') or 0) // 60} minutes after it arrives")


def _invocation_paths(channel, config_name: str) -> list[str]:
    """Every button and escalation in this channel that runs the previewed config.

    A config is not only reached by its own trigger: `buttons.dispatch_button_action` runs a
    `config` button's target, and `buttons._run_escalation` runs an escalation's. Naming them
    is what keeps a `manual` rule from reading like a rule nothing can start.
    """
    paths = []
    for name, other in sorted(channel.configs.items()):
        for button in other.get('buttons') or []:
            action, value = normalize_button(button)
            if action == BUTTON_ACTION_CONFIG and value == config_name:
                paths.append(f"the button `{button.get('label')}` of `{name}`")
        kind, target = buttons._escalation_kind(other)
        if kind == ESCALATION_CONFIG and target == config_name:
            paths.append(f"the escalation of `{name}`")
    return paths


def _missing_config_note(channel, name: str) -> str:
    """The warning for a button or escalation pointing at a config that is not there.

    `dispatch_button_action` and `_run_escalation` both log a warning and report the press as
    not run, so a preview that printed the name alone would promise something that cannot
    happen.
    """
    return "" if name in channel.configs else f" :warning: (no configuration `{name}` in this channel)"


def _opsgenie_line(config: dict, variables: dict) -> str:
    template = config.get('opsgenie_message') or ''
    if template:
        alert = escape_newlines(templating.render_reply_message_template(template, variables, config)) or _EMPTY_VALUE
        note = ""
    else:
        # `maybe_post_opsgenie_alert` falls back to the triggering message, which is the run's
        # `{{message}}` — and a `cron` or `manual` run has none, so the alert body is empty.
        alert = escape_newlines(variables.get('message') or '') or _EMPTY_VALUE
        note = (" — the triggering message; this run has none, so the alert would go out with "
                "an empty body (set `opsgenie-message`)" if not (variables.get('message') or '')
                else " — the triggering message")
    schedule = config.get('opsgenie_schedule_name') or '<none>'
    line = (f"*OpsGenie alert*: {alert} (priority `{opsgenie.get_opsgenie_priority(config)}`, "
            f"schedule `{schedule}`){note}")
    if not state.opsgenie_configured:
        line += " — OpsGenie is not configured on this instance, so no alert is sent"
    return line


async def _run_section(app: AsyncApp, channel, config: dict, config_name: str, variables: dict) -> str:
    """Where the message goes, when the rule fires, and what else the run would do."""
    target_template = config.get('action_target') or ''
    target = (templating.render_reply_message_template(target_template, variables, config)
              if target_template else '')
    try:
        lines = [await _destination_line(app, channel, config, target.strip())]
    except Exception:  # pragma: no cover - a Slack lookup failing must not take the preview down
        lines = [f"*Action* `{config.get('action', ACTION_REPLY)}`, target `{target or '<none>'}`"
                 f" (could not be resolved)"]
    if actions.target_is_templated(target_template):
        lines.append(f"*Target*: `{target_template}` → " + (f"`{target}`" if target.strip() else _EMPTY_VALUE))
    lines.append(_trigger_line(config, channel))
    paths = _invocation_paths(channel, config_name)
    if paths:
        lines.append("*Also run by*: " + ", ".join(paths))

    config_buttons = config.get('buttons') or []
    if config_buttons:
        lines.append("*Buttons*: " + ", ".join(_button_summary(channel, button) for button in config_buttons))
    escalation_minutes = (config.get('escalation_timeout') or 0) // 60
    kind, escalation_target = buttons._escalation_kind(config)
    if escalation_minutes and kind != ESCALATION_NONE:
        escalates_to = (f"auto-presses `{escalation_target}`" if kind == ESCALATION_BUTTON
                        else f"runs `{escalation_target}`{_missing_config_note(channel, escalation_target)}")
        line = f"*Escalation*: after {escalation_minutes} minutes, {escalates_to}"
        if not config_buttons:
            # `run_action_with_reason` only registers the timer for a message that carries
            # buttons, so an escalation on a buttonless rule is set but never armed.
            line += " — inactive: this rule posts no buttons, so no escalation timer is started"
        lines.append(line)
    for label, template in _button_templates(config):
        # Rendered with this run's namespace: `{{press_*}}` and `{{parent_*}}` only have values
        # once somebody presses, so they show their placeholders here.
        lines.append(f"*Ack text* of `{label}`: "
                     f"{escape_newlines(templating.render_reply_message_template(template, variables, config))}")
    if config.get('opsgenie'):
        lines.append(_opsgenie_line(config, variables))

    if not config.get('enabled', True):
        reason = (f", because {state.bot_name} was removed from this channel"
                  if config.get('disabled_reason') == DISABLED_REASON_REMOVED else "")
        # Only the trigger is cut off: `run`, a button and an escalation all reach a disabled
        # config, which is what makes a disabled `manual` rule still usable as a button target.
        lines.append(f"*Disabled*{reason}: its trigger does not fire it, but "
                     f"`{state.slash_command} [config] run`, a button or an escalation still can")
    blocker = actions.missing_target_reason(config)
    if blocker:
        lines.append(f"*Cannot run*: {blocker}")
    return "\n".join(lines)


def _message_gates(config: dict, user, text: str) -> list[tuple[bool, str, str]]:
    """`(met, held, failed)` for each check a message has to pass to be queued at all.

    Two wordings per check rather than one plus a tick, so every line reads as the statement it
    actually is — ":x: now is inside the work hours" would say the opposite of what it means.

    The same checks `routing.handle_channel_message` makes, judged against the only message in
    hand: the one `test` was given (empty for the plain command) and whoever ran it. A rule
    whose pattern does not match this text would not have queued a reminder for it either, so
    a preview that skipped these could report "would run" for a message the rule ignores.
    """
    if config.get('trigger', TRIGGER_MESSAGE) != TRIGGER_MESSAGE:
        return []
    gates: list[tuple[bool, str, str]] = []
    actor_is_bot = bool(getattr(user, 'is_bot', False))
    if config.get('included_teams') or config.get('excluded_teams') or actor_is_bot:
        # The verdict comes from `routing`, so this cannot drift from what actually gates a
        # message; only the wording is this module's.
        met = routing.user_matches_actor_criteria(config, user, actor_is_bot)
        reason = routing.get_actor_mismatch_reason(config, user, actor_is_bot)
        gates.append((met, "the sender matches this rule's audience", reason))
    if config.get('only_work_days'):
        gates.append((datetimefmt.is_work_day(config), "today is a work day", "today is not a work day"))
    hours = config.get('hours') or []
    if len(hours) == 2:
        gates.append((datetimefmt.is_work_time(hours[0], hours[1], config),
                      f"now is inside the work hours {hours[0]} - {hours[1]}",
                      f"now is outside the work hours {hours[0]} - {hours[1]}"))
    pattern = config.get('pattern')
    if pattern:
        casing = "case-sensitive" if config.get('pattern_case_sensitive') else "case-insensitive"
        try:
            matched = bool(re.search(pattern, text or '', 0 if config.get('pattern_case_sensitive') else re.IGNORECASE))
        except re.error:
            matched = False
        failed = f"the message does not match `{pattern}` ({casing})"
        if not text:
            # The plain command has no message behind it, which is a real reason this gate
            # fails — and the mention form is how to give it one.
            failed += f", and there is no message here — try `@{state.bot_user_name} [config] test <message>`"
        gates.append((matched, f"the message matches `{pattern}` ({casing})", failed))
    return gates


def _gates_section(gates: list[tuple[bool, str, str]]) -> str:
    if not gates:
        return ""
    return "*Message gates:*\n" + "\n".join(
        f"{':white_check_mark:' if met else ':x:'} {held if met else failed}"
        for met, held, failed in gates)


def _conditions_section(config: dict, variables: dict) -> str:
    conditions = config.get('conditions') or []
    if not conditions:
        return ""
    mode = config.get('conditions_mode') or CONDITION_MODE_ALL
    lines = []
    for condition in conditions:
        single_met, _ = conditionutil.evaluate_conditions({'conditions': [condition]}, variables)
        lines.append(f"{':white_check_mark:' if single_met else ':x:'} "
                     f"{conditionutil.describe_condition(condition, code=True)}")
    header = "all must apply" if mode == CONDITION_MODE_ALL else "any may apply"
    return f"*Conditions* ({header}):\n" + "\n".join(lines)


def _verdict_section(config: dict, variables: dict, gates: list[tuple[bool, str, str]]) -> str:
    """Whether this rule would run right now, and the first thing stopping it if not.

    Every reason a run is refused, in the order the code refuses them: the trigger has to be
    live, the action needs somewhere to go, a message has to get past the gates, and the
    conditions have to pass.
    """
    trigger = config.get('trigger', TRIGGER_MESSAGE)
    blockers = []
    if not config.get('enabled', True) and trigger in (TRIGGER_MESSAGE, TRIGGER_CRON):
        # A disabled rule is only cut off from its own trigger: `run`, a button and an
        # escalation all reach it regardless (see `actions.run_action_with_reason`).
        blockers.append(f"it is disabled, so its `{trigger}` trigger does not fire it")
    blocker = actions.missing_target_reason(config)
    if blocker:
        blockers.append(blocker)
    blockers += [reason for met, _, reason in gates if not met]
    met, reason = conditionutil.evaluate_conditions(config, variables)
    if not met:
        blockers.append(reason)
    if blockers:
        return f"This rule would *not* run — {blockers[0]}."
    return "This rule would run."


def _used_variables_section(config: dict, variables: dict) -> str:
    """Every variable this configuration actually reads, grouped by the field that reads it."""
    sources: list[tuple[str, list[TemplateExpression]]] = [
        ("Message", _distinct_expressions(config.get('reply_message') or '')),
        ("Target", _distinct_expressions(config.get('action_target') or '')),
    ]
    if config.get('opsgenie'):
        sources.append(("OpsGenie alert", _distinct_expressions(config.get('opsgenie_message') or '')))
    for label, template in _button_templates(config):
        sources.append((f"Ack text of `{label}`", _distinct_expressions(template)))
    sources.append(("Conditions", _condition_expressions(config)))

    lines = []
    for label, expressions in sources:
        if not expressions:
            continue
        lines.append(f"_{label}_")
        lines += [_expression_line(expr, variables, config) for expr in expressions]
    if not lines:
        return "*Variables used*: _none — this configuration reads no template variables._"
    return "*Variables used:*\n" + "\n".join(lines)


def _selection_header(selection, config: dict) -> str:
    """`*Event* `offset=next`, read at Fr, 28 Aug 2026 09:11` — which moment answered with what.

    Worth a line of its own because a relative moment is a different instant in the preview
    than it will be when the rule fires.
    """
    arguments = ", ".join(part for part in (f'at="{selection.at}"' if selection.at else "",
                                            f"offset={selection.offset}" if selection.offset else "") if part)
    moment = datetimefmt.render_datetime(selection.instant, "datetime", config)
    return f"*Event* `{arguments}`, read at {moment}" if arguments else f"*Event* now, read at {moment}"


def _calendar_sections(config: dict, variables: dict) -> list[str]:
    """The feed, and every event the selections above resolved to."""
    feed = calendarfeed.resolve_calendar_feed(config)
    if feed.missing:
        return [f"*Calendar*: the built-in calendar `{feed.builtin}` is not offered by this instance, "
                f"so every `{{{{calendar_*}}}}` variable renders a placeholder."]
    if not feed.url:
        return []
    selections = variables.get(CALENDAR_SELECTIONS_KEY) or []
    sections = [f"*Calendar*: `{variables.get('calendar_name') or calendarfeed.describe_calendar_feed(feed)}`"
                + ("" if selections else " — nothing could be read from it.")]
    for selection in selections:
        header = _selection_header(selection, config)
        if selection.event is None:
            sections.append(f"{header} — _no event_")
            continue
        sections.append(f"{header}\n" + calendarfeed.describe_event(config, "Summary", selection.event, verbose=True))
    return sections


def _all_variables_sections(config: dict, variables: dict) -> list[str]:
    """The whole namespace, plus the neighbouring events every calendar variable can read.

    The full list is what makes `test` a reference as well as a preview: it is where somebody
    writing a template looks up what is available and what it currently holds.
    """
    sections = ["*All template variables:*\n" + "\n".join(
        _expression_line(TemplateExpression(variable, {}), variables, config)
        for variable in sorted(SUPPORTED_TEMPLATE_VARIABLES))]
    if not calendarfeed.resolve_calendar_feed(config).url:
        return sections
    for offset in ("next", "prev"):
        sections.append(f"*Calendar variables at `offset={offset}`:*\n" + "\n".join(
            _expression_line(TemplateExpression(variable, {"offset": offset}), variables, config)
            for variable in sorted(CALENDAR_EVENT_TEMPLATE_VARIABLES)))
    return sections


async def test_reply_message(app: AsyncApp, opsgenie_token: str, channel, config_name: str, user, text: str = "", ts: str = "", thread_ts: str = "") -> None:
    config = channel.configs.get(config_name) or copy.deepcopy(DEFAULT_CONFIG)
    permalink = await slackcache.get_message_permalink(app, channel, ts) if ts else ""
    variables = await templating.build_reply_template_variables(
        app,
        opsgenie_token,
        channel,
        config,
        config_name,
        user,
        text,
        ts,
        permalink,
        include_opsgenie=True,
        include_calendar=True,
        calendar_selectors=_preview_selectors(config),
    )

    gates = _message_gates(config, user, text)
    sections = [
        _message_section(config, config_name, variables),
        await _run_section(app, channel, config, config_name, variables),
        _gates_section(gates),
        _conditions_section(config, variables),
        _verdict_section(config, variables, gates),
        _used_variables_section(config, variables),
        *_calendar_sections(config, variables),
        *_all_variables_sections(config, variables),
    ]
    # Slack splits an oversized message wherever the break lands, so a full report is sent as
    # several messages — the footer belongs on the last one only.
    chunks = messaging.pack_message_chunks([section for section in sections if section])
    for index, chunk in enumerate(chunks):
        await messaging.send_message(app, channel, user, chunk, thread_ts, footer=index == len(chunks) - 1)
