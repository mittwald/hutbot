"""The action engine: render text, run an action, fire OpsGenie, evaluate conditions.

``run_action`` and ``buttons`` reference each other (a config can carry buttons,
and a button runs a config); both sides use module-qualified access so the
import cycle is resolved lazily and monkeypatching stays visible.
"""

from slack_bolt.async_app import AsyncApp
from slack_sdk.errors import SlackApiError

from logutil import log, log_error, log_warning

from . import state
from . import conditionutil
from . import slackcache
from . import messaging
from . import templating
from . import opsgenie
from . import targets
from . import buttons
from .constants import (
    ACTION_DM_USER,
    ACTION_GROUP_DM,
    ACTION_POST_CHANNEL,
    ACTION_REPLY,
    ACTIONS_REQUIRING_TARGET,
    ACTION_TARGET_HINTS,
    CALENDAR_TEMPLATE_VARIABLES,
    GROUP_DM_MEMBER_LIMIT,
    MAX_ACTION_CHAIN_DEPTH,
    MAX_PARENT_VARIABLES,
    OPSGENIE_TEMPLATE_VARIABLES,
    PARENT_VARIABLE_LENGTH_LIMIT,
    TEAM_UNKNOWN,
)
from .models import Channel, User


def _alert_is_live(config: dict) -> bool:
    """Whether this run could really send an OpsGenie alert — the gate `maybe_post_opsgenie_alert` uses."""
    return bool(state.opsgenie_configured and (config or {}).get('opsgenie'))


def _referenced_variables(config: dict) -> set[str]:
    """Every variable name this run of this config will read.

    The union of the message template, the conditions, and — only when this run could really
    send one — the OpsGenie alert template, so a single build serves the gate, the message and
    the alert. Switching OpsGenie off does not clear `opsgenie_message`, and
    `maybe_post_opsgenie_alert` returns before rendering it, so counting a dead alert template
    here would buy a provider round-trip (and its timeout) for text nothing will render.
    """
    referenced = conditionutil.condition_variables(config)
    for template in templating.config_templates(config, include_alert=_alert_is_live(config)):
        referenced |= templating.find_template_variables(template)
    return referenced


async def _build_variables(app: AsyncApp, opsgenie_token: str, channel: Channel, config: dict, config_name: str, context: dict | None, referenced: set[str], calendar_selectors: list[tuple[str, str]] | None = None) -> dict[str, str]:
    """Resolve the template-variable namespace once for a whole run.

    `referenced` is every variable name the run might read — the message template, the
    OpsGenie alert template, and the config's conditions. OpsGenie and the calendar each
    cost a network round-trip, so they are only fetched when something names one of their
    variables. Building this once means the conditions gate, the message, and the alert all
    see the same values; two builds could disagree on a time-dependent condition.
    """
    context = context or {}
    user = context.get('user')
    if user is None:
        user = User(id=state.bot_user_id or '', name=state.bot_user_name, real_name=state.bot_name, team=TEAM_UNKNOWN)
    ts = context.get('ts', '')
    permalink = context.get('permalink')
    if permalink is None:
        permalink = await slackcache.get_message_permalink(app, channel, ts) if ts else ""
    return await templating.build_reply_template_variables(
        app, opsgenie_token, channel, config, config_name, user, context.get('text', ''), ts, permalink,
        include_opsgenie=bool(OPSGENIE_TEMPLATE_VARIABLES.intersection(referenced)),
        include_calendar=bool(CALENDAR_TEMPLATE_VARIABLES.intersection(referenced)),
        calendar_selectors=calendar_selectors,
        parent=context.get('parent'),
        press=context.get('press'),
    )


async def _render_template(app: AsyncApp, opsgenie_token: str, channel: Channel, config: dict, config_name: str, context: dict | None, template: str, variables: dict[str, str] | None = None) -> str:
    template = template or ''
    if variables is None:
        variables = await _build_variables(
            app, opsgenie_token, channel, config, config_name, context,
            templating.find_template_variables(template),
            templating.find_calendar_selectors(template))
    return templating.render_reply_message_template(template, variables, config)


async def render_template_text(app: AsyncApp, opsgenie_token: str, channel: Channel, config: dict, config_name: str, context: dict | None, template: str, variables: dict[str, str] | None = None) -> str:
    """Render any template with a config's variables — a button's message, say."""
    return await _render_template(app, opsgenie_token, channel, config, config_name, context, template, variables)


async def render_action_text(app: AsyncApp, opsgenie_token: str, channel: Channel, config: dict, config_name: str, context: dict | None, variables: dict[str, str] | None = None) -> str:
    return await _render_template(app, opsgenie_token, channel, config, config_name, context, config.get('reply_message') or '', variables)


async def maybe_post_opsgenie_alert(app: AsyncApp, opsgenie_token: str, channel: Channel, config: dict, config_name: str, context: dict | None, posted_ts: str = '', variables: dict[str, str] | None = None) -> None:
    """Fire an OpsGenie alert when a config that just ran has OpsGenie enabled.

    The alert text defaults to the (original) message in context; a non-empty
    `opsgenie_message` template overrides it. This makes OpsGenie a property of
    any config — buttons/timeouts that run an OpsGenie-enabled config alert, with
    no OpsGenie-specific escalation machinery.
    """
    if not (state.opsgenie_configured and config.get('opsgenie')):
        return
    context = context or {}
    user = context.get('user') or User(id='', name=state.bot_user_name, real_name=state.bot_name, team=TEAM_UNKNOWN)
    template = config.get('opsgenie_message') or ''
    alert_text = await _render_template(app, opsgenie_token, channel, config, config_name, context, template, variables) if template else context.get('text', '')
    log(f"Sending OpsGenie alert for config '{config_name}' in #{channel.name}.")
    # Scheduled/manual runs have no original-message ts, which would give every
    # recurrence the same OpsGenie alias and collapse them via dedup. Fall back to
    # the just-posted message ts so each run is a distinct alert. Used for the alias
    # only — not threaded into context/template variables.
    alert_ts = context.get('ts', '') or posted_ts
    await opsgenie.post_opsgenie_alert(app, opsgenie_token, channel, config, user, alert_text, alert_ts, context.get('permalink', ''))


def _with_recipients(posted: dict | None, recipients: list[str]) -> dict | None:
    """Tag a posted message with who received it, for `{{parent_recipients}}`.

    `#name` for a channel and `<@U…>` for a person, which is what `{{channel}}` and `{{user}}`
    already render — so a condition on a recipient compares against the name somebody would
    write, not against an id.
    """
    return {**posted, 'recipients': recipients} if posted else None


async def _channel_recipient(app: AsyncApp, channel_id: str) -> str:
    """`#name` for a channel a config posted into.

    `get_channel_name` is the lookup that does not touch `state.channel_config` — the
    `get_channel_by_id` wrapper *creates* an entry for an id it does not know, which would
    invent a phantom channel config. It falls back to the id, and `#C123` would render as
    literal text, so an unresolved channel stays the `<#C123>` form Slack expands itself.
    """
    name = await slackcache.get_channel_name(app, channel_id)
    return f"#{name}" if name and name != channel_id else f"<#{channel_id}>"


def _chain_depth(context: dict | None) -> int:
    """How many configs deep in a chain this run is. Zero for a message, a schedule, a command."""
    try:
        return int(((context or {}).get('parent') or {}).get('depth', 0))
    except (TypeError, ValueError):
        return 0


def parent_run_facts(config: dict, action: str, target: str, posted: dict | None, variables: dict[str, str], context: dict | None = None) -> dict:
    """What a config triggered by this run gets to know about it: the `{{parent_*}}` values.

    Built here because this is the only place holding all of it at once — the namespace the
    message was rendered with, the action that sent it, the target it was sent to, and who Slack
    says it reached. Reduced to plain strings, because this is persisted verbatim with the
    pending button record and read back after a restart.

    The config's name, its rendered text and the posted timestamp are deliberately absent: the
    record already stores all three under `config_name`, `posted_text` and `message_ts`, and
    reading them back from there is what lets a record written before this existed still answer
    `{{parent_config}}`, `{{parent_message}}` and the date/time variables.
    """
    names, values = templating.rendered_template_values(config.get('reply_message') or '', variables, config)
    return {
        'variable_names': names[:MAX_PARENT_VARIABLES],
        'variables': [value[:PARENT_VARIABLE_LENGTH_LIMIT] for value in values[:MAX_PARENT_VARIABLES]],
        'action': action,
        'target': target,
        'recipients': list((posted or {}).get('recipients') or ()),
        # One hop further than whatever triggered *this* run. Persisted with the record, so a
        # chain cannot launder its depth through a restart.
        'depth': _chain_depth(context) + 1,
    }


async def action_reply(app: AsyncApp, channel: Channel, config: dict, context: dict | None, text: str, blocks: list | None) -> dict | None:
    context = context or {}
    candidate = context.get('thread_ts', '') or context.get('message_ts', '')
    # Only thread when the timestamp belongs to the channel we post to. A button
    # on a message sent to another conversation (DM/mpim/other channel) carries a
    # message_ts that is invalid as a thread_ts here, and Slack would reject it.
    ctx_channel = context.get('channel_id')
    thread_ts = candidate if candidate and (ctx_channel is None or ctx_channel == channel.id) else ""
    posted = await messaging._post_message(app, channel.id, text, blocks, thread_ts)
    # A reply lands in the config's own channel, whose name is already in hand.
    return _with_recipients(posted, [f"#{channel.name}"])


async def action_dm_user(app: AsyncApp, channel: Channel, config: dict, text: str, blocks: list | None, target: str | None = None) -> dict | None:
    target = (target if target is not None else config.get('action_target') or '').strip()
    users = await targets.resolve_user_targets(app, target)
    if not users:
        log_error(f"Action dm_user: cannot resolve user target '{target}'.")
        return None
    if len(users) > 1:
        # A variable can name several people; `dm_user` is one conversation with one of them,
        # and `group_dm` is the action for reaching all of them.
        log_warning(f"Action dm_user: target '{target}' names {len(users)} users; DMing @{users[0].name}. Use `group-dm` to reach all of them.")
    user = users[0]
    try:
        opened = await app.client.conversations_open(users=[user.id])
        dm_id = opened['channel']['id']
    except SlackApiError as e:
        log_error(f"Action dm_user: failed to open DM with {target}:", e)
        return None
    posted = await messaging._post_message(app, dm_id, text, blocks)
    # The posted `channel` is a `D…` id, which names nobody — and a target may name several
    # people while this action DMs one of them, so only the action itself can answer who.
    return _with_recipients(posted, [f"<@{user.id}>"])


async def action_group_dm(app: AsyncApp, channel: Channel, config: dict, text: str, blocks: list | None, target: str | None = None) -> dict | None:
    target = (target if target is not None else config.get('action_target') or '').strip()
    if targets.names_people(target):
        # Mentions or addresses, so the target names the people directly — which is how
        # `{{calendar_other_attendee_users}}` arrives once it is rendered.
        members = [user.id for user in await targets.resolve_user_targets(app, target)]
        if not members:
            log_error(f"Action group_dm: cannot resolve any user from '{target}'.")
            return None
    else:
        usergroup = await targets.resolve_usergroup_target(app, target)
        if not usergroup or not usergroup.id:
            log_error(f"Action group_dm: cannot resolve usergroup '{target}'.")
            return None
        members = await slackcache.get_usergroup_members(app, usergroup.id)
        if not members:
            log_error(f"Action group_dm: usergroup '{target}' has no members.")
            return None
    # Slack multi-person DMs allow at most `GROUP_DM_MEMBER_LIMIT` members besides the bot.
    if len(members) > GROUP_DM_MEMBER_LIMIT:
        log_warning(f"Action group_dm: target '{target}' names {len(members)} people; using first {GROUP_DM_MEMBER_LIMIT} (Slack mpim limit).")
        members = members[:GROUP_DM_MEMBER_LIMIT]
    try:
        opened = await app.client.conversations_open(users=members)
        mpim_id = opened['channel']['id']
    except SlackApiError as e:
        log_error(f"Action group_dm: failed to open group DM for '{target}':", e)
        return None
    posted = await messaging._post_message(app, mpim_id, text, blocks)
    # Read after the 8-member trim above, so this reports who was opened, not who resolved.
    return _with_recipients(posted, [f"<@{member}>" for member in members])


async def action_post_channel(app: AsyncApp, channel: Channel, config: dict, text: str, blocks: list | None, target: str | None = None) -> dict | None:
    target = (target if target is not None else config.get('action_target') or '').strip()
    channel_id = targets.parse_channel_ref(target)
    if not channel_id:
        log_error(f"Action post_channel: invalid channel target '{target}'.")
        return None
    posted = await messaging._post_message(app, channel_id, text, blocks)
    return _with_recipients(posted, [await _channel_recipient(app, channel_id)] if posted else [])


def target_is_templated(target: str) -> bool:
    """Whether a target has to be rendered before it names anything."""
    return "{{" in (target or "")


def missing_target_reason(config: dict) -> str:
    """Why this config's action cannot run, or "" when it can.

    Every action except `reply` sends somewhere else and needs a target; a config
    that has none would only fail deep inside the action with an empty target.

    A target holding `{{variables}}` can only be checked once it is rendered, so it is taken
    on trust here and reported by the action itself if it resolves to nobody.
    """
    action = config.get('action', ACTION_REPLY)
    if action not in ACTIONS_REQUIRING_TARGET:
        return ""
    target = (config.get('action_target') or '').strip()
    if not target:
        return f"action `{action}` has no target"
    if target_is_templated(target):
        return ""
    if action == ACTION_POST_CHANNEL and not targets.parse_channel_ref(target):
        return f"action `{action}` target `{target}` is not a channel"
    return ""


async def evaluate_conditions(app: AsyncApp, opsgenie_token: str, channel: Channel, config: dict, config_name: str, context: dict | None = None, variables: dict[str, str] | None = None) -> tuple[bool, str, dict[str, str] | None]:
    """Whether a config's conditions allow it to run.

    Returns `(met, reason, variables)`; the resolved variables come back so the caller can
    reuse them for the message and any alert instead of resolving everything twice.
    A config with no conditions is not charged for anything.
    """
    if not (config or {}).get('conditions'):
        return True, "", variables
    if variables is None:
        variables = await _build_variables(
            app, opsgenie_token, channel, config, config_name, context,
            _referenced_variables(config),
            templating.config_calendar_selectors(config, include_alert=_alert_is_live(config)))
    met, reason = conditionutil.evaluate_conditions(config, variables)
    return met, reason, variables


async def conditions_ruled_out_at_arrival(app: AsyncApp, opsgenie_token: str, channel: Channel, config: dict, config_name: str, context: dict | None = None) -> tuple[bool, str]:
    """Whether a message rule's conditions already fail on what is known right now.

    A message reminder can sit in the queue for up to a day before its conditions are judged.
    When a condition reads something that cannot change in the meantime — the message, its
    sender, their team — there is no reason to wait to find out it will not pass, so the
    reminder is never queued at all.

    Only settled conditions are consulted, and resolving them touches no network: nothing
    here can reference OpsGenie, the calendar, or the permalink (see
    `FIRE_TIME_TEMPLATE_VARIABLES`).
    """
    referenced = conditionutil.settled_condition_variables(config)
    if not referenced:
        return False, ""
    # An empty permalink keeps this free of a Slack round-trip; `message_link` is a fire-time
    # variable precisely so no settled condition can ask for it.
    context = {**(context or {}), 'permalink': (context or {}).get('permalink') or ''}
    variables = await _build_variables(app, opsgenie_token, channel, config, config_name, context, referenced)
    return conditionutil.conditions_ruled_out(config, variables)


async def run_action_with_reason(app: AsyncApp, opsgenie_token: str, channel: Channel, config: dict, config_name: str, context: dict | None = None) -> tuple[dict | None, str]:
    """`run_action`, plus why nothing was sent — so callers can report it.

    The conditions gate lives here rather than at each trigger, so no entry point can
    forget it. It runs after `missing_target_reason` (which is free, and is a config error
    the user has to fix either way) and before anything is rendered or posted.
    """
    depth = _chain_depth(context)
    if depth > MAX_ACTION_CHAIN_DEPTH:
        log_warning(f"Config '{config_name}' is {depth} configs deep in a chain; stopping to avoid a loop.")
        return None, f"action chain is more than {MAX_ACTION_CHAIN_DEPTH} configs deep"
    action = config.get('action', ACTION_REPLY)
    reason = missing_target_reason(config)
    if reason:
        log_error(f"Config '{config_name}' in #{channel.name} cannot run: {reason}; set one with `set action {action.replace('_', '-')} {ACTION_TARGET_HINTS[action]}`.")
        return None, reason

    met, condition_reason, variables = await evaluate_conditions(app, opsgenie_token, channel, config, config_name, context)
    if not met:
        log(f"Config '{config_name}' in #{channel.name} did not run: {condition_reason}.")
        return None, condition_reason

    if variables is None:
        # A config with no conditions was not charged for a build by the gate, so this is the
        # first one. Built here rather than inside each render so the message, the target and the
        # alert cannot disagree — and so `parent_run_facts` below describes the namespace the
        # message was actually rendered with.
        variables = await _build_variables(
            app, opsgenie_token, channel, config, config_name, context,
            _referenced_variables(config),
            templating.config_calendar_selectors(config, include_alert=_alert_is_live(config)))

    text = await render_action_text(app, opsgenie_token, channel, config, config_name, context, variables)
    # A target may name people through variables — `{{calendar_other_attendee_users}}`
    # for whoever is on call — so it is rendered with the same namespace as the message.
    target = config.get('action_target') or ''
    if target_is_templated(target):
        target = await render_template_text(app, opsgenie_token, channel, config, config_name, context, target, variables)
    blocks = buttons.build_button_blocks(config, channel.id, config_name, text)
    log(f"Running action '{action}' for config '{config_name}' in #{channel.name}.")
    if action == ACTION_REPLY:
        posted = await action_reply(app, channel, config, context, text, blocks)
    elif action == ACTION_DM_USER:
        posted = await action_dm_user(app, channel, config, text, blocks, target)
    elif action == ACTION_GROUP_DM:
        posted = await action_group_dm(app, channel, config, text, blocks, target)
    elif action == ACTION_POST_CHANNEL:
        posted = await action_post_channel(app, channel, config, text, blocks, target)
    else:
        log_error(f"Unknown action '{action}' for config '{config_name}'.")
        return None, f"unknown action `{action}`"
    if posted and posted.get('ts') and config.get('buttons'):
        await buttons.register_escalation(
            app, opsgenie_token, posted['channel'], posted['ts'], channel.id, config_name, config,
            context, posted_text=text,
            parent=parent_run_facts(config, action, target, posted, variables, context))
    # OpsGenie is just a config property: any config that runs and has it enabled alerts.
    await maybe_post_opsgenie_alert(app, opsgenie_token, channel, config, config_name, context, (posted or {}).get('ts', ''), variables)
    if not posted:
        # The action ran but Slack rejected it; callers already say "did not send
        # anything", so adding a reason here would only stutter.
        return None, ""
    return {**posted, 'text': text}, ""


async def run_action(app: AsyncApp, opsgenie_token: str, channel: Channel, config: dict, config_name: str, context: dict | None = None) -> dict | None:
    posted, _ = await run_action_with_reason(app, opsgenie_token, channel, config, config_name, context)
    return posted
