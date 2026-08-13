"""The action engine: render text, run an action, fire OpsGenie, evaluate conditions.

``run_action`` and ``buttons`` reference each other (a config can carry buttons,
and a button runs a config); both sides use module-qualified access so the
import cycle is resolved lazily and monkeypatching stays visible.
"""

import outlook
from slack_bolt.async_app import AsyncApp
from slack_sdk.errors import SlackApiError

from employee_list import log, log_error, log_warning

from . import state
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
    CONDITION_NONE,
    CONDITION_OUTLOOK,
    OPSGENIE_TEMPLATE_VARIABLES,
    TEAM_UNKNOWN,
)
from .models import Channel, User


async def _render_template(app: AsyncApp, opsgenie_token: str, channel: Channel, config: dict, config_name: str, context: dict | None, template: str) -> str:
    template = template or ''
    context = context or {}
    user = context.get('user')
    if user is None:
        user = User(id=state.bot_user_id or '', name=state.bot_user_name, real_name=state.bot_name, team=TEAM_UNKNOWN)
    text = context.get('text', '')
    ts = context.get('ts', '')
    permalink = context.get('permalink')
    if permalink is None:
        permalink = await slackcache.get_message_permalink(app, channel, ts) if ts else ""
    template_variables = templating.find_template_variables(template)
    variables = await templating.build_reply_template_variables(
        app, opsgenie_token, channel, config, config_name, user, text, ts, permalink,
        include_opsgenie=bool(OPSGENIE_TEMPLATE_VARIABLES.intersection(template_variables)),
    )
    return templating.render_reply_message_template(template, variables, config)


async def render_template_text(app: AsyncApp, opsgenie_token: str, channel: Channel, config: dict, config_name: str, context: dict | None, template: str) -> str:
    """Render any template with a config's variables — a button's message, say."""
    return await _render_template(app, opsgenie_token, channel, config, config_name, context, template)


async def render_action_text(app: AsyncApp, opsgenie_token: str, channel: Channel, config: dict, config_name: str, context: dict | None) -> str:
    return await _render_template(app, opsgenie_token, channel, config, config_name, context, config.get('reply_message') or '')


async def maybe_post_opsgenie_alert(app: AsyncApp, opsgenie_token: str, channel: Channel, config: dict, config_name: str, context: dict | None, posted_ts: str = '') -> None:
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
    alert_text = await _render_template(app, opsgenie_token, channel, config, config_name, context, template) if template else context.get('text', '')
    log(f"Sending OpsGenie alert for config '{config_name}' in #{channel.name}.")
    # Scheduled/manual runs have no original-message ts, which would give every
    # recurrence the same OpsGenie alias and collapse them via dedup. Fall back to
    # the just-posted message ts so each run is a distinct alert. Used for the alias
    # only — not threaded into context/template variables.
    alert_ts = context.get('ts', '') or posted_ts
    await opsgenie.post_opsgenie_alert(app, opsgenie_token, channel, config, user, alert_text, alert_ts, context.get('permalink', ''))


async def action_reply(app: AsyncApp, channel: Channel, config: dict, context: dict | None, text: str, blocks: list | None) -> dict | None:
    context = context or {}
    candidate = context.get('thread_ts', '') or context.get('message_ts', '')
    # Only thread when the timestamp belongs to the channel we post to. A button
    # on a message sent to another conversation (DM/mpim/other channel) carries a
    # message_ts that is invalid as a thread_ts here, and Slack would reject it.
    ctx_channel = context.get('channel_id')
    thread_ts = candidate if candidate and (ctx_channel is None or ctx_channel == channel.id) else ""
    return await messaging._post_message(app, channel.id, text, blocks, thread_ts)


async def action_dm_user(app: AsyncApp, channel: Channel, config: dict, text: str, blocks: list | None) -> dict | None:
    target = (config.get('action_target') or '').strip()
    user = await targets.resolve_user_target(app, target)
    if not user or not user.id:
        log_error(f"Action dm_user: cannot resolve user target '{target}'.")
        return None
    try:
        opened = await app.client.conversations_open(users=[user.id])
        dm_id = opened['channel']['id']
    except SlackApiError as e:
        log_error(f"Action dm_user: failed to open DM with {target}:", e)
        return None
    return await messaging._post_message(app, dm_id, text, blocks)


async def action_group_dm(app: AsyncApp, channel: Channel, config: dict, text: str, blocks: list | None) -> dict | None:
    target = (config.get('action_target') or '').strip()
    usergroup = await targets.resolve_usergroup_target(app, target)
    if not usergroup or not usergroup.id:
        log_error(f"Action group_dm: cannot resolve usergroup '{target}'.")
        return None
    members = await slackcache.get_usergroup_members(app, usergroup.id)
    if not members:
        log_error(f"Action group_dm: usergroup '{target}' has no members.")
        return None
    # Slack multi-person DMs allow at most 8 members besides the bot.
    if len(members) > 8:
        log_warning(f"Action group_dm: usergroup '{target}' has {len(members)} members; using first 8 (Slack mpim limit).")
        members = members[:8]
    try:
        opened = await app.client.conversations_open(users=members)
        mpim_id = opened['channel']['id']
    except SlackApiError as e:
        log_error(f"Action group_dm: failed to open group DM for '{target}':", e)
        return None
    return await messaging._post_message(app, mpim_id, text, blocks)


async def action_post_channel(app: AsyncApp, channel: Channel, config: dict, text: str, blocks: list | None) -> dict | None:
    target = (config.get('action_target') or '').strip()
    channel_id = targets.parse_channel_ref(target)
    if not channel_id:
        log_error(f"Action post_channel: invalid channel target '{target}'.")
        return None
    return await messaging._post_message(app, channel_id, text, blocks)


def missing_target_reason(config: dict) -> str:
    """Why this config's action cannot run, or "" when it can.

    Every action except `reply` sends somewhere else and needs a target; a config
    that has none would only fail deep inside the action with an empty target.
    """
    action = config.get('action', ACTION_REPLY)
    if action not in ACTIONS_REQUIRING_TARGET:
        return ""
    target = (config.get('action_target') or '').strip()
    if not target:
        return f"action `{action}` has no target"
    if action == ACTION_POST_CHANNEL and not targets.parse_channel_ref(target):
        return f"action `{action}` target `{target}` is not a channel"
    return ""


async def run_action(app: AsyncApp, opsgenie_token: str, channel: Channel, config: dict, config_name: str, context: dict | None = None, _depth: int = 0) -> dict | None:
    if _depth > 5:
        log_warning(f"Action chain too deep at config '{config_name}'; aborting to avoid loops.")
        return None
    action = config.get('action', ACTION_REPLY)
    reason = missing_target_reason(config)
    if reason:
        log_error(f"Config '{config_name}' in #{channel.name} cannot run: {reason}; set one with `set action {action.replace('_', '-')} {ACTION_TARGET_HINTS[action]}`.")
        return None
    text = await render_action_text(app, opsgenie_token, channel, config, config_name, context)
    blocks = buttons.build_button_blocks(config, channel.id, config_name, text)
    log(f"Running action '{action}' for config '{config_name}' in #{channel.name}.")
    if action == ACTION_REPLY:
        posted = await action_reply(app, channel, config, context, text, blocks)
    elif action == ACTION_DM_USER:
        posted = await action_dm_user(app, channel, config, text, blocks)
    elif action == ACTION_GROUP_DM:
        posted = await action_group_dm(app, channel, config, text, blocks)
    elif action == ACTION_POST_CHANNEL:
        posted = await action_post_channel(app, channel, config, text, blocks)
    else:
        log_error(f"Unknown action '{action}' for config '{config_name}'.")
        return None
    if posted and posted.get('ts') and config.get('buttons'):
        await buttons.register_escalation(app, opsgenie_token, posted['channel'], posted['ts'], channel.id, config_name, config, context, posted_text=text)
    # OpsGenie is just a config property: any config that runs and has it enabled alerts.
    await maybe_post_opsgenie_alert(app, opsgenie_token, channel, config, config_name, context, (posted or {}).get('ts', ''))
    if not posted:
        return None
    return {**posted, 'text': text}


async def evaluate_condition(app: AsyncApp, config: dict) -> bool:
    condition = config.get('condition', CONDITION_NONE)
    if not condition:
        return True
    if condition == CONDITION_OUTLOOK:
        return await outlook.calendar_condition_met(
            config.get('outlook_subject_pattern', ''),
            config.get('outlook_body_pattern', ''),
            bool(config.get('condition_negate', False)),
        )
    log_warning(f"Unknown condition '{condition}'; treating as met.")
    return True
