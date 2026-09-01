"""The Slack side of the config UI: publish, open, read back, apply.

The only half of `apphome` that talks to Slack or changes anything, and every change goes
through `webui_backend` — the same validation and write path the web UI saves through, so the
two cannot drift into disagreeing about what a valid rule is.

Two rules hold the design together:

* **Every submit sends a whole config document.** `validate_config_payload` falls back to
  `DEFAULT_CONFIG` for any key a payload leaves out, so a partial save would silently reset
  every field the form did not show. A section's submit therefore starts from
  `ui_snapshot_configs`, overlays the fields that section owns, and hands the whole thing over.
  That also carries `disabled_reason` through, which is what lets the hub's Enable toggle
  count as an explicit re-enable while an unrelated save leaves an automatic disable standing.

* **No drafts anywhere.** A row form's submit *is* the write, and a list is re-read from the
  live config every time it is rendered. Nothing to persist across a restart, nothing to
  expire, and no way for the screen to disagree with `bot.json`.
"""

import json

from slack_bolt.async_app import AsyncApp
from slack_sdk.errors import SlackApiError

from logutil import log, log_error, log_warning

from . import fields
from . import views
from .. import slackcache
from .. import state
from .. import webui_backend
from ..constants import CONFIG_UI_ACTION_PREFIX
from ..models import OpsGenieTokens
from ..textutil import channel_label


def describe_home_opened(event: dict) -> str:
    """Where an `app_home_opened` came from, as a log-line origin (see `logutil.log_origin`)."""
    user_id = (event or {}).get('user', '') or 'unknown viewer'
    return f"App Home {(event or {}).get('tab', '') or 'tab'} opened by {user_id}"


def _describe_where(body: dict, action: dict | None = None) -> str:
    """`rule 'nightly' in C0123`, from whatever the interaction carries.

    The channel is named by id, not by name: resolving it would be a Slack call at the very
    frame whose failures this origin exists to explain, and no view needs the name anyway —
    Slack renders `<#C0123>` itself.
    """
    target = _target(body, action or {})
    where = channel_label(target.get('channel_id', ''))
    config_name = target.get('config_name', '')
    return f"rule '{config_name}' in {where}" if config_name else where


def describe_action(body: dict, action: dict) -> str:
    """Where a config UI interaction came from, as a log-line origin."""
    user_id = (body.get('user', {}) or {}).get('id', '') or 'unknown user'
    action_id = action.get('action_id', '') or '?'
    return f"config UI {action_id} on {_describe_where(body, action)} from {user_id}"


def describe_submission(body: dict) -> str:
    """Where a config UI form submission came from, as a log-line origin."""
    user_id = (body.get('user', {}) or {}).get('id', '') or 'unknown user'
    callback_id = (body.get('view', {}) or {}).get('callback_id', '') or '?'
    return f"config UI save {callback_id} on {_describe_where(body)} from {user_id}"


def describe_options(body: dict) -> str:
    """Where a config UI typeahead lookup came from, as a log-line origin."""
    user_id = (body.get('user', {}) or {}).get('id', '') or 'unknown user'
    action_id = body.get('action_id', '') or '?'
    return f"config UI options {action_id} on {_describe_where(body)} from {user_id}"


def _parts(action_id: str) -> list[str]:
    """`hutbot_cfg:row:conditions:menu:2` → `["row", "conditions", "menu", "2"]`."""
    prefix = f"{CONFIG_UI_ACTION_PREFIX}:"
    return action_id[len(prefix):].split(':') if action_id.startswith(prefix) else []


def _selected(action: dict):
    """What the pressed element carries: an option's value, or the button's own."""
    if 'selected_option' in action:
        chosen = action['selected_option']
        return chosen.get('value') if isinstance(chosen, dict) else None
    return action.get('value')


def _target(body: dict, action: dict) -> dict:
    """Which channel and rule an interaction is about.

    A button says so in its own `value`, because a Home-tab press has no view to fall back on
    that names the rule. Everything else takes it from the view's `private_metadata`.
    """
    from_view = fields.decode_meta((body.get('view') or {}).get('private_metadata') or "")
    if action.get('value'):
        from_button = fields.decode_meta(action['value'])
        if from_button.get('channel_id'):
            return from_button
    return from_view


def _values(body: dict) -> dict:
    return ((body.get('view') or {}).get('state') or {}).get('values') or {}


def _view_id(body: dict) -> str:
    return (body.get('view') or {}).get('id') or ""


def _meta(config_names=()) -> dict:
    """`ui_meta`, plus the rule names only this channel knows about.

    The rule names let a `config` button and a `config` escalation be picked from a list
    rather than typed as a comma-separated string.
    """
    meta = webui_backend.ui_meta()
    meta['config_names'] = sorted(config_names)
    return meta


def _configs(channel_id: str) -> dict:
    """A channel's rules, redacted, without creating an entry for a channel that has none.

    Deliberately not `slackcache.get_channel_by_id`: that inserts an empty entry for any
    channel it is asked about, and `save_configuration` writes the whole tree — so browsing
    the Home tab would grow `bot.json` a key at a time.
    """
    return webui_backend.ui_snapshot_configs(channel_id)


async def _may_edit(app: AsyncApp, channel_id: str, user_id: str) -> bool:
    """Whether this user may edit this channel's rules.

    Re-checked on every interaction rather than once: a modal outlives the membership it was
    opened with, and so does the ephemeral `show config` the Edit button sits on.
    """
    if not channel_id or not user_id:
        return False
    return await slackcache.is_user_in_channel(app, channel_id, user_id)


# --- the Home tab ---------------------------------------------------------------------

async def refresh_home(app: AsyncApp, user_id: str, channel_id: str = "") -> None:
    """Publish this user's Home tab, for `channel_id` or for wherever they last were."""
    if not user_id:
        return
    user = await slackcache.get_user_by_id(app, user_id)
    channels = await webui_backend.list_user_config_channels(app, user) if user else []
    known = {channel['id'] for channel in channels}
    chosen = channel_id or state.home_tab_channel.get(user_id) or ""
    if chosen not in known:
        chosen = channels[0]['id'] if channels else ""
    # Recorded even when empty: the key is also how a later mutation knows this process has
    # published a tab for this user and that refreshing it is worth a call.
    state.home_tab_channel[user_id] = chosen
    view = views.home_view(_meta(), chosen, channels, _configs(chosen))
    try:
        await app.client.views_publish(user_id=user_id, view=view)
    except SlackApiError as e:
        error = (e.response or {}).get('error', '')
        if error == 'app_home_disabled':
            # Not retried and not raised: the fix is one switch in the Slack app, and the
            # modal editor from `show config` works without it.
            log_warning("App Home is not enabled for this Slack app, so the configuration "
                        "tab cannot be published. Enable App Home → Home Tab.")
        else:
            log_error("Could not publish the App Home tab:", e)


async def _refresh_home_if_open(app: AsyncApp, user_id: str) -> None:
    """Republish only for a user this process has already published a tab for."""
    if user_id in state.home_tab_channel:
        await refresh_home(app, user_id)


async def handle_app_home_opened(app: AsyncApp, event: dict) -> None:
    """The `app_home_opened` event — the same event fires for the Messages tab."""
    if (event or {}).get('tab') != 'home':
        return
    user_id = event.get('user') or ""
    # The published view survives a restart, so its metadata remembers the channel when this
    # process's own memory does not.
    remembered = fields.decode_meta((event.get('view') or {}).get('private_metadata') or "")
    await refresh_home(app, user_id, state.home_tab_channel.get(user_id)
                       or remembered.get('channel_id', ""))


# --- opening and navigating views -----------------------------------------------------

async def _open(app: AsyncApp, body: dict, view: dict) -> None:
    try:
        await app.client.views_open(trigger_id=body.get('trigger_id'), view=view)
    except SlackApiError as e:
        log_error("Could not open a configuration modal:", e)


async def _push(app: AsyncApp, body: dict, view: dict) -> None:
    try:
        await app.client.views_push(trigger_id=body.get('trigger_id'), view=view)
    except SlackApiError as e:
        log_error("Could not open a configuration modal:", e)


async def _update(app: AsyncApp, body: dict, view: dict) -> None:
    # No `hash`: one user drives one modal, so a hash would only buy `hash_conflict` failures.
    try:
        await app.client.views_update(view_id=_view_id(body), view=view)
    except SlackApiError as e:
        log_error("Could not update a configuration modal:", e)


def _hub(channel_id: str, config_name: str, configs: dict | None = None) -> dict:
    """The rule hub, always built from the live config rather than from what was on screen."""
    configs = configs if configs is not None else _configs(channel_id)
    config = configs.get(config_name)
    if config is None:
        return views.notice_view("Gone", f"`{config_name}` no longer exists in <#{channel_id}>.")
    return views.hub_view(_meta(configs), channel_id, config_name, config)


def _list_view(channel_id: str, config_name: str, section: str) -> dict:
    configs = _configs(channel_id)
    config = configs.get(config_name)
    if config is None:
        return views.notice_view("Gone", f"`{config_name}` no longer exists in <#{channel_id}>.")
    builder = views.conditions_view if section == "conditions" else views.buttons_view
    return builder(_meta(configs), channel_id, config_name, config)


def _section_view(channel_id: str, config_name: str, section: str,
                  config: dict | None = None) -> dict:
    configs = _configs(channel_id)
    config = config if config is not None else configs.get(config_name)
    if config is None:
        return views.notice_view("Gone", f"`{config_name}` no longer exists in <#{channel_id}>.")
    return views.section_view(_meta(configs), channel_id, config_name, section, config)


# --- writing ---------------------------------------------------------------------------

async def _apply(app: AsyncApp, channel_id: str, config_name: str,
                 changes: dict) -> tuple[bool, dict]:
    """Overlay `changes` onto the stored rule and save the whole document.

    The snapshot is taken here, at apply time rather than when the form opened, so a
    concurrent edit to a field this form does not touch survives. The redacted `calendar_url`
    it carries is what `validate_config_payload` reads as "unchanged", which is why an
    unrelated section's save cannot disturb a stored feed URL.
    """
    snapshot = _configs(channel_id).get(config_name)
    if snapshot is None:
        return False, {'name': "That rule no longer exists."}
    snapshot.update(changes)
    return await webui_backend.ui_apply_config(app, channel_id, config_name, snapshot)


async def _apply_rows(app: AsyncApp, channel_id: str, config_name: str, kind: str,
                      index: int, row: dict | None) -> tuple[bool, dict]:
    """Write one row of `conditions` or `buttons`; `row=None` deletes it.

    Indexes line up with the backend's error keys because validation reports per input row —
    it steps over a bad row rather than compacting the list.
    """
    snapshot = _configs(channel_id).get(config_name)
    if snapshot is None:
        return False, {'name': "That rule no longer exists."}
    rows = list(snapshot.get(kind) or [])
    if row is None:
        if not 0 <= index < len(rows):
            return False, {'name': "That row is already gone."}
        rows.pop(index)
    elif index >= len(rows):
        rows.append(row)
    else:
        rows[index] = row
    snapshot[kind] = rows
    return await webui_backend.ui_apply_config(app, channel_id, config_name, snapshot)


# --- block_actions ---------------------------------------------------------------------

async def handle_action(app: AsyncApp, body: dict, action: dict,
                        opsgenie_tokens: OpsGenieTokens = OpsGenieTokens()) -> None:
    """One `hutbot_cfg:` interaction. Already acked by the caller."""
    parts = _parts(action.get('action_id') or "")
    if not parts:
        return
    target = _target(body, action)
    channel_id, config_name = target.get('channel_id', ""), target.get('config_name', "")
    user_id = (body.get('user') or {}).get('id') or ""
    kind = parts[0]

    if kind == 'channel':
        # The picker's own value is the channel, not the view's metadata.
        await refresh_home(app, user_id, str(_selected(action) or ""))
        return
    if kind == 'refresh':
        await refresh_home(app, user_id, channel_id)
        return

    if not await _may_edit(app, channel_id, user_id):
        log_warning(f"Config UI: refused {action.get('action_id')} from {user_id} "
                    f"for channel {channel_id or '(none)'}.")
        return

    if kind == 'pick_rule':
        configs = _configs(channel_id)
        await _open(app, body, views.picker_view(_meta(configs), channel_id, configs))
    elif kind == 'rule':
        # From the Home tab there is no modal yet; from the picker there is one to replace.
        view = _hub(channel_id, config_name)
        await (_update(app, body, view) if _view_id(body) else _open(app, body, view))
    elif kind == 'new_rule':
        await _open_or_update(app, body, views.name_view(_meta(), channel_id))
    elif kind == 'rename':
        await _update(app, body, views.name_view(_meta(), channel_id, config_name))
    elif kind == 'nav':
        await _update(app, body, _hub(channel_id, config_name))
    elif kind == 'open':
        section = parts[1] if len(parts) > 1 else ""
        view = (_list_view(channel_id, config_name, section)
                if section in fields.LIST_SECTIONS
                else _section_view(channel_id, config_name, section))
        await _push(app, body, view)
    elif kind == 'toggle_enabled':
        await _toggle_enabled(app, body, channel_id, config_name, user_id)
    elif kind == 'delete':
        await _delete_rule(app, body, channel_id, config_name, user_id)
    elif kind == 'run':
        await _run_now(app, channel_id, config_name, user_id, opsgenie_tokens)
    elif kind == 'row':
        await _row_action(app, body, target, parts, action, user_id)
    elif kind == 'field':
        # The only immediately-applied field outside a form: the condition mode, which sits in
        # a list view that has no submit button to wait for.
        if len(parts) > 1 and parts[1] == 'conditions_mode':
            await _apply(app, channel_id, config_name,
                         {'conditions_mode': str(_selected(action) or "")})
            await _update(app, body, _list_view(channel_id, config_name, "conditions"))
            await _refresh_home_if_open(app, user_id)
    elif kind == 'render':
        await _rerender(app, body, target, parts[1] if len(parts) > 1 else "")


async def _open_or_update(app: AsyncApp, body: dict, view: dict) -> None:
    await (_update(app, body, view) if _view_id(body) else _open(app, body, view))


async def _toggle_enabled(app: AsyncApp, body: dict, channel_id: str, config_name: str,
                          user_id: str) -> None:
    configs = _configs(channel_id)
    config = configs.get(config_name)
    if config is None:
        await _update(app, body, _hub(channel_id, config_name, configs))
        return
    # `disabled_reason` rides along in the snapshot, which is what makes turning a rule the
    # bot disabled itself back on count as an explicit re-enable rather than a stale save.
    ok, errors = await _apply(app, channel_id, config_name,
                              {'enabled': not config.get('enabled', True)})
    if not ok:
        log_warning(f"Config UI: could not toggle `{config_name}`: {errors}")
    await _update(app, body, _hub(channel_id, config_name))
    await _refresh_home_if_open(app, user_id)


async def _delete_rule(app: AsyncApp, body: dict, channel_id: str, config_name: str,
                       user_id: str) -> None:
    ok, message = await webui_backend.ui_delete_config(app, channel_id, config_name)
    if not ok:
        await _update(app, body, views.notice_view("Not deleted", message))
        return
    configs = _configs(channel_id)
    await _update(app, body, views.picker_view(_meta(configs), channel_id, configs))
    await _refresh_home_if_open(app, user_id)


async def _run_now(app: AsyncApp, channel_id: str, config_name: str, user_id: str,
                   opsgenie_tokens: OpsGenieTokens) -> None:
    """Run a rule from the hub, through the same handler `run config` uses.

    Imported here rather than at module scope: `commands.setters` reaches back into
    `webui_backend`, and a top-level import would tie this module into that cycle for a
    feature one button uses.
    """
    from ..commands import setters
    channel = await slackcache.get_channel_by_id(app, channel_id)
    user = await slackcache.get_user_by_id(app, user_id)
    if channel is None or user is None:
        return
    await setters.run_config_now(app, opsgenie_tokens, channel, config_name, user)


async def _row_action(app: AsyncApp, body: dict, target: dict, parts: list[str], action: dict,
                      user_id: str) -> None:
    """Add, edit or delete one condition or button row."""
    channel_id, config_name = target.get('channel_id', ""), target.get('config_name', "")
    kind = parts[1] if len(parts) > 1 else ""
    verb = parts[2] if len(parts) > 2 else ""
    if kind not in fields.LIST_SECTIONS:
        return
    row_view = (views.condition_row_view if kind == "conditions" else views.button_row_view)
    configs = _configs(channel_id)
    config = configs.get(config_name)
    if config is None:
        await _update(app, body, views.notice_view(
            "Gone", f"`{config_name}` no longer exists in <#{channel_id}>."))
        return
    rows = config.get(kind) or []

    if verb == 'add':
        # A new row is the one past the end; `_apply_rows` appends rather than replaces.
        await _update(app, body, row_view(_meta(configs), channel_id, config_name, len(rows), {}))
        return
    if verb != 'menu':
        return
    choice = str(_selected(action) or "")
    operation, _, raw_index = choice.partition(':')
    if not raw_index.isdigit():
        return
    index = int(raw_index)
    if operation == 'edit':
        row = rows[index] if index < len(rows) else {}
        await _update(app, body, row_view(_meta(configs), channel_id, config_name, index, row))
        return
    if operation == 'delete':
        ok, errors = await _apply_rows(app, channel_id, config_name, kind, index, None)
        if not ok:
            # A refusal here is a cross-check the deletion broke (a delay button losing its
            # escalation, say), so the list has to say why instead of silently not deleting.
            await _update(app, body, views.notice_view(
                "Not deleted", "\n".join(f"• {message}" for message in errors.values())))
            return
        await _update(app, body, _list_view(channel_id, config_name, kind))
        await _refresh_home_if_open(app, user_id)


async def _rerender(app: AsyncApp, body: dict, target: dict, field: str) -> None:
    """Redraw a form after a value that decides which other fields it shows.

    The form is rebuilt from what is on screen, not from storage, so nothing typed is lost —
    and nothing is saved either: a redraw is not a write.
    """
    channel_id, config_name = target.get('channel_id', ""), target.get('config_name', "")
    section = target.get('section', "")
    values = _values(body)
    configs = _configs(channel_id)
    config = configs.get(config_name)
    if config is None:
        return
    if section in fields.LIST_SECTIONS:
        row = target.get('row')
        row = 0 if row is None else row
        if section == "conditions":
            view = views.condition_row_view(_meta(configs), channel_id, config_name, row,
                                            fields.read_condition_row(values))
        else:
            view = views.button_row_view(_meta(configs), channel_id, config_name, row,
                                         fields.read_button_row(values))
    elif section in fields.SECTIONS:
        pending = {**config, **fields.read_section_values(values, section)}
        view = views.section_view(_meta(configs), channel_id, config_name, section, pending)
    else:
        return
    await _update(app, body, view)


# --- view_submission -------------------------------------------------------------------

def _submitted_block_ids(view: dict) -> list[str]:
    """The input blocks the submitted view actually had, in the order it showed them.

    Read from `state.values` rather than from the view's `blocks`: those keys are exactly the
    input blocks, Slack always sends them with a submission, and they arrive in block order —
    so the first of them is the block a leftover error is folded onto.
    """
    return list(((view.get('state') or {}).get('values')) or {})


def _errors_for(view: dict, errors: dict, row_key: str = "", row_block_id: str = "") -> dict:
    block_ids = _submitted_block_ids(view)
    return fields.map_errors(errors, block_ids, block_ids[0] if block_ids else "",
                             row_key, row_block_id)


async def handle_view_submission(app: AsyncApp, ack, body: dict) -> None:
    """A form was saved. Acks with the errors, or with the view to land on."""
    view = body.get('view') or {}
    callback_id = view.get('callback_id') or ""
    kind = callback_id.rpartition(':')[2]
    target = fields.decode_meta(view.get('private_metadata') or "")
    channel_id, config_name = target.get('channel_id', ""), target.get('config_name', "")
    user_id = (body.get('user') or {}).get('id') or ""
    values = ((view.get('state') or {}).get('values')) or {}

    if not await _may_edit(app, channel_id, user_id):
        await ack(response_action="update",
                  view=views.notice_view("Not allowed",
                                         "You are no longer a member of that channel."))
        return

    if kind == views.VIEW_SECTION:
        await _submit_section(app, ack, view, values, target)
    elif kind in (views.VIEW_CONDITION_ROW, views.VIEW_BUTTON_ROW):
        await _submit_row(app, ack, view, values, target, kind)
    elif kind in (views.VIEW_NEW_RULE, views.VIEW_RENAME_RULE):
        await _submit_name(app, ack, view, values, target, kind)
    else:
        await ack()
        return
    await _refresh_home_if_open(app, user_id)


async def _submit_section(app: AsyncApp, ack, view: dict, values: dict, target: dict) -> None:
    channel_id, config_name = target['channel_id'], target['config_name']
    section = target.get('section', "")
    if section not in fields.SECTIONS:
        await ack()
        return
    ok, errors = await _apply(app, channel_id, config_name,
                              fields.read_section_values(values, section))
    if not ok:
        await ack(response_action="errors", errors=_errors_for(view, errors))
        return
    # Back to the hub, rebuilt from what was just stored, so the summary the user reads is
    # the saved one rather than the one the form was opened with.
    await ack(response_action="update", view=_hub(channel_id, config_name))


async def _submit_row(app: AsyncApp, ack, view: dict, values: dict, target: dict,
                      kind: str) -> None:
    channel_id, config_name = target['channel_id'], target['config_name']
    section = "conditions" if kind == views.VIEW_CONDITION_ROW else "buttons"
    index = target.get('row')
    index = 0 if index is None else index
    block_ids = _submitted_block_ids(view)
    if section == "conditions":
        row = fields.read_condition_row(values)
        landing = fields.condition_row_error_block(block_ids, row.get('operator', ""))
    else:
        row = fields.read_button_row(values)
        landing = fields.button_row_error_block(block_ids, row.get('label', ""))
    ok, errors = await _apply_rows(app, channel_id, config_name, section, index, row)
    if not ok:
        await ack(response_action="errors",
                  errors=_errors_for(view, errors, f"{section}.{index}", landing))
        return
    await ack(response_action="update", view=_list_view(channel_id, config_name, section))


async def _submit_name(app: AsyncApp, ack, view: dict, values: dict, target: dict,
                       kind: str) -> None:
    channel_id, config_name = target['channel_id'], target['config_name']
    name = fields.read_block(values, fields.block_id(fields.BLOCK_NAME))
    name = str(name or "").strip()
    if kind == views.VIEW_NEW_RULE:
        ok, message = await webui_backend.ui_create_config(app, channel_id, name)
    else:
        ok, message = await webui_backend.ui_rename_config(app, channel_id, config_name, name)
    if not ok:
        await ack(response_action="errors",
                  errors={fields.block_id(fields.BLOCK_NAME): message})
        return
    await ack(response_action="update", view=_hub(channel_id, name))


# --- block_suggestion -----------------------------------------------------------------

async def handle_options(app: AsyncApp, ack, body: dict) -> None:
    """Options for an `external_select`. Teams are the only unbounded list."""
    parts = _parts(body.get('action_id') or "")
    query = str(body.get('value') or "").strip().casefold()
    if len(parts) < 2 or parts[0] != 'options':
        await ack(options=[])
        return
    if parts[1] == 'teams':
        teams = webui_backend.ui_meta()['teams']
        matched = [team for team in teams if query in team.casefold()]
        await ack(options=[{"text": {"type": "plain_text", "text": team[:75]}, "value": team}
                           for team in matched[:views.SLACK_OPTION_LIMIT]])
        return
    await ack(options=[])
