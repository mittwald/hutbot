"""Block Kit for the config UI: the Home tab, and every modal it opens.

Pure builders. Nothing here calls Slack, reads `state.channel_config` or writes anything, and
the option lists arrive as the `meta` argument (`webui_backend.ui_meta()`) rather than being
fetched here — so this module needs no mocks to test, and `commands.info` can import it for
the Edit button on `show config` without pulling the whole config-write stack into the
`commands` import graph.

Three kinds of view, and the difference is forced rather than chosen: a view with `input`
blocks needs a submit button, and the Home tab has none. So the Home tab, the rule hub and the
two row lists carry no inputs at all and apply every change immediately; the section forms and
the row forms carry inputs and apply on submit. A list view holding no inputs is also what
makes `views.update` on it lossless — there is nothing typed to throw away.
"""

from . import fields
from .fields import block_id
from .. import buttonutil
from .. import calendarfeed
from .. import conditionutil
from .. import datetimefmt
from .. import state
from ..constants import (
    ACTION_DM_USER,
    ACTION_GROUP_DM,
    ACTION_POST_CHANNEL,
    ACTION_REPLY,
    BUTTON_ACTION_ACK,
    BUTTON_ACTION_CONFIG,
    BUTTON_ACTION_DELAY,
    CONFIG_UI_ACTION_PREFIX,
    CONFIG_UI_VIEW_PREFIX,
    DISABLED_REASON_REMOVED,
    ESCALATION_BUTTON,
    ESCALATION_CONFIG,
    ESCALATION_NONE,
    TRIGGER_CRON,
    TRIGGER_MANUAL,
    TRIGGER_MESSAGE,
)

# Slack's own caps. A view over the block limit is rejected outright; the text limits are
# truncated silently, which is worse, so they are applied here where the text is built.
SLACK_VIEW_BLOCK_LIMIT = 100
SLACK_OPTION_LIMIT = 100
SLACK_VIEW_TITLE_LIMIT = 24
SLACK_BUTTON_TEXT_LIMIT = 75
SLACK_OPTION_TEXT_LIMIT = 75
SLACK_HEADER_TEXT_LIMIT = 150
SLACK_SECTION_TEXT_LIMIT = 3000

# Kept well under `SLACK_VIEW_BLOCK_LIMIT` with room for the surrounding chrome. A channel
# with more rules than this, or a rule with more rows, is a job for the web UI, which has no
# such cap — the last line of the list says so rather than silently dropping the rest.
HOME_RULE_LIMIT = 40
ROW_LIMIT = 80

# Modal `callback_id`s. Only the three kinds that submit need to be told apart; the rest carry
# one so a stray `view_closed` is still recognisable in a log.
VIEW_SECTION = "section"
VIEW_CONDITION_ROW = "cond_row"
VIEW_BUTTON_ROW = "btn_row"
VIEW_NEW_RULE = "new_rule"
VIEW_RENAME_RULE = "rename_rule"
VIEW_HUB = "hub"
VIEW_PICKER = "picker"
VIEW_LIST = "list"
VIEW_NOTICE = "notice"

# Which section each hub row opens, in the order the hub lists them.
SECTION_ORDER = ("trigger", "message", "conditions", "buttons", "filters",
                 "calendar", "opsgenie", "formatting")

SECTION_TITLES = {
    "trigger": "Trigger",
    "message": "Action & message",
    "conditions": "Conditions",
    "buttons": "Buttons",
    "filters": "Filters",
    "calendar": "Calendar",
    "opsgenie": "OpsGenie",
    "formatting": "Date & time",
    "escalation": "Escalation",
}


# --- primitives -----------------------------------------------------------------------

def _clip(text: str, limit: int) -> str:
    text = str(text or "")
    return text if len(text) <= limit else text[:limit - 1] + "…"


def action_id(*parts) -> str:
    """`hutbot_cfg:open:trigger` — the namespace the action listener matches on."""
    return ":".join([CONFIG_UI_ACTION_PREFIX, *(str(part) for part in parts)])


def _callback_id(kind: str) -> str:
    return f"{CONFIG_UI_VIEW_PREFIX}:{kind}"


def _plain(text: str, limit: int = SLACK_OPTION_TEXT_LIMIT) -> dict:
    # Slack rejects an empty plain_text, and a dash reads better than a stray space.
    return {"type": "plain_text", "text": _clip(text, limit) or "—"}


def _mrkdwn(text: str) -> dict:
    return {"type": "mrkdwn", "text": _clip(text, SLACK_SECTION_TEXT_LIMIT) or "—"}


def _header(text: str) -> dict:
    return {"type": "header", "text": _plain(text, SLACK_HEADER_TEXT_LIMIT)}


def _section(text: str, accessory: dict | None = None, block: str = "") -> dict:
    section = {"type": "section", "text": _mrkdwn(text)}
    if accessory is not None:
        section["accessory"] = accessory
    if block:
        section["block_id"] = block
    return section


def _context(*texts: str) -> dict:
    return {"type": "context", "elements": [_mrkdwn(text) for text in texts if text]}


def _divider() -> dict:
    return {"type": "divider"}


def _actions(elements: list[dict], block: str = "") -> dict:
    actions = {"type": "actions", "elements": elements}
    if block:
        actions["block_id"] = block
    return actions


def _input(field: str, element: dict, label: str = "", hint: str = "",
           optional: bool = True) -> dict:
    """One input block, its id fixed by the field it edits.

    The label comes from `fields.FIELD_LABELS` unless overridden, so a form and an error
    prefix naming the same field cannot word it differently.
    """
    block = {
        "type": "input",
        "block_id": block_id(field),
        "label": _plain(label or fields.FIELD_LABELS.get(field, field), SLACK_OPTION_TEXT_LIMIT),
        "element": element,
        "optional": optional,
    }
    if hint:
        block["hint"] = _plain(hint, SLACK_HEADER_TEXT_LIMIT)
    return block


def _option(value: str, text: str = "", description: str = "") -> dict:
    option = {"text": _plain(text or value), "value": str(value)}
    if description:
        option["description"] = _plain(description, SLACK_HEADER_TEXT_LIMIT)
    return option


def _options(values, labels: dict | None = None) -> list[dict]:
    labels = labels or {}
    return [_option(value, labels.get(value, str(value)))
            for value in list(values)[:SLACK_OPTION_LIMIT]]


def _initial(options: list[dict], value) -> dict | None:
    for option in options:
        if option["value"] == str(value):
            return option
    return None


def _select(field: str, options: list[dict], value=None, placeholder: str = "",
            dispatch: bool = False) -> dict:
    element = {"type": "static_select", "action_id": action_id("field", field), "options": options}
    chosen = _initial(options, value)
    if chosen is not None:
        element["initial_option"] = chosen
    if placeholder:
        element["placeholder"] = _plain(placeholder)
    if dispatch:
        # Re-renders the form, which is how a form shows only the fields the chosen value
        # actually uses instead of every field the section could hold.
        element["action_id"] = action_id("render", field)
    return element


def _multi_select(field: str, options: list[dict], values=None) -> dict:
    element = {"type": "multi_static_select", "action_id": action_id("field", field),
               "options": options, "placeholder": _plain("None")}
    chosen = [option for option in options if option["value"] in set(values or [])]
    if chosen:
        element["initial_options"] = chosen
    return element


def _multi_external_select(field: str, values=None) -> dict:
    element = {"type": "multi_external_select", "action_id": action_id("options", field),
               "min_query_length": 0, "placeholder": _plain("None")}
    if values:
        element["initial_options"] = [_option(value) for value in values]
    return element


def _checkboxes(field: str, label: str = "", checked: bool = False,
                dispatch: bool = False) -> dict:
    option = _option("on", label or fields.FIELD_LABELS.get(field, field))
    element = {"type": "checkboxes", "action_id": action_id("field", field), "options": [option]}
    if checked:
        element["initial_options"] = [option]
    if dispatch:
        element["action_id"] = action_id("render", field)
    return element


def _text_input(field: str, value: str = "", multiline: bool = False, placeholder: str = "",
                dispatch: bool = False) -> dict:
    element = {"type": "plain_text_input", "action_id": action_id("field", field)}
    if multiline:
        element["multiline"] = True
    if value:
        element["initial_value"] = str(value)
    if placeholder:
        element["placeholder"] = _plain(placeholder, SLACK_HEADER_TEXT_LIMIT)
    if dispatch:
        element["action_id"] = action_id("render", field)
    return element


def _minutes_input(field: str, seconds, minimum: int = 0) -> dict:
    """Minutes, not seconds — the unit `set wait time` and `set escalation` already use.

    `min_value`/`max_value` make Slack refuse an out-of-range number in the client too; the
    backend's own bounds stay the ones that decide.
    """
    element = {"type": "number_input", "is_decimal_allowed": False,
               "action_id": action_id("field", field),
               "min_value": str(minimum), "max_value": "1440"}
    try:
        element["initial_value"] = str(int(seconds) // 60)
    except (TypeError, ValueError):
        pass
    return element


def _timepicker(field: str, value: str = "") -> dict:
    element = {"type": "timepicker", "action_id": action_id("field", field)}
    if value:
        element["initial_time"] = str(value)
    return element


def _conversations_select(field: str, value: str = "") -> dict:
    element = {"type": "conversations_select", "action_id": action_id("field", field),
               "placeholder": _plain("Pick a channel")}
    if value:
        element["initial_conversation"] = str(value)
    return element


def _users_select(field: str, value: str = "") -> dict:
    element = {"type": "users_select", "action_id": action_id("field", field),
               "placeholder": _plain("Pick a user")}
    if value:
        element["initial_user"] = str(value)
    return element


def _button(text: str, *parts, value: str = "", style: str = "", confirm: dict | None = None) -> dict:
    element = {"type": "button", "text": _plain(text, SLACK_BUTTON_TEXT_LIMIT),
               "action_id": action_id(*parts)}
    if value:
        element["value"] = value
    if style:
        element["style"] = style
    if confirm is not None:
        element["confirm"] = confirm
    return element


def _confirm(title: str, text: str, ok: str = "Delete") -> dict:
    return {"title": _plain(title, SLACK_VIEW_TITLE_LIMIT), "text": _mrkdwn(text),
            "confirm": _plain(ok, SLACK_VIEW_TITLE_LIMIT), "deny": _plain("Cancel"),
            "style": "danger"}


def _overflow(options: list[dict], *parts, confirm: dict | None = None) -> dict:
    element = {"type": "overflow", "action_id": action_id(*parts), "options": options}
    if confirm is not None:
        element["confirm"] = confirm
    return element


def _modal(kind: str, title: str, blocks: list[dict], meta: str, submit: str = "",
           close: str = "Close") -> dict:
    view = {
        "type": "modal",
        "callback_id": _callback_id(kind),
        "title": _plain(title, SLACK_VIEW_TITLE_LIMIT),
        "close": _plain(close, SLACK_VIEW_TITLE_LIMIT),
        "private_metadata": meta,
        "blocks": blocks[:SLACK_VIEW_BLOCK_LIMIT],
    }
    if submit:
        view["submit"] = _plain(submit, SLACK_VIEW_TITLE_LIMIT)
    return view


# --- summaries ------------------------------------------------------------------------

def _rule_state(config: dict) -> str:
    if config.get('enabled', True):
        return "Active"
    if config.get('disabled_reason') == DISABLED_REASON_REMOVED:
        return "Disabled — the bot was removed from the channel"
    return "Disabled"


def _trigger_summary(config: dict) -> str:
    trigger = config.get('trigger', TRIGGER_MESSAGE)
    if trigger == TRIGGER_CRON:
        return f"on schedule `{config.get('cron') or '—'}`"
    if trigger == TRIGGER_MANUAL:
        return "when run by hand"
    minutes = int(config.get('wait_time') or 0) // 60
    return f"on a message, after {minutes} min"


def _action_summary(config: dict) -> str:
    action = config.get('action', ACTION_REPLY)
    target = config.get('action_target') or ""
    if action == ACTION_POST_CHANNEL:
        return f"post to <#{target}>" if target.startswith('C') else f"post to `{target}`"
    if action == ACTION_DM_USER:
        return f"DM <@{target}>" if target.startswith('U') else f"DM `{target}`"
    if action == ACTION_GROUP_DM:
        return f"group DM `{target}`"
    return "reply in thread"


def rule_summary(config: dict) -> str:
    """The one-line "what this rule does" the hub and the Home tab both print."""
    parts = [_trigger_summary(config)]
    conditions = config.get('conditions') or []
    if conditions:
        mode = config.get('conditions_mode', 'all')
        parts.append(f"{len(conditions)} condition{'s' if len(conditions) != 1 else ''} ({mode})")
    parts.append(_action_summary(config))
    buttons = config.get('buttons') or []
    if buttons:
        parts.append(f"{len(buttons)} button{'s' if len(buttons) != 1 else ''}")
    timeout = int(config.get('escalation_timeout') or 0)
    if timeout and config.get('escalation_kind') != ESCALATION_NONE:
        parts.append(f"escalates after {timeout // 60} min")
    return " → ".join(parts)


def _escalation_summary(config: dict) -> str:
    kind = config.get('escalation_kind', ESCALATION_NONE)
    timeout = int(config.get('escalation_timeout') or 0)
    if not timeout or kind == ESCALATION_NONE:
        return "No escalation: an unpressed message stays unpressed."
    target = config.get('escalation_target') or "—"
    minutes = timeout // 60
    if kind == ESCALATION_BUTTON:
        return f"After {minutes} min, press *{target}* automatically."
    return f"After {minutes} min, run `{target}`."


def _condition_summary(condition: dict) -> str:
    return conditionutil.describe_condition(condition, code=True)


def _button_summary(button: dict) -> str:
    label = button.get('label') or "—"
    action, value = buttonutil.normalize_button(button)
    if action == BUTTON_ACTION_CONFIG:
        return f"*{label}* — runs `{value}`"
    if action == BUTTON_ACTION_DELAY:
        return f"*{label}* — postpones the escalation by {value} min"
    return f"*{label}* — acknowledges" + (f", posting “{_clip(value, 120)}”" if value else "")


def _section_summary(section: str, config: dict) -> str:
    """What a hub row says about the section it opens."""
    if section == "trigger":
        return _trigger_summary(config).capitalize()
    if section == "message":
        return f"{_action_summary(config)} — “{_clip(config.get('reply_message') or '', 120)}”"
    if section == "conditions":
        conditions = config.get('conditions') or []
        if not conditions:
            return "No conditions: the rule always fires."
        return f"{len(conditions)} condition{'s' if len(conditions) != 1 else ''}, " \
               f"{config.get('conditions_mode', 'all')} must match"
    if section == "buttons":
        buttons = config.get('buttons') or []
        counted = (f"{len(buttons)} button{'s' if len(buttons) != 1 else ''}" if buttons
                   else "No buttons")
        return f"{counted}. {_escalation_summary(config)}"
    if section == "filters":
        parts = []
        if config.get('pattern'):
            parts.append(f"pattern `{_clip(config['pattern'], 60)}`")
        if config.get('hours'):
            parts.append(f"{config['hours'][0]}–{config['hours'][1]}")
        if config.get('only_work_days'):
            parts.append("work days only")
        if config.get('include_bots'):
            parts.append("bots included")
        if config.get('included_teams'):
            parts.append("only " + ", ".join(config['included_teams']))
        if config.get('excluded_teams'):
            parts.append("except " + ", ".join(config['excluded_teams']))
        return ", ".join(parts).capitalize() if parts else "No filters: every message counts."
    if section == "calendar":
        if config.get('calendar_builtin'):
            return f"Built-in calendar `{config['calendar_builtin']}`"
        if config.get('calendar_url'):
            return f"Feed at {calendarfeed.describe_calendar_url(config['calendar_url'])}"
        return "No calendar feed."
    if section == "opsgenie":
        if not config.get('opsgenie'):
            return "No OpsGenie alert."
        schedule = config.get('opsgenie_schedule_name') or "—"
        return f"Alerts schedule `{schedule}` at {config.get('opsgenie_priority')}"
    if section == "formatting":
        parts = [part for part in (config.get('date_format'), config.get('time_format'),
                                   config.get('datetime_timezone'), config.get('datetime_locale'))
                 if part]
        if config.get('debug'):
            parts.append("debug logging on")
        return ", ".join(parts) if parts else "Instance defaults."
    return ""


# --- the Edit button on `show config` --------------------------------------------------

def edit_config_blocks(channel_id: str) -> list[dict]:
    """The one actions block appended to `show config`, or nothing when there is nothing to edit."""
    if not channel_id:
        return []
    return [_actions([_button("Edit in Slack", "pick_rule", value=fields.encode_meta(channel_id))],
                     block="hutbot_cfg_edit")]


# --- the Home tab ---------------------------------------------------------------------

def home_view(meta: dict, channel_id: str, channels: list, configs: dict) -> dict:
    """The App Home tab: one channel's rules, with a picker for the others.

    `channels` is `[(channel_id, name), …]`, already filtered to the ones the viewer is in.
    """
    bot_name = meta.get('bot_name') or state.bot_name
    command = meta.get('slash_command') or state.slash_command
    blocks: list[dict] = [_header(f"{bot_name} — configuration")]

    if not channels:
        blocks.append(_section(
            f"I have no configuration in any channel you are in yet.\n"
            f"Invite me to a channel and run `{command} help` to get started."))
        return {"type": "home", "private_metadata": fields.encode_meta(""), "blocks": blocks}

    options = [_option(cid, f"#{name}") for cid, name in channels[:SLACK_OPTION_LIMIT]]
    picker = {"type": "static_select", "action_id": action_id("channel"), "options": options}
    chosen = _initial(options, channel_id)
    if chosen is not None:
        picker["initial_option"] = chosen
    blocks.append(_actions([picker, _button("Refresh", "refresh",
                                            value=fields.encode_meta(channel_id))]))

    if not configs:
        blocks.append(_section(f"No rules in <#{channel_id}> yet."))
    else:
        blocks.append(_context(f"Rules in <#{channel_id}>. Changes here apply immediately."))
    blocks.append(_divider())

    for name in sorted(configs)[:HOME_RULE_LIMIT]:
        config = configs[name]
        row_meta = fields.encode_meta(channel_id, name)
        blocks.append(_section(f"*`{name}`* — {_rule_state(config)}",
                               accessory=_button("Edit", "rule", value=row_meta)))
        blocks.append(_context(rule_summary(config)))
    if len(configs) > HOME_RULE_LIMIT:
        blocks.append(_context(f"…and {len(configs) - HOME_RULE_LIMIT} more. "
                               f"The web UI shows them all."))

    blocks.append(_divider())
    blocks.append(_actions([_button("New rule", "new_rule",
                                    value=fields.encode_meta(channel_id))]))
    blocks.append(_context(f"`{command} help` lists the same settings as commands."))
    return {"type": "home", "private_metadata": fields.encode_meta(channel_id),
            "blocks": blocks[:SLACK_VIEW_BLOCK_LIMIT]}


# --- the rule picker and the hub -------------------------------------------------------

def picker_view(meta: dict, channel_id: str, config_names) -> dict:
    """Which rule to edit — the modal the Edit button on `show config` opens."""
    blocks: list[dict] = [_section(f"Rules in <#{channel_id}>:")]
    for name in sorted(config_names)[:HOME_RULE_LIMIT]:
        blocks.append(_section(f"*`{name}`*", accessory=_button(
            "Edit", "rule", value=fields.encode_meta(channel_id, name))))
    return _modal(VIEW_PICKER, "Pick a rule", blocks, fields.encode_meta(channel_id))


def hub_view(meta: dict, channel_id: str, config_name: str, config: dict) -> dict:
    """One rule, section by section. Every control here applies immediately."""
    rule_meta = fields.encode_meta(channel_id, config_name)
    enabled = config.get('enabled', True)
    blocks: list[dict] = [
        _section(f"*`{config_name}`* in <#{channel_id}>\n{_rule_state(config)}",
                 accessory=_button("Disable" if enabled else "Enable", "toggle_enabled",
                                   value=rule_meta, style="" if enabled else "primary")),
        _context(rule_summary(config)),
        _divider(),
    ]
    for section in SECTION_ORDER:
        blocks.append(_section(f"*{SECTION_TITLES[section]}*\n{_section_summary(section, config)}",
                               accessory=_button("Edit", "open", section, value=rule_meta)))
    blocks.append(_divider())

    row: list[dict] = []
    if config_name != meta.get('default_config_name'):
        # The default rule is the one every command falls back to; renaming or deleting it
        # would leave the channel without one.
        row.append(_button("Rename", "rename", value=rule_meta))
        row.append(_button("Delete", "delete", value=rule_meta, style="danger",
                           confirm=_confirm("Delete rule", f"Delete `{config_name}` for good?")))
    row.append(_button("Run now", "run", value=rule_meta))
    blocks.append(_actions(row))
    return _modal(VIEW_HUB, "Rule", blocks, rule_meta)


def notice_view(title: str, text: str, meta_raw: str = "") -> dict:
    """A modal that only says something — a rule that vanished mid-edit, a refused action."""
    return _modal(VIEW_NOTICE, title, [_section(text)], meta_raw or fields.encode_meta(""))


def name_view(meta: dict, channel_id: str, config_name: str = "") -> dict:
    """New rule, or rename an existing one — the same single field either way."""
    renaming = bool(config_name)
    hint = "Letters, numbers, and - _ . : / only."
    blocks = [_input(fields.BLOCK_NAME,
                     _text_input(fields.BLOCK_NAME, config_name, placeholder="nightly"),
                     label="New name" if renaming else "Name", hint=hint, optional=False)]
    if renaming:
        blocks.append(_context(f"Everything pointing at `{config_name}` is renamed with it."))
    return _modal(VIEW_RENAME_RULE if renaming else VIEW_NEW_RULE,
                  "Rename rule" if renaming else "New rule", blocks,
                  fields.encode_meta(channel_id, config_name), submit="Save")


# --- section forms --------------------------------------------------------------------

def _trigger_blocks(meta: dict, config: dict) -> list[dict]:
    trigger = config.get('trigger', TRIGGER_MESSAGE)
    labels = {TRIGGER_MESSAGE: "On a message", TRIGGER_CRON: "On a schedule",
              TRIGGER_MANUAL: "Only when run by hand"}
    blocks = [_input("trigger", _select("trigger", _options(meta['triggers'], labels), trigger,
                                        dispatch=True), optional=False)]
    # Only the field the chosen trigger actually uses: `fields.read_section_values` leaves out
    # what the form did not show, so the other one keeps its stored value.
    if trigger == TRIGGER_CRON:
        blocks.append(_input("cron", _text_input("cron", config.get('cron') or "",
                                                 placeholder="0 9 * * 1-5"),
                             hint="Five fields, in the rule's time zone.", optional=False))
    elif trigger == TRIGGER_MESSAGE:
        blocks.append(_input("wait_time", _minutes_input("wait_time", config.get('wait_time'), 1),
                             label="Reminder delay (minutes)",
                             hint="How long an unanswered message waits.", optional=False))
    return blocks


def _message_blocks(meta: dict, config: dict) -> list[dict]:
    action = config.get('action', ACTION_REPLY)
    target = config.get('action_target') or ""
    templated = "{{" in target
    labels = {ACTION_REPLY: "Reply in the thread", ACTION_DM_USER: "DM a user",
              ACTION_GROUP_DM: "Open a group DM", ACTION_POST_CHANNEL: "Post in a channel"}
    blocks = [_input("action", _select("action", _options(meta['actions'], labels), action,
                                      dispatch=True), optional=False)]
    if action != ACTION_REPLY:
        blocks.append(_input(fields.BLOCK_TARGET_TEMPLATE,
                             _checkboxes(fields.BLOCK_TARGET_TEMPLATE,
                                         label="Set the target from a {{variable}}",
                                         checked=templated, dispatch=True),
                             label="Target"))
        # A `post_channel` target has to be one `targets.parse_channel_ref` accepts, so it is
        # a select rather than free text — the same for a user. Both write into the same
        # block id as the template input, so an error about the target always has a home.
        if templated:
            element = _text_input("action_target", target, placeholder="{{opsgenie_current_user}}")
        elif action == ACTION_POST_CHANNEL:
            element = _conversations_select("action_target", target)
        elif action == ACTION_DM_USER:
            element = _users_select("action_target", target)
        else:
            element = _text_input("action_target", target, placeholder="@alice, @bob")
        blocks.append(_input("action_target", element, optional=False))
    blocks.append(_input("reply_message",
                         _text_input("reply_message", config.get('reply_message') or "",
                                     multiline=True),
                         hint="`{{variables}}` and @mentions are resolved when it is sent.",
                         optional=False))
    return blocks


def _filters_blocks(meta: dict, config: dict) -> list[dict]:
    hours = config.get('hours') or ["", ""]
    included, excluded = config.get('included_teams') or [], config.get('excluded_teams') or []
    mode = (fields.TEAM_MODE_ONLY if included else
            fields.TEAM_MODE_EXCEPT if excluded else fields.TEAM_MODE_ALL)
    mode_labels = {fields.TEAM_MODE_ALL: "Everyone", fields.TEAM_MODE_ONLY: "Only these teams",
                   fields.TEAM_MODE_EXCEPT: "Everyone except these teams"}
    return [
        _input("pattern", _text_input("pattern", config.get('pattern') or "",
                                      placeholder="urgent|incident"),
               hint="A regular expression. Empty means every message."),
        _input("pattern_case_sensitive",
               _checkboxes("pattern_case_sensitive", label="Match case",
                           checked=bool(config.get('pattern_case_sensitive'))),
               label="Pattern case"),
        _input("include_bots", _checkboxes("include_bots", label="Also watch messages from bots",
                                           checked=bool(config.get('include_bots'))),
               label="Bots"),
        _input("only_work_days", _checkboxes("only_work_days", label="Only Monday to Friday",
                                             checked=bool(config.get('only_work_days'))),
               label="Work days"),
        _input("hours", _timepicker("hours", hours[0]), label="Work hours from"),
        _input(fields.BLOCK_HOURS_END, _timepicker(fields.BLOCK_HOURS_END, hours[1]),
               label="Work hours until", hint="Leave both empty to watch around the clock."),
        _input(fields.BLOCK_TEAM_MODE,
               _select(fields.BLOCK_TEAM_MODE,
                       _options([fields.TEAM_MODE_ALL, fields.TEAM_MODE_ONLY,
                                 fields.TEAM_MODE_EXCEPT], mode_labels), mode),
               label="Whose messages count", optional=False),
        _input("included_teams", _multi_external_select("teams", included or excluded),
               label="Teams", hint="Ignored when the filter above is “Everyone”."),
    ]


def _escalation_blocks(meta: dict, config: dict) -> list[dict]:
    kind = config.get('escalation_kind', ESCALATION_NONE)
    labels = {ESCALATION_NONE: "Nothing", ESCALATION_BUTTON: "Press one of the buttons",
              ESCALATION_CONFIG: "Run other rules"}
    blocks = [
        _input("escalation_kind",
               _select("escalation_kind",
                       _options([ESCALATION_NONE, ESCALATION_BUTTON, ESCALATION_CONFIG], labels),
                       kind, dispatch=True),
               label="When nobody presses a button", optional=False),
    ]
    if kind == ESCALATION_NONE:
        blocks.append(_context("An escalation needs buttons on the message to escalate from."))
        return blocks
    blocks.append(_input("escalation_timeout",
                         _minutes_input("escalation_timeout", config.get('escalation_timeout'), 1),
                         label="Wait (minutes)", optional=False))
    if kind == ESCALATION_BUTTON:
        button_labels = [button.get('label') or "" for button in (config.get('buttons') or [])]
        blocks.append(_input("escalation_target",
                             _select("escalation_target", _options(button_labels),
                                     config.get('escalation_target')),
                             label="Press this button", optional=False))
    else:
        names = buttonutil.parse_config_list(config.get('escalation_target') or "")
        blocks.append(_input("escalation_target",
                             _multi_select("escalation_target",
                                           _options(meta.get('config_names') or names), names),
                             label="Run these rules", optional=False))
        blocks.append(_context("They run in the order listed."))
    return blocks


def _opsgenie_blocks(meta: dict, config: dict) -> list[dict]:
    blocks = []
    if not meta.get('opsgenie_configured'):
        blocks.append(_context("This instance has no OpsGenie credentials, so an alert "
                               "cannot be sent even with this switched on."))
    blocks.append(_input("opsgenie", _checkboxes("opsgenie", label="Raise an OpsGenie alert",
                                                 checked=bool(config.get('opsgenie'))),
                         label="Alert"))
    blocks.append(_input("opsgenie_schedule_name",
                         _text_input("opsgenie_schedule_name",
                                     config.get('opsgenie_schedule_name') or ""),
                         hint="Whose on-call the alert goes to."))
    blocks.append(_input("opsgenie_priority",
                         _select("opsgenie_priority", _options(meta['opsgenie_priorities']),
                                 config.get('opsgenie_priority')), optional=False))
    blocks.append(_input("opsgenie_message",
                         _text_input("opsgenie_message", config.get('opsgenie_message') or "",
                                     multiline=True),
                         hint="Empty sends the original message."))
    return blocks


def _calendar_blocks(meta: dict, config: dict) -> list[dict]:
    calendars = [_option(entry['name'], entry['title']) for entry in meta.get('calendars') or []]
    stored = config.get('calendar_url') or ""
    return [
        _input("calendar_builtin",
               _select("calendar_builtin", [_option("", "None"), *calendars],
                       config.get('calendar_builtin') or "", dispatch=True),
               hint="One of this instance's calendars, no URL needed."),
        _input("calendar_url",
               _text_input("calendar_url", calendarfeed.describe_calendar_url(stored),
                           placeholder="https://outlook.office365.com/…/calendar.ics"),
               hint="Shown shortened because the link is a secret; leave it as it is to keep "
                    "the stored one, or clear it to remove it."),
        _context("A built-in calendar or a URL, never both."),
    ]


def _formatting_blocks(meta: dict, config: dict) -> list[dict]:
    return [
        _input("date_format", _text_input("date_format", config.get('date_format') or "",
                                          placeholder="%a, %d %b %Y")),
        _input("time_format", _text_input("time_format", config.get('time_format') or "",
                                          placeholder="%H:%M")),
        _input("datetime_timezone",
               _text_input("datetime_timezone", config.get('datetime_timezone') or "",
                           placeholder="Europe/Berlin"),
               hint=f"Empty uses the instance default ({datetimefmt.describe_timezone()})."),
        _input("datetime_locale",
               _text_input("datetime_locale", config.get('datetime_locale') or "",
                           placeholder="de_DE")),
        _input("debug", _checkboxes("debug", label="Log every decision for this rule",
                                    checked=bool(config.get('debug'))),
               label="Debug logging"),
    ]


_SECTION_BLOCKS = {
    "trigger": _trigger_blocks,
    "message": _message_blocks,
    "filters": _filters_blocks,
    "escalation": _escalation_blocks,
    "opsgenie": _opsgenie_blocks,
    "calendar": _calendar_blocks,
    "formatting": _formatting_blocks,
}


def section_view(meta: dict, channel_id: str, config_name: str, section: str,
                 config: dict) -> dict:
    """One section's form. Applies on submit, as a whole config document."""
    blocks = _SECTION_BLOCKS[section](meta, config)
    return _modal(VIEW_SECTION, SECTION_TITLES[section], blocks,
                  fields.encode_meta(channel_id, config_name, section), submit="Save")


def first_input_block(view: dict) -> str:
    """Which block a leftover error is folded onto: the form's first input.

    Always present in a form view, and near the top where the user is looking.
    """
    for block in view.get('blocks') or []:
        if block.get('type') == 'input':
            return block.get('block_id') or ""
    return ""


def view_block_ids(view: dict) -> list[str]:
    return [block['block_id'] for block in view.get('blocks') or [] if block.get('block_id')]


# --- row lists and row forms ----------------------------------------------------------

def conditions_view(meta: dict, channel_id: str, config_name: str, config: dict) -> dict:
    """The condition rows, each with its own edit and delete. No inputs, so no submit."""
    rule_meta = fields.encode_meta(channel_id, config_name)
    conditions = config.get('conditions') or []
    modes = _options(meta['condition_modes'],
                     {"all": "All must match", "any": "Any may match"})
    mode = _initial(modes, config.get('conditions_mode')) or modes[0]
    blocks: list[dict] = [
        _section(f"*`{config_name}`* — conditions gate every trigger."),
        _actions([
            {"type": "static_select", "action_id": action_id("field", "conditions_mode"),
             "options": modes, "initial_option": mode},
            _button("Add condition", "row", "conditions", "add", value=rule_meta),
        ]),
        _divider(),
    ]
    if not conditions:
        blocks.append(_section("_No conditions, so the rule always fires._"))
    for index, condition in enumerate(conditions[:ROW_LIMIT]):
        row = _section(f"{index + 1}. {_condition_summary(condition)}", accessory=_overflow([
            _option(f"edit:{index}", "Edit"), _option(f"delete:{index}", "Delete"),
        ], "row", "conditions", "menu", index))
        # The confirm sits on the menu, so the destructive half of it is guarded without a
        # modal of its own — and the harmless Edit option in the same menu is not.
        row["accessory"]["confirm"] = _confirm("Delete condition", f"Delete condition {index + 1}?")
        row["block_id"] = f"cond:{index}"
        blocks.append(row)
    if len(conditions) > ROW_LIMIT:
        blocks.append(_context(f"…and {len(conditions) - ROW_LIMIT} more. "
                               f"The web UI shows them all."))
    blocks.append(_divider())
    blocks.append(_actions([_button("Back to the rule", "nav", "hub", value=rule_meta)]))
    return _modal(VIEW_LIST, "Conditions", blocks,
                  fields.encode_meta(channel_id, config_name, "conditions"))


def buttons_view(meta: dict, channel_id: str, config_name: str, config: dict) -> dict:
    """The button rows, plus the escalation they cross-check with."""
    rule_meta = fields.encode_meta(channel_id, config_name)
    buttons = config.get('buttons') or []
    blocks: list[dict] = [
        _section(f"*`{config_name}`* — buttons on the message it sends."),
        _actions([
            _button("Add button", "row", "buttons", "add", value=rule_meta),
            _button("Escalation…", "open", "escalation", value=rule_meta),
        ]),
        _context(_escalation_summary(config)),
        _divider(),
    ]
    if not buttons:
        blocks.append(_section("_No buttons, so nothing to press and nothing to escalate._"))
    for index, button in enumerate(buttons[:ROW_LIMIT]):
        row = _section(f"{index + 1}. {_button_summary(button)}", accessory=_overflow([
            _option(f"edit:{index}", "Edit"), _option(f"delete:{index}", "Delete"),
        ], "row", "buttons", "menu", index))
        row["accessory"]["confirm"] = _confirm("Delete button", f"Delete button {index + 1}?")
        row["block_id"] = f"btn:{index}"
        blocks.append(row)
    if len(buttons) > ROW_LIMIT:
        blocks.append(_context(f"…and {len(buttons) - ROW_LIMIT} more. "
                               f"The web UI shows them all."))
    blocks.append(_divider())
    blocks.append(_actions([_button("Back to the rule", "nav", "hub", value=rule_meta)]))
    return _modal(VIEW_LIST, "Buttons", blocks,
                  fields.encode_meta(channel_id, config_name, "buttons"))


def condition_row_view(meta: dict, channel_id: str, config_name: str, row: int,
                       condition: dict) -> dict:
    """One condition, in its own form. Its submit is the write."""
    variable, operator, value, case_sensitive, at, offset = \
        conditionutil.normalize_condition(condition or {})
    with_moment = set(meta.get('template_variables_with_moment') or [])
    with_offset = set(meta.get('template_variables_with_selector') or [])
    without_value = set(meta.get('condition_operators_without_value') or [])
    blocks = [
        _input("variable", _select("variable", _options(meta['template_variables']), variable,
                                   placeholder="Pick a variable", dispatch=True), optional=False),
        _input("operator", _select("operator", _options(meta['condition_operators']), operator,
                                  placeholder="Pick an operator", dispatch=True), optional=False),
    ]
    # No value input for an operator that compares nothing, and no moment or offset for a
    # variable that has none — the backend refuses those combinations, so offering them would
    # only invite the error.
    if operator not in without_value:
        blocks.append(_input("value", _text_input("value", value)))
        blocks.append(_input("case_sensitive",
                             _checkboxes("case_sensitive", label="Match case",
                                         checked=bool(case_sensitive)),
                             label="Case"))
    if variable in with_moment:
        blocks.append(_input("at", _text_input("at", at, placeholder="09:00"),
                             hint="Which moment to read, e.g. `09:00` or `tomorrow 09:00`."))
    if variable in with_offset:
        blocks.append(_input("offset", _text_input("offset", offset, placeholder="+1"),
                             hint="Which event, counted from the one at that moment."))
    blocks.append(_context(f"Reads as: {_condition_summary({'variable': variable, 'operator': operator, 'value': value, 'case_sensitive': case_sensitive, 'at': at, 'offset': offset})}"))
    title = "Condition" if condition else "New condition"
    return _modal(VIEW_CONDITION_ROW, title, blocks,
                  fields.encode_meta(channel_id, config_name, "conditions", row), submit="Save")


def button_row_view(meta: dict, channel_id: str, config_name: str, row: int,
                    button: dict) -> dict:
    """One button, in its own form. Its submit is the write."""
    button = button or {}
    label = button.get('label') or ""
    action, value = buttonutil.normalize_button(button)
    labels = {BUTTON_ACTION_CONFIG: "Run other rules", BUTTON_ACTION_ACK: "Acknowledge",
              BUTTON_ACTION_DELAY: "Postpone the escalation"}
    blocks = [
        _input("label", _text_input("label", label, placeholder="Escalate"), optional=False),
        _input("action", _select("action", _options(meta['button_actions'], labels), action,
                                dispatch=True), label="On press", optional=False),
    ]
    if action == BUTTON_ACTION_CONFIG:
        names = buttonutil.parse_config_list(value)
        blocks.append(_input("value",
                             _multi_select("value", _options(meta.get('config_names') or names),
                                           names),
                             label="Rules to run", hint="They run in the order listed.",
                             optional=False))
    elif action == BUTTON_ACTION_DELAY:
        blocks.append(_input("value", {"type": "number_input", "is_decimal_allowed": False,
                                       "action_id": action_id("field", "value"),
                                       "min_value": "1", "max_value": "1440",
                                       **({"initial_value": value} if value.isdigit() else {})},
                             label="Postpone by (minutes)", optional=False))
        blocks.append(_context("Needs an escalation to postpone."))
    else:
        blocks.append(_input("value", _text_input("value", value, multiline=True),
                             label="Text to post", hint="Empty just dismisses the message."))
    title = "Button" if label else "New button"
    return _modal(VIEW_BUTTON_ROW, title, blocks,
                  fields.encode_meta(channel_id, config_name, "buttons", row), submit="Save")
