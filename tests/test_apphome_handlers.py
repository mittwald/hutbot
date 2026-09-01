"""The Slack side of the config UI: authorization, what gets written, and what is acked."""

from tests._common import *

import copy

from hutbot.constants import TRIGGER_MESSAGE
from hutbot.apphome import handlers, views, fields
from hutbot.apphome.fields import block_id


CHANNEL = "C12345"
USER = "U1"


def _app():
    app = AsyncMock()
    app.client = AsyncMock()
    return app


def _seed(configs=None):
    _seed_user_caches()
    hutbot.state.channel_config[CHANNEL] = configs if configs is not None else {
        "default": copy.deepcopy(DEFAULT_CONFIG)}
    return hutbot.state.channel_config[CHANNEL]


@contextlib.contextmanager
def _slack(member=True):
    """Every Slack lookup the handlers make, answered from memory."""
    with patch('hutbot.slackcache.is_user_in_channel', new=AsyncMock(return_value=member)), \
         patch('hutbot.slackcache.get_channel_name', new=AsyncMock(return_value="general")), \
         patch('hutbot.slackcache.get_user_by_id',
               new=AsyncMock(return_value=User(id=USER, name="someuser", real_name="X",
                                               team="Platform"))), \
         patch('hutbot.persistence.save_configuration', new=AsyncMock()):
        yield


def _body(view_meta="", view_id="V1", values=None, callback_id=""):
    view = {"id": view_id, "private_metadata": view_meta,
            "state": {"values": values or {}}}
    if callback_id:
        view["callback_id"] = f"hutbot_cfg_view:{callback_id}"
    body = {"user": {"id": USER}, "trigger_id": "T1"}
    if view_id or view_meta or values or callback_id:
        body["view"] = view
    return body


def _action(action_id, value=None, selected=None):
    action = {"action_id": action_id}
    if value is not None:
        action["value"] = value
    if selected is not None:
        action["selected_option"] = {"value": selected}
    return action


def _element(field, payload):
    return {block_id(field): {f"hutbot_cfg:field:{field}": payload}}


def _plain(text):
    return {"type": "plain_text_input", "value": text}


def _option(value):
    return {"type": "static_select", "selected_option": {"value": value}}


def _published(app):
    return app.client.views_publish.await_args.kwargs["view"]


# --- the Home tab ---------------------------------------------------------------------

@pytest.mark.asyncio
async def test_opening_the_home_tab_publishes_it():
    app = _app()
    _seed()
    with _slack():
        await handlers.handle_app_home_opened(app, {"tab": "home", "user": USER})
    view = _published(app)
    assert view["type"] == "home"
    assert hutbot.state.home_tab_channel[USER] == CHANNEL


@pytest.mark.asyncio
async def test_the_messages_tab_publishes_nothing():
    app = _app()
    _seed()
    with _slack():
        await handlers.handle_app_home_opened(app, {"tab": "messages", "user": USER})
    app.client.views_publish.assert_not_awaited()


@pytest.mark.asyncio
async def test_the_home_tab_remembers_the_channel_across_a_restart_from_its_own_metadata():
    app = _app()
    _seed()
    hutbot.state.channel_config["C99999"] = {"other": copy.deepcopy(DEFAULT_CONFIG)}
    with _slack():
        await handlers.handle_app_home_opened(app, {
            "tab": "home", "user": USER,
            "view": {"private_metadata": fields.encode_meta("C99999")}})
    assert hutbot.state.home_tab_channel[USER] == "C99999"


@pytest.mark.asyncio
async def test_a_remembered_channel_the_user_left_falls_back_to_one_they_are_in():
    app = _app()
    _seed()
    hutbot.state.home_tab_channel[USER] = "C_GONE"
    with _slack():
        await handlers.handle_app_home_opened(app, {"tab": "home", "user": USER})
    assert hutbot.state.home_tab_channel[USER] == CHANNEL


@pytest.mark.asyncio
async def test_picking_another_channel_republishes_for_it():
    app = _app()
    _seed()
    hutbot.state.channel_config["C99999"] = {"other": copy.deepcopy(DEFAULT_CONFIG)}
    with _slack():
        await handlers.handle_action(app, _body(fields.encode_meta(CHANNEL)),
                                     _action("hutbot_cfg:channel", selected="C99999"))
    assert hutbot.state.home_tab_channel[USER] == "C99999"
    assert "<#C99999>" in json.dumps(_published(app))


@pytest.mark.asyncio
async def test_browsing_the_home_tab_never_adds_a_channel_to_the_stored_config():
    # `slackcache.get_channel_by_id` inserts an empty entry for any channel it is asked
    # about, and `save_configuration` writes the whole tree — so a publish must not use it.
    app = _app()
    _seed()
    with _slack():
        await handlers.handle_app_home_opened(app, {"tab": "home", "user": USER})
        await handlers.handle_action(app, _body(fields.encode_meta(CHANNEL)),
                                     _action("hutbot_cfg:channel", selected="C_UNKNOWN"))
    assert set(hutbot.state.channel_config) == {CHANNEL}


@pytest.mark.asyncio
async def test_a_user_with_no_configured_channels_gets_an_empty_tab_rather_than_an_error():
    app = _app()
    _seed_user_caches()
    with _slack():
        await handlers.handle_app_home_opened(app, {"tab": "home", "user": USER})
    assert _published(app)["type"] == "home"
    assert hutbot.state.home_tab_channel[USER] == ""


@pytest.mark.asyncio
async def test_a_slack_app_without_the_home_tab_enabled_is_logged_once_not_retried():
    app = _app()
    _seed()
    app.client.views_publish.side_effect = SlackApiError("no", {"error": "app_home_disabled"})
    with _slack(), patch('hutbot.apphome.handlers.log_warning') as warned:
        await handlers.handle_app_home_opened(app, {"tab": "home", "user": USER})
    assert app.client.views_publish.await_count == 1
    assert "App Home" in warned.call_args.args[0]


# --- authorization --------------------------------------------------------------------

@pytest.mark.asyncio
async def test_the_edit_button_opens_the_picker_for_a_member():
    app = _app()
    _seed()
    with _slack():
        await handlers.handle_action(app, _body(view_id=""),
                                     _action("hutbot_cfg:pick_rule",
                                             value=fields.encode_meta(CHANNEL)))
    assert app.client.views_open.await_args.kwargs["view"]["title"]["text"] == "Pick a rule"


@pytest.mark.asyncio
async def test_a_non_member_opens_nothing_and_writes_nothing():
    # A modal, and the ephemeral `show config` its button sits on, both outlive the
    # membership they were created with.
    app = _app()
    _seed()
    with _slack(member=False):
        await handlers.handle_action(app, _body(view_id=""),
                                     _action("hutbot_cfg:pick_rule",
                                             value=fields.encode_meta(CHANNEL)))
    app.client.views_open.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_submission_from_someone_who_left_the_channel_is_refused():
    app = _app()
    _seed()
    ack = AsyncMock()
    with _slack(member=False):
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL, "default", "trigger"), callback_id=views.VIEW_SECTION,
            values=_element("trigger", _option(TRIGGER_MESSAGE))))
    assert ack.await_args.kwargs["response_action"] == "update"
    assert hutbot.state.channel_config[CHANNEL]["default"]["trigger"] == TRIGGER_MESSAGE


# --- section submissions --------------------------------------------------------------

@pytest.mark.asyncio
async def test_a_section_save_writes_minutes_as_seconds():
    app = _app()
    configs = _seed()
    ack = AsyncMock()
    values = {**_element("trigger", _option(TRIGGER_MESSAGE)),
              **_element("wait_time", _plain("45"))}
    with _slack():
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL, "default", "trigger"),
            callback_id=views.VIEW_SECTION, values=values))
    assert configs["default"]["wait_time"] == 2700
    assert ack.await_args.kwargs["response_action"] == "update"


@pytest.mark.asyncio
async def test_a_section_save_leaves_the_fields_it_does_not_show_alone():
    app = _app()
    configs = _seed()
    configs["default"]["reply_message"] = "Still here?"
    ack = AsyncMock()
    values = {**_element("trigger", _option(TRIGGER_CRON)),
              **_element("cron", _plain("0 9 * * 1-5"))}
    with _slack():
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL, "default", "trigger"),
            callback_id=views.VIEW_SECTION, values=values))
    assert configs["default"]["cron"] == "0 9 * * 1-5"
    assert configs["default"]["reply_message"] == "Still here?"
    # Not shown by the cron form, so it keeps what it had rather than being blanked.
    assert configs["default"]["wait_time"] == DEFAULT_CONFIG["wait_time"]


@pytest.mark.asyncio
async def test_a_section_save_keeps_the_config_object_the_scheduler_holds():
    # A queued reminder and a pending buttoned message hold this dict by identity; replacing
    # it would leave work in flight editing an object nothing else can see.
    app = _app()
    configs = _seed()
    original = configs["default"]
    ack = AsyncMock()
    with _slack():
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL, "default", "trigger"),
            callback_id=views.VIEW_SECTION,
            values={**_element("trigger", _option(TRIGGER_MESSAGE)),
                    **_element("wait_time", _plain("45"))}))
    assert hutbot.state.channel_config[CHANNEL]["default"] is original


@pytest.mark.asyncio
async def test_a_refused_section_save_acks_errors_and_writes_nothing():
    app = _app()
    configs = _seed()
    ack = AsyncMock()
    with _slack():
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL, "default", "trigger"),
            callback_id=views.VIEW_SECTION,
            values={**_element("trigger", _option(TRIGGER_CRON)),
                    **_element("cron", _plain("not a cron"))}))
    assert ack.await_args.kwargs["response_action"] == "errors"
    assert block_id("cron") in ack.await_args.kwargs["errors"]
    assert configs["default"]["cron"] == ""


@pytest.mark.asyncio
async def test_an_error_about_another_section_is_still_shown_rather_than_saving_nothing():
    app = _app()
    configs = _seed({"default": {**copy.deepcopy(DEFAULT_CONFIG),
                                 "buttons": [{"label": "Ack", "action": "ack", "value": ""}],
                                 "escalation_timeout": 900, "escalation_kind": "button",
                                 "escalation_target": "Gone"}})
    ack = AsyncMock()
    with _slack():
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL, "default", "trigger"),
            callback_id=views.VIEW_SECTION,
            values={**_element("trigger", _option(TRIGGER_MESSAGE)),
                    **_element("wait_time", _plain("45"))}))
    assert ack.await_args.kwargs["response_action"] == "errors"
    folded = " ".join(ack.await_args.kwargs["errors"].values())
    assert "Escalation target" in folded
    assert configs["default"]["wait_time"] == DEFAULT_CONFIG["wait_time"]


@pytest.mark.asyncio
async def test_saving_a_section_of_a_rule_that_vanished_says_so():
    app = _app()
    _seed({})
    ack = AsyncMock()
    with _slack():
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL, "gone", "trigger"),
            callback_id=views.VIEW_SECTION,
            values=_element("trigger", _option(TRIGGER_MESSAGE))))
    folded = " ".join(ack.await_args.kwargs["errors"].values())
    assert "no longer exists" in folded


@pytest.mark.asyncio
async def test_a_calendar_feed_url_survives_a_save_of_another_section():
    app = _app()
    secret = "https://cal.example.com/SECRETTOKEN/rota.ics"
    configs = _seed({"default": {**copy.deepcopy(DEFAULT_CONFIG), "calendar_url": secret}})
    ack = AsyncMock()
    with _slack():
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL, "default", "trigger"),
            callback_id=views.VIEW_SECTION,
            values={**_element("trigger", _option(TRIGGER_MESSAGE)),
                    **_element("wait_time", _plain("45"))}))
    assert configs["default"]["calendar_url"] == secret


@pytest.mark.asyncio
async def test_the_work_hours_pair_is_written_from_two_pickers():
    app = _app()
    configs = _seed()
    ack = AsyncMock()
    values = {**_element("hours", {"type": "timepicker", "selected_time": "09:00"}),
              **_element(fields.BLOCK_HOURS_END, {"type": "timepicker", "selected_time": "17:00"}),
              **_element(fields.BLOCK_TEAM_MODE, _option(fields.TEAM_MODE_ALL))}
    with _slack():
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL, "default", "filters"),
            callback_id=views.VIEW_SECTION, values=values))
    assert configs["default"]["hours"] == ["09:00", "17:00"]


@pytest.mark.asyncio
async def test_one_team_control_writes_the_exclusive_list_it_meant():
    app = _app()
    configs = _seed()
    ack = AsyncMock()
    values = {**_element(fields.BLOCK_TEAM_MODE, _option(fields.TEAM_MODE_EXCEPT)),
              **{block_id("included_teams"): {"hutbot_cfg:options:teams": {
                  "type": "multi_external_select",
                  "selected_options": [{"value": "Platform"}]}}}}
    with _slack():
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL, "default", "filters"),
            callback_id=views.VIEW_SECTION, values=values))
    assert configs["default"]["excluded_teams"] == ["Platform"]
    assert configs["default"]["included_teams"] == []


# --- the enable toggle ----------------------------------------------------------------

@pytest.mark.asyncio
async def test_the_toggle_disables_a_rule():
    app = _app()
    configs = _seed()
    with _slack():
        await handlers.handle_action(app, _body(), _action(
            "hutbot_cfg:toggle_enabled", value=fields.encode_meta(CHANNEL, "default")))
    assert configs["default"]["enabled"] is False


@pytest.mark.asyncio
async def test_the_toggle_really_re_enables_a_rule_the_bot_disabled_itself():
    # `ui_apply_config` guards against a stale save undoing that automatic disable, and only
    # a payload carrying the marker counts as an explicit re-enable. The snapshot carries it.
    app = _app()
    configs = _seed({"default": {**copy.deepcopy(DEFAULT_CONFIG), "enabled": False,
                                 "disabled_reason": DISABLED_REASON_REMOVED}})
    with _slack():
        await handlers.handle_action(app, _body(), _action(
            "hutbot_cfg:toggle_enabled", value=fields.encode_meta(CHANNEL, "default")))
    assert configs["default"]["enabled"] is True
    assert configs["default"]["disabled_reason"] == ""


@pytest.mark.asyncio
async def test_saving_a_section_leaves_an_automatic_disable_standing():
    app = _app()
    configs = _seed({"default": {**copy.deepcopy(DEFAULT_CONFIG), "enabled": False,
                                 "disabled_reason": DISABLED_REASON_REMOVED}})
    ack = AsyncMock()
    with _slack():
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL, "default", "trigger"),
            callback_id=views.VIEW_SECTION,
            values={**_element("trigger", _option(TRIGGER_MESSAGE)),
                    **_element("wait_time", _plain("45"))}))
    assert configs["default"]["enabled"] is False
    assert configs["default"]["disabled_reason"] == DISABLED_REASON_REMOVED


# --- rows -----------------------------------------------------------------------------

def _condition_values(variable="message", operator="contains", value="deploy"):
    return {**_element("variable", _option(variable)),
            **_element("operator", _option(operator)),
            **_element("value", _plain(value)),
            **_element("case_sensitive", {"type": "checkboxes", "selected_options": []})}


@pytest.mark.asyncio
async def test_adding_a_condition_appends_it():
    app = _app()
    configs = _seed()
    ack = AsyncMock()
    with _slack():
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL, "default", "conditions", 0),
            callback_id=views.VIEW_CONDITION_ROW, values=_condition_values()))
    assert configs["default"]["conditions"] == [
        {"variable": "message", "operator": "contains", "value": "deploy",
         "case_sensitive": False}]
    assert ack.await_args.kwargs["view"]["title"]["text"] == "Conditions"


@pytest.mark.asyncio
async def test_editing_one_condition_leaves_the_others_alone():
    app = _app()
    rows = [{"variable": "message", "operator": "contains", "value": f"v{i}",
             "case_sensitive": False} for i in range(3)]
    configs = _seed({"default": {**copy.deepcopy(DEFAULT_CONFIG), "conditions": rows}})
    ack = AsyncMock()
    with _slack():
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL, "default", "conditions", 1),
            callback_id=views.VIEW_CONDITION_ROW, values=_condition_values(value="changed")))
    assert [row["value"] for row in configs["default"]["conditions"]] == ["v0", "changed", "v2"]


@pytest.mark.asyncio
async def test_a_refused_row_edit_lands_on_the_rows_own_block_and_writes_nothing():
    app = _app()
    rows = [{"variable": "message", "operator": "contains", "value": "v0",
             "case_sensitive": False}]
    configs = _seed({"default": {**copy.deepcopy(DEFAULT_CONFIG), "conditions": rows}})
    ack = AsyncMock()
    with _slack():
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL, "default", "conditions", 0),
            callback_id=views.VIEW_CONDITION_ROW,
            values=_condition_values(operator="regex", value="(unclosed")))
    assert ack.await_args.kwargs["response_action"] == "errors"
    assert block_id("value") in ack.await_args.kwargs["errors"]
    assert configs["default"]["conditions"] == rows


@pytest.mark.asyncio
async def test_deleting_a_condition_removes_only_that_row():
    app = _app()
    rows = [{"variable": "message", "operator": "contains", "value": f"v{i}",
             "case_sensitive": False} for i in range(3)]
    configs = _seed({"default": {**copy.deepcopy(DEFAULT_CONFIG), "conditions": rows}})
    with _slack():
        await handlers.handle_action(
            app, _body(fields.encode_meta(CHANNEL, "default", "conditions")),
            _action("hutbot_cfg:row:conditions:menu:1", selected="delete:1"))
    assert [row["value"] for row in configs["default"]["conditions"]] == ["v0", "v2"]


@pytest.mark.asyncio
async def test_deleting_a_row_that_is_already_gone_says_so_instead_of_writing():
    app = _app()
    configs = _seed()
    with _slack():
        await handlers.handle_action(
            app, _body(fields.encode_meta(CHANNEL, "default", "conditions")),
            _action("hutbot_cfg:row:conditions:menu:4", selected="delete:4"))
    assert configs["default"]["conditions"] == []
    assert app.client.views_update.await_args.kwargs["view"]["title"]["text"] == "Not deleted"


@pytest.mark.asyncio
async def test_editing_a_row_opens_its_form_without_writing():
    app = _app()
    rows = [{"variable": "message", "operator": "contains", "value": "v0",
             "case_sensitive": False}]
    configs = _seed({"default": {**copy.deepcopy(DEFAULT_CONFIG), "conditions": rows}})
    with _slack():
        await handlers.handle_action(
            app, _body(fields.encode_meta(CHANNEL, "default", "conditions")),
            _action("hutbot_cfg:row:conditions:menu:0", selected="edit:0"))
    view = app.client.views_update.await_args.kwargs["view"]
    assert fields.decode_meta(view["private_metadata"])["row"] == 0
    assert configs["default"]["conditions"] == rows


@pytest.mark.asyncio
async def test_a_button_row_save_normalizes_its_rule_list():
    app = _app()
    configs = _seed({"default": copy.deepcopy(DEFAULT_CONFIG),
                     "oncall": copy.deepcopy(DEFAULT_CONFIG),
                     "backup": copy.deepcopy(DEFAULT_CONFIG)})
    ack = AsyncMock()
    values = {**_element("label", _plain("Escalate")),
              **_element("action", _option("config")),
              **_element("value", {"type": "multi_static_select",
                                   "selected_options": [{"value": "oncall"},
                                                        {"value": "backup"}]})}
    with _slack():
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL, "default", "buttons", 0),
            callback_id=views.VIEW_BUTTON_ROW, values=values))
    assert configs["default"]["buttons"] == [
        {"label": "Escalate", "action": "config", "value": "oncall, backup"}]


@pytest.mark.asyncio
async def test_a_delay_button_without_an_escalation_is_refused_on_its_own_block():
    app = _app()
    configs = _seed()
    ack = AsyncMock()
    values = {**_element("label", _plain("Later")),
              **_element("action", _option("delay")),
              **_element("value", {"type": "number_input", "value": "15"})}
    with _slack():
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL, "default", "buttons", 0),
            callback_id=views.VIEW_BUTTON_ROW, values=values))
    assert ack.await_args.kwargs["response_action"] == "errors"
    assert block_id("value") in ack.await_args.kwargs["errors"]
    assert configs["default"]["buttons"] == []


@pytest.mark.asyncio
async def test_the_condition_mode_applies_straight_from_the_list():
    app = _app()
    configs = _seed()
    with _slack():
        await handlers.handle_action(
            app, _body(fields.encode_meta(CHANNEL, "default", "conditions")),
            _action("hutbot_cfg:field:conditions_mode", selected=CONDITION_MODE_ANY))
    assert configs["default"]["conditions_mode"] == CONDITION_MODE_ANY


# --- rule lifecycle -------------------------------------------------------------------

@pytest.mark.asyncio
async def test_creating_a_rule_goes_through_the_shared_backend():
    app = _app()
    configs = _seed()
    ack = AsyncMock()
    with _slack():
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL), callback_id=views.VIEW_NEW_RULE,
            values=_element(fields.BLOCK_NAME, _plain("nightly"))))
    assert "nightly" in configs
    assert ack.await_args.kwargs["view"]["title"]["text"] == "Rule"


@pytest.mark.asyncio
async def test_a_reserved_rule_name_is_refused_on_the_name_field():
    app = _app()
    _seed()
    ack = AsyncMock()
    with _slack():
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL), callback_id=views.VIEW_NEW_RULE,
            values=_element(fields.BLOCK_NAME, _plain("export"))))
    assert list(ack.await_args.kwargs["errors"]) == [block_id(fields.BLOCK_NAME)]


@pytest.mark.asyncio
async def test_renaming_a_rule_goes_through_the_shared_backend():
    app = _app()
    configs = _seed({"default": copy.deepcopy(DEFAULT_CONFIG),
                     "nightly": copy.deepcopy(DEFAULT_CONFIG)})
    ack = AsyncMock()
    with _slack():
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL, "nightly"), callback_id=views.VIEW_RENAME_RULE,
            values=_element(fields.BLOCK_NAME, _plain("evening"))))
    assert "evening" in configs and "nightly" not in configs


@pytest.mark.asyncio
async def test_deleting_a_rule_goes_through_the_shared_backend():
    app = _app()
    configs = _seed({"default": copy.deepcopy(DEFAULT_CONFIG),
                     "nightly": copy.deepcopy(DEFAULT_CONFIG)})
    with _slack():
        await handlers.handle_action(app, _body(), _action(
            "hutbot_cfg:delete", value=fields.encode_meta(CHANNEL, "nightly")))
    assert "nightly" not in configs


@pytest.mark.asyncio
async def test_the_default_rule_cannot_be_deleted_even_if_the_action_is_forged():
    app = _app()
    configs = _seed()
    with _slack():
        await handlers.handle_action(app, _body(), _action(
            "hutbot_cfg:delete", value=fields.encode_meta(CHANNEL, "default")))
    assert "default" in configs
    assert app.client.views_update.await_args.kwargs["view"]["title"]["text"] == "Not deleted"


# --- redraw ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_changing_the_trigger_redraws_the_form_without_saving():
    app = _app()
    configs = _seed()
    with _slack():
        await handlers.handle_action(
            app, _body(fields.encode_meta(CHANNEL, "default", "trigger"),
                       values=_element("trigger", _option(TRIGGER_CRON))),
            _action("hutbot_cfg:render:trigger"))
    view = app.client.views_update.await_args.kwargs["view"]
    assert block_id("cron") in views.view_block_ids(view)
    assert configs["default"]["trigger"] == TRIGGER_MESSAGE


@pytest.mark.asyncio
async def test_a_redraw_keeps_what_was_already_typed_in_the_form():
    app = _app()
    _seed()
    values = {**_element("action", _option(ACTION_POST_CHANNEL)),
              **_element("reply_message", _plain("Typed but not saved")),
              **_element("action_target", {"type": "conversations_select",
                                          "selected_conversation": "C99999"})}
    with _slack():
        await handlers.handle_action(
            app, _body(fields.encode_meta(CHANNEL, "default", "message"), values=values),
            _action("hutbot_cfg:render:action"))
    view = app.client.views_update.await_args.kwargs["view"]
    assert "Typed but not saved" in json.dumps(view)


# --- external select options ----------------------------------------------------------

@pytest.mark.asyncio
async def test_team_options_are_filtered_by_what_was_typed():
    app = _app()
    _seed_user_caches()
    ack = AsyncMock()
    await handlers.handle_options(app, ack, {"action_id": "hutbot_cfg:options:teams",
                                             "value": "plat"})
    assert [option["value"] for option in ack.await_args.kwargs["options"]] == ["Platform"]


@pytest.mark.asyncio
async def test_an_unknown_options_request_answers_with_nothing():
    ack = AsyncMock()
    await handlers.handle_options(_app(), ack, {"action_id": "hutbot_cfg:options:nope"})
    assert ack.await_args.kwargs["options"] == []


# --- republishing ---------------------------------------------------------------------

@pytest.mark.asyncio
async def test_a_save_republishes_the_home_tab_of_a_user_who_has_one_open():
    app = _app()
    _seed()
    hutbot.state.home_tab_channel[USER] = CHANNEL
    ack = AsyncMock()
    with _slack():
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL, "default", "trigger"),
            callback_id=views.VIEW_SECTION,
            values={**_element("trigger", _option(TRIGGER_MESSAGE)),
                    **_element("wait_time", _plain("45"))}))
    app.client.views_publish.assert_awaited()


@pytest.mark.asyncio
async def test_a_save_publishes_nothing_for_a_user_who_never_opened_the_home_tab():
    app = _app()
    _seed()
    ack = AsyncMock()
    with _slack():
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL, "default", "trigger"),
            callback_id=views.VIEW_SECTION,
            values={**_element("trigger", _option(TRIGGER_MESSAGE)),
                    **_element("wait_time", _plain("45"))}))
    app.client.views_publish.assert_not_awaited()


# --- run now --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_run_now_uses_the_same_handler_as_the_run_command():
    app = _app()
    _seed()
    with _slack(), \
         patch('hutbot.commands.setters.run_config_now', new=AsyncMock()) as run:
        await handlers.handle_action(app, _body(), _action(
            "hutbot_cfg:run", value=fields.encode_meta(CHANNEL, "default")))
    assert run.await_args.args[3] == "default"


# --- export and import ----------------------------------------------------------------

def _export_of(config_name, config):
    return hutbot.configexport.dump_payload(
        hutbot.configexport.build_payload(config_name, config))


@pytest.mark.asyncio
async def test_the_export_button_opens_the_payload_without_writing():
    app = _app()
    configs = _seed({"default": {**copy.deepcopy(DEFAULT_CONFIG), "wait_time": 600}})
    with _slack():
        await handlers.handle_action(app, _body(), _action(
            "hutbot_cfg:export", value=fields.encode_meta(CHANNEL, "default")))
    view = app.client.views_push.await_args.kwargs["view"]
    assert view["title"]["text"] == "Export rule"
    assert configs["default"]["wait_time"] == 600


@pytest.mark.asyncio
async def test_exporting_a_rule_that_vanished_says_so():
    app = _app()
    _seed({})
    with _slack():
        await handlers.handle_action(app, _body(), _action(
            "hutbot_cfg:export", value=fields.encode_meta(CHANNEL, "gone")))
    assert app.client.views_push.await_args.kwargs["view"]["title"]["text"] == "Gone"


@pytest.mark.asyncio
async def test_the_import_button_opens_the_paste_form():
    app = _app()
    _seed()
    with _slack():
        await handlers.handle_action(app, _body(), _action(
            "hutbot_cfg:import", value=fields.encode_meta(CHANNEL, "default")))
    assert app.client.views_push.await_args.kwargs["view"]["title"]["text"] == "Import rule"


def _import_values(name, pasted):
    return {**_element(fields.BLOCK_NAME, _plain(name)),
            **_element(fields.BLOCK_IMPORT, _plain(pasted))}


@pytest.mark.asyncio
async def test_an_import_creates_a_rule_that_does_not_exist_yet():
    app = _app()
    configs = _seed()
    ack = AsyncMock()
    pasted = _export_of("nightly", {**copy.deepcopy(DEFAULT_CONFIG), "wait_time": 600,
                                    "trigger": TRIGGER_CRON, "cron": "0 9 * * 1-5"})
    with _slack():
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL, "default"), callback_id=views.VIEW_IMPORT,
            values=_import_values("nightly", pasted)))
    assert configs["nightly"]["wait_time"] == 600
    assert configs["nightly"]["cron"] == "0 9 * * 1-5"
    assert ack.await_args.kwargs["view"]["title"]["text"] == "Rule"


@pytest.mark.asyncio
async def test_an_import_replaces_a_rule_and_resets_what_the_export_left_out():
    # An export carries only what differs from the defaults, so it describes a whole rule
    # rather than patching whatever was there — the same semantics `import config` has.
    app = _app()
    configs = _seed({"default": {**copy.deepcopy(DEFAULT_CONFIG), "wait_time": 600,
                                 "pattern": "leftover", "only_work_days": True}})
    ack = AsyncMock()
    pasted = _export_of("src", {**copy.deepcopy(DEFAULT_CONFIG), "wait_time": 900})
    with _slack():
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL, "default"), callback_id=views.VIEW_IMPORT,
            values=_import_values("default", pasted)))
    assert configs["default"]["wait_time"] == 900
    assert configs["default"]["pattern"] is None
    assert configs["default"]["only_work_days"] is False


@pytest.mark.asyncio
async def test_an_import_keeps_the_config_object_the_scheduler_holds():
    app = _app()
    configs = _seed()
    original = configs["default"]
    ack = AsyncMock()
    pasted = _export_of("src", {**copy.deepcopy(DEFAULT_CONFIG), "wait_time": 900})
    with _slack():
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL, "default"), callback_id=views.VIEW_IMPORT,
            values=_import_values("default", pasted)))
    assert hutbot.state.channel_config[CHANNEL]["default"] is original


@pytest.mark.asyncio
async def test_an_import_round_trips_a_rule_into_another_name():
    app = _app()
    source = {**copy.deepcopy(DEFAULT_CONFIG), "wait_time": 600, "trigger": TRIGGER_CRON,
              "cron": "0 9 * * 1-5", "reply_message": "Anybody there?",
              "conditions": [{"variable": "message", "operator": "contains",
                              "value": "deploy", "case_sensitive": False}],
              "conditions_mode": CONDITION_MODE_ANY, "only_work_days": True,
              "hours": ["09:00", "17:00"]}
    configs = _seed({"default": copy.deepcopy(source)})
    ack = AsyncMock()
    with _slack():
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL, "default"), callback_id=views.VIEW_IMPORT,
            values=_import_values("copy", _export_of("default", source))))
    assert configs["copy"] == configs["default"]


@pytest.mark.asyncio
async def test_a_paste_that_is_not_json_is_refused_on_the_paste_field():
    app = _app()
    configs = _seed()
    ack = AsyncMock()
    with _slack():
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL, "default"), callback_id=views.VIEW_IMPORT,
            values=_import_values("default", "not json at all")))
    assert list(ack.await_args.kwargs["errors"]) == [block_id(fields.BLOCK_IMPORT)]
    assert configs["default"]["wait_time"] == DEFAULT_CONFIG["wait_time"]


@pytest.mark.asyncio
async def test_a_paste_naming_a_setting_that_does_not_exist_says_which():
    app = _app()
    _seed()
    ack = AsyncMock()
    with _slack():
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL, "default"), callback_id=views.VIEW_IMPORT,
            values=_import_values("default", '{"wait_tim": 600}')))
    assert "wait_tim" in ack.await_args.kwargs["errors"][block_id(fields.BLOCK_IMPORT)]


@pytest.mark.asyncio
async def test_a_paste_a_setter_would_refuse_is_refused_here_too():
    app = _app()
    configs = _seed()
    ack = AsyncMock()
    with _slack():
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL, "default"), callback_id=views.VIEW_IMPORT,
            values=_import_values("default", '{"trigger": "cron", "cron": "nope"}')))
    # Nothing in this form shows the cron field, so the message folds onto the paste field
    # with the setting named.
    folded = ack.await_args.kwargs["errors"][block_id(fields.BLOCK_IMPORT)]
    assert "Schedule:" in folded
    assert configs["default"]["trigger"] == TRIGGER_MESSAGE


@pytest.mark.asyncio
async def test_an_import_into_a_reserved_name_is_refused_on_the_name_field():
    app = _app()
    _seed()
    ack = AsyncMock()
    with _slack():
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL, "default"), callback_id=views.VIEW_IMPORT,
            values=_import_values("export", '{"wait_time": 600}')))
    assert list(ack.await_args.kwargs["errors"]) == [block_id(fields.BLOCK_NAME)]


@pytest.mark.asyncio
async def test_an_import_with_no_name_given_falls_back_to_the_exported_one():
    app = _app()
    configs = _seed()
    ack = AsyncMock()
    pasted = _export_of("from-the-envelope",
                        {**copy.deepcopy(DEFAULT_CONFIG), "wait_time": 600})
    with _slack():
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL, "default"), callback_id=views.VIEW_IMPORT,
            values=_import_values("", pasted)))
    assert configs["from-the-envelope"]["wait_time"] == 600


@pytest.mark.asyncio
async def test_a_non_member_cannot_import():
    app = _app()
    configs = _seed()
    ack = AsyncMock()
    with _slack(member=False):
        await handlers.handle_view_submission(app, ack, _body(
            fields.encode_meta(CHANNEL, "default"), callback_id=views.VIEW_IMPORT,
            values=_import_values("default", '{"wait_time": 900}')))
    assert configs["default"]["wait_time"] == DEFAULT_CONFIG["wait_time"]
