"""The field/block contract of the config UI: readers, and where an error lands."""

from tests._common import *

from hutbot.apphome import fields
from hutbot.apphome.fields import block_id


def _plain(text):
    return {"type": "plain_text_input", "value": text}


def _option(value):
    return {"type": "static_select", "selected_option": {"value": value, "text": {"type": "plain_text", "text": value}}}


def _options(*values):
    return {"type": "multi_static_select",
            "selected_options": [{"value": value, "text": {"type": "plain_text", "text": value}} for value in values]}


def _values(**blocks):
    """`view.state.values`, one element per block, as Slack sends it."""
    return {block_id(field): {f"hutbot_cfg:field:{field}": payload} for field, payload in blocks.items()}


# --- the coverage contract -------------------------------------------------------------

def test_every_config_field_is_reachable_from_some_view():
    # `disabled_reason` is the bot's own bookkeeping, not a setting, exactly as
    # `export_config` leaves it out of an export.
    assert fields.all_ui_fields() == set(DEFAULT_CONFIG) - {"disabled_reason"}


def test_sections_do_not_claim_the_same_field_twice():
    claimed = [field for section in fields.SECTIONS.values() for field in section]
    assert len(claimed) == len(set(claimed))


def test_every_reachable_field_and_non_field_block_has_a_label():
    for field in fields.all_ui_fields() | set(fields.NON_FIELD_BLOCKS):
        assert fields.FIELD_LABELS.get(field), field


def test_every_row_field_has_a_label():
    for field in fields.CONDITION_ROW_FIELDS + fields.BUTTON_ROW_FIELDS:
        assert fields.FIELD_LABELS.get(field), field


# --- block ids ------------------------------------------------------------------------

def test_block_id_round_trips():
    assert block_id("wait_time") == "f:wait_time"
    assert fields.field_of("f:wait_time") == "wait_time"
    assert fields.field_of("hutbot_btn:0") == ""


# --- private_metadata -----------------------------------------------------------------

def test_meta_round_trips_and_stays_small():
    raw = fields.encode_meta("C12345", "nightly", "conditions", 3)
    assert len(raw) < 200
    assert fields.decode_meta(raw) == {
        "channel_id": "C12345", "config_name": "nightly", "section": "conditions", "row": 3}


def test_meta_omits_what_it_was_not_given():
    assert fields.decode_meta(fields.encode_meta("C12345")) == {
        "channel_id": "C12345", "config_name": "", "section": "", "row": None}


def test_meta_survives_a_long_rule_name_under_slacks_cap():
    raw = fields.encode_meta("C12345", "x" * 200, "filters", 0)
    assert len(raw) <= 3000


def test_decode_meta_of_garbage_reads_as_blank_rather_than_missing_keys():
    # Handlers read the keys unconditionally; a blank channel id then fails the membership
    # check the same way any unknown channel does.
    blank = {"channel_id": "", "config_name": "", "section": "", "row": None}
    assert fields.decode_meta("not json") == blank
    assert fields.decode_meta("[1, 2]") == blank
    assert fields.decode_meta("") == blank


# --- reading elements -----------------------------------------------------------------

@pytest.mark.parametrize("payload,expected", [
    ({"type": "plain_text_input", "value": "hi"}, "hi"),
    ({"type": "plain_text_input", "value": None}, None),
    ({"type": "static_select", "selected_option": {"value": "cron"}}, "cron"),
    ({"type": "static_select", "selected_option": None}, None),
    ({"type": "multi_static_select", "selected_options": [{"value": "a"}, {"value": "b"}]}, ["a", "b"]),
    ({"type": "checkboxes", "selected_options": []}, []),
    ({"type": "timepicker", "selected_time": "09:00"}, "09:00"),
    ({"type": "datepicker", "selected_date": "2026-09-01"}, "2026-09-01"),
    ({"type": "conversations_select", "selected_conversation": "C9"}, "C9"),
    ({"type": "users_select", "selected_user": "U9"}, "U9"),
    ({"type": "multi_users_select", "selected_users": ["U1", "U2"]}, ["U1", "U2"]),
    ("not a dict", None),
])
def test_element_value_covers_every_element_type(payload, expected):
    assert fields._element_value(payload) == expected


def test_read_block_of_a_block_the_view_did_not_have():
    assert fields.read_block({}, "f:cron") is None


# --- section readers ------------------------------------------------------------------

def test_minutes_become_seconds():
    submitted = fields.read_section_values(
        _values(trigger=_option("message"), cron=_plain(""), wait_time=_plain("45")), "trigger")
    assert submitted["wait_time"] == 2700


def test_a_non_numeric_delay_is_passed_through_for_the_backend_to_word():
    # Two copies of the same range rule would be two places to keep in step; the backend's
    # message is the one the slash commands already produce.
    submitted = fields.read_section_values(
        _values(trigger=_option("message"), cron=_plain(""), wait_time=_plain("soon")), "trigger")
    assert submitted["wait_time"] == "soon"


def test_zero_escalation_minutes_reads_as_off():
    submitted = fields.read_section_values(
        _values(escalation_kind=_option("none"), escalation_timeout=_plain("0"),
                escalation_target=_plain("")), "escalation")
    assert submitted["escalation_timeout"] == 0


def test_work_hours_need_both_ends_or_neither():
    both = fields.read_section_values(
        _values(pattern=_plain(""), pattern_case_sensitive={"selected_options": []},
                include_bots={"selected_options": []}, only_work_days={"selected_options": []},
                hours={"selected_time": "09:00"}, hours_end={"selected_time": "17:00"},
                team_mode=_option("all"), included_teams=_options()), "filters")
    assert both["hours"] == ["09:00", "17:00"]

    neither = fields.read_section_values(
        _values(hours={"selected_time": None}, hours_end={"selected_time": None}), "filters")
    assert neither["hours"] == []

    half = fields.read_section_values(_values(hours={"selected_time": "09:00"}), "filters")
    assert half["hours"] == ["09:00", ""]


@pytest.mark.parametrize("mode,expected", [
    ("all", ([], [])),
    ("only", (["Platform"], [])),
    ("except", ([], ["Platform"])),
])
def test_one_team_control_writes_the_two_exclusive_lists(mode, expected):
    submitted = fields.read_section_values(
        _values(team_mode=_option(mode), included_teams=_options("Platform")), "filters")
    assert (submitted["included_teams"], submitted["excluded_teams"]) == expected


def test_an_empty_pattern_is_stored_as_none():
    assert fields.read_section_values(_values(pattern=_plain("")), "filters")["pattern"] is None
    assert fields.read_section_values(_values(pattern=_plain("urgent")), "filters")["pattern"] == "urgent"


def test_an_unticked_checkbox_is_false():
    submitted = fields.read_section_values(
        _values(debug={"selected_options": []}, date_format=_plain(""), time_format=_plain(""),
                datetime_timezone=_plain(""), datetime_locale=_plain("")), "formatting")
    assert submitted["debug"] is False


def test_a_ticked_checkbox_is_true():
    submitted = fields.read_section_values(
        _values(debug={"selected_options": [{"value": "on"}]}), "formatting")
    assert submitted["debug"] is True


def test_a_select_target_reads_back_as_the_id_the_backend_accepts():
    submitted = fields.read_section_values(
        _values(action=_option(ACTION_POST_CHANNEL),
                action_target={"selected_conversation": "C99999"},
                reply_message=_plain("Anybody?")), "message")
    # `validate_config_payload` now requires a target `targets.parse_channel_ref` accepts.
    assert hutbot.targets.parse_channel_ref(submitted["action_target"]) == "C99999"


def test_a_section_reader_returns_exactly_its_own_fields():
    submitted = fields.read_section_values(
        _values(calendar_builtin=_option("rota"), calendar_url=_plain("")), "calendar")
    assert set(submitted) == set(fields.SECTIONS["calendar"])


def test_a_field_the_form_did_not_show_is_left_out_so_its_stored_value_survives():
    # The trigger form hides the reminder delay under a cron trigger. Reading it as empty
    # would blank it on every save, because the submit overlays this onto the stored config.
    submitted = fields.read_section_values(
        _values(trigger=_option("cron"), cron=_plain("0 9 * * 1-5")), "trigger")
    assert submitted == {"trigger": "cron", "cron": "0 9 * * 1-5"}


def test_the_filters_readers_are_silent_when_their_controls_are_absent():
    assert fields.read_section_values({}, "filters") == {}


# --- row readers ----------------------------------------------------------------------

def test_condition_row_omits_an_unset_moment_and_offset():
    row = fields.read_condition_row(_values(
        variable=_option("message"), operator=_option("contains"), value=_plain("deploy"),
        case_sensitive={"selected_options": []}, at=_plain(""), offset=_plain("")))
    assert row == {"variable": "message", "operator": "contains", "value": "deploy",
                   "case_sensitive": False}


def test_condition_row_keeps_a_moment_and_offset_it_was_given():
    row = fields.read_condition_row(_values(
        variable=_option("event_title"), operator=_option("not_empty"), value=_plain(""),
        at=_plain("09:00"), offset=_plain("+1")))
    assert row["at"] == "09:00" and row["offset"] == "+1"


def test_button_row_reads_its_three_fields():
    row = fields.read_button_row(_values(
        label=_plain("Escalate"), action=_option("config"), value=_plain("oncall, backup")))
    assert row == {"label": "Escalate", "action": "config", "value": "oncall, backup"}


# --- which block a row error lands on -------------------------------------------------

def test_a_condition_row_error_lands_on_the_value():
    present = [block_id(field) for field in fields.CONDITION_ROW_FIELDS]
    assert fields.condition_row_error_block(present, "contains") == block_id("value")


def test_a_valueless_operator_has_no_value_block_so_the_error_moves():
    # `empty`/`not_empty` render no value input, and every row error for them is about the
    # variable or the moment.
    present = [block_id(field) for field in fields.CONDITION_ROW_FIELDS if field != "value"]
    operator = sorted(CONDITION_OPERATORS_WITHOUT_VALUE)[0]
    assert fields.condition_row_error_block(present, operator) == block_id("offset")


def test_a_button_row_error_lands_on_the_label_only_when_the_label_is_blank():
    present = [block_id(field) for field in fields.BUTTON_ROW_FIELDS]
    assert fields.button_row_error_block(present, "") == block_id("label")
    assert fields.button_row_error_block(present, "Escalate") == block_id("value")


# --- map_errors -----------------------------------------------------------------------

def test_an_error_about_a_shown_field_lands_on_that_field():
    mapped = fields.map_errors({"cron": "Invalid cron expression."},
                               [block_id("trigger"), block_id("cron")], block_id("trigger"))
    assert mapped == {block_id("cron"): "Invalid cron expression."}


def test_an_error_about_a_field_this_modal_does_not_show_is_folded_in_with_its_name():
    # A Message-section save refused over a dangling escalation target: without the fold the
    # save would appear to do nothing at all.
    mapped = fields.map_errors({"escalation_target": "Pick one of this rule's button labels."},
                               [block_id("action"), block_id("reply_message")], block_id("action"))
    assert mapped == {block_id("action"): "Escalation target: Pick one of this rule's button labels."}


def test_a_row_error_for_the_row_being_edited_lands_on_its_designated_block():
    mapped = fields.map_errors({"conditions.2": "`contains` needs a value."},
                               [block_id("variable"), block_id("value")], block_id("variable"),
                               row_key="conditions.2", row_block_id=block_id("value"))
    assert mapped == {block_id("value"): "`contains` needs a value."}


def test_a_row_error_for_another_row_is_folded_in_numbered_from_one():
    mapped = fields.map_errors({"conditions.0": "Invalid pattern: bad"},
                               [block_id("variable"), block_id("value")], block_id("variable"),
                               row_key="conditions.2", row_block_id=block_id("value"))
    assert mapped == {block_id("variable"): "Condition 1: Invalid pattern: bad"}


def test_a_button_row_error_for_another_row_is_folded_in_numbered_from_one():
    mapped = fields.map_errors({"buttons.1": "A delay button needs an escalation to postpone."},
                               [block_id("escalation_kind")], block_id("escalation_kind"))
    assert mapped[block_id("escalation_kind")].startswith("Button 2: ")


def test_several_leftovers_join_into_one_message():
    mapped = fields.map_errors({"escalation_target": "Gone.", "conditions.0": "Broken."},
                               [block_id("action")], block_id("action"))
    folded = mapped[block_id("action")]
    assert "Escalation target: Gone." in folded and "Condition 1: Broken." in folded


def test_a_leftover_joins_an_error_already_on_the_fallback_block():
    mapped = fields.map_errors({"action": "Action must be one of reply.", "escalation_target": "Gone."},
                               [block_id("action")], block_id("action"))
    folded = mapped[block_id("action")]
    assert folded.startswith("Action must be one of reply.") and folded.endswith("Escalation target: Gone.")


def test_a_folded_message_is_truncated_so_slack_does_not_drop_it():
    errors = {f"conditions.{i}": "x" * 400 for i in range(10)}
    mapped = fields.map_errors(errors, [block_id("action")], block_id("action"))
    assert len(mapped[block_id("action")]) == fields.LEFTOVER_LIMIT


def test_an_unmappable_error_with_no_fallback_block_is_dropped_rather_than_faked():
    assert fields.map_errors({"escalation_target": "Gone."}, [block_id("action")], "") == {}


def test_the_name_error_ui_apply_config_returns_has_a_label():
    mapped = fields.map_errors({"name": "That rule no longer exists."},
                               [block_id("action")], block_id("action"))
    assert mapped[block_id("action")] == "Name: That rule no longer exists."


def test_no_errors_maps_to_nothing():
    assert fields.map_errors({}, [block_id("action")], block_id("action")) == {}
