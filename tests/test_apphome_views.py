"""Block Kit for the config UI: Slack's limits, the field contract, and no leaked secrets."""

from tests._common import *

from hutbot.apphome import views
from hutbot.apphome import fields
from hutbot.apphome.fields import block_id


KITCHEN_SINK = {
    **DEFAULT_CONFIG,
    "trigger": TRIGGER_CRON,
    "cron": "0 9 * * 1-5",
    "action": ACTION_POST_CHANNEL,
    "action_target": "C99999",
    "reply_message": "Anybody? {{message}}",
    "pattern": "urgent|incident",
    "pattern_case_sensitive": True,
    "hours": ["09:00", "17:00"],
    "only_work_days": True,
    "include_bots": True,
    "included_teams": ["Platform"],
    "conditions": [{"variable": "message", "operator": "contains", "value": f"v{i}"}
                   for i in range(20)],
    "conditions_mode": CONDITION_MODE_ANY,
    "buttons": [{"label": f"button {i}", "action": "config", "value": "oncall, backup"}
                for i in range(20)],
    "escalation_timeout": 900,
    "escalation_kind": "button",
    "escalation_target": "button 0",
    "opsgenie": True,
    "opsgenie_schedule_name": "platform",
    "calendar_builtin": "rota",
    "date_format": "%d.%m.%Y",
    "datetime_timezone": "Europe/Berlin",
    "debug": True,
    "enabled": False,
    "disabled_reason": DISABLED_REASON_REMOVED,
}

LONG_NAME = "x" * 200


def _meta():
    _seed_user_caches()
    with _patch_builtin_calendars():
        meta = ui_meta()
    meta['config_names'] = ["default", "oncall", "backup"]
    return meta


def _every_view(config, config_name="default"):
    """Every view this module can build, for one config. Named, so a failure says which."""
    meta = _meta()
    built = [
        ("home", views.home_view(meta, "C12345", [{"id": "C12345", "name": "general"}], {config_name: config})),
        ("hub", views.hub_view(meta, "C12345", config_name, config)),
        ("picker", views.picker_view(meta, "C12345", [config_name])),
        ("new_rule", views.name_view(meta, "C12345")),
        ("rename_rule", views.name_view(meta, "C12345", config_name)),
        ("notice", views.notice_view("Gone", "That rule no longer exists.")),
        ("conditions", views.conditions_view(meta, "C12345", config_name, config)),
        ("buttons", views.buttons_view(meta, "C12345", config_name, config)),
        ("export", views.export_view(meta, "C12345", config_name, config)),
        ("import", views.import_view(meta, "C12345", config_name)),
        ("condition_row", views.condition_row_view(meta, "C12345", config_name, 0,
                                                   (config.get('conditions') or [{}])[0])),
        ("button_row", views.button_row_view(meta, "C12345", config_name, 0,
                                             (config.get('buttons') or [{}])[0])),
    ]
    for section in views.SECTION_ORDER:
        if section in views._SECTION_BLOCKS:
            built.append((f"section:{section}",
                          views.section_view(meta, "C12345", config_name, section, config)))
    built.append(("section:escalation",
                  views.section_view(meta, "C12345", config_name, "escalation", config)))
    return built


def _walk(node):
    """Every dict inside a view, so a limit can be checked wherever it applies."""
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item)


CONFIGS = [("defaults", DEFAULT_CONFIG, "default"),
           ("kitchen sink", KITCHEN_SINK, LONG_NAME)]


# --- Slack's limits -------------------------------------------------------------------

@pytest.mark.parametrize("label,config,name", CONFIGS)
def test_no_view_exceeds_slacks_block_limit(label, config, name):
    for view_name, view in _every_view(config, name):
        assert len(view["blocks"]) <= views.SLACK_VIEW_BLOCK_LIMIT, view_name


@pytest.mark.parametrize("label,config,name", CONFIGS)
def test_every_modal_title_fits(label, config, name):
    for view_name, view in _every_view(config, name):
        if view.get("type") == "modal":
            assert len(view["title"]["text"]) <= views.SLACK_VIEW_TITLE_LIMIT, view_name


@pytest.mark.parametrize("label,config,name", CONFIGS)
def test_every_id_fits_slacks_255_characters(label, config, name):
    for view_name, view in _every_view(config, name):
        for node in _walk(view):
            for key in ("block_id", "action_id", "callback_id"):
                if key in node:
                    assert len(node[key]) <= 255, (view_name, key, node[key])


@pytest.mark.parametrize("label,config,name", CONFIGS)
def test_every_button_label_fits(label, config, name):
    for view_name, view in _every_view(config, name):
        for node in _walk(view):
            if node.get("type") == "button":
                assert len(node["text"]["text"]) <= views.SLACK_BUTTON_TEXT_LIMIT, view_name


@pytest.mark.parametrize("label,config,name", CONFIGS)
def test_no_plain_text_is_empty(label, config, name):
    # Slack rejects an empty plain_text outright, and an empty label is easy to produce from
    # a config field nobody filled in.
    for view_name, view in _every_view(config, name):
        for node in _walk(view):
            if node.get("type") == "plain_text":
                assert node["text"], view_name


@pytest.mark.parametrize("label,config,name", CONFIGS)
def test_private_metadata_stays_under_slacks_cap(label, config, name):
    for view_name, view in _every_view(config, name):
        assert len(view.get("private_metadata", "")) <= 3000, view_name


@pytest.mark.parametrize("label,config,name", CONFIGS)
def test_every_view_is_json_serializable(label, config, name):
    for view_name, view in _every_view(config, name):
        json.dumps(view)


@pytest.mark.parametrize("label,config,name", CONFIGS)
def test_no_select_offers_more_than_a_hundred_options(label, config, name):
    for view_name, view in _every_view(config, name):
        for node in _walk(view):
            if "options" in node and isinstance(node["options"], list):
                assert len(node["options"]) <= views.SLACK_OPTION_LIMIT, view_name


def test_a_channel_with_more_rules_than_the_home_tab_shows_says_so():
    meta = _meta()
    configs = {f"rule{i}": dict(DEFAULT_CONFIG) for i in range(views.HOME_RULE_LIMIT + 5)}
    view = views.home_view(meta, "C12345", [{"id": "C12345", "name": "general"}], configs)
    assert len(view["blocks"]) <= views.SLACK_VIEW_BLOCK_LIMIT
    assert "and 5 more" in json.dumps(view)


def test_a_rule_with_more_rows_than_the_list_shows_says_so():
    meta = _meta()
    config = {**DEFAULT_CONFIG,
              "conditions": [{"variable": "message", "operator": "not_empty"}
                             for _ in range(views.ROW_LIMIT + 3)]}
    view = views.conditions_view(meta, "C12345", "default", config)
    assert len(view["blocks"]) <= views.SLACK_VIEW_BLOCK_LIMIT
    assert "and 3 more" in json.dumps(view)


# --- the field contract ---------------------------------------------------------------

@pytest.mark.parametrize("section", sorted(views._SECTION_BLOCKS))
def test_a_section_form_only_carries_blocks_that_section_owns(section):
    meta = _meta()
    view = views.section_view(meta, "C12345", "default", section, KITCHEN_SINK)
    allowed = set(fields.SECTIONS[section]) | set(fields.NON_FIELD_BLOCKS)
    for block in view["blocks"]:
        if block.get("type") != "input":
            continue
        field = fields.field_of(block["block_id"])
        # An "insert a variable" select is not a config field, but it must name one the
        # section owns — that name is how the handler knows where to append.
        picked_for = fields.variable_pick_field(block["block_id"])
        if picked_for:
            assert picked_for in fields.SECTIONS[section], (section, block["block_id"])
            continue
        assert field in allowed, (section, block["block_id"])


@pytest.mark.parametrize("section", sorted(views._SECTION_BLOCKS))
def test_every_section_form_has_a_block_for_a_leftover_error_to_land_on(section):
    meta = _meta()
    view = views.section_view(meta, "C12345", "default", section, DEFAULT_CONFIG)
    assert views.first_input_block(view)


@pytest.mark.parametrize("section", sorted(views._SECTION_BLOCKS))
def test_a_sections_own_error_maps_onto_one_of_its_blocks(section):
    # The contract the whole error path rests on: an error key from the backend becomes a
    # block id by concatenation, and that block is really in the form.
    meta = _meta()
    view = views.section_view(meta, "C12345", "default", section, KITCHEN_SINK)
    block_ids = views.view_block_ids(view)
    shown = {fields.field_of(bid) for bid in block_ids} & set(fields.SECTIONS[section])
    for field in shown:
        mapped = fields.map_errors({field: "nope"}, block_ids, views.first_input_block(view))
        assert mapped == {block_id(field): "nope"}, (section, field)


def test_a_row_form_error_maps_onto_a_block_the_row_form_has():
    meta = _meta()
    view = views.condition_row_view(meta, "C12345", "default", 1,
                                    {"variable": "message", "operator": "contains", "value": "x"})
    block_ids = views.view_block_ids(view)
    landing = fields.condition_row_error_block(block_ids, "contains")
    assert landing in block_ids
    mapped = fields.map_errors({"conditions.1": "`contains` needs a value."}, block_ids,
                               views.first_input_block(view),
                               row_key="conditions.1", row_block_id=landing)
    assert mapped == {landing: "`contains` needs a value."}


def test_input_and_render_action_ids_share_the_prefix_the_listener_matches():
    meta = _meta()
    for view_name, view in _every_view(KITCHEN_SINK, LONG_NAME):
        for node in _walk(view):
            if "action_id" in node:
                assert node["action_id"].startswith("hutbot_cfg:"), view_name


def test_no_action_id_collides_with_the_existing_button_listener():
    # `routing` matches `^hutbot_btn:` for message buttons and `^hutbot_cfg:` for these; a
    # config UI id caught by the message-button handler would run a rule instead of opening a
    # form.
    for view_name, view in _every_view(KITCHEN_SINK, LONG_NAME):
        for node in _walk(view):
            assert not str(node.get("action_id", "")).startswith("hutbot_btn:"), view_name


# --- conditional rendering ------------------------------------------------------------

def test_the_trigger_form_shows_the_schedule_only_for_a_schedule_trigger():
    meta = _meta()
    cron = views.section_view(meta, "C1", "default", "trigger",
                              {**DEFAULT_CONFIG, "trigger": TRIGGER_CRON})
    message = views.section_view(meta, "C1", "default", "trigger", DEFAULT_CONFIG)
    assert block_id("cron") in views.view_block_ids(cron)
    assert block_id("wait_time") not in views.view_block_ids(cron)
    assert block_id("wait_time") in views.view_block_ids(message)
    assert block_id("cron") not in views.view_block_ids(message)


def test_the_message_form_asks_for_no_target_when_the_action_is_a_reply():
    meta = _meta()
    view = views.section_view(meta, "C1", "default", "message", DEFAULT_CONFIG)
    assert block_id("action_target") not in views.view_block_ids(view)


def test_a_channel_target_is_a_select_whose_value_the_backend_accepts():
    meta = _meta()
    view = views.section_view(meta, "C1", "default", "message",
                              {**DEFAULT_CONFIG, "action": ACTION_POST_CHANNEL,
                               "action_target": "C99999"})
    element = [block["element"] for block in view["blocks"]
               if block.get("block_id") == block_id("action_target")][0]
    assert element["type"] == "conversations_select"
    assert element["initial_conversation"] == "C99999"


def test_a_templated_target_falls_back_to_free_text_in_the_same_block():
    meta = _meta()
    view = views.section_view(meta, "C1", "default", "message",
                              {**DEFAULT_CONFIG, "action": ACTION_DM_USER,
                               "action_target": "{{opsgenie_current_user}}"})
    element = [block["element"] for block in view["blocks"]
               if block.get("block_id") == block_id("action_target")][0]
    assert element["type"] == "plain_text_input"


def test_a_valueless_operator_gets_no_value_input():
    meta = _meta()
    operator = sorted(CONDITION_OPERATORS_WITHOUT_VALUE)[0]
    view = views.condition_row_view(meta, "C1", "default", 0,
                                    {"variable": "message", "operator": operator})
    assert block_id("value") not in views.view_block_ids(view)


def test_a_variable_with_no_events_gets_no_offset_input():
    meta = _meta()
    view = views.condition_row_view(meta, "C1", "default", 0,
                                    {"variable": "message", "operator": "contains", "value": "x"})
    assert block_id("offset") not in views.view_block_ids(view)


def test_a_calendar_variable_gets_a_moment_and_an_offset():
    meta = _meta()
    variable = sorted(meta['template_variables_with_selector'])[0]
    view = views.condition_row_view(meta, "C1", "default", 0,
                                    {"variable": variable, "operator": "not_empty"})
    assert block_id("at") in views.view_block_ids(view)
    assert block_id("offset") in views.view_block_ids(view)


def test_the_escalation_form_asks_for_nothing_more_when_it_escalates_to_nothing():
    meta = _meta()
    view = views.section_view(meta, "C1", "default", "escalation", DEFAULT_CONFIG)
    assert block_id("escalation_timeout") not in views.view_block_ids(view)


def test_a_button_escalation_offers_this_rules_button_labels():
    meta = _meta()
    view = views.section_view(meta, "C1", "default", "escalation", KITCHEN_SINK)
    element = [block["element"] for block in view["blocks"]
               if block.get("block_id") == block_id("escalation_target")][0]
    assert element["initial_option"]["value"] == "button 0"


def test_a_config_button_picks_rule_names_rather_than_free_text():
    # The stored value is a comma-separated list, which a multi-select cannot get wrong.
    meta = _meta()
    view = views.button_row_view(meta, "C1", "default", 0,
                                 {"label": "Escalate", "action": "config", "value": "oncall, backup"})
    element = [block["element"] for block in view["blocks"]
               if block.get("block_id") == block_id("value")][0]
    assert element["type"] == "multi_static_select"
    assert [option["value"] for option in element["initial_options"]] == ["oncall", "backup"]


def test_a_delay_button_asks_for_minutes_and_says_it_needs_an_escalation():
    meta = _meta()
    view = views.button_row_view(meta, "C1", "default", 0,
                                 {"label": "Later", "action": "delay", "value": "15"})
    element = [block["element"] for block in view["blocks"]
               if block.get("block_id") == block_id("value")][0]
    assert element["type"] == "number_input" and element["initial_value"] == "15"
    assert "escalation" in json.dumps(view)


def test_the_default_rule_can_be_neither_renamed_nor_deleted_from_the_hub():
    meta = _meta()
    default = views.hub_view(meta, "C1", meta['default_config_name'], DEFAULT_CONFIG)
    other = views.hub_view(meta, "C1", "nightly", DEFAULT_CONFIG)
    assert "hutbot_cfg:delete" not in json.dumps(default)
    assert "hutbot_cfg:delete" in json.dumps(other)


def test_a_rule_the_bot_disabled_itself_says_why():
    meta = _meta()
    view = views.hub_view(meta, "C1", "nightly", KITCHEN_SINK)
    assert "removed from the channel" in json.dumps(view)


def test_the_minutes_shown_are_the_stored_seconds_divided():
    meta = _meta()
    view = views.section_view(meta, "C1", "default", "trigger", DEFAULT_CONFIG)
    element = [block["element"] for block in view["blocks"]
               if block.get("block_id") == block_id("wait_time")][0]
    assert element["initial_value"] == str(DEFAULT_CONFIG["wait_time"] // 60) == "30"


# --- reuse rather than re-implementation ----------------------------------------------

def test_a_condition_row_is_described_by_conditionutil():
    meta = _meta()
    condition = {"variable": "message", "operator": "contains", "value": "deploy"}
    view = views.conditions_view(meta, "C1", "default", {**DEFAULT_CONFIG,
                                                         "conditions": [condition]})
    row = [block for block in view["blocks"] if block.get("block_id") == "cond:0"][0]
    assert row["text"]["text"].endswith(
        hutbot.conditionutil.describe_condition(condition, code=True))


def test_the_home_tab_names_the_channel_by_reference_rather_than_by_a_looked_up_name():
    # `<#C…>` renders as the live name, which is why no view needs a Slack call to build.
    meta = _meta()
    view = views.home_view(meta, "C12345", [{"id": "C12345", "name": "general"}], {"default": DEFAULT_CONFIG})
    assert "<#C12345>" in json.dumps(view)


# --- secrets --------------------------------------------------------------------------

@pytest.mark.parametrize("label,config,name", CONFIGS)
def test_no_view_ever_prints_a_calendar_feed_token(label, config, name):
    secret = "https://cal.example.com/SECRETTOKEN/rota.ics"
    leaky = {**config, "calendar_url": secret, "calendar_builtin": ""}
    for view_name, view in _every_view(leaky, name):
        assert "SECRETTOKEN" not in json.dumps(view), view_name


def test_the_calendar_form_shows_the_shortened_url_so_leaving_it_be_keeps_it():
    meta = _meta()
    secret = "https://cal.example.com/SECRETTOKEN/rota.ics"
    view = views.section_view(meta, "C1", "default", "calendar",
                              {**DEFAULT_CONFIG, "calendar_url": secret})
    element = [block["element"] for block in view["blocks"]
               if block.get("block_id") == block_id("calendar_url")][0]
    assert element["initial_value"] == hutbot.calendarfeed.describe_calendar_url(secret)


def test_the_built_in_calendar_options_carry_names_not_urls():
    meta = _meta()
    view = views.section_view(meta, "C1", "default", "calendar", DEFAULT_CONFIG)
    assert "cal.example.com" not in json.dumps(view)


# --- the Edit button on `show config` -------------------------------------------------

def test_the_edit_button_carries_the_channel_it_was_pressed_in():
    blocks = views.edit_config_blocks("C12345")
    assert len(blocks) == 1 and blocks[0]["type"] == "actions"
    button = blocks[0]["elements"][0]
    assert button["action_id"] == "hutbot_cfg:pick_rule"
    assert fields.decode_meta(button["value"])["channel_id"] == "C12345"


def test_no_edit_button_without_a_channel():
    assert views.edit_config_blocks("") == []


# --- export and import ----------------------------------------------------------------

def test_the_export_modal_shows_the_same_payload_the_command_prints():
    meta = _meta()
    config = {**DEFAULT_CONFIG, "wait_time": 600, "cron": "0 9 * * 1-5"}
    view = views.export_view(meta, "C12345", "nightly", config)
    preformatted = [block for block in view["blocks"] if block["type"] == "rich_text"][0]
    dumped = preformatted["elements"][0]["elements"][0]["text"]
    assert dumped == hutbot.configexport.dump_payload(
        hutbot.configexport.build_payload("nightly", config))
    assert json.loads(dumped)["settings"] == {"wait_time": 600, "cron": "0 9 * * 1-5"}


def test_the_export_modal_has_nothing_to_submit():
    view = views.export_view(_meta(), "C12345", "default", DEFAULT_CONFIG)
    assert "submit" not in view


def test_the_export_modal_warns_that_a_calendar_url_was_left_out():
    secret = "https://cal.example.com/SECRETTOKEN/rota.ics"
    view = views.export_view(_meta(), "C12345", "default",
                             {**DEFAULT_CONFIG, "calendar_url": secret})
    assert "SECRETTOKEN" not in json.dumps(view)
    assert "not* included" in json.dumps(view)


def test_the_export_modal_says_nothing_about_a_calendar_when_there_is_none():
    view = views.export_view(_meta(), "C12345", "default", DEFAULT_CONFIG)
    assert "not* included" not in json.dumps(view)


def test_the_import_modal_asks_for_a_name_and_the_json():
    view = views.import_view(_meta(), "C12345", "nightly")
    block_ids = views.view_block_ids(view)
    assert block_id(fields.BLOCK_NAME) in block_ids
    assert block_id(fields.BLOCK_IMPORT) in block_ids
    # Prefilled with the rule it was opened from, so a paste lands where the person is.
    name_input = [block["element"] for block in view["blocks"]
                  if block.get("block_id") == block_id(fields.BLOCK_NAME)][0]
    assert name_input["initial_value"] == "nightly"


def test_the_import_modal_warns_that_omitted_settings_go_back_to_their_defaults():
    view = views.import_view(_meta(), "C12345", "default")
    assert "default" in json.dumps(view)


def test_the_hub_offers_export_and_import():
    view = views.hub_view(_meta(), "C12345", "nightly", DEFAULT_CONFIG)
    dumped = json.dumps(view)
    assert "hutbot_cfg:export" in dumped and "hutbot_cfg:import" in dumped


# --- the modal stack ------------------------------------------------------------------

@pytest.mark.parametrize("label,config,name", CONFIGS)
def test_no_view_carries_a_back_button_in_its_body(label, config, name):
    # Every view but the hub is pushed, and Slack gives a pushed view its own way back —
    # tidier, and in the chrome where people look for it.
    for view_name, view in _every_view(config, name):
        assert "hutbot_cfg:nav" not in json.dumps(view), view_name


# --- what Slack refuses outright ------------------------------------------------------

# The configs that actually broke: a fresh rule has no calendars to offer, no buttons for an
# escalation to point at, and a switched-off escalation whose stored zero is below the one
# minute its own input allows.
BREAKING_CONFIGS = [
    ("fresh", DEFAULT_CONFIG),
    ("escalates to a button it has not got",
     {**DEFAULT_CONFIG, "escalation_kind": "button", "escalation_timeout": 0}),
    ("escalates to a rule, switched off",
     {**DEFAULT_CONFIG, "escalation_kind": "config", "escalation_timeout": 0}),
    ("no calendars and no feed", {**DEFAULT_CONFIG, "calendar_builtin": "", "calendar_url": ""}),
    ("kitchen sink", KITCHEN_SINK),
]


def _no_calendars_meta():
    """`ui_meta` on an instance that offers no built-in calendars — the shipped default."""
    _seed_user_caches()
    meta = ui_meta()
    meta['config_names'] = ["default"]
    return meta


def _all_views(meta, config):
    built = [("home", views.home_view(meta, "C1", [{"id": "C1", "name": "general"}],
                                      {"default": config})),
             ("hub", views.hub_view(meta, "C1", "default", config)),
             ("conditions", views.conditions_view(meta, "C1", "default", config)),
             ("buttons", views.buttons_view(meta, "C1", "default", config)),
             ("new_rule", views.name_view(meta, "C1")),
             ("condition_row", views.condition_row_view(meta, "C1", "default", 0, {})),
             ("button_row", views.button_row_view(meta, "C1", "default", 0, {}))]
    for section in sorted(views._SECTION_BLOCKS):
        built.append((f"section:{section}",
                      views.section_view(meta, "C1", "default", section, config)))
    return built


@pytest.mark.parametrize("label,config", BREAKING_CONFIGS)
def test_no_select_is_ever_built_without_an_option(label, config):
    # Slack rejects a select with no options, and a view it rejects is a screen nobody sees.
    for view_name, view in _all_views(_no_calendars_meta(), config):
        for node in _walk(view):
            if node.get("type", "").endswith("_select") and "options" in node:
                assert node["options"], (view_name, node.get("action_id"))


@pytest.mark.parametrize("label,config", BREAKING_CONFIGS)
def test_no_option_carries_an_empty_value(label, config):
    # `must be more than 0 characters` — an option's value cannot be the empty string, so
    # "nothing chosen" needs a sentinel of its own.
    for view_name, view in _all_views(_no_calendars_meta(), config):
        for node in _walk(view):
            if "value" in node and "text" in node and isinstance(node.get("value"), str):
                assert node["value"], (view_name, node)


@pytest.mark.parametrize("label,config", BREAKING_CONFIGS)
def test_no_initial_option_carries_an_empty_value(label, config):
    for view_name, view in _all_views(_no_calendars_meta(), config):
        for node in _walk(view):
            chosen = node.get("initial_option")
            if isinstance(chosen, dict):
                assert chosen.get("value"), (view_name, node.get("action_id"))


@pytest.mark.parametrize("label,config", BREAKING_CONFIGS)
def test_no_number_input_starts_below_its_own_minimum(label, config):
    # `initial value must be greater than or equal to min value` — a stored zero is exactly
    # that for a field that starts at one, which is an escalation switched off.
    for view_name, view in _all_views(_no_calendars_meta(), config):
        for node in _walk(view):
            if node.get("type") == "number_input" and "initial_value" in node:
                assert int(node["initial_value"]) >= int(node["min_value"]), \
                    (view_name, node.get("action_id"))
                assert int(node["initial_value"]) <= int(node["max_value"]), \
                    (view_name, node.get("action_id"))


@pytest.mark.parametrize("label,config", BREAKING_CONFIGS)
def test_every_input_block_sits_in_a_view_that_can_be_submitted(label, config):
    # An input with no submit button is a form with no way to save it.
    for view_name, view in _all_views(_no_calendars_meta(), config):
        if any(block.get("type") == "input" for block in view["blocks"]):
            assert view.get("submit"), view_name


def test_the_calendar_none_entry_reads_back_as_no_calendar():
    view = views.section_view(_no_calendars_meta(), "C1", "default", "calendar", DEFAULT_CONFIG)
    element = [block["element"] for block in view["blocks"]
               if block.get("block_id") == block_id("calendar_builtin")][0]
    chosen = element["initial_option"]["value"]
    assert chosen == fields.NO_OPTION_VALUE
    submitted = fields.read_section_values(
        {block_id("calendar_builtin"): {"a": {"selected_option": {"value": chosen}}},
         block_id("calendar_url"): {"b": {"value": ""}}}, "calendar")
    assert submitted == {"calendar_builtin": "", "calendar_url": ""}


def test_an_escalation_with_no_buttons_says_so_instead_of_offering_nothing():
    view = views.section_view(_no_calendars_meta(), "C1", "default", "escalation",
                              {**DEFAULT_CONFIG, "escalation_kind": "button"})
    assert block_id("escalation_target") not in views.view_block_ids(view)
    assert "no buttons yet" in json.dumps(view)


# --- variables ------------------------------------------------------------------------

@pytest.mark.parametrize("section,field", [("message", "reply_message"),
                                           ("opsgenie", "opsgenie_message")])
def test_a_field_that_takes_variables_offers_them(section, field):
    view = views.section_view(_meta(), "C1", "default", section, DEFAULT_CONFIG)
    block_ids = views.view_block_ids(view)
    assert block_id(f"{field}{fields.VARIABLE_PICK_SUFFIX}") in block_ids
    assert "hutbot_cfg:variables:" in json.dumps(view)


def test_an_acknowledgement_text_offers_them_too():
    view = views.button_row_view(_meta(), "C1", "default", 0,
                                 {"label": "Got it", "action": "ack", "value": ""})
    assert block_id(f"value{fields.VARIABLE_PICK_SUFFIX}") in views.view_block_ids(view)


def test_a_field_that_takes_no_variables_does_not_offer_them():
    for section in ("trigger", "filters", "calendar", "formatting"):
        view = views.section_view(_meta(), "C1", "default", section, DEFAULT_CONFIG)
        assert fields.VARIABLE_PICK_SUFFIX not in json.dumps(view), section


def test_every_variable_is_offered_with_what_it_takes():
    options = views._variable_options()
    offered = {option["value"] for option in options}
    assert offered == set(SUPPORTED_TEMPLATE_VARIABLES)
    for option in options:
        assert option["text"]["text"] == "{{" + option["value"] + "}}"
        # Slack truncates an option description silently past 75 characters.
        assert 0 < len(option["description"]["text"]) <= 75, option["value"]


def test_the_reference_is_the_same_text_the_command_prints():
    # One source, so the form cannot describe a variable the command does not.
    view = views.section_view(_meta(), "C1", "default", "message", DEFAULT_CONFIG,
                              variables_expanded=True)
    texts = [block["text"]["text"] for block in view["blocks"] if block.get("text")]
    rendered = "\n".join(texts)
    for title, variables in hutbot.templatedocs.variable_groups():
        assert title in rendered
        for name in variables:
            assert "{{" + name + "}}" in rendered
    # Every note the command prints, verbatim and whole.
    for note in hutbot.templatedocs.argument_notes("/hutbot"):
        assert note in texts


@pytest.mark.parametrize("build", [
    lambda meta: views.section_view(meta, "C1", "default", "message", DEFAULT_CONFIG, True),
    lambda meta: views.section_view(meta, "C1", "default", "opsgenie", DEFAULT_CONFIG, True),
    lambda meta: views.button_row_view(meta, "C1", "default", 0,
                                       {"label": "Ack", "action": "ack", "value": ""}, True),
])
def test_a_form_with_the_reference_unfolded_still_fits(build):
    # Block Kit has no collapsible section, so the reference is 20-odd blocks appended to a
    # form that has to stay inside Slack's hundred.
    view = build(_meta())
    assert len(view["blocks"]) <= views.SLACK_VIEW_BLOCK_LIMIT
    for block in view["blocks"]:
        if block.get("text"):
            assert len(block["text"]["text"]) <= views.SLACK_SECTION_TEXT_LIMIT


def test_the_reference_is_folded_away_until_it_is_asked_for():
    folded = views.section_view(_meta(), "C1", "default", "message", DEFAULT_CONFIG)
    unfolded = views.section_view(_meta(), "C1", "default", "message", DEFAULT_CONFIG, True)
    assert len(unfolded["blocks"]) > len(folded["blocks"])
    assert "Every variable" not in json.dumps(folded)
    assert "Every variable" in json.dumps(unfolded)
    # The fold is remembered by the view, so another redraw does not close it.
    assert fields.decode_meta(unfolded["private_metadata"])["variables_expanded"] is True
    assert fields.decode_meta(folded["private_metadata"])["variables_expanded"] is False


def test_the_toggle_says_which_way_it_goes():
    folded = views.section_view(_meta(), "C1", "default", "message", DEFAULT_CONFIG)
    unfolded = views.section_view(_meta(), "C1", "default", "message", DEFAULT_CONFIG, True)
    assert "What can I use?" in json.dumps(folded)
    assert "Hide the variable reference" in json.dumps(unfolded)


def test_the_toggle_carries_no_value_so_it_reads_the_views_own_state():
    # The section and the current fold are both in the view's metadata; a value on the button
    # would shadow them and the toggle would forget which form it was in.
    view = views.section_view(_meta(), "C1", "default", "message", DEFAULT_CONFIG)
    toggle = [element for block in view["blocks"] if block.get("type") == "actions"
              for element in block["elements"]
              if element["action_id"].startswith("hutbot_cfg:variables:")][0]
    assert "value" not in toggle


def test_an_acknowledgement_text_can_unfold_the_reference_too():
    # It sits at the bottom of the depth budget, which is exactly why the reference is a fold
    # rather than a view.
    view = views.button_row_view(_meta(), "C1", "default", 0,
                                 {"label": "Ack", "action": "ack", "value": ""}, True)
    assert "Every variable" in json.dumps(view)


def test_the_opsgenie_schedule_is_a_list_when_there_are_credentials():
    meta = _meta()
    meta['opsgenie_configured'] = True
    view = views.section_view(meta, "C1", "default", "opsgenie", DEFAULT_CONFIG)
    element = [block["element"] for block in view["blocks"]
               if block.get("block_id") == block_id("opsgenie_schedule_name")][0]
    assert element["type"] == "external_select"
    assert element["action_id"] == "hutbot_cfg:options:opsgenie_schedule_name"


def test_a_stored_schedule_is_shown_even_though_slack_cannot_know_it():
    meta = _meta()
    meta['opsgenie_configured'] = True
    view = views.section_view(meta, "C1", "default", "opsgenie",
                              {**DEFAULT_CONFIG, "opsgenie_schedule_name": "Platform on-call"})
    element = [block["element"] for block in view["blocks"]
               if block.get("block_id") == block_id("opsgenie_schedule_name")][0]
    assert element["initial_option"]["value"] == "Platform on-call"


def test_the_schedule_stays_typeable_on_an_instance_with_no_credentials():
    # Otherwise an instance that gets its token later could never have been configured for it.
    meta = _meta()
    meta['opsgenie_configured'] = False
    view = views.section_view(meta, "C1", "default", "opsgenie", DEFAULT_CONFIG)
    element = [block["element"] for block in view["blocks"]
               if block.get("block_id") == block_id("opsgenie_schedule_name")][0]
    assert element["type"] == "plain_text_input"
