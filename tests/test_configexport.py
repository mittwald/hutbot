"""The shape of an export, and reading one back."""

from tests._common import *

from hutbot import configexport


def test_only_the_fields_that_differ_from_the_defaults_are_exported():
    config = {**DEFAULT_CONFIG, "wait_time": 600, "reply_message": "Anybody?"}
    settings = configexport.exported_settings(config)
    # `reply_message` is at its default here, so it is not part of the export.
    assert settings == {"wait_time": 600}


def test_a_calendar_url_is_never_exported():
    # Possession of a published-calendar link is access to it, and an export is printed into
    # a channel or shown in a modal.
    config = {**DEFAULT_CONFIG, "calendar_url": "https://cal.example.com/SECRETTOKEN/x.ics"}
    dumped = configexport.dump_payload(configexport.build_payload("rota", config))
    assert "SECRETTOKEN" not in dumped


def test_the_bots_own_bookkeeping_is_never_exported():
    config = {**DEFAULT_CONFIG, "enabled": False,
              "disabled_reason": DISABLED_REASON_REMOVED}
    settings = configexport.exported_settings(config)
    assert settings == {"enabled": False}


def test_a_setting_a_backtick_cannot_close_the_code_fence_it_is_printed_in():
    config = {**DEFAULT_CONFIG, "reply_message": "Run ```deploy```"}
    dumped = configexport.dump_payload(configexport.build_payload("x", config))
    assert "`" not in dumped
    # Still valid JSON, and still the original text once parsed.
    assert json.loads(dumped)["settings"]["reply_message"] == "Run ```deploy```"


def test_an_export_round_trips_through_read_payload():
    config = {**DEFAULT_CONFIG, "wait_time": 600, "cron": "0 9 * * 1-5"}
    dumped = configexport.dump_payload(configexport.build_payload("nightly", config))
    settings, name, error = configexport.read_payload(dumped, "/hutbot")
    assert not error and name == "nightly"
    assert settings == {"wait_time": 600, "cron": "0 9 * * 1-5"}


@pytest.mark.parametrize("wrapped", [
    "```{}```",
    "```json\n{}\n```",
    "`{}`",
    "  {}  ",
])
def test_a_pasted_export_is_read_through_whatever_slack_wrapped_it_in(wrapped):
    body = '{"format": "hutbot-config/1", "name": "x", "settings": {"wait_time": 600}}'
    settings, name, error = configexport.read_payload(wrapped.format(body), "/hutbot")
    assert not error and settings == {"wait_time": 600}


def test_a_bare_settings_object_is_accepted_for_a_hand_written_import():
    settings, name, error = configexport.read_payload('{"wait_time": 600}', "/hutbot")
    assert not error and name == "" and settings == {"wait_time": 600}


@pytest.mark.parametrize("text,expected", [
    ("not json", "not valid JSON"),
    ("[1, 2]", "must be a JSON object"),
    ('{"format": "hutbot-config/9", "settings": {}}', "Unsupported export format"),
    ('{"format": "hutbot-config/1", "settings": 5}', "must be a JSON object"),
])
def test_an_unreadable_import_says_what_is_wrong_with_it(text, expected):
    settings, name, error = configexport.read_payload(text, "/hutbot")
    assert settings is None and expected in error


def test_an_error_that_suggests_what_to_paste_names_this_instances_command():
    _, _, error = configexport.read_payload("not json", "/hutbot_dev")
    assert "/hutbot_dev export config" in error


def test_a_key_that_is_not_a_setting_is_named_rather_than_ignored():
    assert configexport.unknown_settings({"wait_time": 60, "wait_tim": 60, "nope": 1}) == \
        ["nope", "wait_tim"]


def test_a_slack_wrapped_calendar_url_is_unwrapped():
    settings = configexport.normalized_settings(
        {"calendar_url": "<https://cal.example.com/x.ics>"})
    assert settings["calendar_url"] == "https://cal.example.com/x.ics"


def test_normalizing_leaves_a_payload_without_a_url_alone():
    payload = {"wait_time": 600}
    assert configexport.normalized_settings(payload) is payload
