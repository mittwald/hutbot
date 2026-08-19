from tests._common import *  # noqa: F401,F403



def test_get_env_var_decoding_and_passthrough(monkeypatch):
    encoded = base64.b64encode(b"hello world").decode("utf-8")
    monkeypatch.setenv("MY_ENV_VAR", encoded)
    assert get_env_var("MY_ENV_VAR") == "hello world"
    monkeypatch.setenv("MY_ENV_VAR_PLAIN", "plain value")
    assert get_env_var("MY_ENV_VAR_PLAIN") == "plain value"



def test_extract_message_text_prefers_top_level_text():
    event = {
        "text": "Top-level text",
        "attachments": [{"text": "Attachment text"}],
    }

    assert extract_message_text(event) == "Top-level text"



def test_extract_message_text_extracts_attachment_text():
    event = {
        "text": "",
        "attachments": [{
            "text": "Alerts: \n       - 1 removeQueueItemForAbortedOrder temporal executions needs operating."
        }],
    }

    assert extract_message_text(event) == "Alerts: \n       - 1 removeQueueItemForAbortedOrder temporal executions needs operating."



def test_extract_message_text_includes_attachment_title_and_text():
    event = {
        "text": "",
        "attachments": [{
            "title": "[FIRING:1] FailedTemporalExecutions",
            "text": "Alerts: temporal executions need operating.",
            "fallback": "Noisy fallback",
        }],
    }

    assert extract_message_text(event) == "[FIRING:1] FailedTemporalExecutions\nAlerts: temporal executions need operating."



def test_extract_message_text_uses_fallback_only_without_cleaner_attachment_text():
    event = {
        "text": "",
        "attachments": [{
            "fallback": "[FIRING:1] FailedTemporalExecutions noisy fallback",
        }],
    }

    assert extract_message_text(event) == "[FIRING:1] FailedTemporalExecutions noisy fallback"



def test_extract_message_text_handles_missing_attachments():
    assert extract_message_text({"text": ""}) == ""


# ----- backticks count as quotes -----

@pytest.mark.parametrize("text,expected", [
    ('"foo"', "foo"),
    ("'foo'", "foo"),
    ("`foo`", "foo"),
    ("`a b c`", "a b c"),
    ("foo", "foo"),
    # Not a matched pair, so nothing is stripped.
    ("`foo", "`foo"),
    ("foo`", "foo`"),
    ('"foo\'', '"foo\''),
    # A lone quote character is not an empty quoted string.
    ("`", "`"),
    ('"', '"'),
    ("", ""),
])
def test_strip_quotes_accepts_backticks(text, expected):
    assert strip_quotes(text) == expected


def test_parse_quoted_tokens_accepts_backticks():
    assert parse_quoted_tokens("`02.01.2006` `15:04` Europe/Berlin") == (
        ["02.01.2006", "15:04", "Europe/Berlin"], "")
    # Mixed quoting in one command still works.
    assert parse_quoted_tokens('`a b` "c d" \'e f\' g') == (["a b", "c d", "e f", "g"], "")


_LOCAL_URL = "http://127.0.0.1:8073/calendar.ics?token=abc123"


@pytest.mark.parametrize("typed", [
    _LOCAL_URL,
    f"`{_LOCAL_URL}`",
    f'"{_LOCAL_URL}"',
    f"<{_LOCAL_URL}>",
    f"<{_LOCAL_URL}|127.0.0.1>",
    # Slack auto-links a URL typed inside backticks, so both wrappers can arrive together.
    f"`<{_LOCAL_URL}>`",
    f"  `<{_LOCAL_URL}|127.0.0.1>`  ",
])
def test_unwrap_slack_link_handles_quotes_and_link_wrapping(typed):
    assert unwrap_slack_link(typed) == _LOCAL_URL
