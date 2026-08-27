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


# ----- `\n` in a command argument -----

@pytest.mark.parametrize("typed,expected", [
    ("First.\\nSecond.", "First.\nSecond."),
    ("a\\nb\\nc", "a\nb\nc"),
    # `\\n` is how a literal backslash-n is typed.
    ("literal \\\\n here", "literal \\n here"),
    # A backslash before anything else is not an escape and stays put, so a datetime
    # format or a regex in a template argument survives.
    ("%Y\\%m", "%Y\\%m"),
    ("\\t tab stays literal", "\\t tab stays literal"),
    # A trailing backslash has nothing to escape.
    ("ends with \\", "ends with \\"),
    ("", ""),
])
def test_decode_escaped_newlines(typed, expected):
    assert decode_escaped_newlines(typed) == expected


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


# ----- @mentioning by email address -----

@pytest.mark.parametrize("text,expected", [
    ("@d.grieser@mittwald.de", ["d.grieser@mittwald.de"]),
    ("hi @d.grieser@mittwald.de there", ["d.grieser@mittwald.de"]),
    ("@a@b.de and @c@d.de", ["a@b.de", "c@d.de"]),
    ("@Nico.Engelbrecht@Mittwald.DE", ["Nico.Engelbrecht@Mittwald.DE"]),
    # A bare address is not a mention.
    ("mail me at d.grieser@mittwald.de", []),
    # Neither is a plain username, an id, or a Slack-formatted link.
    ("@plainname", []),
    ("<@U123>", []),
    ("<mailto:a@b.de|a@b.de>", []),
])
def test_email_mention_pattern(text, expected):
    assert hutbot.constants.EMAIL_MENTION_PATTERN.findall(text) == expected


@pytest.mark.asyncio
async def test_process_mentions_resolves_an_email_address():
    app = AsyncMock()
    known = User("U9", "dave", "Dave Grieser", "Platform")
    with patch('hutbot.slackcache.get_user_by_email', new=AsyncMock(return_value=known)):
        ok, error, message = await hutbot.messaging.process_mentions(app, "Hey @d.grieser@mittwald.de look")
    assert (ok, error, message) == (True, "", "Hey <@U9> look")


@pytest.mark.asyncio
async def test_process_mentions_reports_an_unknown_email_at_set_time():
    app = AsyncMock()
    with patch('hutbot.slackcache.get_user_by_email', new=AsyncMock(return_value=User(None, "x", "", "T"))):
        ok, error, message = await hutbot.messaging.process_mentions(app, "Hey @nope@example.com")
    assert ok is False and "nope@example.com" in error


@pytest.mark.asyncio
async def test_an_email_mention_is_not_mistaken_for_a_username():
    """MENTION_PATTERN stops at the second `@`, so it would resolve `d.grieser` by name."""
    app = AsyncMock()
    by_name = AsyncMock(return_value=User("U1", "wrong", "Wrong Person", "T"))
    with patch('hutbot.slackcache.get_user_by_email', new=AsyncMock(return_value=User("U9", "dave", "Dave", "T"))), \
         patch('hutbot.slackcache.get_user_by_name', new=by_name):
        ok, _, message = await hutbot.messaging.process_mentions(app, "Hey @d.grieser@mittwald.de")
    assert message == "Hey <@U9>"
    by_name.assert_not_awaited()


@pytest.mark.asyncio
async def test_set_message_accepts_an_email_mention():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")
    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.slackcache.get_user_by_email', new=AsyncMock(return_value=User("U9", "dave", "Dave", "T"))), \
         patch('hutbot.messaging.send_message'):
        await process_command(app, "set message Ping @d.grieser@mittwald.de now", channel, user)
    assert channel.configs["default"]["reply_message"] == "Ping <@U9> now"


def test_escape_newlines_shows_line_breaks_the_way_commands_spell_them():
    escape = hutbot.textutil.escape_newlines

    assert escape("a\nb") == "a\\nb"
    assert escape("") == "" and escape(None) == ""
    # Other backslashes are left alone, like the decoder leaves them.
    assert escape("%Y\\%m") == "%Y\\%m"
    # Round-trips through the decoder the command input goes through.
    assert hutbot.textutil.decode_escaped_newlines(escape("a\nb")) == "a\nb"
