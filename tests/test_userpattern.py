"""Member-written patterns are matched with a deadline, so one cannot stall the event loop."""

import time

from tests._common import *  # noqa: F401,F403

import hutbot.userpattern as userpattern
from hutbot.conditionutil import evaluate_conditions

# Nested quantifiers that backtrack exponentially on a long run of `x` without a `y`.
CATASTROPHIC = r"(x+x+)+y"
HOSTILE_TEXT = "x" * 5000


def test_pattern_error_accepts_what_re_accepts():
    assert userpattern.pattern_error(r".*alarm.*") == ""
    assert userpattern.pattern_error(r"(?i)\bdeploy\b") == ""


def test_pattern_error_keeps_the_re_wording():
    assert userpattern.pattern_error("*") == "nothing to repeat at position 0"


def test_pattern_error_caps_the_length():
    assert "limited to" in userpattern.pattern_error("a" * (userpattern.MAX_PATTERN_LENGTH + 1))
    assert userpattern.pattern_error("a" * userpattern.MAX_PATTERN_LENGTH) == ""


# Small enough that even an unguarded `regex.compile` of them stays cheap in a test run.
@pytest.mark.parametrize("pattern", [r"a{20000}", r"(?:a{150}){150}", r"(a){10000}", r"(?=x{20000})"])
def test_pattern_error_refuses_a_repeat_that_regex_would_unroll_too_far(pattern):
    """`regex` copies a repeat's body `min` times when compiling: `a{4294967294}` would exhaust memory."""
    assert "repeats too much" in userpattern.pattern_error(pattern)


@pytest.mark.parametrize("pattern", [r"\d{4}-\d{2}-\d{2}", r"a{0,1000000}", r"[a-z]{2,10}", r"(?:ab){5000}"])
def test_pattern_error_accepts_ordinary_repeats(pattern):
    assert userpattern.pattern_error(pattern) == ""


def test_search_refuses_a_stored_pattern_that_would_unroll_too_far():
    """A pattern stored before the check existed is still never handed to `regex` to compile."""
    with pytest.raises(userpattern.regex.error, match="repeats too much"):
        userpattern.search(r"a{20000}", "aaa")


def test_pattern_error_refuses_deep_nesting():
    assert userpattern.pattern_error("(" * 499 + ")" * 499) == "the pattern nests too deeply"


def test_search_is_case_insensitive_unless_asked():
    assert userpattern.search("ALARM", "an alarm went off") is True
    assert userpattern.search("ALARM", "an alarm went off", case_sensitive=True) is False


def test_a_catastrophic_pattern_runs_out_of_time_instead_of_hanging():
    started = time.monotonic()
    with pytest.raises(userpattern.PatternTimeout):
        userpattern.search(CATASTROPHIC, HOSTILE_TEXT)
    assert time.monotonic() - started < 2


def test_a_pattern_that_ran_out_of_time_is_skipped_for_a_while():
    with pytest.raises(userpattern.PatternTimeout):
        userpattern.search(CATASTROPHIC, HOSTILE_TEXT)
    with patch.object(userpattern.regex, "search", side_effect=AssertionError("must not run")):
        with pytest.raises(userpattern.PatternTimeout, match="recently"):
            userpattern.search(CATASTROPHIC, "short")


def test_a_held_pattern_is_tried_again_once_the_hold_is_over():
    with pytest.raises(userpattern.PatternTimeout):
        userpattern.search(CATASTROPHIC, HOSTILE_TEXT)
    with patch.object(userpattern, "TIMED_OUT_PATTERN_HOLD_SECONDS", 0):
        assert userpattern.search(CATASTROPHIC, "xxy") is True


@pytest.mark.parametrize("operator", ["regex", "not_regex"])
def test_a_condition_whose_pattern_runs_out_of_time_fails_closed(operator):
    condition = {"variable": "message", "operator": operator, "value": CATASTROPHIC, "case_sensitive": False}

    met, reason = evaluate_conditions({"conditions": [condition]}, {"message": HOSTILE_TEXT})

    assert met is False
    assert "took longer than" in reason


@pytest.mark.asyncio
async def test_a_catastrophic_rule_pattern_does_not_stall_message_handling():
    app = AsyncMock()
    configs = {"slow": {**DEFAULT_CONFIG.copy(), "pattern": CATASTROPHIC},
               "fine": {**DEFAULT_CONFIG.copy(), "pattern": "x+"}}
    channel = Channel(id="C12345", name="general", configs=configs)
    user = User(id="U12345", name="test", real_name="Test User", team="team1")

    started = time.monotonic()
    with patch('hutbot.datetimefmt.is_work_day', return_value=True), \
         patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()), \
         patch('hutbot.scheduling.schedule_reply') as mock_schedule_reply:
        await handle_channel_message(app, OPSGENIE_TOKENS, channel, user, HOSTILE_TEXT, "1234.1")

    assert time.monotonic() - started < 2
    # The broken rule is skipped; the healthy one still queues its reminder.
    assert [c.args[4] for c in mock_schedule_reply.call_args_list] == ["fine"]


@pytest.mark.asyncio
async def test_set_pattern_refuses_an_overlong_pattern():
    app = AsyncMock()
    channel = _mk_channel()
    user = User(id="U1", name="u", real_name="U", team="T")
    with patch('hutbot.messaging.send_message', new=AsyncMock()) as mock_send_message, \
         patch('hutbot.persistence.save_configuration', new=AsyncMock()):
        await set_pattern(app, channel, "default", "a" * (userpattern.MAX_PATTERN_LENGTH + 1), None, user, "")

    assert "limited to" in mock_send_message.call_args.args[3]
    assert channel.configs["default"]["pattern"] is None
