import copy

from tests._common import *  # noqa: F401,F403

from hutbot.conditionutil import (
    canonical_condition_mode,
    conditions_ruled_out,
    canonical_operator,
    condition_variables,
    describe_condition,
    evaluate_conditions,
    normalize_condition,
    normalize_variable,
    settled_condition_variables,
    split_case_flag,
)


# The engine is pure, so none of these need a mock.
VARIABLES = {
    "message": "Composerbereitstellung",
    "blank": "",
    "team": "Platform",
    "opsgenie_current_user": "<no-user-set>",
}


def _c(variable, operator, value="", case_sensitive=False):
    return {"variable": variable, "operator": operator, "value": value, "case_sensitive": case_sensitive}


def _ev(conditions, mode="all", variables=None):
    return evaluate_conditions(
        {"conditions": conditions, "conditions_mode": mode},
        VARIABLES if variables is None else variables,
    )


# ----- operator names -----

@pytest.mark.parametrize("typed,expected", [
    ("equals", "equals"), ("is", "equals"), ("=", "equals"), ("==", "equals"), ("eq", "equals"),
    ("!=", "not_equals"), ("ne", "not_equals"), ("isnt", "not_equals"), ("is not", "not_equals"),
    ("has", "contains"), ("includes", "contains"), ("contain", "contains"),
    ("not contains", "not_contains"), ("not-contains", "not_contains"),
    ("!contains", "not_contains"), ("NOT CONTAINS", "not_contains"),
    ("excludes", "not_contains"), ("lacks", "not_contains"),
    ("matches", "regex"), ("=~", "regex"), ("!~", "not_regex"), ("not regex", "not_regex"),
    ("starts with", "starts_with"), ("startswith", "starts_with"), ("prefix", "starts_with"),
    ("not starts with", "not_starts_with"),
    ("endswith", "ends_with"), ("suffix", "ends_with"),
    ("blank", "empty"), ("unset", "empty"), ("not empty", "not_empty"), ("present", "not_empty"),
    # Double negation folds back rather than producing a name that does not exist.
    ("not not_contains", "contains"),
    ("bogus", ""), ("", ""), ("   ", ""),
])
def test_canonical_operator(typed, expected):
    assert canonical_operator(typed) == expected


@pytest.mark.parametrize("typed,expected", [
    ("all", "all"), ("any", "any"), ("and", "all"), ("or", "any"),
    ("every", "all"), ("some", "any"), ("ALL", "all"), ("nope", ""), ("", ""),
])
def test_canonical_condition_mode(typed, expected):
    assert canonical_condition_mode(typed) == expected


@pytest.mark.parametrize("typed,expected", [
    ("message", "message"), ("{{message}}", "message"), ("MESSAGE", "message"),
    ("  {{ message }}  ", "message"),
])
def test_normalize_variable(typed, expected):
    assert normalize_variable(typed) == expected


# ----- the trailing case flag -----

@pytest.mark.parametrize("spec,expected", [
    ('"daily" 1', ("daily", True)),
    ("daily 1", ("daily", True)),
    ("daily 0", ("daily", False)),
    ("daily", ("daily", False)),
    ('"daily" case-sensitive', ("daily", True)),
    ('"daily" case_insensitive', ("daily", False)),
    ('"daily" yes', ("daily", True)),
    ('"daily" off', ("daily", False)),
    # A quoted value keeps its spaces, and the flag still comes off the end.
    ('"deploy to prod" 1', ("deploy to prod", True)),
    ('"deploy to prod" 0', ("deploy to prod", False)),
    # Unquoted multi-word values cannot carry a flag — same limitation as `set pattern`.
    ("deploy to prod", ("deploy to prod", False)),
    # Quoting is what protects a value that is itself a flag word.
    ('"true"', ("true", False)),
    ("true", ("true", False)),
])
def test_split_case_flag(spec, expected):
    assert split_case_flag(spec) == expected


# ----- operators against real values -----

@pytest.mark.parametrize("operator,value,expected", [
    ("equals", "composerbereitstellung", True),
    ("equals", "something else", False),
    ("not_equals", "something else", True),
    ("not_equals", "composerbereitstellung", False),
    ("contains", "composer", True),
    ("contains", "zzz", False),
    ("not_contains", "zzz", True),
    ("not_contains", "composer", False),
    ("starts_with", "composer", True),
    ("starts_with", "bereit", False),
    ("not_starts_with", "bereit", True),
    ("ends_with", "stellung", True),
    ("ends_with", "composer", False),
    ("not_ends_with", "composer", True),
    ("regex", "^composer.*ung$", True),
    ("regex", "^nope", False),
    ("not_regex", "^nope", True),
    ("not_regex", "^composer", False),
])
def test_operators_case_insensitive_by_default(operator, value, expected):
    assert _ev([_c("message", operator, value)])[0] is expected


def test_empty_and_not_empty():
    assert _ev([_c("blank", "empty")])[0] is True
    assert _ev([_c("blank", "not_empty")])[0] is False
    assert _ev([_c("message", "empty")])[0] is False
    assert _ev([_c("message", "not_empty")])[0] is True


def test_equals_empty_string_is_a_synonym_for_empty():
    assert _ev([_c("blank", "equals", "")])[0] is True
    assert _ev([_c("message", "equals", "")])[0] is False


def test_opsgenie_placeholder_counts_as_empty_but_not_as_equals_empty():
    """`opsgenie_current_user empty` is the natural "is anyone on call?" check.

    The providers never hand back a bare "", so without the placeholder set that question
    could never be answered yes. Comparison operators still see the raw placeholder.
    """
    assert _ev([_c("opsgenie_current_user", "empty")])[0] is True
    assert _ev([_c("opsgenie_current_user", "not_empty")])[0] is False
    assert _ev([_c("opsgenie_current_user", "equals", "")])[0] is False
    assert _ev([_c("opsgenie_current_user", "contains", "no-user-set")])[0] is True


# ----- case sensitivity -----

@pytest.mark.parametrize("operator,value", [
    ("equals", "composerbereitstellung"),
    ("contains", "composer"),
    ("starts_with", "composer"),
    ("ends_with", "STELLUNG"),
    ("regex", "^composer"),
])
def test_case_sensitive_flag_flips_matching(operator, value):
    assert _ev([_c("message", operator, value, case_sensitive=False)])[0] is True
    assert _ev([_c("message", operator, value, case_sensitive=True)])[0] is False


@pytest.mark.parametrize("operator,value", [
    ("not_equals", "composerbereitstellung"),
    ("not_contains", "composer"),
    ("not_starts_with", "composer"),
    ("not_regex", "^composer"),
])
def test_case_sensitive_flag_flips_negated_matching(operator, value):
    assert _ev([_c("message", operator, value, case_sensitive=False)])[0] is False
    assert _ev([_c("message", operator, value, case_sensitive=True)])[0] is True


def test_case_sensitive_match_with_the_right_casing():
    assert _ev([_c("message", "contains", "Composer", case_sensitive=True)])[0] is True


def test_missing_case_sensitive_key_defaults_to_insensitive():
    assert evaluate_conditions(
        {"conditions": [{"variable": "message", "operator": "contains", "value": "composer"}]},
        VARIABLES,
    )[0] is True


def test_value_less_operators_normalize_the_case_flag_away():
    assert normalize_condition(_c("message", "empty", "junk", True)) == ("message", "empty", "", False, "", "")
    assert normalize_condition(_c("message", "not_empty", "junk", True)) == ("message", "not_empty", "", False, "", "")


# ----- chaining -----

def test_empty_chain_always_passes_under_both_modes():
    """`any` over an empty list must not mean "never"."""
    assert evaluate_conditions({"conditions": []}, VARIABLES) == (True, "")
    assert evaluate_conditions({"conditions": [], "conditions_mode": "any"}, VARIABLES) == (True, "")
    assert evaluate_conditions({}, VARIABLES) == (True, "")


def test_all_requires_every_condition():
    both = [_c("message", "contains", "composer"), _c("team", "equals", "platform")]
    assert _ev(both)[0] is True
    met, reason = _ev([*both, _c("message", "contains", "zzz")])
    assert met is False and "zzz" in reason


def test_any_requires_one_condition():
    conditions = [_c("message", "contains", "zzz"), _c("team", "equals", "platform")]
    assert _ev(conditions, "any")[0] is True
    met, reason = _ev([_c("message", "contains", "zzz"), _c("team", "equals", "nope")], "any")
    assert met is False and "none of the conditions matched" in reason


def test_unknown_match_mode_falls_back_to_all():
    conditions = [_c("message", "contains", "composer"), _c("message", "contains", "zzz")]
    assert evaluate_conditions({"conditions": conditions, "conditions_mode": "bogus"}, VARIABLES)[0] is False


# ----- fail closed -----

@pytest.mark.parametrize("operator", ["equals", "not_equals", "contains", "not_contains", "regex", "not_regex"])
def test_unknown_variable_is_never_met_whatever_the_polarity(operator):
    """A vanished variable must not satisfy a `not_*` operator and page somebody."""
    met, reason = _ev([_c("nope", operator, "x")])
    assert met is False
    assert "unknown variable" in reason


@pytest.mark.parametrize("operator", ["regex", "not_regex"])
def test_invalid_regex_is_never_met(operator):
    met, reason = _ev([_c("message", operator, "[unclosed")])
    assert met is False
    assert "invalid pattern" in reason


def test_unusable_condition_is_never_met():
    met, reason = _ev([{"variable": "message", "operator": "bogus", "value": "x"}])
    assert met is False and reason


def test_one_broken_condition_does_not_block_the_others_under_any():
    conditions = [_c("nope", "equals", "x"), _c("message", "contains", "composer")]
    assert _ev(conditions, "any")[0] is True
    assert _ev(conditions, "all")[0] is False


# ----- description and variable collection -----

def test_describe_condition_always_states_the_casing():
    """Nobody should have to remember which way the default goes."""
    assert describe_condition(_c("message", "contains", "urgent")) == '{{message}} contains "urgent" (case-insensitive)'
    assert describe_condition(_c("message", "contains", "urgent", True)) == '{{message}} contains "urgent" (case-sensitive)'
    # `empty`/`not_empty` compare nothing, so there is no casing to report.
    assert describe_condition(_c("message", "not_empty")) == "{{message}} not_empty"
    assert describe_condition(_c("message", "empty")) == "{{message}} empty"
    assert describe_condition({"variable": "", "operator": ""}) == "<invalid condition>"


def test_condition_variables_skips_unusable_entries():
    config = {"conditions": [_c("message", "contains", "x"), {"variable": "team", "operator": "bogus"}, "junk"]}
    assert condition_variables(config) == {"message"}


# ----- commands -----

@pytest.mark.asyncio
async def test_add_condition_stores_the_case_flag():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")
    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, 'add condition message contains "Deploy" 1', channel, user)
    condition = channel.configs["default"]["conditions"][0]
    assert condition == {"variable": "message", "operator": "contains", "value": "Deploy", "case_sensitive": True}
    assert "case-sensitive" in send.call_args.args[3]


@pytest.mark.asyncio
async def test_add_condition_defaults_to_case_insensitive():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")
    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, "add condition message contains deploy", channel, user)
    assert channel.configs["default"]["conditions"][0]["case_sensitive"] is False
    assert "(case-insensitive)" in send.call_args.args[3]


@pytest.mark.asyncio
async def test_add_condition_keeps_spaces_in_a_quoted_value():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")
    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message'):
        await process_command(app, 'add condition message contains "deploy to prod" 0', channel, user)
    condition = channel.configs["default"]["conditions"][0]
    assert condition["value"] == "deploy to prod" and condition["case_sensitive"] is False


@pytest.mark.asyncio
async def test_add_condition_treats_a_quoted_flag_word_as_a_value():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")
    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message'):
        await process_command(app, 'add condition message equals "true"', channel, user)
    assert channel.configs["default"]["conditions"][0]["value"] == "true"


@pytest.mark.asyncio
@pytest.mark.parametrize("command,expected", [
    ("add condition nope contains x", "Unknown *condition variable*"),
    ("add condition message bogus x", "Invalid *condition operator*"),
    ("add condition message empty something", "takes no value"),
    ("add condition message contains", "needs a value"),
    ("add condition message regex [unclosed", "Invalid pattern"),
    ("set condition-mode sometimes", "Invalid *condition mode*"),
])
async def test_add_condition_rejections(command, expected):
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")
    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, command, channel, user)
    assert expected in send.call_args.args[3]
    assert channel.configs["default"]["conditions"] == []


@pytest.mark.asyncio
async def test_duplicate_condition_is_refused_but_a_different_case_flag_is_not():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")
    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, "add condition message contains deploy", channel, user)
        await process_command(app, "add condition message contains deploy", channel, user)
        assert "is already set" in send.call_args.args[3]
        assert len(channel.configs["default"]["conditions"]) == 1
        # Differing only in case sensitivity makes it a genuinely different test.
        await process_command(app, 'add condition message contains "deploy" 1', channel, user)
    assert len(channel.configs["default"]["conditions"]) == 2


@pytest.mark.asyncio
async def test_clear_conditions_and_match_mode():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")
    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message'):
        await process_command(app, "add condition message not_empty", channel, user)
        await process_command(app, "set condition-mode any", channel, user)
        assert channel.configs["default"]["conditions_mode"] == "any"
        await process_command(app, "clear conditions", channel, user)
    assert channel.configs["default"]["conditions"] == []


@pytest.mark.asyncio
async def test_new_condition_patterns_are_recognised_as_commands():
    for text in ("add condition message not_empty", "clear conditions", "set condition-mode any",
                 # the older spellings stay accepted
                 "set conditions-match any", "set condition-logic and", "set condition-combine any"):
        assert hutbot.commands.dispatch.matches_a_command(text), text


# ----- the shared-mutable-default trap -----

@pytest.mark.asyncio
async def test_add_condition_does_not_leak_into_the_defaults():
    """`DEFAULT_CONFIG.copy()` is shallow, so a shared list would leak across configs."""
    app = AsyncMock()
    channel = _mk_channel({})
    user = User("U1", "dave", "Dave", "T")
    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message'):
        await process_command(app, "one add condition message not_empty", channel, user)
        await process_command(app, "two add condition team equals Platform", channel, user)

    assert DEFAULT_CONFIG["conditions"] == []
    assert len(channel.configs["one"]["conditions"]) == 1
    assert len(channel.configs["two"]["conditions"]) == 1
    assert channel.configs["one"]["conditions"] is not channel.configs["two"]["conditions"]


@pytest.mark.asyncio
async def test_add_excluded_team_does_not_leak_into_the_defaults():
    """`add excluded-team` appends in place — with a shared list that poisoned every config."""
    app = AsyncMock()
    channel = _mk_channel({})
    user = User("U1", "dave", "Dave", "T")
    _seed_user_caches()
    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message'):
        await process_command(app, "one add excluded-team Platform", channel, user)

    assert DEFAULT_CONFIG["excluded_teams"] == []
    assert channel.configs["one"]["excluded_teams"] == ["Platform"]


@pytest.mark.asyncio
async def test_default_backfill_gives_each_config_its_own_lists():
    config = {"C1": {"one": {"wait_time": 60}, "two": {"wait_time": 60}}}
    migrated = await migrate_and_apply_defaults(AsyncMock(), config)
    one, two = migrated["C1"]["one"], migrated["C1"]["two"]
    for field in ("conditions", "hours", "excluded_teams", "included_teams", "buttons"):
        assert one[field] is not two[field], field
        assert one[field] is not DEFAULT_CONFIG[field], field


# ----- persistence normalization -----

@pytest.mark.asyncio
async def test_migration_drops_the_outlook_era_condition_fields():
    config = {"C1": {"default": {
        "wait_time": 60,
        "condition": "outlook_calendar",
        "condition_negate": True,
        "outlook_subject_pattern": "standup",
        "outlook_body_pattern": "ooo",
    }}}
    migrated = await migrate_and_apply_defaults(AsyncMock(), config)
    single = migrated["C1"]["default"]
    for dead in ("condition", "condition_negate", "outlook_subject_pattern", "outlook_body_pattern"):
        assert dead not in single, dead
    assert single["conditions"] == []
    assert single["conditions_mode"] == CONDITION_MODE_ALL


@pytest.mark.asyncio
async def test_migration_normalizes_conditions_and_drops_junk():
    config = {"C1": {"default": {
        "wait_time": 60,
        "conditions": [
            {"variable": "{{message}}", "operator": "has", "value": "x"},
            {"variable": "message", "operator": "bogus", "value": "y"},
            {"variable": "no_such_variable", "operator": "contains", "value": "z"},
            "not even a dict",
            {"variable": "message", "operator": "empty", "value": "ignored", "case_sensitive": True},
        ],
        "conditions_mode": "sometimes",
    }}}
    migrated = await migrate_and_apply_defaults(AsyncMock(), config)
    single = migrated["C1"]["default"]
    assert single["conditions"] == [
        {"variable": "message", "operator": "contains", "value": "x", "case_sensitive": False},
        {"variable": "message", "operator": "empty", "value": "", "case_sensitive": False},
    ]
    assert single["conditions_mode"] == CONDITION_MODE_ALL


# ----- deciding early, when nothing can change before the reply fires -----

@pytest.mark.asyncio
@pytest.mark.parametrize("conditions,mode,scheduled", [
    # Nothing to decide.
    ([], "all", True),
    # Settled variables: judged straight away.
    ([_c("message", "contains", "look")], "all", True),
    ([_c("message", "contains", "zzz")], "all", False),
    ([_c("team", "equals", "Platform")], "all", True),
    ([_c("team", "equals", "Support")], "all", False),
    ([_c("user_name", "contains", "Dave")], "all", True),
    ([_c("user_name", "contains", "Nobody")], "all", False),
    # A fire-time variable can only be judged when the reply fires.
    ([_c("calendar_summary", "contains", "daily")], "all", True),
    ([_c("opsgenie_current_user", "not_empty")], "all", True),
    # `message_link` needs a Slack call, so it is deferred too.
    ([_c("message_link", "not_empty")], "all", True),
    # all: one settled failure settles the chain, whatever else is in it.
    ([_c("message", "contains", "zzz"), _c("calendar_summary", "contains", "x")], "all", False),
    # any: a deferred condition could still carry it, so nothing is decided early.
    ([_c("message", "contains", "zzz"), _c("calendar_summary", "contains", "x")], "any", True),
    # any: every condition settled and none match -> it can never pass.
    ([_c("message", "contains", "zzz"), _c("team", "equals", "Support")], "any", False),
    ([_c("message", "contains", "zzz"), _c("team", "equals", "Platform")], "any", True),
])
async def test_a_reply_is_only_queued_when_the_conditions_could_still_pass(conditions, mode, scheduled):
    app = AsyncMock()
    cfg = {**copy.deepcopy(DEFAULT_CONFIG), "conditions": conditions, "conditions_mode": mode}
    channel = Channel(id="C1", name="general", configs={"default": cfg})
    hutbot.state.channel_config["C1"] = channel.configs
    user = User("U1", "dave", "Dave Grieser", "Platform")
    with patch('hutbot.scheduling.schedule_reply', new=AsyncMock()) as sched, \
         patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()):
        await hutbot.routing.handle_channel_message(app, "token", channel, user, "please look at this", "1.1")
    assert (sched.call_count == 1) is scheduled


@pytest.mark.asyncio
async def test_deciding_early_never_touches_the_network():
    """Nothing settled can reference a provider or the permalink, so none may be fetched."""
    app = AsyncMock()
    cfg = {**copy.deepcopy(DEFAULT_CONFIG), "conditions": [_c("message", "contains", "zzz")]}
    channel = Channel(id="C1", name="general", configs={"default": cfg})
    hutbot.state.channel_config["C1"] = channel.configs
    with patch('hutbot.scheduling.schedule_reply', new=AsyncMock()), \
         patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()), \
         patch('hutbot.slackcache.get_message_permalink', new=AsyncMock()) as permalink, \
         patch('hutbot.opsgenie.get_opsgenie_template_variables', new=AsyncMock(return_value={})) as opsgenie, \
         patch('hutbot.calendarfeed.get_calendar_template_variables', new=AsyncMock(return_value={})) as calendar:
        await hutbot.routing.handle_channel_message(
            app, "token", channel, User("U1", "dave", "Dave", "Platform"), "please look", "1.1")
    permalink.assert_not_awaited()
    opsgenie.assert_not_awaited()
    calendar.assert_not_awaited()


def test_conditions_ruled_out_leaves_fire_time_conditions_alone():
    config = {"conditions": [_c("calendar_summary", "contains", "daily")], "conditions_mode": "all"}
    # No calendar variable resolved at all, and it still must not be ruled out.
    assert conditions_ruled_out(config, {"message": "hi"}) == (False, "")


def test_settled_condition_variables_excludes_fire_time_ones():
    config = {"conditions": [
        _c("message", "contains", "x"),
        _c("calendar_summary", "contains", "y"),
        _c("opsgenie_current_user", "not_empty"),
        _c("message_link", "not_empty"),
        _c("team", "equals", "Platform"),
    ]}
    assert settled_condition_variables(config) == {"message", "team"}


# ----- how a condition is written out -----

def test_replies_put_the_variable_in_a_code_span():
    """`show config` prints inside a code fence, where backticks would be literal."""
    condition = _c("message", "contains", "urgent")
    assert describe_condition(condition) == '{{message}} contains "urgent" (case-insensitive)'
    assert describe_condition(condition, code=True) == '`{{message}}` contains "urgent" (case-insensitive)'


@pytest.mark.asyncio
async def test_add_condition_reply_uses_a_code_span():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")
    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, "add condition message contains deploy", channel, user)
    assert '`{{message}}` contains "deploy" (case-insensitive)' in send.call_args.args[3]


@pytest.mark.asyncio
async def test_show_config_leaves_the_variable_bare_inside_the_fence():
    app = AsyncMock()
    cfg = {**copy.deepcopy(DEFAULT_CONFIG), "conditions": [_c("message", "contains", "deploy")]}
    channel = Channel(id="C1", name="general", configs={"default": cfg})
    with patch('hutbot.messaging.send_message') as send:
        await show_config(app, channel, User("U1", "dave", "Dave", "T"), "")
    block = sent_messages(send).split("```")[1]
    assert '{{message}} contains "deploy" (case-insensitive)' in block
    assert '`{{message}}`' not in block


# ----- a condition may read another moment -----

@pytest.mark.asyncio
async def test_add_condition_accepts_a_calendar_selector():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, "add condition calendar_summary(at=+1d,offset=next) contains Wartung", channel, user)

    condition = channel.configs["default"]["conditions"][0]
    assert condition == {"variable": "calendar_summary", "operator": "contains", "value": "Wartung",
                         "case_sensitive": False, "at": "+1d", "offset": "next"}
    assert 'at="+1d"' in send.call_args.args[3] and "offset=next" in send.call_args.args[3]


@pytest.mark.asyncio
@pytest.mark.parametrize("spec,expected", [
    ("message(at=+1d) contains x", "does not read a calendar event"),
    ("calendar_summary(at=tomorrow) contains x", "must look like"),
    ("calendar_summary(offset=2h) contains x", "counts events"),
    ("calendar_summary(nth=1) contains x", "takes only `at` and `offset`"),
    ("calendar_summary(at=2026-08-27 09:00) contains x", "without a space"),
])
async def test_add_condition_rejects_an_unusable_selector(spec, expected):
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, f"add condition {spec}", channel, user)

    assert expected in send.call_args.args[3]
    assert not channel.configs["default"]["conditions"]


def test_a_condition_judges_the_slice_its_selector_names():
    """The condition and a message with the same arguments read one resolved value."""
    from hutbot.constants import event_slice_name as slice_name

    variables = {"calendar_summary": "Today",
                 f"__{slice_name('calendar_summary', '+1d', '')}": "Wartungsfenster"}
    tomorrow = {"variable": "calendar_summary", "operator": "contains", "value": "Wartung", "at": "+1d"}
    today = {"variable": "calendar_summary", "operator": "contains", "value": "Wartung"}

    assert hutbot.conditionutil.evaluate_conditions({"conditions": [tomorrow]}, variables)[0] is True
    assert hutbot.conditionutil.evaluate_conditions({"conditions": [today]}, variables)[0] is False


def test_a_condition_on_a_list_slice_matches_any_entry():
    from hutbot.constants import event_slice_name as slice_name

    stem = slice_name("calendar_attendee_emails", "", "next")
    variables = {"calendar_attendee_emails": "ann@example.com",
                 "__calendar_attendee_emails_items": ["ann@example.com"],
                 f"__{stem}": "bob@example.com, cleo@example.com",
                 f"__{stem}_items": ["bob@example.com", "cleo@example.com"]}
    condition = {"variable": "calendar_attendee_emails", "operator": "equals",
                 "value": "cleo@example.com", "offset": "next"}

    assert hutbot.conditionutil.evaluate_conditions({"conditions": [condition]}, variables)[0] is True


def test_a_selector_is_dropped_from_a_condition_that_cannot_use_one():
    """`at` on a non-calendar variable is meaningless, so it is not kept."""
    condition = {"variable": "message", "operator": "contains", "value": "x", "at": "+1d"}

    assert hutbot.conditionutil.normalize_condition(condition)[4:] == ("", "")


@pytest.mark.asyncio
async def test_add_condition_accepts_a_moment_on_a_clock_variable():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, "add condition date(at=+2w) equals 25.08.2026", channel, user)

    assert channel.configs["default"]["conditions"] == [
        {"variable": "date", "operator": "equals", "value": "25.08.2026",
         "case_sensitive": False, "at": "+2w"}]
    assert 'at="+2w"' in send.call_args.args[3]


@pytest.mark.asyncio
@pytest.mark.parametrize("spec,expected", [
    ("date(offset=next) equals x", "no events to count"),
    ("time(at=tomorrow) equals x", "must look like"),
    ("datetime(nth=1) equals x", "takes only `at` and `offset`"),
])
async def test_add_condition_rejects_what_a_clock_variable_cannot_use(spec, expected):
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, f"add condition {spec}", channel, user)

    assert expected in send.call_args.args[3]
    assert not channel.configs["default"]["conditions"]


def test_a_clock_condition_judges_the_moment_its_at_names():
    """The condition and `{{date(at="+2w")}}` in the message read one resolved value."""
    from hutbot.constants import clock_slice_name

    config = {"date_format": "%d.%m.%Y", "time_format": "%H:%M", "datetime_timezone": "Europe/Berlin"}
    variables = {"__timestamp_raw": "1786453297.645799", "date": "11.08.2026",
                 **hutbot.templating.clock_slice_variables(
                     {**config, "conditions": [{"variable": "date", "operator": "equals",
                                                "value": "x", "at": "+2w"}]},
                     "1786453297.645799")}

    assert variables[f"__{clock_slice_name('date', '+2w')}"] == "25.08.2026"
    judge = hutbot.conditionutil.evaluate_conditions
    fortnight = {"variable": "date", "operator": "equals", "value": "25.08.2026", "at": "+2w"}
    today = {"variable": "date", "operator": "equals", "value": "25.08.2026"}

    assert judge({**config, "conditions": [fortnight]}, variables)[0] is True
    assert judge({**config, "conditions": [today]}, variables)[0] is False


def test_an_offset_is_dropped_from_a_clock_condition_but_the_moment_is_kept():
    """`at` moves the instant a clock variable reports; there are no events to count."""
    condition = {"variable": "datetime", "operator": "equals", "value": "x", "at": "+2w", "offset": "next"}

    assert hutbot.conditionutil.normalize_condition(condition)[4:] == ("+2w", "")


def test_a_clock_condition_with_an_unreadable_moment_fails_closed():
    """Only a hand-edited config gets here, and `empty` must not pass on a missing slice."""
    condition = {"variable": "date", "operator": "empty", "at": "next week"}

    met, reason = hutbot.conditionutil.evaluate_conditions(
        {"conditions": [condition]}, {"date": "11.08.2026", "__timestamp_raw": "1786453297.645799"})

    assert met is False
    assert "cannot be read" in reason


def test_condition_clock_moments_are_deduped_and_calendar_free():
    config = {"conditions": [
        {"variable": "date", "operator": "equals", "value": "a", "at": "+2w"},
        {"variable": "date", "operator": "equals", "value": "b", "at": " +2W "},
        {"variable": "time", "operator": "equals", "value": "c", "at": "09:00"},
        # No `at`: the plain variable is already in the namespace.
        {"variable": "datetime", "operator": "not_empty", "value": ""},
        {"variable": "calendar_summary", "operator": "contains", "value": "d", "at": "+1d"},
    ]}

    assert hutbot.conditionutil.condition_clock_moments(config) == [("date", "+2w"), ("time", "09:00")]
    assert hutbot.conditionutil.condition_calendar_selectors(config) == [("+1d", "")]


def test_condition_calendar_selectors_are_deduped():
    config = {"conditions": [
        {"variable": "calendar_summary", "operator": "contains", "value": "a", "at": "+1d"},
        {"variable": "calendar_location", "operator": "contains", "value": "b", "at": " +1D "},
        {"variable": "calendar_summary", "operator": "contains", "value": "c", "offset": "next"},
        {"variable": "message", "operator": "contains", "value": "d"},
    ]}

    assert hutbot.conditionutil.condition_calendar_selectors(config) == [("+1d", ""), ("", "next")]


@pytest.mark.asyncio
async def test_two_conditions_differing_only_in_their_moment_are_not_duplicates():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message'):
        await process_command(app, "add condition calendar_summary(at=+1d) contains x", channel, user)
        await process_command(app, "add condition calendar_summary(at=+2d) contains x", channel, user)

    assert len(channel.configs["default"]["conditions"]) == 2


@pytest.mark.asyncio
async def test_the_migration_keeps_a_conditions_selector():
    app = AsyncMock()
    config = {"C1": {"cal": {**DEFAULT_CONFIG.copy(), "conditions": [
        {"variable": "calendar_summary", "operator": "contains", "value": "x", "at": " +1D ", "offset": "NEXT"},
        {"variable": "calendar_next_summary", "operator": "contains", "value": "y"},
    ]}}}

    with patch('hutbot.persistence.log_warning') as log_warning:
        migrated = await hutbot.persistence.migrate_and_apply_defaults(app, config)

    conditions = migrated["C1"]["cal"]["conditions"]
    # The selector survives, normalised; the condition on a name that no longer exists is dropped.
    assert conditions == [{"variable": "calendar_summary", "operator": "contains", "value": "x",
                           "case_sensitive": False, "at": "+1D", "offset": "NEXT"}]
    assert "calendar_next_summary" in log_warning.call_args.args[0]


@pytest.mark.asyncio
async def test_the_migration_keeps_a_clock_conditions_moment_and_drops_its_offset():
    app = AsyncMock()
    config = {"C1": {"clock": {**DEFAULT_CONFIG.copy(), "conditions": [
        {"variable": "date", "operator": "equals", "value": "25.08.2026", "at": "+2w", "offset": "next"},
    ]}}}

    migrated = await hutbot.persistence.migrate_and_apply_defaults(app, config)

    assert migrated["C1"]["clock"]["conditions"] == [
        {"variable": "date", "operator": "equals", "value": "25.08.2026",
         "case_sensitive": False, "at": "+2w"}]


# ----- a condition may read the config that triggered this one -----

def test_a_condition_can_gate_on_which_config_triggered_this_one():
    triggered = hutbot.templating.parent_template_variables({
        'config_name': 'reminder', 'message': 'Anybody?', 'timestamp': '1786453297.6',
        'recipients': ['<@U1>', '<@U2>'], 'variable_names': ['user'], 'variables': ['<@U1>'],
    })
    unchained = hutbot.templating.parent_template_variables(None)
    judge = hutbot.conditionutil.evaluate_conditions

    is_reminder = {"variable": "parent_config", "operator": "equals", "value": "reminder"}
    assert judge({"conditions": [is_reminder]}, triggered)[0] is True
    assert judge({"conditions": [is_reminder]}, unchained)[0] is False


def test_nothing_triggered_me_is_the_empty_operator():
    """`<no-parent>` counts as empty, so this is the natural way to ask."""
    judge = hutbot.conditionutil.evaluate_conditions
    nobody = {"variable": "parent_config", "operator": "empty", "value": ""}

    assert judge({"conditions": [nobody]}, hutbot.templating.parent_template_variables(None))[0] is True
    assert judge({"conditions": [nobody]}, hutbot.templating.parent_template_variables(
        {'config_name': 'reminder'}))[0] is False


def test_a_condition_on_the_parents_recipients_matches_any_of_them():
    variables = hutbot.templating.parent_template_variables({
        'config_name': 'reminder', 'recipients': ['<@U1>', '<@U2>']})
    judge = hutbot.conditionutil.evaluate_conditions

    assert judge({"conditions": [{"variable": "parent_recipients", "operator": "contains",
                                  "value": "U2"}]}, variables)[0] is True
    assert judge({"conditions": [{"variable": "parent_recipients", "operator": "not_contains",
                                  "value": "U2"}]}, variables)[0] is False
    assert judge({"conditions": [{"variable": "parent_recipients", "operator": "not_contains",
                                  "value": "U9"}]}, variables)[0] is True


def test_a_condition_on_the_parents_variables_matches_any_entry():
    variables = hutbot.templating.parent_template_variables({
        'config_name': 'reminder', 'variable_names': ['user', 'message'],
        'variables': ['<@U1>', 'DB down']})

    assert hutbot.conditionutil.evaluate_conditions(
        {"conditions": [{"variable": "parent_variables", "operator": "contains", "value": "DB"}]},
        variables)[0] is True


@pytest.mark.asyncio
async def test_a_parent_condition_is_settled_so_it_is_judged_the_same_at_arrival():
    """Why the parent family is not a fire-time variable: only `message` rules are judged at
    arrival, and a `message` rule is never the config a button or a timeout runs — so the
    answer at arrival is the same placeholder it would be at fire time."""
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(),
              "conditions": [{"variable": "parent_config", "operator": "equals", "value": "reminder"}]}
    channel = _mk_channel({"default": config})

    assert "parent_config" in hutbot.conditionutil.settled_condition_variables(config)
    ruled_out, reason = await hutbot.actions.conditions_ruled_out_at_arrival(
        app, "token", channel, config, "default", {"text": "DB down"})

    assert ruled_out is True
    assert "parent_config" in reason


@pytest.mark.asyncio
async def test_add_condition_accepts_a_parent_variable():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, "add condition parent_config equals reminder", channel, user)

    # No `at`/`offset` keys: those are stored only for a variable that reads a calendar event.
    assert channel.configs["default"]["conditions"] == [
        {"variable": "parent_config", "operator": "equals", "value": "reminder", "case_sensitive": False}]


@pytest.mark.asyncio
async def test_add_condition_rejects_a_selector_on_a_parent_variable():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "dave", "Dave", "T")

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, "add condition parent_date(at=+1d) equals x", channel, user)

    assert "does not read a calendar event" in send.call_args.args[3]
    assert not channel.configs["default"]["conditions"]
