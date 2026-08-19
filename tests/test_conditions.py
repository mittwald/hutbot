from tests._common import *  # noqa: F401,F403

from hutbot.conditionutil import (
    canonical_match_mode,
    canonical_operator,
    condition_variables,
    describe_condition,
    evaluate_conditions,
    normalize_condition,
    normalize_variable,
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
        {"conditions": conditions, "conditions_match": mode},
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
def test_canonical_match_mode(typed, expected):
    assert canonical_match_mode(typed) == expected


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
    assert normalize_condition(_c("message", "empty", "junk", True)) == ("message", "empty", "", False)
    assert normalize_condition(_c("message", "not_empty", "junk", True)) == ("message", "not_empty", "", False)


# ----- chaining -----

def test_empty_chain_always_passes_under_both_modes():
    """`any` over an empty list must not mean "never"."""
    assert evaluate_conditions({"conditions": []}, VARIABLES) == (True, "")
    assert evaluate_conditions({"conditions": [], "conditions_match": "any"}, VARIABLES) == (True, "")
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
    assert evaluate_conditions({"conditions": conditions, "conditions_match": "bogus"}, VARIABLES)[0] is False


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

def test_describe_condition():
    assert describe_condition(_c("message", "contains", "urgent")) == '{{message}} contains "urgent"'
    assert describe_condition(_c("message", "contains", "urgent", True)) == '{{message}} contains "urgent" (case-sensitive)'
    assert describe_condition(_c("message", "not_empty")) == "{{message}} not_empty"
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
    assert "case-sensitive" not in send.call_args.args[3]


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
    ("set conditions-match sometimes", "Invalid *conditions match*"),
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
        await process_command(app, "set conditions-match any", channel, user)
        assert channel.configs["default"]["conditions_match"] == "any"
        await process_command(app, "clear conditions", channel, user)
    assert channel.configs["default"]["conditions"] == []


@pytest.mark.asyncio
async def test_new_condition_patterns_are_recognised_as_commands():
    for text in ("add condition message not_empty", "clear conditions", "set conditions-match any"):
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
    assert single["conditions_match"] == CONDITION_MATCH_ALL


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
        "conditions_match": "sometimes",
    }}}
    migrated = await migrate_and_apply_defaults(AsyncMock(), config)
    single = migrated["C1"]["default"]
    assert single["conditions"] == [
        {"variable": "message", "operator": "contains", "value": "x", "case_sensitive": False},
        {"variable": "message", "operator": "empty", "value": "", "case_sensitive": False},
    ]
    assert single["conditions_match"] == CONDITION_MATCH_ALL
