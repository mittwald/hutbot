"""The variable reference: one source for the command and for the config UI."""

from tests._common import *

from hutbot import templatedocs


def test_every_variable_belongs_to_exactly_one_group():
    grouped = [name for _, variables in templatedocs.variable_groups() for name in variables]
    assert sorted(grouped) == sorted(SUPPORTED_TEMPLATE_VARIABLES)
    assert len(grouped) == len(set(grouped))


def test_every_variable_has_a_hint_short_enough_for_a_slack_option():
    # Slack truncates an option description silently past 75 characters.
    for name in SUPPORTED_TEMPLATE_VARIABLES:
        hint = templatedocs.describe_variable(name)
        assert 0 < len(hint) <= 75, name


def test_a_variable_nobody_knows_has_no_hint_rather_than_a_wrong_one():
    assert templatedocs.describe_variable("not_a_variable") == ""


def test_a_hint_says_which_arguments_its_group_takes():
    assert "at, offset" in templatedocs.describe_variable("calendar_summary")
    assert "fmt, tz, lc" in templatedocs.describe_variable("datetime")


def test_the_notes_name_the_instances_own_command():
    notes = templatedocs.argument_notes("/hutbot_dev")
    assert any("/hutbot_dev" in note for note in notes)
    assert not any("/hutbot " in note for note in notes)


def test_the_notes_carry_the_examples_that_do_not_fit_in_a_hint():
    joined = "\n".join(templatedocs.argument_notes("/hutbot"))
    for example in ('offset=next', 'at="+1d"', 'nth=2', 'fmt=', 'offset=same-day'):
        assert example in joined, example


def test_every_note_fits_in_one_slack_section():
    for note in templatedocs.argument_notes("/hutbot"):
        assert len(note) <= 3000
