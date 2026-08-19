"""Command dispatch: match a slash-command string and run the matching handler."""

import re
import traceback

from slack_bolt.async_app import AsyncApp

from employee_list import log_error

from .. import state
from .. import messaging
from .. import opsgenie
from .. import calendarfeed
from ..constants import CONFIG_NAME_PATTERN, DEFAULT_CONFIG_NAME, RESERVED_CONFIG_NAMES
from ..textutil import log_debug, strip_quotes

from . import patterns
from . import setters
from . import info


async def parse_and_execute_command(app: AsyncApp, command_text: str, channel, config_name: str, user, thread_ts: str = "", opsgenie_token: str = "", allow_test_message: bool = False, command_ts: str = "") -> bool:
    """Parses and executes a command, returns True if a command was matched."""
    # A bare `/hutbot` — or a lone @mention, whose text is stripped to nothing before it
    # gets here — is someone looking for the command list, not a typo to scold.
    if not command_text.strip():
        await messaging.send_help_message(app, channel, user, thread_ts)
    elif (match := (patterns.TEST_WITH_MESSAGE_PATTERN if allow_test_message else patterns.TEST_PATTERN).match(command_text)):
        test_message = match.group("message") if allow_test_message and match.groupdict().get("message") is not None else ""
        await setters.test_reply_message(app, opsgenie_token, channel, config_name, user, test_message, command_ts, thread_ts)
    elif (match := patterns.SET_WAIT_TIME_PATTERN.match(command_text)):
        await setters.set_wait_time(app, channel, config_name, match.group("wait_time"), user, thread_ts)
    elif (match := patterns.SET_REPLY_MESSAGE_PATTERN.match(command_text)):
        message = strip_quotes(match.group("message"))
        await setters.set_reply_message(app, channel, config_name, message, user, thread_ts)
    elif (match := patterns.SET_OPSGENIE_SCHEDULE_PATTERN.match(command_text)):
        schedule_name = strip_quotes(match.group("schedule"))
        await setters.set_opsgenie_schedule_name(app, channel, config_name, schedule_name, user, thread_ts)
    elif (match := patterns.SET_OPSGENIE_PRIORITY_PATTERN.match(command_text)):
        priority = strip_quotes(match.group("priority"))
        await setters.set_opsgenie_priority(app, channel, config_name, priority, user, thread_ts)
    elif patterns.CLEAR_OPSGENIE_MESSAGE_PATTERN.match(command_text):
        await setters.clear_opsgenie_message(app, channel, config_name, user, thread_ts)
    elif (match := patterns.SET_OPSGENIE_MESSAGE_PATTERN.match(command_text)):
        await setters.set_opsgenie_message(app, channel, config_name, strip_quotes(match.group("message")), user, thread_ts)
    elif patterns.SHOW_CALENDAR_PATTERN.match(command_text):
        await calendarfeed.send_current_calendar_event(app, channel, config_name, user, thread_ts)
    elif patterns.CLEAR_CALENDAR_PATTERN.match(command_text):
        await setters.clear_calendar_url(app, channel, config_name, user, thread_ts)
    elif (match := patterns.SET_CALENDAR_PATTERN.match(command_text)):
        await setters.set_calendar_url(app, channel, config_name, match.group("url"), user, thread_ts)
    elif (match := patterns.SET_DATETIME_FORMAT_PATTERN.match(command_text)):
        await setters.set_datetime_format(app, channel, config_name, match.group("values"), user, thread_ts)
    elif patterns.CLEAR_PATTERN_PATTERN.match(command_text):
        await setters.clear_pattern(app, channel, config_name, user, thread_ts)
    elif (match := patterns.SET_PATTERN_PATTERN.match(command_text)):
        pattern = match.group("pattern")
        case_sensitive = match.group("case_sensitive")
        await setters.set_pattern(app, channel, config_name, pattern, case_sensitive, user, thread_ts)
    elif (match := patterns.ENABLE_OPSGENIE_PATTERN.match(command_text)):
        await setters.set_opsgenie(app, channel, config_name, True, user, thread_ts)
    elif (match := patterns.DISABLE_OPSGENIE_PATTERN.match(command_text)):
        await setters.set_opsgenie(app, channel, config_name, False, user, thread_ts)
    elif (match := patterns.ENABLE_BOTS_PATTERN.match(command_text)):
        await setters.set_bots(app, channel, config_name, True, user, thread_ts)
    elif (match := patterns.DISABLE_BOTS_PATTERN.match(command_text)):
        await setters.set_bots(app, channel, config_name, False, user, thread_ts)
    elif (match := patterns.ENABLE_ONLY_WORK_DAYS_PATTERN.match(command_text)):
        await setters.set_only_work_days(app, channel, config_name, True, user, thread_ts)
    elif (match := patterns.DISABLE_ONLY_WORK_DAYS_PATTERN.match(command_text)):
        await setters.set_only_work_days(app, channel, config_name, False, user, thread_ts)
    elif patterns.CLEAR_WORK_HOURS_PATTERN.match(command_text):
        await setters.clear_work_hours(app, channel, config_name, user, thread_ts)
    elif (match := patterns.SET_WORK_HOURS_PATTERN.match(command_text)):
        start = strip_quotes(match.group("start"))
        end = strip_quotes(match.group("end"))
        await setters.set_work_hours(app, channel, config_name, start, end, user, thread_ts)
    elif patterns.LIST_TEAMS_PATTERN.match(command_text):
        await info.list_teams(app, channel, user, thread_ts)
    elif patterns.LIST_OPSGENIE_SCHEDULES_PATTERN.match(command_text):
        await info.list_opsgenie_schedules(app, channel, user, thread_ts)
    elif (match := patterns.ON_CALL_PATTERN.match(command_text)):
        schedule_name = strip_quotes(match.group("schedule") or "")
        await opsgenie.send_current_on_call(app, opsgenie_token, channel, config_name, schedule_name, user, thread_ts)
    elif (match := patterns.EMPLOYEE_TEAM_PATTERN.match(command_text)):
        username = strip_quotes(match.group("user"))
        await info.get_team_of(app, channel, username, user, thread_ts)
    elif (match := patterns.ADD_EXCLUDED_TEAM_PATTERN.match(command_text)):
        team = strip_quotes(match.group("team"))
        await setters.add_excluded_team(app, channel, config_name, team, user, thread_ts)
    elif (match := patterns.CLEAR_EXCLUDED_TEAM_PATTERN.match(command_text)):
        await setters.clear_excluded_team(app, channel, config_name, user, thread_ts)
    elif (match := patterns.ADD_INCLUDED_TEAM_PATTERN.match(command_text)):
        team = strip_quotes(match.group("team"))
        await setters.add_included_team(app, channel, config_name, team, user, thread_ts)
    elif (match := patterns.CLEAR_INCLUDED_TEAM_PATTERN.match(command_text)):
        await setters.clear_included_team(app, channel, config_name, user, thread_ts)
    elif (match := patterns.SET_TRIGGER_PATTERN.match(command_text)):
        await setters.set_trigger(app, channel, config_name, match.group("trigger"), match.group("expression"), user, thread_ts)
    elif patterns.CLEAR_CONDITIONS_PATTERN.match(command_text):
        await setters.clear_conditions(app, channel, config_name, user, thread_ts)
    elif (match := patterns.SET_CONDITION_MODE_PATTERN.match(command_text)):
        await setters.set_conditions_mode(app, channel, config_name, match.group("mode"), user, thread_ts)
    elif (match := patterns.ADD_CONDITION_PATTERN.match(command_text)):
        await setters.add_condition(app, channel, config_name, match.group("spec"), user, thread_ts)
    elif (match := patterns.SET_ACTION_PATTERN.match(command_text)):
        await setters.set_action(app, channel, config_name, match.group("action"), match.group("target"), user, thread_ts)
    elif (match := patterns.ADD_BUTTON_PATTERN.match(command_text)):
        await setters.add_button(app, channel, config_name, match.group("label"), match.group("spec"), user, thread_ts)
    elif patterns.CLEAR_BUTTONS_PATTERN.match(command_text):
        await setters.clear_buttons(app, channel, config_name, user, thread_ts)
    elif patterns.CLEAR_ESCALATION_PATTERN.match(command_text):
        await setters.clear_escalation(app, channel, config_name, user, thread_ts)
    elif (match := patterns.SET_ESCALATION_PATTERN.match(command_text)):
        await setters.set_escalation(app, channel, config_name, match.group("minutes"), match.group("kind"), match.group("target"), user, thread_ts)
    elif patterns.RUN_PATTERN.match(command_text):
        await setters.run_config_now(app, opsgenie_token, channel, config_name, user, thread_ts)
    elif patterns.ENABLE_REPLIES_PATTERN.match(command_text):
        await setters.set_replies_enabled(app, channel, config_name, True, user, thread_ts)
    elif patterns.DISABLE_REPLIES_PATTERN.match(command_text):
        await setters.set_replies_enabled(app, channel, config_name, False, user, thread_ts)
    elif (match := patterns.DELETE_CONFIG_PATTERN.match(command_text)):
        name = strip_quotes(match.group("name"))
        await setters.delete_config(app, channel, name, user, thread_ts)
    elif patterns.SHOW_CONFIG_PATTERN.match(command_text):
        await info.show_config(app, channel, user, thread_ts)
    elif patterns.HELP_PATTERN.match(command_text):
        await messaging.send_help_message(app, channel, user, thread_ts)
    elif patterns.WHATSNEW_PATTERN.match(command_text):
        await messaging.send_news_message(app, channel, user, thread_ts)
    else:
        return False
    return True


def matches_a_command(command_text: str, allow_test_message: bool = False) -> bool:
    """Whether `command_text` is a command in its own right.

    Used to tell `<config> <command>` from a `<command>` whose first word happens
    to look like a config name. Every regex in `patterns` is tried, so this cannot
    drift out of step with what `parse_and_execute_command` accepts.
    """
    for name, pattern in vars(patterns).items():
        if not name.endswith("_PATTERN") or not isinstance(pattern, re.Pattern):
            continue
        if name == "TEST_WITH_MESSAGE_PATTERN" and not allow_test_message:
            continue
        if pattern.match(command_text):
            return True
    return False


async def process_command(app: AsyncApp, text: str, channel, user, thread_ts: str = "", opsgenie_token: str = "", allow_test_message: bool = False, command_ts: str = "") -> None:
    try:
        await _process_command(app, text, channel, user, thread_ts, opsgenie_token, allow_test_message, command_ts)
    except Exception as e:
        # Never let a bad command take down the listener: log it and tell the user.
        log_error(f"Failed to process command in #{getattr(channel, 'name', '?')}: {text}", e)
        log_error(traceback.format_exc())
        try:
            await messaging.send_message(app, channel, user, "Sorry, something went wrong while running that command. :confused: Please check the syntax with `" + state.slash_command + " help`.", thread_ts)
        except Exception as send_error:
            log_error("Failed to report command error to the user:", send_error)


async def _process_command(app: AsyncApp, text: str, channel, user, thread_ts: str = "", opsgenie_token: str = "", allow_test_message: bool = False, command_ts: str = "") -> None:
    text = text.replace(f"<@{state.bot_user_id}>", "").strip()
    log_debug(channel, f"Received command for channel #{channel.name}: {text}")
    # Replies quote this back, so a mention and a slash command read the same way.
    state.current_command.set(f"{state.slash_command} {text}".strip())
    command_ts = command_ts or thread_ts

    async def run(command_text: str, config_name: str) -> bool:
        return await parse_and_execute_command(app, command_text, channel, config_name, user, thread_ts, opsgenie_token, allow_test_message, command_ts)

    parts = text.split(None, 1)
    leading_word, remainder = (parts[0], parts[1]) if len(parts) > 1 else ("", "")

    # `<config> <command>` and `<command>` can both fit the same text — say a config
    # named `trigger` and the command `trigger cron "…"`. An existing config wins
    # that tie, because naming one is deliberate; otherwise the text is a command
    # for the default config.
    if remainder and leading_word in channel.configs and matches_a_command(remainder, allow_test_message):
        if await run(remainder, leading_word):
            return

    if await run(text, DEFAULT_CONFIG_NAME):
        return

    # Nothing matched as a command, so a leading word can only be a config name —
    # including one that does not exist yet, which is how configs are created.
    if remainder and matches_a_command(remainder, allow_test_message):
        if leading_word.lower() in RESERVED_CONFIG_NAMES:
            await messaging.send_message(app, channel, user, f"`{leading_word}` cannot be a configuration name; it starts a command. Check the syntax with `{state.slash_command} help`.", thread_ts)
            return
        if not CONFIG_NAME_PATTERN.match(leading_word):
            await messaging.send_message(app, channel, user, f"Invalid config name: `{leading_word}`. Only characters `A-Z`, `a-z`, `0-9`, `.`, `:`, `/`, `-`, `_` are allowed.", thread_ts)
            return
        if await run(remainder, leading_word):
            return

    await messaging.send_message(app, channel, user, f"Huh? :thinking_face: Maybe type `{state.slash_command} help` for a list of commands.", thread_ts)
