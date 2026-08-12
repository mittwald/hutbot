"""Command dispatch: match a slash-command string and run the matching handler."""

import traceback

from slack_bolt.async_app import AsyncApp

from employee_list import log_error

from .. import state
from .. import messaging
from .. import opsgenie
from ..constants import CONFIG_NAME_PATTERN, DEFAULT_CONFIG_NAME
from ..textutil import log_debug, strip_quotes

from . import patterns
from . import setters
from . import info


async def parse_and_execute_command(app: AsyncApp, command_text: str, channel, config_name: str, user, thread_ts: str = "", opsgenie_token: str = "", allow_test_message: bool = False, command_ts: str = "") -> bool:
    """Parses and executes a command, returns True if a command was matched."""
    if (match := (patterns.TEST_WITH_MESSAGE_PATTERN if allow_test_message else patterns.TEST_PATTERN).match(command_text)):
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
    elif (match := patterns.SET_DATETIME_FORMAT_PATTERN.match(command_text)):
        await setters.set_datetime_format(app, channel, config_name, match.group("values"), user, thread_ts)
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
    elif (match := patterns.SET_WORK_HOURS_PATTERN.match(command_text)):
        if match.group("all_day"):
            start = end = "0:00"
        else:
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
        await setters.set_trigger(app, channel, config_name, match.group("trigger"), user, thread_ts)
    elif (match := patterns.SET_CRON_PATTERN.match(command_text)):
        await setters.set_schedule_cron(app, channel, config_name, match.group("cron"), user, thread_ts)
    elif (match := patterns.SET_SCHEDULE_TIMEZONE_PATTERN.match(command_text)):
        await setters.set_schedule_timezone(app, channel, config_name, match.group("tz"), user, thread_ts)
    elif (match := patterns.SET_CONDITION_PATTERN.match(command_text)):
        await setters.set_condition(app, channel, config_name, match.group("condition"), user, thread_ts)
    elif (match := patterns.SET_OUTLOOK_SUBJECT_PATTERN.match(command_text)):
        await setters.set_outlook_pattern(app, channel, config_name, "outlook_subject_pattern", match.group("pattern"), user, thread_ts)
    elif (match := patterns.SET_OUTLOOK_BODY_PATTERN.match(command_text)):
        await setters.set_outlook_pattern(app, channel, config_name, "outlook_body_pattern", match.group("pattern"), user, thread_ts)
    elif patterns.ENABLE_CONDITION_NEGATE_PATTERN.match(command_text):
        await setters.set_condition_negate(app, channel, config_name, True, user, thread_ts)
    elif patterns.DISABLE_CONDITION_NEGATE_PATTERN.match(command_text):
        await setters.set_condition_negate(app, channel, config_name, False, user, thread_ts)
    elif (match := patterns.SET_ACTION_PATTERN.match(command_text)):
        await setters.set_action(app, channel, config_name, match.group("action"), match.group("target"), user, thread_ts)
    elif (match := patterns.ADD_BUTTON_PATTERN.match(command_text)):
        await setters.add_button(app, channel, config_name, match.group("label"), match.group("spec"), user, thread_ts)
    elif patterns.CLEAR_BUTTONS_PATTERN.match(command_text):
        await setters.clear_buttons(app, channel, config_name, user, thread_ts)
    elif patterns.CLEAR_DEFAULT_BUTTON_PATTERN.match(command_text):
        await setters.clear_default_button(app, channel, config_name, user, thread_ts)
    elif (match := patterns.SET_DEFAULT_BUTTON_PATTERN.match(command_text)):
        await setters.set_default_button(app, channel, config_name, match.group("label"), user, thread_ts)
    elif (match := patterns.SET_BUTTON_TIMEOUT_TARGET_PATTERN.match(command_text)):
        await setters.set_button_timeout_target(app, channel, config_name, match.group("target"), user, thread_ts)
    elif (match := patterns.SET_BUTTON_TIMEOUT_PATTERN.match(command_text)):
        await setters.set_button_timeout(app, channel, config_name, match.group("minutes"), user, thread_ts)
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
    command_ts = command_ts or thread_ts

    # First, try to parse the command with the default config.
    if await parse_and_execute_command(app, text, channel, DEFAULT_CONFIG_NAME, user, thread_ts, opsgenie_token, allow_test_message, command_ts):
        return

    # If that fails, assume the first part is a config name.
    parts = text.split()
    if len(parts) > 1:
        config_name = parts[0]
        command_text = " ".join(parts[1:])

        if not CONFIG_NAME_PATTERN.match(config_name):
            await messaging.send_message(app, channel, user, f"Invalid config name: `{config_name}`. Only characters `A-Z`, `a-z`, `0-9`, `.`, `:`, `/`, `-`, `_` are allowed.", thread_ts)
            return

        if await parse_and_execute_command(app, command_text, channel, config_name, user, thread_ts, opsgenie_token, allow_test_message, command_ts):
            return

    await messaging.send_message(app, channel, user, f"Huh? :thinking_face: Maybe type `{state.slash_command} help` for a list of commands.", thread_ts)
