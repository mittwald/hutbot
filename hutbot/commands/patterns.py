"""Compiled regexes for slash-command parsing."""

import re


def create_command_pattern(command_regex: str) -> re.Pattern:
    return re.compile(f'^{command_regex}', re.IGNORECASE)


# Every command that sets something takes an optional leading `set`, so
# `set wait-time 5` and `wait-time 5` are the same command.


HELP_PATTERN = re.compile(r'help', re.IGNORECASE)
WHATSNEW_PATTERN = re.compile(r'news', re.IGNORECASE)
TEST_PATTERN = re.compile(r'^test$', re.IGNORECASE)
TEST_WITH_MESSAGE_PATTERN = re.compile(r'^test(?:\s+(?P<message>.*))?$', re.IGNORECASE)
SET_WAIT_TIME_PATTERN = create_command_pattern(r'(set\s+)?wait([_ -]?time)?\s+(?P<wait_time>.+)')
SET_REPLY_MESSAGE_PATTERN = create_command_pattern(r'(set\s+)?(message|reply)\s+(?P<message>.+)')
SET_OPSGENIE_SCHEDULE_PATTERN = create_command_pattern(r'(set\s+)?opsgenie[_ -]?schedule\s+(?P<schedule>.+)')
SET_OPSGENIE_PRIORITY_PATTERN = create_command_pattern(r'(set\s+)?opsgenie[_ -]?priority\s+(?P<priority>.+)')
CLEAR_OPSGENIE_MESSAGE_PATTERN = create_command_pattern(r'(clear|unset|remove)\s+opsgenie[_ -]?message')
SET_OPSGENIE_MESSAGE_PATTERN = create_command_pattern(r'(set\s+)?opsgenie[_ -]?message\s+(?P<message>.+)')
SET_DATETIME_FORMAT_PATTERN = create_command_pattern(r'(set\s+)?(datetime[_ -]?format|date[_ -]?format|datefmt)\s+(?P<values>.+)')
CLEAR_PATTERN_PATTERN = create_command_pattern(r'(clear|unset|remove)\s+pattern')
SET_PATTERN_PATTERN = create_command_pattern(r'(set\s+)?pattern\s+(?P<pattern>"[^"]*"|\'[^\']*\'|[^\r\n\t\f\v\s"\']+)(?:\s+(?P<case_sensitive>true|false|1|0))?')
ADD_EXCLUDED_TEAM_PATTERN = create_command_pattern(r'(add\s+)?excluded?([_ -]?teams?)?\s+(?P<team>.+)')
CLEAR_EXCLUDED_TEAM_PATTERN = create_command_pattern(r'clear\s+excluded?([_ -]?teams?)?')
ADD_INCLUDED_TEAM_PATTERN = create_command_pattern(r'(add\s+)?included?([_ -]?teams?)?\s+(?P<team>.+)')
CLEAR_INCLUDED_TEAM_PATTERN = create_command_pattern(r'clear\s+included?([_ -]?teams?)?')
LIST_TEAMS_PATTERN = re.compile(r'^(list\s+)?teams?$', re.IGNORECASE)
EMPLOYEE_TEAM_PATTERN = re.compile(r'^team(\s+of)?\s+(?P<user>.+)$', re.IGNORECASE)
LIST_OPSGENIE_SCHEDULES_PATTERN = re.compile(r'^list\s+opsgenie[_ -]?schedules$', re.IGNORECASE)
ON_CALL_PATTERN = create_command_pattern(r'on[_ -]?call(?:\s+(?P<schedule>.+))?$')
ENABLE_OPSGENIE_PATTERN = create_command_pattern(r'enable\s+(opsgenie|alerts?)')
DISABLE_OPSGENIE_PATTERN = create_command_pattern(r'disable\s+(opsgenie|alerts?)')
ENABLE_BOTS_PATTERN = create_command_pattern(r'(enable|include|set)?\s+bots?')
DISABLE_BOTS_PATTERN = create_command_pattern(r'(disable|exclude)\s+bots?')
CLEAR_WORK_HOURS_PATTERN = create_command_pattern(r'(clear|unset|remove)\s+(work[_ -]?)?hours')
SET_WORK_HOURS_PATTERN = create_command_pattern(r'(set\s+)?(work[_ -]?)?hours\s+(?P<start>.+)\s+(?P<end>.+)')
ENABLE_ONLY_WORK_DAYS_PATTERN = create_command_pattern(r'enable\s+(only[_ -]?)?work[_ -]?days')
DISABLE_ONLY_WORK_DAYS_PATTERN = create_command_pattern(r'disable\s+(only[_ -]?)?work[_ -]?days')
SHOW_CONFIG_PATTERN = re.compile(r'^(show\s+)?config(uration)?$', re.IGNORECASE)
DELETE_CONFIG_PATTERN = create_command_pattern(r'delete\s+config\s+(?P<name>.+)')
ENABLE_REPLIES_PATTERN = create_command_pattern(r'enable$')
DISABLE_REPLIES_PATTERN = create_command_pattern(r'disable$')
# The cron expression belongs to the `cron` trigger, so both arrive together.
SET_TRIGGER_PATTERN = create_command_pattern(r'(set\s+)?trigger\s+(?P<trigger>\S+)(?:\s+(?P<expression>.+))?$')
SET_CONDITION_PATTERN = create_command_pattern(r'(set\s+)?condition\s+(?P<condition>.+)')
SET_OUTLOOK_SUBJECT_PATTERN = create_command_pattern(r'(set\s+)?outlook[_ -]?subject\s+(?P<pattern>.+)')
SET_OUTLOOK_BODY_PATTERN = create_command_pattern(r'(set\s+)?outlook[_ -]?body\s+(?P<pattern>.+)')
ENABLE_CONDITION_NEGATE_PATTERN = create_command_pattern(r'enable\s+(condition[_ -]?)?negate')
DISABLE_CONDITION_NEGATE_PATTERN = create_command_pattern(r'disable\s+(condition[_ -]?)?negate')
# The target belongs to the action, so both arrive in one command. `set` is
# optional, like it is for `wait-time` and `message`.
SET_ACTION_PATTERN = create_command_pattern(r'(set\s+)?action\s+(?P<action>\S+)(?:\s+(?P<target>.+))?$')
ADD_BUTTON_PATTERN = create_command_pattern(r'(add\s+)?button\s+(?P<label>"[^"]*"|\'[^\']*\'|\S+)\s+(?P<spec>.+)')
CLEAR_BUTTONS_PATTERN = create_command_pattern(r'clear\s+buttons?')
# `<minutes> <kind> <target>`: the timeout and what it escalates to are one setting.
CLEAR_ESCALATION_PATTERN = create_command_pattern(r'(clear|unset|remove)\s+escalation')
SET_ESCALATION_PATTERN = create_command_pattern(r'(set\s+)?escalation\s+(?P<minutes>\S+)(?:\s+(?P<kind>\S+)(?:\s+(?P<target>.+))?)?$')
RUN_PATTERN = re.compile(r'^(run|fire)$', re.IGNORECASE)
