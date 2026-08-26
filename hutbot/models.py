"""Data types shared across the package: namedtuples + template expression."""

import collections
from dataclasses import dataclass

ScheduledReply = collections.namedtuple('ScheduledReply', ['task', 'user_id'])
# `is_bot` defaults to False so the many four-field constructions stay valid.
User = collections.namedtuple('User', ['id', 'name', 'real_name', 'team', 'is_bot'], defaults=(False,))
Usergroup = collections.namedtuple('Usergroup', ['id', 'handle', 'name'])
Channel = collections.namedtuple('Channel', ['id', 'name', 'configs'])
OpsGeniePeriod = collections.namedtuple('OpsGeniePeriod', ['recipient_email', 'slack_user', 'start', 'end'])
OpsGenieContext = collections.namedtuple('OpsGenieContext', ['schedule_name', 'current', 'next'])
# A single calendar entry read from an ICS feed. `start`/`end` are ISO-8601 strings
# (like OpsGeniePeriod) so the date/time formatters can re-render them; for an all-day
# event `end` is the *inclusive* last day, not the RFC-exclusive one.
# `attendees` and `attendee_emails` are lists; an attendee may have a name without a usable
# address, or an address without a name, so the two are collected independently.
CalendarEvent = collections.namedtuple('CalendarEvent', ['uid', 'summary', 'location', 'description', 'organizer', 'organizer_email', 'attendees', 'attendee_emails', 'other_attendees', 'other_attendee_emails', 'status', 'start', 'end', 'all_day'])
# The feed's name plus the one event a selection resolved to. Which event is a matter of
# the `at`/`offset` template arguments, not of two fixed fields.
CalendarContext = collections.namedtuple('CalendarContext', ['name', 'event'])
# One of the instance's built-in calendars, read from HUTBOT_BUILTIN_CALENDARS. `url` carries a
# secret token, so only `name` and `title` are ever echoed to a user or handed to the web UI.
BuiltinCalendar = collections.namedtuple('BuiltinCalendar', ['name', 'title', 'url'])
# The feed a config reads, resolved at fetch time. `builtin` is the built-in's name ("" for a
# per-config URL); `url` is "" when there is nothing to fetch, and `missing` tells the two
# reasons for that apart: nothing configured, or a built-in this instance no longer offers.
CalendarFeed = collections.namedtuple('CalendarFeed', ['url', 'title', 'builtin', 'missing'])


@dataclass(frozen=True)
class TemplateExpression:
    variable: str
    args: dict[str, str]


class TemplateExpressionError(ValueError):
    pass
