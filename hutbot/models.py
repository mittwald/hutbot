"""Data types shared across the package: namedtuples + template expression."""

import collections
from collections.abc import Sequence
from dataclasses import dataclass
from typing import NamedTuple

ScheduledReply = collections.namedtuple('ScheduledReply', ['task', 'user_id'])
# `is_bot` defaults to False so the many four-field constructions stay valid.
User = collections.namedtuple('User', ['id', 'name', 'real_name', 'team', 'is_bot'], defaults=(False,))
Usergroup = collections.namedtuple('Usergroup', ['id', 'handle', 'name'])
Channel = collections.namedtuple('Channel', ['id', 'name', 'configs'])
# The two Opsgenie credentials, which are not interchangeable: alerts and the heartbeat ping go
# through an *integration* API key (Teams -> Integrations -> API), while reading a schedule or its
# timeline needs an *account* API key (Settings -> API key management) — an integration key is not
# authorized for those, and a read-only account key is not authorized to create alerts. Both travel
# together because one rule run renders on-call variables and then posts the alert.
OpsGenieTokens = collections.namedtuple('OpsGenieTokens', ['alert', 'api'], defaults=("", ""))
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
# One resolved calendar selection, kept beside the variables it filled: the `at`/`offset` as
# they were written, the namespace prefix their slice lives under ("" for the default
# selection), the instant they resolved to, and the event that was running there (or None).
# `test` prints these, so a preview can show which event each moment actually found without
# fetching the feed a second time.
CalendarSelection = collections.namedtuple('CalendarSelection', ['at', 'offset', 'prefix', 'instant', 'event'])


class BuiltinCalendar(NamedTuple):
    """One of the instance's built-in calendars: from the calendar bridge, or from the environment.

    `url` carries a secret token, so only `name` and `title` are ever echoed to a user or handed
    to the web UI. `title` is empty for a bridge calendar whose ICS has not been read yet, which
    is what `display_title` covers; `bridge` says which of the two sources brought this one.
    """

    name: str
    title: str
    url: str
    # Whether the bridge listing brought this one, as opposed to HUTBOT_BUILTIN_CALENDARS. Defaults
    # to False so the many three-field constructions stay valid.
    bridge: bool = False

    @property
    def display_title(self) -> str:
        """What to print for this calendar: its own title, or its name until that is known."""
        return self.title or self.name


# The feed a config reads, resolved at fetch time. `builtin` is the built-in's name ("" for a
# per-config URL); `url` is "" when there is nothing to fetch, and `missing` tells the two
# reasons for that apart: nothing configured, or a built-in this instance no longer offers.
CalendarFeed = collections.namedtuple('CalendarFeed', ['url', 'title', 'builtin', 'missing'])


class PressOutcome(NamedTuple):
    """What running a button's action came to — a real press or a timeout auto-press.

    `happened` is whether anything was actually sent, which is what the note replacing the
    buttons may claim; `delivery_failed` separates Slack refusing the post (worth another
    attempt) from a target config declining (settled).

    The two lists exist because one button may run several configs: `ran` names each of them
    with whether it sent, in the order the button lists them, and `retry` names only the ones
    Slack refused — the ones a timeout escalation's next attempt runs again, so a list that
    half went out does not go out twice.
    """

    happened: bool
    delivery_failed: bool
    # Empty tuples rather than empty lists: a NamedTuple default is one object shared by every
    # instance that leaves it out, so a mutable one would be a trap.
    ran: Sequence[tuple[str, bool]] = ()
    retry: Sequence[str] = ()


@dataclass(frozen=True)
class TemplateExpression:
    variable: str
    args: dict[str, str]


class TemplateExpressionError(ValueError):
    pass
