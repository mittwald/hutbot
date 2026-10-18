"""The `{{variable}}` reference: which variables exist, and what their arguments do.

Both places that document them read from here — `messaging.send_variables_help_message`, which
prints the reference into a channel, and the config UI, which shows it in a modal beside the
fields that take one. A second copy of this text would drift the day a variable is added.

Grouped from the same sets the renderer resolves, so a new variable appears in the reference
without anyone having to remember this file.

A leaf: `constants` only.
"""

from .constants import (
    CALENDAR_TEMPLATE_VARIABLES,
    CONDITION_OPERATORS_ORDERED,
    DATETIME_TEMPLATE_VARIABLES,
    OPSGENIE_TEMPLATE_VARIABLES,
    PARENT_TEMPLATE_VARIABLES,
    PRESS_TEMPLATE_VARIABLES,
    SUPPORTED_TEMPLATE_VARIABLES,
)


def variable_groups() -> list[tuple[str, set]]:
    """Every variable, grouped by what it describes."""
    general_variables = (SUPPORTED_TEMPLATE_VARIABLES - DATETIME_TEMPLATE_VARIABLES - OPSGENIE_TEMPLATE_VARIABLES
                         - CALENDAR_TEMPLATE_VARIABLES - PARENT_TEMPLATE_VARIABLES - PRESS_TEMPLATE_VARIABLES)
    groups = [
        ("Message, sender and config", general_variables),
        ("Date and time", DATETIME_TEMPLATE_VARIABLES),
        ("OpsGenie", OPSGENIE_TEMPLATE_VARIABLES),
        ("Calendar", CALENDAR_TEMPLATE_VARIABLES),
        ("The config that triggered this one", PARENT_TEMPLATE_VARIABLES),
        ("The button press that ran this", PRESS_TEMPLATE_VARIABLES),
    ]
    return groups


def argument_notes(command: str) -> list[str]:
    """What the arguments do, with examples — one note per idea, each whole on its own."""
    notes = [
        "Every date/time variable takes `fmt`/`format`, `tz`/`timezone` and `lc`/`locale` arguments, e.g. "
        "`{{opsgenie_next_start_datetime(fmt=\"%d.%m.%Y %H:%M\", tz=\"Europe/Berlin\", lc=\"de_DE\")}}`. "
        f"Without them the config's `{command} [config] set datetime-format` values are used.",
        "`{{date}}`, `{{time}}` and `{{datetime}}` also take `at`, which moves the instant they "
        "render: `{{date(at=\"+2w\")}}` is a fortnight after the triggering message's time, "
        "`{{datetime(at=\"+90m\")}}` an hour and a half after it, and `{{date(at=\"2026-09-01\")}}` "
        "that day. Written the same way as a calendar `at` (below), but counted from the message "
        "rather than from the run — and they take no `offset`, having no events to count.",
        "Every calendar variable describes *one* event, and two arguments choose which. "
        "`offset` counts events — `next`, `prev`, or a number like `+2`/`-1` — and `at` names "
        "the moment to count from: `{{calendar_summary}}` is what is running now, "
        "`{{calendar_summary(offset=next)}}` the one after it, and "
        "`{{calendar_summary(at=\"+1d\", offset=next)}}` the event after whatever runs this time "
        "tomorrow. In a gap between events the plain form renders `<no-event>`, and `offset=-1`/"
        "`offset=next` are still the events either side.",
        "`offset=same-day` counts nothing: it is the event running at that moment, or the first "
        "one starting later *the same day*, and `<no-event>` once the day is out. The rota "
        "question — is this day covered from here on? — which `offset=next` answers wrongly by "
        "reporting an entry days later: `{{calendar_other_attendee_emails(at=\"+2w\", "
        "offset=same-day)}}` is empty exactly when nobody has that day.",
        "Write `at` as `2026-08-27 09:00` (a `T` and seconds are both fine), as `2026-08-27` for "
        "midnight that day, as `09:00` for today at that hour, or as a signed offset from now: "
        "`+2h`, `-30m`, `+1d`, `+2w`. `+1d` is this time tomorrow while `+24h` is 24 real hours, "
        "so on the two days a year the clocks change they differ by an hour. A time without a `Z` "
        "or a `+02:00` is read in the config's timezone, and `tz` only decides how the answer is "
        "printed — so an explicit offset is how you name a moment in another zone. A moment in "
        "the past is fine; one the calendar does not reach renders the usual placeholders.",
        "A variable holding a list — the calendar's `{{calendar_attendees}}`/"
        "`{{calendar_attendee_emails}}` and their `other_*` forms, which leave out the organizer — "
        "renders comma-separated, and `nth` picks one entry counting from 1: "
        "`{{calendar_attendees(nth=2)}}` is the second. Asking for an entry that is not there "
        "renders empty.",
        "The `{{parent_*}}` variables describe the config that *triggered* this one — they are "
        "filled in only when a button press or an escalation timeout ran this config, and render "
        "`<no-parent>` otherwise. `{{parent_config}}` is its name, `{{parent_message}}` the full "
        "text it posted, and `{{parent_date}}`/`{{parent_time}}`/`{{parent_datetime}}` when it "
        "posted. `{{message}}` still means the *original* message, so the two are different "
        "things; and where one config runs another which runs a third, the parent is always the "
        "one immediately before.",
        "`{{parent_variables}}` holds what the parent's own `{{…}}` came out as, in the order its "
        "message reads: `{{parent_variables(nth=1)}}` is the first one. `of` names one instead of "
        "counting to it — `{{parent_variables(of=\"calendar_summary\")}}` is whatever the parent "
        "rendered there — which survives someone reordering the parent's message.",
        "`{{parent_recipients}}` is who received the parent's message: the channel for `reply` "
        "and `post-channel`, the person for `dm-user`, and every member for `group-dm`. "
        "`{{parent_action}}` and `{{parent_target}}` are how it was sent. Slack reports delivery "
        "and not readership, so none of these say who *read* it — and for a channel post the "
        "recipient is the conversation, not the people in it.",
        "The `{{press_*}}` variables describe the button press that ran this — usable in an "
        "`ack` text and in a config a button runs, and `<no-press>` anywhere else. "
        "`{{press_label}}` is the label of the button, `{{press_user}}` who pressed it as a "
        "mention and `{{press_user_name}}` their name, and `{{press_date}}`/`{{press_time}}`/"
        "`{{press_datetime}}` when it was pressed (`{{press_timestamp}}` is the raw instant). "
        "`{{press_kind}}` is `user` when a person pressed and `timeout` when nobody did and the "
        "escalation auto-pressed the default button — for a `timeout` there is no presser, so "
        "`{{press_user}}` renders empty. An escalation that runs a config instead of pressing a "
        "button is no press at all, and renders `<no-press>` like everything else.",
        "`{{calendar_name}}` is the built-in calendar's title when a config uses one, and "
        "otherwise the feed's own name — or its redacted URL, when the feed does not name itself.",
        "You can `@mention` someone by email address (`@nico@example.com`) as well as by username, "
        "and the calendar's `{{..._users}}` variables are its people already mapped to Slack "
        "mentions — usable in a message or as a `dm-user`/`group-dm` target.",
        f"*Condition operators*\n{', '.join(f'`{operator}`' for operator in CONDITION_OPERATORS_ORDERED)}\n"
        f"`{command} [config] add condition <variable> <operator> [value] [0|1]` gates the rule; `1` makes "
        "the comparison case sensitive. An operator on a list variable matches when *any* entry matches, "
        "and its `not_` form when *none* does, so `add condition calendar_attendee_emails equals "
        "nico@example.com` asks whether that person is on the event.",
        "A condition on a calendar variable takes `at` and `offset` too, written on the variable: "
        f"`{command} [config] add condition calendar_summary(at=+1d) contains Wartung` gates the rule "
        "on tomorrow's event rather than today's. Write a date and time without a space there "
        "(`at=2026-08-27T09:00`), because the operator is split off first.",
        f"`{{{{date}}}}`, `{{{{time}}}}` and `{{{{datetime}}}}` take `at` in a condition too — "
        f"`{command} [config] add condition date(at=+2w) equals 25.08.2026` — and no `offset`. The "
        "value compared is the one the same expression renders in a message, so it is written in "
        f"the config's `{command} [config] set datetime-format`.",
        "Conditions are checked when the rule fires — for a `message` rule that is after the "
        "reminder delay, judged against the conditions as they were when the message arrived. "
        "A condition that reads only the message or its sender is checked straight away, so no "
        "reminder is queued when it already cannot pass.",
    ]
    return notes


# What each group's variables take, for the one-line hint a picker can show beside a name.
# Derived from the group rather than written per variable, so a new variable is described the
# day it is added.
_GROUP_HINTS = {
    "Date and time": "a moment — takes fmt, tz, lc, at",
    "OpsGenie": "who is on call — takes fmt, tz, lc where it is a time",
    "Calendar": "one calendar event — takes at, offset",
    "The config that triggered this one": "the config that ran this one, or <no-parent>",
    "The button press that ran this": "the press that ran this, or <no-press>",
    "Message, sender and config": "the message, its sender, or this config",
}


def describe_variable(name: str) -> str:
    """A one-line hint for `name`, short enough for a Slack option description (75 chars)."""
    for title, variables in variable_groups():
        if name in variables:
            return _GROUP_HINTS.get(title, title)
    return ""


def condition_operators_note(command: str) -> str:
    """The operator list, for a reference that shows conditions as well as variables."""
    return (", ".join(f"`{operator}`" for operator in CONDITION_OPERATORS_ORDERED)
            + f"\n`{command} [config] add condition <variable> <operator> [value] [0|1]`"
            " gates the rule; `1` makes the comparison case sensitive.")
