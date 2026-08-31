# hutbot Slack Bot

The hutbot is a simple Slack bot that monitors messages in a channel and automatically replies in a thread if no one reacts or responds to the message within a configurable time period (by default 30 minutes). The bot reminds channel members that a message has gone unanswered. Scheduled reminders are cancelled when someone replies in the thread or reacts in a way that does not match the config criteria that caused that reminder to be scheduled, or when the original message is deleted. Users can adjust both the waiting time and the reminder message directly within the channel, including `{{variable}}` placeholders in the reminder text.

Run `/hutbot` (or just `@hutbot` on its own) with nothing after it to get the full command
list; `/hutbot help` does the same. `/hutbot help variables` prints the separate reference of
every `{{variable}}` — grouped by message, date/time, Opsgenie and calendar — plus the
condition operators. Any argument may be quoted with `"`, `'` or backticks —
handy since Slack renders a backticked value as code as you type it.

A reply message can span several lines: a command arrives as a single line, so type `\n`
where the break belongs — `/hutbot set message "First line.\nSecond line."` — and `\\n` when a
literal backslash-n is what you want. Every other backslash is left alone. The web UI takes
real line breaks in its text box instead.

A reply message can `@mention` someone by **email address** — `@d.grieser@example.com` — which
is resolved to their Slack user when the message is set, alongside the existing `@username`
form. An address that maps to nobody is reported there and then rather than rendering wrongly
later.

Reply messages support built-in placeholders such as `{{user}}`, `{{channel}}`, and `{{message_link}}`. `{{date}}`, `{{time}}`, and `{{datetime}}` render the triggering message's time — or the time the rule ran, for `cron`/`manual` triggers and for `test`/`run` — using the config's date/time format, timezone, and locale, and take the same `fmt`/`tz`/`lc` arguments as the Opsgenie date/time variables below, plus the `at` argument of the calendar variables — `{{date(at="+2w")}}` is a fortnight after the instant the plain form reports. `{{timestamp}}` is the raw Slack timestamp of the same instant. If a channel config also has an Opsgenie schedule configured via `/hutbot [config] set opsgenie-schedule <name>`, Hutbot can resolve the current on-call person and expose:

- `{{opsgenie_schedule_name}}` for the configured schedule
- `{{opsgenie_current_user}}` for a Slack `@mention`
- `{{opsgenie_current_email}}` for the Opsgenie recipient email
- `{{opsgenie_current_name}}` for the resolved Slack display name, or the Opsgenie email if no Slack match is found
- `{{opsgenie_current_start_date}}`, `{{opsgenie_current_start_time}}`, and `{{opsgenie_current_start_datetime}}`
- `{{opsgenie_current_end_date}}`, `{{opsgenie_current_end_time}}`, and `{{opsgenie_current_end_datetime}}`
- `{{opsgenie_next_user}}`, `{{opsgenie_next_email}}`, and `{{opsgenie_next_name}}`
- `{{opsgenie_next_start_date}}`, `{{opsgenie_next_start_time}}`, and `{{opsgenie_next_start_datetime}}`
- `{{opsgenie_next_end_date}}`, `{{opsgenie_next_end_time}}`, and `{{opsgenie_next_end_datetime}}`

If a channel config has a calendar feed configured via `/hutbot [config] set calendar <name|url>`,
Hutbot reads the ICS feed and exposes **one event** — by default the one running when the rule
fires. Which event is a matter of two arguments, `offset` and `at`, described below:

- `{{calendar_name}}` for the built-in calendar's **title** when the config uses one, else the
  feed's own name (`X-WR-CALNAME`), else its redacted URL — `<unknown-calendar>` when the
  config names a built-in this instance no longer offers
- `{{calendar_summary}}`, `{{calendar_location}}`, `{{calendar_description}}`
- `{{calendar_organizer}}` (display name) and `{{calendar_organizer_email}}`
- `{{calendar_attendees}}` (display names) and `{{calendar_attendee_emails}}` —
  **lists**, rendered comma-separated — plus `{{calendar_attendee_count}}`
- `{{calendar_other_attendees}}` / `{{calendar_other_attendee_emails}}` — the
  same lists **without the organizer**. A shared mailbox invites itself to the events it
  organizes, so on a rota entry organized by *Notfallhotline* these leave just the person
  actually on call

- `{{calendar_organizer_user}}`, `{{calendar_attendee_users}}` and
  `{{calendar_other_attendee_users}}` — the same people **mapped to Slack users**, as
  `<@U…>` mentions. Addresses are matched against the Slack directory with the bot's usual
  user mapping; anyone without a Slack account is simply left out, so a mapped list can be
  shorter than the address list it came from

- `{{calendar_uid}}`, `{{calendar_status}}`
- `{{calendar_start_date}}`, `{{calendar_start_time}}`, and `{{calendar_start_datetime}}`
- `{{calendar_end_date}}`, `{{calendar_end_time}}`, and `{{calendar_end_datetime}}`

A list variable renders comma-separated, and `nth` picks one entry out of it, counting from 1:
`{{calendar_attendees(nth=2)}}` is the second (`n=2` is the short spelling). Asking for
an entry the list does not have renders **empty** rather than failing, so a message written for
two attendees still reads when there is only one:

```bash
/hutbot oncall set message "On call: {{calendar_other_attendees(nth=1)}} <{{calendar_other_attendee_emails(nth=1)}}> until {{calendar_end_time}}"
```

### Which event: `offset` and `at`

`offset` counts **events** and `at` moves **time**. Either may be left out, and they compose:

```
{{calendar_summary}}                        # running now
{{calendar_summary(offset=next)}}           # the next one — `prev` for the one before
{{calendar_summary(offset=+2)}}             # the one after next; `-2` counts back
{{calendar_summary(at="2026-08-27 09:00")}} # what is on at 09:00 on the 27th
{{calendar_summary(at="+1d", offset=next)}} # the event after whatever runs this time tomorrow
{{calendar_summary(offset=same-day)}}       # running now, else the next one *today* — nothing after midnight
```

In a gap between events the plain form renders `<no-event>` — it never silently reports the
upcoming one — while `offset=prev` and `offset=next` are still the events either side of that
moment. With an event running, `prev` and `next` are its two neighbours. An offset counts at most
20 events either way, and `prev` searches back 90 days (`HUTBOT_CALENDAR_LOOKBACK_DAYS`), so a
longer gap reports `<no-event>` too.

`offset=same-day` is the one value that counts nothing: it is the event running at that moment,
or the first one starting **later the same calendar day** (the day in the config's timezone), and
`<no-event>` once the day is out. That is the question a rota check asks — *is this day covered
from here on?* — and the one `offset=next` cannot answer, because it happily reports an entry
three days later, which is exactly the uncovered day it was asked about. Spelled `same-day`,
`same_day`, `that-day`, `today` or `day`.

```bash
# nobody has the hotline on the day two weeks out — checked at 10:00 for an 18:00 entry
/hutbot notfallhotline-check add condition calendar_other_attendee_emails(at=+2w, offset=same-day) empty
```

`at` accepts:

| Spelling | Means |
| -------- | ----- |
| `at="2026-08-27 09:00"` | that wall clock **in the config's timezone** (a `T` and seconds are both fine) |
| `at="2026-08-27T09:00:00Z"`, `at="2026-08-27T09:00+09:00"` | an absolute instant, converted to the config's timezone |
| `at="2026-08-27"` | **00:00** that day — exactly right for an all-day rota entry, and usually finds nothing on a calendar of timed meetings |
| `at="09:00"`, `at=9` | **today** at that hour, the spelling `set work-hours` takes |
| `at="+2h"`, `at="-30m"`, `at="+1d"`, `at="+2w"` | a signed offset from the moment the rule fires |

`+1d` is *this time tomorrow*; `+24h` is 24 *real* hours — on the two days a year the clocks
change, those differ by an hour. A time without a `Z` or a `+02:00` is read in the config's
timezone, never UTC, and `tz` only decides how the answer is **printed**, so an explicit offset is
how you name a moment in another zone. A moment in the past is fine. A relative `at` is measured
from when the rule runs, so a message reminder with a 30-minute delay measures `+1d` from the
reminder, not from the message. `{{calendar_name}}` takes neither argument.

`{{date}}`, `{{time}}` and `{{datetime}}` take `at` too — but not `offset`, having no events to
count. Their `at` is counted from the instant they already report, the triggering message's time
(or the run's, for `cron`/`manual` and `test`/`run`), which is the one place a relative `at` is not
measured from the run: `{{date(at="+0m")}}` is always the plain form, and the same 30-minute
reminder measures `{{date(at="+1d")}}` from the message it answers. An `at` naming a moment
outside the range a date can hold renders `<unknown>`. A *condition* takes it the same way, written
on the variable — `add condition date(at="+2w") equals 25.08.2026` — and is judged against the very
value the same expression renders in a message.

Calendar date/time variables take the same `fmt`/`tz`/`lc` arguments as the Opsgenie ones. For an
**all-day** event the end is the *inclusive* last day, not the exclusive `DTEND` the ICS file
carries — a one-day event on the 19th reports the 19th, not the 20th. Cancelled events are skipped;
tentative ones are kept, and `{{calendar_status}}` says which is which. Recurring events
(`RRULE`, with `EXDATE` exclusions) are expanded, including their `VTIMEZONE`.

### The config that triggered this one

A button press and an escalation timeout both run another config. The config they run can read
what triggered it through the `parent_*` variables:

- `{{parent_config}}` — the triggering config's name
- `{{parent_message}}` — the full text it posted
- `{{parent_variables}}` — what its own `{{…}}` came out as, in the order its message reads them
- `{{parent_date}}`, `{{parent_time}}` and `{{parent_datetime}}` — when it posted, taking the same
  `fmt`/`tz`/`lc` arguments as every other date/time variable
- `{{parent_timestamp}}` — the raw Slack timestamp of the same instant
- `{{parent_action}}` and `{{parent_target}}` — how it was sent (`reply`, `dm_user`, `group_dm`,
  `post_channel`) and the target it was sent to, already rendered
- `{{parent_recipients}}` — who received it, as `#channel` or `<@person>`: the channel for `reply`
  and `post-channel`, the person for `dm-user`, every member for `group-dm`

`{{parent_variables}}` renders comma-separated like any list variable, and `nth` picks one entry
counting from 1. `of` names one instead of counting to it, which survives someone reordering the
parent's message:

```
{{parent_variables(nth=1)}}                  the first {{…}} of the parent's message
{{parent_variables(of="calendar_summary")}}  whatever the parent rendered there
```

Two things are easy to get wrong. `{{message}}` still means the **original** Slack message, which
travels down the whole chain — `{{parent_message}}` is the text the config immediately before this
one posted, so the two are different things. And where one config runs another which runs a third,
the parent is always the one **immediately** before: the third sees the second, never the first.

Nothing triggered a `message`, `cron` or `manual` run, nor a `test` or `run` command, so there the
whole family renders `<no-parent>`. In a button's `ack` text the family describes the message the
button is attached to, which is how an ack can quote what it is acknowledging.

What this cannot tell you: who *read* the message — Slack reports delivery, not readership — and
which people a channel post reached, because `{{parent_recipients}}` names the channel rather than
its members. A `group-dm` does list its members, as they stood when the message was sent.

```bash
/hutbot escalate set message "No answer to {{parent_config}} from {{parent_datetime}} to {{parent_recipients}}: {{parent_message}}"
/hutbot escalate add condition parent_config equals reminder
```

### The button press that ran this

The `press_*` variables describe the press itself, rather than the config behind it. They are
filled in for a button's `ack` text and for a config a button runs:

- `{{press_label}}` — the label of the button that was pressed
- `{{press_user}}` — who pressed it, as a `<@mention>`, and `{{press_user_name}}` as their name
- `{{press_date}}`, `{{press_time}}` and `{{press_datetime}}` — when it was pressed, taking the same
  `fmt`/`tz`/`lc` arguments as every other date/time variable
- `{{press_timestamp}}` — the raw timestamp of the same instant
- `{{press_kind}}` — `user` when a person pressed the button, `timeout` when nobody did in time and
  the escalation auto-pressed the default button

A `timeout` press has a button and a time but nobody behind it, so `{{press_user}}` and
`{{press_user_name}}` render empty there — which is how one `ack` text can cover both cases:

```bash
/hutbot incident add button "I've got it" ack "{{press_user}} is on it, as of {{press_time}}."
/hutbot page-oncall add condition press_kind equals timeout   # page only when nobody pressed in time
```

An escalation that runs a config instead of auto-pressing a button is a timeout without a press,
so the whole family renders `<no-press>` there — as it does for a `message`, `cron` or `manual`
run and for `test`/`run`.

`{{press_user}}` is not the same as `{{user}}`: a run started by a button still reports the
**original** message's author as `{{user}}`, so the press is an addition to that context and never
a replacement for it.

Opsgenie date/time variables support `fmt`/`format`, `tz`/`timezone`, and `lc`/`locale` arguments, for example `{{opsgenie_next_start_datetime(format='02.01.2006 15:04', timezone='Europe/Berlin', locale='de_DE')}}`. The default date/time output for Opsgenie variables and `/hutbot on-call` can be configured with:

```bash
/hutbot [config] set datetime-format "<date>" "<time>" [<timezone> <locale>]
/hutbot [config] set date-format "<date>" "<time>" [<timezone> <locale>]
/hutbot [config] set datefmt "<date>" "<time>" [<timezone> <locale>]
```

The `<timezone>` is also the timezone the config's work days and work hours are
counted in — `/hutbot [config] set work-hours 9:00 17:00`, `/hutbot [config] clear work-hours` to
react at any hour, and `/hutbot [config] enable only-work-days` for Mon–Fri only. Without a
timezone, all of them fall back to the server's local time.

Instance-wide defaults for configs that set neither come from the deployment
(`time.timezone` / `time.locale` in the Helm chart, `HUTBOT_TIMEZONE` /
`HUTBOT_DEFAULT_DATETIME_LOCALE` for `helmfile`):

- `time.timezone` is the container's `TZ`, i.e. the server local timezone. The
  image itself is UTC, so without it every config that sets no timezone formats
  and counts work hours in UTC.
- `time.locale` is the fallback date/time locale. Only `de` has translations;
  every other locale renders English day/month names. The server's own `LANG` is
  never used for this.

Neither has a default: without them the instance runs UTC with English names.
The `.env` / `.env-dev` files the deploy scripts source are the place to set
them, e.g. `HUTBOT_TIMEZONE='Europe/Berlin'` and
`HUTBOT_DEFAULT_DATETIME_LOCALE='de_DE'`.

`show config` prints what a config actually ends up with, e.g.
`Date/time timezone  Europe/Berlin (CEST, UTC+02:00, server local time)` and
`Date/time locale    de_DE (instance default)`.

Opsgenie alert priority defaults to `P4` and can be configured per channel config with:

```bash
/hutbot [config] set opsgenie-priority <P1|P2|P3|P4|P5>
```

## Calendar feeds

A config can read **one** ICS calendar feed, the same way it has one Opsgenie schedule — either a
**built-in calendar** the instance provides, or a published `.ics` link of your own:

```bash
/hutbot list calendars                  # the built-in calendars available here
/hutbot [config] set calendar <name>    # one of them, by name
/hutbot [config] set calendar <url>     # or a published .ics link
/hutbot [config] clear calendar
/hutbot [config] show calendar          # the event before, the one now, and the next
```

The event a config points at becomes the `{{calendar_*}}` template variables (see above), so a
message can name it — and a condition can gate a rule on it. `offset` and `at` pick a different
event or a different moment: `{{calendar_summary(offset=next)}}`, `{{calendar_summary(at="+1d")}}`.

### Built-in calendars

Built-in calendars come from the instance's **calendar bridge**: it publishes which calendars it
serves, and Hutbot reads that list at startup and then hourly, so a calendar the bridge gains shows
up without a deployment. Each has a `name` (what you type), a `title` (what Hutbot shows — the name
the calendar itself carries) and a feed URL that only the deployment knows. A deployment can offer
further calendars on top, and override one the bridge serves, through
`HUTBOT_BUILTIN_CALENDARS`; both are described under
[Built-in calendar feeds](#built-in-calendar-feeds). An instance with neither has no built-in
calendars, and a config there needs a published `.ics` URL of its own.

Pointing a config at one stores **the name**, never the URL, so `bot.json` never holds a feed
token and rotating one takes effect without editing a single config. `show config` names the
calendar by its title (`Calendar  Platform on-call rota (built-in: rota)`) and `{{calendar_name}}`
renders that same title. Two configs on the same built-in share one fetch.

A built-in name may hold lower-case letters, digits, `.`, `-` and `_` — never `:` or `/` — which
is how `set calendar <value>` tells a name from a URL. If a built-in is renamed or removed while
a config still names it, that config fetches nothing, `{{calendar_name}}` renders
`<unknown-calendar>`, and `show config` says `built-in: rota (not available on this instance)`. A
bridge that is briefly unreachable is *not* that case: the calendars from the last listing stay
available until a later refresh replaces them.

**The URL is a secret.** A published-calendar link needs no login, so possession of it *is* read
access to the calendar. Hutbot therefore only ever echoes a redacted form
(`outlook.office365.com/…`) in `show config` and in the setter's confirmation — and a
built-in calendar's URL is never printed at all, not even redacted, because it belongs to the
instance rather than to the channel that uses it.
The feed is cached for 5 minutes (`HUTBOT_CALENDAR_TTL`, in seconds), and `offset=prev` searches
back 90 days (`HUTBOT_CALENDAR_LOOKBACK_DAYS`) — widen that for a calendar whose events are
months apart. Both are chart values as well (`calendar.ttlSeconds`, `calendar.lookbackDays`), so a
deployment can set them without touching the image.

A remote feed must be `https://`, and URLs pointing at any non-global address — including private,
link-local and the shared `100.64.0.0/10` range — are refused because the bot fetches them from
inside the cluster. The host name is resolved and checked too, at every redirect hop, so a public
name that answers with `10.0.0.1` is refused just the same. **Loopback is exempt**, over plain
`http://` too, so a local file server works while developing:
`/hutbot set calendar http://127.0.0.1:8073/calendar.ics`.

An internal feed — an in-cluster ICS bridge, say — is refused by that same check, which cannot tell
it from a target somebody talked the bot into. Name its host in `HUTBOT_CALENDAR_ALLOWED_HOSTS`
(comma-separated, exact host names, `https://` still required) to exempt it. This is an operator
setting, not something a channel can set, and it exempts one name rather than a range. The
`NETWORKPOLICY_RULES` entry for the host is still needed as well: the allow-list lets the bot try,
the egress rule lets the packet leave.

## Renaming a config

```bash
/hutbot rename config <name> <new-name>
/hutbot delete config <name>
```

A config's name is its identity — there is no separate name field — so renaming one moves
everything that points at it in the same step:

- the button targets (`add button "<label>" config <name>`) and escalation targets
  (`set escalation <minutes> config <name>`) of every config in the channel, including the
  renamed one where it escalates to itself;
- buttoned messages already posted and still waiting for a press, so a press or a timeout
  minutes later still runs the right config;
- reminders already queued for an unanswered message, which keep their deadline.

The reply says what else moved, e.g. *"also updated 2 rules and 1 posted message"*. The
`default` config cannot be renamed, a name already in use is refused, and so is a name that
starts a command (`set`, `delete`, `rename`, …) — the same rules the web UI applies, where
renaming is the **Rename** button next to **Delete rule**.

## Triggers, conditions, and actions

Beyond the classic "reply if a message goes unanswered" behavior, each named config is a **rule**
with a `trigger`, an optional `condition`, and an `action`. The trigger defaults to `message`, so
existing configs keep working unchanged.

- **Triggers** (`/hutbot [config] set trigger <trigger> [<cron expression>]`). The cron trigger
  carries its expression, so a rule can never be left with a schedule that never fires.
  - `set trigger message` — the classic behavior (matches channel messages by pattern/teams/hours).
  - `set trigger cron "0 9 * * 1-5"` — fires on a 5-field cron schedule, in the config's date/time
    timezone (see `set datetime-format`) or server local time without one. `schedule` and
    `scheduled` are accepted as names for this trigger.
  - `set trigger manual` — never fires on its own; used as the target of a button or a button timeout.

- **Conditions** gate a rule on any `{{variable}}`, and apply to **every** trigger. Each one is
  added separately, so several chain together:
  - `/hutbot [config] add condition <variable> <operator> ["value"] [0|1]` — the trailing `0|1`
    is case sensitivity (default `0`, case-**in**sensitive), exactly like `set pattern`.
  - `/hutbot [config] set condition-mode <all|any>` — whether every condition must apply, or
    any one of them is enough. Defaults to `all`.
  - `/hutbot [config] clear conditions` — remove them all; the rule stops being gated.
  - Operators: `empty`, `not_empty`, `equals`, `not_equals`, `contains`, `not_contains`,
    `starts_with`, `not_starts_with`, `ends_with`, `not_ends_with`, `regex`, `not_regex`.
    Common spellings are accepted too (`is`, `=`, `!=`, `has`, `matches`, `not contains`, …).
  - The left-hand side is any supported reply variable, so a rule can react to the message
    (`{{message}}`), the sender (`{{team}}`), the on-call state (`{{opsgenie_current_user}}`),
    or the calendar (`{{calendar_summary}}`).
  - **List variables** — the calendar's `attendees` / `attendee_emails` and their
    `other_*` counterparts — match when *any* entry matches, and their `not_` forms when
    *none* does. So `equals` is a membership test and `not_equals` means "not among
    them", rather than the useless "some entry differs":
    ```bash
    # is this person on the event that is running right now?
    /hutbot oncall add condition calendar_attendee_emails equals nico@example.com
    # …and `at`/`offset` work here too, written on the variable:
    /hutbot oncall add condition calendar_summary(at=+1d) contains Wartung
    # `at` on the clock family as well — no `offset`, they have no events to count
    /hutbot oncall add condition date(at=+2w) equals 25.08.2026
    # nobody from outside the company is on it
    /hutbot oncall add condition calendar_attendee_emails not_contains @external.com
    ```
  - **Quote a value that contains spaces** if you also want the case flag:
    `add condition message contains "deploy to prod" 1`.
  - A condition that cannot be judged (an unknown variable, an invalid regex) counts as **not
    met**, whatever its operator — so a broken config stays quiet instead of paging someone.
  - Conditions are evaluated **when the rule fires** — for a `message` rule that is *after*
    the reminder delay, so a calendar or on-call condition is asked about the moment the
    reply would go out, not the moment the message arrived.
  - Pending work is judged against **the conditions that were in place when it was
    committed to** — when the message arrived for a reminder, and when the message was
    posted for a button or an escalation. Editing a rule never retroactively changes what an
    already-queued reminder or an already-posted buttoned message does, the same way a press
    is resolved against the buttons that were posted. Both snapshots survive a restart.
  - A condition that reads only settled values — the message, its sender, their team, and the
    `{{date}}`/`{{time}}`/`{{datetime}}` family, `at` and all, which count from the message's own
    timestamp — is checked **immediately**, and no reminder is queued at all when it already
    cannot pass.
    Conditions on `{{calendar_*}}`, `{{opsgenie_*}}` or `{{message_link}}` can only be
    answered later, so those always wait.
  - `/hutbot [config] test` prints each condition with ✓/✗ and whether the rule would run.

  ```bash
  # nudge only while a "Composer" meeting is actually running
  /hutbot standup set calendar https://outlook.office365.com/owa/calendar/…/calendar.ics
  /hutbot standup add condition calendar_summary contains composer
  /hutbot standup add condition calendar_summary(offset=next) not_empty
  /hutbot standup add condition message not_empty
  /hutbot standup set condition-mode all
  ```

- **Actions** (`/hutbot [config] set action <action> [<target>]`) decide what the rule does, using
  `reply_message` (with the usual `{{variables}}`) as the body. The recipient is part of the same
  command, so a config can never be left with an action that has nowhere to send.
  - `set action reply` — post in the rule's channel. Takes no target.
  - `set action dm-user <@user>` — DM a single user. The target may be a mention, an email
    address, or a `{{variable}}`, so `set action dm-user {{calendar_other_attendee_users(nth=1)}}`
    DMs whoever the calendar says is on call right now.
  - `set action group-dm <@usergroup>` — open one group DM (mpim) with all members of a Slack user
    group and post once (Slack caps a group DM at 8 members). The target may instead name the
    people directly — mentions or addresses, including from a variable:
    `set action group-dm {{calendar_attendee_users}}`. A bare handle like `@sre` is
    always taken as a user group, so nothing changes for existing configs.
  - A target built from variables is resolved when the rule runs, and the rule simply does not
    send when it resolves to nobody.
  - `set action post-channel <#channel>` — post to another channel. Pick the channel from Slack's
    autocomplete so it arrives as a link, or pass its `C…` id.

- **Buttons** attach interactive buttons to the message a rule sends (including the classic
  unanswered-message reply). Each button is added incrementally with a typed action (the leading
  `add`, like `set` elsewhere, is optional):
  - `/hutbot [config] add button "<label>" config <config>` — run another config (a `manual` rule).
  - `/hutbot [config] add button "<label>" ack [text]` — mark the message handled: stop any
    escalation, remove the buttons, and post `[text]` in the thread when given. Like a reply message,
    the text may use `{{variables}}` and `@mentions`, both resolved against the *original* message
    when pressed, plus the `{{press_*}}` variables of the press itself. `[text]` is **not** a private
    confirmation for whoever pressed: it is posted as a thread reply under the buttoned message, so it
    lands in whatever conversation that message went to — this channel, another channel, or a DM — and
    everyone who can see that conversation can read it. Whoever pressed is named on the message itself,
    where the buttons were.
  - `/hutbot [config] add button "<label>" delay <minutes>` — push the escalation out by N minutes
    and leave the buttons in place (the only button that does not consume the message). It needs an
    escalation to postpone, so set one first; `clear escalation` warns if it strands such a button.
  - `/hutbot [config] clear buttons`
  - `/hutbot [config] set escalation <minutes> button "<label>"` — if nobody presses within
    `<minutes>`, auto-press that button (exactly as a human click would).
  - `/hutbot [config] set escalation <minutes> config <config>` — …or run that config instead.
  - `/hutbot [config] clear escalation` — never escalate; the buttons stay open until pressed.
    The timeout and its target are one setting, so a timer can never exist with nothing to fire.
    Pending escalations survive restarts.
  - A button/timeout that runs a config passes the **original message context** to it, so the target's
    templates and any OpsGenie alert reference the original message. The config it runs can also read
    what triggered it — its name, its text, when it posted and who it reached — through the
    [`{{parent_*}}` variables](#the-config-that-triggered-this-one).
  - A chain of configs is cut off after 10 hops, so a config that escalates to itself (directly or
    around a loop) stops instead of posting once per timeout forever. The count travels with the
    pending message, so a restart does not reset it. `add condition parent_config empty` is the way
    to say "only run when nothing triggered me".
  - Once a message is handled, its buttons are removed and replaced by a one-line note of what
    happened: *Dave Grieser: [I've got it]* or *Dave Grieser: [Page] ▶︎ alarm* for a press, and
    *⌛︎ 1m* or *⌛︎ 5m ▶︎ alarm* when the escalation acted instead.

- **"Need help?" example** — a question that defaults to "Yes" if ignored:
  ```bash
  /hutbot helpcheck set message Need help?
  /hutbot helpcheck add button "Yes" ack "Here's the help doc: …"
  /hutbot helpcheck add button "No" ack
  /hutbot helpcheck set escalation 5 button "Yes"
  ```
  Pressing *Yes* posts the help message; *No* dismisses it; if nobody clicks within 5 minutes, Hutbot
  auto-presses *Yes* and posts the help message.

- **OpsGenie is just a config property**: any config that runs and has OpsGenie enabled sends an alert
  (with `set opsgenie-message "<template>"` to customise the alert text; default is the original
  message). So to **button-gate** an alert, put OpsGenie on a *separate* `manual` config and run it
  from a button or the escalation — don't put OpsGenie on the question config itself (or it would
  alert as soon as the question is posted). Example:
  ```bash
  # question — no OpsGenie
  /hutbot incident set message Incident — on it?
  /hutbot incident add button "I've got it" ack
  /hutbot incident set escalation 5 config page-oncall   # page if nobody acknowledges
  # alert config — OpsGenie on, runs only when escalated (or via a Yes-style button)
  /hutbot page-oncall set trigger manual
  /hutbot page-oncall enable opsgenie
  /hutbot page-oncall set opsgenie-schedule "Team Primary"
  /hutbot page-oncall set opsgenie-message "Unanswered incident in {{channel}}: {{message}}"
  ```
  *I've got it* cancels the escalation (no page); otherwise after 5 minutes `page-oncall` runs and pages
  on-call, referencing the original message. A `delay` button pushes the 5-minute timer out.

Use `/hutbot [config] run` to fire a configuration's action immediately (handy for testing).

### Previewing a rule: `test`

`/hutbot [config] test` renders one configuration without sending anything, and reports, in this
order:

1. **the message**, rendered with the values it has right now;
2. **what the run would do** — where it lands, with the target resolved to the people it actually
   names (a rota rule usually targets `{{calendar_other_attendee_users(nth=1)}}`, and this is where
   you find out who that is), when the rule fires next, what its buttons say, what it would alert,
   and whether it is disabled or missing a target;
3. **the gates and the conditions** — for a `message` rule, the checks the message itself has to
   pass (teams, work days and hours, the pattern, judged against the text you passed), then each
   condition with ✓/✗, and a verdict saying whether the rule would run and what stops it first;
4. **the variables the configuration reads**, grouped by the field that reads them — the message,
   the target, the alert text, each button text, and the conditions;
5. **every calendar event it resolved**, one per moment the templates and conditions name, with the
   attendees, organizer, body and UID behind the values;
6. **the whole variable namespace**, plus every calendar variable at `offset=next` and
   `offset=prev` — the reference half of the command.

A preview resolves more than a run does: it reads the button texts (which a run only renders once
somebody presses) and the two neighbouring events. It also reports what a run would *not* manage:
recipients Slack's 8-member group-DM limit leaves out, a button or escalation pointing at a
configuration that does not exist, an escalation on a rule that posts no buttons (which never arms a
timer), and an empty OpsGenie body on a rule with no triggering message. Long reports are split
across several Slack messages.

`@hutbot [config] test <message>` does the same with `<message>` as `{{message}}`.

## Leaving and rejoining a channel

Configurations outlive channel membership, so removing the bot from a channel would otherwise leave
`cron` rules firing (and pending reminders/escalations coming due) for a channel it can no longer
post in. When Hutbot is removed from a channel (kicked, or `/remove`d):

- every enabled configuration of that channel is disabled and marked as *disabled because Hutbot was
  removed* (`disabled_reason`), which `/hutbot show config` and the web UI show;
- all pending reminders scheduled for that channel are cancelled;
- all pending button escalations are dropped — both those posted in that channel and those posted
  elsewhere by one of its rules (so nothing escalates into a now-disabled configuration).

Configurations are **not** re-enabled automatically. When Hutbot is added back it posts a message
listing the configurations it disabled, which can then be re-enabled with `/hutbot [config] enable`
(or the web UI). Configurations that a user had disabled by hand are left alone and are not part of
that message.

## Web configuration UI

Hutbot can serve a small web UI from the **same bot process** (no separate service) that lets a
logged-in user view and edit the Hutbot rule configuration for the Slack channels they belong to. It
shows configuration only — there is no message log or analytics. It is **disabled by default**.

The calendar section offers the instance's built-in calendars as a dropdown (hidden when there are
none) beside the feed-URL field. The two are mutually exclusive: picking a built-in clears the URL,
and a save carrying both is rejected. A stored built-in this instance no longer offers stays
selected, labelled *not available on this instance*, so saving cannot silently drop it.

The UI is intended to run behind a Keycloak-fronting reverse proxy (e.g. oauth2-proxy). The proxy
authenticates the user and passes their email in a trusted HTTP header. Hutbot resolves that email to
a Slack user (reusing the same employee-list / Slack mapping the bot already uses), determines their
team, and lists the channels that (a) have a Hutbot config **and** (b) the user is a member of.
Editing is gated by channel membership.

> **Security model:** Hutbot **trusts** the configured header. You **must** ensure the bot's HTTP port
> is only reachable through the authenticating proxy (in Kubernetes the Helm chart's NetworkPolicy plus
> a ClusterIP Service + Ingress do this). Anyone able to reach the port directly could spoof the header.

### Enabling it locally

```bash
export HUTBOT_UI_ENABLED=1
# optional overrides:
export HUTBOT_UI_PORT=8080            # default 8080
export HUTBOT_UI_HOST=0.0.0.0         # default 0.0.0.0
export HUTBOT_UI_USER_HEADER=X-Forwarded-Email   # default
python -m hutbot
```

Then test with a manual header:

```bash
curl -H "X-Forwarded-Email: you@yourcompany.com" http://localhost:8080/api/me
curl -H "X-Forwarded-Email: you@yourcompany.com" http://localhost:8080/api/channels
```

Open http://localhost:8080/ in a browser (send the header via a browser extension or your local proxy
during development). Without a valid, resolvable header the API returns `403`.

### Header per proxy

Set `HUTBOT_UI_USER_HEADER` to match the header your proxy sends:

- **oauth2-proxy** → `X-Forwarded-Email` (default)
- **Keycloak gatekeeper (louketo)** → `X-Auth-Email`
- **custom nginx `auth_request`** → whatever header you configure

### Endpoints

- `GET /healthz` — unauthenticated, for Kubernetes probes.
- `GET /api/me`, `GET /api/meta`, `GET /api/channels` — require a resolvable user. `/api/meta`
  carries the option lists the editor needs, including the built-in calendars as **name and title
  only** — their feed URLs never leave the bot.
- `GET`/`PUT`/`POST`/`DELETE` `/api/channels/{id}/configs[/{name}]` — require a resolvable user, and
  channel routes additionally require membership of the channel.

### Kubernetes / Helm

Enable the UI through the chart with the following `values.yaml` keys under `ui:`:

```yaml
ui:
  enabled: true
  port: 8080
  userHeader: "X-Forwarded-Email"
  service:
    type: ClusterIP
  ingress:
    enabled: true
    className: "nginx"
    host: "hutbot.internal.example.com"
    annotations: {}   # put your Keycloak/oauth2-proxy auth annotations here
    tls: []
```

When `ui.enabled` is `true` the chart renders a Service, exposes the container port, adds `/healthz`
readiness/liveness probes, and opens the NetworkPolicy ingress for that port; the Ingress is rendered
when `ui.ingress.enabled` is also `true`. The Keycloak integration itself (oauth2-proxy / annotations)
is the operator's responsibility — Hutbot only consumes the resulting header.

> **Security:** the UI trusts the proxy-set email header, so any pod able to reach the UI port can
> spoof it and edit configs. Restrict the NetworkPolicy ingress to your auth proxy / ingress
> controller with `ui.allowedIngress` (a list of NetworkPolicy peers rendered into the rule's `from:`).
> Leaving it empty allows all sources (back-compat) and is not recommended:
> ```yaml
> ui:
>   allowedIngress:
>     - namespaceSelector:
>         matchLabels:
>           kubernetes.io/metadata.name: ingress-nginx
> ```

## Step 1: Set Up the Slack App

1. **Create a New Slack App**

   - Go to [Slack API: Applications](https://api.slack.com/apps) and click **"Create New App"**.
   - Choose **"From scratch"** and give your app a name and select your workspace.

2. **Create an App-Level Token**

   - Go back to your app's settings.
   - Navigate to **"Basic Information"**.
   - Scroll down to **"App-Level Tokens"**.
   - Click **"Generate Token and Scopes"**.
   - Give it a name (e.g., `default`) and add the scope `connections:write`.
   - Click **"Generate"** and copy the token.

3. **Enable Socket Mode**

   - Go to **"Socket Mode"**.
   - Click on **"Enable Socket Mode"**.

4. **Add Required Permissions**

   - Navigate to **"OAuth & Permissions"** on the left sidebar.
   - Under **"Scopes"**, add the following bot token scopes:
     - `channels:history`
     - `channels:read`
     - `chat:write`
     - `reactions:read`
     - `im:history`
     - `im:read`
     - `im:write`
     - `mpim:history`
     - `mpim:read`
     - `mpim:write`
     - `groups:history`
     - `groups:read`
     - `usergroups:read`
     - `team:read`
     - `users:read`
     - `users:read.email`
     - `commands`

   `users:read.email` is what puts `profile.email` in the `users.list` response, and without
   it the bot has no address for anyone: the web UI rejects every request as unauthenticated,
   and mapping an Opsgenie recipient or a calendar attendee to a Slack user falls back to
   guessing from the address's local part. **Adding a scope to an installed app requires
   reinstalling it** to the workspace before the new scope takes effect.

5. **Enable Event Subscriptions**

   - Go to **"Event Subscriptions"**.
   - Turn on **"Enable Events"**.
   - Under **"Subscribe to bot events"**, add:
     - `message.channels`
     - `reaction_added`
     - `message.groups`
     - `message.im`
     - `message.mpim`
     - `member_joined_channel`
     - `member_left_channel`

6. **Enable Interactivity** (required for buttons)

   - Go to **"Interactivity & Shortcuts"**.
   - Turn on **"Interactivity"**.
   - Because the app uses **Socket Mode**, no Request URL is needed — interactive
     button presses (`block_actions`) are delivered over the same socket.

7. **Add Slash Command**

   - Go to **"Slash Commands"**.
   - Click **"Create New Command"**.
   - Set the command to `/hutbot`.
   - Set the short description to `Configure @Hutbot`.
   - Click **"Save"**.

8. **Install the App**

   - Go to **"Install App"**.
   - Click **"Install App to Workspace"** and authorize the app.
   - Copy the **Bot User OAuth Token**; you'll need it later.

8. **Run the App**

```
export SLACK_BOT_TOKEN='xoxb-your-bot-token'
export SLACK_APP_TOKEN='xapp-your-app-level-token'
pip install -r requirements.txt
python -m hutbot
```

   - See [Hutbot Slack App](https://api.slack.com/apps/A07RQ54Q5H9)
   - See [Hutbot_DEV Slack App](https://api.slack.com/apps/A0BN19HUTAP)
   - Hosted at `nexus-cli get projects p-knksv4 -olink`

9. **Invite Bot**

```
/invite @Hutbot
```

## Docker and Kubernetes Deployment

A GitHub Actions workflow automatically builds and publishes the Docker image to GitHub Container
Registry on pushes to `main` and on tags matching `v*.*.*`. Cutting a release is just pushing a tag:

```bash
git tag v1.1.0
git push origin v1.1.0
```

The published tags are:

| Trigger              | Image tags                     | Deployable |
| -------------------- | ------------------------------ | ---------- |
| Tag push `v1.1.0`    | `v1.1.0`, `1.1.0`              | yes        |
| Push to `main`       | `main`, `latest`               | no         |

```bash
docker pull ghcr.io/mittwald/hutbot:v1.1.0
```

> **Note:** `latest` and `main` are floating convenience tags. Deployments must pin an exact release
> tag — the Helm chart refuses to render if `image.tag` is empty, so a version has to be chosen
> explicitly.

This repository includes a Helm chart under `charts/hutbot` and a Helmfile configuration at `helmfile.yaml.gotmpl`.

**Credentials are never Helm values.** The chart requires `existingSecret` and reads a Kubernetes
Secret it does not manage, synced from Vault out of band before deploying — so no token ends up in
a values file, in the release metadata Helm keeps in the cluster, or in a pipeline variable. `.env`
holds only the non-secret deploy settings and is optional:

```bash
# Slash command this instance listens on; must match the Slack app. Default: /hutbot
export HUTBOT_SLASH_COMMAND='/hutbot'
# Name the bot uses for itself in help/news messages. Default: Hutbot
export HUTBOT_BOT_NAME='Hutbot'
# Timezone and date/time locale of the instance. Empty means UTC and English names.
export HUTBOT_TIMEZONE='Europe/Berlin'
export HUTBOT_DEFAULT_DATETIME_LOCALE='de_DE'
# Egress rules for INTERNAL destinations, as a space-separated list of <port>:<cidr[,cidr...]>
# entries. DNS and every public destination are already allowed by the chart defaults, so a
# public calendar feed or Slack needs nothing here; an internal host does, on the port it
# listens on, or the connection is dropped without a trace. Set NETWORKPOLICY_PUBLIC_EGRESS=false
# to close the public rule, NETWORKPOLICY_ALLOW_DNS=false to close DNS, NETWORKPOLICY_ENABLED=false
# to drop the policy entirely.
export NETWORKPOLICY_RULES='443:192.168.0.15/32 80:10.0.0.0/24,10.0.1.0/24'
# To define host aliases for the pod (/etc/hosts entries), you can set a comma-separated list of <hostname>=<ip> entries:
export HOST_ALIASES='lb.mittwald.it=192.168.0.15'
# Calendar feed hosts that resolve to an internal address and are meant to be fetched anyway.
# Without an entry the bot refuses the fetch and logs the address it resolved to. Needs the
# matching NETWORKPOLICY_RULES entry (and HOST_ALIASES, if cluster DNS does not serve the zone).
export HUTBOT_CALENDAR_ALLOWED_HOSTS='outlook-bridge.prod.example.systems'
# Calendar tunables; unset means the bot's own defaults, 300 seconds and 90 days.
export HUTBOT_CALENDAR_TTL=300
export HUTBOT_CALENDAR_LOOKBACK_DAYS=90
# Minutes between reads of the calendar bridge's listing; unset means 60, `0` reads it once at
# startup. The listing URL itself carries a token and lives in the Secret, not here.
export HUTBOT_CALENDAR_BRIDGE_REFRESH=60
```

To query the employee list locally from your terminal, you can use the standalone helper script:

```bash
python query_employees.py john
python query_employees.py --team Support
python query_employees.py john.slack --cache-only
python query_employees.py john --json
```

The helper reads the same employee cache and `employees-fallback.json` as the bot, so a fallback
record can be checked locally before it is copied onto the state volume.

### Secret sync

Source of truth is Vault at <https://vault.m3.services>: `secrets-coabkube/production/hutbot` for
production, `.../hutbot-dev` for the dev instance. Every field becomes one key of the Kubernetes
Secret named after the release (`mw-internal/hutbot`, `mw-internal/hutbot-dev`). Ordinary fields
reach the bot through individual environment references; `HUTBOT_BUILTIN_CALENDARS` is mounted
only as a file so large lists do not hit the process environment's size limit.

| Field | Required | Purpose |
| ----- | -------- | ------- |
| `SLACK_APP_TOKEN` | yes | Socket Mode connection (`xapp-…`) |
| `SLACK_BOT_TOKEN` | yes | Slack Web API (`xoxb-…`) |
| `OPSGENIE_TOKEN` | no | Opsgenie alerts, on-call lookups, heartbeat |
| `OPSGENIE_HEARTBEAT_NAME` | no | Heartbeat to ping; empty on dev so it cannot ping production's |
| `EMPLOYEE_LIST_USERNAME` | no | Employee-list credentials for team lookups |
| `EMPLOYEE_LIST_PASSWORD` | no | " |
| `EMPLOYEE_LIST_MAPPINGS` | no | `user=alias` overrides for the mapping; `user=-` silences the "cannot be mapped" warning for accounts with no employee record |
| `HUTBOT_CALENDAR_BRIDGE_URL` | no | The calendar bridge's listing endpoint, token included (see below) |
| `HUTBOT_BUILTIN_CALENDARS` | no | Calendars offered on top of the bridge's, and overrides of them (see below) |

```bash
export VAULT_ADDR=https://vault.m3.services
vault login -method=oidc            # Keycloak SSO in the browser
kubectl config use-context coabkube-prod

make sync-secret                        # production Secret `hutbot`
make sync-secret-dev                    # dev Secret `hutbot-dev`
make sync-secret ARGS='--dry-run'       # key names and byte lengths only
make sync-secret ARGS='--restart'       # sync, then roll the deployment
```

Filling an empty Vault path the first time is `scripts/seed-vault.sh`, which reads the fields
out of the env file that used to carry them:

```bash
make seed-vault-dev ARGS='--dry-run'    # field names and byte lengths from .env-dev
make seed-vault-dev                     # write them to .../hutbot-dev
make seed-vault                         # and .../hutbot from .env
make seed-vault ARGS='--calendars ./calendars.json --sync'
```

It picks only the nine secret keys out of the file, drops the ones it does not set (an empty
`OPSGENIE_HEARTBEAT_NAME` stays unset rather than becoming `""`), requires both Slack tokens,
validates a `--calendars` file the way the sync script does, and hands Vault a `@file` so no value
reaches a command line. It **refuses a path that already has fields** unless `--force`, because a
`vault kv put` replaces the whole version: seeding is a one-shot, and everything after it is a
`vault kv patch`.

`scripts/sync-secret.sh` refuses to run against any kube-context but `coabkube-prod`, rejects keys
that are not usable variable names, requires both Slack tokens, ignores Vault fields hutbot does not
read, validates the built-in calendar list and prints its feed hosts, and refuses a sync that would
remove a key the live Secret already has (`--allow-drop`, or `--drop KEY`, to mean it). Values move
through files, never through a command line.

> **`vault kv put` replaces every field.** Use `vault kv patch <path> KEY=…` to change one.
> `secrets-coabkube/production` is a **KV v1** mount today, where there is no `kv patch` and no
> version history to roll back to — so a careless put is unrecoverable and the Secret already in the
> cluster is the only remaining copy. `scripts/edit-calendars.sh` handles that: on v1 it merges the
> sibling fields back in explicitly, and `sync-secret.sh` refuses to write a Secret that would lose
> a key. On a v2 mount both use `kv patch`, and `vault kv rollback -version=N <path>` undoes a bad
> put.

Because the Secret is not part of the release, changing it does not restart the bot — the bot reads
its environment at startup, so pass `--restart` when a change has to take effect now.

Without Vault access, the same Secret can be built from `.env`:

```bash
set -a; . ./.env; set +a
./scripts/sync-secret.sh --local --dry-run
./scripts/sync-secret.sh --local --restart
```

Only the nine keys above are read — `NETWORKPOLICY_RULES` and the other deploy settings stay out of
the Secret — and a key missing from the environment is carried over from the Secret already in the
cluster, so updating one value never needs the others at hand.

### Built-in calendar feeds

The built-in calendars come from the **calendar bridge**. `HUTBOT_CALENDAR_BRIDGE_URL` is its
listing endpoint — `https://<host>/calendars/?token=…`, the token included, which is why it is a
Secret field — and the listing it answers with is a JSON document naming the calendars the bridge
serves:

```json
{"feeds": ["notfallhotline", "cloudhosting", "mkubed", "infrastruktur"]}
```

Each of those hangs off the listing path as `<name>.ics` with the same token, so the bot needs
nothing but that one URL: it reads the listing at startup and then every
`HUTBOT_CALENDAR_BRIDGE_REFRESH` minutes (default 60, `0` reads it once at startup and never again;
`calendar.bridgeRefreshMinutes` is the chart value), and a calendar the bridge gains shows up within
that long rather than at the next restart. Each calendar's **title** is what its own ICS calls
itself (`X-WR-CALNAME`), read once per name and kept for the life of the process; a calendar whose
title cannot be read is shown by its name. One log line per change names the roster:

```
Calendar bridge serves: cloudhosting, infrastruktur, mkubed, notfallhotline.
```

Startup waits for that first listing — at most 45 seconds, then it comes up without it and says so
— before restoring the reminders and button escalations it persisted: one that came due during the
restart runs the moment it is restored, and it has to see the same calendars it saw before. Only the
listing is waited for; the titles behind it are read afterwards, so a calendar is usable (under its
name) the moment it is listed and an unreachable title endpoint delays nothing.

The URLs never appear in a log, a reply or `bot.json` — a config stores the *name*, so rotating the
bridge token takes effect without touching a single config. A bridge that cannot be read
(unreachable, 503, a document that is not a listing) leaves the calendars from the last successful
listing in place and says so; a listing that genuinely names nothing does clear them. An instance
with no bridge configured simply has no bridge-served calendars.

`HUTBOT_BUILTIN_CALENDARS` is the registry **on top of** that: a JSON array of
`{"name", "title", "url"}` objects for calendars the bridge does not serve — one behind a different
bridge, say, or a public feed — and for overriding one it does, since a name in both belongs to the
registry entry (which is then never fetched for a title either). Each URL grants read access to its
calendar, which is why the list lives in the Secret and not in a ConfigMap. The chart projects it as
a file (`/etc/hutbot/builtin-calendars.json`, mode `0440`) and points
`HUTBOT_BUILTIN_CALENDARS_FILE` at it; `builtinCalendars.mountFile=false` disables the registry in
the chart. Source checkouts can still use `HUTBOT_BUILTIN_CALENDARS` directly when no file is
configured.

Create or rotate a registry entry:

```bash
make calendars                      # $EDITOR on the list from Vault, validated, written back
make calendars ARGS='--sync'        # … and sync the Secret + restart in one go
make calendars ARGS='--show'        # print the current list (it contains the feed tokens)
```

On a KV v2 mount that write is a `kv patch` of the one field. On the v1 mount in use today there is
no patch, so the script merges the other fields back in from the copy it read when the edit started
— which is not atomic: nobody else should be editing that path at the same time.

By hand, the shape being the part worth remembering:

```bash
cat > calendars.json <<'JSON'
[
  { "name": "rota", "title": "Platform on-call rota",
    "url": "https://outlook.office365.com/owa/calendar/…/calendar.ics" }
]
JSON
# KV v2 only — it touches just this field. The v1 mount in use today has no `patch`, so there
# `make calendars` is the way: a bare `put` would drop every other field.
vault kv patch secrets-coabkube/production/hutbot HUTBOT_BUILTIN_CALENDARS=@calendars.json
shred -u calendars.json
make sync-secret ARGS='--restart'
```

`@file` keeps the JSON off the command line and byte-exact — and it is `patch`, not `put`, so the
Slack and Opsgenie fields beside it survive. A name may hold lower-case letters, digits, `.`, `-`
and `_`; an entry with a bad name, a blank title or a non-`https` URL is skipped at startup with a
warning naming it, and the rest of the list still loads.

Read a value back:

```bash
vault kv get -field=HUTBOT_BUILTIN_CALENDARS secrets-coabkube/production/hutbot | jq .
# what the cluster has:
kubectl -n mw-internal get secret hutbot -o jsonpath='{.data.HUTBOT_BUILTIN_CALENDARS}' | base64 -d | jq .
# what the pod sees, without the tokens:
kubectl -n mw-internal exec deploy/hutbot -- cat /etc/hutbot/builtin-calendars.json | jq -r '.[].name'
```

The first two print the feed tokens.

The registry is read at startup, so a change to it needs `make sync-secret ARGS='--restart'` (or
`kubectl -n mw-internal rollout restart deploy/hutbot`). The Deployment uses `strategy: Recreate` —
hutbot is a singleton on a ReadWriteOnce volume, so a rolling restart would briefly run two bots
against one `bot.json` — which means every restart has a few seconds of gap.

The bridge's own listing is not read at startup only, so a calendar it gains needs no restart —
but a change to `HUTBOT_CALENDAR_BRIDGE_URL` itself does, since the bot reads its environment once.

**Egress:** a public feed host (`outlook.office365.com` and friends) is covered by the chart's
default public-egress rule — everything outside the private, shared and link-local ranges, on any
port — so it needs no entry anywhere. An internal host needs a `HOST_ALIASES` entry, because
cluster DNS does not serve that zone, a `NETWORKPOLICY_RULES` entry on its port, **and** its name in
`HUTBOT_CALENDAR_ALLOWED_HOSTS`, or the bot refuses the internal address before it dials. With only
some of the three the fetch fails — with a resolution error, a refusal in the log, or no trace at
all. `sync-secret.sh` prints the feed hosts so they can be checked against the rules. The calendar
bridge is such a host: `mittwald-outlook-bridge.prod.mittwald.systems` needs all three, and the
listing goes down the same guarded path as any feed — https only, every redirect hop revalidated.

### Deploy

```bash
make deploy-dev                  # newest release tag, release hutbot-dev
make deploy-dev ARGS='diff'      # preview first
make deploy-prod                 # newest release tag, release hutbot
make deploy-dev IMAGE_TAG=v1.1.0 # or pin one explicitly
```

`IMAGE_TAG` defaults to the most recently created `v*` git tag (`make tags` lists the last five) —
an image is published per pushed tag, so that is the newest deployable one. Sorted by creation date
rather than by version, because git's version sort ranks a prerelease against its release
unpredictably. The target warns when that tag is unknown to your clone (`git fetch --tags`) or when
HEAD has commits the image does not contain, and refuses to deploy with no tag at all. `make image`
labels a local build from `git describe` instead (`BUILD_TAG`), so a dirty working tree can never
masquerade as a release.

The scripts can also be called directly:

```bash
./deploy-prod.sh v1.1.0          # release hutbot, environment default
./deploy-prod.sh v1.1.0 diff     # preview first
./deploy-dev.sh  v1.1.0          # release hutbot-dev, environment dev
```

Both scripts check that the Secret exists **and** carries both Slack tokens, and stop before Helm
runs if not — under `strategy: Recreate` the old pod is gone before a broken new one would start.

They also clear a leftover `spec.strategy.rollingUpdate` block on an existing Deployment. A
Deployment first created with the default `RollingUpdate` strategy carries one the API server filled
in; server-side apply merges `type: Recreate` on top but leaves that block alone, and the API server
then refuses the object outright:

```
spec.strategy.rollingUpdate: Forbidden: may not be specified when strategy `type` is 'Recreate'
```

The equivalent by hand, if you ever hit it outside the scripts — idempotent, and it restarts
nothing, since strategy is no part of the pod template:

```bash
kubectl -n mw-internal patch deployment hutbot --type=merge \
  -p '{"spec":{"strategy":{"type":"Recreate","rollingUpdate":null}}}'
```
`HUTBOT_EXISTING_SECRET` picks a different Secret name. `helmfile` can also be run directly; no
variable in `helmfile.yaml.gotmpl` is required any more, so `helmfile -e default diff` works in a
shell that has never seen a token.

### Deploying a Dev Instance

The Helmfile defines two environments so a second, independent instance can run alongside production
in the same namespace:

| Environment | Release name  | Purpose                                          |
| ----------- | ------------- | ------------------------------------------------ |
| `default`   | `hutbot`      | Production instance                              |
| `dev`       | `hutbot-dev`  | Dev instance (separate Slack app, own PVC/Secret) |

All chart resources are named after the Helm release, so the dev release gets its own Deployment,
PersistentVolumeClaim (`hutbot-dev-pvc`) and NetworkPolicy, and reads its own Secret
(`mw-internal/hutbot-dev`, synced rather than templated). The two instances share nothing.

Register a second Slack app for the dev bot — [Hutbot_DEV Slack App](https://api.slack.com/apps/A0BN19HUTAP) —
and put its credentials in the dev Vault path, with the same field names production uses:

```bash
vault kv put secrets-coabkube/production/hutbot-dev \
  SLACK_APP_TOKEN='<dev app-level token>' \
  SLACK_BOT_TOKEN='<dev bot token>'
make sync-secret-dev
```

Then deploy the `dev` environment:

```bash
./deploy-dev.sh v1.1.0
```

Production is unaffected and keeps deploying with `./deploy-prod.sh <tag>`, which is
`helmfile -e default sync` with the pre-flight checks.

> **Note:** Point the dev instance at its own Opsgenie heartbeat, or leave
> `OPSGENIE_HEARTBEAT_NAME` empty in the dev secret (an empty optional field is left out of the
> Secret rather than rejected), otherwise the dev pod will ping the production heartbeat.

#### Telling the instances apart

`HUTBOT_BOT_NAME` (default `Hutbot`) is the name the bot uses for itself in user-facing text, so the
dev instance introduces itself as *Hutbot (DEV)* in its help and news messages. The Helmfile sets it
per environment (`botName`), and it can be overridden with the environment variable.

The `@mention` examples in the help text are not affected by this: they have to be a working Slack
handle, so they are taken from the bot's own `auth.test` response at startup (`@hutbot` vs.
`@hutbot_dev`) rather than from `HUTBOT_BOT_NAME`.

The name is used everywhere the instance identifies itself:

| Surface           | With `HUTBOT_BOT_NAME='Hutbot (DEV)'`                       |
| ----------------- | ----------------------------------------------------------- |
| Help / news       | *Hi! I am **Hutbot (DEV)*** …                                 |
| Web UI            | Page title, wordmark and messages (served via `/api/meta`)   |
| OpsGenie alert    | Tag `Hutbot (DEV)`, detail `bot: hutbot-dev`                  |

The OpsGenie **alias** — the field OpsGenie deduplicates on — uses a slug of the name
(`Hutbot` → `hutbot`, `Hutbot (DEV)` → `hutbot-dev`) instead of the display name. The production
alias is therefore unchanged, and dev alerts can no longer deduplicate against production ones.

#### Slash command per instance

A Slack app cannot register a slash command that another app already owns, so the dev Slack app has
to use its own — e.g. `/hutbot_dev`. The bot listens on the command in `HUTBOT_SLASH_COMMAND`
(default `/hutbot`) and uses it in all help and error texts, so `/hutbot_dev help` prints
`/hutbot_dev …` examples. If the running instance does not know about the command, Slack Bolt logs:

```
Unhandled request ({'type': None, 'command': '/hutbot_dev'})
```

The Helmfile sets this per environment (`slashCommand` in the `environments` block: `/hutbot` for
`default`, `/hutbot_dev` for `dev`), and it can be overridden per invocation:

```bash
export HUTBOT_SLASH_COMMAND=/hutbot_test
helmfile -e dev sync
```

The command name must match exactly what is configured in the Slack app (the leading `/` is added
automatically if omitted).

Each environment pins a specific image tag in the `environments` block of `helmfile.yaml.gotmpl`
(`imageTag`) — no floating `latest`. Bump that value to roll out a new release, or override it per
invocation to test a build in dev before promoting it to production:

```bash
export IMAGE_TAG=v1.1.0
export IMAGE_REPOSITORY=ghcr.io/mittwald/hutbot   # optional
helmfile -e dev sync
```

The target namespace defaults to `mw-internal` for both environments and can be overridden with
`NAMESPACE`.

### Persisting the Configuration File

Hutbot stores its channel configuration in a JSON file (`bot.json`) on a mounted volume. You can configure the persistence options in the Helm chart like this:

```yaml
persistence:
  enabled: true
  accessModes:
    - ReadWriteOnce
  size: 1Gi
  storageClass: "<your-storage-class>"
  mountPath: "/data"
```

When persistence is enabled (default: `true`), the chart will automatically set the `HUTBOT_CONFIG_FILE` environment variable so Hutbot reads and writes its config from the mounted volume (at `<mountPath>/bot.json`).
Additionally, Hutbot stores its employee list cache in a JSON file (`employees.json`) on the same mounted volume. The chart will set the `HUTBOT_EMPLOYEE_CACHE_FILE` environment variable so Hutbot reads and writes its employee cache from the mounted volume (at `<mountPath>/employees.json`).

Beside that cache the chart also points `HUTBOT_EMPLOYEE_FALLBACK_FILE` at
`<mountPath>/employees-fallback.json`. That file is optional and Hutbot never writes it: it holds
records for people the employee API does not return — someone whose record is flagged deleted,
or who is missing from it entirely — so that they still get a team instead of `<unknown>`. It has
the same shape as `employees.json`, a JSON array of employee records, and only four fields
matter:

```json
[
  {"ad_name": "rmantler", "fullname": "Rudi Mantler", "group": "Support", "is_deleted": false}
]
```

The employee list wins every collision: a fallback entry is used only for an `ad_name` the API
has no live record for. Set `is_deleted` to `true` to retire an entry without removing it. Place
the file and restart, since the employee list is read when the user cache is cold:

```bash
kubectl -n mw-internal cp employees-fallback.json <hutbot-pod>:/data/employees-fallback.json
kubectl -n mw-internal rollout restart deploy/hutbot
```

Accounts that are nobody — shared or functional Slack users — belong in `EMPLOYEE_LIST_MAPPINGS`
as `user=-` instead, which silences the "cannot be mapped" warning without inventing a record.

> **Note:** The PersistentVolumeClaim created by this chart is annotated with `helm.sh/resource-policy: keep`, so it will not be deleted when you run `helm uninstall`. You can manually remove the PVC (and its underlying volume) by running `kubectl delete pvc <release-name>-pvc`. Keep in mind that if your StorageClass has a `Delete` reclaimPolicy, the underlying storage will still be deleted by the provisioner; to prevent this, use a StorageClass with `ReclaimPolicy: Retain`.

If you override values via environment variables in Helmfile, you can configure persistence like this:

```bash
export PERSISTENCE_ENABLED=true
export PERSISTENCE_SIZE=1Gi
export PERSISTENCE_STORAGE_CLASS=<your-storage-class>
export PERSISTENCE_MOUNT_PATH=/data
# Egress rules for INTERNAL destinations (see above); public destinations and DNS are allowed
# by the chart defaults.
export NETWORKPOLICY_RULES='443:192.168.0.15/32 80:10.0.0.0/24,10.0.1.0/24'
# To define host aliases for the pod (/etc/hosts entries), you can set a comma-separated list of <hostname>=<ip> entries:
export HOST_ALIASES='lb.mittwald.it=192.168.0.15'
# Calendar feed hosts that resolve to an internal address and are meant to be fetched anyway.
# Without an entry the bot refuses the fetch and logs the address it resolved to. Needs the
# matching NETWORKPOLICY_RULES entry (and HOST_ALIASES, if cluster DNS does not serve the zone).
export HUTBOT_CALENDAR_ALLOWED_HOSTS='outlook-bridge.prod.example.systems'
# Calendar tunables; unset means the bot's own defaults, 300 seconds and 90 days.
export HUTBOT_CALENDAR_TTL=300
export HUTBOT_CALENDAR_LOOKBACK_DAYS=90
# Minutes between reads of the calendar bridge's listing; unset means 60, `0` reads it once at
# startup. The listing URL itself carries a token and lives in the Secret, not here.
export HUTBOT_CALENDAR_BRIDGE_REFRESH=60
./deploy-prod.sh v1.1.0
```

## Development

Hutbot is a Python package (`hutbot/`). The former monolithic `bot.py` has been
split into cohesive modules; `bot.py` remains as a backward-compatible launcher:

- `hutbot/state.py` — shared in-memory caches and runtime flags
- `hutbot/models.py`, `hutbot/constants.py` — data types and configuration defaults
- `hutbot/textutil.py`, `hutbot/datetimefmt.py` — logging/text helpers and date/time formatting
- `hutbot/persistence.py` — config and cache load/save
- `hutbot/slackcache.py` — Slack user/channel/usergroup lookups
- `hutbot/templating.py`, `hutbot/opsgenie.py` — reply templates and OpsGenie integration
- `hutbot/calendarfeed.py` — the ICS calendar feed (fetch, parse, current/next event) and the
  instance's built-in calendars (parse, look up, resolve to a URL)
- `hutbot/conditionutil.py` — condition normalization and evaluation
- `hutbot/messaging.py`, `hutbot/actions.py`, `hutbot/buttons.py` — sending, the action engine, and interactive buttons/escalation
- `hutbot/scheduling.py`, `hutbot/routing.py` — scheduled replies / cron triggers and Slack event routing
- `hutbot/commands/` — slash-command parsing and handlers
- `hutbot/webui_backend.py` — the web-UI bridge (the HTTP server lives in `webui.py`)
- `hutbot/__main__.py` — the entry point

Run it locally with `python -m hutbot`. Existing `python bot.py` invocations remain supported.

### Running tests

```bash
pip install -r requirements-dev.txt
pytest
```

Tests live in `tests/` (one file per module) and run automatically in CI before
the Docker image is built. `make check` additionally runs `shellcheck` on the deploy and secret
scripts and `helm lint` on the chart; the chart and script tests in
`tests/test_deployment_validation.py` skip themselves where `helm` is not installed.
