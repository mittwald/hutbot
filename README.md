# hutbot Slack Bot

The hutbot is a simple Slack bot that monitors messages in a channel and automatically replies in a thread if no one reacts or responds to the message within a configurable time period (by default 30 minutes). The bot reminds channel members that a message has gone unanswered. Scheduled reminders are cancelled when someone replies in the thread or reacts in a way that does not match the config criteria that caused that reminder to be scheduled, or when the original message is deleted. Users can adjust both the waiting time and the reminder message directly within the channel, including `{{variable}}` placeholders in the reminder text.

Run `/hutbot` (or just `@hutbot` on its own) with nothing after it to get the full command
list; `/hutbot help` does the same. Any argument may be quoted with `"`, `'` or backticks —
handy since Slack renders a backticked value as code as you type it.

A reply message can `@mention` someone by **email address** — `@d.grieser@example.com` — which
is resolved to their Slack user when the message is set, alongside the existing `@username`
form. An address that maps to nobody is reported there and then rather than rendering wrongly
later.

Reply messages support built-in placeholders such as `{{user}}`, `{{channel}}`, and `{{message_link}}`. `{{date}}`, `{{time}}`, and `{{datetime}}` render the triggering message's time — or the time the rule ran, for `cron`/`manual` triggers and for `test`/`run` — using the config's date/time format, timezone, and locale, and take the same `fmt`/`tz`/`lc` arguments as the Opsgenie date/time variables below. `{{timestamp}}` is the raw Slack timestamp of the same instant. If a channel config also has an Opsgenie schedule configured via `/hutbot [config] set opsgenie-schedule <name>`, Hutbot can resolve the current on-call person and expose:

- `{{opsgenie_schedule_name}}` for the configured schedule
- `{{opsgenie_current_user}}` for a Slack `@mention`
- `{{opsgenie_current_email}}` for the Opsgenie recipient email
- `{{opsgenie_current_name}}` for the resolved Slack display name, or the Opsgenie email if no Slack match is found
- `{{opsgenie_current_start_date}}`, `{{opsgenie_current_start_time}}`, and `{{opsgenie_current_start_datetime}}`
- `{{opsgenie_current_end_date}}`, `{{opsgenie_current_end_time}}`, and `{{opsgenie_current_end_datetime}}`
- `{{opsgenie_next_user}}`, `{{opsgenie_next_email}}`, and `{{opsgenie_next_name}}`
- `{{opsgenie_next_start_date}}`, `{{opsgenie_next_start_time}}`, and `{{opsgenie_next_start_datetime}}`
- `{{opsgenie_next_end_date}}`, `{{opsgenie_next_end_time}}`, and `{{opsgenie_next_end_datetime}}`

If a channel config has a calendar feed configured via `/hutbot [config] set calendar <url>`,
Hutbot reads the ICS feed and exposes the event running **now** and the **next** one:

- `{{calendar_name}}` for the feed's own name (`X-WR-CALNAME`), or its redacted URL
- `{{calendar_current_summary}}`, `{{calendar_current_location}}`, `{{calendar_current_description}}`
- `{{calendar_current_organizer}}` (display name) and `{{calendar_current_organizer_email}}`
- `{{calendar_current_attendees}}` (display names) and `{{calendar_current_attendee_emails}}` —
  **lists**, rendered comma-separated — plus `{{calendar_current_attendee_count}}`
- `{{calendar_current_other_attendees}}` / `{{calendar_current_other_attendee_emails}}` — the
  same lists **without the organizer**. A shared mailbox invites itself to the events it
  organizes, so on a rota entry organized by *Notfallhotline* these leave just the person
  actually on call

- `{{calendar_current_organizer_user}}`, `{{calendar_current_attendee_users}}` and
  `{{calendar_current_other_attendee_users}}` — the same people **mapped to Slack users**, as
  `<@U…>` mentions. Addresses are matched against the Slack directory with the bot's usual
  user mapping; anyone without a Slack account is simply left out, so a mapped list can be
  shorter than the address list it came from

A list variable renders comma-separated, and `nth` picks one entry out of it, counting from 1:
`{{calendar_current_attendees(nth=2)}}` is the second (`n=2` is the short spelling). Asking for
an entry the list does not have renders **empty** rather than failing, so a message written for
two attendees still reads when there is only one:

```bash
/hutbot oncall set message "On call: {{calendar_current_other_attendees(nth=1)}} <{{calendar_current_other_attendee_emails(nth=1)}}> until {{calendar_current_end_time}}"
```
- `{{calendar_current_uid}}`, `{{calendar_current_status}}`
- `{{calendar_current_start_date}}`, `{{calendar_current_start_time}}`, and `{{calendar_current_start_datetime}}`
- `{{calendar_current_end_date}}`, `{{calendar_current_end_time}}`, and `{{calendar_current_end_datetime}}`
- the same set again as `{{calendar_next_…}}` for the next event that starts after now

Calendar date/time variables take the same `fmt`/`tz`/`lc` arguments as the Opsgenie ones. For an
**all-day** event the end is the *inclusive* last day, not the exclusive `DTEND` the ICS file
carries — a one-day event on the 19th reports the 19th, not the 20th. Cancelled events are skipped;
tentative ones are kept, and `{{calendar_current_status}}` says which is which. Recurring events
(`RRULE`, with `EXDATE` exclusions) are expanded, including their `VTIMEZONE`.

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

A config can read **one** ICS calendar feed, the same way it has one Opsgenie schedule:

```bash
/hutbot [config] set calendar <url>     # a published .ics link
/hutbot [config] clear calendar
/hutbot [config] show calendar          # the event running now, and the next one
```

The event running now and the next one become `{{calendar_*}}` template variables (see above),
so a message can name them — and a condition can gate a rule on them.

**The URL is a secret.** A published-calendar link needs no login, so possession of it *is* read
access to the calendar. Hutbot therefore only ever echoes a redacted form
(`outlook.office365.com/…/calendar.ics`) in `show config` and in the setter's confirmation.
The feed is cached for 5 minutes (`HUTBOT_CALENDAR_TTL`, in seconds).

A remote feed must be `https://`, and URLs pointing at the private ranges or the cloud metadata
address are refused — the bot fetches them from inside the cluster. **Loopback is exempt**, over
plain `http://` too, so a local file server works while developing:
`/hutbot set calendar http://127.0.0.1:8073/calendar.ics`.

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
    or the calendar (`{{calendar_current_summary}}`).
  - **List variables** — the calendar's `attendees` / `attendee_emails` and their
    `other_*` counterparts — match when *any* entry matches, and their `not_` forms when
    *none* does. So `equals` is a membership test and `not_equals` means "not among
    them", rather than the useless "some entry differs":
    ```bash
    # is this person on the event that is running right now?
    /hutbot oncall add condition calendar_current_attendee_emails equals nico@example.com
    # nobody from outside the company is on it
    /hutbot oncall add condition calendar_current_attendee_emails not_contains @external.com
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
  - A condition that reads only settled values — the message, its sender, their team — is
    checked **immediately**, and no reminder is queued at all when it already cannot pass.
    Conditions on `{{calendar_*}}`, `{{opsgenie_*}}` or `{{message_link}}` can only be
    answered later, so those always wait.
  - `/hutbot [config] test` prints each condition with ✓/✗ and whether the rule would run.

  ```bash
  # nudge only while a "Composer" meeting is actually running
  /hutbot standup set calendar https://outlook.office365.com/owa/calendar/…/calendar.ics
  /hutbot standup add condition calendar_current_summary contains composer
  /hutbot standup add condition message not_empty
  /hutbot standup set condition-mode all
  ```

- **Actions** (`/hutbot [config] set action <action> [<target>]`) decide what the rule does, using
  `reply_message` (with the usual `{{variables}}`) as the body. The recipient is part of the same
  command, so a config can never be left with an action that has nowhere to send.
  - `set action reply` — post in the rule's channel. Takes no target.
  - `set action dm-user <@user>` — DM a single user. The target may be a mention, an email
    address, or a `{{variable}}`, so `set action dm-user {{calendar_current_other_attendee_users(nth=1)}}`
    DMs whoever the calendar says is on call right now.
  - `set action group-dm <@usergroup>` — open one group DM (mpim) with all members of a Slack user
    group and post once (Slack caps a group DM at 8 members). The target may instead name the
    people directly — mentions or addresses, including from a variable:
    `set action group-dm {{calendar_current_attendee_users}}`. A bare handle like `@sre` is
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
    when pressed.
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
    templates and any OpsGenie alert reference the original message.
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
- `GET /api/me`, `GET /api/meta`, `GET /api/channels` — require a resolvable user.
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

Create a `.env` file in the project root (this file is ignored by git) with the following content:

```bash
export SLACK_BOT_TOKEN='<your bot token>'
export SLACK_APP_TOKEN='<your app-level token>'
export OPSGENIE_TOKEN='<your Opsgenie API token>'
export OPSGENIE_HEARTBEAT_NAME='<your Opsgenie heartbeat name>'
export EMPLOYEE_LIST_USERNAME='<your employee list username>'
export EMPLOYEE_LIST_PASSWORD='<your employee list password>'
export EMPLOYEE_LIST_MAPPINGS='<optional comma-separated mappings, e.g.: user1=alias1,user2=alias2>'
# Slash command this instance listens on; must match the Slack app. Default: /hutbot
export HUTBOT_SLASH_COMMAND='/hutbot'
# Name the bot uses for itself in help/news messages. Default: Hutbot
export HUTBOT_BOT_NAME='Hutbot'
# To define netpol egress rules, you can set a space-separated list of <port>:<cidr[,cidr...]> entries:
# NOTE: this is an allow-list. A calendar feed (`set calendar <url>`) is fetched from inside the
# cluster, so its host needs an entry here on 443 or the fetch is silently dropped. Only TCP
# rules are rendered, so DNS resolution has to be reachable by other means.
export NETWORKPOLICY_RULES='443:192.168.0.15/32 80:10.0.0.0/24,10.0.1.0/24'
# To define host aliases for the pod (/etc/hosts entries), you can set a comma-separated list of <hostname>=<ip> entries:
export HOST_ALIASES='lb.mittwald.it=192.168.0.15'
```

Load the environment variables before deploying with Helmfile:

```bash
source .env
```

To query the employee list locally from your terminal, you can use the standalone helper script:

```bash
python query_employees.py john
python query_employees.py --team Support
python query_employees.py john.slack --cache-only
python query_employees.py john --json
```

Before running, update `helmfile.yaml.gotmpl` with your Docker image repository and other configuration values.

Deploy the bot to your Kubernetes cluster using Helmfile:

```bash
helmfile sync
```

> **Note:** Helmfile uses Go templating to inject these variables and will error if any required environment variables are missing.
> Ensure you run `source .env` in the same shell as you execute `helmfile sync`.

### Deploying a Dev Instance

The Helmfile defines two environments so a second, independent instance can run alongside production
in the same namespace:

| Environment | Release name  | Purpose                                          |
| ----------- | ------------- | ------------------------------------------------ |
| `default`   | `hutbot`      | Production instance                              |
| `dev`       | `hutbot-dev`  | Dev instance (separate Slack app, own PVC/Secret) |

All chart resources are named after the Helm release, so the dev release gets its own Deployment,
Secret (`hutbot-dev-secret`), PersistentVolumeClaim (`hutbot-dev-pvc`) and NetworkPolicy. The two
instances share nothing.

Register a second Slack app for the dev bot — [Hutbot_DEV Slack App](https://api.slack.com/apps/A0BN19HUTAP) —
and put its credentials in a `.env-dev` file (also ignored by git). It uses the exact same variable
names as `.env`:

```bash
export SLACK_BOT_TOKEN='<dev bot token>'
export SLACK_APP_TOKEN='<dev app-level token>'
# ... same variables as .env
```

Then deploy with the `dev` environment selected:

```bash
source .env-dev
helmfile -e dev sync
```

Production is unaffected and keeps deploying as before (`source .env && helmfile sync`), which is
equivalent to `helmfile -e default sync`.

> **Note:** Point the dev instance at its own Opsgenie heartbeat (or leave `OPSGENIE_HEARTBEAT_NAME`
> empty in `.env-dev`), otherwise the dev pod will ping the production heartbeat.

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

> **Note:** The PersistentVolumeClaim created by this chart is annotated with `helm.sh/resource-policy: keep`, so it will not be deleted when you run `helm uninstall`. You can manually remove the PVC (and its underlying volume) by running `kubectl delete pvc <release-name>-pvc`. Keep in mind that if your StorageClass has a `Delete` reclaimPolicy, the underlying storage will still be deleted by the provisioner; to prevent this, use a StorageClass with `ReclaimPolicy: Retain`.

If you override values via environment variables in Helmfile, you can configure persistence like this:

```bash
export PERSISTENCE_ENABLED=true
export PERSISTENCE_SIZE=1Gi
export PERSISTENCE_STORAGE_CLASS=<your-storage-class>
export PERSISTENCE_MOUNT_PATH=/data
# To define netpol egress rules, you can set a space-separated list of <port>:<cidr[,cidr...]> entries:
# NOTE: this is an allow-list. A calendar feed (`set calendar <url>`) is fetched from inside the
# cluster, so its host needs an entry here on 443 or the fetch is silently dropped. Only TCP
# rules are rendered, so DNS resolution has to be reachable by other means.
export NETWORKPOLICY_RULES='443:192.168.0.15/32 80:10.0.0.0/24,10.0.1.0/24'
# To define host aliases for the pod (/etc/hosts entries), you can set a comma-separated list of <hostname>=<ip> entries:
export HOST_ALIASES='lb.mittwald.it=192.168.0.15'
helmfile sync
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
- `hutbot/calendarfeed.py` — the ICS calendar feed (fetch, parse, current/next event)
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
the Docker image is built.
