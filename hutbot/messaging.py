"""Low-level Slack message posting + Slack-text cleaning / mention resolution."""

import re
import asyncio

from slack_bolt.async_app import AsyncApp
from slack_sdk.errors import SlackApiError

from employee_list import log_error, log_warning

from . import slackcache
from . import state
from .constants import (
    CALENDAR_TEMPLATE_VARIABLES,
    CONDITION_OPERATORS_ORDERED,
    DATETIME_TEMPLATE_VARIABLES,
    EMAIL_MENTION_PATTERN,
    ID_PATTERN,
    LIST_TEMPLATE_VARIABLES,
    MENTION_PATTERN,
    OPSGENIE_TEMPLATE_VARIABLES,
    SUPPORTED_TEMPLATE_VARIABLES,
    TEMPLATE_DATETIME_VARIABLES,
)
from .models import Channel, User
from .textutil import log_debug


# Slack cuts a message this long into several, wherever the break happens to fall —
# mid code fence included. Anything longer has to be split by us, on our own lines.
SLACK_MESSAGE_CHARACTER_LIMIT = 3800


def pack_message_chunks(parts: list[str], separator: str = "\n\n", limit: int = SLACK_MESSAGE_CHARACTER_LIMIT) -> list[str]:
    """Greedily group `parts` into messages no longer than `limit`.

    A single part longer than the limit is kept whole — splitting it would break
    whatever made it one part (a code block, one config's settings).
    """
    chunks: list[str] = []
    current = ""
    for part in parts:
        candidate = f"{current}{separator}{part}" if current else part
        if current and len(candidate) > limit:
            chunks.append(current)
            current = part
        else:
            current = candidate
    if current:
        chunks.append(current)
    return chunks


def command_footer() -> str:
    """`Response to command:` plus the command being answered, or "" outside a command.

    Appended by `send_message` at the API boundary rather than by each of its ~120 callers.
    """
    command = state.current_command.get()
    if not command:
        return ""
    # The fence stays outside the quote: Slack renders a `>` inside a code block literally,
    # so quoting those lines puts the prefixes in the output.
    return f"\n\n> Response to command:\n```\n{command}\n```"


async def send_message(app: AsyncApp, channel: Channel, user: User, text: str, thread_ts: str = "", footer: bool = True) -> None:
    """Reply to a command. `footer` is off for all but the last part of a chunked reply."""
    if footer:
        text += command_footer()
    log_debug(channel, f"Attempting to send message to #{channel.name}, user @{user.name}: {text.replace(chr(10), '\\n')}")
    retries = 3
    delay = 1
    for attempt in range(retries):
        try:
            if thread_ts:
                await app.client.chat_postMessage(
                    channel=channel.id,
                    thread_ts=thread_ts,
                    text=text,
                    mrkdwn=True
                )
            else:
                await app.client.chat_postEphemeral(
                    channel=channel.id,
                    user=user.id,
                    text=text,
                    mrkdwn=True
                )
            log_debug(channel, f"Successfully sent message to #{channel.name}, user @{user.name}")
            return  # Exit if successful
        except SlackApiError as e:
            if attempt < retries - 1:
                log_warning(f"Failed to send message in channel #{channel.name}, user @{user.name}, retrying in {delay} seconds ({attempt + 1}/{retries})...", e)
                await asyncio.sleep(delay)
                delay *= 2  # Exponential backoff
            else:
                log_error(f"Failed to send message in channel #{channel.name}, user @{user.name} after {retries} attempts:", e)


async def _post_message(app: AsyncApp, channel_id: str, text: str, blocks: list | None, thread_ts: str = "") -> dict | None:
    kwargs = {"channel": channel_id, "text": text, "mrkdwn": True}
    if blocks:
        kwargs["blocks"] = blocks
    if thread_ts:
        kwargs["thread_ts"] = thread_ts
    retries = 3
    delay = 1
    for attempt in range(retries):
        try:
            response = await app.client.chat_postMessage(**kwargs)
            return {"channel": channel_id, "ts": response.get("ts")}
        except SlackApiError as e:
            if attempt < retries - 1:
                log_warning(f"Failed to post message to {channel_id}, retrying in {delay} seconds ({attempt + 1}/{retries})...", e)
                await asyncio.sleep(delay)
                delay *= 2
            else:
                log_error(f"Failed to post message to {channel_id} after {retries} attempts:", e)
                return None


async def replace_ids(app: AsyncApp, channel: Channel | None, text: str) -> str:
    for match in ID_PATTERN.finditer(text):
        full_match = match.group(0)
        log_debug(channel, f"Found ID match: {full_match}...")
        id = match.group(1)
        handled = False
        if id and id[0] == '@':
            user_id = id[1:]
            log_debug(channel, f"Looking up user with ID {user_id}...")
            user = await slackcache.get_user_by_id(app, user_id)
            if user.id:
                log_debug(channel, f"Found user {user}")
                text = text.replace(full_match, user.real_name)
                handled = True
        elif id and id[0] == '#':
            ch_id = id[1:]
            log_debug(channel, f"Looking up channel with ID {ch_id}...")
            ch = await slackcache.get_channel_by_id(app, ch_id)
            if ch.id:
                log_debug(channel, f"Found channel {ch}")
                text = text.replace(full_match, f"#{ch.name}")
                handled = True
        elif id and id.startswith('!subteam^'):
            ug_id = id[9:]
            log_debug(channel, f"Looking up usergroup with ID {ug_id}...")
            ug = await slackcache.get_usergroup_by_id(app, ug_id)
            if ug.id:
                log_debug(channel, f"Found usergroup {ug}")
                text = text.replace(full_match, f"@{ug.handle}")
                handled = True
        if not handled:
            alias = match.group(3)
            if alias:
                log_debug(channel, f"Fallback, replacing {full_match} with alias {alias}.")
                text = text.replace(full_match, alias)
            else:
                log_debug(channel, f"Fallback, replacing {full_match} with {id}.")
                text = text.replace(full_match, id)
    return text


async def clean_slack_text(app: AsyncApp, channel: Channel, text: str):
    # replace all kinds of <@ID> mentions
    text = await replace_ids(app, channel, text)

    # unescape any escaped formatting characters (like \*, \_, etc.)
    text = re.sub(r'\\([*_~`])', r'\1', text)

    # process all <...> elements to extract display text or URL
    def replace_link(match):
        parts = match.group(1).split('|', 1)
        if len(parts) == 1 and parts[0].startswith('http'):
            return "[URL]"
        return parts[1] if len(parts) > 1 and len(parts[1]) > 0 else parts[0]

    text = re.sub(r'<([^>]+)>', replace_link, text)

    # remove all remaining formatting characters and new lines
    text = re.sub(r'[*_~`]', '', text).replace('\n', ' ')

    # reduce duplicate spaces and trim
    text = re.sub(r'\s{2,}', ' ', text).strip()

    return text


async def process_mentions(app: AsyncApp, message: str) -> tuple[bool, str, str]:
    """Turn `@username` and `@someone@example.com` into Slack mentions.

    Addresses are resolved first: `MENTION_PATTERN` stops at the second `@`, so it would
    otherwise take the local part of an address for a username. An unknown mention is
    reported here, at `set message` time, rather than rendering wrongly later.
    """
    for email_match in EMAIL_MENTION_PATTERN.findall(message):
        user = await slackcache.get_user_by_email(app, email_match)
        if user.id:
            message = message.replace(f"@{email_match}", f"<@{user.id}>")
        else:
            log_error(f"Invalid *reply message*: no Slack user for `{email_match}`")
            return False, f"no Slack user for {email_match}", ""

    # Regular expression to find @username patterns
    matches = MENTION_PATTERN.findall(message)
    if matches:
        for user_match in matches:
            user = await slackcache.get_user_by_name(app, user_match)
            if user.id:
                message = message.replace(f"@{user_match}", f"<@{user.id}>")
            else:
                log_error(f"Invalid *reply message*: username `{user_match}` not found")
                return False, f"{user_match} not found", ""
    return True, "", message


async def send_news_message(app: AsyncApp, channel: Channel, user: User, thread_ts: str = "") -> None:
    command = state.slash_command
    name = state.bot_name
    version = state.version
    mention = f"@{state.bot_user_name}"
    update_text = (
        f"Hi! :wave: I am *{name}* `{version}` :palm_up_hand::tophat: Here's what's :new::\n\n"
        "> :robot_face: *Triggers, actions & buttons*\n>\n"
        f"> Rules can now run on a `cron` schedule, DM a user or group, post to a channel, and carry interactive buttons (with an auto-press default + timeout escalation). See `{command} help`.\n>\n"
        "> :calendar: *OpsGenie date/time template variables and defaults*\n>\n"
        f"> OpsGenie templates can now include current and next on-call start/end dates, times, and datetimes. Use `{command} [config] set datetime-format \"<date>\" \"<time>\" [<timezone> <locale>]` to set the defaults.\n>\n"
        "> :date: *Calendar feeds*\n>\n"
        f"> Point a config at an ICS calendar URL — or one of the instance's built-in calendars — with `{command} [config] set calendar <name|url>`, then read it from any message: `{{{{calendar_summary}}}}` is the event running now, `{{{{calendar_summary(offset=next)}}}}` the one after it, and `{{{{calendar_summary(at=\"+1d\")}}}}` what is on this time tomorrow. `{command} [config] show calendar` prints the event before, the one now and the next.\n>\n"
        "> :traffic_light: *Conditions on any variable*\n>\n"
        f"> A rule can now be gated on any `{{{{variable}}}}`: `{command} [config] add condition <var> <operator> [value]`, with `empty`, `equals`, `contains`, `starts-with`, `ends-with`, `regex` and their `not-` forms. Chain several and pick `{command} [config] set condition-mode <all|any>`. Conditions apply to every trigger, and `{command} [config] test` shows which ones pass.\n>\n"
        "> :pencil: *Customize reply messages with `{{placeholders}}`*\n>\n"
        "> That means " + name + " can include details like the `{{user}}`, `{{team}}`, `{{channel}}` or `{{wait_minutes}}`, or even mention the person who is currently on-call `{{opsgenie_current_user}}` in the reply message :exploding_head:.\n>\n"
        "> :sparkles: Just configure an Opsgenie schedule and you are good to go.\n>\n"
        "> :list-item: *List available Opsgenie schedules*\n>\n"
        "> :telephone_receiver: *Print the current on-call user*\n"
        f"> Use `{command} [config] on-call [schedule name]` to get the current OpsGenie on-call user as a Slack mention.\n>\n"
        "> :test_tube: *Preview your configured reply*\n"
        f"> Use `{command} [config] test` or mention me with `{mention} [config] test <message>` to test reply templates and variables.\n>\n"
        f"> :bug: *{name} now ONLY cancels replying, when the _expected_ team(s) have already replied* :lightbulb:\n>\n"
        "> Issue was:\n>\n"
        "> 1. Team *A* sends a message intended for Team *B*\n"
        "> 2. Someone else from Team *A* adds additional information\n"
        f"> 3. {name} cancels the reply and does NOT remind Team *B* anymore :fail:\n"
    )
    await send_message(app, channel, user, update_text, thread_ts)


async def send_help_message(app: AsyncApp, channel: Channel, user: User, thread_ts: str = "") -> None:
    command = state.slash_command
    name = state.bot_name
    version = state.version
    mention = f"@{state.bot_user_name}"
    # Grouped in the order a rule runs — configs, then trigger, condition, what it
    # matches, timing, the message it sends, buttons, alerting, formatting — with
    # lookups and meta commands last. Same grouping as `show config` prints.
    command_groups = [
        ("Configurations", [
            (f"{command} show config", "Show all configurations."),
            (f"{command} [config] enable", "Enable this config."),
            (f"{command} [config] disable", "Disable this config."),
            (f"{command} delete config <name>", "Delete a configuration."),
        ]),
        ("Trigger", [
            (f"{command} [config] set trigger <message|manual>", "Set how the rule starts."),
            (f"{command} [config] set trigger cron \"<expr>\"", "Fire on a cron schedule, e.g. 0 9 * * 1-5."),
        ]),
        ("Conditions", [
            (f"{command} [config] add condition <var> <operator> [value] [0|1]", "Gate this rule on a variable; 1 means case sensitive."),
            (f"{command} [config] set condition-mode <all|any>", "All conditions must apply, or any one of them."),
            (f"{command} [config] clear conditions", "Remove all conditions; the rule stops being gated."),
        ]),
        ("What to react to", [
            (f"{command} [config] set pattern \"<regex>\" [0|1]", "Set message pattern; 1 means case sensitive."),
            (f"{command} [config] clear pattern", "React to every message again."),
            (f"{command} [config] add included-team <team>", "Add an allowed team."),
            (f"{command} [config] clear included-teams", "Clear allowed teams."),
            (f"{command} [config] add excluded-team <team>", "Add an ignored team."),
            (f"{command} [config] clear excluded-teams", "Clear ignored teams."),
            (f"{command} [config] enable bots", "Respond to bot messages."),
            (f"{command} [config] disable bots", "Ignore bot messages."),
        ]),
        ("When to react", [
            (f"{command} [config] set wait-time <minutes>", "Set reminder delay."),
            (f"{command} [config] enable only-work-days", "Respond only on work days."),
            (f"{command} [config] disable only-work-days", "Respond on all days."),
            (f"{command} [config] set work-hours <start> <end>", "Set active hours, e.g. 9:00 17:00."),
            (f"{command} [config] clear work-hours", "React at any hour."),
        ]),
        ("Message and action", [
            (f"{command} [config] set message \"<reply message>\"", "Set reminder message."),
            (f"{command} [config] set action reply", "Reply in this channel (the default)."),
            (f"{command} [config] set action post-channel <#channel>", "Post to another channel."),
            (f"{command} [config] set action dm-user <@user>", "DM a single user."),
            (f"{command} [config] set action group-dm <@usergroup>", "Open one group DM with a user group."),
        ]),
        ("Buttons", [
            (f"{command} [config] add button \"<label>\" config <config>", "Button runs another config (e.g. an alert config)."),
            (f"{command} [config] add button \"<label>\" ack [text]", "Button marks it handled, posting [text] if given."),
            (f"{command} [config] add button \"<label>\" delay <minutes>", "Button postpones the escalation; buttons stay."),
            (f"{command} [config] clear buttons", "Remove all buttons."),
            (f"{command} [config] set escalation <minutes> button \"<label>\"", "Auto-press that button if nobody does in time."),
            (f"{command} [config] set escalation <minutes> config <config>", "Run that config if nobody presses in time."),
            (f"{command} [config] clear escalation", "Never escalate; buttons stay open."),
        ]),
        ("OpsGenie", [
            (f"{command} [config] enable opsgenie", "Enable OpsGenie alerts."),
            (f"{command} [config] disable opsgenie", "Disable OpsGenie alerts."),
            (f"{command} [config] set opsgenie-schedule <name>", "Set the OpsGenie schedule name."),
            (f"{command} [config] set opsgenie-priority <P1-P5>", "Set the OpsGenie alert priority."),
            (f"{command} [config] set opsgenie-message <text>", "Template for the alert text (default: the message)."),
            (f"{command} [config] clear opsgenie-message", "Back to alerting with the message itself."),
        ]),
        ("Calendar", [
            (f"{command} [config] set calendar <name|url>", "Read a built-in calendar, or an ICS feed URL."),
            (f"{command} [config] clear calendar", "Stop reading a calendar feed."),
            (f"{command} [config] show calendar", "Show the event running now and the next one."),
        ]),
        ("Date and time", [
            (f"{command} [config] set datetime-format \"<date>\" \"<time>\" [<tz> <locale>]", "Date/time output; <tz> also drives cron and work hours."),
        ]),
        ("Try it out and look things up", [
            (f"{command} [config] run", "Run this configuration's action now."),
            (f"{command} [config] test", "Preview configured reply."),
            (f"{mention} [config] test <message>", "Preview reply with <message> as {{message}}."),
            (f"{command} [config] on-call [opsgenie-schedule]", "Show current on-call user."),
            (f"{command} list teams", "List available teams."),
            (f"{command} list opsgenie-schedules", "List OpsGenie schedules."),
            (f"{command} list calendars", "List the built-in calendars available here."),
            (f"{command} team of <@user>", "Show a user's team."),
        ]),
        ("Help", [
            (f"{command} news", "Show what's new."),
            (f"{command} help", "Show this help."),
            (f"{command} help variables", "List all {{variables}} and condition operators."),
        ]),
    ]
    command_width = max(len(command) for _, rows in command_groups for command, _ in rows)
    group_blocks = [
        f"# {title}\n" + "\n".join(f"{command:<{command_width}}  {description}" for command, description in rows)
        for title, rows in command_groups
    ]
    intro = (
        f"Hi! :wave: I am *{name}* `{version}` :palm_up_hand::tophat: Here's what I can do:\n\n"
        "*Show All Configurations:*\n"
        f"> Either use the command `{command}` or just `{mention}` me.\n"
        f"```{command} show config\n"
        f"{mention} show config```\n"
        f"Displays all configurations for `#{channel.name}`."
    )
    # The variable and operator lists ran longer than the command table itself, so they
    # live behind `help variables` now; what is left is the syntax every command shares.
    outro_notes = [
        "`[config]` is optional; omitted commands use `default`. The leading `set`/`add` is optional too. "
        "Any value can be quoted with `\"`, `'` or a backtick.",
        f"`{command} help variables` lists every `{{{{variable}}}}` you can put in a message or a "
        "condition, and every condition operator.",
    ]
    # The command table alone is well past Slack's per-message limit, and Slack
    # splits an oversized message wherever it happens to land — which cuts the code
    # fence in half. Send it in chunks that each close their own fence.
    command_messages = [
        f"*Commands{'' if index == 0 else ' (continued)'}:*\n```\n{chunk}\n```"
        for index, chunk in enumerate(pack_message_chunks(group_blocks, limit=SLACK_MESSAGE_CHARACTER_LIMIT - 200))
    ]
    outro_messages = pack_message_chunks(outro_notes, limit=SLACK_MESSAGE_CHARACTER_LIMIT - 200)
    messages = [intro, *command_messages, *outro_messages]
    for index, message in enumerate(messages):
        await send_message(app, channel, user, message, thread_ts, footer=index == len(messages) - 1)


async def send_variables_help_message(app: AsyncApp, channel: Channel, user: User, thread_ts: str = "") -> None:
    """The `{{variable}}` and condition-operator reference, split out of the command help.

    Grouped from the same sets the renderer resolves, so a new variable appears here
    without anyone having to remember this file.
    """
    command = state.slash_command
    name = state.bot_name
    version = state.version
    general_variables = SUPPORTED_TEMPLATE_VARIABLES - DATETIME_TEMPLATE_VARIABLES - OPSGENIE_TEMPLATE_VARIABLES - CALENDAR_TEMPLATE_VARIABLES
    variable_groups = [
        ("Message, sender and config", general_variables),
        ("Date and time", DATETIME_TEMPLATE_VARIABLES),
        ("OpsGenie", OPSGENIE_TEMPLATE_VARIABLES),
        ("Calendar", CALENDAR_TEMPLATE_VARIABLES),
    ]
    intro = (
        f"Hi! :wave: I am *{name}* `{version}` :palm_up_hand::tophat: Here are all the variables I know:\n\n"
        f"Write one as `{{{{variable}}}}` in a reply `message`, an `opsgenie-message`, a `dm-user`/`group-dm` "
        f"target or a `condition`. `{command} [config] test` renders every one of them for this channel, and "
        "a variable nothing has resolved renders a `<placeholder>` such as `<no-event>`."
    )
    # One note per group, each its own part so a group ends up whole in whichever
    # message it lands in — the full list is several times Slack's per-message limit.
    group_notes = [
        f"*{title}*\n" + ", ".join(f"`{{{{{variable}}}}}`" for variable in sorted(variables))
        for title, variables in variable_groups
    ]
    detail_notes = [
        "Every date/time variable takes `fmt`/`format`, `tz`/`timezone` and `lc`/`locale` arguments, e.g. "
        "`{{opsgenie_next_start_datetime(fmt=\"%d.%m.%Y %H:%M\", tz=\"Europe/Berlin\", lc=\"de_DE\")}}`. "
        f"Without them the config's `{command} [config] set datetime-format` values are used.",
        "Every calendar variable describes *one* event, and two arguments choose which. "
        "`offset` counts events — `next`, `prev`, or a number like `+2`/`-1` — and `at` names "
        "the moment to count from: `{{calendar_summary}}` is what is running now, "
        "`{{calendar_summary(offset=next)}}` the one after it, and "
        "`{{calendar_summary(at=\"+1d\", offset=next)}}` the event after whatever runs this time "
        "tomorrow. In a gap between events the plain form renders `<no-event>`, and `offset=-1`/"
        "`offset=next` are still the events either side.",
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
        "Conditions are checked when the rule fires — for a `message` rule that is after the "
        "reminder delay, judged against the conditions as they were when the message arrived. "
        "A condition that reads only the message or its sender is checked straight away, so no "
        "reminder is queued when it already cannot pass.",
    ]
    messages = pack_message_chunks([intro, *group_notes, *detail_notes], limit=SLACK_MESSAGE_CHARACTER_LIMIT - 200)
    for index, message in enumerate(messages):
        await send_message(app, channel, user, message, thread_ts, footer=index == len(messages) - 1)
