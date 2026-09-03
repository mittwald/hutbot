"""Low-level Slack message posting + Slack-text cleaning / mention resolution."""

import re

from slack_bolt.async_app import AsyncApp

from logutil import log_error
import retryutil

from . import slackcache
from . import state
from . import templatedocs
from .constants import (
    EMAIL_MENTION_PATTERN,
    ID_PATTERN,
    LIST_TEMPLATE_VARIABLES,
    MENTION_PATTERN,
    TEMPLATE_DATETIME_VARIABLES,
)
from .models import Channel, User
from .textutil import log_debug


# Slack cuts a message this long into several, wherever the break happens to fall —
# mid code fence included. Anything longer has to be split by us, on our own lines.
# One `section` block holds 3000 characters, and a reply is rendered as section blocks (so the
# footer can be a `rich_text` block beside them) — so a message is chunked below that, and a
# whole message is one section. Splitting a message across two sections would have to cut
# somewhere, and the cut lands inside a code fence often enough to be worth avoiding.
SLACK_SECTION_TEXT_LIMIT = 3000
SLACK_MESSAGE_CHARACTER_LIMIT = 2900


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


def section_blocks(text: str) -> list[dict]:
    """Message text as `section` blocks, split on line boundaries under Slack's 3000-char cap.

    Lines are kept whole because a cut inside a code fence breaks the block for the rest of
    the message; a single line longer than the cap has no boundary to use and is sliced.
    """
    blocks: list[dict] = []
    current = ""
    for line in (text or " ").split("\n"):
        while len(line) > SLACK_SECTION_TEXT_LIMIT:
            if current:
                blocks.append(current)
                current = ""
            blocks.append(line[:SLACK_SECTION_TEXT_LIMIT])
            line = line[SLACK_SECTION_TEXT_LIMIT:]
        candidate = f"{current}\n{line}" if current else line
        if len(candidate) > SLACK_SECTION_TEXT_LIMIT:
            blocks.append(current)
            current = line
        else:
            current = candidate
    if current or not blocks:
        blocks.append(current)
    return [{"type": "section", "text": {"type": "mrkdwn", "text": block or " "}} for block in blocks]


def quote_lines(text: str) -> str:
    """`text` as a Slack quote, with any fenced code block left out of the quote.

    Slack does not strip a `>` from inside a code block: quoting those lines prints the
    prefixes as content, and a quoted closing fence leaves a stray `>` line behind in the
    block. mrkdwn cannot put a code block inside a quote at all (only a `rich_text` block can,
    via `border` — see `command_footer_blocks`), so a fenced block breaks out of the quote
    instead of being quoted wrongly. Everything around it stays quoted.
    """
    entries: list[tuple[bool, str]] = []
    fenced = False
    for line in text.split("\n"):
        fences = line.count("```")
        if fences:
            # The fence line itself is never quoted, on either side of the block.
            entries.append((False, line))
            fenced ^= bool(fences % 2)
            continue
        entries.append((not fenced, line))

    kept: list[tuple[bool, str]] = []
    for index, entry in enumerate(entries):
        quoted, line = entry
        if quoted and not line.strip():
            # A blank quoted line is a gap *inside* a quote. Opening or closing one with it
            # instead — which is what a separator next to a code block does, since the block
            # ends the quote — renders as a stray `>` on a line of its own.
            previous = kept[-1] if kept else None
            following = next((e for e in entries[index + 1:] if e[1].strip()), None)
            if not (previous and previous[0]) or not (following and following[0]):
                continue
        kept.append(entry)
    return "\n".join(f"> {line}".rstrip() if quoted else line for quoted, line in kept)


def command_footer() -> str:
    """The footer as plain text, for the notification fallback and for logs."""
    command = state.current_command.get()
    return f"\n\nResponse to command:\n```\n{command}\n```" if command else ""


def command_footer_blocks() -> list[dict]:
    """`Response to command:` plus the command being answered, or none outside a command.

    Added by `send_message` at the API boundary rather than by each of its ~120 callers.

    A `rich_text` block, because mrkdwn cannot put a code block inside a quote: quoting the
    fence lines leaves their `>` in the rendered block, and quoting only the opening fence
    leaves the block outside the bar. `rich_text_quote` is no help either — it takes inline
    elements only — so the bar comes from `border: 1` on the code block itself, which is what
    Slack's own composer produces for a quote with a code block in it.
    """
    command = state.current_command.get()
    if not command:
        return []
    return [{
        "type": "rich_text",
        "elements": [
            {"type": "rich_text_quote",
             "elements": [{"type": "text", "text": "Response to command:"}]},
            {"type": "rich_text_preformatted", "border": 1,
             "elements": [{"type": "text", "text": command}]},
        ],
    }]


async def send_message(app: AsyncApp, channel: Channel, user: User, text: str, thread_ts: str = "", footer: bool = True, blocks: list[dict] | None = None) -> None:
    """Reply to a command. `footer` is off for all but the last part of a chunked reply.

    Callers may supply blocks when content needs a block type that mrkdwn sections cannot
    represent safely, such as one preformatted export longer than a section's 3000 characters.
    """
    # Blocks render the message; `text` stays the notification fallback, and carries the footer
    # in its plain-text spelling so a push notification is not missing the command it answers.
    blocks = list(blocks) if blocks is not None else section_blocks(text)
    blocks += command_footer_blocks() if footer else []
    if footer:
        text += command_footer()
    log_debug(channel, f"Attempting to send message to #{channel.name}, user @{user.name}: {text.replace(chr(10), '\\n')}")

    async def attempt() -> None:
        if thread_ts:
            await app.client.chat_postMessage(
                channel=channel.id,
                thread_ts=thread_ts,
                text=text,
                blocks=blocks,
                mrkdwn=True
            )
        else:
            await app.client.chat_postEphemeral(
                channel=channel.id,
                user=user.id,
                text=text,
                blocks=blocks,
                mrkdwn=True
            )

    try:
        await retryutil.retry_async(attempt, what=f"Sending a message in #{channel.name} to @{user.name}")
    except Exception as e:
        # A command reply nobody can resend: the command is gone by the time this is read, so
        # the failure is logged rather than raised at a handler that could only log it again.
        log_error(f"Failed to send message in channel #{channel.name}, user @{user.name}:", e)
        return
    log_debug(channel, f"Successfully sent message to #{channel.name}, user @{user.name}")


async def _post_message(app: AsyncApp, channel_id: str, text: str, blocks: list | None, thread_ts: str = "") -> dict | None:
    """Post a message, or return None once the retries are used up.

    Callers treat None as "nothing was posted": `run_action` skips the buttons that would have
    been attached to it, and the scheduled reply that asked for it is kept for another turn
    rather than dropped.
    """
    kwargs = {"channel": channel_id, "text": text, "mrkdwn": True}
    if blocks:
        kwargs["blocks"] = blocks
    if thread_ts:
        kwargs["thread_ts"] = thread_ts

    async def attempt() -> dict:
        response = await app.client.chat_postMessage(**kwargs)
        return {"channel": channel_id, "ts": response.get("ts")}

    try:
        return await retryutil.retry_async(attempt, what=f"Posting a message to {channel_id}")
    except Exception as e:
        log_error(f"Failed to post message to {channel_id}:", e)
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
    intro = f"Hi! :wave: I am *{name}* `{version}` :palm_up_hand::tophat: Here's what's :new::"
    # One headline plus one bullet per thing you can type: the news is a list of new
    # commands, so it reads as a list. `•` rather than `-`, because Slack turns a `-` line
    # inside a quote block into a nested list and re-indents it.
    entries = [
        "> :robot_face: *Triggers, actions & buttons*\n>\n"
        f"> • `{command} [config] set trigger cron \"0 9 * * 1-5\"` — fire on a schedule, "
        "no message needed.\n"
        f"> • `{command} [config] set trigger manual` — fire only on request.\n"
        f"> • `{command} [config] set action <action>` — `reply`, `post-channel #<channel>`, "
        "`dm-user @<user>` or `group-dm @<usergroup>`.\n"
        f"> • `{command} [config] add button \"<label>\" <ack|delay|config>` — interactive "
        "buttons on the message.\n"
        f"> • `{command} [config] set escalation <minutes> button \"<label>\"` — press that "
        "button itself if nobody does.",

        "> :traffic_light: *Conditions on any variable*\n>\n"
        f"> • `{command} [config] add condition <var> <operator> [value]` — gate a rule on any "
        "`{{variable}}`.\n"
        "> • Operators: `empty`, `equals`, `contains`, `starts-with`, `ends-with`, `regex`, each "
        "with a `not-` form.\n"
        f"> • `{command} [config] test` — which conditions pass.",

        "> :date: *Use Calendars*\n>\n"
        f"> • `{command} [config] set calendar <name|url>` — an ICS URL or a built-in calendar; "
        f"`{command} list calendars` names them.\n"
        "> • `{{calendar_summary}}` is the event running now, `{{calendar_summary(offset=next)}}` the "
        "one after it, `{{calendar_summary(at=\"+1d\")}}` this time tomorrow.\n"
        "> • `{{calendar_organizer_user}}` and `{{calendar_attendee_users}}` are the people on the "
        "event as Slack mentions, so a rule can DM them; `{{calendar_attendees(nth=2)}}` picks one.\n"
        f"> • `{command} [config] show calendar` — the event before, the one now, the next.",

        "> :test_tube: *Preview a whole rule, or run it now*\n>\n"
        f"> • `{command} [config] test` — the rendered message, where it would go (targets "
        "resolved to real people), when it fires next, which variables each field reads, and the "
        "calendar events behind them.\n"
        f"> • `{mention} [config] test <message>` — preview it against a message of your own.\n"
        f"> • `{command} [config] run` — let it act for real, right now.",

        "> :books: *Look things up*\n>\n"
        f"> • `{command} help variables` — every `{{{{variable}}}}` and every condition operator.\n"
        f"> • `{command} list teams`, `{command} list calendars`, `{command} list opsgenie-schedules` "
        "— what this instance offers.\n"
        f"> • `{command} [config] on-call [schedule name]` — the current OpsGenie on-call user as "
        "a Slack mention.",
    ]
    # One entry is never split, and entries stay in one quote block per message: a blank line
    # between them would end the quote, so they are joined by an empty quoted line.
    chunks = pack_message_chunks(entries, separator="\n>\n", limit=SLACK_MESSAGE_CHARACTER_LIMIT - 200)
    messages = [f"{intro}\n\n{chunks[0]}", *chunks[1:]]
    for index, message in enumerate(messages):
        await send_message(app, channel, user, message, thread_ts, footer=index == len(messages) - 1)


def tokenize_command(command: str) -> list[str]:
    """A command spelling split into words, keeping a bracketed or quoted group whole.

    `[<tz> <locale>]` is one argument and `<button "<label>"|config <name>>` is one too, so the
    split has to count `<`/`[` depth and skip over quotes rather than cut at every space.
    """
    tokens: list[str] = []
    current: list[str] = []
    depth = 0
    quote = ""
    for character in command:
        if quote:
            current.append(character)
            if character == quote:
                quote = ""
            continue
        if character in ('"', "'", "`"):
            quote = character
            current.append(character)
            continue
        if character in "<[":
            depth += 1
        elif character in ">]":
            depth = max(0, depth - 1)
        if character.isspace() and depth == 0:
            if current:
                tokens.append("".join(current))
                current = []
            continue
        current.append(character)
    if current:
        tokens.append("".join(current))
    return tokens


def _is_argument(token: str) -> bool:
    """Whether a token is a value the reader has to fill in, rather than a word they type."""
    return "<" in token or token.startswith("[")


def split_command_spec(command: str) -> tuple[str, list[str]]:
    """A command as `(head, arguments)`: the words to type, then the values to fill in.

    The head is what a reader scans the column for, so the arguments can move to their own
    lines when a command would otherwise push every description to the right. A keyword that
    introduces a value (`config <config>`) stays with it, because neither half means anything
    alone.
    """
    tokens = tokenize_command(command)
    # `[config]` is part of every command's head: it sits between the command word and the
    # keywords, so cutting there would leave the keywords hanging under it.
    first = next((index for index, token in enumerate(tokens) if index > 1 and _is_argument(token)),
                 len(tokens))
    head_tokens, argument_tokens = tokens[:first], tokens[first:]
    arguments = []
    index = 0
    while index < len(argument_tokens):
        token = argument_tokens[index]
        following = argument_tokens[index + 1] if index + 1 < len(argument_tokens) else ""
        if not _is_argument(token) and following and _is_argument(following):
            arguments.append(f"{token} {following}")
            index += 2
        else:
            arguments.append(token)
            index += 1
    return " ".join(head_tokens), arguments


def command_head(command: str) -> str:
    return split_command_spec(command)[0]


# How wide the command column may get before the descriptions beside it are squeezed. A few
# commands are far longer than the rest (`set datetime-format "<date>" "<time>" [<tz> <locale>]`),
# and sizing the column to those pushes every description across the screen — so past this they
# wrap their arguments instead. It is a ceiling, not a target: a table of short commands keeps a
# short column.
COMMAND_COLUMN_LIMIT = 56


def command_column_width(commands: list[str]) -> int:
    """The column every description lines up in: wide enough for the commands that fit in it.

    The heads are the floor — a head has nowhere else to go, so the column can never be
    narrower than the longest one — and `COMMAND_COLUMN_LIMIT` is the ceiling. In between it is
    the longest command that fits, so only the commands past the limit wrap.
    """
    if not commands:
        return 0
    longest_head = max(len(command_head(command)) for command in commands)
    fitting = [len(command) for command in commands if len(command) <= COMMAND_COLUMN_LIMIT]
    return max(longest_head, max(fitting, default=0))


def _fitting_count(prefix: str, arguments: list[str], width: int) -> int:
    """How many of `arguments` still fit after `prefix`, filling the column as far as it goes."""
    count = 0
    length = len(prefix)
    for argument in arguments:
        length += 1 + len(argument)
        if length > width:
            break
        count += 1
    return count


def _pack(arguments: list[str], indent: int, width: int) -> list[str]:
    """The leftover arguments as indented lines, each filled to the column."""
    lines = []
    remaining = list(arguments)
    while remaining:
        # At least one per line: an argument wider than the column has nowhere to go.
        count = max(1, _fitting_count(" " * indent, remaining, width))
        lines.append(" " * indent + " ".join(remaining[:count]))
        remaining = remaining[count:]
    return lines


def format_command_rows(rows: list[tuple[str, str]], width: int, gap: int = 2) -> list[str]:
    """The help table's rows: each command, its description, and any wrapped arguments.

    A command that fits the column is printed as one line. A longer one fills the column with
    as many arguments as fit beside its head — the description still starts `gap` spaces after
    the column — and the rest are stacked underneath, indented to the head's last word so they
    read as belonging to it. Without this a single long command (`set datetime-format "<date>"
    "<time>" [<tz> <locale>]`) sets the column width for the whole table and pushes every
    description off to the right.

    Commands sharing a head break at the same argument, even where one of them would have fitted
    the column whole: the three `add button "<label>" <action>` spellings are one command with
    three endings, and breaking them in three different places reads as three unrelated rows.
    """
    specs = [(command, description, *split_command_spec(command)) for command, description in rows]
    # Per head, how many arguments the first line carries — the fewest any of its rows can fit,
    # so they all break in the same place. A head whose rows all fit whole keeps them inline.
    first_line_counts: dict[str, int] = {}
    for command, _, head, arguments in specs:
        if not arguments:
            continue
        count = len(arguments) if len(command) <= width else _fitting_count(head, arguments, width)
        first_line_counts[head] = min(first_line_counts.get(head, count), count)
    lines = []
    for command, description, head, arguments in specs:
        count = first_line_counts.get(head, 0)
        if not arguments or count == len(arguments):
            lines.append(f"{command:<{width}}{' ' * gap}{description}")
            continue
        first = " ".join([head, *arguments[:count]]) if count else head
        indent = len(head) - len(head.rsplit(" ", 1)[-1]) if " " in head else 0
        lines.append(f"{first:<{width}}{' ' * gap}{description}")
        lines.extend(_pack(arguments[count:], indent, width))
    return lines


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
            (f"{command} rename config <name> <new-name>", "Rename a configuration, and everything pointing at it."),
            (f"{command} delete config <name>", "Delete a configuration."),
            (f"{command} export config [<name>]", "Print a configuration as JSON to copy elsewhere."),
            (f"{command} import config [<name>] <json>", "Create or replace a configuration from an export."),
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
            (f"{command} [config] set included-teams <team>[,<team>…]", "Replace the allowed teams."),
            (f"{command} [config] clear included-teams", "Clear allowed teams."),
            (f"{command} [config] add excluded-team <team>", "Add an ignored team."),
            (f"{command} [config] set excluded-teams <team>[,<team>…]", "Replace the ignored teams."),
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
            (f"{command} [config] set message \"<reply message>\"", "Set reminder message; `\\n` breaks a line."),
            (f"{command} [config] set action reply", "Reply in this channel (the default)."),
            (f"{command} [config] set action post-channel #<channel>", "Post to another channel."),
            (f"{command} [config] set action dm-user @<user>", "DM a single user."),
            (f"{command} [config] set action group-dm @<usergroup>", "Open one group DM with a user group."),
        ]),
        ("Buttons", [
            (f"{command} [config] add button \"<label>\" config <config>[,<config>…]", "Button runs other configs, in that order."),
            (f"{command} [config] add button \"<label>\" ack [text]", "Button marks it handled; [text] replies in the thread."),
            (f"{command} [config] add button \"<label>\" delay <minutes>", "Button postpones the escalation; buttons stay."),
            (f"{command} [config] clear buttons", "Remove all buttons."),
            (f"{command} [config] set escalation <minutes> button \"<label>\"", "Auto-press that button if nobody does in time."),
            (f"{command} [config] set escalation <minutes> config <config>[,<config>…]", "Run those configs if nobody presses in time."),
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
            (f"{command} [config] test", "Preview a rule: message, destination, variables, events."),
            (f"{mention} [config] test <message>", "Preview it with <message> as {{message}}."),
            (f"{command} [config] on-call [opsgenie-schedule]", "Show current on-call user."),
            (f"{command} list teams", "List available teams."),
            (f"{command} list opsgenie-schedules", "List OpsGenie schedules."),
            (f"{command} list calendars", "List the built-in calendars available here."),
            (f"{command} team of @<user>", "Show a user's team."),
        ]),
        ("Help", [
            (f"{command} news", "Show what's new."),
            (f"{command} help", "Show this help."),
            (f"{command} help variables", "List all {{variables}} and condition operators."),
        ]),
    ]
    command_width = command_column_width(
        [command for _, rows in command_groups for command, _ in rows])
    group_blocks = [
        f"# {title}\n" + "\n".join(format_command_rows(rows, command_width))
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
    variable_groups = templatedocs.variable_groups()
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
    detail_notes = templatedocs.argument_notes(command)
    messages = pack_message_chunks([intro, *group_notes, *detail_notes], limit=SLACK_MESSAGE_CHARACTER_LIMIT - 200)
    for index, message in enumerate(messages):
        await send_message(app, channel, user, message, thread_ts, footer=index == len(messages) - 1)
