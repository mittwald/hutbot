"""Low-level Slack message posting + Slack-text cleaning / mention resolution."""

import re
import asyncio

from slack_bolt.async_app import AsyncApp
from slack_sdk.errors import SlackApiError

from employee_list import log_error, log_warning

from . import slackcache
from . import state
from .constants import ID_PATTERN, MENTION_PATTERN, SUPPORTED_TEMPLATE_VARIABLES
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


async def send_message(app: AsyncApp, channel: Channel, user: User, text: str, thread_ts: str = "") -> None:
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
        f"> Rules can now run on a `schedule` (cron), DM a user or group, post to a channel, and carry interactive buttons (with an auto-press default + timeout escalation). See `{command} help`.\n>\n"
        "> :calendar: *OpsGenie date/time template variables and defaults*\n>\n"
        f"> OpsGenie templates can now include current and next on-call start/end dates, times, and datetimes. Use `{command} [config] set datetime-format \"<date>\" \"<time>\" [<timezone> <locale>]` to set the defaults.\n>\n"
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
    supported_template_variables = ", ".join(f"`{{{{{variable}}}}}`" for variable in sorted(SUPPORTED_TEMPLATE_VARIABLES))
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
            (f"{command} [config] set trigger <message|schedule|manual>", "Set how the rule starts."),
            (f"{command} [config] set cron <expr>", "Set the cron schedule, e.g. 0 9 * * 1-5."),
            (f"{command} [config] set schedule-timezone <tz>", "Set the cron timezone (IANA name)."),
        ]),
        ("Condition", [
            (f"{command} [config] set condition <none|outlook>", "Gate a schedule on a condition."),
            (f"{command} [config] set outlook-subject <regex>", "Match Outlook event subject (stub)."),
            (f"{command} [config] set outlook-body <regex>", "Match Outlook event body (stub)."),
            (f"{command} [config] enable negate", "Invert the condition (e.g. no matching event)."),
            (f"{command} [config] disable negate", "Stop inverting the condition."),
        ]),
        ("What to react to", [
            (f"{command} [config] set pattern \"<regex>\" [0|1]", "Set message pattern; 1 means case sensitive."),
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
            (f"{command} [config] set work-hours all day", "React at any hour (same as 0:00 0:00)."),
        ]),
        ("Message and action", [
            (f"{command} [config] set message \"<reply message>\"", "Set reminder message."),
            (f"{command} [config] set action <reply|dm-user|group-dm|post-channel>", "Set what the rule does."),
            (f"{command} [config] set target <@user|@group|#channel>", "Set the action recipient."),
            (f"{command} [config] set forward-channel <#channel>", "Forward replies to another channel."),
            (f"{command} [config] clear forward-channel", "Remove the forward channel."),
        ]),
        ("Buttons", [
            (f"{command} [config] add button \"<label>\" config <config>", "Button runs another config (e.g. an alert config)."),
            (f"{command} [config] add button \"<label>\" ack [text]", "Button acknowledges/dismisses (stops escalation)."),
            (f"{command} [config] add button \"<label>\" message <text>", "Button posts a fixed message."),
            (f"{command} [config] add button \"<label>\" delay <minutes>", "Button delays the escalation."),
            (f"{command} [config] clear buttons", "Remove all buttons."),
            (f"{command} [config] set button-timeout <minutes>", "Escalate if no button is pressed in time."),
            (f"{command} [config] set button-timeout-target <config>", "Config to run on button timeout."),
            (f"{command} [config] set default-button \"<label>\"", "Auto-press this button on timeout."),
        ]),
        ("OpsGenie", [
            (f"{command} [config] enable opsgenie", "Enable OpsGenie alerts."),
            (f"{command} [config] disable opsgenie", "Disable OpsGenie alerts."),
            (f"{command} [config] set opsgenie-schedule <name>", "Set the OpsGenie schedule name."),
            (f"{command} [config] set opsgenie-priority <P1-P5>", "Set the OpsGenie alert priority."),
            (f"{command} [config] set opsgenie-message <text>", "Template for the alert text (default: the message)."),
        ]),
        ("Date and time", [
            (f"{command} [config] set datetime-format \"<date>\" \"<time>\" [<tz> <locale>]", "Set date/time formats."),
        ]),
        ("Try it out and look things up", [
            (f"{command} [config] run", "Run this configuration's action now."),
            (f"{command} [config] test", "Preview configured reply."),
            (f"{mention} [config] test <message>", "Preview reply with <message> as {{message}}."),
            (f"{command} [config] on-call [schedule]", "Show current on-call user."),
            (f"{command} list teams", "List available teams."),
            (f"{command} list opsgenie-schedules", "List OpsGenie schedules."),
            (f"{command} team of <@user>", "Show a user's team."),
        ]),
        ("Help", [
            (f"{command} news", "Show what's new."),
            (f"{command} help", "Show this help."),
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
    outro = (
        "`[config]` is optional; omitted commands use `default`.\n\n"
        f"Supported reply variables: {supported_template_variables}."
    )
    # The command table alone is well past Slack's per-message limit, and Slack
    # splits an oversized message wherever it happens to land — which cuts the code
    # fence in half. Send it in chunks that each close their own fence.
    command_messages = [
        f"*Commands{'' if index == 0 else ' (continued)'}:*\n```\n{chunk}\n```"
        for index, chunk in enumerate(pack_message_chunks(group_blocks, limit=SLACK_MESSAGE_CHARACTER_LIMIT - 200))
    ]
    for message in [intro, *command_messages, outro]:
        await send_message(app, channel, user, message, thread_ts)
