"""Low-level Slack message posting + Slack-text cleaning / mention resolution."""

import re
import asyncio

from slack_bolt.async_app import AsyncApp
from slack_sdk.errors import SlackApiError

from employee_list import log_error, log_warning

from . import slackcache
from .constants import ID_PATTERN, MENTION_PATTERN, SUPPORTED_TEMPLATE_VARIABLES
from .models import Channel, User
from .textutil import log_debug


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
    update_text = (
        "Hi! :wave: I am *Hutbot* :palm_up_hand::tophat: Here's what's :new::\n\n"
        "> :robot_face: *Triggers, actions & buttons*\n>\n"
        "> Rules can now run on a `schedule` (cron), DM a user or group, post to a channel, and carry interactive buttons (with an auto-press default + timeout escalation). See `/hutbot help`.\n>\n"
        "> :calendar: *OpsGenie date/time template variables and defaults*\n>\n"
        "> OpsGenie templates can now include current and next on-call start/end dates, times, and datetimes. Use `/hutbot [config] set datetime-format \"<date>\" \"<time>\" [<timezone> <locale>]` to set the defaults.\n>\n"
        "> :pencil: *Customize reply messages with `{{placeholders}}`*\n>\n"
        "> That means Hutbot can include details like the `{{user}}`, `{{team}}`, `{{channel}}` or `{{wait_minutes}}`, or even mention the person who is currently on-call `{{opsgenie_current_user}}` in the reply message :exploding_head:.\n>\n"
        "> :sparkles: Just configure an Opsgenie schedule and you are good to go.\n>\n"
        "> :list-item: *List available Opsgenie schedules*\n>\n"
        "> :telephone_receiver: *Print the current on-call user*\n"
        "> Use `/hutbot [config] on-call [schedule name]` to get the current OpsGenie on-call user as a Slack mention.\n>\n"
        "> :test_tube: *Preview your configured reply*\n"
        "> Use `/hutbot [config] test` or mention me with `@Hutbot [config] test <message>` to test reply templates and variables.\n>\n"
        "> :bug: *Hutbot now ONLY cancels replying, when the _expected_ team(s) have already replied* :lightbulb:\n>\n"
        "> Issue was:\n>\n"
        "> 1. Team *A* sends a message intended for Team *B*\n"
        "> 2. Someone else from Team *A* adds additional information\n"
        "> 3. Hutbot cancels the reply and does NOT remind Team *B* anymore :fail:\n"
    )
    await send_message(app, channel, user, update_text, thread_ts)


async def send_help_message(app: AsyncApp, channel: Channel, user: User, thread_ts: str = "") -> None:
    supported_template_variables = ", ".join(f"`{{{{{variable}}}}}`" for variable in sorted(SUPPORTED_TEMPLATE_VARIABLES))
    command_rows = [
        ("/hutbot show config", "Show all configurations."),
        ("/hutbot [config] enable opsgenie", "Enable OpsGenie alerts."),
        ("/hutbot [config] disable opsgenie", "Disable OpsGenie alerts."),
        ("/hutbot [config] set opsgenie-schedule <name>", "Set the OpsGenie schedule name."),
        ("/hutbot [config] set opsgenie-priority <P1-P5>", "Set the OpsGenie alert priority."),
        ("/hutbot [config] set opsgenie-message <text>", "Template for the alert text (default: the message)."),
        ("/hutbot [config] set datetime-format \"<date>\" \"<time>\" [<tz> <locale>]", "Set date/time formats."),
        ("/hutbot [config] set wait-time <minutes>", "Set reminder delay."),
        ("/hutbot list teams", "List available teams."),
        ("/hutbot list opsgenie-schedules", "List OpsGenie schedules."),
        ("/hutbot [config] on-call [schedule]", "Show current on-call user."),
        ("/hutbot team of <@user>", "Show a user's team."),
        ("/hutbot [config] add excluded-team <team>", "Add an ignored team."),
        ("/hutbot [config] clear excluded-teams", "Clear ignored teams."),
        ("/hutbot [config] add included-team <team>", "Add an allowed team."),
        ("/hutbot [config] clear included-teams", "Clear allowed teams."),
        ("/hutbot [config] enable bots", "Respond to bot messages."),
        ("/hutbot [config] disable bots", "Ignore bot messages."),
        ("/hutbot [config] enable only-work-days", "Respond only on work days."),
        ("/hutbot [config] disable only-work-days", "Respond on all days."),
        ("/hutbot [config] enable", "Enable sending replies for this config."),
        ("/hutbot [config] disable", "Disable sending replies for this config."),
        ("/hutbot [config] set work-hours <start> <end>", "Set active hours; 0:00 0:00 means all day."),
        ("/hutbot [config] set pattern \"<regex>\" [0|1]", "Set message pattern; 1 means case sensitive."),
        ("/hutbot [config] set message \"<reply message>\"", "Set reminder message."),
        ("/hutbot [config] set forward-channel <#channel>", "Forward replies to another channel."),
        ("/hutbot [config] clear forward-channel", "Remove the forward channel."),
        ("/hutbot [config] set trigger <message|schedule|manual>", "Set how the rule starts."),
        ("/hutbot [config] set cron <expr>", "Set the cron schedule, e.g. 0 9 * * 1-5."),
        ("/hutbot [config] set schedule-timezone <tz>", "Set the cron timezone (IANA name)."),
        ("/hutbot [config] set condition <none|outlook>", "Gate a schedule on a condition."),
        ("/hutbot [config] set outlook-subject <regex>", "Match Outlook event subject (stub)."),
        ("/hutbot [config] set outlook-body <regex>", "Match Outlook event body (stub)."),
        ("/hutbot [config] enable negate", "Invert the condition (e.g. no matching event)."),
        ("/hutbot [config] disable negate", "Stop inverting the condition."),
        ("/hutbot [config] set action <reply|dm-user|group-dm|post-channel>", "Set what the rule does."),
        ("/hutbot [config] set target <@user|@group|#channel>", "Set the action recipient."),
        ("/hutbot [config] add button \"<label>\" config <config>", "Button runs another config (e.g. an alert config)."),
        ("/hutbot [config] add button \"<label>\" ack [text]", "Button acknowledges/dismisses (stops escalation)."),
        ("/hutbot [config] add button \"<label>\" message <text>", "Button posts a fixed message."),
        ("/hutbot [config] add button \"<label>\" delay <minutes>", "Button delays the escalation."),
        ("/hutbot [config] clear buttons", "Remove all buttons."),
        ("/hutbot [config] set button-timeout <minutes>", "Escalate if no button is pressed in time."),
        ("/hutbot [config] set button-timeout-target <config>", "Config to run on button timeout."),
        ("/hutbot [config] set default-button \"<label>\"", "Auto-press this button on timeout."),
        ("/hutbot [config] run", "Run this configuration's action now."),
        ("/hutbot [config] test", "Preview configured reply."),
        ("@Hutbot [config] test <message>", "Preview reply with <message> as {{message}}."),
        ("/hutbot delete config <name>", "Delete a configuration."),
        ("/hutbot news", "Show what's new."),
        ("/hutbot help", "Show this help."),
    ]
    command_width = max(len(command) for command, _ in command_rows)
    command_usage = "\n".join(f"{command:<{command_width}}  {description}" for command, description in command_rows)
    help_text = (
        "Hi! :wave: I am *Hutbot* :palm_up_hand::tophat: Here's what I can do:\n\n"
        "*Show All Configurations:*\n"
        "> Either use the command `/hutbot` or just `@Hutbot` me.\n"
        "```/hutbot show config\n"
        "@Hutbot show config```\n"
        f"Displays all configurations for `#{channel.name}`.\n\n"
        "*Commands:*\n"
        f"```\n{command_usage}\n```\n\n"
        "`[config]` is optional; omitted commands use `default`.\n\n"
        f"Supported reply variables: {supported_template_variables}."
    )
    await send_message(app, channel, user, help_text, thread_ts)
