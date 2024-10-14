import os
import re
import sys
import asyncio
import json
import aiofiles
from slack_bolt.async_app import AsyncApp
from slack_bolt.adapter.socket_mode.aiohttp import AsyncSocketModeHandler
from slack_sdk.errors import SlackApiError

default_config = {
    "wait_time": 30 * 60,
    "reply_message": "Anybody?",
}

config_file = 'hutmensch.json'  # Path to the configuration file
channel_config = {}             # Will be loaded from disk

# Dictionary to keep track of scheduled tasks
scheduled_messages = {}

# Regex patterns for command parsing
HELP_PATTERN = re.compile(r'help', re.IGNORECASE)
SET_WAIT_TIME_PATTERN = re.compile(r'set\s+wait[_-]?time\s+(\d+)', re.IGNORECASE)
SET_REPLY_MESSAGE_PATTERN = re.compile(r'set\s+message\s+(.+)', re.IGNORECASE)
SHOW_CONFIG_PATTERN = re.compile(r'show\s+config', re.IGNORECASE)

# Load configuration from disk at startup
async def load_configuration():
    global channel_config
    try:
        async with aiofiles.open(config_file, 'r') as f:
            content = await f.read()
            channel_config = json.loads(content)
            print("Configuration loaded from disk.")
    except FileNotFoundError:
        print("No configuration file found. Using default settings.")
        channel_config = {}
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON configuration: {e} Using default settings.")
        channel_config = {}

# Save configuration to disk
async def save_configuration():
    try:
        async with aiofiles.open(config_file, 'w') as f:
            content = json.dumps(channel_config)
            await f.write(content)
    except Exception as e:
        print(f"Error saving configuration: {e}")

async def is_command(app, text):
    # Check if the message is directed at the bot and is a command
    bot_user_id = (await app.client.auth_test())["user_id"]
    return f"<@{bot_user_id}>" in text


async def handle_command(app, text, channel, user):
    # Remove bot mention
    bot_user_id = (await app.client.auth_test())["user_id"]
    text = text.replace(f"<@{bot_user_id}>", "").strip()

    # Parse commands
    if SET_WAIT_TIME_PATTERN.match(text):
        match = SET_WAIT_TIME_PATTERN.match(text)
        wait_time_minutes = int(match.group(1))
        await set_wait_time(app, channel, wait_time_minutes, user)
    elif SET_REPLY_MESSAGE_PATTERN.match(text):
        match = SET_REPLY_MESSAGE_PATTERN.match(text)
        message = match.group(1).strip('"').strip("'")
        await set_reply_message(app, channel, message, user)
    elif SHOW_CONFIG_PATTERN.match(text):
        await show_config(app, channel, user)
    elif HELP_PATTERN.match(text):
        await send_help_message(app, channel, user)
    else:
        await send_message(app, channel, user, "Sorry, I didn't understand that command. Type 'help' for a list of commands.")


async def set_wait_time(app, channel, wait_time_minutes, user):
    # check if number and in range 0-1440
    if not wait_time_minutes or wait_time_minutes < 0 or wait_time_minutes > 1440:
        await send_message(app, channel, user, "Invalid wait time. Must be a number between 0 and 1440.")
        return

    if channel not in channel_config:
        channel_config[channel] = default_config.copy()
    channel_config[channel]['wait_time'] = wait_time_minutes * 60  # Convert to seconds
    await save_configuration()
    await send_message(app, channel, user, f"Wait time set to {wait_time_minutes} minutes.")


async def set_reply_message(app, channel, message, user):
    # check message
    if not message or message.strip() == "":
        await send_message(app, channel, user, "Invalid reply message. Must be non-empty.")
        return

    if channel not in channel_config:
        channel_config[channel] = default_config.copy()
    channel_config[channel]['reply_message'] = message
    await save_configuration()
    await send_message(app, channel, user, f"Reply message set to: {message}")


async def show_config(app, channel, user):
    config = channel_config.get(channel, default_config)
    wait_time_minutes = config['wait_time'] // 60
    reply_message = config['reply_message']
    message = f"This is the configuration for the current channel:\n\n*Wait time*: `{wait_time_minutes}` minutes\n\n*Reply message*:\n{reply_message}"
    await send_message(app, channel, user, message)


async def send_message(app, channel, user, text):
    try:
        await app.client.chat_postEphemeral(
            channel=channel,
            user=user,
            text=text,
            mrkdwn=True  # Enable Markdown formatting
        )
    except SlackApiError as e:
        print(f"ERROR: Failed to send message: {e}")


async def send_help_message(app, channel, user):
    help_text = (
        "Hi! :wave: I am *Hutbot* :palm_up_hand::tophat: Here's how you can configure me via command or @mention:\n\n"
        "*Set Wait Time:*\n"
        "```/hutbot set wait-time [minutes]```\n"
        "```@Hutbot set wait-time [minutes]```\n"
        "Sets the wait time before I send a reminder. Replace `[minutes]` with the number of minutes you want.\n\n"
        "*Set Reply Message:*\n"
        "```/hutbot set message \"Your reminder message\"```\n"
        "```@Hutbot set message \"Your reminder message\"```\n"
        "Sets the reminder message I'll send. Enclose your message in quotes.\n\n"
        "*Show Current Configuration:*\n"
        "```/hutbot show config```\n"
        "```@Hutbot show config```\n"
        "Displays the current wait time and reply message.\n\n"
        "*Help:*\n"
        "```/hutbot help```\n"
        "```@Hutbot help```\n"
        "Displays this help message.\n"
    )
    await send_message(app, channel, user, help_text)


async def schedule_reply(app, channel, ts):
    config = channel_config.get(channel, default_config)
    wait_time = config['wait_time']
    reply_message = config['reply_message']
    try:
        await asyncio.sleep(wait_time)
        await app.client.chat_postMessage(
            channel=channel,
            thread_ts=ts,
            text=reply_message
        )
    except asyncio.CancelledError:
        pass  # Task was cancelled because a reaction or reply was detected
    except SlackApiError as e:
        print(f"ERROR: Failed to send scheduled reply: {e}")


def register_app_handlers(app):
    @app.event("message")
    async def handle_message_events(body, logger):
        event = body.get('event', {})
        channel = event.get('channel')
        user = event.get('user')
        ts = event.get('ts')
        text = event.get('text', '')

        # Ignore messages from the bot itself
        if user == body['authorizations'][0]['user_id']:
            return

        # Check if the message is a command directed at the bot
        if await is_command(app, text):
            await handle_command(app, text, channel, user)
        else:
            # Schedule a reminder
            logger.info(f"Scheduling reminder for message {ts} in channel {channel}")
            task = asyncio.create_task(schedule_reply(app, channel, ts))
            scheduled_messages[(channel, ts)] = task


    @app.event("reaction_added")
    async def handle_reaction_added_events(body, logger):
        event = body.get('event', {})
        item = event.get('item', {})
        channel = item.get('channel')
        ts = item.get('ts')

        # Cancel the scheduled task if it exists
        key = (channel, ts)
        if key in scheduled_messages:
            logger.info(f"Reaction added. Cancelling reminder for message {ts} in channel {channel}")
            scheduled_messages[key].cancel()
            del scheduled_messages[key]


    @app.event("message")
    async def handle_thread_responses(body, logger):
        event = body.get('event', {})
        channel = event.get('channel')
        thread_ts = event.get('thread_ts')
        user = event.get('user')

        # Ignore messages from the bot itself
        if user == body['authorizations'][0]['user_id']:
            return

        if thread_ts:
            # Cancel the scheduled task if it exists
            key = (channel, thread_ts)
            if key in scheduled_messages:
                logger.info(f"Thread reply detected. Cancelling reminder for message {thread_ts} in channel {channel}")
                scheduled_messages[key].cancel()
                del scheduled_messages[key]


    @app.command("/hutbot")
    async def handle_config_command(ack, body, logger):
        await ack()
        text = body.get('text', '')
        channel = body['channel_id']
        user = body['user_id']
        await handle_command(app, text, channel, user)

async def main():
    if os.environ.get("SLACK_APP_TOKEN") is None or os.environ.get("SLACK_BOT_TOKEN") is None:
        print("ERROR: Environment variables SLACK_APP_TOKEN and SLACK_BOT_TOKEN must be set to run this app", file=sys.stderr)
        exit(1)

    try:
        await load_configuration()
        app = AsyncApp(token=os.environ.get("SLACK_BOT_TOKEN"))
        register_app_handlers(app)
        handler = AsyncSocketModeHandler(app, os.environ["SLACK_APP_TOKEN"])
        await handler.start_async()
    except asyncio.CancelledError:
        pass # Task was cancelled because a reaction or reply was detected
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        exit(1)
    except KeyboardInterrupt:
        print("\rExiting...")
        exit(0)

if __name__ == "__main__":
    asyncio.run(main())
