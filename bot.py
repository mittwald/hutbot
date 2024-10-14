import os
import re
import asyncio
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from slack_sdk.errors import SlackApiError

# Initialize the app with your bot token and signing secret
app = App(token=os.environ.get("SLACK_BOT_TOKEN"))

# Default configurations
default_config = {
    "wait_time": 30 * 60,  # 30 minutes in seconds
    "reply_message": "Anybody?",
}

# Store configurations per channel
channel_config = {}

# Dictionary to keep track of scheduled tasks
scheduled_messages = {}

# Regex patterns for command parsing
SET_WAIT_TIME_PATTERN = re.compile(r'set\s+wait_time\s+(\d+)', re.IGNORECASE)
SET_REPLY_MESSAGE_PATTERN = re.compile(r'set\s+message\s+(.+)', re.IGNORECASE)
SHOW_CONFIG_PATTERN = re.compile(r'show\s+config', re.IGNORECASE)
HELP_PATTERN = re.compile(r'help', re.IGNORECASE)

@app.event("message")
def handle_message_events(body, logger):
    event = body.get('event', {})
    channel = event.get('channel')
    user = event.get('user')
    ts = event.get('ts')
    text = event.get('text', '')

    # Ignore messages from the bot itself
    if user == body['authorizations'][0]['user_id']:
        return

    # Check if the message is a command directed at the bot
    if is_command(text):
        handle_command(text, channel, user)
    else:
        # Schedule a reminder
        logger.info(f"Scheduling reminder for message {ts} in channel {channel}")
        task = asyncio.create_task(schedule_reply(channel, ts))
        scheduled_messages[(channel, ts)] = task


@app.event("reaction_added")
def handle_reaction_added_events(body, logger):
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
def handle_thread_responses(body, logger):
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


def is_command(text):
    # Check if the message is directed at the bot and is a command
    bot_user_id = app.client.auth_test()["user_id"]
    return f"<@{bot_user_id}>" in text


def handle_command(text, channel, user):
    # Remove bot mention
    bot_user_id = app.client.auth_test()["user_id"]
    text = text.replace(f"<@{bot_user_id}>", "").strip()

    # Parse commands
    if SET_WAIT_TIME_PATTERN.match(text):
        match = SET_WAIT_TIME_PATTERN.match(text)
        wait_time_minutes = int(match.group(1))
        set_wait_time(channel, wait_time_minutes, user)
    elif SET_REPLY_MESSAGE_PATTERN.match(text):
        match = SET_REPLY_MESSAGE_PATTERN.match(text)
        message = match.group(1).strip('"').strip("'")
        set_reply_message(channel, message, user)
    elif SHOW_CONFIG_PATTERN.match(text):
        show_config(channel, user)
    elif HELP_PATTERN.match(text):
        send_help_message(channel, user)
    else:
        send_message(channel, user, "Sorry, I didn't understand that command. Type 'help' for a list of commands.")


@app.command("/hutbot")
def handle_config_command(ack, body, logger):
    ack()
    text = body.get('text', '')
    channel = body['channel_id']
    user = body['user_id']
    handle_command(text, channel, user)

def set_wait_time(channel, wait_time_minutes, user):
    if channel not in channel_config:
        channel_config[channel] = default_config.copy()
    channel_config[channel]['wait_time'] = wait_time_minutes * 60  # Convert to seconds
    send_message(channel, user, f"Wait time set to {wait_time_minutes} minutes.")


def set_reply_message(channel, message, user):
    if channel not in channel_config:
        channel_config[channel] = default_config.copy()
    channel_config[channel]['reply_message'] = message
    send_message(channel, user, f"Reply message set to: {message}")


def show_config(channel, user):
    config = channel_config.get(channel, default_config)
    wait_time_minutes = config['wait_time'] // 60
    reply_message = config['reply_message']
    message = f"Current configuration:\n- Wait time: {wait_time_minutes} minutes\n- Reply message: {reply_message}"
    send_message(channel, user, message)


def send_message(channel, user, text):
    try:
        app.client.chat_postEphemeral(
            channel=channel,
            user=user,
            text=text,
            mrkdwn=True  # Enable Markdown formatting
        )
    except SlackApiError as e:
        print(f"Error sending message: {e}")


def send_help_message(channel, user):
    help_text = (
        "Hello! I'm *Hutbot*. Here's how you can interact with me:\n\n"
        "*Set Wait Time:*\n"
        "```@Hutbot set wait_time [minutes]```\n"
        "Sets the wait time before I send a reminder. Replace `[minutes]` with the number of minutes you want.\n\n"
        "*Set Reply Message:*\n"
        "```@Hutbot set message \"Your reminder message\"```\n"
        "Sets the reminder message I'll send. Enclose your message in quotes.\n\n"
        "*Show Current Configuration:*\n"
        "```@Hutbot show config```\n"
        "Displays the current wait time and reply message.\n\n"
        "*Help:*\n"
        "```@Hutbot help```\n"
        "Displays this help message.\n"
    )
    send_message(channel, user, help_text)


async def schedule_reply(channel, ts):
    config = channel_config.get(channel, default_config)
    wait_time = config['wait_time']
    reply_message = config['reply_message']
    try:
        await asyncio.sleep(wait_time)
        app.client.chat_postMessage(
            channel=channel,
            thread_ts=ts,
            text=reply_message
        )
    except asyncio.CancelledError:
        pass  # Task was cancelled because a reaction or reply was detected
    except SlackApiError as e:
        print(f"Error sending scheduled reply: {e}")


if __name__ == "__main__":
    # Set your bot token and app token as environment variables
    # os.environ["SLACK_BOT_TOKEN"] = "xoxb-your-slack-bot-token"
    # os.environ["SLACK_APP_TOKEN"] = "xapp-your-app-level-token"
    handler = SocketModeHandler(app, os.environ["SLACK_APP_TOKEN"])
    handler.start()
