import os
import re
import sys
import collections
import asyncio
import json
import aiofiles
import datetime
import aiohttp  # Added for making HTTP requests
from slack_bolt.async_app import AsyncApp
from slack_bolt.adapter.socket_mode.aiohttp import AsyncSocketModeHandler
from slack_sdk.errors import SlackApiError

ScheduledReply = collections.namedtuple('ScheduledReply', ['task', 'user'])

default_config = {
    "wait_time": 30 * 60,
    "reply_message": "Anybody?",
}

users_file = 'users.json'  # Path to the users retrieved from https://lb.mittwald.it/api/users
config_file = 'hutmensch.json'  # Path to the configuration file
channel_config = {}             # Will be loaded from disk

# Dictionary to keep track of scheduled tasks
scheduled_messages = {}

user_cache = {}

bot_user_id = None

opsgenie_configured = False

# Regex patterns for command parsing
HELP_PATTERN = re.compile(r'help', re.IGNORECASE)
SET_WAIT_TIME_PATTERN = re.compile(r'set\s+wait[_-]?time\s+(\d+)', re.IGNORECASE)
SET_REPLY_MESSAGE_PATTERN = re.compile(r'set\s+message\s+(.+)', re.IGNORECASE)
ENABLE_OPSGENIE_PATTERN = re.compile(r'enable\s+opsgenie', re.IGNORECASE)
DISABLE_OPSGENIE_PATTERN = re.compile(r'disable\s+opsgenie', re.IGNORECASE)
SHOW_CONFIG_PATTERN = re.compile(r'show\s+config', re.IGNORECASE)

def load_env_file():
    env_file_path = os.path.join(os.path.dirname(__file__), '.env')
    if not os.path.exists(env_file_path):
        return

    with open(env_file_path) as file:
        for line in file:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # remove "export " from the start of the line
            if line.startswith('export '):
                line = line[7:]

            # Split key-value pairs
            key, sep, value = line.partition('=')
            if sep != '=':
                continue  # Skip malformed lines

            # Remove surrounding quotes from the value if present
            key = key.strip()
            value = value.strip().strip('\'"')

            # Set the environment variable
            os.environ[key] = value

def log(*args):
    message = ' '.join([str(arg) for arg in args])
    prefix = f"{datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')} INFO: "
    print(prefix, message, flush=True)


def log_error(*args):
    message = ' '.join([str(arg) for arg in args])
    prefix = f"{datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')} ERROR:"
    print(prefix, message, flush=True, file=sys.stderr)


async def load_configuration():
    global channel_config
    try:
        async with aiofiles.open(config_file, 'r') as f:
            content = await f.read()
            channel_config = json.loads(content)
            log("Configuration loaded from disk.")
    except FileNotFoundError:
        log("No configuration file found. Using default settings.")
        channel_config = {}
    except json.JSONDecodeError as e:
        log(f"Failed to decode JSON configuration: {e} Using default settings.")
        channel_config = {}


async def save_configuration():
    try:
        async with aiofiles.open(config_file, 'w') as f:
            content = json.dumps(channel_config)
            await f.write(content)
    except Exception as e:
        log_error(f"Failed to save configuration: {e}")

async def load_users() -> dict:
    try:
        async with aiofiles.open(users_file, 'r') as f:
            content = await f.read()
            users = json.loads(content)
            log("Users loaded from disk.")
            return users
    except FileNotFoundError:
        log("No users file found. Will not be able to do department mapping.")
    except json.JSONDecodeError as e:
        log(f"Failed to decode JSON users: {e}. Will not be able to do department mapping.")
    return {}

async def update_user_cache(app: AsyncApp):
    global user_cache
    if not user_cache:
        try:
            response = await app.client.users_list()
            users = response['members']
            for user in users:
                log(f"{user}")
                log(user.get('profile', {}).get('email', ''))
                user_id = user['id']
                user_name = user['name']
                user_cache[user_name] = user_id
        except SlackApiError as e:
            log_error(f"Failed to fetch user list: {e}")


def is_command(text):
    return f"<@{bot_user_id}>" in text


async def handle_command(app, text, channel, user):
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
    elif ENABLE_OPSGENIE_PATTERN.match(text):
        await set_opsgenie(app, channel, True, user)
    elif DISABLE_OPSGENIE_PATTERN.match(text):
        await set_opsgenie(app, channel, False, user)
    elif SHOW_CONFIG_PATTERN.match(text):
        await show_config(app, channel, user)
    elif HELP_PATTERN.match(text):
        await send_help_message(app, channel, user)
    else:
        await send_message(app, channel, user, "Huh? :thinking_face: Maybe type `help` for a list of commands.")


async def set_opsgenie(app, channel, enabled, user):
    if channel not in channel_config:
        channel_config[channel] = default_config.copy()
    channel_config[channel]['opsgenie'] = enabled
    await save_configuration()
    await send_message(app, channel, user, f"OpsGenie integration {'enabled' if enabled else 'disabled'}{', but not configured' if enabled and not opsgenie_configured else ''}.")


async def set_wait_time(app, channel, wait_time_minutes, user):
    # check if number and in range 0-1440
    if not wait_time_minutes or wait_time_minutes < 0 or wait_time_minutes > 1440:
        await send_message(app, channel, user, "Invalid wait time. Must be a number between 0 and 1440.")
        return

    if channel not in channel_config:
        channel_config[channel] = default_config.copy()
    channel_config[channel]['wait_time'] = wait_time_minutes * 60  # Convert to seconds
    await save_configuration()
    await send_message(app, channel, user, f"*Wait time* set to `{wait_time_minutes}` minutes.")


async def set_reply_message(app, channel, message, user):
    # check message
    if not message or message.strip() == "":
        await send_message(app, channel, user, "Invalid reply message. Must be non-empty.")
        return
    ok, error, message = await process_mentions(app, message)
    if not ok:
        await send_message(app, channel, user, "Invalid reply message: " + error + ".")
        return
    if channel not in channel_config:
        channel_config[channel] = default_config.copy()

    channel_config[channel]['reply_message'] = message
    await save_configuration()
    await send_message(app, channel, user, f"*Reply message* set to: {message}")


async def process_mentions(app, message) -> tuple[bool, str, str]:
    # Regular expression to find @username patterns
    mention_pattern = re.compile(r'(?<![|<])@([a-z0-9-_.]+)(?!>)')
    matches = mention_pattern.findall(message)
    if matches:
        # Ensure user cache is updated
        await update_user_cache(app)
        for username in matches:
            user_id = user_cache.get(username)
            if user_id:
                message = message.replace(f"@{username}", f"<@{user_id}>")
            else:
                log_error(f"Invalid reply message: username {username} not found")
                return False, f"{username} not found", None
    return True, None, message


async def show_config(app, channel, user):
    config = channel_config.get(channel, default_config)
    opsgenie_enabled = config.get('opsgenie', False)
    wait_time_minutes = config['wait_time'] // 60
    reply_message = config['reply_message']
    message = f"This is the configuration for the current channel:\n\n*OpsGenie integration*: {'enabled' if opsgenie_enabled else 'disabled'}{'' if opsgenie_configured else ' (not configured)'}\n\n*Wait time*: `{wait_time_minutes}` minutes\n\n*Reply message*:\n{reply_message}"
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
        log_error(f"Failed to send message: {e}")


async def send_help_message(app, channel, user):
    help_text = (
        "Hi! :wave: I am *Hutbot* :palm_up_hand::tophat: Here's how you can configure me via command or @mention:\n\n"
        "*Enable OpsGenie Integration:*\n"
        "```/hutbot enable opsgenie\n"
        "@Hutbot enable opsgenie```\n"
        "Enables the OpsGenie integration.\n\n"
        "*Disable OpsGenie Integration:*\n"
        "```/hutbot disable opsgenie\n"
        "@Hutbot disable opsgenie```\n"
        "Disables the OpsGenie integration.\n\n"
        "*Set Wait Time:*\n"
        "```/hutbot set wait-time [minutes]\n"
        "@Hutbot set wait-time [minutes]```\n"
        "Sets the wait time before I send a reminder. Replace `[minutes]` with the number of minutes you want.\n\n"
        "*Set Reply Message:*\n"
        "```/hutbot set message \"Your reminder message\"\n"
        "@Hutbot set message \"Your reminder message\"```\n"
        "Sets the reminder message I'll send. Enclose your message in quotes.\n\n"
        "*Show Current Configuration:*\n"
        "```/hutbot show config\n"
        "@Hutbot show config```\n"
        "Displays the current wait time and reply message.\n\n"
        "*Help:*\n"
        "```/hutbot help\n"
        "@Hutbot help```\n"
        "Displays this help message.\n"
    )
    await send_message(app, channel, user, help_text)


async def schedule_reply(app, opsgenie_token, event, channel, user, text, ts):
    config = channel_config.get(channel, default_config)
    opsgenie_enabled = config.get('opsgenie', False)
    wait_time = config['wait_time']
    reply_message = config['reply_message']
    try:
        await asyncio.sleep(wait_time)
        await app.client.chat_postMessage(
            channel=channel,
            thread_ts=ts,
            text=reply_message,
            mrkdwn=True
        )
        if opsgenie_configured and opsgenie_enabled:
            await post_opsgenie_alert(opsgenie_token, event, channel, user, text, ts)
    except asyncio.CancelledError:
        pass  # Task was cancelled because a reaction or reply was detected
    except SlackApiError as e:
        log_error(f"Failed to send scheduled reply: {e}")

async def post_opsgenie_alert(opsgenie_token, event, channel, user, text, ts):
    url = 'https://api.opsgenie.com/v2/alerts'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'GenieKey {opsgenie_token}'
    }
    async with aiohttp.ClientSession() as session:
        try:
            # example data: {"message": "Test 19:48","alias": "hutbot: Test Test","description":"Every alert needs a description","tags": ["Hutbot"],"details":{"channel":"#cloud-hosting-ks","sender":"Dave","bot":"hutbot"},"priority":"P4"}
            data = {
                "message": f"{text}",
                "alias": f"hutbot: {user} in {channel} at {ts}",
                "description": f"#{channel}: {user} at {ts}: {text}",
                "tags": ["Hutbot"],
                "details": {
                    "channel": channel,
                    "sender": user,
                    "bot": "hutbot",
                },
                "priority": "P4",
            }
            async with session.post(url, headers=headers, data=json.dumps(data)) as response:
                if response.status != 202:
                    log_error(f"Failed to send alert: {response.status}")
                else:
                    log(f"Successfully sent OpsGenie alert for {user} in {channel} at {ts} with status code {response.status}")
        except Exception as e:
            log_error(f"Exception while sending alert: {e}")

def register_app_handlers(app: AsyncApp, opsgenie_token=None):

    @app.event("message")
    async def handle_message_events(body, logger):
        event = body.get('event', {})
        subtype = event.get('subtype')
        previous_message = event.get('previous_message')
        channel = event.get('channel')
        user = event.get('user')
        ts = event.get('ts')
        thread_ts = event.get('thread_ts')
        text = event.get('text', '')

        # Ignore messages from the bot itself
        if user == bot_user_id:
            log(f"Ignoring message from the bot from channel {channel}.")
            return

        if subtype == 'message_deleted' and previous_message:
            # deleted message
            await handle_message_deletion(app, event, channel, previous_message.get('user'), previous_message.get('ts'))
        elif user and is_command(text):
            # command
            await handle_command(app, text, channel, user)
        elif user and thread_ts:
            # thread
            await handle_thread_response(app, event, channel, user, thread_ts)
        elif user and ts:
            # channel message
            await handle_channel_message(app, event, channel, user, text, ts)


    async def handle_thread_response(app, event, channel, user, thread_ts):
        key = (channel, thread_ts)
        if key in scheduled_messages and scheduled_messages[key].user != user:
            log(f"Thread reply from a different user detected. Cancelling reminder for message {thread_ts} in channel {channel}")
            scheduled_messages[key].task.cancel()
            del scheduled_messages[key]


    async def handle_channel_message(app, event, channel, user, text, ts):
        # Schedule a reminder
        log(f"Scheduling reminder for message {ts} in channel {channel} by user {user}")
        task = asyncio.create_task(schedule_reply(app, opsgenie_token, event, channel, user, text, ts))
        scheduled_messages[(channel, ts)] = ScheduledReply(task, user)


    async def handle_message_deletion(app, event, channel, previous_message_user, previous_message_ts):
        if previous_message_user == bot_user_id:
            log(f"Ignoring message deletion by bot from channel {channel}.")
            return

        # Cancel the scheduled task if it exists
        key = (channel, previous_message_ts)
        if key in scheduled_messages:
            log(f"Message deleted. Cancelling reminder for message {previous_message_ts} in channel {channel} by user {previous_message_user}")
            scheduled_messages[key].task.cancel()
            del scheduled_messages[key]


    @app.event("reaction_added")
    async def handle_reaction_added_events(body, logger):
        event = body.get('event', {})
        item = event.get('item', {})
        channel = item.get('channel')
        user = event.get('user')
        ts = item.get('ts')

        # Cancel the scheduled task if it exists
        key = (channel, ts)
        if key in scheduled_messages and scheduled_messages[key].user != user:
            log(f"Reaction added by different user. Cancelling reminder for message {ts} in channel {channel}")
            scheduled_messages[key].task.cancel()
            del scheduled_messages[key]


    @app.command("/hutbot")
    async def handle_config_command(ack, body, logger):
        await ack()
        text = body.get('text', '')
        channel = body.get('channel_id')
        user = body.get('user_id')
        await handle_command(app, text, channel, user)

async def send_heartbeat(opsgenie_token, opsgenie_heartbeat_name):
    url = 'https://api.opsgenie.com/v2/heartbeats/' + opsgenie_heartbeat_name + '/ping'
    headers = {
        'Authorization': f'GenieKey {opsgenie_token}'
    }
    log(f"Starting to send heartbeat to {url}...")
    async with aiohttp.ClientSession() as session:
        while True:
            try:
                async with session.get(url, headers=headers) as response:
                    if response.status != 202:
                        log_error(f"Failed to send heartbeat: {response.status}")
            except Exception as e:
                log_error(f"Exception while sending heartbeat: {e}")
            await asyncio.sleep(60)

async def main():
    load_env_file()
    slack_app_token = os.environ.get("SLACK_APP_TOKEN")
    slack_bot_token = os.environ.get("SLACK_BOT_TOKEN")
    opsgenie_token = os.environ.get("OPSGENIE_TOKEN")
    opsgenie_heartbeat_name = os.environ.get("OPSGENIE_HEARTBEAT_NAME")
    if slack_app_token is None or slack_bot_token is None:
        log_error("Environment variables SLACK_APP_TOKEN and SLACK_BOT_TOKEN must be set to run this app")
        exit(1)

    handler = None
    heartbeat_task = None
    try:
        await load_configuration()
        app = AsyncApp(token=slack_bot_token)
        global bot_user_id
        bot_user_id = (await app.client.auth_test())["user_id"]
        await update_user_cache(app)
        register_app_handlers(app, opsgenie_token=opsgenie_token)
        handler = AsyncSocketModeHandler(app, slack_app_token)
        if opsgenie_token and opsgenie_heartbeat_name:
            global opsgenie_configured
            opsgenie_configured = True
            heartbeat_task = asyncio.create_task(send_heartbeat(opsgenie_token, opsgenie_heartbeat_name))
        await handler.start_async()
    except asyncio.CancelledError:
        pass
    except KeyboardInterrupt:
        pass
    except Exception as e:
        log_error(e)
        exit(1)
    finally:
        try:
            if handler:
                await handler.close_async()
            if heartbeat_task:
                heartbeat_task.cancel()
                try:
                    await heartbeat_task
                except asyncio.CancelledError:
                    pass
        except BaseException as e:
            pass

if __name__ == "__main__":
    asyncio.run(main())
