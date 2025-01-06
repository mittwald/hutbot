import os
import re
import sys
import collections
import asyncio
import json
import aiofiles
import datetime
import aiohttp  # Added for making HTTP requests
from unidecode import unidecode
from slack_bolt.async_app import AsyncApp
from slack_bolt.adapter.socket_mode.aiohttp import AsyncSocketModeHandler
from slack_sdk.errors import SlackApiError

ScheduledReply = collections.namedtuple('ScheduledReply', ['task', 'user_id'])
User = collections.namedtuple('User', ['id', 'name', 'real_name', 'team'])

default_config = {
    "wait_time": 30 * 60,
    "reply_message": "Anybody?",
    "excluded_teams": [],
    "included_teams": [],
}

company_users_file = 'company_users.json'  # Path to the users retrieved from https://lb.mittwald.it/api/users
config_file = 'hutmensch.json'  # Path to the configuration file
channel_config = {}             # Will be loaded from disk
team_unknown = '<unknown>'

# Dictionary to keep track of scheduled tasks
scheduled_messages = {}

user_id_cache = {}
id_user_cache = {}
team_cache = set()

bot_user_id = None

opsgenie_configured = False

# Regex patterns for command parsing
HELP_PATTERN = re.compile(r'help', re.IGNORECASE)
SET_WAIT_TIME_PATTERN = re.compile(r'set\s+wait[_-]?time\s+(\d+)', re.IGNORECASE)
SET_REPLY_MESSAGE_PATTERN = re.compile(r'set\s+message\s+(.+)', re.IGNORECASE)
ADD_EXCLUDED_TEAM_PATTERN = re.compile(r'add\s+excluded[_-]?teams?\s+(.+)', re.IGNORECASE)
CLEAR_EXCLUDED_TEAM_PATTERN = re.compile(r'clear\s+excluded[_-]?teams?', re.IGNORECASE)
ADD_INCLUDED_TEAM_PATTERN = re.compile(r'add\s+included[_-]?teams?\s+(.+)', re.IGNORECASE)
CLEAR_INCLUDED_TEAM_PATTERN = re.compile(r'clear\s+included[_-]?teams?', re.IGNORECASE)
LIST_TEAMS_PATTERN = re.compile(r'list\s+teams?', re.IGNORECASE)
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

def apply_defaults(config):
    for key, value in default_config.items():
        if key not in config:
            config[key] = value
    return config

async def load_configuration():
    global channel_config
    try:
        async with aiofiles.open(config_file, 'r') as f:
            content = await f.read()
            channel_config = apply_defaults(json.loads(content))
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

async def load_company_users() -> dict:
    # TODO: use the API directly
    try:
        async with aiofiles.open(company_users_file, 'r') as f:
            content = await f.read()
            users = json.loads(content)
            company_users = {}
            for user in users:
                id = user.get('ad_name', '').strip()
                is_deleted = user.get('is_deleted', False)
                if not is_deleted and len(id) > 0:
                    company_users[id] = user
            log(f"{len(company_users)} company users loaded from disk.")
            return company_users
    except FileNotFoundError:
        log("No company users file found. Will not be able to do team mapping.")
    except json.JSONDecodeError as e:
        log(f"Failed to decode company users JSON: {e}. Will not be able to do team mapping.")
    return {}

async def get_channel_name(app: AsyncApp, channel_id: str) -> str:
    try:
        response = app.client.conversations_info(channel=channel_id)
        channel_name = response["channel"]["name"]
        return channel_name
    except SlackApiError as e:
        log_error(f"Failed to get channel name: {e}")
        return channel_id

def normalize_real_name(real_name: str) -> str:
    normalized = real_name.strip().lower().replace(' ', '_').replace('.', '_')
    # replace non latin characters
    normalized = unidecode(normalized)
    return normalized

async def update_user_cache(app: AsyncApp):
    global user_id_cache, id_user_cache
    if not user_id_cache or not id_user_cache:
        company_users = await load_company_users()
        try:
            response = await app.client.users_list()
            users = response['members']
            for user in users:
                if not user.get('deleted') and not user.get('is_bot', False):
                    user_id = user.get('id', '')
                    user_name = user.get('name', '')
                    user_name_normalized = user_name.lower().replace('.', '').strip()
                    user_real_name = normalize_real_name(user.get('real_name', ''))
                    user_team = ''
                    if user_name in company_users:
                        user_team = company_users[user_name].get('group', '').strip()
                    elif user_name_normalized in company_users:
                        user_team = company_users[user_name_normalized].get('group', '').strip()
                    else:
                        # try with real name
                        for _, value in company_users.items():
                            company_real_name_normalized = normalize_real_name(value.get('fullname', ''))
                            # hackidy hack for slack, actually for AD fullnames with umlauts replaced
                            company_real_name_super_normalized = normalize_real_name(value.get('fullname', '').lower().replace('ae', 'ä').replace('oe', 'ö').replace('ue', 'ü').strip())
                            if company_real_name_normalized == user_real_name or company_real_name_super_normalized == user_real_name:
                                user_team = value.get('group', '').strip()
                                break
                        if user_team == '':
                            log(f"ERROR: Failed to map user {user_name} with real name {user_real_name} to a company user.")

                    if user_team == '':
                        user_team = team_unknown

                    user_id_cache[user_name] = User(id=user_id, name=user_name, team=user_team, real_name=user_real_name)
                    id_user_cache[user_id] = User(id=user_id, name=user_name, team=user_team, real_name=user_real_name)
                    if user_team not in team_cache:
                        team_cache.add(user_team)
        except SlackApiError as e:
            log_error(f"Failed to fetch user list: {e}")

async def get_user_by_id(app: AsyncApp, id: str) -> User:
    await update_user_cache(app)
    user = id_user_cache.get(id, None)
    if not user:
        user = User(id=id, name=id, team=team_unknown, real_name='')
    return user

async def get_user_by_name(app: AsyncApp, name: str) -> User:
    await update_user_cache(app)
    user = user_id_cache.get(name, None)
    if not user:
        user = User(id=None, name=name, team=team_unknown, real_name='')
    return user

def is_command(text):
    return f"<@{bot_user_id}>" in text

async def handle_command(app, text, channel_id, user_id):
    text = text.replace(f"<@{bot_user_id}>", "").strip()

    # Parse commands
    if SET_WAIT_TIME_PATTERN.match(text):
        match = SET_WAIT_TIME_PATTERN.match(text)
        wait_time_minutes = int(match.group(1))
        await set_wait_time(app, channel_id, wait_time_minutes, user_id)
    elif SET_REPLY_MESSAGE_PATTERN.match(text):
        match = SET_REPLY_MESSAGE_PATTERN.match(text)
        message = match.group(1).strip('"').strip("'")
        await set_reply_message(app, channel_id, message, user_id)
    elif ENABLE_OPSGENIE_PATTERN.match(text):
        await set_opsgenie(app, channel_id, True, user_id)
    elif DISABLE_OPSGENIE_PATTERN.match(text):
        await set_opsgenie(app, channel_id, False, user_id)
    elif LIST_TEAMS_PATTERN.match(text):
        await list_teams(app, channel_id, user_id)
    elif ADD_EXCLUDED_TEAM_PATTERN.match(text):
        match = ADD_EXCLUDED_TEAM_PATTERN.match(text)
        team = match.group(1)
        await add_excluded_team(app, channel_id, team, user_id)
    elif CLEAR_EXCLUDED_TEAM_PATTERN.match(text):
        await clear_excluded_team(app, channel_id, user_id)
    elif ADD_INCLUDED_TEAM_PATTERN.match(text):
        match = ADD_INCLUDED_TEAM_PATTERN.match(text)
        team = match.group(1)
        await add_included_team(app, channel_id, team, user_id)
    elif CLEAR_INCLUDED_TEAM_PATTERN.match(text):
        await clear_included_team(app, channel_id, user_id)
    elif SHOW_CONFIG_PATTERN.match(text):
        await show_config(app, channel_id, user_id)
    elif HELP_PATTERN.match(text):
        await send_help_message(app, channel_id, user_id)
    else:
        await send_message(app, channel_id, user_id, "Huh? :thinking_face: Maybe type `help` for a list of commands.")

async def set_opsgenie(app, channel_id, enabled, user_id):
    if channel_id not in channel_config:
        channel_config[channel_id] = default_config.copy()
    channel_config[channel_id]['opsgenie'] = enabled
    await save_configuration()
    await send_message(app, channel_id, user_id, f"OpsGenie integration {'enabled' if enabled else 'disabled'}{', but not configured' if enabled and not opsgenie_configured else ''}.")

async def set_wait_time(app, channel_id, wait_time_minutes, user_id):
    # check if number and in range 0-1440
    if not wait_time_minutes or wait_time_minutes < 0 or wait_time_minutes > 1440:
        await send_message(app, channel_id, user_id, "Invalid wait time. Must be a number between 0 and 1440.")
        return

    if channel_id not in channel_config:
        channel_config[channel_id] = default_config.copy()
    channel_config[channel_id]['wait_time'] = wait_time_minutes * 60  # Convert to seconds
    await save_configuration()
    await send_message(app, channel_id, user_id, f"*Wait time* set to `{wait_time_minutes}` minutes.")

async def set_reply_message(app, channel_id, message, user_id):
    # check message
    if not message or message.strip() == "":
        await send_message(app, channel_id, user_id, "Invalid reply message. Must be non-empty.")
        return
    ok, error, message = await process_mentions(app, message)
    if not ok:
        await send_message(app, channel_id, user_id, "Invalid reply message: " + error + ".")
        return
    if channel_id not in channel_config:
        channel_config[channel_id] = default_config.copy()

    channel_config[channel_id]['reply_message'] = message
    await save_configuration()
    await send_message(app, channel_id, user_id, f"*Reply message* set to: {message}")

async def process_mentions(app, message) -> tuple[bool, str, str]:
    # Regular expression to find @username patterns
    mention_pattern = re.compile(r'(?<![|<])@([a-z0-9-_.]+)(?!>)')
    matches = mention_pattern.findall(message)
    if matches:
        for username in matches:
            user = get_user_by_name(app, username)
            if user.id:
                message = message.replace(f"@{username}", f"<@{user.id}>")
            else:
                log_error(f"Invalid reply message: username {username} not found")
                return False, f"{username} not found", None
    return True, None, message

async def add_excluded_team(app, channel_id, team, user_id):
    await update_user_cache(app)
    if team not in team_cache:
        await send_message(app, channel_id, user_id, f"Unknown team: {team}.")
        return
    if channel_id not in channel_config:
        channel_config[channel_id] = default_config.copy()
    if team in channel_config[channel_id]['excluded_teams']:
        await send_message(app, channel_id, user_id, f"{team} is already excluded.")
        return

    if len(channel_config[channel_id]['included_teams']) > 0:
        await send_message(app, channel_id, user_id, f"Either set included teams or excluded teams, not both.")
        return

    channel_config[channel_id]['excluded_teams'].append(team)
    await save_configuration()
    await send_message(app, channel_id, user_id, f"Added {team} to excluded teams.")

async def clear_excluded_team(app, channel_id, user_id):
    if channel_id not in channel_config:
        channel_config[channel_id] = default_config.copy()
    channel_config[channel_id]['excluded_teams'] = []
    await save_configuration()
    await send_message(app, channel_id, user_id, "Cleared *excluded teams*.")

async def add_included_team(app, channel_id, team, user_id):
    await update_user_cache(app)
    if team not in team_cache:
        await send_message(app, channel_id, user_id, f"Unknown team: {team}.")
        return
    if channel_id not in channel_config:
        channel_config[channel_id] = default_config.copy()
    if team in channel_config[channel_id]['included_teams']:
        await send_message(app, channel_id, user_id, f"{team} is already included.")
        return

    if len(channel_config[channel_id]['excluded_teams']) > 0:
        await send_message(app, channel_id, user_id, f"Either set included teams or excluded teams, not both.")
        return

    channel_config[channel_id]['included_teams'].append(team)
    await save_configuration()
    await send_message(app, channel_id, user_id, f"Added {team} to *included teams*.")

async def clear_included_team(app, channel_id, user_id):
    if channel_id not in channel_config:
        channel_config[channel_id] = default_config.copy()
    channel_config[channel_id]['included_teams'] = []
    await save_configuration()
    await send_message(app, channel_id, user_id, "Cleared *included teams*.")

async def list_teams(app, channel_id, user_id):
    await update_user_cache(app)
    if channel_id not in channel_config:
        channel_config[channel_id] = default_config.copy()
    message = f"*Available teams*:\n{'\n'.join(sorted(team_cache))}"
    await send_message(app, channel_id, user_id, message)

async def show_config(app, channel_id, user_id):
    config = channel_config.get(channel_id, default_config)
    opsgenie_enabled = config.get('opsgenie', False)
    wait_time_minutes = config['wait_time'] // 60
    included_teams = config.get('included_teams', [])
    excluded_teams = config.get('excluded_teams', [])
    reply_message = config['reply_message']
    message = (
        "This is the configuration for the current channel:\n\n"
        f"*OpsGenie integration*: {'enabled' if opsgenie_enabled else 'disabled'}"
        f"{'' if opsgenie_configured else ' (not configured)'}\n\n"
        f"*Wait time*: `{wait_time_minutes}` minutes\n\n"
        f"*Included teams*: {', '.join(included_teams) if included_teams else '<None>'}\n\n"
        f"*Excluded teams*: {', '.join(excluded_teams) if excluded_teams else '<None>'}\n\n"
        f"*Reply message*:\n{reply_message}"
    )
    await send_message(app, channel_id, user_id, message)

async def send_message(app, channel_id, user_id, text):
    try:
        await app.client.chat_postEphemeral(
            channel=channel_id,
            user=user_id,
            text=text,
            mrkdwn=True  # Enable Markdown formatting
        )
    except SlackApiError as e:
        log_error(f"Failed to send message: {e}")

async def send_help_message(app, channel_id, user_id):
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
        "*List Available Teams:*\n"
        "```/hutbot list teams\n"
        "@Hutbot list teams```\n"
        "Lists the available teams.\n\n"
        "*Add Excluded Team:*\n"
        "```/hutbot add excluded-team [team]\n"
        "@Hutbot add excluded-team [team]```\n"
        "Adds a team whose members I will not respond to. Replace `[team]` with the name of the team.\n\n"
        "*Clear Excluded Teams:*\n"
        "```/hutbot clear excluded-teams\n"
        "@Hutbot clear excluded-teams```\n"
        "Clears the list of excluded teams.\n\n"
        "*Add Included Team:*\n"
        "```/hutbot add included-team [team]\n"
        "@Hutbot add included-team [team]```\n"
        "Adds a team whose members I will respond to *only*. Replace `[team]` with the name of the team.\n\n"
        "*Clear Included Teams:*\n"
        "```/hutbot clear included-teams\n"
        "@Hutbot clear included-teams```\n"
        "Clears the list of included teams.\n\n"
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
    await send_message(app, channel_id, user_id, help_text)

async def schedule_reply(app, opsgenie_token, channel_id, channel_name, user_id, user_name, text, ts):
    config = channel_config.get(channel_id, default_config)
    opsgenie_enabled = config.get('opsgenie', False)
    wait_time = config['wait_time']
    reply_message = config['reply_message']
    try:
        await asyncio.sleep(wait_time)
        await app.client.chat_postMessage(
            channel=channel_id,
            thread_ts=ts,
            text=reply_message,
            mrkdwn=True
        )
        if opsgenie_configured and opsgenie_enabled:
            await post_opsgenie_alert(opsgenie_token, channel_name, user_name, text, ts)
    except asyncio.CancelledError:
        pass  # Task was cancelled because a reaction or reply was detected
    except SlackApiError as e:
        log_error(f"Failed to send scheduled reply: {e}")

async def post_opsgenie_alert(opsgenie_token, channel_name, user_name, text, ts):
    url = 'https://api.opsgenie.com/v2/alerts'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'GenieKey {opsgenie_token}'
    }
    async with aiohttp.ClientSession() as session:
        try:
            # example data: {"message": "Test 19:48","alias": "hutbot: Test Test","description":"Every alert needs a description","tags": ["Hutbot"],"details":{"channel":"#cloud-hosting-ks","sender":"Dave","bot":"hutbot"},"priority":"P4"}
            data = {
                "message": f"{user_name}: {text}",
                "alias": f"hutbot: {user_name} in {channel_name} at {ts}",
                "description": f"#{channel_name}: {user_name} at {ts}: {text}",
                "tags": ["Hutbot"],
                "details": {
                    "channel": channel_name,
                    "sender": user_name,
                    "bot": "hutbot",
                },
                "priority": "P4",
            }
            async with session.post(url, headers=headers, data=json.dumps(data)) as response:
                if response.status != 202:
                    log_error(f"Failed to send alert: {response.status}")
                else:
                    log(f"Successfully sent OpsGenie alert for {user_name} in {channel_name} at {ts} with status code {response.status}")
        except Exception as e:
            log_error(f"Exception while sending alert: {e}")

def register_app_handlers(app: AsyncApp, opsgenie_token=None):

    @app.event("message")
    async def handle_message_events(body, logger):
        event = body.get('event', {})
        subtype = event.get('subtype')
        previous_message = event.get('previous_message')
        channel_id = event.get('channel')
        user_id = event.get('user_id')
        ts = event.get('ts')
        thread_ts = event.get('thread_ts')
        text = event.get('text', '')

        # Ignore messages from the bot itself
        if user_id == bot_user_id:
            log(f"Ignoring message from the bot from channel {channel_id}.")
            return

        if subtype == 'message_deleted' and previous_message:
            # deleted message
            await handle_message_deletion(app, event, channel_id, previous_message.get('user'), previous_message.get('ts'))
        elif user_id and is_command(text):
            # command
            await handle_command(app, text, channel_id, user_id)
        elif user_id and thread_ts:
            # thread
            await handle_thread_response(app, event, channel_id, user_id, thread_ts)
        elif user_id and ts:
            # channel message
            await handle_channel_message(app, event, channel_id, user_id, text, ts)

    async def handle_thread_response(app, event, channel_id, user_id, thread_ts):
        key = (channel_id, thread_ts)
        if key in scheduled_messages and scheduled_messages[key].user_id != user_id:
            channel_name = await get_channel_name(app, channel_id)
            message_user_id = scheduled_messages[key].user_id
            message_user = await get_user_by_id(app, message_user_id)
            reply_user = await get_user_by_id(app, user_id)
            log(f"Thread reply by user {reply_user.name} detected. Cancelling reminder for message {thread_ts} in channel {channel_name} by user {message_user.name}")
            scheduled_messages[key].task.cancel()
            del scheduled_messages[key]

    async def handle_channel_message(app, event, channel_id, user_id, text, ts):
        # Schedule a reminder
        channel_name = await get_channel_name(app, channel_id)
        user = await get_user_by_id(app, user_id)
        log(f"Scheduling reminder for message {ts} in channel {channel_name} by user {user.name}")
        task = asyncio.create_task(schedule_reply(app, opsgenie_token, channel_id, channel_name, user_id, user.name, text, ts))
        scheduled_messages[(channel_id, ts)] = ScheduledReply(task, user_id)

    async def handle_message_deletion(app, event, channel_id, previous_message_user_id, previous_message_ts):
        if previous_message_user_id == bot_user_id:
            log(f"Ignoring message deletion by bot from channel {channel_name}.")
            return

        # Cancel the scheduled task if it exists
        key = (channel_id, previous_message_ts)
        if key in scheduled_messages:
            channel_name = await get_channel_name(app, channel_id)
            previous_message_user = await get_user_by_id(app, previous_message_user_id)
            log(f"Message deleted. Cancelling reminder for message {previous_message_ts} in channel {channel_name} by user {previous_message_user.name}")
            scheduled_messages[key].task.cancel()
            del scheduled_messages[key]

    @app.event("reaction_added")
    async def handle_reaction_added_events(body, logger):
        event = body.get('event', {})
        item = event.get('item', {})
        channel_id = item.get('channel')
        user_id = event.get('user')
        ts = item.get('ts')

        # Cancel the scheduled task if it exists
        key = (channel_id, ts)
        if key in scheduled_messages and scheduled_messages[key].user_id != user_id:
            channel_name = await get_channel_name(app, channel_id)
            message_user_id = scheduled_messages[key].user_id
            message_user = await get_user_by_id(app, message_user_id)
            reaction_user = await get_user_by_id(app, user_id)
            log(f"Reaction added by user {reaction_user.name}. Cancelling reminder for message {ts} in channel {channel_name} by user {message_user.name}")
            scheduled_messages[key].task.cancel()
            del scheduled_messages[key]

    @app.command("/hutbot")
    async def handle_config_command(ack, body, logger):
        await ack()
        text = body.get('text', '')
        channel_id = body.get('channel_id')
        user_id = body.get('user_id')
        await handle_command(app, text, channel_id, user_id)

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
