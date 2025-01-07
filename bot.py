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
Channel = collections.namedtuple('Channel', ['id', 'name', 'config'])


DEFAULT_CONFIG = {
    "wait_time": 30 * 60,
    "reply_message": "Anybody?",
    "excluded_teams": [],
    "included_teams": [],
}

COMPANY_USERS_FILE_NAME = 'company_users.json'  # Path to the users retrieved from https://lb.mittwald.it/api/users
CONFIG_FILE_NAME = 'hutmensch.json'  # Path to the configuration file
TEAM_UNKNOWN = '<unknown>'

channel_config = {}
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

def load_env_file() -> None:
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

def log(*args: object) -> None:
    message = ' '.join([str(arg) for arg in args])
    prefix = f"{datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')} INFO: "
    print(prefix, message, flush=True)

def log_error(*args: object) -> None:
    message = ' '.join([str(arg) for arg in args])
    prefix = f"{datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')} ERROR:"
    print(prefix, message, flush=True, file=sys.stderr)

def log_warning(*args: object) -> None:
    message = ' '.join([str(arg) for arg in args])
    prefix = f"{datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')} WARN: "
    print(prefix, message, flush=True, file=sys.stderr)

def apply_defaults(config: dict) -> dict:
    for _, channel_config in config.items():
        for key, value in DEFAULT_CONFIG.items():
            if key not in channel_config:
                channel_config[key] = value
    return config

async def load_configuration() -> None:
    global channel_config
    try:
        async with aiofiles.open(CONFIG_FILE_NAME, 'r') as f:
            content = await f.read()
            channel_config = apply_defaults(json.loads(content))
            log("Configuration loaded from disk.")
    except FileNotFoundError:
        log("No configuration file found. Using default settings.")
        channel_config = {}
    except json.JSONDecodeError as e:
        log(f"Failed to decode JSON configuration: {e} Using default settings.")
        channel_config = {}

async def save_configuration() -> None:
    try:
        async with aiofiles.open(CONFIG_FILE_NAME, 'w') as f:
            content = json.dumps(channel_config)
            await f.write(content)
    except Exception as e:
        log_error(f"Failed to save configuration: {e}")

async def load_company_users() -> dict:
    # TODO: use the API directly
    try:
        async with aiofiles.open(COMPANY_USERS_FILE_NAME, 'r') as f:
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

async def get_channel_by_id(app: AsyncApp, channel_id: str) -> Channel:
    global channel_config
    if channel_id not in channel_config:
        channel_config[channel_id] = DEFAULT_CONFIG.copy()

    name = await get_channel_name(app, channel_id)
    config = channel_config[channel_id]

    return Channel(id=channel_id, name=name, config=config)

async def get_channel_name(app: AsyncApp, channel_id: str) -> str:
    try:
        response = await app.client.conversations_info(channel=channel_id)
        channel_name = response.get('channel', {}).get('name', '')
        if channel_name:
            return channel_name
    except SlackApiError as e:
        log_error(f"Failed to get channel name: {e}")

    return channel_id

def normalize_real_name(real_name: str) -> str:
    normalized = real_name.strip().lower().replace(' ', '_').replace('.', '_')
    # replace non latin characters
    normalized = unidecode(normalized)
    return normalized

async def update_user_cache(app: AsyncApp) -> None:
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
                    user_real_name = user.get('real_name', '').strip()
                    user_real_name_normalized = normalize_real_name(user_real_name)
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
                            if company_real_name_normalized == user_real_name_normalized or company_real_name_super_normalized == user_real_name_normalized:
                                user_team = value.get('group', '').strip()
                                break
                        if user_team == '':
                            log_warning(f"Failed to map user @{user_name} with real name {user_real_name} to a company user.")

                    if user_team == '':
                        user_team = TEAM_UNKNOWN

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
        user = User(id=id, name=id, team=TEAM_UNKNOWN, real_name='')
    return user

async def get_user_by_name(app: AsyncApp, name: str) -> User:
    await update_user_cache(app)
    user = user_id_cache.get(name, None)
    if not user:
        user = User(id=None, name=name, team=TEAM_UNKNOWN, real_name='')
    return user

def is_command(text: str) -> bool:
    return f"<@{bot_user_id}>" in text

async def handle_command(app: AsyncApp, text: str, channel: Channel, user_id: str, thread_ts: str = None) -> None:
    text = text.replace(f"<@{bot_user_id}>", "").strip()

    # Parse commands
    if SET_WAIT_TIME_PATTERN.match(text):
        match = SET_WAIT_TIME_PATTERN.match(text)
        wait_time_minutes = int(match.group(1))
        await set_wait_time(app, channel, wait_time_minutes, user_id, thread_ts)
    elif SET_REPLY_MESSAGE_PATTERN.match(text):
        match = SET_REPLY_MESSAGE_PATTERN.match(text)
        message = match.group(1).strip('"').strip("'")
        await set_reply_message(app, channel, message, user_id, thread_ts)
    elif ENABLE_OPSGENIE_PATTERN.match(text):
        await set_opsgenie(app, channel, True, user_id, thread_ts)
    elif DISABLE_OPSGENIE_PATTERN.match(text):
        await set_opsgenie(app, channel, False, user_id, thread_ts)
    elif LIST_TEAMS_PATTERN.match(text):
        await list_teams(app, channel, user_id, thread_ts)
    elif ADD_EXCLUDED_TEAM_PATTERN.match(text):
        match = ADD_EXCLUDED_TEAM_PATTERN.match(text)
        team = match.group(1).strip('"').strip("'")
        await add_excluded_team(app, channel, team, user_id, thread_ts)
    elif CLEAR_EXCLUDED_TEAM_PATTERN.match(text):
        await clear_excluded_team(app, channel, user_id, thread_ts)
    elif ADD_INCLUDED_TEAM_PATTERN.match(text):
        match = ADD_INCLUDED_TEAM_PATTERN.match(text)
        team = match.group(1).strip('"').strip("'")
        await add_included_team(app, channel, team, user_id, thread_ts)
    elif CLEAR_INCLUDED_TEAM_PATTERN.match(text):
        await clear_included_team(app, channel, user_id, thread_ts)
    elif SHOW_CONFIG_PATTERN.match(text):
        await show_config(app, channel, user_id, thread_ts)
    elif HELP_PATTERN.match(text):
        await send_help_message(app, channel, user_id, thread_ts)
    else:
        await send_message(app, channel, user_id, "Huh? :thinking_face: Maybe type `help` for a list of commands.", thread_ts)

async def set_opsgenie(app: AsyncApp, channel: Channel, enabled: bool, user_id: str, thread_ts: str = None) -> None:
    channel.config['opsgenie'] = enabled
    await save_configuration()
    await send_message(app, channel, user_id, f"OpsGenie integration {'enabled' if enabled else 'disabled'}{', but not configured' if enabled and not opsgenie_configured else ''}.", thread_ts)

async def set_wait_time(app: AsyncApp, channel: Channel, wait_time_minutes: int, user_id: str, thread_ts: str = None) -> None:
    # check if number and in range 0-1440
    if not wait_time_minutes or wait_time_minutes < 0 or wait_time_minutes > 1440:
        await send_message(app, channel, user_id, "Invalid wait time. Must be a number between 0 and 1440.", thread_ts)
        return

    channel.config['wait_time'] = wait_time_minutes * 60  # Convert to seconds
    await save_configuration()
    await send_message(app, channel, user_id, f"*Wait time* set to `{wait_time_minutes}` minutes.", thread_ts)

async def set_reply_message(app: AsyncApp, channel: Channel, message: str, user_id: str, thread_ts: str = None) -> None:
    # check message
    if not message or message.strip() == "":
        await send_message(app, channel, user_id, "Invalid *reply message*. Must be non-empty.", thread_ts)
        return
    ok, error, message = await process_mentions(app, message)
    if not ok:
        await send_message(app, channel, user_id, "Invalid *reply message*: " + error + ".", thread_ts)
        return

    channel.config['reply_message'] = message
    await save_configuration()
    await send_message(app, channel, user_id, f"*Reply message* set to: {message}", thread_ts)

async def process_mentions(app: AsyncApp, message: str) -> tuple[bool, str, str]:
    # Regular expression to find @username patterns
    mention_pattern = re.compile(r'(?<![|<])@([a-z0-9-_.]+)(?!>)')
    matches = mention_pattern.findall(message)
    if matches:
        for username in matches:
            user = await get_user_by_name(app, username)
            if user.id:
                message = message.replace(f"@{username}", f"<@{user.id}>")
            else:
                log_error(f"Invalid *reply message*: username `{username}` not found")
                return False, f"{username} not found", None
    return True, None, message

async def add_excluded_team(app: AsyncApp, channel: Channel, team: str, user_id: str, thread_ts: str = None) -> None:
    await update_user_cache(app)
    if team not in team_cache:
        await send_message(app, channel, user_id, f"Unknown team: `{team}`.", thread_ts)
        return
    if team in channel.config['excluded_teams']:
        await send_message(app, channel, user_id, f"`{team}` is already excluded.", thread_ts)
        return

    if len(channel.config['included_teams']) > 0:
        await send_message(app, channel, user_id, f"Either set *included teams* or *excluded teams*, not both.", thread_ts)
        return

    channel.config['excluded_teams'].append(team)
    await save_configuration()
    await send_message(app, channel, user_id, f"Added `{team}` to *excluded teams*.", thread_ts)

async def clear_excluded_team(app: AsyncApp, channel: Channel, user_id: str, thread_ts: str = None) -> None:
    channel.config['excluded_teams'] = []
    await save_configuration()
    await send_message(app, channel, user_id, "Cleared *excluded teams*.", thread_ts)

async def add_included_team(app: AsyncApp, channel: Channel, team: str, user_id: str, thread_ts: str = None) -> None:
    await update_user_cache(app)
    if team not in team_cache:
        await send_message(app, channel, user_id, f"Unknown team: `{team}`.", thread_ts)
        return
    if team in channel.config['included_teams']:
        await send_message(app, channel, user_id, f"`{team}` is already included.", thread_ts)
        return

    if len(channel.config['excluded_teams']) > 0:
        await send_message(app, channel, user_id, f"Either set *included teams* or *excluded teams*, not both.", thread_ts)
        return

    channel.config['included_teams'].append(team)
    await save_configuration()
    await send_message(app, channel, user_id, f"Added `{team}` to *included teams*.", thread_ts)

async def clear_included_team(app: AsyncApp, channel: Channel, user_id: str, thread_ts: str = None) -> None:
    channel.config['included_teams'] = []
    await save_configuration()
    await send_message(app, channel, user_id, "Cleared *included teams*.", thread_ts)

async def list_teams(app: AsyncApp, channel: Channel, user_id: str, thread_ts: str = None) -> None:
    await update_user_cache(app)
    message = f"*Available teams*:\n{'\n'.join(sorted(team_cache, key=lambda v: v.upper()))}"
    await send_message(app, channel, user_id, message, thread_ts)

async def show_config(app: AsyncApp, channel: Channel, user_id: str, thread_ts: str = None) -> None:
    opsgenie_enabled = channel.config.get('opsgenie')
    wait_time_minutes = channel.config.get('wait_time')
    included_teams = channel.config.get('included_teams')
    excluded_teams = channel.config.get('excluded_teams')
    reply_message = channel.config.get('reply_message')
    message = (
        f"This is the configuration for #{channel.name}:\n\n"
        f"*OpsGenie integration*: {'enabled' if opsgenie_enabled else 'disabled'}"
        f"{'' if opsgenie_configured else ' (not configured)'}\n\n"
        f"*Wait time*: `{wait_time_minutes}` minutes\n\n"
        f"*Included teams*: {' '.join(f'`{team}`' for team in included_teams) if included_teams else '<None>'}\n\n"
        f"*Excluded teams*: {' '.join(f'`{team}`' for team in excluded_teams) if excluded_teams else '<None>'}\n\n"
        f"*Reply message*:\n{reply_message}"
    )
    await send_message(app, channel, user_id, message, thread_ts)

async def send_message(app: AsyncApp, channel: Channel, user_id: str, text: str, thread_ts: str = None) -> None:
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
                user=user_id,
                text=text,
                mrkdwn=True  # Enable Markdown formatting
            )
    except SlackApiError as e:
        log_error(f"Failed to send message in channel #{channel.name} for user @{user_id}: {e}")

async def send_help_message(app: AsyncApp, channel: Channel, user_id: str, thread_ts: str = None) -> None:
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
    await send_message(app, channel, user_id, help_text, thread_ts)

async def schedule_reply(app: AsyncApp, opsgenie_token: str, channel: Channel, user: User, text: str, ts: str) -> None:
    opsgenie_enabled = channel.config.get('opsgenie')
    wait_time = channel.config.get('wait_time')
    reply_message = channel.config('reply_message')
    try:
        await asyncio.sleep(wait_time)
        await app.client.chat_postMessage(
            channel=channel.id,
            thread_ts=ts,
            text=reply_message,
            mrkdwn=True
        )
        if opsgenie_configured and opsgenie_enabled:
            await post_opsgenie_alert(opsgenie_token, channel, user, text, ts)
    except asyncio.CancelledError:
        pass  # Task was cancelled because a reaction or reply was detected
    except SlackApiError as e:
        log_error(f"Failed to send scheduled reply: {e}")

async def post_opsgenie_alert(opsgenie_token: str, channel: Channel, user: User, text: str, ts: str) -> None:
    user_name = user.real_name if user.real_name else user.name
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
                "alias": f"hutbot: {user_name} in #{channel.name} at {ts}",
                "description": f"#{channel.name}: {user_name} at {ts}: {text}",
                "tags": ["Hutbot"],
                "details": {
                    "channel": f"#{channel.name}",
                    "sender": user_name,
                    "bot": "hutbot",
                },
                "priority": "P4",
            }
            async with session.post(url, headers=headers, data=json.dumps(data)) as response:
                if response.status != 202:
                    log_error(f"Failed to send alert: {response.status}")
                else:
                    log(f"Successfully sent OpsGenie alert for {user_name} in #{channel.name} at {ts} with status code {response.status}")
        except Exception as e:
            log_error(f"Exception while sending alert: {e}")

async def handle_thread_response(app: AsyncApp, event: dict, channel: Channel, user_id: str, thread_ts: str):
    key = (channel.name, thread_ts)
    if key in scheduled_messages and scheduled_messages[key].user_id != user_id:
        message_user_id = scheduled_messages[key].user_id
        message_user = await get_user_by_id(app, message_user_id)
        reply_user = await get_user_by_id(app, user_id)
        log(f"Thread reply by user {reply_user.name} detected. Cancelling reminder for message {thread_ts} in channel #{channel.name} by user @{message_user.name}")
        scheduled_messages[key].task.cancel()
        del scheduled_messages[key]

async def handle_channel_message(app: AsyncApp, opsgenie_token: str, event: dict, channel: Channel, user_id: str, text: str, ts: str):
    user = await get_user_by_id(app, user_id)
    included_teams = channel.config.get('included_teams')
    excluded_teams = channel.config.get('excluded_teams')
    if len(included_teams) > 0 and user.team not in included_teams:
        log(f"Message from user @{user.name} in #{channel.name} will be ignored because team {user.team} is not included.")
        return
    if len(excluded_teams) > 0 and user.team in excluded_teams:
        log(f"Message from user @{user.name} in #{channel.name} will be ignored because team {user.team} is excluded.")
        return

    log(f"Scheduling reminder for message {ts} in channel #{channel.name} by user @{user.name}")
    task = asyncio.create_task(schedule_reply(app, opsgenie_token, channel, user, text, ts))
    scheduled_messages[(channel.id, ts)] = ScheduledReply(task, user_id)

async def handle_message_deletion(app: AsyncApp, event: str, channel: Channel, previous_message_user_id: str, previous_message_ts: str):
    if previous_message_user_id == bot_user_id:
        log(f"Ignoring message deletion by bot from channel #{channel.name}.")
        return

    # Cancel the scheduled task if it exists
    key = (channel.id, previous_message_ts)
    if key in scheduled_messages:
        previous_message_user = await get_user_by_id(app, previous_message_user_id)
        log(f"Message deleted. Cancelling reminder for message {previous_message_ts} in channel #{channel.name} by user @{previous_message_user.name}")
        scheduled_messages[key].task.cancel()
        del scheduled_messages[key]

def register_app_handlers(app: AsyncApp, opsgenie_token: str = None) -> None:

    @app.event("message")
    async def handle_message_events(body, logger):
        event = body.get('event', {})
        subtype = event.get('subtype')
        previous_message = event.get('previous_message')
        channel_id = event.get('channel')
        user_id = event.get('user')
        ts = event.get('ts')
        thread_ts = event.get('thread_ts')
        text = event.get('text', '')

        channel = await get_channel_by_id(app, channel_id)

        # Ignore messages from the bot itself
        if user_id == bot_user_id:
            log(f"Ignoring message from the bot from channel #{channel.name}.")
            return

        if subtype == 'message_deleted' and previous_message:
            # deleted message
            await handle_message_deletion(app, event, channel, previous_message.get('user'), previous_message.get('ts'))
        elif user_id and is_command(text):
            # command
            await handle_command(app, text, channel, user_id, ts)
        elif user_id and thread_ts:
            # thread
            await handle_thread_response(app, event, channel, user_id, thread_ts)
        elif user_id and ts:
            # channel message
            await handle_channel_message(app, opsgenie_token, event, channel, user_id, text, ts)

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
            channel = await get_channel_by_id(app, channel_id)
            message_user_id = scheduled_messages[key].user_id
            message_user = await get_user_by_id(app, message_user_id)
            reaction_user = await get_user_by_id(app, user_id)
            log(f"Reaction added by user {reaction_user.name}. Cancelling reminder for message {ts} in channel #{channel.name} by user @{message_user.name}")
            scheduled_messages[key].task.cancel()
            del scheduled_messages[key]

    @app.command("/hutbot")
    async def handle_config_command(ack, body, logger):
        await ack()
        text = body.get('text', '')
        channel_id = body.get('channel_id')
        user_id = body.get('user_id')

        channel = await get_channel_by_id(app, channel_id)
        await handle_command(app, text, channel, user_id)

async def send_heartbeat(opsgenie_token: str, opsgenie_heartbeat_name: str) -> None:
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

async def main() -> None:
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
