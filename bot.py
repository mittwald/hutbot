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
Usergroup = collections.namedtuple('Usergroup', ['id', 'handle', 'name'])
Channel = collections.namedtuple('Channel', ['id', 'name', 'config'])


DEFAULT_CONFIG = {
    "wait_time": 30 * 60,
    "reply_message": "Anybody?",
    "opsgenie": False,
    "debug": False,
    "include_bots": False,
    "excluded_teams": [],
    "included_teams": [],
}

EMPLOYEE_CACHE_FILE_NAME = 'employees.json'
CONFIG_FILE_NAME = 'bot.json'  # Path to the configuration file
TEAM_UNKNOWN = '<unknown>'

IGNORED_MESSAGE_SUBTYPES = set(['channel_join',
                                'channel_leave',
                                'channel_archived',
                                'channel_unarchived',
                                'channel_convert_to_private',
                                'channel_convert_to_public',
                                'channel_name',
                                'channel_posting_permissions',
                                'channel_purpose',
                                'channel_topic' ])

channel_config = {}
scheduled_messages = {}

user_id_cache = {}
id_user_cache = {}
usergroup_id_cache = {}
id_usergroup_cache = {}
team_cache = set()

bot_user_id = None

opsgenie_configured = False

MENTION_PATTERN = re.compile(r'(?<![|<])@([a-z0-9-_.]+)(?!>)')
ID_PATTERN = re.compile(r'<([#@!][a-zA-Z0-9^]+)([|]([^>]*))?>')

# Regex patterns for command parsing
HELP_PATTERN = re.compile(r'help', re.IGNORECASE)
SET_WAIT_TIME_PATTERN = re.compile(r'^(set\s+)?wait([_ -]?time)?\s+(?P<wait_time>.+)$', re.IGNORECASE)
SET_REPLY_MESSAGE_PATTERN = re.compile(r'^(set\s+)?(message|reply)\s+(?P<message>.+)$', re.IGNORECASE)
ADD_EXCLUDED_TEAM_PATTERN = re.compile(r'^(add\s+)?excluded?([_ -]?teams?)?\s+(?P<team>.+)$', re.IGNORECASE)
CLEAR_EXCLUDED_TEAM_PATTERN = re.compile(r'^clear\s+excluded?([_ -]?teams?)?$', re.IGNORECASE)
ADD_INCLUDED_TEAM_PATTERN = re.compile(r'^(add\s+)?included?([_ -]?teams?)?\s+(?P<team>.+)$', re.IGNORECASE)
CLEAR_INCLUDED_TEAM_PATTERN = re.compile(r'^clear\s+included?([_ -]?teams?)?$', re.IGNORECASE)
LIST_TEAMS_PATTERN = re.compile(r'^(list\s+)?teams?$', re.IGNORECASE)
EMPLOYEE_TEAM_PATTERN = re.compile(r'^team(\s+of)?\s+(?P<user>.+)$', re.IGNORECASE)
ENABLE_OPSGENIE_PATTERN = re.compile(r'^enable\s+(opsgenie|alerts?)$', re.IGNORECASE)
DISABLE_OPSGENIE_PATTERN = re.compile(r'^disable\s+(opsgenie|alerts?)$', re.IGNORECASE)
ENABLE_BOTS_PATTERN = re.compile(r'^(enable|include|set)?\s+bots?$', re.IGNORECASE)
DISABLE_BOTS_PATTERN = re.compile(r'^(disable|exclude)\s+bots?$', re.IGNORECASE)
SHOW_CONFIG_PATTERN = re.compile(r'^(show\s+)?config(uration)?$', re.IGNORECASE)

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
    __log(sys.stdout, 'INFO', *args)

def log_warning(*args: object) -> None:
    __log(sys.stderr, 'WARN', *args)

def log_error(*args: object) -> None:
    __log(sys.stderr, 'ERROR', *args)

def log_debug(channel: Channel | None, *args: object) -> None:
    if channel and channel.config.get('debug'):
        __log(sys.stderr, 'DEBUG', *args)

def __log(file, prefix, *args: object) -> None:
    parts = []
    for arg in args:
        part = str(arg)
        if isinstance(arg, BaseException):
            error_type = type(arg).__name__
            error_message = str(arg)
            part = f"{error_type}{': ' + error_message if error_message else ''}"
        parts.append(part)
    message = ' '.join(parts)
    prefix = f"{datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')} {prefix}:"
    print(prefix, message, flush=True, file=file)

def normalize_id(id: str) -> str: return id.lower().strip()

def normalize_user_name(user_name: str) -> str: return user_name.lower().strip().replace('.', '')

def normalize_real_name(real_name: str) -> str:
    normalized = real_name.lower().strip().replace(' ', '_').replace('.', '_')
    # replace non latin characters
    normalized = unidecode(normalized)
    return normalized

def normalize_real_name_with_diagraphs(real_name: str) -> str:
    # don't ask, you wouldn't be able to grasp the extend...
    return normalize_real_name(real_name.lower().replace('ae', 'ä').replace('oe', 'ö').replace('ue', 'ü'))

async def apply_defaults(app: AsyncApp, config: dict) -> dict:
    for channel_id, channel_config in config.items():
        channel_config['name'] = await get_channel_name(app, channel_id)
        for key, value in DEFAULT_CONFIG.items():
            if key not in channel_config:
                channel_config[key] = value
    return config

async def load_configuration(app: AsyncApp) -> None:
    global channel_config
    try:
        async with aiofiles.open(CONFIG_FILE_NAME, 'r') as f:
            content = await f.read()
            channel_config = await apply_defaults(app, json.loads(content))
            log("Configuration loaded from disk.")
    except FileNotFoundError:
        log_warning("No configuration file found. Using default settings.")
        channel_config = {}
    except json.JSONDecodeError as e:
        log_error(f"Failed to decode JSON configuration:", e)
        channel_config = {}

async def save_configuration() -> None:
    try:
        async with aiofiles.open(CONFIG_FILE_NAME, 'w') as f:
            content = json.dumps(channel_config, indent=2)
            await f.write(content)
    except Exception as e:
        log_error("Failed to save configuration:", e)

def generate_employee_list(users: list) -> dict:
    employees = {}
    for user in users:
        id = normalize_id(user.get('ad_name', ''))
        is_deleted = user.get('is_deleted', False)
        if not is_deleted and len(id) > 0:
            employees[id] = user
    return employees

def load_employee_mappings() -> dict:
    result = {}
    employee_mappings = os.environ.get("EMPLOYEE_LIST_MAPPINGS", "").strip()
    if employee_mappings:
        log(f"Attempting to load employee mappings from environment variable.")
        mappings = employee_mappings.split(',')
        for mapping in mappings:
            items = mapping.split('=')
            if items and len(items) == 2 and len(items[0]) > 0 and len(items[1]) > 0:
                key = normalize_id(items[0])
                value = normalize_id(items[1])
                if key in result:
                    log_warning(f"Failed to parse employee mapping '{key}' is already mapped, skipping")
                else:
                    result[key] = value
            else:
                log_warning(f"Failed to parse employee mapping '{mapping}', skipping")

        log(f"{len(result)} employee mappings loaded from environment variable.")
    return result

async def load_employees_from_disk() -> dict:
    log(f"Attempting to load employees from disk.")
    try:
        async with aiofiles.open(EMPLOYEE_CACHE_FILE_NAME, 'r') as f:
            content = await f.read()
            users = json.loads(content)
            employees = generate_employee_list(users)
            log(f"{len(employees)} employees loaded from disk.")
            return employees
    except FileNotFoundError:
        log_error("No employee file found. Will not be able to do team mapping.")
    except json.JSONDecodeError as e:
        log_error(f"Failed to decode employee JSON:", e, "Will not be able to do team mapping.")
    return {}

async def load_employees() -> dict:
    username = os.environ.get("EMPLOYEE_LIST_USERNAME")
    password = os.environ.get("EMPLOYEE_LIST_PASSWORD")
    if not username or not password:
        return await load_employees_from_disk()

    employee_auth_url = 'https://identity.prod.mittwald.systems/authenticate'
    employee_url = 'https://lb.mittwald.it/api/users'

    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            auth_payload = {
                "username": username,
                "password": password,
                "providers": ["service"]
            }

            async with session.post(employee_auth_url, json=auth_payload) as auth_response:
                if auth_response.status != 200:
                    log_error(f"Failed to authenticate to retrieve employees: {await auth_response.text()}")
                    return await load_employees_from_disk()

                auth_data = await auth_response.json()
                token = auth_data.get("token")

                if not token:
                    log_error(f"Failed to authenticate to retrieve employees, no token received: {json.dumps(auth_data)}")
                    return await load_employees_from_disk()

            headers = {"jwt": token}
            async with session.get(employee_url, headers=headers) as users_response:
                if users_response.status != 200:
                    log_error(f"Failed to fetch employees: {await users_response.text()}")
                    return await load_employees_from_disk()

                users = await users_response.json()
                employees = generate_employee_list(users)
                log(f"{len(employees)} employees retrieved from {employee_url}.")
                return employees
    except Exception as e:
        log_error(f"Failed to retrieve employees from {employee_url}:", e)
        return await load_employees_from_disk()

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
        log_error(f"Failed to get channel name for {channel_id}", e)

    return channel_id

async def get_message_permalink(app: AsyncApp, channel: Channel, ts: str) -> str:
    permalink = ""
    try:
        response = await app.client.chat_getPermalink(
            channel=channel.id,
            message_ts=ts
        )

        permalink = response.get('permalink', '')
    except SlackApiError as e:
        log_error(f"Failed to get permalink for message {ts} in channel #{channel.name}:", e)

    return permalink

async def update_usergroup_cache(app: AsyncApp) -> None:
  global usergroup_id_cache, id_usergroup_cache
  if not usergroup_id_cache or not id_usergroup_cache:
      try:
          response = await app.client.usergroups_list()
          usergroups = response['usergroups']
          for usergroup in usergroups:
              if usergroup.get('date_deleted', 0) == 0:
                  usergroup_id = usergroup.get('id', '')
                  usergroup_handle = usergroup.get('handle', '')
                  usergroup_name = usergroup.get('name', '')
                  usergroup_id_cache[usergroup_handle] = Usergroup(id=usergroup_id, handle=usergroup_handle, name=usergroup_name)
                  id_usergroup_cache[usergroup_id] = Usergroup(id=usergroup_id, handle=usergroup_handle, name=usergroup_name)
      except SlackApiError as e:
          log_error(f"Failed to fetch usergroup list:", e)

async def update_user_cache(app: AsyncApp) -> None:
    global user_id_cache, id_user_cache
    if not user_id_cache or not id_user_cache:
        employees = await load_employees()
        mappings = load_employee_mappings()
        try:
            response = await app.client.users_list()
            users = response['members']
            for user in users:
                if not user.get('deleted') and \
                   not user.get('is_bot', False) and \
                   not user.get('is_restricted', False) and \
                   user.get('id', '') != 'USLACKBOT':
                    user_id = user.get('id', '')
                    user_name = normalize_id(user.get('name', ''))
                    if user_name in mappings:
                        log(f"Applying employee mapping: {user_name} -> {mappings[user_name]}")
                        user_name = mappings[user_name]
                    user_name_normalized = normalize_user_name(user_name)
                    user_email = normalize_id(user.get('profile', {}).get('email', ''))
                    user_email_alias = normalize_id(user_email.split('@')[0])
                    user_email_alias_normalized = normalize_user_name(user_email_alias)
                    user_real_name = user.get('real_name', '').strip()
                    user_real_name_normalized = normalize_real_name(user_real_name)
                    user_team = TEAM_UNKNOWN

                    if len(employees) > 0:
                        # Try different variations of the username to find a match in employees
                        user_key_candidates = [
                            user_name,
                            user_name_normalized,
                            user_email_alias,
                            user_email_alias_normalized
                        ]
                        user_key = next((k for k in user_key_candidates if k in employees), None)

                        if not user_key:
                            # loop through all employees and try to match some form of the real name
                            for employee_key, employee in employees.items():
                                employee_real_name = employee.get('fullname', '').strip()
                                employee_real_name_normalized = normalize_real_name(employee_real_name)
                                employee_real_name_super_normalized = normalize_real_name_with_diagraphs(employee_real_name)
                                user_real_name_super_normalized = normalize_real_name_with_diagraphs(user_real_name)
                                if employee_real_name_normalized == user_real_name_normalized or \
                                employee_real_name_super_normalized == user_real_name_normalized or \
                                employee_real_name_super_normalized == user_real_name_super_normalized:
                                    user_key = employee_key
                                    # finally!
                                    break
                            if not user_key:
                                user_json = json.dumps(user)
                                if len(user_json) > 100:
                                    user_json = user_json[:97] + '...'
                                log_warning(f"Failed to map user @{user_name} to a employee: {user_json}")

                        if user_key:
                            user_team = employees[user_key].get('group', '').strip()

                    user_id_cache[user_name] = User(id=user_id, name=user_name, team=user_team, real_name=user_real_name)
                    id_user_cache[user_id] = User(id=user_id, name=user_name, team=user_team, real_name=user_real_name)
                    if user_team not in team_cache:
                        team_cache.add(user_team)
        except SlackApiError as e:
            log_error(f"Failed to fetch user list:", e)

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

async def get_usergroup_by_id(app: AsyncApp, id: str) -> Usergroup:
    await update_usergroup_cache(app)
    usergroup = id_usergroup_cache.get(id, None)
    if not usergroup:
        usergroup = Usergroup(id=id, handle=id, name=id)
    return usergroup

async def get_usergroup_by_handle(app: AsyncApp, handle: str) -> Usergroup:
    await update_usergroup_cache(app)
    usergroup = usergroup_id_cache.get(handle, None)
    if not usergroup:
        usergroup = Usergroup(id=None, handle=handle, name=handle)
    return usergroup

def is_command(text: str) -> bool:
    return f"<@{bot_user_id}>" in text

async def process_command(app: AsyncApp, text: str, channel: Channel, user: User, thread_ts: str = "") -> None:
    text = text.replace(f"<@{bot_user_id}>", "").strip()

    log_debug(channel, f"Received command for channel #{channel.name}: {text}")

    # Parse commands
    if (match := SET_WAIT_TIME_PATTERN.match(text)):
        wait_time_minutes = int(match.group("wait_time").strip('"').strip("'"))
        await set_wait_time(app, channel, wait_time_minutes, user, thread_ts)
    elif (match := SET_REPLY_MESSAGE_PATTERN.match(text)):
        message = match.group("message").strip('"').strip("'")
        await set_reply_message(app, channel, message, user, thread_ts)
    elif ENABLE_OPSGENIE_PATTERN.match(text):
        await set_opsgenie(app, channel, True, user, thread_ts)
    elif DISABLE_OPSGENIE_PATTERN.match(text):
        await set_opsgenie(app, channel, False, user, thread_ts)
    elif ENABLE_BOTS_PATTERN.match(text):
        await set_bots(app, channel, True, user, thread_ts)
    elif DISABLE_BOTS_PATTERN.match(text):
        await set_bots(app, channel, False, user, thread_ts)
    elif LIST_TEAMS_PATTERN.match(text):
        await list_teams(app, channel, user, thread_ts)
    elif (match := EMPLOYEE_TEAM_PATTERN.match(text)):
        username = match.group("user").strip('"').strip("'")
        await get_team_of(app, channel, username, user, thread_ts)
    elif (match := ADD_EXCLUDED_TEAM_PATTERN.match(text)):
        team = match.group("team").strip('"').strip("'")
        await add_excluded_team(app, channel, team, user, thread_ts)
    elif CLEAR_EXCLUDED_TEAM_PATTERN.match(text):
        await clear_excluded_team(app, channel, user, thread_ts)
    elif (match := ADD_INCLUDED_TEAM_PATTERN.match(text)):
        team = match.group("team").strip('"').strip("'")
        await add_included_team(app, channel, team, user, thread_ts)
    elif CLEAR_INCLUDED_TEAM_PATTERN.match(text):
        await clear_included_team(app, channel, user, thread_ts)
    elif SHOW_CONFIG_PATTERN.match(text):
        await show_config(app, channel, user, thread_ts)
    elif HELP_PATTERN.match(text):
        await send_help_message(app, channel, user, thread_ts)
    else:
        await send_message(app, channel, user, "Huh? :thinking_face: Maybe type `/hutbot help` for a list of commands.", thread_ts)

async def set_bots(app: AsyncApp, channel: Channel, enabled: bool, user: User, thread_ts: str = "") -> None:
    channel.config['include_bots'] = enabled
    await save_configuration()
    await send_message(app, channel, user, f"Include bots {'enabled' if enabled else 'disabled'}.", thread_ts)

async def set_opsgenie(app: AsyncApp, channel: Channel, enabled: bool, user: User, thread_ts: str = "") -> None:
    channel.config['opsgenie'] = enabled
    await save_configuration()
    await send_message(app, channel, user, f"OpsGenie integration {'enabled' if enabled else 'disabled'}{', but not configured' if enabled and not opsgenie_configured else ''}.", thread_ts)

async def set_wait_time(app: AsyncApp, channel: Channel, wait_time_minutes: int, user: User, thread_ts: str = "") -> None:
    # check if number and in range 0-1440
    if not wait_time_minutes or wait_time_minutes < 0 or wait_time_minutes > 1440:
        await send_message(app, channel, user, "Invalid wait time. Must be a number between 0 and 1440.", thread_ts)
        return

    channel.config['wait_time'] = wait_time_minutes * 60  # Convert to seconds
    log_debug(channel, f"Wait time for #{channel.name} set to {wait_time_minutes} minutes")
    await save_configuration()
    await send_message(app, channel, user, f"*Wait time* set to `{wait_time_minutes}` minutes.", thread_ts)

async def set_reply_message(app: AsyncApp, channel: Channel, message: str, user: User, thread_ts: str = "") -> None:
    # check message
    if not message or message.strip() == "":
        await send_message(app, channel, user, "Invalid *reply message*. Must be non-empty.", thread_ts)
        return
    ok, error, message = await process_mentions(app, message)
    if not ok:
        await send_message(app, channel, user, "Invalid *reply message*: " + error + ".", thread_ts)
        return

    channel.config['reply_message'] = message
    await save_configuration()
    await send_message(app, channel, user, f"*Reply message* set to: {message}", thread_ts)

async def process_mentions(app: AsyncApp, message: str) -> tuple[bool, str, str]:
    # Regular expression to find @username patterns
    matches = MENTION_PATTERN.findall(message)
    if matches:
        for user_match in matches:
            user = await get_user_by_name(app, user_match)
            if user.id:
                message = message.replace(f"@{user_match}", f"<@{user.id}>")
            else:
                log_error(f"Invalid *reply message*: username `{user_match}` not found")
                return False, f"{user_match} not found", ""
    return True, "", message

async def add_excluded_team(app: AsyncApp, channel: Channel, team: str, user: User, thread_ts: str = "") -> None:
    await update_user_cache(app)
    if team not in team_cache:
        await send_message(app, channel, user, f"Unknown team: `{team}`.", thread_ts)
        return
    if team in channel.config['excluded_teams']:
        await send_message(app, channel, user, f"`{team}` is already excluded.", thread_ts)
        return

    if len(channel.config['included_teams']) > 0:
        await send_message(app, channel, user, f"Either set *included teams* or *excluded teams*, not both.", thread_ts)
        return

    channel.config['excluded_teams'].append(team)
    await save_configuration()
    await send_message(app, channel, user, f"Added `{team}` to *excluded teams*.", thread_ts)

async def clear_excluded_team(app: AsyncApp, channel: Channel, user: User, thread_ts: str = "") -> None:
    channel.config['excluded_teams'] = []
    await save_configuration()
    await send_message(app, channel, user, "Cleared *excluded teams*.", thread_ts)

async def add_included_team(app: AsyncApp, channel: Channel, team: str, user: User, thread_ts: str = "") -> None:
    await update_user_cache(app)
    if team not in team_cache:
        await send_message(app, channel, user, f"Unknown team: `{team}`.", thread_ts)
        return
    if team in channel.config['included_teams']:
        await send_message(app, channel, user, f"`{team}` is already included.", thread_ts)
        return

    if len(channel.config['excluded_teams']) > 0:
        await send_message(app, channel, user, f"Either set *included teams* or *excluded teams*, not both.", thread_ts)
        return

    channel.config['included_teams'].append(team)
    await save_configuration()
    await send_message(app, channel, user, f"Added `{team}` to *included teams*.", thread_ts)

async def clear_included_team(app: AsyncApp, channel: Channel, user: User, thread_ts: str = "") -> None:
    channel.config['included_teams'] = []
    await save_configuration()
    await send_message(app, channel, user, "Cleared *included teams*.", thread_ts)

async def list_teams(app: AsyncApp, channel: Channel, user: User, thread_ts: str = "") -> None:
    await update_user_cache(app)
    message = f"*Available teams*:\n{'\n'.join(sorted(team_cache, key=lambda v: v.upper()))}"
    await send_message(app, channel, user, message, thread_ts)

async def get_team_of(app: AsyncApp, channel: Channel, username: str, user: User, thread_ts: str = "") -> None:
    message = None
    for match in ID_PATTERN.finditer(username):
        full_match = match.group(0)
        log_debug(channel, f"Found ID match: {full_match}...")
        id = match.group(1)
        if id and id[0] == '@':
            user_id = id[1:]
            log_debug(channel, f"Looking up user with ID {user_id}...")
            u = await get_user_by_id(app, user_id)
            if u.id:
                log_debug(channel, f"Found user {u}")
                msg = f"*{u.real_name}* (<@{u.id}>): `{u.team}`"
                if message is None:
                    message = msg
                else:
                    message += f"\n{msg}"
            else:
                log_error(f"Invalid request: username `{full_match}` not found")
    if message:
        await send_message(app, channel, user, message, thread_ts)
    else:
        await send_message(app, channel, user, f"Unknown user: `{username}`.", thread_ts)

async def show_config(app: AsyncApp, channel: Channel, user: User, thread_ts: str = "") -> None:
    opsgenie_enabled = channel.config.get('opsgenie')
    wait_time_minutes = channel.config.get('wait_time') // 60
    included_teams = channel.config.get('included_teams')
    excluded_teams = channel.config.get('excluded_teams')
    include_bots = channel.config.get('include_bots')
    reply_message = channel.config.get('reply_message')
    message = (
        f"This is the configuration for #{channel.name}:\n\n"
        f"*OpsGenie integration*: {'enabled' if opsgenie_enabled else 'disabled'}"
        f"{'' if opsgenie_configured else ' (not configured)'}\n\n"
        f"*Wait time*: `{wait_time_minutes}` minutes\n\n"
        f"*Included teams*: {' '.join(f'`{team}`' for team in included_teams) if included_teams else '<None>'}\n\n"
        f"*Excluded teams*: {' '.join(f'`{team}`' for team in excluded_teams) if excluded_teams else '<None>'}\n\n"
        f"*Include bots*: {'enabled' if include_bots else 'disabled'}\n\n"
        f"*Reply message*:\n{reply_message}"
    )
    await send_message(app, channel, user, message, thread_ts)

async def send_message(app: AsyncApp, channel: Channel, user: User, text: str, thread_ts: str = "") -> None:
    log_debug(channel, f"Attempting to send message to #{channel.name}, user @{user.name}: {text.replace('\n', '\\n')}")
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

async def send_help_message(app: AsyncApp, channel: Channel, user: User, thread_ts: str = "") -> None:
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
        "*Team of User:*\n"
        "```/hutbot team of [user]\n"
        "@Hutbot team of [user]```\n"
        "Lists the team of a user. Replace `[user]` with @<user>.\n\n"
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
        "*Include Bot Messages:*\n"
        "```/hutbot enable bots\n"
        "@Hutbot enable bots```\n"
        "Also responds to messages from bots.\n\n"
        "*Exclude Bot Messages:*\n"
        "```/hutbot disable bots\n"
        "@Hutbot disable bots```\n"
        "Don't respond to messages from bots.\n\n"
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
    await send_message(app, channel, user, help_text, thread_ts)

async def schedule_reply(app: AsyncApp, opsgenie_token: str, channel: Channel, user: User, text: str, ts: str) -> None:
    opsgenie_enabled = channel.config.get('opsgenie')
    wait_time = channel.config.get('wait_time')
    reply_message = channel.config.get('reply_message')
    log(f"Scheduling reply for message {ts} in channel #{channel.name}, user @{user.name}, wait time {wait_time // 60} mins, opsgenie {'enabled' if opsgenie_enabled else 'disabled'}{', but not configured' if opsgenie_enabled and not opsgenie_configured else ''}")
    try:
        await asyncio.sleep(wait_time)
        await send_message(app, channel, user, reply_message, ts)
        if opsgenie_configured and opsgenie_enabled:
            log(f"Attempting to send OpsGenie alert for message {ts} in channel #{channel.name}, user @{user.name}...")
            permalink = await get_message_permalink(app, channel, ts)
            await post_opsgenie_alert(app, opsgenie_token, channel, user, text, ts, permalink)
    except asyncio.CancelledError as e:
        log(f"Cancelling scheduled reply for message {ts} in channel #{channel.name}, user @{user.name}:", e)
    except Exception as e:
        log_error(f"Failed to send scheduled reply for message {ts} in channel #{channel.name}, user @{user.name}:", e)

async def replace_ids(app: AsyncApp, channel: Channel | None, text: str) -> str:
    for match in ID_PATTERN.finditer(text):
        full_match = match.group(0)
        log_debug(channel, f"Found ID match: {full_match}...")
        id = match.group(1)
        handled = False
        if id and id[0] == '@':
            user_id = id[1:]
            log_debug(channel, f"Looking up user with ID {user_id}...")
            user = await get_user_by_id(app, user_id)
            if user.id:
                log_debug(channel, f"Found user {user}")
                text = text.replace(full_match, user.real_name)
                handled = True
        elif id and id[0] == '#':
            ch_id = id[1:]
            log_debug(channel, f"Looking up channel with ID {ch_id}...")
            ch = await get_channel_by_id(app, ch_id)
            if ch.id:
                log_debug(channel, f"Found channel {ch}")
                text = text.replace(full_match, f"#{ch.name}")
                handled = True
        elif id and id.startswith('!subteam^'):
            ug_id = id[9:]
            log_debug(channel, f"Looking up usergroup with ID {ug_id}...")
            ug = await get_usergroup_by_id(app, ug_id)
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

    # reduce duplicate spaces ands trim
    text = re.sub(r'\s{2,}', ' ', text).strip()

    return text

async def post_opsgenie_alert(app: AsyncApp, opsgenie_token: str, channel: Channel, user: User, text: str, ts: str, permalink: str) -> None:
    log_debug(channel, f"> {text.replace('\n', '\\n')}")
    text = await clean_slack_text(app, channel, text)
    log_debug(channel, f"< {text}")
    user_name = user.real_name if user.real_name else user.name
    url = 'https://api.opsgenie.com/v2/alerts'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'GenieKey {opsgenie_token}'
    }
    async with aiohttp.ClientSession() as session:
        try:
            data = {
                "message": f"#{channel.name}: {text}",
                "alias": f"hutbot: {user_name} in #{channel.name} {ts}",
                "description": f"{user_name} in #{channel.name}: {text}",
                "tags": ["Hutbot"],
                "details": {
                    "channel": f"#{channel.name}",
                    "sender": user_name,
                    "bot": "hutbot",
                    "permalink": permalink,
                },
                "priority": "P4",
            }
            async with session.post(url, headers=headers, data=json.dumps(data)) as response:
                if response.status != 202:
                    log_error(f"Failed to send alert for message {ts} in channel #{channel.name}, user @{user.name}: {response.status}")
                else:
                    log(f"Successfully sent OpsGenie alert for message {ts} in channel #{channel.name}, user @{user.name} with status code {response.status}")
        except Exception as e:
            log_error(f"Failed to send alert for message {ts} in channel #{channel.name}, user @{user.name}:", e)

async def route_message(app: AsyncApp, opsgenie_token: str, event: dict) -> None:
    subtype = event.get('subtype')
    previous_message = event.get('previous_message', {})
    channel_id = event.get('channel', '')
    user_id = event.get('user', '')
    bot_id = event.get('bot_id', '')
    ts = event.get('ts', '')
    thread_ts = event.get('thread_ts', '')
    text = event.get('text', '')

    channel = await get_channel_by_id(app, channel_id)
    log_debug(channel, f"Received message event from #{channel.name}: {json.dumps(event)}")

    # Ignore messages from the bot itself
    if user_id == bot_user_id or bot_id == bot_user_id:
        log(f"Ignoring message from the bot from channel #{channel.name}.")
        return

    if subtype in IGNORED_MESSAGE_SUBTYPES:
        log(f"Ignoring message with subtype '{subtype}' for channel #{channel.name}.")
        return

    user = None
    if user_id:
        user = await get_user_by_id(app, user_id)
    elif bot_id and channel.config.get('include_bots', False):
        user = await get_user_by_id(app, bot_id)

    if subtype == 'message_deleted' and previous_message:
        # deleted message
        previous_user = await get_user_by_id(app, previous_message.get('user'))
        await handle_message_deletion(app, channel, previous_user, previous_message.get('ts'))
    elif user and is_command(text):
        # command
        await process_command(app, text, channel, user, ts)
    elif user and thread_ts:
        # thread
        await handle_thread_response(app, channel, user, thread_ts)
    elif user and ts:
        # channel message
        await handle_channel_message(app, opsgenie_token, channel, user, text, ts)

async def handle_thread_response(app: AsyncApp, channel: Channel, reply_user: User, thread_ts: str):
    key = (channel.id, thread_ts)
    if key in scheduled_messages and scheduled_messages[key].user_id != reply_user.id:
        message_user_id = scheduled_messages[key].user_id
        message_user = await get_user_by_id(app, message_user_id)
        log(f"Thread reply by user @{reply_user.name} detected. Cancelling reminder for message {thread_ts} in channel #{channel.name}, user @{message_user.name}")
        scheduled_messages[key].task.cancel()
        del scheduled_messages[key]

async def handle_channel_message(app: AsyncApp, opsgenie_token: str, channel: Channel, user: User, text: str, ts: str):
    included_teams = channel.config.get('included_teams')
    excluded_teams = channel.config.get('excluded_teams')
    if len(included_teams) > 0 and user.team not in included_teams:
        log(f"Message from user @{user.name} in #{channel.name} will be ignored because team '{user.team}' is not included.")
        return
    if len(excluded_teams) > 0 and user.team in excluded_teams:
        log(f"Message from user @{user.name} in #{channel.name} will be ignored because team '{user.team}' is excluded.")
        return

    task = asyncio.create_task(schedule_reply(app, opsgenie_token, channel, user, text, ts))
    scheduled_messages[(channel.id, ts)] = ScheduledReply(task, user.id)

async def handle_reaction_added(app: AsyncApp, event):
    item = event.get('item', {})
    channel_id = item.get('channel', '')
    user_id = event.get('user', '')
    ts = item.get('ts')

    # Cancel the scheduled task if it exists
    key = (channel_id, ts)
    if key in scheduled_messages and scheduled_messages[key].user_id != user_id:
        channel = await get_channel_by_id(app, channel_id)
        message_user_id = scheduled_messages[key].user_id
        message_user = await get_user_by_id(app, message_user_id)
        reaction_user = await get_user_by_id(app, user_id)
        log(f"Reaction added by user @{reaction_user.name}. Cancelling reminder for message {ts} in channel #{channel.name}, user @{message_user.name}")
        scheduled_messages[key].task.cancel()
        del scheduled_messages[key]

async def handle_message_deletion(app: AsyncApp, channel: Channel, previous_message_user: User, previous_message_ts: str):
    if previous_message_user.id == bot_user_id:
        log(f"Ignoring message deletion by bot from channel #{channel.name}.")
        return

    # Cancel the scheduled task if it exists
    key = (channel.id, previous_message_ts)
    if key in scheduled_messages:
        log(f"Message deleted. Cancelling reply for message {previous_message_ts} in channel #{channel.name}, user @{previous_message_user.name}")
        scheduled_messages[key].task.cancel()
        del scheduled_messages[key]

async def handle_command_event(app: AsyncApp, command: dict):
    text = command.get('text', '')
    channel_id = command.get('channel_id', '')
    user_id = command.get('user_id', '')

    channel = await get_channel_by_id(app, channel_id)
    user = await get_user_by_id(app, user_id)
    await process_command(app, text, channel, user)

def register_app_handlers(app: AsyncApp, opsgenie_token: str = "") -> None:

    @app.event("message")
    async def handle_message_events(body, logger):
        await route_message(app, opsgenie_token, body.get('event', {}) if body else {})

    @app.event("reaction_added")
    async def handle_reaction_added_events(body, logger):
        await handle_reaction_added(app, body.get('event', {}) if body else {})

    @app.command("/hutbot")
    async def handle_command(ack, body, logger):
        await ack()
        await handle_command_event(app, body)

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
                log_error(f"Exception while sending heartbeat:", e)
            await asyncio.sleep(60)

async def main() -> None:
    load_env_file()
    slack_app_token = os.environ.get("SLACK_APP_TOKEN", "")
    slack_bot_token = os.environ.get("SLACK_BOT_TOKEN", "")
    opsgenie_token = os.environ.get("OPSGENIE_TOKEN", "")
    opsgenie_heartbeat_name = os.environ.get("OPSGENIE_HEARTBEAT_NAME")
    if slack_app_token is None or slack_bot_token is None:
        log_error("Environment variables SLACK_APP_TOKEN and SLACK_BOT_TOKEN must be set to run this app")
        exit(1)

    handler = None
    heartbeat_task = None
    try:
        app = AsyncApp(token=slack_bot_token)
        await load_configuration(app)
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
