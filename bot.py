import os
import base64
import binascii
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
Channel = collections.namedtuple('Channel', ['id', 'name', 'configs'])

DEFAULT_CONFIG = {
    "wait_time": 30 * 60,
    "reply_message": "Anybody?",
    "opsgenie": False,
    "debug": False,
    "include_bots": False,
    "excluded_teams": [],
    "included_teams": [],
    "only_work_days": False,
    "hours": [],
    "pattern": None,
    "pattern_case_sensitive": False
}

EMPLOYEE_CACHE_FILE_NAME = os.environ.get('HUTBOT_EMPLOYEE_CACHE_FILE', 'employees.json')
CONFIG_FILE_NAME = os.environ.get('HUTBOT_CONFIG_FILE', 'bot.json')
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
TIME_HOUR_PATTERN = re.compile(r"^[0-9]{1,2}$")

# Regex patterns for command parsing
def create_command_pattern(command_regex: str) -> re.Pattern:
    return re.compile(f'^{command_regex}', re.IGNORECASE)

HELP_PATTERN = re.compile(r'help', re.IGNORECASE)
SET_WAIT_TIME_PATTERN = create_command_pattern(r'(set\s+)?wait([_ -]?time)?\s+(?P<wait_time>.+)')
SET_REPLY_MESSAGE_PATTERN = create_command_pattern(r'(set\s+)?(message|reply)\s+(?P<message>.+)')
SET_PATTERN_PATTERN = create_command_pattern(r'set\s+pattern\s+(?P<pattern>".*?"|\S+)(?:\s+(?P<case_sensitive>true|false|1|0))?')
ADD_EXCLUDED_TEAM_PATTERN = create_command_pattern(r'(add\s+)?excluded?([_ -]?teams?)?\s+(?P<team>.+)')
CLEAR_EXCLUDED_TEAM_PATTERN = create_command_pattern(r'clear\s+excluded?([_ -]?teams?)?')
ADD_INCLUDED_TEAM_PATTERN = create_command_pattern(r'(add\s+)?included?([_ -]?teams?)?\s+(?P<team>.+)')
CLEAR_INCLUDED_TEAM_PATTERN = create_command_pattern(r'clear\s+included?([_ -]?teams?)?')
LIST_TEAMS_PATTERN = re.compile(r'^(list\s+)?teams?$', re.IGNORECASE)
EMPLOYEE_TEAM_PATTERN = re.compile(r'^team(\s+of)?\s+(?P<user>.+)$', re.IGNORECASE)
ENABLE_OPSGENIE_PATTERN = create_command_pattern(r'enable\s+(opsgenie|alerts?)')
DISABLE_OPSGENIE_PATTERN = create_command_pattern(r'disable\s+(opsgenie|alerts?)')
ENABLE_BOTS_PATTERN = create_command_pattern(r'(enable|include|set)?\s+bots?')
DISABLE_BOTS_PATTERN = create_command_pattern(r'(disable|exclude)\s+bots?')
SET_WORK_HOURS_PATTERN = create_command_pattern(r'(set\s+)?(work[_ -]?)?hours\s+(?P<start>.+)\s+(?P<end>.+)')
ENABLE_ONLY_WORK_DAYS_PATTERN = create_command_pattern(r'enable\s+(only[_ -]?)?work[_ -]?days')
DISABLE_ONLY_WORK_DAYS_PATTERN = create_command_pattern(r'disable\s+(only[_ -]?)?work[_ -]?days')
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


def _decode_env_value(value: str) -> str:
    try:
        decoded = base64.b64decode(value, validate=True).decode('utf-8')
        return decoded
    except (binascii.Error, UnicodeDecodeError):
        return value


def get_env_var(name: str, default: str = "") -> str:
    raw = os.environ.get(name, default)
    if raw is None:
        return default
    return _decode_env_value(raw)

def log(*args: object) -> None:
    __log(sys.stdout, 'INFO', *args)

def log_warning(*args: object) -> None:
    __log(sys.stderr, 'WARN', *args)

def log_error(*args: object) -> None:
    __log(sys.stderr, 'ERROR', *args)

def log_debug(channel: Channel | None, *args: object) -> None:
    if channel and any(c.get('debug') for c in channel.configs.values()):
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

async def migrate_and_apply_defaults(app: AsyncApp, config: dict) -> dict:
    for channel_id, channel_data in config.items():
        # Migration for old format
        # old format: "C1234": { "wait_time": 60, ... }
        # new format: "C1234": { "default": { "wait_time": 60, ... } }
        is_flat_config = any(k in DEFAULT_CONFIG for k in channel_data.keys())
        if is_flat_config:
            # This looks like an old, flat config. Let's wrap it.
            log(f"Migrating old configuration for channel {channel_id}")
            channel_data = {"default": channel_data}
            config[channel_id] = channel_data

        for config_name, single_config in channel_data.items():
            for key, value in DEFAULT_CONFIG.items():
                if key not in single_config:
                    single_config[key] = value
    return config


async def load_configuration(app: AsyncApp) -> None:
    global channel_config
    try:
        async with aiofiles.open(CONFIG_FILE_NAME, 'r') as f:
            content = await f.read()
            loaded_config = json.loads(content)
            channel_config = await migrate_and_apply_defaults(app, loaded_config)
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
    employee_mappings = get_env_var("EMPLOYEE_LIST_MAPPINGS", "").strip()
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

async def save_employees_to_disk(users: list) -> None:
    try:
        async with aiofiles.open(EMPLOYEE_CACHE_FILE_NAME, 'w') as f:
            await f.write(json.dumps(users, indent=2))
    except Exception as e:
        log_error("Failed to save employees to disk:", e)

async def load_employees() -> dict:
    username = get_env_var("EMPLOYEE_LIST_USERNAME")
    password = get_env_var("EMPLOYEE_LIST_PASSWORD")
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

                token = (await auth_response.text()).strip()
                if not token:
                    log_error(f"Failed to authenticate to retrieve employees, no token received: {token!r}")
                    return await load_employees_from_disk()

            headers = {"jwt": token}
            async with session.get(employee_url, headers=headers) as users_response:
                if users_response.status != 200:
                    log_error(f"Failed to fetch employees: {await users_response.text()}")
                    return await load_employees_from_disk()

                users = await users_response.json()
                employees = generate_employee_list(users)
                log(f"{len(employees)} employees retrieved from {employee_url}.")
                await save_employees_to_disk(users)
                return employees
    except Exception as e:
        log_error(f"Failed to retrieve employees from {employee_url}:", e)
        return await load_employees_from_disk()

async def get_channel_by_id(app: AsyncApp, channel_id: str) -> Channel:
    global channel_config
    if channel_id not in channel_config:
        channel_config[channel_id] = {}

    name = await get_channel_name(app, channel_id)
    configs = channel_config[channel_id]

    return Channel(id=channel_id, name=name, configs=configs)

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

def is_work_day() -> bool:
    today = datetime.date.today()
    # TODO: add holidays
    return today.weekday() < 5

def is_work_time(start_time_str: str, end_time_str: str) -> bool:
    now = datetime.datetime.now()
    start = parse_time(start_time_str)
    end = parse_time(end_time_str)
    if not start or not end:
        log_error(f"Invalid time format {start_time_str} - {end_time_str}")
        return True
    start_today = datetime.datetime.combine(now.date(), start)
    end_today = datetime.datetime.combine(now.date(), end)
    return start_today < now < end_today

def is_command(text: str) -> bool:
    return f"<@{bot_user_id}>" in text

async def process_command(app: AsyncApp, text: str, channel: Channel, user: User, thread_ts: str = "") -> None:
    text = text.replace(f"<@{bot_user_id}>", "").strip()

    log_debug(channel, f"Received command for channel #{channel.name}: {text}")

    parts = text.split()
    config_name = "default"
    command_text = text

    # This is a bit of a hack. If the first word does not match any known command keywords,
    # we assume it's a configuration name.
    known_command_keywords = ['set', 'add', 'clear', 'list', 'team', 'enable', 'disable', 'show', 'help']
    if parts and parts[0] not in known_command_keywords:
        # It's not a perfect check, as a team name could be "set", but it's good enough for now.
        is_command_like = any(p.match(parts[0]) for p in [LIST_TEAMS_PATTERN, EMPLOYEE_TEAM_PATTERN, SHOW_CONFIG_PATTERN, HELP_PATTERN])
        if not is_command_like:
            config_name = parts[0]
            command_text = " ".join(parts[1:])

    # Parse commands
    if (match := SET_WAIT_TIME_PATTERN.match(command_text)):
        wait_time_minutes = int(match.group("wait_time").strip('"').strip("'"))
        await set_wait_time(app, channel, config_name, wait_time_minutes, user, thread_ts)
    elif (match := SET_REPLY_MESSAGE_PATTERN.match(command_text)):
        message = match.group("message").strip('"').strip("'")
        await set_reply_message(app, channel, config_name, message, user, thread_ts)
    elif (match := SET_PATTERN_PATTERN.match(command_text)):
        pattern = match.group("pattern")
        case_sensitive = match.group("case_sensitive")
        await set_pattern(app, channel, config_name, pattern, case_sensitive, user, thread_ts)
    elif (match := ENABLE_OPSGENIE_PATTERN.match(command_text)):
        await set_opsgenie(app, channel, config_name, True, user, thread_ts)
    elif (match := DISABLE_OPSGENIE_PATTERN.match(command_text)):
        await set_opsgenie(app, channel, config_name, False, user, thread_ts)
    elif (match := ENABLE_BOTS_PATTERN.match(command_text)):
        await set_bots(app, channel, config_name, True, user, thread_ts)
    elif (match := DISABLE_BOTS_PATTERN.match(command_text)):
        await set_bots(app, channel, config_name, False, user, thread_ts)
    elif (match := ENABLE_ONLY_WORK_DAYS_PATTERN.match(command_text)):
        await set_only_work_days(app, channel, config_name, True, user, thread_ts)
    elif (match := DISABLE_ONLY_WORK_DAYS_PATTERN.match(command_text)):
        await set_only_work_days(app, channel, config_name, False, user, thread_ts)
    elif (match := SET_WORK_HOURS_PATTERN.match(command_text)):
        start = match.group("start").strip('"').strip("'")
        end = match.group("end").strip('"').strip("'")
        await set_work_hours(app, channel, config_name, start, end, user, thread_ts)
    elif LIST_TEAMS_PATTERN.match(command_text):
        await list_teams(app, channel, user, thread_ts)
    elif (match := EMPLOYEE_TEAM_PATTERN.match(command_text)):
        username = match.group("user").strip('"').strip("'")
        await get_team_of(app, channel, username, user, thread_ts)
    elif (match := ADD_EXCLUDED_TEAM_PATTERN.match(command_text)):
        team = match.group("team").strip('"').strip("'")
        await add_excluded_team(app, channel, config_name, team, user, thread_ts)
    elif (match := CLEAR_EXCLUDED_TEAM_PATTERN.match(command_text)):
        await clear_excluded_team(app, channel, config_name, user, thread_ts)
    elif (match := ADD_INCLUDED_TEAM_PATTERN.match(command_text)):
        team = match.group("team").strip('"').strip("'")
        await add_included_team(app, channel, config_name, team, user, thread_ts)
    elif (match := CLEAR_INCLUDED_TEAM_PATTERN.match(command_text)):
        await clear_included_team(app, channel, config_name, user, thread_ts)
    elif SHOW_CONFIG_PATTERN.match(command_text):
        await show_config(app, channel, user, thread_ts)
    elif HELP_PATTERN.match(command_text):
        await send_help_message(app, channel, user, thread_ts)
    else:
        await send_message(app, channel, user, "Huh? :thinking_face: Maybe type `/hutbot help` for a list of commands.", thread_ts)

async def set_bots(app: AsyncApp, channel: Channel, config_name: str, enabled: bool, user: User, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    channel.configs[config_name]['include_bots'] = enabled
    await save_configuration()
    await send_message(app, channel, user, f"*Bot messages* will {'also be *handled*' if enabled else 'be *ignored*'} in configuration `{config_name}`.", thread_ts)

async def set_only_work_days(app: AsyncApp, channel: Channel, config_name: str, enabled: bool, user: User, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    channel.configs[config_name]['only_work_days'] = enabled
    await save_configuration()
    await send_message(app, channel, user, f"Messages will be handled {'*only on work days*' if enabled else '*on all days*'} in configuration `{config_name}`.", thread_ts)

def parse_time(time_str) -> datetime.time | None:
    if TIME_HOUR_PATTERN.match(time_str):
        time_str = f"{time_str}:00"

    time = None
    try:
        time = datetime.datetime.strptime(time_str, "%H:%M").time()
    except ValueError:
        pass

    return time

async def set_work_hours(app: AsyncApp, channel: Channel, config_name: str, start: str, end: str, user: User, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    start_time = parse_time(start)
    end_time = parse_time(end)
    if not start_time:
        await send_message(app, channel, user, f"Invalid time format `{start}`.", thread_ts)
        return
    if not end_time:
        await send_message(app, channel, user, f"Invalid time format `{end}`.", thread_ts)
        return
    hours = [start_time.strftime("%H:%M"), end_time.strftime("%H:%M")]
    if hours[0] == "00:00" and hours[1] == "00:00":
        hours = []
    channel.configs[config_name]['hours'] = hours
    await save_configuration()
    await send_message(app, channel, user, f"*Work hours* set to {f'`{hours[0]}` - `{hours[1]}`' if len(hours) == 2 else 'all day'} in configuration `{config_name}`", thread_ts)

async def set_opsgenie(app: AsyncApp, channel: Channel, config_name: str, enabled: bool, user: User, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    channel.configs[config_name]['opsgenie'] = enabled
    await save_configuration()
    await send_message(app, channel, user, f"*OpsGenie integration* {'*enabled*' if enabled else '*disabled*'}{', but not configured' if enabled and not opsgenie_configured else ''} in configuration `{config_name}`.", thread_ts)

async def set_wait_time(app: AsyncApp, channel: Channel, config_name: str, wait_time_minutes: int, user: User, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    # check if number and in range 0-1440
    if not wait_time_minutes or wait_time_minutes < 0 or wait_time_minutes > 1440:
        await send_message(app, channel, user, "Invalid wait time. Must be a number between 0 and 1440.", thread_ts)
        return

    channel.configs[config_name]['wait_time'] = wait_time_minutes * 60  # Convert to seconds
    log_debug(channel, f"Wait time for #{channel.name} set to {wait_time_minutes} minutes for configuration `{config_name}`")
    await save_configuration()
    await send_message(app, channel, user, f"*Wait time* set to `{wait_time_minutes}` minutes in configuration `{config_name}`.", thread_ts)

async def set_reply_message(app: AsyncApp, channel: Channel, config_name: str, message: str, user: User, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    # check message
    if not message or message.strip() == "":
        await send_message(app, channel, user, "Invalid *reply message*. Must be non-empty.", thread_ts)
        return
    ok, error, message = await process_mentions(app, message)
    if not ok:
        await send_message(app, channel, user, "Invalid *reply message*: " + error + ".", thread_ts)
        return

    channel.configs[config_name]['reply_message'] = message
    await save_configuration()
    await send_message(app, channel, user, f"*Reply message* set to: {message} in configuration `{config_name}`.", thread_ts)

async def set_pattern(app: AsyncApp, channel: Channel, config_name: str, pattern_str: str, case_sensitive_str: str | None, user: User, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()

    # Validate the regex pattern
    pattern_str = pattern_str.strip('"')
    try:
        re.compile(pattern_str)
    except re.error as e:
        await send_message(app, channel, user, f"Invalid regex pattern: `{e}`", thread_ts)
        return

    case_sensitive = case_sensitive_str is not None and case_sensitive_str.lower() in ['true', '1']

    channel.configs[config_name]['pattern'] = pattern_str
    channel.configs[config_name]['pattern_case_sensitive'] = case_sensitive
    await save_configuration()

    message = f"Pattern set to `{pattern_str}` for configuration `{config_name}`."
    if case_sensitive:
        message += " (case-sensitive)"
    else:
        message += " (case-insensitive)"
    await send_message(app, channel, user, message, thread_ts)

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

async def add_excluded_team(app: AsyncApp, channel: Channel, config_name: str, team: str, user: User, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    config = channel.configs[config_name]
    await update_user_cache(app)
    if team not in team_cache:
        await send_message(app, channel, user, f"Unknown team: `{team}`.", thread_ts)
        return
    if team in config['excluded_teams']:
        await send_message(app, channel, user, f"`{team}` is already excluded in configuration `{config_name}`.", thread_ts)
        return

    if len(config['included_teams']) > 0:
        await send_message(app, channel, user, f"Either set *included teams* or *excluded teams*, not both, in configuration `{config_name}`.", thread_ts)
        return

    config['excluded_teams'].append(team)
    await save_configuration()
    await send_message(app, channel, user, f"Added `{team}` to *excluded teams* in configuration `{config_name}`.", thread_ts)

async def clear_excluded_team(app: AsyncApp, channel: Channel, config_name: str, user: User, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    channel.configs[config_name]['excluded_teams'] = []
    await save_configuration()
    await send_message(app, channel, user, f"Cleared *excluded teams* in configuration `{config_name}`.", thread_ts)

async def add_included_team(app: AsyncApp, channel: Channel, config_name: str, team: str, user: User, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    config = channel.configs[config_name]
    await update_user_cache(app)
    if team not in team_cache:
        await send_message(app, channel, user, f"Unknown team: `{team}`.", thread_ts)
        return
    if team in config['included_teams']:
        await send_message(app, channel, user, f"`{team}` is already included in configuration `{config_name}`.", thread_ts)
        return

    if len(config['excluded_teams']) > 0:
        await send_message(app, channel, user, f"Either set *included teams* or *excluded teams*, not both, in configuration `{config_name}`.", thread_ts)
        return

    config['included_teams'].append(team)
    await save_configuration()
    await send_message(app, channel, user, f"Added `{team}` to *included teams* in configuration `{config_name}`.", thread_ts)

async def clear_included_team(app: AsyncApp, channel: Channel, config_name: str, user: User, thread_ts: str = "") -> None:
    if config_name not in channel.configs:
        channel.configs[config_name] = DEFAULT_CONFIG.copy()
    channel.configs[config_name]['included_teams'] = []
    await save_configuration()
    await send_message(app, channel, user, f"Cleared *included teams* in configuration `{config_name}`.", thread_ts)

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
    if not channel.configs:
        message = f"There is no configuration for #{channel.name}."
        await send_message(app, channel, user, message, thread_ts)
        return

    message = f"This is the configuration for #{channel.name}:"
    for config_name, config in sorted(channel.configs.items()):
        opsgenie_enabled = config.get('opsgenie')
        wait_time_minutes = config.get('wait_time') // 60
        included_teams = config.get('included_teams')
        excluded_teams = config.get('excluded_teams')
        include_bots = config.get('include_bots')
        only_work_days = config.get('only_work_days')
        hours = config.get('hours')
        pattern = config.get('pattern')
        pattern_case_sensitive = config.get('pattern_case_sensitive')
        reply_message = config.get('reply_message')

        message += (
            f"\n\n---\n*Configuration*: `{config_name}`\n\n"
            f"*OpsGenie integration*: {'enabled' if opsgenie_enabled else 'disabled'}"
            f"{'' if opsgenie_configured else ' (not configured)'}\n\n"
            f"*Wait time*: `{wait_time_minutes}` minutes\n\n"
            f"*Included teams*: {' '.join(f'`{team}`' for team in included_teams) if included_teams else '<None>'}\n\n"
            f"*Excluded teams*: {' '.join(f'`{team}`' for team in excluded_teams) if excluded_teams else '<None>'}\n\n"
            f"*Include bots*: {'enabled' if include_bots else 'disabled'}\n\n"
            f"*Only work days*: {'enabled' if only_work_days else 'disabled'}\n\n"
            f"*Work hours*: {f'`{hours[0]}` - `{hours[1]}`' if len(hours) == 2 else 'all day'}\n\n"
            f"*Pattern*: {f'`{pattern}` (case-sensitive)' if pattern_case_sensitive else f'`{pattern}` (case-insensitive)' if pattern else '<None>'}\n\n"
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
        "*Only Work Days:*\n"
        "```/hutbot enable only-work-days\n"
        "@Hutbot enable only-work-days```\n"
        "Only respond to messages on work days.\n\n"
        "*All Days:*\n"
        "```/hutbot disable only-work-days\n"
        "@Hutbot disable only-work-days```\n"
        "Respond to messages on all days.\n\n"
        "*Set Work Hours:*\n"
        "```/hutbot set work-hours [start-time] [end-time]\n"
        "@Hutbot set work-hours [start-time] [end-time]```\n"
        "Respond to messages during these hours. Set `0:00` `0:00` for all day.\n\n"
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

async def schedule_reply(app: AsyncApp, opsgenie_token: str, channel: Channel, config: dict, config_name: str, user: User, text: str, ts: str) -> None:
    opsgenie_enabled = config.get('opsgenie')
    wait_time = config.get('wait_time')
    reply_message = config.get('reply_message')
    log(f"Scheduling reply for message {ts} in channel #{channel.name} for config '{config_name}', user @{user.name}, wait time {wait_time // 60} mins, opsgenie {'enabled' if opsgenie_enabled else 'disabled'}{', but not configured' if opsgenie_enabled and not opsgenie_configured else ''}")
    try:
        await asyncio.sleep(wait_time)
        await send_message(app, channel, user, reply_message, ts)
        if opsgenie_configured and opsgenie_enabled:
            log(f"Attempting to send OpsGenie alert for message {ts} in channel #{channel.name}, user @{user.name}...")
            permalink = await get_message_permalink(app, channel, ts)
            await post_opsgenie_alert(app, opsgenie_token, channel, user, text, ts, permalink)
    except asyncio.CancelledError as e:
        log(f"Cancelling scheduled reply for message {ts} in channel #{channel.name} for config '{config_name}', user @{user.name}:", e)
    except Exception as e:
        log_error(f"Failed to send scheduled reply for message {ts} in channel #{channel.name} for config '{config_name}', user @{user.name}:", e)

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

    # reduce duplicate spaces and trim
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
    elif bot_id and any(c.get('include_bots', False) for c in channel.configs.values()):
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
    keys_to_cancel = []
    for key, scheduled_reply in scheduled_messages.items():
        if key[0] == channel.id and key[1] == thread_ts and scheduled_reply.user_id != reply_user.id:
            keys_to_cancel.append(key)

    if not keys_to_cancel:
        return

    message_user_id = scheduled_messages[keys_to_cancel[0]].user_id
    message_user = await get_user_by_id(app, message_user_id)
    log(f"Thread reply by user @{reply_user.name} detected. Cancelling {len(keys_to_cancel)} reminder(s) for message {thread_ts} in channel #{channel.name}, user @{message_user.name}")

    for key in keys_to_cancel:
        scheduled_messages[key].task.cancel()
        del scheduled_messages[key]

async def handle_channel_message(app: AsyncApp, opsgenie_token: str, channel: Channel, user: User, text: str, ts: str):
    for config_name, config in channel.configs.items():
        only_work_days = config.get('only_work_days')
        hours = config.get('hours')
        included_teams = config.get('included_teams')
        excluded_teams = config.get('excluded_teams')
        pattern = config.get('pattern')
        pattern_case_sensitive = config.get('pattern_case_sensitive')

        if only_work_days and not is_work_day():
            log(f"Message from user @{user.name} in #{channel.name} will be ignored for config '{config_name}' because of a non work day.")
            continue
        if len(hours) == 2 and not is_work_time(hours[0], hours[1]):
            log(f"Message from user @{user.name} in #{channel.name} will be ignored for config '{config_name}' because it was sent outside work time.")
            continue
        if len(included_teams) > 0 and user.team not in included_teams:
            log(f"Message from user @{user.name} in #{channel.name} will be ignored for config '{config_name}' because team '{user.team}' is not included.")
            continue
        if len(excluded_teams) > 0 and user.team in excluded_teams:
            log(f"Message from user @{user.name} in #{channel.name} will be ignored for config '{config_name}' because team '{user.team}' is excluded.")
            continue

        if pattern:
            flags = 0 if pattern_case_sensitive else re.IGNORECASE
            if not re.search(pattern, text, flags):
                log(f"Message from user @{user.name} in #{channel.name} will be ignored for config '{config_name}' because it does not match pattern '{pattern}'.")
                continue

        task = asyncio.create_task(schedule_reply(app, opsgenie_token, channel, config, config_name, user, text, ts))
        scheduled_messages[(channel.id, ts, config_name)] = ScheduledReply(task, user.id)

async def handle_reaction_added(app: AsyncApp, event):
    item = event.get('item', {})
    channel_id = item.get('channel', '')
    user_id = event.get('user', '')
    ts = item.get('ts')

    keys_to_cancel = []
    for key, scheduled_reply in scheduled_messages.items():
        if key[0] == channel_id and key[1] == ts and scheduled_reply.user_id != user_id:
            keys_to_cancel.append(key)

    if not keys_to_cancel:
        return

    channel = await get_channel_by_id(app, channel_id)
    message_user_id = scheduled_messages[keys_to_cancel[0]].user_id
    message_user = await get_user_by_id(app, message_user_id)
    reaction_user = await get_user_by_id(app, user_id)
    log(f"Reaction added by user @{reaction_user.name}. Cancelling {len(keys_to_cancel)} reminder(s) for message {ts} in channel #{channel.name}, user @{message_user.name}")

    for key in keys_to_cancel:
        scheduled_messages[key].task.cancel()
        del scheduled_messages[key]

async def handle_message_deletion(app: AsyncApp, channel: Channel, previous_message_user: User, previous_message_ts: str):
    if previous_message_user.id == bot_user_id:
        log(f"Ignoring message deletion by bot from channel #{channel.name}.")
        return

    keys_to_cancel = []
    for key in scheduled_messages.keys():
        if key[0] == channel.id and key[1] == previous_message_ts:
            keys_to_cancel.append(key)

    if not keys_to_cancel:
        return

    log(f"Message deleted. Cancelling {len(keys_to_cancel)} reply/replies for message {previous_message_ts} in channel #{channel.name}, user @{previous_message_user.name}")
    for key in keys_to_cancel:
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
    slack_app_token = get_env_var("SLACK_APP_TOKEN")
    slack_bot_token = get_env_var("SLACK_BOT_TOKEN")
    opsgenie_token = get_env_var("OPSGENIE_TOKEN")
    opsgenie_heartbeat_name = get_env_var("OPSGENIE_HEARTBEAT_NAME")
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
