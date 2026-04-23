import base64
import binascii
import datetime
import json
import os
import sys

import aiofiles
import aiohttp
from unidecode import unidecode


def load_env_file() -> None:
    env_file_path = os.path.join(os.path.dirname(__file__), ".env")
    if not os.path.exists(env_file_path):
        return

    with open(env_file_path) as file:
        for line in file:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("export "):
                line = line[7:]

            key, sep, value = line.partition("=")
            if sep != "=":
                continue

            key = key.strip()
            value = value.strip().strip("'\"")
            os.environ[key] = value


def _decode_env_value(value: str) -> str:
    try:
        decoded = base64.b64decode(value, validate=True).decode("utf-8")
        return decoded
    except (binascii.Error, UnicodeDecodeError):
        return value


def get_env_var(name: str, default: str = "") -> str:
    raw = os.environ.get(name, default)
    if raw is None:
        return default
    return _decode_env_value(raw)


def _log(file, prefix: str, *args: object) -> None:
    parts = []
    for arg in args:
        part = str(arg)
        if isinstance(arg, BaseException):
            error_type = type(arg).__name__
            error_message = str(arg)
            part = f"{error_type}{': ' + error_message if error_message else ''}"
        parts.append(part)
    message = " ".join(parts)
    formatted_prefix = f"{datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')} {prefix}:"
    print(formatted_prefix, message, flush=True, file=file)


def log(*args: object) -> None:
    _log(sys.stdout, "INFO", *args)


def log_warning(*args: object) -> None:
    _log(sys.stderr, "WARN", *args)


def log_error(*args: object) -> None:
    _log(sys.stderr, "ERROR", *args)


def normalize_id(value: str) -> str:
    return value.lower().strip()


def normalize_user_name(user_name: str) -> str:
    return user_name.lower().strip().replace(".", "")


def normalize_real_name(real_name: str) -> str:
    normalized = real_name.lower().strip().replace(" ", "_").replace(".", "_")
    return unidecode(normalized)


def normalize_real_name_with_diagraphs(real_name: str) -> str:
    return normalize_real_name(real_name.lower().replace("ae", "ä").replace("oe", "ö").replace("ue", "ü"))


def get_employee_cache_file_name() -> str:
    return get_env_var("HUTBOT_EMPLOYEE_CACHE_FILE", "employees.json")


def generate_employee_list(users: list) -> dict:
    employees = {}
    for user in users:
        employee_id = normalize_id(user.get("ad_name", ""))
        is_deleted = user.get("is_deleted", False)
        if not is_deleted and employee_id:
            employees[employee_id] = user
    return employees


def load_employee_mappings() -> dict:
    result = {}
    employee_mappings = get_env_var("EMPLOYEE_LIST_MAPPINGS", "").strip()
    if employee_mappings:
        log("Attempting to load employee mappings from environment variable.")
        mappings = employee_mappings.split(",")
        for mapping in mappings:
            items = mapping.split("=")
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
    log("Attempting to load employees from disk.")
    try:
        async with aiofiles.open(get_employee_cache_file_name(), "r") as f:
            content = await f.read()
            users = json.loads(content)
            employees = generate_employee_list(users)
            log(f"{len(employees)} employees loaded from disk.")
            return employees
    except FileNotFoundError:
        log_error("No employee file found. Will not be able to do team mapping.")
    except json.JSONDecodeError as e:
        log_error("Failed to decode employee JSON:", e, "Will not be able to do team mapping.")
    return {}


async def save_employees_to_disk(users: list) -> None:
    try:
        async with aiofiles.open(get_employee_cache_file_name(), "w") as f:
            await f.write(json.dumps(users, indent=2))
    except Exception as e:
        log_error("Failed to save employees to disk:", e)


async def load_employees() -> dict:
    username = get_env_var("EMPLOYEE_LIST_USERNAME")
    password = get_env_var("EMPLOYEE_LIST_PASSWORD")
    if not username or not password:
        return await load_employees_from_disk()

    employee_auth_url = "https://identity.prod.mittwald.systems/authenticate"
    employee_url = "https://lb.mittwald.it/api/users"

    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            auth_payload = {
                "username": username,
                "password": password,
                "providers": ["service"],
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
