import asyncio
import base64
import binascii
import json
import os

import aiofiles
import aiohttp
from unidecode import unidecode

from logutil import log, log_error, log_warning
import retryutil


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


def get_employee_fallback_file_name() -> str:
    return get_env_var("HUTBOT_EMPLOYEE_FALLBACK_FILE", "employees-fallback.json")


def generate_employee_list(users: list) -> dict:
    employees = {}
    for user in users:
        employee_id = normalize_id(user.get("ad_name", ""))
        is_deleted = user.get("is_deleted", False)
        if not is_deleted and employee_id:
            employees[employee_id] = user
    return employees


# A mapping target of "-" means the Slack user has no employee record and none is expected
# (shared or functional accounts, people who left, people missing from the employee source).
# Such a user is mapped as usual, but never warned about when the mapping fails.
EMPLOYEE_MAPPING_IGNORE = "-"


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

        ignored = sum(1 for value in result.values() if value == EMPLOYEE_MAPPING_IGNORE)
        log(f"{len(result)} employee mappings loaded from environment variable, "
            f"{ignored} of them ignored users.")
    return result


async def load_employees_from_disk() -> dict:
    log("Attempting to load employees from disk.")
    employees = {}
    try:
        async with aiofiles.open(get_employee_cache_file_name(), "r") as f:
            content = await f.read()
            users = json.loads(content)
            employees = generate_employee_list(users)
            log(f"{len(employees)} employees loaded from disk.")
    except FileNotFoundError:
        log_error("No employee cache file found. Trying employee fallback records.")
    except OSError as e:
        log_error("Failed to read the employee cache:", e, "Trying employee fallback records.")
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError, AttributeError) as e:
        log_error("Failed to read the employee cache:", e, "Trying employee fallback records.")
    return merge_employee_fallbacks(employees, await load_employee_fallbacks())


# The string fields anything downstream reads off a record: `generate_employee_list` and the
# CLI's search terms normalize them, `build_user` strips them. A number or a null where one of
# them belongs raises somewhere far from the file that carries it.
_EMPLOYEE_TEXT_FIELDS = ("ad_name", "fullname", "group", "mail")


def is_valid_employee_record(user: object) -> bool:
    return isinstance(user, dict) and all(
        isinstance(user.get(field, ""), str) for field in _EMPLOYEE_TEXT_FIELDS
    )


async def load_employee_fallbacks() -> dict:
    """Hand-maintained records for people the employee API does not return.

    Same shape as the cache file, a JSON array of employee records, but written by an
    operator rather than by the bot: the cache is rewritten on every successful fetch, so
    anything added there would be gone with the next one. Having no such file is the normal
    case and stays silent; a broken one is reported and skipped rather than fatal.
    """
    try:
        async with aiofiles.open(get_employee_fallback_file_name(), "r") as f:
            content = await f.read()
            users = json.loads(content)
            if not isinstance(users, list):
                log_error(f"Ignoring {get_employee_fallback_file_name()}: expected a JSON array "
                          "of employee records.")
                return {}
            records = []
            for position, user in enumerate(users, start=1):
                if is_valid_employee_record(user):
                    records.append(user)
                else:
                    # Entry by entry, like the mappings: one bad record must not cost the file.
                    log_warning(f"Skipping employee fallback record {position}: expected an "
                                "object whose ad_name, fullname, group and mail are strings.")
            return generate_employee_list(records)
    except FileNotFoundError:
        pass
    except json.JSONDecodeError as e:
        log_error("Failed to decode the employee fallback JSON:", e, "Ignoring it.")
    return {}


def merge_employee_fallbacks(employees: dict, fallbacks: dict) -> dict:
    """The employee list, with fallback records filling what it does not carry.

    The API wins every collision: a fallback entry only reaches the result for an `ad_name`
    the live list has no record for — including one it dropped as deleted.
    """
    if not fallbacks:
        return employees

    merged = {**fallbacks, **employees}
    added = len(merged) - len(employees)
    if added:
        log(f"{added} employees added from {get_employee_fallback_file_name()}.")
    return merged


async def save_employees_to_disk(users: list) -> None:
    """Write the employee cache, atomically, so a failed write cannot destroy the last good one.

    This file is what `load_employees_from_disk` falls back to when the directory is
    unreachable — a half-written one would take that fallback away exactly when it is needed.
    """
    path = get_employee_cache_file_name()
    temporary = f"{path}.tmp"
    content = json.dumps(users, indent=2)

    async def attempt() -> None:
        async with aiofiles.open(temporary, "w") as f:
            await f.write(content)
            await f.flush()
            await asyncio.to_thread(os.fsync, f.fileno())
        await asyncio.to_thread(os.replace, temporary, path)

    try:
        await retryutil.retry_async(attempt, what="Writing the employee cache")
    except Exception as e:
        log_error("Failed to save employees to disk:", e)
        try:
            await asyncio.to_thread(os.unlink, temporary)
        except OSError:
            pass


async def load_employees() -> dict:
    username = get_env_var("EMPLOYEE_LIST_USERNAME")
    password = get_env_var("EMPLOYEE_LIST_PASSWORD")
    if not username or not password:
        return await load_employees_from_disk()

    employee_auth_url = "https://identity.prod.mittwald.systems/authenticate"
    employee_url = "https://lb.mittwald.it/api/users"

    async def attempt() -> list | None:
        """One authenticate-and-fetch round trip. None means a permanent refusal."""
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            auth_payload = {
                "username": username,
                "password": password,
                "providers": ["service"],
            }

            async with session.post(employee_auth_url, json=auth_payload) as auth_response:
                if retryutil.is_retryable_status(auth_response.status):
                    raise retryutil.TransientHTTPError(
                        "Authenticating against the employee directory", auth_response.status,
                        retryutil.parse_retry_after(auth_response.headers.get("Retry-After")))
                if auth_response.status != 200:
                    log_error(f"Failed to authenticate to retrieve employees: {await auth_response.text()}")
                    return None

                token = (await auth_response.text()).strip()
                if not token:
                    log_error(f"Failed to authenticate to retrieve employees, no token received: {token!r}")
                    return None

            headers = {"jwt": token}
            async with session.get(employee_url, headers=headers) as users_response:
                if retryutil.is_retryable_status(users_response.status):
                    raise retryutil.TransientHTTPError(
                        "Reading the employee directory", users_response.status,
                        retryutil.parse_retry_after(users_response.headers.get("Retry-After")))
                if users_response.status != 200:
                    log_error(f"Failed to fetch employees: {await users_response.text()}")
                    return None
                return await users_response.json()

    # The disk cache below is a real fallback, but it is a *stale* one: everybody hired since
    # the last successful fetch is missing from it, and their team is what several conditions
    # are judged on. Worth a few more attempts before settling for it.
    try:
        users = await retryutil.retry_async(attempt, what="Reading the employee directory")
    except Exception as e:
        log_error(f"Failed to retrieve employees from {employee_url}:", e)
        return await load_employees_from_disk()
    if users is None:
        return await load_employees_from_disk()

    employees = generate_employee_list(users)
    log(f"{len(employees)} employees retrieved from {employee_url}.")
    await save_employees_to_disk(users)
    return merge_employee_fallbacks(employees, await load_employee_fallbacks())
