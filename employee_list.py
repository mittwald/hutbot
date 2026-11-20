import base64
import binascii
import json
import os
import urllib.parse

import aiofiles
import aiohttp
from unidecode import unidecode

from logutil import log, log_error, log_warning
import fileutil
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
    It holds personal data, so it keeps whatever mode it already had (0600 after a state
    import) rather than being recreated under the process umask.
    """
    await fileutil.write_json_file(get_employee_cache_file_name(), users, "Writing the employee cache")


# The employee directory is Atlas, read through mittwald's internal API. Its token comes from a
# service key pair, traded at the public API the way any mittwald service authenticates.
EMPLOYEE_API_URL = "https://api.prod.mittwald.systems/internal-v2"
EMPLOYEE_AUTH_URL = "https://api-public.prod.mittwald.systems/v2"
EMPLOYEE_ACCESS_KEY_ENV = "EMPLOYEE_LIST_ACCESS_KEY_ID"
EMPLOYEE_SECRET_KEY_ENV = "EMPLOYEE_LIST_SECRET_ACCESS_KEY"
# Atlas answers up to 10000 records a page by default; asking for fewer keeps one answer small.
_EMPLOYEE_PAGE_SIZE = 1000


def employee_credentials() -> tuple[str, str]:
    """The service key pair the employee directory is read with, or two empty strings."""
    access = get_env_var(EMPLOYEE_ACCESS_KEY_ENV).strip()
    secret = get_env_var(EMPLOYEE_SECRET_KEY_ENV).strip()
    return (access, secret) if access and secret else ("", "")


def employee_record(employee: dict, group_names: dict) -> dict:
    """An Atlas employee in the record shape the cache file, the fallback file and the CLI share.

    The cache predates Atlas, and keeping its shape keeps a cache written by an older version,
    the hand-written fallback file and `query_employees.py` readable without a migration.
    """
    forename = str(employee.get("forename") or "").strip()
    surname = str(employee.get("surname") or "").strip()
    group_id = employee.get("groupId") or next(iter(employee.get("groupIds") or []), "")
    return {
        "ad_name": str(employee.get("adName") or "").strip(),
        "fullname": f"{forename} {surname}".strip(),
        "group": group_names.get(group_id, ""),
        "mail": str(employee.get("email") or "").strip(),
        "is_deleted": bool(employee.get("archivedAt")) or bool(employee.get("isIgnored")),
    }


async def _read_json(response, what: str):
    if retryutil.is_retryable_status(response.status):
        raise retryutil.TransientHTTPError(
            what, response.status, retryutil.parse_retry_after(response.headers.get("Retry-After")))
    if response.status != 200:
        body = (await response.text())[:300]
        log_error(f"{what} failed with status {response.status}: {body}")
        return None
    return await response.json()


async def _list_all(session: aiohttp.ClientSession, path: str, headers: dict, params: dict,
                    what: str) -> list | None:
    """Every item of a paginated internal-v2 listing, or None when a page was refused."""
    items: list = []
    while True:
        page_params = {**params, "limit": str(_EMPLOYEE_PAGE_SIZE), "skip": str(len(items))}
        async with session.get(f"{EMPLOYEE_API_URL}/{path}", headers=headers,
                               params=page_params) as response:
            page = await _read_json(response, what)
        if page is None:
            return None
        if not isinstance(page, list):
            raise ValueError(f"{what} answered with {type(page).__name__}, not a list")
        items.extend(page)
        if len(page) < _EMPLOYEE_PAGE_SIZE:
            return items


async def fetch_employees() -> dict | None:
    """The employee list read live from Atlas, with the fallback records merged in.

    None when no key pair is configured or the directory could not be read: the caller decides
    whether the disk cache is good enough (`load_employees`) or whether what it already holds is
    better (the user cache refresh). A successful read also rewrites the disk cache.
    """
    access, secret = employee_credentials()
    if not access:
        return None
    employee_url = f"{EMPLOYEE_API_URL}/employees"

    async def attempt() -> list | None:
        """One authenticate-and-fetch round trip. None means a permanent refusal."""
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            auth_url = f"{EMPLOYEE_AUTH_URL}/services/{urllib.parse.quote(access, safe='')}/actions/authenticate"
            async with session.post(auth_url, json={"secretAccessKey": secret}) as auth_response:
                payload = await _read_json(auth_response, "Authenticating against the employee directory")
            if payload is None:
                return None
            access_token = payload.get("accessToken") if isinstance(payload, dict) else None
            token = str((access_token or {}).get("publicToken") or "").strip() \
                if isinstance(access_token, dict) else ""
            if not token:
                log_error("Failed to authenticate to retrieve employees: no token in the answer.")
                return None

            headers = {"x-access-token": token, "Accept": "application/json"}
            # Archived groups included, so an employee still filed under one keeps its name.
            groups = await _list_all(session, "groups", headers, {"withArchived": "true"},
                                     "Reading the employee groups")
            if groups is None:
                return None
            employees = await _list_all(session, "employees", headers, {},
                                        "Reading the employee directory")
            if employees is None:
                return None
            group_names = {g.get("id"): str(g.get("name") or "").strip()
                           for g in groups if isinstance(g, dict)}
            return [employee_record(e, group_names) for e in employees]

    # The disk cache is a real fallback, but it is a *stale* one: everybody hired since the last
    # successful fetch is missing from it, and their team is what several conditions are judged
    # on. Worth a few more attempts before settling for it.
    try:
        users = await retryutil.retry_async(attempt, what="Reading the employee directory")
    except Exception as e:
        log_error(f"Failed to retrieve employees from {employee_url}:", e)
        return None
    if users is None:
        return None

    # A 200 with JSON of the wrong shape — an object, or a list with a null in it — must not
    # escape: this runs at startup, and an exception here aborts the process instead of falling
    # back to the disk cache.
    try:
        employees = generate_employee_list(users)
    except Exception as e:
        log_error(f"Failed to read the employees returned by {employee_url}:", e)
        return None

    log(f"{len(employees)} employees retrieved from {employee_url}.")
    await save_employees_to_disk(users)
    return merge_employee_fallbacks(employees, await load_employee_fallbacks())


async def load_employees() -> dict:
    """The employee list: live from Atlas when possible, else the disk cache and fallbacks."""
    employees = await fetch_employees()
    if employees is None:
        return await load_employees_from_disk()
    return employees
