import base64
import binascii
import json
import os
import re
import urllib.parse
import xml.etree.ElementTree as ET

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


# The employee directory is Atlas, read through an internal API. Its token comes from a service
# key pair, traded at the authentication API. Both base URLs come from the deployment.
EMPLOYEE_API_URL_ENV = "EMPLOYEE_LIST_API_URL"
EMPLOYEE_AUTH_URL_ENV = "EMPLOYEE_LIST_AUTH_URL"
_warned_missing_urls = False
EMPLOYEE_ACCESS_KEY_ENV = "EMPLOYEE_LIST_ACCESS_KEY_ID"
EMPLOYEE_SECRET_KEY_ENV = "EMPLOYEE_LIST_SECRET_ACCESS_KEY"
# Atlas answers up to 10000 records a page by default; asking for fewer keeps one answer small.
_EMPLOYEE_PAGE_SIZE = 1000


def employee_api_urls() -> tuple[str, str]:
    """The directory's API and authentication base URLs, without a trailing slash, or two empty
    strings while either is unset."""
    api = os.environ.get(EMPLOYEE_API_URL_ENV, "").strip().rstrip("/")
    auth = os.environ.get(EMPLOYEE_AUTH_URL_ENV, "").strip().rstrip("/")
    return (api, auth) if api and auth else ("", "")


def employee_credentials() -> tuple[str, str]:
    """The service key pair the employee directory is read with, or two empty strings.

    Also empty while the directory's URLs are unset: without them the pair reaches nothing.
    """
    access = get_env_var(EMPLOYEE_ACCESS_KEY_ENV).strip()
    secret = get_env_var(EMPLOYEE_SECRET_KEY_ENV).strip()
    if not (access and secret):
        return "", ""
    if not employee_api_urls()[0]:
        global _warned_missing_urls
        if not _warned_missing_urls:
            _warned_missing_urls = True
            log_warning(f"{EMPLOYEE_API_URL_ENV} and {EMPLOYEE_AUTH_URL_ENV} must both be set; "
                        "the employee directory is not read.")
        return "", ""
    return access, secret


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


async def _list_all(session: aiohttp.ClientSession, api_url: str, path: str, headers: dict,
                    params: dict, what: str) -> list | None:
    """Every item of a paginated internal-v2 listing, or None when a page was refused."""
    items: list = []
    while True:
        page_params = {**params, "limit": str(_EMPLOYEE_PAGE_SIZE), "skip": str(len(items))}
        async with session.get(f"{api_url}/{path}", headers=headers,
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
    api_url, auth_url_base = employee_api_urls()
    employee_url = f"{api_url}/employees"
    # The names of the groups still in use, for placing employees without one (see below).
    active_groups: list[str] = []

    async def attempt() -> list | None:
        """One authenticate-and-fetch round trip. None means a permanent refusal."""
        active_groups.clear()
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            auth_url = f"{auth_url_base}/services/{urllib.parse.quote(access, safe='')}/actions/authenticate"
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
            groups = await _list_all(session, api_url, "groups", headers, {"withArchived": "true"},
                                     "Reading the employee groups")
            if groups is None:
                return None
            employees = await _list_all(session, api_url, "employees", headers, {},
                                        "Reading the employee directory")
            if employees is None:
                return None
            group_names = {g.get("id"): str(g.get("name") or "").strip()
                           for g in groups if isinstance(g, dict)}
            active_groups.extend(name for g in groups if isinstance(g, dict) and not g.get("archivedAt")
                                 for name in [group_names.get(g.get("id"))] if name)
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

    await fill_missing_groups(users, active_groups)

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


# A fallback for employees Atlas has no group for: the department Exchange files them under,
# read from the organisation's directory, an address book served over CardDAV. Off unless the
# URL, user and token are all set, and never consulted for an employee Atlas does place.
DIRECTORY_CARDDAV_TOKEN_ENV = "HUTBOT_DIRECTORY_CARDDAV_TOKEN"
DIRECTORY_CARDDAV_URL_ENV = "HUTBOT_DIRECTORY_CARDDAV_URL"
DIRECTORY_CARDDAV_USER_ENV = "HUTBOT_DIRECTORY_CARDDAV_USER"
# The whole directory (about 800 cards) is a few hundred kilobytes; anything far larger is not it.
_DIRECTORY_MAX_BYTES = 16 * 1024 * 1024
_DIRECTORY_TIMEOUT_SECONDS = 15
_CARDDAV_NS = "urn:ietf:params:xml:ns:carddav"
_DIRECTORY_QUERY = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<C:addressbook-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">'
    '<D:prop><C:address-data/></D:prop></C:addressbook-query>'
)


def directory_carddav_settings() -> tuple[str, str, str]:
    """The address book's URL, user and token, or three empty strings while any of them is unset.

    Read straight from the environment rather than through `get_env_var`: the bridge's tokens are
    hex, which is also valid base64, and must never be "decoded".
    """
    token = os.environ.get(DIRECTORY_CARDDAV_TOKEN_ENV, "").strip()
    url = os.environ.get(DIRECTORY_CARDDAV_URL_ENV, "").strip()
    user = os.environ.get(DIRECTORY_CARDDAV_USER_ENV, "").strip()
    if not (token and url and user):
        return "", "", ""
    return url, user, token


def _vcard_unescape(value: str) -> str:
    return re.sub(r"\\(.)", lambda m: "\n" if m.group(1) in "nN" else m.group(1), value)


def card_departments(vcards: list[str]) -> dict[str, str]:
    """{lowercased email: department} out of vCards, for every card that names a department.

    The department is the second component of ORG (`company;department`).
    """
    departments: dict[str, str] = {}
    for text in vcards:
        # Unfold first: a long line continues on the next one after a space or a tab.
        lines = re.sub(r"\r?\n[ \t]", "", text).splitlines()
        emails, department = [], ""
        for line in lines:
            name, sep, value = line.partition(":")
            if not sep:
                continue
            # Drop parameters (`EMAIL;TYPE=INTERNET`) and a group prefix (`item1.EMAIL`).
            prop = name.split(";", 1)[0].rsplit(".", 1)[-1].upper()
            if prop == "EMAIL":
                emails.append(_vcard_unescape(value).strip().lower())
            elif prop == "ORG":
                parts = re.split(r"(?<!\\);", value)
                if len(parts) > 1:
                    department = _vcard_unescape(parts[1]).strip()
        if department:
            for email in emails:
                if email:
                    departments.setdefault(email, department)
    return departments


def _group_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", unidecode(name).lower())


# Hand-written `key=Team` lists for the two team fallbacks, keyed by department and by whole user
# group handle. Kept apart from EMPLOYEE_LIST_MAPPINGS, which names employees rather than teams.
# Read raw, like the CardDAV token: a value of plain letters is also valid base64, and
# `get_env_var` would "decode" it.
DEPARTMENT_MAPPINGS_ENV = "EMPLOYEE_LIST_DEPARTMENT_MAPPINGS"
USERGROUP_MAPPINGS_ENV = "EMPLOYEE_LIST_USERGROUP_MAPPINGS"
# Records whose group came from a fallback rather than from Atlas carry this as `group_source`, so
# a better fallback (a Slack user group) may still replace it.
GROUP_SOURCE_DIRECTORY = "directory"


def _parse_team_mappings(env: str, what: str) -> list[tuple[str, str]]:
    """`key=Team` pairs of a comma-separated env var, in the order written, malformed ones skipped."""
    pairs: list[tuple[str, str]] = []
    for item in os.environ.get(env, "").split(","):
        if not item.strip():
            continue
        key, sep, team = item.partition("=")
        key, team = key.strip(), team.strip()
        if not sep or not key or not team:
            log_warning(f"Failed to parse {what} mapping '{item.strip()}', skipping")
            continue
        pairs.append((key, team))
    return pairs


def load_department_mappings() -> dict[str, str]:
    """{department key: team} from EMPLOYEE_LIST_DEPARTMENT_MAPPINGS, e.g. `CS=Central Services`.

    Keys compare the way `resolve_department` compares group names: ignoring case, spacing and
    punctuation. The first entry for a key wins.
    """
    mappings: dict[str, str] = {}
    for department, team in _parse_team_mappings(DEPARTMENT_MAPPINGS_ENV, "department"):
        key = _group_key(department)
        if key and key not in mappings:
            mappings[key] = team
    return mappings


def load_usergroup_mappings() -> list[tuple[str, str]]:
    """(lowercased user group handle, team) pairs from EMPLOYEE_LIST_USERGROUP_MAPPINGS, e.g.
    `cloud-ops=Cloud (c³)`, in the order written: the first that fits a user wins. A leading `@`
    on the handle is optional."""
    mappings = []
    for handle, team in _parse_team_mappings(USERGROUP_MAPPINGS_ENV, "user group"):
        handle = handle.strip().removeprefix("@").strip().lower()
        if handle:
            mappings.append((handle, team))
        else:
            log_warning(f"Ignoring a {USERGROUP_MAPPINGS_ENV} entry without a handle: '@={team}'.")
    return mappings


def resolve_department(department: str, group_names: list[str],
                       mappings: dict[str, str] | None = None) -> str:
    """The Atlas group a free-text Exchange department stands for, or the department itself.

    Exchange writes departments by hand: "Infrastructure - Mail", "Development_Apps",
    "Productmanagement". The whole department is tried first, then each part, the most specific
    (last) first. For each, an EMPLOYEE_LIST_DEPARTMENT_MAPPINGS entry decides; otherwise it is
    compared with every group name ignoring case, spacing and punctuation, and with the part of a
    name before a slash ("Infrastructure" is "Infrastructure/Engineering").
    What matches nothing is kept as written, so the employee still gets a team, if one no
    condition will name.
    """
    parts = [part.strip() for part in re.split(r"\s+-\s+|_", department) if part.strip()]
    for candidate in [department.strip(), *reversed(parts)]:
        key = _group_key(candidate)
        if not key:
            continue
        team = (mappings or {}).get(key)
        if team:
            return team
        for name in group_names:
            if key in (_group_key(name), _group_key(name.split("/", 1)[0])):
                return name
    return department.strip()


async def fetch_directory_departments() -> dict[str, str] | None:
    """{email: department} from the CardDAV directory, or None when it is off or unreadable."""
    url, user, token = directory_carddav_settings()
    if not token:
        return None

    credentials = base64.b64encode(f"{user}:{token}".encode()).decode()
    headers = {"Authorization": f"Basic {credentials}", "Depth": "1",
               "Content-Type": "application/xml; charset=utf-8"}

    async def attempt() -> dict[str, str] | None:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=_DIRECTORY_TIMEOUT_SECONDS)) as session:
            async with session.request("REPORT", url, data=_DIRECTORY_QUERY.encode(),
                                       headers=headers) as response:
                if response.status != 207:
                    log_error(f"Reading the CardDAV directory failed with status {response.status}.")
                    return None
                # Read to the end in chunks: one `read(n)` returns what has arrived so far, not n bytes.
                body = bytearray()
                async for chunk in response.content.iter_chunked(64 * 1024):
                    body.extend(chunk)
                    if len(body) > _DIRECTORY_MAX_BYTES:
                        log_error(f"The CardDAV directory answered with more than {_DIRECTORY_MAX_BYTES} bytes.")
                        return None
        root = ET.fromstring(bytes(body))
        return card_departments([el.text or "" for el in root.iter(f"{{{_CARDDAV_NS}}}address-data")])

    # One attempt, not retried: this runs on the startup path ahead of the health endpoint, and
    # the fallback is optional. A miss is tried again at the next user cache refresh.
    try:
        departments = await attempt()
    except Exception as e:
        log_error(f"Failed to read the CardDAV directory at {url}:", e)
        return None
    if departments is not None and not departments:
        # The bridge serves an empty book until its first crawl of the directory has finished.
        log_warning("The CardDAV directory has no departments yet.")
        return None
    return departments


async def fill_missing_groups(users: list, group_names: list[str]) -> None:
    """Give employees Atlas has no group for the team their Exchange department names.

    Only a fallback: a record that has a group keeps it, and nothing is changed when the
    directory is off or cannot be read. Records are changed in place, so the disk cache keeps
    the placement too.
    """
    missing = [u for u in users if isinstance(u, dict) and not u.get("group") and not u.get("is_deleted")
               and u.get("mail")]
    if not missing or not directory_carddav_settings()[2]:
        return
    departments = await fetch_directory_departments()
    if not departments:
        return
    mappings = load_department_mappings()
    placed, unplaced = [], []
    for user in missing:
        department = departments.get(str(user["mail"]).strip().lower())
        if department:
            user["group"] = resolve_department(department, group_names, mappings)
            user["group_source"] = GROUP_SOURCE_DIRECTORY
            placed.append(f"{user.get('ad_name')} -> {user['group']}")
        else:
            unplaced.append(str(user.get("ad_name")))
    if placed:
        log(f"{len(placed)} employees without an Atlas group placed by their Exchange department: "
            f"{', '.join(placed)}.")
    if unplaced:
        log_warning(f"{len(unplaced)} employees have no group in Atlas and no department in the "
                    f"CardDAV directory: {', '.join(unplaced)}.")


async def load_employees() -> dict:
    """The employee list: live from Atlas when possible, else the disk cache and fallbacks."""
    employees = await fetch_employees()
    if employees is None:
        return await load_employees_from_disk()
    return employees
