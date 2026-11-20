"""Reading the employee directory from Atlas."""

from tests._common import *  # noqa: F401,F403


class _Response:
    def __init__(self, status, body, headers=None):
        self.status = status
        self._body = body
        self.headers = headers or {}

    async def text(self):
        return json.dumps(self._body)

    async def json(self):
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


class _Atlas:
    """A fake of the two APIs: the public one trades the key, the internal one lists."""

    def __init__(self, employees, groups, auth_status=200, page_size=None):
        self.employees = employees
        self.groups = groups
        self.auth_status = auth_status
        self.page_size = page_size
        self.requests = []

    def __call__(self, *args, **kwargs):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    def post(self, url, json=None):
        self.requests.append(("POST", url, json))
        if self.auth_status != 200:
            return _Response(self.auth_status, {"message": "nope"})
        return _Response(200, {"accessToken": {"publicToken": "svc-token"}})

    def get(self, url, headers=None, params=None):
        self.requests.append(("GET", url, dict(params or {}), dict(headers or {})))
        items = self.groups if url.endswith("/groups") else self.employees
        skip, limit = int(params["skip"]), int(params["limit"])
        if self.page_size:
            limit = min(limit, self.page_size)
        return _Response(200, items[skip:skip + limit])


@contextlib.contextmanager
def _directory(atlas, tmp_path, credentials=True):
    env = {"EMPLOYEE_LIST_ACCESS_KEY_ID": "ak-1", "EMPLOYEE_LIST_SECRET_ACCESS_KEY": "sk-1"} \
        if credentials else {}
    with patch.dict(os.environ, {**env, "HUTBOT_EMPLOYEE_CACHE_FILE": str(tmp_path / "employees.json"),
                                 "HUTBOT_EMPLOYEE_FALLBACK_FILE": str(tmp_path / "fallback.json")}), \
         patch('employee_list.aiohttp.ClientSession', atlas):
        if not credentials:
            os.environ.pop("EMPLOYEE_LIST_ACCESS_KEY_ID", None)
            os.environ.pop("EMPLOYEE_LIST_SECRET_ACCESS_KEY", None)
        yield


GROUPS = [{"id": "g-sw", "name": "Software"}, {"id": "g-m3", "name": "m-kubed (m³)"}]


def _employee(ad_name, forename, surname, group_id, **extra):
    return {"id": f"id-{ad_name}", "source": "ad", "adName": ad_name, "forename": forename,
            "surname": surname, "groupId": group_id, "email": f"{ad_name}@example.com", **extra}


@pytest.mark.asyncio
async def test_atlas_employees_become_records_with_their_group_name(tmp_path):
    atlas = _Atlas([_employee("edfriesen", "Edwin", "Friesen", "g-m3"),
                    _employee("jdoe", "Jane", "Doe", "g-sw")], GROUPS)
    with _directory(atlas, tmp_path):
        employees = await employee_list.load_employees()

    assert employees["edfriesen"]["group"] == "m-kubed (m³)"
    assert employees["edfriesen"]["fullname"] == "Edwin Friesen"
    assert employees["jdoe"]["group"] == "Software"
    # The cache keeps the record shape older versions and the fallback file share.
    cached = json.loads((tmp_path / "employees.json").read_text())
    assert cached[0] == {"ad_name": "edfriesen", "fullname": "Edwin Friesen", "group": "m-kubed (m³)",
                         "mail": "edfriesen@example.com", "is_deleted": False}


@pytest.mark.asyncio
async def test_the_service_key_is_traded_for_the_token_the_listing_sends(tmp_path):
    atlas = _Atlas([], GROUPS)
    with _directory(atlas, tmp_path):
        await employee_list.fetch_employees()

    method, url, body = atlas.requests[0]
    assert (method, url, body) == (
        "POST", "https://api-public.prod.mittwald.systems/v2/services/ak-1/actions/authenticate",
        {"secretAccessKey": "sk-1"})
    listing = [r for r in atlas.requests if r[0] == "GET" and r[1].endswith("/employees")][0]
    assert listing[1] == "https://api.prod.mittwald.systems/internal-v2/employees"
    assert listing[3]["x-access-token"] == "svc-token"


@pytest.mark.asyncio
async def test_archived_and_ignored_employees_are_left_out(tmp_path):
    atlas = _Atlas([_employee("gone", "Gone", "Away", "g-sw", archivedAt="2026-01-01T00:00:00Z"),
                    _employee("skip", "Skip", "Me", "g-sw", isIgnored=True),
                    _employee("here", "Still", "Here", "g-sw"),
                    {"id": "no-ad", "source": "manual", "forename": "No", "surname": "Account"}],
                   GROUPS)
    with _directory(atlas, tmp_path):
        employees = await employee_list.fetch_employees()

    assert set(employees) == {"here"}


@pytest.mark.asyncio
async def test_every_page_of_the_listing_is_read(tmp_path, monkeypatch):
    monkeypatch.setattr(employee_list, "_EMPLOYEE_PAGE_SIZE", 2)
    atlas = _Atlas([_employee(f"user{i}", "U", str(i), "g-sw") for i in range(5)], GROUPS)
    with _directory(atlas, tmp_path):
        employees = await employee_list.fetch_employees()

    assert len(employees) == 5
    skips = [r[2]["skip"] for r in atlas.requests if r[0] == "GET" and r[1].endswith("/employees")]
    assert skips == ["0", "2", "4"]


@pytest.mark.asyncio
async def test_a_refused_key_falls_back_to_the_disk_cache(tmp_path, capsys):
    (tmp_path / "employees.json").write_text(json.dumps(
        [{"ad_name": "cached", "fullname": "Cached One", "group": "Support"}]))
    atlas = _Atlas([], GROUPS, auth_status=403)
    with _directory(atlas, tmp_path):
        assert await employee_list.fetch_employees() is None
        employees = await employee_list.load_employees()

    assert set(employees) == {"cached"}
    assert "Authenticating against the employee directory failed with status 403" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_without_a_key_pair_nothing_is_requested(tmp_path):
    atlas = _Atlas([], GROUPS)
    with _directory(atlas, tmp_path, credentials=False):
        assert await employee_list.fetch_employees() is None
    assert atlas.requests == []
