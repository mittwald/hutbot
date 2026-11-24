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
    env.update({"EMPLOYEE_LIST_API_URL": "https://api.example.com/internal/",
                "EMPLOYEE_LIST_AUTH_URL": "https://auth.example.com/v2"})
    with patch.dict(os.environ, {**env, "HUTBOT_EMPLOYEE_CACHE_FILE": str(tmp_path / "employees.json"),
                                 "HUTBOT_EMPLOYEE_FALLBACK_FILE": str(tmp_path / "fallback.json")}), \
         patch('employee_list.aiohttp.ClientSession', atlas):
        if not credentials:
            os.environ.pop("EMPLOYEE_LIST_ACCESS_KEY_ID", None)
            os.environ.pop("EMPLOYEE_LIST_SECRET_ACCESS_KEY", None)
        yield


GROUPS = [{"id": "g-sw", "name": "Software"}, {"id": "g-m3", "name": "Cloud (c³)"}]


def _employee(ad_name, forename, surname, group_id, **extra):
    return {"id": f"id-{ad_name}", "source": "ad", "adName": ad_name, "forename": forename,
            "surname": surname, "groupId": group_id, "email": f"{ad_name}@example.com", **extra}


@pytest.mark.asyncio
async def test_atlas_employees_become_records_with_their_group_name(tmp_path):
    atlas = _Atlas([_employee("edschmidt", "Edwin", "Schmidt", "g-m3"),
                    _employee("jdoe", "Jane", "Doe", "g-sw")], GROUPS)
    with _directory(atlas, tmp_path):
        employees = await employee_list.load_employees()

    assert employees["edschmidt"]["group"] == "Cloud (c³)"
    assert employees["edschmidt"]["fullname"] == "Edwin Schmidt"
    assert employees["jdoe"]["group"] == "Software"
    # The cache keeps the record shape older versions and the fallback file share.
    cached = json.loads((tmp_path / "employees.json").read_text())
    assert cached[0] == {"ad_name": "edschmidt", "fullname": "Edwin Schmidt", "group": "Cloud (c³)",
                         "mail": "edschmidt@example.com", "is_deleted": False}


@pytest.mark.asyncio
async def test_the_service_key_is_traded_for_the_token_the_listing_sends(tmp_path):
    atlas = _Atlas([], GROUPS)
    with _directory(atlas, tmp_path):
        await employee_list.fetch_employees()

    method, url, body = atlas.requests[0]
    assert (method, url, body) == (
        "POST", "https://auth.example.com/v2/services/ak-1/actions/authenticate",
        {"secretAccessKey": "sk-1"})
    listing = [r for r in atlas.requests if r[0] == "GET" and r[1].endswith("/employees")][0]
    # A trailing slash on the base URL does not double up.
    assert listing[1] == "https://api.example.com/internal/employees"
    assert listing[3]["x-access-token"] == "svc-token"


@pytest.mark.parametrize("unset", ["EMPLOYEE_LIST_API_URL", "EMPLOYEE_LIST_AUTH_URL"])
@pytest.mark.asyncio
async def test_without_both_urls_the_directory_is_never_read(tmp_path, unset, capsys, monkeypatch):
    monkeypatch.setattr(employee_list, "_warned_missing_urls", False)
    atlas = _Atlas([], GROUPS)
    with _directory(atlas, tmp_path):
        os.environ.pop(unset)
        assert await employee_list.fetch_employees() is None
        assert employee_list.employee_credentials() == ("", "")

    assert not atlas.requests
    assert capsys.readouterr().err.count("must both be set") == 1


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


# ----- CardDAV department fallback -----

def _vcard(email, org=None, *, group_prefix=False):
    lines = ["BEGIN:VCARD", "VERSION:3.0", "FN:Somebody"]
    lines.append(f"{'item1.' if group_prefix else ''}EMAIL;TYPE=INTERNET,PREF:{email}")
    if org is not None:
        lines.append(f"ORG:{org}")
    lines.append("END:VCARD")
    return "\r\n".join(lines) + "\r\n"


def _multistatus(*cards):
    responses = "".join(
        f'<D:response><D:href>/carddav/books/directory/{i}.vcf</D:href><D:propstat><D:prop>'
        f'<C:address-data>{card.replace("&", "&amp;").replace("<", "&lt;")}</C:address-data>'
        f'</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>'
        for i, card in enumerate(cards))
    return ('<?xml version="1.0" encoding="UTF-8"?><D:multistatus xmlns:D="DAV:" '
            f'xmlns:C="urn:ietf:params:xml:ns:carddav">{responses}</D:multistatus>').encode()


class _Body:
    """A response body that arrives in small pieces, the way a real network delivers it."""

    def __init__(self, data):
        self._data = data

    async def iter_chunked(self, n):
        for i in range(0, len(self._data), 97):
            yield self._data[i:i + 97]


class _DavResponse(_Response):
    def __init__(self, status, data):
        super().__init__(status, None)
        self.content = _Body(data)


class _AtlasWithDirectory(_Atlas):
    """Atlas plus the bridge's CardDAV book, both behind the one patched ClientSession."""

    def __init__(self, employees, groups, cards=(), dav_status=207, **kwargs):
        super().__init__(employees, groups, **kwargs)
        self.cards = cards
        self.dav_status = dav_status

    def request(self, method, url, data=None, headers=None):
        self.requests.append((method, url, data, dict(headers or {})))
        return _DavResponse(self.dav_status, _multistatus(*self.cards))


DIRECTORY_GROUPS = [{"id": "g-it", "name": "Infrastructure/Engineering"}, {"id": "g-mail", "name": "Mail"},
                    {"id": "g-pm", "name": "Product Management"},
                    {"id": "g-old", "name": "Altlast", "archivedAt": "2025-01-01T00:00:00Z"}]


_DIRECTORY_URL = "https://bridge.example.com/carddav/books/directory/"


@contextlib.contextmanager
def _with_token(token="cafe0123"):
    with patch.dict(os.environ, {"HUTBOT_DIRECTORY_CARDDAV_TOKEN": token,
                                 "HUTBOT_DIRECTORY_CARDDAV_URL": _DIRECTORY_URL,
                                 "HUTBOT_DIRECTORY_CARDDAV_USER": "directory"}):
        yield


@pytest.mark.asyncio
async def test_an_employee_without_a_group_takes_the_department_from_the_directory(tmp_path):
    atlas = _AtlasWithDirectory(
        [_employee("lbg", "Lena", "B", None), _employee("pm", "Pia", "M", None),
         _employee("mail", "Max", "Mail", None), _employee("placed", "Paul", "P", "g-mail")],
        DIRECTORY_GROUPS,
        cards=[_vcard("LBG@example.com", "Example Corp;Infrastructure"),
               _vcard("pm@example.com", "Example Corp;Productmanagement", group_prefix=True),
               _vcard("mail@example.com", "Example Corp;Infrastructure - Mail"),
               _vcard("placed@example.com", "Example Corp;Productmanagement")])
    with _directory(atlas, tmp_path), _with_token():
        employees = await employee_list.fetch_employees()

    assert employees["lbg"]["group"] == "Infrastructure/Engineering"
    assert employees["pm"]["group"] == "Product Management"
    assert employees["mail"]["group"] == "Mail"
    # Atlas's own group always wins; the directory is only a fallback.
    assert employees["placed"]["group"] == "Mail"
    # The placement is cached with the rest, for when Atlas is down at the next start.
    cached = {r["ad_name"]: r["group"] for r in json.loads((tmp_path / "employees.json").read_text())}
    assert cached["lbg"] == "Infrastructure/Engineering"
    dav = [r for r in atlas.requests if r[0] == "REPORT"]
    assert len(dav) == 1
    assert dav[0][1] == _DIRECTORY_URL
    assert dav[0][3]["Authorization"] == "Basic " + base64.b64encode(b"directory:cafe0123").decode()
    assert b"addressbook-query" in dav[0][2]
    assert dav[0][3]["Depth"] == "1"


@pytest.mark.asyncio
async def test_a_department_no_group_matches_is_kept_as_written(tmp_path):
    atlas = _AtlasWithDirectory([_employee("cs", "Z", "S", None)], DIRECTORY_GROUPS,
                                cards=[_vcard("cs@example.com", "Example Corp;CS")])
    with _directory(atlas, tmp_path), _with_token():
        employees = await employee_list.fetch_employees()

    assert employees["cs"]["group"] == "CS"


@pytest.mark.asyncio
async def test_the_directory_is_not_read_when_every_employee_has_a_group(tmp_path):
    atlas = _AtlasWithDirectory([_employee("placed", "Paul", "P", "g-mail")], DIRECTORY_GROUPS)
    with _directory(atlas, tmp_path), _with_token():
        await employee_list.fetch_employees()

    assert not [r for r in atlas.requests if r[0] == "REPORT"]


@pytest.mark.asyncio
async def test_without_a_token_the_directory_is_never_read(tmp_path):
    atlas = _AtlasWithDirectory([_employee("lbg", "Lena", "B", None)], DIRECTORY_GROUPS,
                                cards=[_vcard("lbg@example.com", "X;Infrastructure")])
    with _directory(atlas, tmp_path), patch.dict(os.environ, {}, clear=False):
        os.environ.pop("HUTBOT_DIRECTORY_CARDDAV_TOKEN", None)
        employees = await employee_list.fetch_employees()

    assert employees["lbg"]["group"] == ""
    assert not [r for r in atlas.requests if r[0] == "REPORT"]


@pytest.mark.parametrize("unset", ["HUTBOT_DIRECTORY_CARDDAV_URL", "HUTBOT_DIRECTORY_CARDDAV_USER"])
@pytest.mark.asyncio
async def test_without_a_url_or_user_the_directory_is_never_read(tmp_path, unset):
    atlas = _AtlasWithDirectory([_employee("lbg", "Lena", "B", None)], DIRECTORY_GROUPS,
                                cards=[_vcard("lbg@example.com", "X;Infrastructure")])
    with _directory(atlas, tmp_path), _with_token():
        os.environ.pop(unset)
        employees = await employee_list.fetch_employees()

    assert employees["lbg"]["group"] == ""
    assert not [r for r in atlas.requests if r[0] == "REPORT"]


@pytest.mark.asyncio
async def test_a_failing_directory_leaves_atlas_alone(tmp_path, capsys):
    atlas = _AtlasWithDirectory([_employee("lbg", "Lena", "B", None), _employee("ok", "O", "K", "g-mail")],
                                DIRECTORY_GROUPS, dav_status=401)
    with _directory(atlas, tmp_path), _with_token():
        employees = await employee_list.fetch_employees()

    assert employees["lbg"]["group"] == ""
    assert employees["ok"]["group"] == "Mail"
    assert "Reading the CardDAV directory failed with status 401" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_an_empty_directory_changes_nothing(tmp_path, capsys):
    atlas = _AtlasWithDirectory([_employee("lbg", "Lena", "B", None)], DIRECTORY_GROUPS, cards=[])
    with _directory(atlas, tmp_path), _with_token():
        employees = await employee_list.fetch_employees()

    assert employees["lbg"]["group"] == ""
    assert "no departments yet" in capsys.readouterr().err


def test_vcard_departments_unfold_unescape_and_key_on_every_address():
    card = ("BEGIN:VCARD\r\nVERSION:3.0\r\nEMAIL;TYPE=INTERNET:A@Example.com\r\nEMAIL:b@example.com\r\n"
            "ORG:Example\\, Corp;Development - Hosting\r\n  Add-Ons\r\nEND:VCARD\r\n")
    assert employee_list.card_departments([card, _vcard("c@example.com", "Only a company")]) == {
        "a@example.com": "Development - Hosting Add-Ons",
        "b@example.com": "Development - Hosting Add-Ons",
    }


@pytest.mark.asyncio
async def test_an_oversized_directory_answer_is_refused(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(employee_list, "_DIRECTORY_MAX_BYTES", 100)
    atlas = _AtlasWithDirectory([_employee("lbg", "Lena", "B", None)], DIRECTORY_GROUPS,
                                cards=[_vcard("lbg@example.com", "X;Infrastructure")])
    with _directory(atlas, tmp_path), _with_token():
        employees = await employee_list.fetch_employees()

    assert employees["lbg"]["group"] == ""
    assert "more than 100 bytes" in capsys.readouterr().err


def test_a_hex_token_is_never_taken_for_base64():
    token = "0123456789abcdef0123456789abcdef0123456789abcdef"
    with _with_token(token):
        assert employee_list.directory_carddav_settings()[2] == token


# ----- EMPLOYEE_LIST_DEPARTMENT_MAPPINGS -----

_ATLAS_GROUPS = ["Infrastructure/Engineering", "Mail", "Controlling", "Central Services"]


def test_a_department_mapping_turns_an_abbreviation_into_a_team():
    with patch.dict(os.environ, {"EMPLOYEE_LIST_DEPARTMENT_MAPPINGS": "C.S.=Central Services"}):
        mappings = employee_list.load_department_mappings()
    assert employee_list.resolve_department("CS", _ATLAS_GROUPS, mappings) == "Central Services"
    # A more specific part that names a group still wins over the mapped department.
    assert employee_list.resolve_department("CS - Controlling", _ATLAS_GROUPS, mappings) == "Controlling"
    # Without the mapping the abbreviation stays as written.
    assert employee_list.resolve_department("CS", _ATLAS_GROUPS) == "CS"


def test_a_department_mapping_wins_over_the_automatic_match():
    with patch.dict(os.environ, {"EMPLOYEE_LIST_DEPARTMENT_MAPPINGS": "Infrastructure=Mail"}):
        mappings = employee_list.load_department_mappings()
    assert employee_list.resolve_department("Infrastructure", _ATLAS_GROUPS, mappings) == "Mail"


def test_malformed_team_mappings_are_skipped_and_the_first_entry_wins(capsys):
    raw = "CS=Central Services, broken ,=NoKey,NoTeam=,cs=Other"
    with patch.dict(os.environ, {"EMPLOYEE_LIST_DEPARTMENT_MAPPINGS": raw}):
        assert employee_list.load_department_mappings() == {"cs": "Central Services"}
    err = capsys.readouterr().err
    assert "'broken'" in err and "'=NoKey'" in err and "'NoTeam='" in err


def test_usergroup_mappings_keep_their_order_and_lowercase_the_part():
    # Plain letters are valid base64 too; the value must be read as written.
    with patch.dict(os.environ, {"EMPLOYEE_LIST_USERGROUP_MAPPINGS": "Cloud-Ops=Cloud (c³),abcd=Team"}):
        assert employee_list.load_usergroup_mappings() == [("cloud-ops", "Cloud (c³)"), ("abcd", "Team")]


@pytest.mark.asyncio
async def test_the_carddav_fallback_applies_the_department_mapping_and_marks_its_records(tmp_path):
    atlas = _AtlasWithDirectory([_employee("cs", "Z", "S", None), _employee("ok", "O", "K", "g-mail")],
                                DIRECTORY_GROUPS + [{"id": "g-cs", "name": "Central Services"}],
                                cards=[_vcard("cs@example.com", "Example Corp;CS")])
    with _directory(atlas, tmp_path), _with_token(), \
         patch.dict(os.environ, {"EMPLOYEE_LIST_DEPARTMENT_MAPPINGS": "CS=Central Services"}):
        employees = await employee_list.fetch_employees()

    assert employees["cs"]["group"] == "Central Services"
    assert employees["cs"]["group_source"] == employee_list.GROUP_SOURCE_DIRECTORY
    assert "group_source" not in employees["ok"]
