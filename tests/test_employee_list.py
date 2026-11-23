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


DIRECTORY_GROUPS = [{"id": "g-it", "name": "Infrastruktur/Technik"}, {"id": "g-mail", "name": "Mail"},
                    {"id": "g-pm", "name": "Produkt Management"},
                    {"id": "g-old", "name": "Altlast", "archivedAt": "2025-01-01T00:00:00Z"}]


@contextlib.contextmanager
def _with_token(token="cafe0123"):
    with patch.dict(os.environ, {"HUTBOT_DIRECTORY_CARDDAV_TOKEN": token}):
        yield


@pytest.mark.asyncio
async def test_an_employee_without_a_group_takes_the_department_from_the_directory(tmp_path):
    atlas = _AtlasWithDirectory(
        [_employee("lbg", "Leon", "B", None), _employee("pm", "Pia", "M", None),
         _employee("mail", "Max", "Mail", None), _employee("placed", "Paul", "P", "g-mail")],
        DIRECTORY_GROUPS,
        cards=[_vcard("LBG@example.com", "Mittwald CM Service;Infrastruktur"),
               _vcard("pm@example.com", "Mittwald CM Service;Produktmanagement", group_prefix=True),
               _vcard("mail@example.com", "Mittwald CM Service;Infrastruktur - Mail"),
               _vcard("placed@example.com", "Mittwald CM Service;Produktmanagement")])
    with _directory(atlas, tmp_path), _with_token():
        employees = await employee_list.fetch_employees()

    assert employees["lbg"]["group"] == "Infrastruktur/Technik"
    assert employees["pm"]["group"] == "Produkt Management"
    assert employees["mail"]["group"] == "Mail"
    # Atlas's own group always wins; the directory is only a fallback.
    assert employees["placed"]["group"] == "Mail"
    # The placement is cached with the rest, for when Atlas is down at the next start.
    cached = {r["ad_name"]: r["group"] for r in json.loads((tmp_path / "employees.json").read_text())}
    assert cached["lbg"] == "Infrastruktur/Technik"
    dav = [r for r in atlas.requests if r[0] == "REPORT"]
    assert len(dav) == 1
    assert dav[0][1] == employee_list.DEFAULT_DIRECTORY_CARDDAV_URL
    assert dav[0][3]["Authorization"] == "Basic " + base64.b64encode(b"mittwald:cafe0123").decode()
    assert b"addressbook-query" in dav[0][2]
    assert dav[0][3]["Depth"] == "1"


@pytest.mark.asyncio
async def test_a_department_no_group_matches_is_kept_as_written(tmp_path):
    atlas = _AtlasWithDirectory([_employee("zsb", "Z", "S", None)], DIRECTORY_GROUPS,
                                cards=[_vcard("zsb@example.com", "Mittwald CM Service;ZSB")])
    with _directory(atlas, tmp_path), _with_token():
        employees = await employee_list.fetch_employees()

    assert employees["zsb"]["group"] == "ZSB"


@pytest.mark.asyncio
async def test_the_directory_is_not_read_when_every_employee_has_a_group(tmp_path):
    atlas = _AtlasWithDirectory([_employee("placed", "Paul", "P", "g-mail")], DIRECTORY_GROUPS)
    with _directory(atlas, tmp_path), _with_token():
        await employee_list.fetch_employees()

    assert not [r for r in atlas.requests if r[0] == "REPORT"]


@pytest.mark.asyncio
async def test_without_a_token_the_directory_is_never_read(tmp_path):
    atlas = _AtlasWithDirectory([_employee("lbg", "Leon", "B", None)], DIRECTORY_GROUPS,
                                cards=[_vcard("lbg@example.com", "X;Infrastruktur")])
    with _directory(atlas, tmp_path), patch.dict(os.environ, {}, clear=False):
        os.environ.pop("HUTBOT_DIRECTORY_CARDDAV_TOKEN", None)
        employees = await employee_list.fetch_employees()

    assert employees["lbg"]["group"] == ""
    assert not [r for r in atlas.requests if r[0] == "REPORT"]


@pytest.mark.asyncio
async def test_a_failing_directory_leaves_atlas_alone(tmp_path, capsys):
    atlas = _AtlasWithDirectory([_employee("lbg", "Leon", "B", None), _employee("ok", "O", "K", "g-mail")],
                                DIRECTORY_GROUPS, dav_status=401)
    with _directory(atlas, tmp_path), _with_token():
        employees = await employee_list.fetch_employees()

    assert employees["lbg"]["group"] == ""
    assert employees["ok"]["group"] == "Mail"
    assert "Reading the CardDAV directory failed with status 401" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_an_empty_directory_changes_nothing(tmp_path, capsys):
    atlas = _AtlasWithDirectory([_employee("lbg", "Leon", "B", None)], DIRECTORY_GROUPS, cards=[])
    with _directory(atlas, tmp_path), _with_token():
        employees = await employee_list.fetch_employees()

    assert employees["lbg"]["group"] == ""
    assert "no departments yet" in capsys.readouterr().err


def test_vcard_departments_unfold_unescape_and_key_on_every_address():
    card = ("BEGIN:VCARD\r\nVERSION:3.0\r\nEMAIL;TYPE=INTERNET:A@Example.com\r\nEMAIL:b@example.com\r\n"
            "ORG:Mittwald\\, CM;Produktentwicklung - Hosting\r\n  Add-Ons\r\nEND:VCARD\r\n")
    assert employee_list.card_departments([card, _vcard("c@example.com", "Only a company")]) == {
        "a@example.com": "Produktentwicklung - Hosting Add-Ons",
        "b@example.com": "Produktentwicklung - Hosting Add-Ons",
    }


@pytest.mark.asyncio
async def test_an_oversized_directory_answer_is_refused(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(employee_list, "_DIRECTORY_MAX_BYTES", 100)
    atlas = _AtlasWithDirectory([_employee("lbg", "Leon", "B", None)], DIRECTORY_GROUPS,
                                cards=[_vcard("lbg@example.com", "X;Infrastruktur")])
    with _directory(atlas, tmp_path), _with_token():
        employees = await employee_list.fetch_employees()

    assert employees["lbg"]["group"] == ""
    assert "more than 100 bytes" in capsys.readouterr().err


def test_a_hex_token_is_never_taken_for_base64():
    token = "2136154b95aa943a36faa49db3f4199891d243049ea68a4d"
    with _with_token(token):
        assert employee_list.directory_carddav_settings()[2] == token
