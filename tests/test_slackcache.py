"""Slack lookups that the caches cannot answer — bot ids above all."""

from tests._common import *  # noqa: F401,F403


def test_a_bot_id_is_told_apart_from_a_user_id():
    assert hutbot.slackcache.is_bot_id("B08BSKV9CMB") is True
    assert hutbot.slackcache.is_bot_id("U12345") is False
    assert hutbot.slackcache.is_bot_id("W12345") is False
    assert hutbot.slackcache.is_bot_id("") is False


@pytest.mark.asyncio
async def test_a_bot_without_a_bot_user_becomes_a_user_built_from_its_name():
    app = AsyncMock()
    app.client.bots_info.return_value = {"ok": True, "bot": {"id": "B08BSKV9CMB", "name": "Alertmanager"}}

    user = await hutbot.slackcache.fetch_bot_by_id(app, "B08BSKV9CMB")

    app.client.bots_info.assert_awaited_once_with(bot="B08BSKV9CMB")
    app.client.users_info.assert_not_awaited()
    assert user == User(id="B08BSKV9CMB", name="alertmanager", real_name="Alertmanager",
                        team=TEAM_UNKNOWN, is_bot=True)
    # Filed under the id the next message from this app will carry, so it is asked for once.
    assert hutbot.state.id_user_cache["B08BSKV9CMB"] == user
    assert hutbot.state.user_id_cache["alertmanager"] == user


@pytest.mark.asyncio
async def test_a_bot_with_a_bot_user_is_resolved_to_that_user():
    app = AsyncMock()
    app.client.bots_info.return_value = {
        "ok": True, "bot": {"id": "B1", "name": "grafana", "user_id": "U9"},
    }
    app.client.users_info.return_value = {
        "user": {"id": "U9", "name": "grafana", "real_name": "Grafana", "is_bot": True, "profile": {}},
    }

    with patch('hutbot.slackcache.load_employees', new=AsyncMock(return_value={})), \
         patch('hutbot.slackcache.load_employee_mappings', return_value={}):
        user = await hutbot.slackcache.fetch_bot_by_id(app, "B1")

    assert user.id == "U9" and user.real_name == "Grafana" and user.is_bot is True
    # Both ids lead to it: the bot user for a message that carries `user`, the bot id for one
    # that carries only `bot_id`.
    assert hutbot.state.id_user_cache["U9"] == user
    assert hutbot.state.id_user_cache["B1"] == user


@pytest.mark.asyncio
async def test_a_bot_user_already_cached_is_not_fetched_again():
    app = AsyncMock()
    app.client.bots_info.return_value = {"ok": True, "bot": {"id": "B1", "name": "grafana", "user_id": "U9"}}
    cached = User(id="U9", name="grafana", real_name="Grafana", team=TEAM_UNKNOWN, is_bot=True)
    hutbot.state.id_user_cache["U9"] = cached

    assert await hutbot.slackcache.fetch_bot_by_id(app, "B1") == cached
    app.client.users_info.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_bot_slack_cannot_name_resolves_to_nobody(capsys):
    app = AsyncMock()
    app.client.bots_info.return_value = {"ok": True, "bot": {"id": "B1", "name": "  "}}

    assert await hutbot.slackcache.fetch_bot_by_id(app, "B1") is None
    assert "Slack knows bot `B1` but gave it no name." in capsys.readouterr().err


@pytest.mark.asyncio
async def test_a_message_from_an_app_asks_bots_info_and_not_users_info():
    # The lookup that used to answer `user_not_found` for every message from this app.
    app = AsyncMock()
    app.client.bots_info.return_value = {"ok": True, "bot": {"id": "B08BSKV9CMB", "name": "Alertmanager"}}

    with patch('hutbot.slackcache.update_user_cache', new=AsyncMock()):
        user = await hutbot.slackcache.get_user_by_id(app, "B08BSKV9CMB")
        # The second message from the same app is a cache hit.
        again = await hutbot.slackcache.get_user_by_id(app, "B08BSKV9CMB")

    app.client.users_info.assert_not_awaited()
    assert app.client.bots_info.await_count == 1
    assert user == again
    assert user.real_name == "Alertmanager" and user.is_bot is True


@pytest.mark.asyncio
async def test_a_bot_lookup_that_fails_still_leaves_a_usable_user(capsys):
    app = AsyncMock()
    app.client.bots_info.side_effect = SlackApiError("nope", {"ok": False, "error": "bot_not_found"})

    with patch('hutbot.slackcache.update_user_cache', new=AsyncMock()):
        user = await hutbot.slackcache.get_user_by_id(app, "B08BSKV9CMB")

    # The same fallback a failed user lookup gets: the id stands in for the name.
    assert user == User(id="B08BSKV9CMB", name="B08BSKV9CMB", real_name="", team=TEAM_UNKNOWN)
    assert "Failed to fetch bot `B08BSKV9CMB`:" in capsys.readouterr().err


# ----- user cache refresh -----

def _member(uid, name, real_name, email):
    return {"id": uid, "name": name, "real_name": real_name, "profile": {"email": email}}


def _users_list(*members):
    return {"members": list(members), "response_metadata": {"next_cursor": ""}}


@pytest.mark.asyncio
async def test_a_refresh_picks_up_a_team_change_and_drops_departed_accounts(capsys):
    app = AsyncMock()
    app.client.users_list.return_value = _users_list(
        _member("U1", "a.alpha", "Anna Alpha", "a.alpha@example.com"),
        _member("U2", "b.beta", "Bert Beta", "b.beta@example.com"))
    employees = {"a.alpha": {"fullname": "Anna Alpha", "group": "Support"},
                 "b.beta": {"fullname": "Bert Beta", "group": "Platform"}}
    with patch('hutbot.slackcache.load_employees', new=AsyncMock(return_value=employees)), \
         patch('hutbot.slackcache.load_employee_mappings', return_value={}):
        await hutbot.slackcache.update_user_cache(app)
        assert hutbot.state.id_user_cache["U1"].team == "Support"

        # Anna moves team, Bert leaves the workspace.
        employees = {"a.alpha": {"fullname": "Anna Alpha", "group": "Software"}}
        app.client.users_list.return_value = _users_list(
            _member("U1", "a.alpha", "Anna Alpha", "a.alpha@example.com"))
        with patch('hutbot.slackcache.fetch_employees', new=AsyncMock(return_value=employees)):
            assert await hutbot.slackcache.refresh_user_cache(app) is True

    assert hutbot.state.id_user_cache["U1"].team == "Software"
    assert hutbot.state.user_id_cache["a.alpha"].team == "Software"
    assert hutbot.state.user_email_cache["a.alpha@example.com"].team == "Software"
    assert "U2" not in hutbot.state.id_user_cache
    assert "b.beta" not in hutbot.state.user_id_cache
    assert hutbot.state.team_cache == {"Software"}
    assert "User cache refreshed: 1 users, 1 team changes." in capsys.readouterr().out


@pytest.mark.asyncio
async def test_a_refresh_keeps_bots_that_users_list_leaves_out():
    app = AsyncMock()
    bot = User(id="B1", name="alertmanager", real_name="Alertmanager", team=TEAM_UNKNOWN, is_bot=True)
    hutbot.slackcache.cache_user("", bot)
    app.client.users_list.return_value = _users_list(
        _member("U1", "a.alpha", "Anna Alpha", "a.alpha@example.com"))
    with patch('hutbot.slackcache.fetch_employees', new=AsyncMock(return_value={})), \
         patch('hutbot.slackcache.load_employee_mappings', return_value={}):
        assert await hutbot.slackcache.refresh_user_cache(app) is True

    assert hutbot.state.id_user_cache["B1"] == bot
    assert hutbot.state.user_id_cache["alertmanager"] == bot
    assert "U1" in hutbot.state.id_user_cache


@pytest.mark.asyncio
async def test_a_failed_refresh_keeps_the_caches_it_had():
    app = AsyncMock()
    anna = User(id="U1", name="a.alpha", real_name="Anna Alpha", team="Support")
    hutbot.slackcache.cache_user("a.alpha@example.com", anna)
    app.client.users_list.side_effect = SlackApiError("nope", {"ok": False, "error": "invalid_auth"})
    with patch('hutbot.slackcache.fetch_employees', new=AsyncMock(return_value={"a.alpha": {"group": "X"}})), \
         patch('hutbot.slackcache.load_employee_mappings', return_value={}):
        assert await hutbot.slackcache.refresh_user_cache(app) is False

    assert hutbot.state.id_user_cache == {"U1": anna}
    assert hutbot.state.team_cache == {"Support"}


@pytest.mark.asyncio
async def test_a_refresh_keeps_the_caches_while_the_employee_directory_is_down(capsys):
    """Its disk cache may be gone too, and fallback records alone would wipe the other teams."""
    app = AsyncMock()
    anna = User(id="U1", name="a.alpha", real_name="Anna Alpha", team="Support")
    hutbot.slackcache.cache_user("a.alpha@example.com", anna)
    with patch('hutbot.slackcache.fetch_employees', new=AsyncMock(return_value=None)), \
         patch('hutbot.slackcache.employee_credentials', return_value=("ak", "sk")):
        assert await hutbot.slackcache.refresh_user_cache(app) is False

    app.client.users_list.assert_not_awaited()
    assert hutbot.state.id_user_cache["U1"].team == "Support"
    assert "Keeping the user cache: the employee directory could not be read." in capsys.readouterr().err


@pytest.mark.asyncio
async def test_a_refresh_without_a_directory_reads_the_disk_cache():
    app = AsyncMock()
    app.client.users_list.return_value = _users_list(
        _member("U1", "a.alpha", "Anna Alpha", "a.alpha@example.com"))
    from_disk = {"a.alpha": {"fullname": "Anna Alpha", "group": "Support"}}
    with patch('hutbot.slackcache.fetch_employees', new=AsyncMock(return_value=None)), \
         patch('hutbot.slackcache.employee_credentials', return_value=("", "")), \
         patch('hutbot.slackcache.load_employees_from_disk', new=AsyncMock(return_value=from_disk)), \
         patch('hutbot.slackcache.load_employee_mappings', return_value={}):
        assert await hutbot.slackcache.refresh_user_cache(app) is True

    assert hutbot.state.id_user_cache["U1"].team == "Support"


def test_an_unmapped_user_is_warned_about_once():
    employees = {"other": {"fullname": "Someone Else", "group": "Support"}}
    member = _member("U1", "e.binek", "Eva Binek", "e.binek@example.com")
    with patch('hutbot.slackcache.log_warning') as mock_log_warning:
        hutbot.slackcache.build_user(member, employees, {})
        hutbot.slackcache.build_user(member, employees, {})

    assert mock_log_warning.call_count == 1


_DEFAULT_TIMES = (datetime.time(6), datetime.time(12), datetime.time(20))


@pytest.mark.parametrize("raw, expected", [
    (None, _DEFAULT_TIMES),
    ("", _DEFAULT_TIMES),
    ("off", ()),
    ("OFF", ()),
    ("19:30, 07:00", (datetime.time(7), datetime.time(19, 30))),
    ("07:00,bogus", (datetime.time(7),)),
    ("bogus", _DEFAULT_TIMES),
    ("06:00Z,12:00", (datetime.time(12),)),
    ("06:00+01:00", _DEFAULT_TIMES),
])
def test_the_user_cache_refresh_times_are_read_from_the_environment(monkeypatch, raw, expected):
    if raw is None:
        monkeypatch.delenv('HUTBOT_USER_CACHE_REFRESH_TIMES', raising=False)
    else:
        monkeypatch.setenv('HUTBOT_USER_CACHE_REFRESH_TIMES', raw)
    assert hutbot.slackcache.user_cache_refresh_times() == expected


@pytest.mark.parametrize("now, expected", [
    ("2026-11-20 05:59", "2026-11-20 06:00"),
    ("2026-11-20 06:00", "2026-11-20 12:00"),
    ("2026-11-20 13:15", "2026-11-20 20:00"),
    ("2026-11-20 20:00", "2026-11-21 06:00"),
    ("2026-11-20 23:59", "2026-11-21 06:00"),
])
def test_the_next_refresh_is_the_next_time_of_day(now, expected):
    parse = lambda v: datetime.datetime.strptime(v, "%Y-%m-%d %H:%M")
    assert hutbot.slackcache.next_user_cache_refresh(parse(now), _DEFAULT_TIMES) == parse(expected)


@pytest.mark.asyncio
async def test_off_starts_no_refresh_loop(monkeypatch):
    monkeypatch.setenv('HUTBOT_USER_CACHE_REFRESH_TIMES', 'off')
    with patch('hutbot.slackcache.refresh_user_cache', new=AsyncMock()) as refresh:
        await hutbot.slackcache.run_user_cache_refresh_loop(AsyncMock())
    refresh.assert_not_awaited()


@pytest.mark.asyncio
async def test_the_refresh_loop_waits_for_the_next_time_and_retries_a_failed_turn(monkeypatch):
    monkeypatch.setenv('HUTBOT_USER_CACHE_REFRESH_TIMES', '06:00,12:00,20:00')
    clock = {"now": datetime.datetime(2026, 11, 20, 5, 0)}
    sleeps = []

    class _Clock(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return clock["now"]

    async def fake_sleep(seconds):
        sleeps.append(round(seconds))
        if len(sleeps) > 3:
            raise asyncio.CancelledError
        clock["now"] += datetime.timedelta(seconds=seconds)

    refresh = AsyncMock(side_effect=[RuntimeError("boom"), False, True])
    with patch('hutbot.slackcache.datetime.datetime', _Clock), \
         patch('hutbot.slackcache.time.time', side_effect=lambda: clock["now"].timestamp()), \
         patch('hutbot.slackcache.asyncio.sleep', new=fake_sleep), \
         patch('hutbot.slackcache.refresh_user_cache', new=refresh):
        with pytest.raises(asyncio.CancelledError):
            await hutbot.slackcache.run_user_cache_refresh_loop(AsyncMock())

    # 05:00 -> 06:00; it fails and is tried 15 minutes later, twice; the success waits for 12:00.
    assert sleeps == [3600, 900, 900, 5 * 3600 + 1800]
    assert refresh.await_count == 3


# ----- matching a Slack user to an employee -----

_SCHMIDTS = {
    "edschmidt": {"ad_name": "edschmidt", "fullname": "Edwin Schmidt", "group": "Cloud (c³)",
                  "mail": "Ed.Schmidt@example.com"},
    "eschmidt": {"ad_name": "eschmidt", "fullname": "Elias Schmidt", "group": "Software",
                 "mail": "E.Schmidt@example.com"},
    "lmeyerlang": {"ad_name": "lmeyerlang", "fullname": "Anna Maria Meyer-Lang",
                     "group": "Software", "mail": "L.Meyer-Lang@example.com"},
}


def test_a_user_is_matched_by_email_when_no_name_fits():
    """`l.meyer-lang` loses only its dot when normalized, and the directory spells it without
    the hyphen too; the full names differ by a middle name. The mailbox is the same."""
    _, user = hutbot.slackcache.build_user(
        _member("U1", "l.meyer-lang", "Anna M. Meyer-Lang", "l.meyer-lang@example.com"),
        _SCHMIDTS, {})
    assert user.team == "Software"


def test_the_email_match_picks_the_right_namesake():
    _, user = hutbot.slackcache.build_user(
        _member("U2", "e.schmidt", "Elias Schmidt", "e.schmidt@example.com"), _SCHMIDTS, {})
    assert user.team == "Software"


def test_an_explicit_mapping_wins_over_the_email_match():
    _, user = hutbot.slackcache.build_user(
        _member("U2", "e.schmidt", "Elias Schmidt", "e.schmidt@example.com"), _SCHMIDTS,
        {"e.schmidt": "edschmidt"})
    assert user.team == "Cloud (c³)"
    assert user.name == "edschmidt"


def test_without_a_matching_email_the_name_still_matches():
    _, user = hutbot.slackcache.build_user(
        _member("U2", "e.schmidt", "Elias Schmidt", "elias@private.example"), _SCHMIDTS, {})
    assert user.team == "Software"


# ----- EMPLOYEE_LIST_USERGROUP_MAPPINGS -----

def _usergroups(*groups):
    return {"ok": True, "usergroups": [{"id": f"S{i}", "handle": handle, "users": users, "date_delete": 0}
                                       for i, (handle, users) in enumerate(groups)]}


_PLACED = {
    "atlas": {"ad_name": "atlas", "fullname": "At Las", "group": "Software", "mail": "atlas@example.com"},
    "dept": {"ad_name": "dept", "fullname": "De Pt", "group": "Infrastructure/Engineering",
             "group_source": "directory", "mail": "dept@example.com"},
    "none": {"ad_name": "none", "fullname": "No Ne", "group": "", "mail": "none@example.com"},
}


@pytest.mark.asyncio
async def test_a_usergroup_mapping_fills_in_only_where_atlas_has_no_group():
    app = AsyncMock()
    app.client.usergroups_list.return_value = _usergroups(
        ("cloud-ops", ["U1", "U2", "U3", "U4", "U5"]), ("team-internal-it", ["U3"]))
    with patch.dict(os.environ,
                    {"EMPLOYEE_LIST_USERGROUP_MAPPINGS": "team-internal-it=Internal IT,@Cloud-Ops=Cloud (c³)"}):
        await hutbot.slackcache.refresh_usergroup_teams(app)

    app.client.usergroups_list.assert_awaited_once_with(include_users=True)
    # The first mapping that fits decides: U3 is in both groups.
    assert hutbot.state.usergroup_teams == {"U3": "Internal IT", "U1": "Cloud (c³)", "U2": "Cloud (c³)",
                                            "U4": "Cloud (c³)", "U5": "Cloud (c³)"}

    def team(uid, name, mappings=None):
        return hutbot.slackcache.build_user(_member(uid, name, name, f"{name}@example.com"),
                                            _PLACED, mappings or {})[1].team

    assert team("U1", "atlas") == "Software"            # Atlas's own group wins
    assert team("U2", "dept") == "Cloud (c³)"         # beats the CardDAV department
    assert team("U4", "none") == "Cloud (c³)"         # fills an empty group
    assert team("U5", "stranger") == "Cloud (c³)"     # and a Slack user with no record at all
    assert team("U5", "stranger", {"stranger": "-"}) == TEAM_UNKNOWN  # ignored accounts stay alone
    assert team("U9", "dept") == "Infrastructure/Engineering"  # outside every group: the fallback stays


@pytest.mark.asyncio
async def test_a_handle_matches_whole_and_never_a_piece_of_another(capsys):
    app = AsyncMock()
    app.client.usergroups_list.return_value = _usergroups(
        ("ops-po", ["U1"]), ("devops", ["U2"]), ("OPS", ["U3"]), ("ops", ["U4"]))
    with patch.dict(os.environ, {"EMPLOYEE_LIST_USERGROUP_MAPPINGS": "ops=Operations,dev=Dev"}):
        await hutbot.slackcache.refresh_usergroup_teams(app)

    # Handles compare ignoring case, but only as a whole: `dev` fits nothing.
    assert hutbot.state.usergroup_teams == {"U3": "Operations", "U4": "Operations"}
    assert "No Slack user group has the handle '@dev'" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_without_usergroup_mappings_no_usergroups_are_read():
    hutbot.state.usergroup_teams = {"U1": "Old"}
    app = AsyncMock()
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("EMPLOYEE_LIST_USERGROUP_MAPPINGS", None)
        await hutbot.slackcache.refresh_usergroup_teams(app)
    app.client.usergroups_list.assert_not_awaited()
    assert hutbot.state.usergroup_teams == {}


@pytest.mark.asyncio
async def test_a_failed_usergroup_read_keeps_the_previous_teams(capsys):
    hutbot.state.usergroup_teams = {"U1": "Cloud (c³)"}
    app = AsyncMock()
    app.client.usergroups_list.side_effect = SlackApiError("nope", {"ok": False, "error": "missing_scope"})
    with patch.dict(os.environ, {"EMPLOYEE_LIST_USERGROUP_MAPPINGS": "cloud-ops=Cloud (c³)"}):
        await hutbot.slackcache.refresh_usergroup_teams(app)
    assert hutbot.state.usergroup_teams == {"U1": "Cloud (c³)"}
    assert "Failed to fetch the Slack user groups" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_a_refresh_reads_the_usergroups_before_building_users():
    app = AsyncMock()
    app.client.users_list.return_value = _users_list(_member("U4", "none", "No Ne", "none@example.com"))
    app.client.usergroups_list.return_value = _usergroups(("cloud-ops", ["U4"]))
    with patch('hutbot.slackcache.fetch_employees', new=AsyncMock(return_value=dict(_PLACED))), \
         patch('hutbot.slackcache.load_employee_mappings', return_value={}), \
         patch.dict(os.environ, {"EMPLOYEE_LIST_USERGROUP_MAPPINGS": "cloud-ops=Cloud (c³)"}):
        assert await hutbot.slackcache.refresh_user_cache(app) is True

    assert hutbot.state.id_user_cache["U4"].team == "Cloud (c³)"
    assert "Cloud (c³)" in hutbot.state.team_cache
