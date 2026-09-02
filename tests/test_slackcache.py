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
