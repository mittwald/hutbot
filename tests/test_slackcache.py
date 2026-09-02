"""Slack lookups the caches cannot answer: bot ids, and what a conversation is."""

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


# --- channels ---------------------------------------------------------------------------

def _info_app(info=None, error=None):
    app = AsyncMock()
    if error is not None:
        app.client.conversations_info = AsyncMock(side_effect=SlackApiError("no", {"error": error}))
    else:
        app.client.conversations_info = AsyncMock(return_value={"channel": info})
    return app


@pytest.mark.asyncio
async def test_a_channel_is_looked_up_once_and_then_served_from_the_cache():
    # Every rule list needs one lookup per conversation it shows, so an uncached one is one
    # `conversations.info` per entry on every render of the App Home tab and the web UI.
    app = _info_app(_channel_info("general"))
    assert await hutbot.slackcache.get_channel_name(app, "C12345") == "general"
    assert await hutbot.slackcache.is_configurable_channel(app, "C12345") is True
    assert app.client.conversations_info.await_count == 1


@pytest.mark.asyncio
async def test_a_stale_lookup_is_made_again():
    app = _info_app(_channel_info("general"))
    await hutbot.slackcache.get_channel_name(app, "C12345")
    stamp, info = hutbot.state._channel_info_cache["C12345"]
    hutbot.state._channel_info_cache["C12345"] = (
        stamp - hutbot.slackcache._CHANNEL_INFO_TTL - 1, info)
    await hutbot.slackcache.get_channel_name(app, "C12345")
    assert app.client.conversations_info.await_count == 2


@pytest.mark.asyncio
async def test_a_failed_lookup_is_not_cached():
    # Otherwise a channel the bot momentarily could not read would be written off — printed
    # by its id and hidden from both UIs — for the next five minutes.
    app = _info_app(error="ratelimited")
    assert await hutbot.slackcache.get_channel_name(app, "C12345") == "C12345"
    assert "C12345" not in hutbot.state._channel_info_cache


@pytest.mark.asyncio
async def test_a_conversation_without_a_name_is_still_cached():
    # A DM has no name, which is a stable answer rather than a failed lookup.
    app = _info_app(_channel_info("", is_im=True, is_channel=False, is_member=None))
    assert await hutbot.slackcache.get_channel_name(app, "D12345") == "D12345"
    assert "D12345" in hutbot.state._channel_info_cache
    await hutbot.slackcache.get_channel_name(app, "D12345")
    assert app.client.conversations_info.await_count == 1


# --- which conversations a rule can live in -------------------------------------------
# The cases are the ones the dev instance actually had in `bot.json`.

@pytest.mark.asyncio
async def test_a_private_channel_the_bot_is_in_is_configurable():
    app = _info_app(_channel_info("davetest", is_private=True))
    assert await hutbot.slackcache.is_configurable_channel(app, "C02CGL76M8C") is True


@pytest.mark.asyncio
async def test_a_group_dm_is_not_configurable_even_though_slack_calls_it_a_channel():
    # The trap: Slack reports `is_channel` for a group DM as well as `is_mpim`, so testing
    # for the absence of `is_channel` would let one through.
    info = _channel_info("mpdm-hutbotdev--d.grieser--f.gueney-1", is_mpim=True)
    assert info["is_channel"] is True
    app = _info_app(info)
    assert await hutbot.slackcache.is_configurable_channel(app, "C0BPUU33ABW") is False


@pytest.mark.asyncio
async def test_a_direct_message_is_not_configurable():
    app = _info_app(_channel_info("", is_im=True, is_channel=False, is_member=None))
    assert await hutbot.slackcache.is_configurable_channel(app, "D0BT605QXLK") is False


@pytest.mark.asyncio
async def test_a_channel_the_bot_has_left_is_not_configurable():
    app = _info_app(_channel_info("general", is_member=False))
    assert await hutbot.slackcache.is_configurable_channel(app, "C12345") is False


@pytest.mark.asyncio
async def test_a_private_channel_the_bot_is_out_of_is_not_configurable():
    # Slack answers `channel_not_found` rather than a channel with `is_member: false`.
    app = _info_app(error="channel_not_found")
    assert await hutbot.slackcache.is_configurable_channel(app, "C0BASJXHX2T") is False


@pytest.mark.asyncio
async def test_an_invisible_channel_is_asked_about_once_per_ttl_not_once_per_render():
    # Every rule list asks about every conversation it knows, so an uncached not-found logged
    # a failure per entry on every render for as long as the entry survived.
    app = _info_app(error="channel_not_found")
    with patch('hutbot.slackcache.log_error') as errored, \
         patch('hutbot.slackcache.log_warning') as warned:
        for _ in range(3):
            assert await hutbot.slackcache.is_configurable_channel(app, "C0BASJXHX2T") is False
    assert app.client.conversations_info.await_count == 1
    # A state of the world, not a fault: warned about once, never logged as an error.
    assert warned.call_count == 1
    errored.assert_not_called()


@pytest.mark.asyncio
async def test_an_archived_channel_is_not_configurable():
    app = _info_app(error="is_archived")
    assert await hutbot.slackcache.is_configurable_channel(app, "C12345") is False


@pytest.mark.asyncio
async def test_a_rate_limited_lookup_is_still_asked_again():
    # The counterpart: a fault has to stay uncached, or a blip writes a real channel off for
    # a whole TTL. (`ratelimited` is retried inside one call, so only the cache is asserted.)
    app = _info_app(error="ratelimited")
    with patch('hutbot.slackcache.log_error'):
        await hutbot.slackcache.is_configurable_channel(app, "C12345")
        first = app.client.conversations_info.await_count
        await hutbot.slackcache.is_configurable_channel(app, "C12345")
    assert "C12345" not in hutbot.state._channel_info_cache
    assert app.client.conversations_info.await_count > first
