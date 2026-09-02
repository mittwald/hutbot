"""Slack lookups backed by the caches in `state`."""

from tests._common import *


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
