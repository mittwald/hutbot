"""Slack lookups backed by the caches in `state`."""

from tests._common import *


@pytest.mark.asyncio
async def test_a_channel_name_is_looked_up_once_and_then_served_from_the_cache():
    # Every rule list needs one name per channel it shows, so an uncached lookup is one
    # `conversations.info` per channel on every render of the App Home tab and the web UI.
    app = AsyncMock()
    app.client.conversations_info = AsyncMock(return_value={"channel": {"name": "general"}})
    assert await hutbot.slackcache.get_channel_name(app, "C12345") == "general"
    assert await hutbot.slackcache.get_channel_name(app, "C12345") == "general"
    assert app.client.conversations_info.await_count == 1


@pytest.mark.asyncio
async def test_a_stale_channel_name_is_looked_up_again():
    app = AsyncMock()
    app.client.conversations_info = AsyncMock(return_value={"channel": {"name": "general"}})
    await hutbot.slackcache.get_channel_name(app, "C12345")
    stamp, name = hutbot.state._channel_name_cache["C12345"]
    hutbot.state._channel_name_cache["C12345"] = (stamp - hutbot.slackcache._CHANNEL_NAME_TTL - 1, name)
    await hutbot.slackcache.get_channel_name(app, "C12345")
    assert app.client.conversations_info.await_count == 2


@pytest.mark.asyncio
async def test_a_failed_channel_name_lookup_is_not_cached():
    # Otherwise a channel the bot momentarily could not read would be printed by its id for
    # the next five minutes.
    app = AsyncMock()
    app.client.conversations_info = AsyncMock(side_effect=SlackApiError("no", {"error": "boom"}))
    assert await hutbot.slackcache.get_channel_name(app, "C12345") == "C12345"
    assert "C12345" not in hutbot.state._channel_name_cache
