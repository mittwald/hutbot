"""Compatibility checks for runtime entry points."""


def test_legacy_bot_entrypoint_delegates_to_package_main():
    import bot
    from hutbot.__main__ import main

    assert bot.main is main


import pytest
from unittest.mock import AsyncMock, patch


@pytest.mark.asyncio
async def test_fetch_bot_handle_prefers_the_profile_display_name():
    import hutbot
    app = AsyncMock()
    app.client.users_info.return_value = {
        "user": {"name": "hutbotdev", "profile": {"display_name": "Hutbot_DEV", "display_name_normalized": "Hutbot_DEV"}}
    }

    assert await hutbot.slackcache.fetch_bot_handle(app, "UBOT") == "Hutbot_DEV"
    app.client.users_info.assert_awaited_once_with(user="UBOT")


@pytest.mark.asyncio
async def test_fetch_bot_handle_falls_back_to_the_username():
    import hutbot
    app = AsyncMock()
    app.client.users_info.return_value = {"user": {"name": "hutbotdev", "profile": {"display_name": "  "}}}

    assert await hutbot.slackcache.fetch_bot_handle(app, "UBOT") == "hutbotdev"


@pytest.mark.asyncio
async def test_fetch_bot_handle_returns_empty_without_a_bot_user_or_on_error():
    import hutbot
    from slack_sdk.errors import SlackApiError
    app = AsyncMock()

    assert await hutbot.slackcache.fetch_bot_handle(app, "") == ""
    app.client.users_info.assert_not_awaited()

    app.client.users_info.side_effect = SlackApiError("nope", {"error": "user_not_found"})
    assert await hutbot.slackcache.fetch_bot_handle(app, "UBOT") == ""
