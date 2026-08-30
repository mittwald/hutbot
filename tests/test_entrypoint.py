"""Compatibility checks for runtime entry points."""

import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def test_legacy_bot_entrypoint_delegates_to_package_main():
    import bot
    from hutbot.__main__ import main

    assert bot.main is main


def test_source_env_is_loaded_before_modules_capture_runtime_settings():
    code = r'''
import asyncio
import os
import employee_list

def fake_load_env_file():
    os.environ.update({
        "SLACK_APP_TOKEN": "xapp-test",
        "SLACK_BOT_TOKEN": "xoxb-test",
        "HUTBOT_CALENDAR_ALLOWED_HOSTS": "bridge.internal.example",
        "HUTBOT_CALENDAR_TTL": "17",
        "HUTBOT_CALENDAR_LOOKBACK_DAYS": "23",
        "HUTBOT_BUTTON_CACHE_FILE": "/tmp/from-env-buttons.json",
    })

employee_list.load_env_file = fake_load_env_file
import hutbot.__main__ as entrypoint

class StopStartup(Exception):
    pass

def stop_after_imports(*args, **kwargs):
    raise StopStartup()

entrypoint.AsyncApp = stop_after_imports
try:
    asyncio.run(entrypoint.main())
except SystemExit:
    pass

from hutbot import calendarfeed, constants
print("SETTINGS", calendarfeed._CALENDAR_TTL, calendarfeed._CALENDAR_LOOKBACK_DAYS,
      sorted(calendarfeed._CALENDAR_ALLOWED_HOSTS), constants.BUTTON_CACHE_FILE)
'''
    names = {
        "SLACK_APP_TOKEN", "SLACK_BOT_TOKEN", "HUTBOT_CALENDAR_ALLOWED_HOSTS",
        "HUTBOT_CALENDAR_TTL", "HUTBOT_CALENDAR_LOOKBACK_DAYS", "HUTBOT_BUTTON_CACHE_FILE",
    }
    environment = {key: value for key, value in os.environ.items() if key not in names}
    result = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=environment,
                            capture_output=True, text=True, check=False)

    assert result.returncode == 0, result.stderr
    assert "SETTINGS 17.0 23 ['bridge.internal.example'] /tmp/from-env-buttons.json" in result.stdout


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
