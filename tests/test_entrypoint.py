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
    from hutbot import slackcache
    app = AsyncMock()
    app.client.users_info.return_value = {
        "user": {"name": "hutbotdev", "profile": {"display_name": "Hutbot_DEV", "display_name_normalized": "Hutbot_DEV"}}
    }

    assert await slackcache.fetch_bot_handle(app, "UBOT") == "Hutbot_DEV"
    app.client.users_info.assert_awaited_once_with(user="UBOT")


@pytest.mark.asyncio
async def test_fetch_bot_handle_falls_back_to_the_username():
    from hutbot import slackcache
    app = AsyncMock()
    app.client.users_info.return_value = {"user": {"name": "hutbotdev", "profile": {"display_name": "  "}}}

    assert await slackcache.fetch_bot_handle(app, "UBOT") == "hutbotdev"


@pytest.mark.asyncio
async def test_fetch_bot_handle_returns_empty_without_a_bot_user_or_on_error():
    from hutbot import slackcache
    from slack_sdk.errors import SlackApiError
    app = AsyncMock()

    assert await slackcache.fetch_bot_handle(app, "") == ""
    app.client.users_info.assert_not_awaited()

    app.client.users_info.side_effect = SlackApiError("nope", {"error": "user_not_found"})
    assert await slackcache.fetch_bot_handle(app, "UBOT") == ""


@pytest.mark.asyncio
async def test_startup_waits_for_the_bridge_roster_before_restoring_timers(monkeypatch):
    """A restored reminder that is already due must not evaluate against an empty calendar list."""
    import asyncio
    from unittest.mock import MagicMock

    import hutbot.__main__ as entrypoint
    from hutbot import buttons, calendarfeed, opsgenie, persistence, routing, scheduling, slackcache, webui_backend

    monkeypatch.setenv("SLACK_APP_TOKEN", "xapp-test")
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-test")
    for name in ("OPSGENIE_TOKEN", "OPSGENIE_API_TOKEN", "OPSGENIE_HEARTBEAT_NAME", "HUTBOT_BUILTIN_CALENDARS",
                 "HUTBOT_BUILTIN_CALENDARS_FILE", "HUTBOT_CALENDAR_BRIDGE_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(entrypoint, "load_env_file", lambda: None)
    # Its handlers would outlive this test on the root logger and reroute every later test's
    # library output; `tests/test_logutil.py` covers what it does.
    monkeypatch.setattr(entrypoint, "configure_stdlib_logging", lambda: None)

    order = []

    def record(name, result=None):
        async def recorder(*args, **kwargs):
            order.append(name)
            return result
        return recorder

    def record_call(name):
        """Records when the coroutine is *created*, which for a task is when it is started."""
        def factory(*args, **kwargs):
            order.append(name)

            async def run():
                return None
            return run()
        return factory

    app = MagicMock()
    app.client.auth_test = AsyncMock(return_value={"user_id": "UBOT", "user": "hutbot"})
    handler = MagicMock()
    # The only way out of `main`: it treats a cancellation as an ordinary shutdown.
    handler.start_async = AsyncMock(side_effect=asyncio.CancelledError)
    handler.close_async = AsyncMock()

    with patch.object(entrypoint, "AsyncApp", lambda **kwargs: app), \
         patch.object(entrypoint, "AsyncSocketModeHandler", lambda *a, **k: handler), \
         patch.object(persistence, "load_configuration", new=record("load_configuration")), \
         patch.object(persistence, "load_replies_cache", new=record("load_replies_cache")), \
         patch.object(persistence, "load_button_cache", new=record("load_button_cache")), \
         patch.object(slackcache, "fetch_bot_handle", new=record("fetch_bot_handle", "Hutbot")), \
         patch.object(slackcache, "update_user_cache", new=record("update_user_cache")), \
         patch.object(calendarfeed, "run_bridge_refresh_loop", new=record_call("run_bridge_refresh_loop")), \
         patch.object(calendarfeed, "wait_for_bridge_roster", new=record("wait_for_bridge_roster")), \
         patch.object(scheduling, "restore_scheduled_replies", new=record("restore_scheduled_replies")), \
         patch.object(scheduling, "run_scheduler", new=record_call("run_scheduler")), \
         patch.object(buttons, "restore_pending_buttons", new=record("restore_pending_buttons")), \
         patch.object(opsgenie, "send_heartbeat", new=record_call("send_heartbeat")), \
         patch.object(routing, "register_app_handlers", new=MagicMock()), \
         patch.object(webui_backend, "maybe_start_web_ui", new=record("maybe_start_web_ui")):
        await entrypoint.main()

    assert "wait_for_bridge_roster" in order, order
    for restored in ("restore_scheduled_replies", "restore_pending_buttons"):
        assert order.index("wait_for_bridge_roster") < order.index(restored), order
    # The listing is read while the Slack calls are in flight, not after the wait began.
    assert order.index("run_bridge_refresh_loop") < order.index("wait_for_bridge_roster"), order
