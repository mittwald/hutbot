"""Entry point: ``python -m hutbot``."""

import asyncio

from slack_bolt.async_app import AsyncApp
from slack_bolt.adapter.socket_mode.aiohttp import AsyncSocketModeHandler

from employee_list import get_env_var, load_env_file, log_error

from . import __version__
from . import state
from . import datetimefmt
from .constants import DEFAULT_BOT_NAME, normalize_slash_command, normalize_version
from . import persistence
from . import slackcache
from . import scheduling
from . import buttons
from . import routing
from . import opsgenie
from . import webui_backend


async def main() -> None:
    load_env_file()
    slack_app_token = get_env_var("SLACK_APP_TOKEN")
    slack_bot_token = get_env_var("SLACK_BOT_TOKEN")
    opsgenie_token = get_env_var("OPSGENIE_TOKEN")
    opsgenie_heartbeat_name = get_env_var("OPSGENIE_HEARTBEAT_NAME")
    state.slash_command = normalize_slash_command(get_env_var("HUTBOT_SLASH_COMMAND"))
    state.bot_name = get_env_var("HUTBOT_BOT_NAME").strip() or DEFAULT_BOT_NAME
    # The deployed image tag, so `help` / `news` name the version actually running.
    state.version = normalize_version(get_env_var("HUTBOT_VERSION")) or normalize_version(__version__)
    # Locale for configs that set none. The timezone counterpart is the container's
    # TZ: a config without its own timezone uses server local time anyway.
    state.default_datetime_locale = datetimefmt.resolve_default_locale(get_env_var("HUTBOT_DEFAULT_DATETIME_LOCALE"))
    if slack_app_token is None or slack_bot_token is None:
        log_error("Environment variables SLACK_APP_TOKEN and SLACK_BOT_TOKEN must be set to run this app")
        exit(1)

    handler = None
    heartbeat_task = None
    scheduler_task = None
    web_runner = None
    try:
        app = AsyncApp(token=slack_bot_token)
        await persistence.load_configuration(app)
        auth = await app.client.auth_test()
        state.bot_user_id = auth["user_id"]
        # The Slack handle differs per app (hutbot vs. hutbot_dev), so the help
        # text's `@mention` examples have to come from the workspace, not a constant.
        state.bot_user_name = auth.get("user") or DEFAULT_BOT_NAME
        await slackcache.update_user_cache(app)
        await persistence.load_replies_cache()
        await scheduling.restore_scheduled_replies(app, opsgenie_token)
        await persistence.load_button_cache()
        await buttons.restore_pending_buttons(app, opsgenie_token)
        routing.register_app_handlers(app, opsgenie_token=opsgenie_token)
        handler = AsyncSocketModeHandler(app, slack_app_token)
        if opsgenie_token and opsgenie_heartbeat_name:
            state.opsgenie_configured = True
            heartbeat_task = asyncio.create_task(opsgenie.send_heartbeat(opsgenie_token, opsgenie_heartbeat_name))
        scheduler_task = asyncio.create_task(scheduling.run_scheduler(app, opsgenie_token))
        web_runner = await webui_backend.maybe_start_web_ui(app)
        await handler.start_async()
    except asyncio.CancelledError:
        pass
    except KeyboardInterrupt:
        pass
    except Exception as e:
        log_error(e)
        exit(1)
    finally:
        try:
            if web_runner:
                await web_runner.cleanup()
            if handler:
                await handler.close_async()
            for background_task in (heartbeat_task, scheduler_task):
                if background_task:
                    background_task.cancel()
                    try:
                        await background_task
                    except asyncio.CancelledError:
                        pass
        except BaseException as e:
            pass


if __name__ == "__main__":
    asyncio.run(main())
