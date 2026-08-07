"""Entry point: ``python -m hutbot``."""

import asyncio

from slack_bolt.async_app import AsyncApp
from slack_bolt.adapter.socket_mode.aiohttp import AsyncSocketModeHandler

from employee_list import get_env_var, load_env_file, log_error

from . import state
from .constants import normalize_slash_command
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
        state.bot_user_id = (await app.client.auth_test())["user_id"]
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
