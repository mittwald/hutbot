"""The web UI's HTTP layer: which request a log line belongs to."""

from tests._common import *

from aiohttp import web
from aiohttp.test_utils import make_mocked_request

import logutil
import webui


def _ctx(user=None, **overrides):
    """A `WebUIContext` whose bridge back to the bot answers from memory."""
    fields = dict(
        user_header="X-Forwarded-Email",
        resolve_user=AsyncMock(return_value=user),
        list_channels=AsyncMock(return_value=[]),
        is_member=AsyncMock(return_value=True),
        get_configs=lambda channel_id: {},
        apply_config=AsyncMock(return_value=(True, {})),
        create_config=AsyncMock(return_value=(True, "")),
        delete_config=AsyncMock(return_value=(True, "")),
        rename_config=AsyncMock(return_value=(True, "")),
        meta=lambda: {},
        bot_name="Hutbot",
    )
    fields.update(overrides)
    return webui.WebUIContext(**fields)


def _request(method="GET", path="/api/channels", email="x@example.com", ctx=None):
    headers = {"X-Forwarded-Email": email} if email else {}
    return make_mocked_request(method, path, headers=headers,
                               app=webui.create_app(ctx if ctx is not None else _ctx()))


def _user(user_id="U1"):
    return User(id=user_id, name="someuser", real_name="Someone", team="Platform")


# --- Where a log line came from (see `logutil.log_origin`) ----------------------------

def test_the_origin_middleware_is_the_outermost_one():
    # A failure raised while the security-header middleware finishes a response belongs to
    # the request just as much as one from the handler.
    app = webui.create_app(_ctx())
    assert app.middlewares[0] is webui._log_request_origin


@pytest.mark.asyncio
async def test_an_error_while_serving_a_request_says_which_request(capsys):
    async def handler(request):
        logutil.log_error("Failed to fetch channel `C1`:", ValueError("channel_not_found"))
        return web.Response(text="ok")

    await webui._log_request_origin(_request(path="/api/channels"), handler)

    assert "ERROR [web UI GET /api/channels]: Failed to fetch channel `C1`:" \
        in capsys.readouterr().err


@pytest.mark.asyncio
async def test_the_origin_names_the_caller_once_they_have_a_slack_identity(capsys):
    request = _request(path="/api/me", ctx=_ctx(user=_user()))

    async def handler(inner):
        user, _ = await webui._current_user(inner)
        assert user is not None
        logutil.log_error("Failed to list channels:", ValueError("boom"))
        return web.Response(text="ok")

    await webui._log_request_origin(request, handler)

    assert "ERROR [web UI GET /api/me from U1]: Failed to list channels:" \
        in capsys.readouterr().err


@pytest.mark.asyncio
async def test_the_origin_never_carries_the_callers_address(capsys):
    # No log line anywhere else in the bot names a user by address, and the proxy in front of
    # this server already records the ones it lets through.
    request = _request(path="/api/me", email="d.grieser@example.com", ctx=_ctx(user=_user()))

    async def handler(inner):
        await webui._current_user(inner)
        logutil.log_error("boom:", ValueError("x"))
        return web.Response(text="ok")

    await webui._log_request_origin(request, handler)

    assert "d.grieser@example.com" not in capsys.readouterr().err


@pytest.mark.asyncio
async def test_an_identity_that_resolves_to_nobody_leaves_the_origin_as_it_was(capsys):
    request = _request(path="/api/me", ctx=_ctx(user=None))

    async def handler(inner):
        user, email = await webui._current_user(inner)
        assert user is None and email == "x@example.com"
        logutil.log_error("boom:", ValueError("x"))
        return web.Response(text="ok")

    await webui._log_request_origin(request, handler)

    assert "ERROR [web UI GET /api/me]: boom:" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_the_origin_does_not_outlive_the_request():
    # Concurrent requests share the process, so one must not inherit another's caller.
    async def handler(inner):
        await webui._current_user(inner)
        return web.Response(text="ok")

    await webui._log_request_origin(_request(ctx=_ctx(user=_user())), handler)
    assert logutil.get_log_origin() == ""


@pytest.mark.asyncio
async def test_a_write_route_is_named_by_its_method_and_path(capsys):
    request = _request(method="PUT", path="/api/channels/C1/configs/default",
                       ctx=_ctx(user=_user()))

    async def handler(inner):
        logutil.log_error("boom:", ValueError("x"))
        return web.Response(text="ok")

    await webui._log_request_origin(request, handler)

    assert "ERROR [web UI PUT /api/channels/C1/configs/default]: boom:" \
        in capsys.readouterr().err
