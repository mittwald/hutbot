"""Config web UI for Hutbot.

A small aiohttp application served by the same process as the bot. It lets a
Keycloak-authenticated user edit the Hutbot rule configuration for the channels
they belong to. The bot wires up a :class:`WebUIContext` with closures over its
live state and validation, so this module stays free of bot internals.

The authenticated identity is read from a trusted reverse-proxy header
(default ``X-Forwarded-Email``); the pod is only reachable through that proxy,
so the header is trusted. See the README for the proxy/header setup.
"""

import os
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from aiohttp import web

try:  # pragma: no cover - logging is best-effort if employee_list is unavailable
    from employee_list import log, log_error
except Exception:  # pragma: no cover
    def log(*args, **kwargs):
        pass

    def log_error(*args, **kwargs):
        pass

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "webui_static")

# Everything the UI needs is same-origin and bundled, so we can lock the page
# down hard. No inline scripts/styles — index.html links app.js and styles.css.
_CSP = (
    "default-src 'self'; "
    "img-src 'self' data:; "
    "style-src 'self'; "
    "script-src 'self'; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'none'"
)


@dataclass
class WebUIContext:
    """Bridge to the live bot. Async fields return coroutines; sync ones return values."""

    user_header: str
    resolve_user: Callable[[str], Awaitable[Any]]
    list_channels: Callable[[Any], Awaitable[list]]
    is_member: Callable[[str, str], Awaitable[bool]]
    get_configs: Callable[[str], dict]
    apply_config: Callable[[str, str, dict], Awaitable[tuple]]
    create_config: Callable[[str, str], Awaitable[tuple]]
    delete_config: Callable[[str, str], Awaitable[tuple]]
    meta: Callable[[], dict]


def _ctx(request) -> WebUIContext:
    return request.app["ctx"]


def _forbidden(message: str = "You don't have access to this."):
    return web.json_response({"error": message}, status=403)


async def _current_user(request):
    """Resolve the proxy-supplied identity to a Slack user. Returns (user, email)."""
    ctx = _ctx(request)
    email = (request.headers.get(ctx.user_header) or "").strip()
    if not email:
        return None, ""
    # Some proxies send a comma-separated list; the first value is the user's.
    email = email.split(",")[0].strip()
    user = await ctx.resolve_user(email)
    if not user or not getattr(user, "id", None):
        return None, email
    return user, email


async def _require_member(request):
    """Authorize a channel route. Returns (user, channel_id) or (None, error_response)."""
    user, _ = await _current_user(request)
    if not user:
        return None, _forbidden("Sign in with your Slack-linked account to manage Hutbot.")
    channel_id = request.match_info["cid"]
    if not await _ctx(request).is_member(channel_id, user.id):
        return None, _forbidden("You're not a member of that channel.")
    return user, channel_id


async def handle_healthz(request):
    return web.Response(text="ok")


async def handle_index(request):
    index = os.path.join(STATIC_DIR, "index.html")
    if not os.path.exists(index):
        return web.Response(status=404, text="Config UI assets are missing.")
    return web.FileResponse(index)


async def handle_me(request):
    user, email = await _current_user(request)
    if not user:
        return _forbidden("Sign in with your Slack-linked account to manage Hutbot.")
    return web.json_response({
        "email": email,
        "slack_user_id": user.id,
        "name": user.name,
        "real_name": user.real_name,
        "team": user.team,
    })


async def handle_meta(request):
    user, _ = await _current_user(request)
    if not user:
        return _forbidden()
    return web.json_response(_ctx(request).meta())


async def handle_channels(request):
    user, _ = await _current_user(request)
    if not user:
        return _forbidden()
    channels = await _ctx(request).list_channels(user)
    return web.json_response({"channels": channels})


async def handle_get_configs(request):
    user, result = await _require_member(request)
    if not user:
        return result
    return web.json_response({"configs": _ctx(request).get_configs(result)})


async def handle_put_config(request):
    user, result = await _require_member(request)
    if not user:
        return result
    channel_id = result
    name = request.match_info["name"]
    try:
        payload = await request.json()
    except Exception:
        return web.json_response({"error": "The request body wasn't valid JSON."}, status=400)
    ok, errors = await _ctx(request).apply_config(channel_id, name, payload)
    if not ok:
        return web.json_response({"errors": errors}, status=422)
    return web.json_response({"ok": True, "config": _ctx(request).get_configs(channel_id).get(name)})


async def handle_post_config(request):
    user, result = await _require_member(request)
    if not user:
        return result
    channel_id = result
    try:
        payload = await request.json()
    except Exception:
        return web.json_response({"error": "The request body wasn't valid JSON."}, status=400)
    name = str((payload or {}).get("name") or "").strip()
    ok, error = await _ctx(request).create_config(channel_id, name)
    if not ok:
        return web.json_response({"error": error}, status=409)
    return web.json_response(
        {"ok": True, "name": name, "config": _ctx(request).get_configs(channel_id).get(name)},
        status=201,
    )


async def handle_delete_config(request):
    user, result = await _require_member(request)
    if not user:
        return result
    channel_id = result
    name = request.match_info["name"]
    ok, error = await _ctx(request).delete_config(channel_id, name)
    if not ok:
        status = 403 if "can't" in error.lower() else 404
        return web.json_response({"error": error}, status=status)
    return web.json_response({"ok": True})


@web.middleware
async def _security_headers(request, handler):
    try:
        response = await handler(request)
    except web.HTTPException as exc:
        response = exc
    response.headers["Content-Security-Policy"] = _CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def create_app(ctx: WebUIContext) -> web.Application:
    app = web.Application(middlewares=[_security_headers])
    app["ctx"] = ctx
    app.router.add_get("/healthz", handle_healthz)
    app.router.add_get("/", handle_index)
    app.router.add_get("/api/me", handle_me)
    app.router.add_get("/api/meta", handle_meta)
    app.router.add_get("/api/channels", handle_channels)
    app.router.add_get("/api/channels/{cid}/configs", handle_get_configs)
    app.router.add_post("/api/channels/{cid}/configs", handle_post_config)
    app.router.add_put("/api/channels/{cid}/configs/{name}", handle_put_config)
    app.router.add_delete("/api/channels/{cid}/configs/{name}", handle_delete_config)
    if os.path.isdir(STATIC_DIR):
        app.router.add_static("/static/", path=STATIC_DIR, name="static", show_index=False)
    return app


async def start_web_ui(ctx: WebUIContext, host: str, port: int) -> web.AppRunner:
    """Bind the UI to host:port on the running event loop and return its runner."""
    app = create_app(ctx)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    log(f"Config UI listening on http://{host}:{port} (user header: {ctx.user_header})")
    return runner
