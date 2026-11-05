"""The config UI's own HTTP layer: whose identity it takes, and which writes it accepts."""

from aiohttp.test_utils import TestClient, TestServer

from tests._common import *  # noqa: F401,F403

import webui

HEADER = "X-Forwarded-Email"
ALICE = User(id="U1", name="alice", real_name="Alice", team="Platform")


def _ctx(**overrides):
    defaults = dict(
        user_header=HEADER,
        resolve_user=AsyncMock(side_effect=lambda email: ALICE if email == "alice@example.com"
                               else User(id=None, name=email, real_name="", team=TEAM_UNKNOWN)),
        list_channels=AsyncMock(return_value=[]),
        is_member=AsyncMock(return_value=True),
        get_configs=MagicMock(return_value={"default": {}}),
        apply_config=AsyncMock(return_value=(True, {})),
        create_config=AsyncMock(return_value=(True, "")),
        delete_config=AsyncMock(return_value=(True, "")),
        rename_config=AsyncMock(return_value=(True, "")),
        meta=MagicMock(return_value={}),
    )
    defaults.update(overrides)
    return webui.WebUIContext(**defaults)


@contextlib.asynccontextmanager
async def _client(ctx):
    client = TestClient(TestServer(webui.create_app(ctx)))
    await client.start_server()
    try:
        yield client
    finally:
        await client.close()


# ----- identity -----

@pytest.mark.asyncio
async def test_one_identity_header_signs_the_user_in():
    async with _client(_ctx()) as client:
        response = await client.get("/api/me", headers={HEADER: "alice@example.com"})
        assert response.status == 200
        assert (await response.json())["slack_user_id"] == "U1"


@pytest.mark.asyncio
async def test_a_repeated_identity_header_is_refused():
    """What a proxy that appends produces: the client's value comes first."""
    ctx = _ctx()
    async with _client(ctx) as client:
        response = await client.get("/api/me", headers=[(HEADER, "alice@example.com"),
                                                        (HEADER, "mallory@example.com")])
    assert response.status == 403
    ctx.resolve_user.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_list_of_identities_is_refused():
    ctx = _ctx()
    async with _client(ctx) as client:
        response = await client.get("/api/me", headers={HEADER: "alice@example.com, mallory@example.com"})
    assert response.status == 403
    ctx.resolve_user.assert_not_awaited()


@pytest.mark.asyncio
async def test_without_the_header_nobody_is_signed_in():
    async with _client(_ctx()) as client:
        assert (await client.get("/api/me")).status == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("sent,status", [(None, 403), ("wrong", 403), ("s3cret", 200)])
async def test_a_configured_proxy_secret_is_required(sent, status):
    ctx = _ctx(proxy_secret="s3cret")
    headers = {HEADER: "alice@example.com"}
    if sent is not None:
        headers["X-Hutbot-Proxy-Secret"] = sent
    async with _client(ctx) as client:
        assert (await client.get("/api/me", headers=headers)).status == status


@pytest.mark.asyncio
async def test_the_health_check_needs_no_identity():
    async with _client(_ctx(proxy_secret="s3cret")) as client:
        assert (await client.get("/healthz")).status == 200


# ----- writes must be same-origin JSON -----

@pytest.mark.asyncio
async def test_a_cross_site_text_plain_form_cannot_create_a_rule():
    ctx = _ctx()
    async with _client(ctx) as client:
        response = await client.post(
            "/api/channels/C1/configs", data='{"name":"spam","x":"="}\r\n',
            headers={HEADER: "alice@example.com", "Content-Type": "text/plain"})
    assert response.status == 415
    ctx.create_config.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path", [("POST", "/api/channels/C1/configs"),
                                         ("PUT", "/api/channels/C1/configs/default"),
                                         ("DELETE", "/api/channels/C1/configs/nag"),
                                         ("POST", "/api/channels/C1/configs/nag/rename")])
async def test_a_request_the_browser_marks_cross_site_is_refused(method, path):
    ctx = _ctx()
    async with _client(ctx) as client:
        response = await client.request(method, path, json={"name": "x"},
                                        headers={HEADER: "alice@example.com", "Sec-Fetch-Site": "cross-site"})
    assert response.status == 403
    for write in (ctx.create_config, ctx.apply_config, ctx.delete_config, ctx.rename_config):
        write.assert_not_awaited()


@pytest.mark.asyncio
async def test_the_editor_s_own_requests_still_work():
    ctx = _ctx()
    headers = {HEADER: "alice@example.com", "Sec-Fetch-Site": "same-origin"}
    async with _client(ctx) as client:
        created = await client.post("/api/channels/C1/configs", json={"name": "nag"}, headers=headers)
        saved = await client.put("/api/channels/C1/configs/default", json={"reply_message": "Hi"}, headers=headers)
        deleted = await client.delete("/api/channels/C1/configs/nag", headers=headers)

    assert (created.status, saved.status, deleted.status) == (201, 200, 200)
    ctx.create_config.assert_awaited_once_with("C1", "nag")
    # The saver's Slack id travels with the payload, for the post-channel membership check.
    ctx.apply_config.assert_awaited_once_with("C1", "default", {"reply_message": "Hi"}, "U1")
