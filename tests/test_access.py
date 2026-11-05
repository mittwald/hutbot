"""Only full members of the bot's own workspace may run commands."""

import os

from tests._common import *  # noqa: F401,F403

from hutbot import access
from hutbot.routing import handle_command_event

TEAM = "T0HOME"
MEMBER = {"id": "U1", "team_id": TEAM, "name": "dave"}


def _app(account=None, error=None):
    app = AsyncMock()
    if error is not None:
        app.client.users_info.side_effect = error
    else:
        app.client.users_info.return_value = {"ok": True, "user": account}
    return app


@pytest.fixture(autouse=True)
def _home_team():
    hutbot.state.bot_team_id = TEAM
    hutbot.state.bot_user_id = "UBOT"


@pytest.mark.asyncio
async def test_a_full_member_may_run_commands_and_is_looked_up_once():
    app = _app(MEMBER)

    assert await access.command_refusal(app, "U1") == ""
    assert await access.command_refusal(app, "U1") == ""
    app.client.users_info.assert_awaited_once_with(user="U1")


@pytest.mark.asyncio
@pytest.mark.parametrize("flags", [{"is_restricted": True},
                                   {"is_restricted": True, "is_ultra_restricted": True},
                                   {"is_ultra_restricted": True}])
async def test_a_guest_is_refused(flags):
    assert await access.command_refusal(_app({**MEMBER, **flags}), "U1") == access.REFUSAL_GUEST


@pytest.mark.asyncio
async def test_guests_can_be_let_in_explicitly():
    with patch.dict(os.environ, {access.ALLOW_GUEST_COMMANDS_ENV: "true"}):
        assert await access.command_refusal(_app({**MEMBER, "is_restricted": True}), "U1") == ""


@pytest.mark.asyncio
async def test_a_slack_connect_member_of_another_workspace_is_refused_even_with_guests_allowed():
    with patch.dict(os.environ, {access.ALLOW_GUEST_COMMANDS_ENV: "true"}):
        assert await access.command_refusal(_app({**MEMBER, "team_id": "T0OTHER"}), "U1") == access.REFUSAL_EXTERNAL
        assert await access.command_refusal(_app({**MEMBER, "is_stranger": True}), "U1") == access.REFUSAL_EXTERNAL


@pytest.mark.asyncio
async def test_a_member_of_the_same_grid_organization_is_let_in():
    hutbot.state.bot_enterprise_id = "E0ORG"
    account = {**MEMBER, "team_id": "T0SIBLING", "enterprise_user": {"enterprise_id": "E0ORG"}}

    assert await access.command_refusal(_app(account), "U1") == ""


@pytest.mark.asyncio
@pytest.mark.parametrize("flags,expected", [({"deleted": True}, access.REFUSAL_DEACTIVATED),
                                            ({"is_bot": True}, access.REFUSAL_BOT),
                                            ({"is_app_user": True}, access.REFUSAL_BOT)])
async def test_deactivated_and_bot_accounts_are_refused(flags, expected):
    assert await access.command_refusal(_app({**MEMBER, **flags}), "U1") == expected


@pytest.mark.asyncio
async def test_a_bot_is_refused_without_a_lookup():
    app = _app(MEMBER)

    assert await access.command_refusal(app, "U1", actor_is_bot=True) == access.REFUSAL_BOT
    assert await access.command_refusal(app, "B0APP") == access.REFUSAL_BOT
    assert await access.command_refusal(app, "USLACKBOT") == access.REFUSAL_BOT
    app.client.users_info.assert_not_awaited()


@pytest.mark.asyncio
async def test_an_account_that_cannot_be_looked_up_is_refused():
    with patch('hutbot.access.log_error'):
        assert await access.command_refusal(_app(error=RuntimeError("down")), "U1") == access.REFUSAL_UNVERIFIED
    assert await access.command_refusal(_app(None), "U1") == access.REFUSAL_UNVERIFIED
    assert await access.command_refusal(_app(MEMBER), "") == access.REFUSAL_UNVERIFIED


@pytest.mark.asyncio
async def test_nothing_is_let_in_before_the_workspace_is_known():
    hutbot.state.bot_team_id = ""

    assert await access.command_refusal(_app(MEMBER), "U1") == access.REFUSAL_EXTERNAL


# ----- both entry points are gated -----

def _mention(user="U1", **extra):
    return {"type": "message", "text": "<@UBOT> enable opsgenie", "ts": "1234.1", "user": user,
            "channel": "C12345", "channel_type": "channel", **extra}


@pytest.mark.asyncio
async def test_a_guest_mention_runs_no_command_and_is_told_why():
    app = _app({**MEMBER, "is_restricted": True})
    channel = _mk_channel()
    guest = User(id="U1", name="guest", real_name="Guest", team=TEAM_UNKNOWN)
    with patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=guest)), \
         patch('hutbot.commands.process_command', new=AsyncMock()) as process, \
         patch('hutbot.messaging.send_message', new=AsyncMock()) as send:
        await route_message(app, OPSGENIE_TOKENS, _mention())

    process.assert_not_awaited()
    assert send.await_args.args[2] is guest
    assert "full members of this workspace" in send.await_args.args[3]
    # Privately: no thread reply for the whole channel to read.
    assert len(send.await_args.args) == 4


@pytest.mark.asyncio
async def test_a_bot_mention_runs_no_command_and_gets_no_answer():
    app = _app(MEMBER)
    channel = _mk_channel({"default": {**DEFAULT_CONFIG.copy(), "include_bots": True}})
    bot = User(id="B0APP", name="relay", real_name="Relay", team=TEAM_UNKNOWN, is_bot=True)
    event = {"type": "message", "subtype": "bot_message", "text": "<@UBOT> config delete",
             "ts": "1234.1", "bot_id": "B0APP", "channel": "C12345", "channel_type": "channel"}
    with patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=bot)), \
         patch('hutbot.commands.process_command', new=AsyncMock()) as process, \
         patch('hutbot.messaging.send_message', new=AsyncMock()) as send:
        await route_message(app, OPSGENIE_TOKENS, event)

    process.assert_not_awaited()
    send.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_member_mention_still_runs_the_command():
    app = _app(MEMBER)
    channel = _mk_channel()
    member = User(id="U1", name="dave", real_name="Dave", team="Platform")
    with patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=member)), \
         patch('hutbot.commands.process_command', new=AsyncMock()) as process:
        await route_message(app, OPSGENIE_TOKENS, _mention())

    process.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("account,runs", [(MEMBER, True),
                                          ({**MEMBER, "is_restricted": True}, False),
                                          ({**MEMBER, "team_id": "T0OTHER"}, False)])
async def test_the_slash_command_is_gated_the_same_way(account, runs):
    app = _app(account)
    channel = _mk_channel()
    sender = User(id="U1", name="dave", real_name="Dave", team="Platform")
    with patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=sender)), \
         patch('hutbot.commands.process_command', new=AsyncMock()) as process, \
         patch('hutbot.messaging.send_message', new=AsyncMock()) as send:
        await handle_command_event(app, {"text": "on-call rota", "channel_id": "C12345", "user_id": "U1"})

    assert process.await_count == (1 if runs else 0)
    assert send.await_count == (0 if runs else 1)
