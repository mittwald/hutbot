from tests._common import *  # noqa: F401,F403



@pytest.mark.asyncio
async def test_validate_config_payload_accepts_good_config():
    _seed_user_caches()
    app = _ui_app()
    payload = {
        "enabled": True,
        "trigger": "schedule",
        "schedule_cron": "0 9 * * 1-5",
        "reply_message": "Hi {{user}} in {{channel}}",
        "action": "post-channel",
        "action_target": "C0123ABCD",
        "included_teams": ["Platform"],
        "hours": ["09:00", "17:00"],
        "opsgenie_priority": "p2",
        "wait_time": 600,
        "button_timeout": 300,
        "buttons": [
            {"label": "Snooze", "action": "delay", "value": "10"},
            {"label": "Note", "action": "message", "value": "Some message"},
        ],
    }

    cfg, errors = await validate_config_payload(payload, app)

    assert errors == {}
    assert cfg is not None
    assert cfg["trigger"] == "schedule"
    assert cfg["schedule_cron"] == "0 9 * * 1-5"
    # action "post-channel" normalizes to "post_channel" with target preserved.
    assert cfg["action"] == "post_channel"
    assert cfg["action_target"] == "C0123ABCD"
    # template vars stay intact.
    assert cfg["reply_message"] == "Hi {{user}} in {{channel}}"
    assert cfg["included_teams"] == ["Platform"]
    assert cfg["excluded_teams"] == []
    assert cfg["hours"] == ["09:00", "17:00"]
    # priority lowercased input is uppercased.
    assert cfg["opsgenie_priority"] == "P2"
    # wait_time/button_timeout stay in seconds.
    assert cfg["wait_time"] == 600
    assert cfg["button_timeout"] == 300
    assert cfg["buttons"] == [
        {"label": "Snooze", "action": "delay", "value": "10"},
        {"label": "Note", "action": "message", "value": "Some message"},
    ]
    # the Slack client is never touched when caches are seeded and there are no @mentions.
    app.client.users_list.assert_not_called()



@pytest.mark.asyncio
async def test_validate_config_payload_collects_field_errors():
    _seed_user_caches()
    app = _ui_app()
    payload = {
        "reply_message": "",
        "trigger": "bogus",
        "schedule_cron": "nope",
        "wait_time": 0,
        "datetime_timezone": "Mars/Phobos",
        "opsgenie_priority": "P9",
        "included_teams": ["Platform"],
        "excluded_teams": ["Support"],
        "pattern": "(",
        "hours": ["09:00"],
        "action": "dm_user",
        "action_target": "",
        "buttons": [
            {"label": "", "action": "ack", "value": ""},
            {"label": "Snooze", "action": "delay", "value": "9999"},
        ],
    }

    cfg, errors = await validate_config_payload(payload, app)

    assert cfg is None
    for field in ("reply_message", "trigger", "schedule_cron", "wait_time",
                  "datetime_timezone", "opsgenie_priority", "included_teams",
                  "pattern", "hours", "action_target"):
        assert field in errors, f"expected an error for {field}, got {sorted(errors)}"
    assert any(key.startswith("buttons") for key in errors), f"expected a buttons.* error, got {sorted(errors)}"



@pytest.mark.asyncio
async def test_validate_config_payload_rejects_unknown_team():
    _seed_user_caches()
    app = _ui_app()
    payload = {"reply_message": "Hello", "included_teams": ["Nope"]}

    cfg, errors = await validate_config_payload(payload, app)

    assert cfg is None
    assert "included_teams" in errors
    assert "Nope" in errors["included_teams"]



@pytest.mark.asyncio
async def test_is_user_in_channel_true_false():
    hutbot.state._channel_members_cache = {}
    app = _ui_app()
    app.client.conversations_members = AsyncMock(return_value={
        "members": ["U1", "U2"],
        "response_metadata": {"next_cursor": ""},
    })

    assert await is_user_in_channel(app, "C1", "U1") is True
    assert await is_user_in_channel(app, "C1", "U9") is False
    # empty user id short-circuits to False.
    assert await is_user_in_channel(app, "C1", "") is False



@pytest.mark.asyncio
async def test_list_user_config_channels_filters_by_membership():
    hutbot.state._channel_members_cache = {}
    hutbot.state.channel_config = {"C1": {"default": {}}, "C2": {"default": {}}}
    app = _ui_app()

    async def members_side_effect(channel=None, cursor=None, limit=None):
        members = ["U1"] if channel == "C1" else ["U7"]
        return {"members": members, "response_metadata": {"next_cursor": ""}}

    async def info_side_effect(channel=None):
        return {"channel": {"name": f"name-{channel}"}}

    app.client.conversations_members = AsyncMock(side_effect=members_side_effect)
    app.client.conversations_info = AsyncMock(side_effect=info_side_effect)

    user = hutbot.models.User(id="U1", name="someuser", real_name="X", team="Platform")
    channels = await list_user_config_channels(app, user)

    assert channels == [{"id": "C1", "name": "name-C1"}]



@pytest.mark.asyncio
async def test_ui_create_config_rejects_bad_name_and_duplicate(monkeypatch):
    hutbot.state.channel_config = {}
    monkeypatch.setattr(hutbot.persistence, "save_configuration", AsyncMock())
    app = _ui_app()

    # bad name (space not allowed by the name pattern)
    ok, msg = await hutbot.webui_backend.ui_create_config(app, "C1", "bad name")
    assert ok is False and msg

    # good name succeeds and seeds from DEFAULT_CONFIG
    ok, msg = await hutbot.webui_backend.ui_create_config(app, "C1", "my-rule")
    assert ok is True
    assert hutbot.state.channel_config["C1"]["my-rule"]["reply_message"] == hutbot.constants.DEFAULT_CONFIG["reply_message"]
    hutbot.persistence.save_configuration.assert_awaited()

    # duplicate is rejected
    ok, msg = await hutbot.webui_backend.ui_create_config(app, "C1", "my-rule")
    assert ok is False and "already exists" in msg



@pytest.mark.asyncio
async def test_ui_delete_config_refuses_default(monkeypatch):
    hutbot.state.channel_config = {"C1": {"default": {}, "my-rule": {}}}
    monkeypatch.setattr(hutbot.persistence, "save_configuration", AsyncMock())
    app = _ui_app()

    ok, msg = await hutbot.webui_backend.ui_delete_config(app, "C1", "default")
    assert ok is False and msg
    assert "default" in hutbot.state.channel_config["C1"]

    ok, msg = await hutbot.webui_backend.ui_delete_config(app, "C1", "my-rule")
    assert ok is True
    assert "my-rule" not in hutbot.state.channel_config["C1"]
