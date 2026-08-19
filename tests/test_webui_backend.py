from tests._common import *  # noqa: F401,F403



@pytest.mark.asyncio
async def test_validate_config_payload_accepts_good_config():
    _seed_user_caches()
    app = _ui_app()
    payload = {
        "enabled": True,
        "trigger": "schedule",
        "cron": "0 9 * * 1-5",
        "reply_message": "Hi {{user}} in {{channel}}",
        "action": "post-channel",
        "action_target": "C0123ABCD",
        "included_teams": ["Platform"],
        "hours": ["09:00", "17:00"],
        "opsgenie_priority": "p2",
        "wait_time": 600,
        "escalation_timeout": 300,
        "escalation_kind": "config",
        "escalation_target": "alarm",
        "buttons": [
            {"label": "Snooze", "action": "delay", "value": "10"},
            {"label": "Note", "action": "ack", "value": "Some message"},
        ],
    }

    cfg, errors = await validate_config_payload(payload, app)

    assert errors == {}
    assert cfg is not None
    assert cfg["trigger"] == "cron"
    assert cfg["cron"] == "0 9 * * 1-5"
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
    # wait_time/escalation_timeout stay in seconds.
    assert cfg["wait_time"] == 600
    assert cfg["escalation_timeout"] == 300
    assert cfg["escalation_kind"] == "config"
    assert cfg["escalation_target"] == "alarm"
    assert cfg["buttons"] == [
        {"label": "Snooze", "action": "delay", "value": "10"},
        {"label": "Note", "action": "ack", "value": "Some message"},
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
        "cron": "nope",
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
    for field in ("reply_message", "trigger", "cron", "wait_time",
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
async def test_ui_apply_config_requires_valid_existing_target(monkeypatch):
    _seed_user_caches()
    hutbot.state.channel_config = {"C1": {"existing": DEFAULT_CONFIG.copy()}}
    monkeypatch.setattr(hutbot.persistence, "save_configuration", AsyncMock())
    app = _ui_app()
    payload = {"reply_message": "Updated"}

    ok, errors = await hutbot.webui_backend.ui_apply_config(app, "C1", "bad name", payload)
    assert ok is False and "name" in errors

    ok, errors = await hutbot.webui_backend.ui_apply_config(app, "C1", "deleted", payload)
    assert ok is False and errors == {"name": "That rule no longer exists."}
    assert "deleted" not in hutbot.state.channel_config["C1"]
    hutbot.persistence.save_configuration.assert_not_awaited()



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


@pytest.mark.asyncio
async def test_get_user_by_email_strict_rejects_username_fallback():
    # Regression (F4): UI auth must match on exact email only; the lenient resolver
    # (used for OpsGenie / rule targets) still falls back to the username local-part.
    app = AsyncMock()
    alice = User("U1", "alice", "Alice", "Team")
    hutbot.state.user_email_cache["alice@corp.example"] = alice
    hutbot.state.user_id_cache["alice"] = alice
    with patch('hutbot.slackcache.update_user_cache', new=AsyncMock()):
        assert (await hutbot.slackcache.get_user_by_email_strict(app, "alice@corp.example")).id == "U1"
        # external address whose local-part matches a Slack username is NOT authorized
        assert (await hutbot.slackcache.get_user_by_email_strict(app, "alice@external.example")).id is None
        # contrast: the lenient resolver still falls back to the username (the flagged behavior)
        assert (await hutbot.slackcache.get_user_by_email(app, "alice@external.example")).id == "U1"


# ----- Per-instance naming -----

def test_ui_meta_exposes_bot_name_and_slash_command():
    with patch('hutbot.state.bot_name', 'Hutbot (DEV)'), \
         patch('hutbot.state.slash_command', '/hutbot_dev'):
        meta = ui_meta()
    assert meta['bot_name'] == 'Hutbot (DEV)'
    assert meta['slash_command'] == '/hutbot_dev'


@pytest.mark.asyncio
async def test_ui_apply_config_keeps_the_automatic_disable_reason(monkeypatch):
    _seed_user_caches()
    hutbot.state.channel_config = {"C1": {"rule": {**DEFAULT_CONFIG.copy(), "enabled": False,
                                                   "disabled_reason": DISABLED_REASON_REMOVED}}}
    monkeypatch.setattr(hutbot.persistence, "save_configuration", AsyncMock())
    app = _ui_app()

    # Editing a rule that stays disabled keeps the marker...
    ok, errors = await hutbot.webui_backend.ui_apply_config(app, "C1", "rule", {"reply_message": "Updated", "enabled": False})
    assert ok is True and errors == {}
    assert hutbot.state.channel_config["C1"]["rule"]["disabled_reason"] == DISABLED_REASON_REMOVED

    # ...explicitly enabling a draft loaded after removal clears the marker.
    ok, errors = await hutbot.webui_backend.ui_apply_config(
        app, "C1", "rule",
        {"reply_message": "Updated", "enabled": True, "disabled_reason": DISABLED_REASON_REMOVED},
    )
    assert ok is True and errors == {}
    assert hutbot.state.channel_config["C1"]["rule"]["disabled_reason"] == ""


@pytest.mark.asyncio
async def test_ui_apply_config_stale_save_cannot_undo_removal_disable(monkeypatch):
    _seed_user_caches()
    stale_payload = {**DEFAULT_CONFIG.copy(), "reply_message": "Updated in stale editor"}
    hutbot.state.channel_config = {"C1": {"rule": {
        **DEFAULT_CONFIG.copy(),
        "enabled": False,
        "disabled_reason": DISABLED_REASON_REMOVED,
    }}}
    monkeypatch.setattr(hutbot.persistence, "save_configuration", AsyncMock())

    ok, errors = await hutbot.webui_backend.ui_apply_config(_ui_app(), "C1", "rule", stale_payload)

    assert ok is True and errors == {}
    config = hutbot.state.channel_config["C1"]["rule"]
    assert config["reply_message"] == "Updated in stale editor"
    assert config["enabled"] is False
    assert config["disabled_reason"] == DISABLED_REASON_REMOVED


@pytest.mark.asyncio
async def test_validate_config_payload_stores_escalation_as_one_setting():
    _seed_user_caches()
    app = _ui_app()
    base = {
        "reply_message": "Hi", "wait_time": 600, "trigger": "message", "action": "reply",
        "buttons": [{"label": "Yes", "action": "ack", "value": ""}],
    }

    # Half a setting is stored as switched off, not as a timer with nothing to fire.
    cfg, errors = await validate_config_payload({**base, "escalation_timeout": 300}, app)
    assert errors == {}
    assert (cfg["escalation_timeout"], cfg["escalation_kind"], cfg["escalation_target"]) == (0, "none", "")

    cfg, errors = await validate_config_payload(
        {**base, "escalation_timeout": 0, "escalation_kind": "button", "escalation_target": "Yes"}, app)
    assert errors == {}
    assert (cfg["escalation_timeout"], cfg["escalation_kind"], cfg["escalation_target"]) == (0, "none", "")

    # A kind with a timeout but no target is an error, not a silent no-op.
    cfg, errors = await validate_config_payload(
        {**base, "escalation_timeout": 300, "escalation_kind": "config", "escalation_target": ""}, app)
    assert errors == {"escalation_target": "Pick a button label or a rule to escalate to."}

    cfg, errors = await validate_config_payload(
        {**base, "escalation_timeout": 300, "escalation_kind": "nonsense", "escalation_target": "x"}, app)
    assert errors == {"escalation_kind": "Escalation must be none, button or config."}


@pytest.mark.asyncio
async def test_validate_config_payload_accepts_and_canonicalizes_conditions():
    _seed_user_caches()
    app = _ui_app()
    payload = {
        "reply_message": "Hi",
        "wait_time": 600,
        "conditions": [
            # `is` canonicalizes to `equals`; the case flag is coerced from a UI string.
            {"variable": "{{team}}", "operator": "is", "value": "Platform", "case_sensitive": "true"},
            # A value-less operator drops both the value and the flag.
            {"variable": "message", "operator": "not empty", "value": "junk", "case_sensitive": True},
        ],
        "conditions_mode": "any",
        "calendar_url": "https://cal.example.com/a/b/calendar.ics",
    }

    cfg, errors = await validate_config_payload(payload, app)

    assert errors == {}
    assert cfg["conditions"] == [
        {"variable": "team", "operator": "equals", "value": "Platform", "case_sensitive": True},
        {"variable": "message", "operator": "not_empty", "value": "", "case_sensitive": False},
    ]
    assert cfg["conditions_mode"] == "any"
    assert cfg["calendar_url"] == "https://cal.example.com/a/b/calendar.ics"


@pytest.mark.asyncio
async def test_validate_config_payload_defaults_conditions():
    _seed_user_caches()
    cfg, errors = await validate_config_payload({"reply_message": "Hi", "wait_time": 600}, _ui_app())
    assert errors == {}
    assert cfg["conditions"] == [] and cfg["conditions_mode"] == "all"
    assert cfg["calendar_url"] == ""


@pytest.mark.asyncio
@pytest.mark.parametrize("condition,expected", [
    ({"variable": "nope", "operator": "contains", "value": "x"}, "supported template variable"),
    ({"variable": "message", "operator": "bogus", "value": "x"}, "Operator must be one of"),
    ({"variable": "message", "operator": "contains", "value": ""}, "needs a value"),
    ({"variable": "message", "operator": "regex", "value": "[unclosed"}, "Invalid pattern"),
    ("not even a dict", "needs a variable and an operator"),
])
async def test_validate_config_payload_reports_per_condition_errors(condition, expected):
    _seed_user_caches()
    payload = {
        "reply_message": "Hi", "wait_time": 600,
        "conditions": [
            {"variable": "message", "operator": "not_empty", "value": "", "case_sensitive": False},
            condition,
        ],
    }
    cfg, errors = await validate_config_payload(payload, _ui_app())
    assert cfg is None
    # Indexed like the buttons editor, so the UI can mark the offending row.
    assert expected in errors["conditions.1"]


@pytest.mark.asyncio
async def test_validate_config_payload_rejects_a_bad_conditions_shape_and_match():
    _seed_user_caches()
    cfg, errors = await validate_config_payload(
        {"reply_message": "Hi", "wait_time": 600, "conditions": "nope", "conditions_mode": "sometimes"},
        _ui_app())
    assert cfg is None
    assert "must be a list" in errors["conditions"]
    assert "conditions_mode" in errors


@pytest.mark.asyncio
@pytest.mark.parametrize("url,expected", [
    ("http://cal.example.com/feed.ics", "https"),
    ("https://127.0.0.1/feed.ics", "internal"),
    ("https://user:pw@cal.example.com/feed.ics", "credentials"),
])
async def test_validate_config_payload_rejects_unsafe_calendar_urls(url, expected):
    _seed_user_caches()
    cfg, errors = await validate_config_payload(
        {"reply_message": "Hi", "wait_time": 600, "calendar_url": url}, _ui_app())
    assert cfg is None
    assert expected in errors["calendar_url"]


def test_ui_meta_ships_condition_operators_in_declared_order():
    meta = ui_meta()
    # Not sorted: each operator has to sit next to its negation in the dropdown.
    assert meta["condition_operators"] == list(CONDITION_OPERATORS_ORDERED)
    assert meta["condition_operators"] != sorted(meta["condition_operators"])
    assert meta["condition_operators_without_value"] == sorted(CONDITION_OPERATORS_WITHOUT_VALUE)
    assert meta["condition_modes"] == [CONDITION_MODE_ALL, CONDITION_MODE_ANY]
    # The variable picker and the defaults pick up the calendar entries for free.
    assert CALENDAR_TEMPLATE_VARIABLES <= set(meta["template_variables"])
    assert meta["default_config"]["conditions"] == []
    assert "conditions" not in meta
