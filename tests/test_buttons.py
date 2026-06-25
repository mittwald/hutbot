from tests._common import *  # noqa: F401,F403



@pytest.mark.asyncio
async def test_add_button_copy_on_write_and_clear():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "test", "Test User", "Testers")
    default_buttons_before = list(DEFAULT_CONFIG["buttons"])
    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message'):
        await process_command(app, 'add button "Approve" approve-flow', channel, user)
        # Bare target ⇒ config action (back-compat).
        assert channel.configs["default"]["buttons"] == [{"label": "Approve", "action": "config", "value": "approve-flow"}]
        # DEFAULT_CONFIG's list must not have been mutated (copy-on-write).
        assert DEFAULT_CONFIG["buttons"] == default_buttons_before
        await process_command(app, "clear buttons", channel, user)
        assert channel.configs["default"]["buttons"] == []



@pytest.mark.asyncio
async def test_add_button_typed_actions():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "test", "Test User", "Testers")
    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as send:
        await process_command(app, 'add button "Ack" ack "Got it"', channel, user)
        await process_command(app, 'add button "FAQ" message "See the wiki"', channel, user)
        await process_command(app, 'add button "Wait" delay 3', channel, user)
        await process_command(app, 'add button "Run" config approve-flow', channel, user)
    assert channel.configs["default"]["buttons"] == [
        {"label": "Ack", "action": "ack", "value": "Got it"},
        {"label": "FAQ", "action": "message", "value": "See the wiki"},
        {"label": "Wait", "action": "delay", "value": "3"},
        {"label": "Run", "action": "config", "value": "approve-flow"},
    ]
    # invalid delay rejected
    await process_command(app, 'add button "Bad" delay nope', channel, user)
    assert len(channel.configs["default"]["buttons"]) == 4



@pytest.mark.asyncio
async def test_migrate_normalizes_legacy_buttons():
    cfg = DEFAULT_CONFIG.copy()
    cfg["buttons"] = [{"label": "Old", "target": "legacy-flow"}]
    config = {"C12345": {"default": cfg}}
    migrated = await migrate_and_apply_defaults(AsyncMock(), config)
    assert migrated["C12345"]["default"]["buttons"] == [{"label": "Old", "action": "config", "value": "legacy-flow"}]



@pytest.mark.asyncio
async def test_set_button_timeout_minutes_to_seconds():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "test", "Test User", "Testers")
    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message'):
        await process_command(app, "set button-timeout 15", channel, user)
        assert channel.configs["default"]["button_timeout"] == 900
        await process_command(app, "set button-timeout-target escalate", channel, user)
        assert channel.configs["default"]["button_timeout_target"] == "escalate"



# ----- Actions -----

def test_build_button_blocks_structure():
    config = DEFAULT_CONFIG.copy()
    config["buttons"] = [
        {"label": "Yes", "action": "config", "value": "yes-flow"},
        {"label": "No", "action": "ack", "value": ""},
    ]
    blocks = hutbot.buttons.build_button_blocks(config, "C12345", "src", "Pick one")
    assert blocks[0]["type"] == "section"
    elements = blocks[1]["elements"]
    assert [e["action_id"] for e in elements] == ["hutbot_btn:0", "hutbot_btn:1"]
    # Payload only locates the button; the definition is resolved server-side.
    payload = json.loads(elements[0]["value"])
    assert payload == {"channel": "C12345", "config": "src", "index": 0}



@pytest.mark.asyncio
async def test_run_action_reply_posts_with_buttons():
    app = AsyncMock()
    app.client.chat_postMessage.return_value = {"ts": "99.1"}
    config = DEFAULT_CONFIG.copy()
    config["action"] = hutbot.constants.ACTION_REPLY
    config["reply_message"] = "Hi there"
    config["buttons"] = [{"label": "Ok", "action": "config", "value": "tgt"}]
    config["button_timeout"] = 0  # no timeout watch
    channel = _mk_channel({"src": config})
    with patch('hutbot.buttons.register_escalation', new=AsyncMock()) as reg:
        posted = await hutbot.actions.run_action(app, "token", channel, config, "src", context=None)
    assert posted == {"channel": "C12345", "ts": "99.1", "text": "Hi there"}
    reg.assert_awaited_once()  # buttons present ⇒ escalation registered
    kwargs = app.client.chat_postMessage.call_args.kwargs
    assert kwargs["channel"] == "C12345"
    assert kwargs["text"] == "Hi there"
    assert kwargs["blocks"][1]["type"] == "actions"



# ----- Buttons: press + timeout -----

@pytest.mark.asyncio
async def test_handle_button_press_routes_to_target_and_cancels_timeout():
    app = AsyncMock()
    target_config = DEFAULT_CONFIG.copy()
    target_config["trigger"] = "manual"
    src_config = DEFAULT_CONFIG.copy()
    src_config["buttons"] = [{"label": "Go", "action": "config", "value": "tgt"}]
    channel = _mk_channel({"src": src_config, "tgt": target_config})
    body = {
        "channel": {"id": "C12345"},
        "container": {"message_ts": "10.1"},
        "user": {"id": "U9"},
        "message": {"ts": "10.1"},
    }
    action = {"action_id": "hutbot_btn:0", "value": json.dumps({"channel": "C12345", "config": "src", "index": 0})}
    with patch('hutbot.buttons.cancel_pending_button', new=AsyncMock()) as cancel, \
         patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=User("U9", "bob", "Bob", "T"))), \
         patch('hutbot.actions.run_action', new=AsyncMock()) as run:
        await hutbot.buttons.handle_button_press(app, "token", body, action)
    cancel.assert_awaited_once_with("C12345", "10.1")
    assert run.await_count == 1
    assert run.await_args.args[3] is target_config
    assert run.await_args.args[4] == "tgt"



@pytest.mark.asyncio
async def test_button_press_ack_cancels_without_running_config():
    app = AsyncMock()
    src_config = DEFAULT_CONFIG.copy()
    src_config["buttons"] = [{"label": "Got it", "action": "ack", "value": "Thanks!"}]
    channel = _mk_channel({"src": src_config})
    body = {"channel": {"id": "C12345"}, "container": {"message_ts": "10.1"}, "user": {"id": "U9"}}
    action = {"action_id": "hutbot_btn:0", "value": json.dumps({"channel": "C12345", "config": "src", "index": 0})}
    with patch('hutbot.buttons.cancel_pending_button', new=AsyncMock()) as cancel, \
         patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=User("U9", "bob", "Bob", "T"))), \
         patch('hutbot.messaging._post_message', new=AsyncMock()) as post, \
         patch('hutbot.actions.run_action', new=AsyncMock()) as run:
        await hutbot.buttons.handle_button_press(app, "token", body, action)
    cancel.assert_awaited_once_with("C12345", "10.1")
    run.assert_not_awaited()
    post.assert_awaited_once_with(app, "C12345", "Thanks!", None, "10.1")



@pytest.mark.asyncio
async def test_button_press_config_passes_orig_context():
    # A `config` button runs its target with the *original* message context, so a
    # target with OpsGenie on alerts about the original message.
    app = AsyncMock()
    target_config = DEFAULT_CONFIG.copy()
    target_config["trigger"] = "manual"
    src_config = DEFAULT_CONFIG.copy()
    src_config["buttons"] = [{"label": "Help needed", "action": "config", "value": "oncall"}]
    channel = _mk_channel({"src": src_config, "oncall": target_config})
    hutbot.state.pending_buttons.clear()
    hutbot.state.pending_buttons[("C12345", "10.1")] = {"task": None, "orig": {"user_id": "U5", "text": "help", "ts": "9.9", "permalink": "p"}}
    body = {"channel": {"id": "C12345"}, "container": {"message_ts": "10.1"}, "user": {"id": "U9"}}
    action = {"action_id": "hutbot_btn:0", "value": json.dumps({"channel": "C12345", "config": "src", "index": 0})}
    with patch('hutbot.buttons.cancel_pending_button', new=AsyncMock()), \
         patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=User("U5", "carol", "Carol", "T"))), \
         patch('hutbot.actions.run_action', new=AsyncMock()) as run:
        await hutbot.buttons.handle_button_press(app, "token", body, action)
    run.assert_awaited_once()
    assert run.await_args.args[4] == "oncall"
    ctx = run.await_args.kwargs["context"]
    assert ctx["text"] == "help" and ctx["ts"] == "9.9" and ctx["permalink"] == "p"



@pytest.mark.asyncio
async def test_button_press_delay_reschedules():
    app = AsyncMock()
    src_config = DEFAULT_CONFIG.copy()
    src_config["buttons"] = [{"label": "Wait", "action": "delay", "value": "3"}]
    channel = _mk_channel({"src": src_config})
    body = {"channel": {"id": "C12345"}, "container": {"message_ts": "10.1"}, "user": {"id": "U9"}}
    action = {"action_id": "hutbot_btn:0", "value": json.dumps({"channel": "C12345", "config": "src", "index": 0})}
    with patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=User("U9", "bob", "Bob", "T"))), \
         patch('hutbot.buttons.cancel_pending_button', new=AsyncMock()) as cancel, \
         patch('hutbot.buttons.reschedule_escalation', new=AsyncMock()) as resched:
        await hutbot.buttons.handle_button_press(app, "token", body, action)
    resched.assert_awaited_once_with(app, "token", "C12345", "10.1", 3)
    cancel.assert_not_awaited()  # delay reschedules, does not cancel



@pytest.mark.asyncio
async def test_register_and_cancel_escalation():
    app = AsyncMock()
    config = DEFAULT_CONFIG.copy()
    config["buttons"] = [{"label": "Ok", "action": "config", "value": "tgt"}]
    config["button_timeout"] = 3600
    config["button_timeout_target"] = "escalate"
    hutbot.state.pending_buttons.clear()
    with patch('hutbot.persistence.flush_button_cache', new=AsyncMock()):
        await hutbot.buttons.register_escalation(app, "token", "C12345", "10.1", "C12345", "src", config, {"text": "x", "ts": "9.1"})
        entry = hutbot.state.pending_buttons.get(("C12345", "10.1"))
        assert entry is not None
        assert entry["escalation_kind"] == "config" and entry["escalation_target"] == "escalate"
        await hutbot.buttons.cancel_pending_button("C12345", "10.1")
        assert ("C12345", "10.1") not in hutbot.state.pending_buttons
    await asyncio.sleep(0)  # let the cancelled task settle



@pytest.mark.asyncio
async def test_escalation_task_runs_config_target():
    app = AsyncMock()
    escalate = DEFAULT_CONFIG.copy()
    escalate["trigger"] = "manual"
    channel = _mk_channel({"escalate": escalate})
    key = ("C12345", "10.1")
    hutbot.state.pending_buttons.clear()
    hutbot.state.pending_buttons[key] = {
        "task": None, "posted_channel_id": "C12345", "message_ts": "10.1",
        "def_channel_id": "C12345", "config_name": "src",
        "escalation_kind": "config", "escalation_target": "escalate", "orig": {},
    }
    with patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.persistence.flush_button_cache', new=AsyncMock()), \
         patch('hutbot.actions.run_action', new=AsyncMock()) as run:
        await hutbot.buttons._escalation_task(app, "token", key, 0)
    assert run.await_count == 1
    assert run.await_args.args[4] == "escalate"



@pytest.mark.asyncio
async def test_escalation_task_config_passes_orig_context():
    # Timeout → run the target config with the original message context (so an
    # OpsGenie-enabled target alerts about the original message).
    app = AsyncMock()
    oncall = DEFAULT_CONFIG.copy()
    oncall["trigger"] = "manual"
    oncall["opsgenie"] = True
    channel = _mk_channel({"oncall": oncall})
    key = ("C12345", "10.1")
    hutbot.state.pending_buttons.clear()
    hutbot.state.pending_buttons[key] = {
        "task": None, "posted_channel_id": "C12345", "message_ts": "10.1",
        "def_channel_id": "C12345", "config_name": "src",
        "escalation_kind": "config", "escalation_target": "oncall",
        "orig": {"user_id": "U5", "text": "DB down", "ts": "9.9", "permalink": "p"},
    }
    with patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=User("U5", "carol", "Carol", "T"))), \
         patch('hutbot.persistence.flush_button_cache', new=AsyncMock()), \
         patch('hutbot.actions.run_action', new=AsyncMock()) as run:
        await hutbot.buttons._escalation_task(app, "token", key, 0)
    run.assert_awaited_once()
    assert run.await_args.args[4] == "oncall"
    ctx = run.await_args.kwargs["context"]
    assert ctx["text"] == "DB down" and ctx["ts"] == "9.9" and ctx["permalink"] == "p"



@pytest.mark.asyncio
async def test_register_escalation_keeps_record_with_orig():
    # No default-button / timeout-target ⇒ nothing to escalate to (kind none), but a
    # record is still kept so button presses get the original message context.
    app = AsyncMock()
    cfg = DEFAULT_CONFIG.copy()
    cfg["button_timeout"] = 0
    cfg["buttons"] = [{"label": "Yes", "action": "config", "value": "flow"}]
    hutbot.state.pending_buttons.clear()
    with patch('hutbot.persistence.flush_button_cache', new=AsyncMock()):
        await hutbot.buttons.register_escalation(app, "tok", "C12345", "1.1", "C12345", "src", cfg, {"text": "t", "ts": "1.1", "permalink": "p"})
    entry = hutbot.state.pending_buttons.get(("C12345", "1.1"))
    assert entry is not None
    assert entry["escalation_kind"] == "none"
    assert entry["task"] is None and entry["run_at"] == ""
    assert entry["orig"]["text"] == "t" and entry["orig"]["ts"] == "1.1"



# ----- Default button: auto-press on timeout -----

@pytest.mark.asyncio
async def test_set_default_button_command():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "test", "Test User", "Testers")
    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message'):
        await process_command(app, 'set default-button "Yes"', channel, user)
        assert channel.configs["default"]["default_button"] == "Yes"
        await process_command(app, "clear default-button", channel, user)
        assert channel.configs["default"]["default_button"] == ""



def test_escalation_kind_prefers_default_button():
    cfg = DEFAULT_CONFIG.copy()
    cfg["buttons"] = [{"label": "Yes", "action": "message", "value": "Help text"}]
    cfg["default_button"] = "Yes"
    cfg["button_timeout_target"] = "some-config"  # default button still wins
    assert hutbot.buttons._escalation_kind(cfg) == (hutbot.constants.ESCALATION_BUTTON, "Yes")
    # Unknown default-button label falls back to the config target.
    cfg["default_button"] = "Nope"
    assert hutbot.buttons._escalation_kind(cfg) == (hutbot.constants.ESCALATION_CONFIG, "some-config")



@pytest.mark.asyncio
async def test_escalation_task_auto_presses_default_button():
    app = AsyncMock()
    src = DEFAULT_CONFIG.copy()
    src["buttons"] = [
        {"label": "Yes", "action": "message", "value": "Here is the help"},
        {"label": "No", "action": "ack", "value": ""},
    ]
    channel = _mk_channel({"src": src})
    key = ("C12345", "10.1")
    hutbot.state.pending_buttons.clear()
    hutbot.state.pending_buttons[key] = {
        "task": None, "posted_channel_id": "C12345", "message_ts": "10.1",
        "def_channel_id": "C12345", "config_name": "src",
        "escalation_kind": "button", "escalation_target": "Yes", "orig": {},
    }
    with patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.persistence.flush_button_cache', new=AsyncMock()), \
         patch('hutbot.messaging._post_message', new=AsyncMock()) as post:
        await hutbot.buttons._escalation_task(app, "token", key, 0)
    # auto-pressed "Yes" (message) ⇒ posts the help text in the thread
    post.assert_awaited_once_with(app, "C12345", "Here is the help", None, "10.1")


@pytest.mark.asyncio
async def test_delay_press_does_not_clobber_rescheduled_escalation():
    # Regression (F2): a `delay` press cancels the active timer and stores a fresh
    # one under the same key. The cancelled task's cleanup must not remove the new
    # entry, or the delayed escalation would never fire.
    app = AsyncMock()
    config = DEFAULT_CONFIG.copy()
    config["buttons"] = [{"label": "Wait", "action": "delay", "value": "3"}]
    config["button_timeout"] = 3600
    config["button_timeout_target"] = "escalate"
    key = ("C12345", "10.1")
    with patch('hutbot.persistence.flush_button_cache', new=AsyncMock()):
        await hutbot.buttons.register_escalation(
            app, "token", "C12345", "10.1", "C12345", "src", config, {"text": "x", "ts": "9.1"})
        first = hutbot.state.pending_buttons[key]["task"]
        assert await hutbot.buttons.reschedule_escalation(app, "token", "C12345", "10.1", 5)
        try:
            await first  # wait for the cancelled timer to run its finally
        except asyncio.CancelledError:
            pass
        assert key in hutbot.state.pending_buttons        # not clobbered by cancelled task
        entry = hutbot.state.pending_buttons[key]
        assert entry["task"] is not first
        assert entry["timeout"] == 300                    # the rescheduled 5-minute timer
        await hutbot.buttons.cancel_pending_button("C12345", "10.1")
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_config_button_attributes_to_original_author_not_presser():
    # F3: a config-running button pressed by someone else runs with the ORIGINAL
    # author as {{user}}/{{team}}, not the clicker.
    app = AsyncMock()
    target = DEFAULT_CONFIG.copy(); target["trigger"] = "manual"
    src = DEFAULT_CONFIG.copy(); src["buttons"] = [{"label": "Go", "action": "config", "value": "tgt"}]
    channel = _mk_channel({"src": src, "tgt": target})
    users = {"U9": User("U9", "bob", "Bob", "Ops"), "U5": User("U5", "carol", "Carol", "Platform")}
    hutbot.state.pending_buttons[("C12345", "10.1")] = {
        "task": None, "orig": {"user_id": "U5", "text": "help", "ts": "9.9", "permalink": "p"},
        "buttons": src["buttons"], "posted_text": "Need help?",
    }
    body = {"channel": {"id": "C12345"}, "container": {"message_ts": "10.1"}, "user": {"id": "U9"}}
    action = {"action_id": "hutbot_btn:0", "value": json.dumps({"channel": "C12345", "config": "src", "index": 0})}
    with patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(side_effect=lambda app, uid, *a, **k: users[uid])), \
         patch('hutbot.persistence.flush_button_cache', new=AsyncMock()), \
         patch('hutbot.actions.run_action', new=AsyncMock()) as run:
        await hutbot.buttons.handle_button_press(app, "token", body, action)
    ctx = run.await_args.kwargs["context"]
    assert ctx["user"].id == "U5"   # original author, not presser U9
    assert ctx["text"] == "help"


@pytest.mark.asyncio
async def test_button_resolves_from_snapshot_and_strips_after_press():
    # F6: a press resolves against the buttons snapshotted at post time (not a
    # since-edited config), and the message is de-buttoned once handled.
    app = AsyncMock()
    src = DEFAULT_CONFIG.copy(); src["buttons"] = [{"label": "Ack", "action": "ack", "value": "ok"}]
    channel = _mk_channel({"src": src})
    key = ("C12345", "10.1")
    hutbot.state.pending_buttons[key] = {
        "task": None, "orig": {}, "posted_text": "Approve?",
        "buttons": [{"label": "Ack", "action": "ack", "value": "ok"}],
    }
    # config edited AFTER posting: index 0 now maps to a dangerous config action
    channel.configs["src"]["buttons"] = [{"label": "Run", "action": "config", "value": "danger"}]
    body = {"channel": {"id": "C12345"}, "container": {"message_ts": "10.1"}, "user": {"id": "U9"}}
    action = {"action_id": "hutbot_btn:0", "value": json.dumps({"channel": "C12345", "config": "src", "index": 0})}
    with patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=User("U9", "bob", "Bob", "T"))), \
         patch('hutbot.persistence.flush_button_cache', new=AsyncMock()), \
         patch('hutbot.messaging._post_message', new=AsyncMock()) as post, \
         patch('hutbot.actions.run_action', new=AsyncMock()) as run:
        await hutbot.buttons.handle_button_press(app, "token", body, action)
    run.assert_not_awaited()                                   # snapshot ack, not the edited config action
    post.assert_awaited_once_with(app, "C12345", "ok", None, "10.1")
    app.client.chat_update.assert_awaited_once()               # buttons stripped
    kw = app.client.chat_update.await_args.kwargs
    assert kw["ts"] == "10.1" and kw["text"] == "Approve?"
