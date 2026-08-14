from tests._common import *  # noqa: F401,F403



@pytest.mark.asyncio
async def test_add_button_copy_on_write_and_clear():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "test", "Test User", "Testers")
    default_buttons_before = list(DEFAULT_CONFIG["buttons"])
    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message'):
        await process_command(app, 'add button "Approve" config approve-flow', channel, user)
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
        await process_command(app, 'add button "FAQ" ack "See the wiki"', channel, user)
        # A delay button needs something to postpone.
        await process_command(app, "set escalation 5 config approve-flow", channel, user)
        await process_command(app, 'add button "Wait" delay 3', channel, user)
        await process_command(app, 'add button "Run" config approve-flow', channel, user)
    assert channel.configs["default"]["buttons"] == [
        {"label": "Ack", "action": "ack", "value": "Got it"},
        {"label": "FAQ", "action": "ack", "value": "See the wiki"},
        {"label": "Wait", "action": "delay", "value": "3"},
        {"label": "Run", "action": "config", "value": "approve-flow"},
    ]
    # invalid delay rejected
    await process_command(app, 'add button "Bad" delay nope', channel, user)
    assert len(channel.configs["default"]["buttons"]) == 4



@pytest.mark.asyncio
async def test_migrate_keeps_buttons_to_label_action_value():
    cfg = DEFAULT_CONFIG.copy()
    cfg["buttons"] = [
        {"label": "Run", "action": "config", "value": "approve-flow", "stray": 1},
        {"label": "Plain"},
        "not-a-button",
    ]
    config = {"C12345": {"default": cfg}}
    migrated = await migrate_and_apply_defaults(AsyncMock(), config)
    assert migrated["C12345"]["default"]["buttons"] == [
        {"label": "Run", "action": "config", "value": "approve-flow"},
        {"label": "Plain", "action": "config", "value": ""},
    ]


@pytest.mark.asyncio
async def test_add_button_requires_an_action_keyword():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "test", "Test User", "Testers")
    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as send:
        await process_command(app, 'add button "Approve" approve-flow', channel, user)

    assert channel.configs["default"]["buttons"] == []
    assert send.call_args.args[3] == (
        "Invalid *button action* `approve-flow`. Must be one of `ack`, `config`, `delay`."
    )



@pytest.mark.asyncio
async def test_set_escalation_stores_minutes_kind_and_target():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "test", "Test User", "Testers")
    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as send:
        await process_command(app, "set escalation 15 config escalate", channel, user)
        cfg = channel.configs["default"]
        assert (cfg["escalation_timeout"], cfg["escalation_kind"], cfg["escalation_target"]) == (900, "config", "escalate")
        assert "after `15` minutes without a press, run `escalate`" in send.call_args.args[3]

        await process_command(app, 'add button "Yes" ack', channel, user)
        await process_command(app, 'escalation 5 button "Yes"', channel, user)
        assert (cfg["escalation_timeout"], cfg["escalation_kind"], cfg["escalation_target"]) == (300, "button", "Yes")

        # `none` points at the clear command instead of doing it silently.
        await process_command(app, "set escalation none", channel, user)
        assert "use `/hutbot default clear escalation`" in send.call_args.args[3]
        assert cfg["escalation_timeout"] == 300

        await process_command(app, "clear escalation", channel, user)
        assert (cfg["escalation_timeout"], cfg["escalation_kind"], cfg["escalation_target"]) == (0, "none", "")
        assert "buttons stay open until pressed" in send.call_args.args[3]


@pytest.mark.asyncio
async def test_set_escalation_refuses_half_a_setting():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "test", "Test User", "Testers")
    cfg = channel.configs["default"]
    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as send:
        # A timeout with nothing to escalate to used to be accepted and do nothing.
        await process_command(app, "set escalation 5", channel, user)
        assert "needs what to escalate to" in send.call_args.args[3]
        # A button that does not exist would only fail at escalation time.
        await process_command(app, 'set escalation 5 button "Nope"', channel, user)
        assert "No button labelled `Nope`" in send.call_args.args[3]
        await process_command(app, "set escalation 5 button", channel, user)
        assert "needs a button label" in send.call_args.args[3]
        await process_command(app, "set escalation 0 config escalate", channel, user)
        assert "clear escalation" in send.call_args.args[3]
        await process_command(app, "set escalation 5000 config escalate", channel, user)
        assert "between 1 and 1440" in send.call_args.args[3]

    assert (cfg["escalation_timeout"], cfg["escalation_kind"], cfg["escalation_target"]) == (0, "none", "")



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


def test_build_button_blocks_respects_slack_block_limits():
    config = DEFAULT_CONFIG.copy()
    config["buttons"] = [
        {"label": f"Button {i}", "action": "ack", "value": ""}
        for i in range(26)
    ]
    text = "x" * 6001

    blocks = hutbot.buttons.build_button_blocks(config, "C12345", "src", text)

    sections = [block for block in blocks if block["type"] == "section"]
    actions_blocks = [block for block in blocks if block["type"] == "actions"]
    assert "".join(block["text"]["text"] for block in sections) == text
    assert all(len(block["text"]["text"]) <= 3000 for block in sections)
    assert [len(block["elements"]) for block in actions_blocks] == [25, 1]
    assert actions_blocks[1]["elements"][0]["action_id"] == "hutbot_btn:25"



@pytest.mark.asyncio
async def test_run_action_reply_posts_with_buttons():
    app = AsyncMock()
    app.client.chat_postMessage.return_value = {"ts": "99.1"}
    config = DEFAULT_CONFIG.copy()
    config["action"] = hutbot.constants.ACTION_REPLY
    config["reply_message"] = "Hi there"
    config["buttons"] = [{"label": "Ok", "action": "config", "value": "tgt"}]
    config["escalation_timeout"] = 0  # no timeout watch
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
    key = ("C12345", "10.1")
    hutbot.state.pending_buttons[key] = {"task": None, "buttons": src_config["buttons"], "orig": {}}
    with patch('hutbot.persistence.flush_button_cache', new=AsyncMock()), \
         patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=User("U9", "bob", "Bob", "T"))), \
         patch('hutbot.actions.run_action', new=AsyncMock()) as run:
        await hutbot.buttons.handle_button_press(app, "token", body, action)
    assert key not in hutbot.state.pending_buttons
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
    key = ("C12345", "10.1")
    hutbot.state.pending_buttons[key] = {"task": None, "buttons": src_config["buttons"], "orig": {}}
    with patch('hutbot.persistence.flush_button_cache', new=AsyncMock()), \
         patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=User("U9", "bob", "Bob", "T"))), \
         patch('hutbot.messaging._post_message', new=AsyncMock()) as post, \
         patch('hutbot.actions.run_action', new=AsyncMock()) as run:
        await hutbot.buttons.handle_button_press(app, "token", body, action)
    assert key not in hutbot.state.pending_buttons
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
    with patch('hutbot.persistence.flush_button_cache', new=AsyncMock()), \
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
    key = ("C12345", "10.1")
    entry = {"task": None, "buttons": src_config["buttons"], "orig": {}}
    hutbot.state.pending_buttons[key] = entry
    with patch('hutbot.persistence.flush_button_cache', new=AsyncMock()), \
         patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=User("U9", "bob", "Bob", "T"))), \
         patch('hutbot.buttons.reschedule_escalation', new=AsyncMock()) as resched:
        await hutbot.buttons.handle_button_press(app, "token", body, action)
    assert resched.await_args.args == (app, "token", "C12345", "10.1", 3)
    assert resched.await_args.kwargs == {"_entry": entry}



@pytest.mark.asyncio
async def test_register_and_cancel_escalation():
    app = AsyncMock()
    config = DEFAULT_CONFIG.copy()
    config["buttons"] = [{"label": "Ok", "action": "config", "value": "tgt"}]
    config["escalation_timeout"] = 3600
    config["escalation_kind"] = "config"
    config["escalation_target"] = "escalate"
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
async def test_cancelled_timer_keeps_persisted_record_for_restart():
    app = AsyncMock()
    config = DEFAULT_CONFIG.copy()
    config["buttons"] = [{"label": "Ok", "action": "config", "value": "tgt"}]
    config["escalation_timeout"] = 3600
    config["escalation_kind"] = "config"
    config["escalation_target"] = "escalate"
    key = ("C12345", "10.1")

    with patch('hutbot.persistence.flush_button_cache', new=AsyncMock()) as flush:
        await hutbot.buttons.register_escalation(
            app, "token", "C12345", "10.1", "C12345", "src", config, {"text": "x", "ts": "9.1"})
        task = hutbot.state.pending_buttons[key]["task"]
        await asyncio.sleep(0)
        flush.reset_mock()

        task.cancel()
        await task

        assert key in hutbot.state.pending_buttons
        assert key in hutbot.state._button_states_cache
        flush.assert_not_awaited()
        await hutbot.buttons.cancel_pending_button(*key)


@pytest.mark.asyncio
async def test_button_record_is_consumed_once_for_duplicate_and_stale_presses():
    app = AsyncMock()
    target = {**DEFAULT_CONFIG.copy(), "trigger": "manual"}
    src = {**DEFAULT_CONFIG.copy(), "buttons": [{"label": "Go", "action": "config", "value": "tgt"}]}
    channel = _mk_channel({"src": src, "tgt": target})
    key = ("C12345", "10.1")
    record = {"task": None, "buttons": src["buttons"], "orig": {}}
    hutbot.state.pending_buttons[key] = record
    hutbot.state._button_states_cache[key] = {k: v for k, v in record.items() if k != "task"}
    body = {"channel": {"id": "C12345"}, "container": {"message_ts": "10.1"}, "user": {"id": "U9"}}
    button_action = {"action_id": "hutbot_btn:0", "value": json.dumps({"channel": "C12345", "config": "src", "index": 0})}

    with patch('hutbot.persistence.flush_button_cache', new=AsyncMock()), \
         patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=User("U9", "bob", "Bob", "T"))), \
         patch('hutbot.actions.run_action', new=AsyncMock()) as run:
        await asyncio.gather(
            hutbot.buttons.handle_button_press(app, "token", body, button_action),
            hutbot.buttons.handle_button_press(app, "token", body, button_action),
        )
        await hutbot.buttons.handle_button_press(app, "token", body, button_action)

    run.assert_awaited_once()
    assert key not in hutbot.state.pending_buttons
    assert key not in hutbot.state._button_states_cache



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
    cfg["escalation_timeout"] = 0
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
async def test_the_old_three_commands_are_gone():
    app = AsyncMock()
    channel = _mk_channel()
    user = User("U1", "test", "Test User", "Testers")
    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as send:
        for gone in ('set default-button "Yes"', "clear default-button", "set button-timeout 5",
                     "set button-timeout-target alarm"):
            await process_command(app, gone, channel, user)
            assert "Huh?" in send.call_args.args[3], gone
    cfg = channel.configs["default"]
    assert (cfg["escalation_timeout"], cfg["escalation_kind"], cfg["escalation_target"]) == (0, "none", "")



def test_escalation_kind_reads_what_was_stored():
    import hutbot
    cfg = DEFAULT_CONFIG.copy()
    assert hutbot.buttons._escalation_kind(cfg) == (ESCALATION_NONE, "")

    cfg["escalation_kind"], cfg["escalation_target"] = "button", "Yes"
    assert hutbot.buttons._escalation_kind(cfg) == ("button", "Yes")

    cfg["escalation_kind"], cfg["escalation_target"] = "config", "some-config"
    assert hutbot.buttons._escalation_kind(cfg) == ("config", "some-config")

    # Half a setting escalates nothing.
    cfg["escalation_target"] = ""
    assert hutbot.buttons._escalation_kind(cfg) == (ESCALATION_NONE, "")



@pytest.mark.asyncio
async def test_escalation_task_auto_presses_default_button():
    app = AsyncMock()
    src = DEFAULT_CONFIG.copy()
    src["buttons"] = [
        {"label": "Yes", "action": "ack", "value": "Here is the help"},
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
    config["escalation_timeout"] = 3600
    config["escalation_kind"] = "config"
    config["escalation_target"] = "escalate"
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
    # The buttons are replaced by a note saying who took the message.
    assert kw["ts"] == "10.1" and kw["text"] == "Approve?\n\n🔘 _`Ack` Bob_"


@pytest.mark.asyncio
async def test_cancel_channel_pending_buttons():
    task = MagicMock()
    task.done.return_value = False
    posted_here = ("C12345", "1.1")
    defined_here = ("C99999", "2.2")
    unrelated = ("C99999", "3.3")

    hutbot.state.pending_buttons.clear()
    hutbot.state.pending_buttons[posted_here] = {
        "task": task, "posted_channel_id": "C12345", "def_channel_id": "C12345", "orig": {}}
    hutbot.state.pending_buttons[defined_here] = {
        # posted elsewhere by a rule that lives in the removed channel
        "task": None, "posted_channel_id": "C99999", "def_channel_id": "C12345", "orig": {}}
    hutbot.state.pending_buttons[unrelated] = {
        "task": None, "posted_channel_id": "C99999", "def_channel_id": "C99999", "orig": {}}
    hutbot.state._button_states_cache.clear()
    for key, entry in hutbot.state.pending_buttons.items():
        hutbot.state._button_states_cache[key] = {k: v for k, v in entry.items() if k != "task"}
    # A cached record with no live counterpart (never restored) goes too.
    hutbot.state._button_states_cache[("C12345", "4.4")] = {
        "posted_channel_id": "C12345", "def_channel_id": "C12345"}

    with patch('hutbot.persistence.flush_button_cache') as mock_flush:
        cancelled = await hutbot.buttons.cancel_channel_pending_buttons("C12345")

    assert cancelled == 3
    assert list(hutbot.state.pending_buttons.keys()) == [unrelated]
    assert list(hutbot.state._button_states_cache.keys()) == [unrelated]
    task.cancel.assert_called_once()
    mock_flush.assert_awaited_once()


@pytest.mark.asyncio
async def test_cancel_channel_pending_buttons_without_matches_does_not_flush():
    hutbot.state.pending_buttons[("C99999", "1.1")] = {
        "task": None, "posted_channel_id": "C99999", "def_channel_id": "C99999", "orig": {}}
    with patch('hutbot.persistence.flush_button_cache') as mock_flush:
        assert await hutbot.buttons.cancel_channel_pending_buttons("C12345") == 0
        assert await hutbot.buttons.cancel_channel_pending_buttons("") == 0
    mock_flush.assert_not_awaited()


@pytest.mark.asyncio
async def test_button_message_is_a_template_rendered_against_the_original_message():
    import hutbot
    app = AsyncMock()
    config = {**DEFAULT_CONFIG.copy(), "date_format": "%d.%m.%Y", "datetime_timezone": "Europe/Berlin"}
    channel = Channel(id="C1", name="davetest", configs={"default": config})
    author = User("UAUTH", "author", "Ada Author", "Platform")
    entry = {
        'posted_channel_id': "C1", 'message_ts': "R1", 'def_channel_id': "C1", 'config_name': "default",
        'orig': {'user_id': author.id, 'text': "the server is down", 'ts': "1786453297.645799", 'permalink': "https://slack.test/p1"},
    }
    button = {'label': "help", 'action': "ack",
              'value': "Help <@UAUTH> with {{message}} from {{date}} ({{user_name}}) — {{message_link}}"}

    with patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=author)), \
         patch('hutbot.messaging._post_message', new=AsyncMock(return_value={"channel": "C1", "ts": "R2"})) as post:
        run_context = await hutbot.buttons._escalation_context(app, entry, "C1", "R1")
        await hutbot.buttons.dispatch_button_action(app, "tok", channel, "C1", "R1", button, run_context, config, "default")

    assert post.await_args.args[2] == (
        "Help <@UAUTH> with the server is down from 11.08.2026 (Ada Author) — https://slack.test/p1"
    )
    # Posted in the thread of the buttoned message.
    assert post.await_args.args[4] == "R1"


@pytest.mark.asyncio
async def test_add_button_resolves_mentions_and_rejects_unknown_variables():
    app = AsyncMock()
    config = DEFAULT_CONFIG.copy()
    channel = Channel(id="C1", name="davetest", configs={"default": config})
    user = User("U1", "dave", "Dave", "T")
    author = User("UAUTH", "author", "Ada Author", "Platform")

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.slackcache.get_user_by_name', new=AsyncMock(return_value=author)), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, 'add button "help" ack "Help @author with {{message}}"', channel, user)
        assert config["buttons"] == [
            {"label": "help", "action": "ack", "value": "Help <@UAUTH> with {{message}}"}
        ]

        await process_command(app, 'add button "bad" ack "{{nope}}"', channel, user)
        assert "unsupported template variable(s) `{{nope}}`" in send.call_args.args[3]
        # Nothing added for the rejected button.
        assert len(config["buttons"]) == 1

        # `ack` text gets the same treatment.
        await process_command(app, 'add button "ok" ack "Thanks @author"', channel, user)
        assert config["buttons"][1]["value"] == "Thanks <@UAUTH>"


@pytest.mark.asyncio
async def test_add_button_reports_an_unknown_mention():
    app = AsyncMock()
    config = DEFAULT_CONFIG.copy()
    channel = Channel(id="C1", name="davetest", configs={"default": config})
    user = User("U1", "dave", "Dave", "T")

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.slackcache.get_user_by_name', new=AsyncMock(return_value=User(None, "ghost", "", "T"))), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, 'add button "help" ack "Help @ghost"', channel, user)

    assert send.call_args.args[3] == "Invalid *button* message: ghost not found."
    assert config["buttons"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("command", ["clear escalation", "unset escalation", "remove escalation"])
async def test_clear_escalation_switches_it_off(command):
    app = AsyncMock()
    channel = _mk_channel()
    config = channel.configs["default"]
    config.update({"escalation_timeout": 300, "escalation_kind": "config", "escalation_target": "alarm"})
    user = User("U1", "test", "Test User", "Testers")

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as send:
        await process_command(app, command, channel, user)

    assert (config["escalation_timeout"], config["escalation_kind"], config["escalation_target"]) == (0, ESCALATION_NONE, "")
    assert send.call_args.args[3] == (
        "*Escalation* cleared in configuration `default`; buttons stay open until pressed."
    )


@pytest.mark.asyncio
async def test_delay_press_without_an_escalation_keeps_the_buttons_and_starts_no_timer():
    import hutbot
    app = AsyncMock()
    channel = _mk_channel()
    key = ("C12345", "R1")
    hutbot.state.pending_buttons.clear()
    hutbot.state._button_states_cache.clear()
    hutbot.state.pending_buttons[key] = {
        "task": None, "posted_channel_id": "C12345", "message_ts": "R1",
        "def_channel_id": "C12345", "config_name": "default",
        "escalation_kind": ESCALATION_NONE, "escalation_target": "",
        "buttons": [{"label": "Later", "action": "delay", "value": "10"}],
        "orig": {"user_id": "U1", "text": "x", "ts": "9.9", "permalink": "p"},
    }

    with patch('hutbot.persistence.flush_button_cache', new=AsyncMock()):
        delayed = await hutbot.buttons.reschedule_escalation(app, "tok", "C12345", "R1", 10)

    assert delayed is False
    entry = hutbot.state.pending_buttons[key]
    # Record kept so the other buttons still resolve, but no timer was created.
    assert entry["task"] is None
    assert entry["escalation_kind"] == ESCALATION_NONE


@pytest.mark.asyncio
async def test_add_delay_button_requires_an_escalation():
    app = AsyncMock()
    channel = _mk_channel()
    config = channel.configs["default"]
    user = User("U1", "test", "Test User", "Testers")

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as send:
        await process_command(app, 'add button "Later" delay 10', channel, user)
        assert send.call_args.args[3] == (
            'A `delay` button needs an escalation to postpone. Set one first with '
            '`/hutbot default set escalation <minutes> <button "<label>"|config <name>>`.'
        )
        assert config["buttons"] == []

        await process_command(app, "set escalation 5 config alarm", channel, user)
        await process_command(app, 'add button "Later" delay 10', channel, user)

    assert config["buttons"] == [{"label": "Later", "action": "delay", "value": "10"}]


@pytest.mark.asyncio
async def test_clear_escalation_warns_about_a_stranded_delay_button():
    app = AsyncMock()
    channel = _mk_channel()
    config = channel.configs["default"]
    user = User("U1", "test", "Test User", "Testers")

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as send:
        await process_command(app, "set escalation 5 config alarm", channel, user)
        await process_command(app, 'add button "Later" delay 10', channel, user)
        await process_command(app, "clear escalation", channel, user)

    assert send.call_args.args[3] == (
        "*Escalation* cleared in configuration `default`; buttons stay open until pressed "
        ":warning: (`Later` now has nothing to postpone)."
    )


@pytest.mark.asyncio
async def test_add_is_optional_for_button_commands():
    app = AsyncMock()
    channel = _mk_channel()
    config = channel.configs["default"]
    user = User("U1", "test", "Test User", "Testers")

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message') as send:
        await process_command(app, 'button "Yes" ack "Got it"', channel, user)
        await process_command(app, 'add button "FAQ" ack "See the wiki"', channel, user)
        # A label alone is not a command.
        await process_command(app, "button", channel, user)
        assert "Huh?" in send.call_args.args[3]

    assert config["buttons"] == [
        {"label": "Yes", "action": "ack", "value": "Got it"},
        {"label": "FAQ", "action": "ack", "value": "See the wiki"},
    ]


@pytest.mark.asyncio
async def test_a_config_named_button_still_gets_its_own_commands():
    app = AsyncMock()
    configs = {"default": DEFAULT_CONFIG.copy(), "button": DEFAULT_CONFIG.copy()}
    channel = Channel(id="C1", name="davetest", configs=configs)
    user = User("U1", "test", "Test User", "Testers")

    with patch('hutbot.persistence.save_configuration'), patch('hutbot.messaging.send_message'):
        # `wait-time 5` is a command, so the leading word is the config.
        await process_command(app, "button wait-time 5", channel, user)
        # `"Yes" ack` is not, so this adds a button to `default`.
        await process_command(app, 'button "Yes" ack', channel, user)

    assert configs["button"]["wait_time"] == 300
    assert configs["button"]["buttons"] == []
    assert [b["label"] for b in configs["default"]["buttons"]] == ["Yes"]


@pytest.mark.asyncio
@pytest.mark.parametrize("button,expected", [
    ({"label": "I've got it", "action": "ack", "value": "On it"}, "🔘 _`I've got it` Dave Grieser_"),
    ({"label": "No", "action": "ack", "value": ""}, "🔘 _`No` Dave Grieser_"),
    ({"label": "Page", "action": "config", "value": "alarm"}, "🔘 _`Page` Dave Grieser_ ▶️ _`alarm`_"),
])
async def test_a_press_leaves_a_note_in_place_of_the_buttons(button, expected):
    import hutbot
    app = AsyncMock()
    channel = _mk_channel({"default": DEFAULT_CONFIG.copy(), "alarm": DEFAULT_CONFIG.copy()})
    dave = User("U1", "dave", "Dave Grieser", "T")
    key = ("C12345", "R1")
    hutbot.state.pending_buttons.clear()
    hutbot.state.pending_buttons[key] = {
        "task": None, "orig": {}, "posted_text": "Incident — on it?",
        "posted_channel_id": "C12345", "message_ts": "R1", "def_channel_id": "C12345",
        "config_name": "default", "buttons": [button],
    }
    body = {"channel": {"id": "C12345"}, "container": {"message_ts": "R1"}, "user": {"id": "U1"}}
    action = {"value": json.dumps({"channel": "C12345", "config": "default", "index": 0})}

    with patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=dave)), \
         patch('hutbot.persistence.flush_button_cache', new=AsyncMock()), \
         patch('hutbot.messaging._post_message', new=AsyncMock(return_value={"channel": "C12345", "ts": "R2"})), \
         patch('hutbot.actions.run_action', new=AsyncMock()):
        await hutbot.buttons.handle_button_press(app, "token", body, action)

    assert app.client.chat_update.await_args.kwargs["text"] == f"Incident — on it?\n\n{expected}"


@pytest.mark.asyncio
@pytest.mark.parametrize("escalation,expected", [
    ({"escalation_kind": "button", "escalation_target": "I've got it", "timeout": 60}, "⏰ _`1m`_"),
    ({"escalation_kind": "config", "escalation_target": "alarm", "timeout": 300}, "⏰ _`5m`_ ▶️ _`alarm`_"),
])
async def test_an_escalation_leaves_a_note_in_place_of_the_buttons(escalation, expected):
    import hutbot
    app = AsyncMock()
    channel = _mk_channel({"default": DEFAULT_CONFIG.copy(), "alarm": DEFAULT_CONFIG.copy()})
    key = ("C12345", "R1")
    hutbot.state.pending_buttons.clear()
    hutbot.state.pending_buttons[key] = {
        "task": None, "orig": {}, "posted_text": "Incident — on it?",
        "posted_channel_id": "C12345", "message_ts": "R1", "def_channel_id": "C12345",
        "config_name": "default", "buttons": [{"label": "I've got it", "action": "ack", "value": "On it"}],
        **escalation,
    }

    with patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=User("U1", "dave", "Dave", "T"))), \
         patch('hutbot.persistence.flush_button_cache', new=AsyncMock()), \
         patch('hutbot.messaging._post_message', new=AsyncMock(return_value={"channel": "C12345", "ts": "R2"})), \
         patch('hutbot.actions.run_action', new=AsyncMock()):
        await hutbot.buttons._escalation_task(app, "token", key, 0)

    assert app.client.chat_update.await_args.kwargs["text"] == f"Incident — on it?\n\n{expected}"
