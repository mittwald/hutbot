"""Renaming a config, and everything that writes its name down."""

from tests._common import *  # noqa: F401,F403


def _seed(configs: dict):
    """Install a channel's configs as the live ones, the way the bot holds them."""
    hutbot.state.channel_config.clear()
    hutbot.state.channel_config["C1"] = configs
    hutbot.state.pending_buttons.clear()
    hutbot.state._button_states_cache.clear()
    hutbot.state.scheduled_messages.clear()
    hutbot.state._scheduled_replies_cache.clear()
    return Channel(id="C1", name="general", configs=configs)


def _config(**overrides):
    return {**DEFAULT_CONFIG.copy(), **overrides}


async def _rename(old, new):
    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.persistence.flush_button_cache', new=AsyncMock()), \
         patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()):
        return await hutbot.renaming.rename_config("C1", old, new)


# ----- the config itself -----

@pytest.mark.asyncio
async def test_rename_moves_the_config_and_keeps_its_settings():
    configs = {"default": _config(), "nag": _config(reply_message="Anybody?", wait_time=120)}
    _seed(configs)
    original = configs["nag"]

    ok, error, changed = await _rename("nag", "standup-nag")

    assert (ok, error) == (True, "")
    assert "nag" not in configs
    # The same object, not a copy: a waiting reminder holds this dict.
    assert configs["standup-nag"] is original
    assert configs["standup-nag"]["reply_message"] == "Anybody?"
    assert changed == {'configs': 0, 'messages': 0, 'reminders': 0}


@pytest.mark.asyncio
async def test_rename_keeps_the_config_where_it_was_in_the_list():
    configs = {"default": _config(), "nag": _config(), "pager": _config()}
    _seed(configs)

    await _rename("nag", "zzz-last-alphabetically")

    assert list(configs) == ["default", "zzz-last-alphabetically", "pager"]


# ----- what points at it -----

@pytest.mark.asyncio
async def test_rename_repoints_buttons_and_escalations_of_other_configs():
    configs = {
        "default": _config(),
        "nag": _config(),
        "watcher": _config(buttons=[{"label": "Page", "action": "config", "value": "nag"},
                                    {"label": "Ok", "action": "ack", "value": "nag"}],
                          escalation_kind="config", escalation_target="nag", escalation_timeout=60),
        "other": _config(buttons=[{"label": "Page", "action": "config", "value": "someone-else"}]),
    }
    _seed(configs)

    ok, _, changed = await _rename("nag", "standup-nag")

    assert ok
    assert configs["watcher"]["buttons"][0]["value"] == "standup-nag"
    # An `ack` value is a message, not a config name, so it is left alone.
    assert configs["watcher"]["buttons"][1]["value"] == "nag"
    assert configs["watcher"]["escalation_target"] == "standup-nag"
    assert configs["other"]["buttons"][0]["value"] == "someone-else"
    assert changed['configs'] == 1


@pytest.mark.asyncio
async def test_rename_follows_a_config_that_points_at_itself():
    configs = {"default": _config(),
               "loop": _config(buttons=[{"label": "Again", "action": "config", "value": "loop"}],
                               escalation_kind="config", escalation_target="loop", escalation_timeout=60)}
    _seed(configs)

    ok, _, changed = await _rename("loop", "again")

    assert ok
    assert configs["again"]["buttons"][0]["value"] == "again"
    assert configs["again"]["escalation_target"] == "again"
    assert changed['configs'] == 1


@pytest.mark.asyncio
async def test_a_button_escalation_target_is_a_label_and_is_left_alone():
    """`escalation_kind: button` names a button label, which no rename should touch."""
    configs = {"default": _config(),
               "watcher": _config(buttons=[{"label": "nag", "action": "ack", "value": ""}],
                                  escalation_kind="button", escalation_target="nag", escalation_timeout=60)}
    _seed(configs)

    await _rename("watcher", "renamed")

    assert configs["renamed"]["escalation_target"] == "nag"


# ----- work already in flight -----

@pytest.mark.asyncio
async def test_rename_repoints_a_buttoned_message_already_posted():
    configs = {"default": _config(), "nag": _config(), "pager": _config(trigger="manual")}
    _seed(configs)
    key = ("C1", "10.1")
    entry = {
        'posted_channel_id': "C1", 'message_ts': "10.1", 'def_channel_id': "C1",
        'config_name': "nag",
        'buttons': [{"label": "Page", "action": "config", "value": "pager"}],
        'escalation_kind': "config", 'escalation_target': "pager",
        'target_conditions': {"pager": {"conditions": [], "conditions_mode": "all"}},
    }
    hutbot.state.pending_buttons[key] = {'task': None, **entry}
    hutbot.state._button_states_cache[key] = entry

    ok, _, changed = await _rename("pager", "escalate")

    assert ok
    for records in (hutbot.state.pending_buttons, hutbot.state._button_states_cache):
        record = records[key]
        assert record['buttons'][0]['value'] == "escalate"
        assert record['escalation_target'] == "escalate"
        assert list(record['target_conditions']) == ["escalate"]
    assert changed['messages'] == 1


@pytest.mark.asyncio
async def test_renaming_the_config_that_posted_a_buttoned_message_renames_it_there_too():
    configs = {"default": _config(), "nag": _config()}
    _seed(configs)
    key = ("C1", "10.1")
    entry = {'posted_channel_id': "C1", 'message_ts': "10.1", 'def_channel_id': "C1",
             'config_name': "nag", 'buttons': [], 'posted_text': "Anybody?"}
    hutbot.state.pending_buttons[key] = {'task': None, **entry}
    hutbot.state._button_states_cache[key] = entry

    await _rename("nag", "standup-nag")

    assert hutbot.state.pending_buttons[key]['config_name'] == "standup-nag"
    assert hutbot.state._button_states_cache[key]['config_name'] == "standup-nag"


@pytest.mark.asyncio
async def test_rename_leaves_another_channels_records_alone():
    configs = {"default": _config(), "nag": _config()}
    _seed(configs)
    elsewhere = ("C9", "10.1")
    entry = {'posted_channel_id': "C9", 'message_ts': "10.1", 'def_channel_id': "C9",
             'config_name': "nag", 'buttons': [{"label": "Go", "action": "config", "value": "nag"}]}
    hutbot.state.pending_buttons[elsewhere] = {'task': None, **entry}
    hutbot.state._button_states_cache[elsewhere] = entry

    ok, _, changed = await _rename("nag", "standup-nag")

    assert ok and changed['messages'] == 0
    assert hutbot.state.pending_buttons[elsewhere]['config_name'] == "nag"
    assert hutbot.state.pending_buttons[elsewhere]['buttons'][0]['value'] == "nag"


@pytest.mark.asyncio
async def test_rename_moves_a_queued_reminder_onto_the_new_name():
    configs = {"default": _config(), "nag": _config()}
    _seed(configs)
    hutbot.state.scheduled_messages[("C1", "9.1", "nag")] = ScheduledReply(task=AsyncMock(), user_id="U1")
    hutbot.state._scheduled_replies_cache[("C1", "9.1", "nag")] = {
        'channel_id': "C1", 'ts': "9.1", 'config_name': "nag", 'user_id': "U1",
        'text': "x", 'send_at': "2026-01-01T00:00:00"}
    hutbot.state.scheduled_messages[("C1", "9.1", "other")] = ScheduledReply(task=AsyncMock(), user_id="U1")

    ok, _, changed = await _rename("nag", "standup-nag")

    assert ok and changed['reminders'] == 1
    assert ("C1", "9.1", "standup-nag") in hutbot.state.scheduled_messages
    assert ("C1", "9.1", "nag") not in hutbot.state.scheduled_messages
    entry = hutbot.state._scheduled_replies_cache[("C1", "9.1", "standup-nag")]
    assert entry['config_name'] == "standup-nag"
    # A reminder of a different config keeps its own key.
    assert ("C1", "9.1", "other") in hutbot.state.scheduled_messages


@pytest.mark.asyncio
async def test_a_reminder_renamed_mid_wait_still_cleans_up_after_itself():
    """The task holds the config object, so it finds its records under the new name."""
    app = AsyncMock()
    app.client.chat_getPermalink.return_value = {"permalink": ""}
    app.client.chat_postMessage.return_value = {"ts": "reply-ts"}
    configs = {"default": _config(), "nag": _config(wait_time=0)}
    channel = _seed(configs)
    config = configs["nag"]
    hutbot.state._scheduled_replies_cache[("C1", "9.1", "nag")] = {
        'channel_id': "C1", 'ts': "9.1", 'config_name': "nag", 'user_id': "U1",
        'text': "x", 'send_at': "2026-01-01T00:00:00"}
    await _rename("nag", "standup-nag")

    with patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()):
        await hutbot.scheduling.schedule_reply(
            app, OPSGENIE_TOKENS, channel, config, "nag", User("U1", "d", "D", "T"), "x", "9.1")

    # Filed under the new name, and cleaned up there — not left behind to fire again on restart.
    assert not hutbot.state._scheduled_replies_cache
    app.client.chat_postMessage.assert_awaited_once()


@pytest.mark.asyncio
async def test_a_deleted_config_still_cleans_up_its_reminder():
    """The other half of the identity lookup: no new name to find, so the old key is used."""
    app = AsyncMock()
    app.client.chat_getPermalink.return_value = {"permalink": ""}
    app.client.chat_postMessage.return_value = {"ts": "reply-ts"}
    configs = {"default": _config(), "nag": _config(wait_time=0)}
    channel = _seed(configs)
    config = configs.pop("nag")
    hutbot.state._scheduled_replies_cache[("C1", "9.1", "nag")] = {
        'channel_id': "C1", 'ts': "9.1", 'config_name': "nag", 'user_id': "U1",
        'text': "x", 'send_at': "2026-01-01T00:00:00"}

    with patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()):
        await hutbot.scheduling.schedule_reply(
            app, OPSGENIE_TOKENS, channel, config, "nag", User("U1", "d", "D", "T"), "x", "9.1")

    assert not hutbot.state._scheduled_replies_cache


# ----- what a rename refuses -----

@pytest.mark.asyncio
@pytest.mark.parametrize("old,new,expected", [
    ("default", "anything", "cannot be renamed"),
    ("missing", "anything", "not found"),
    ("nag", "", "Give the new name"),
    ("nag", "nag", "already called that"),
    ("nag", "bad name!", "Invalid config name"),
    ("nag", "set", "starts a command"),
    ("nag", "RENAME", "starts a command"),
    ("nag", "pager", "already exists"),
])
async def test_rename_refuses(old, new, expected):
    configs = {"default": _config(), "nag": _config(), "pager": _config()}
    _seed(configs)

    ok, error, changed = await hutbot.renaming.rename_config("C1", old, new)

    assert not ok and expected in error and changed == {}
    assert set(configs) == {"default", "nag", "pager"}


@pytest.mark.asyncio
async def test_rename_only_differing_in_case_is_allowed():
    configs = {"default": _config(), "nag": _config()}
    _seed(configs)

    ok, error, _ = await _rename("nag", "Nag")

    assert (ok, error) == (True, "")
    assert list(configs) == ["default", "Nag"]


def test_rename_cannot_be_a_config_name():
    """Otherwise a config called `rename` would swallow the command."""
    assert "rename" in hutbot.constants.RESERVED_CONFIG_NAMES


# ----- the slash command -----

@pytest.mark.asyncio
async def test_the_command_renames_and_reports_what_else_moved():
    app = AsyncMock()
    configs = {"default": _config(), "nag": _config(),
               "watcher": _config(escalation_kind="config", escalation_target="nag", escalation_timeout=60)}
    channel = _seed(configs)

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, "rename config nag standup-nag", channel, User("U1", "d", "D", "T"))

    assert "standup-nag" in configs
    assert send.call_args.args[3] == (
        "Configuration `nag` has been renamed to `standup-nag`; also updated 1 rule.")


@pytest.mark.asyncio
async def test_the_command_says_nothing_extra_when_nothing_else_moved():
    app = AsyncMock()
    configs = {"default": _config(), "nag": _config()}
    channel = _seed(configs)

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, "rename config nag standup-nag", channel, User("U1", "d", "D", "T"))

    assert send.call_args.args[3] == "Configuration `nag` has been renamed to `standup-nag`."


@pytest.mark.asyncio
async def test_the_command_reports_a_refusal():
    app = AsyncMock()
    configs = {"default": _config(), "nag": _config()}
    channel = _seed(configs)

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.messaging.send_message') as send:
        await process_command(app, "rename config nag default", channel, User("U1", "d", "D", "T"))

    assert "already exists" in send.call_args.args[3]
    assert "nag" in configs


@pytest.mark.asyncio
async def test_the_command_is_listed_in_the_help():
    app = AsyncMock()
    channel = _seed({"default": _config()})

    with patch('hutbot.messaging.send_message') as send:
        await process_command(app, "help", channel, User("U1", "d", "D", "T"))

    assert "rename config <name> <new-name>" in sent_messages(send)


# ----- the web UI -----

@pytest.mark.asyncio
async def test_the_ui_renames_through_the_same_rules():
    configs = {"default": _config(), "nag": _config(),
               "watcher": _config(buttons=[{"label": "Go", "action": "config", "value": "nag"}])}
    _seed(configs)

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()), \
         patch('hutbot.persistence.flush_button_cache', new=AsyncMock()), \
         patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()):
        ok, error = await ui_rename_config(_ui_app(), "C1", "nag", "  standup-nag  ")

    assert (ok, error) == (True, "")
    assert "standup-nag" in configs
    assert configs["watcher"]["buttons"][0]["value"] == "standup-nag"


@pytest.mark.asyncio
@pytest.mark.parametrize("old,new,expected", [
    ("default", "x", "cannot be renamed"),
    ("nag", "pager", "already exists"),
    ("nag", "set", "starts a command"),
    ("nag", "", "Give the new name"),
])
async def test_the_ui_refuses_the_same_renames(old, new, expected):
    configs = {"default": _config(), "nag": _config(), "pager": _config()}
    _seed(configs)

    ok, error = await ui_rename_config(_ui_app(), "C1", old, new)

    assert not ok and expected in error
    assert set(configs) == {"default", "nag", "pager"}


@pytest.mark.parametrize("error,status", [
    ("Configuration `nag` not found.", 404),
    ("The `default` configuration cannot be renamed.", 403),
    ("A configuration named `pager` already exists.", 409),
    ("Configuration `nag` is already called that.", 409),
    ("Invalid config name: `bad name!`. Only characters …", 400),
    ("`set` cannot be a configuration name; it starts a command.", 400),
    ("", 400),
])
def test_the_ui_maps_each_refusal_to_a_status(error, status):
    import webui
    assert webui.rename_error_status(error) == status


# ----- in-flight work keeps working under the new name -----

@pytest.mark.asyncio
async def test_a_reminder_renamed_mid_wait_runs_under_the_new_name():
    """`{{config}}` is what the config is called when the reply goes out, not when it queued."""
    app = AsyncMock()
    app.client.chat_getPermalink.return_value = {"permalink": ""}
    app.client.chat_postMessage.return_value = {"ts": "reply-ts"}
    configs = {"default": _config(), "nag": _config(wait_time=0, reply_message="from {{config}}")}
    channel = _seed(configs)
    config = configs["nag"]
    await _rename("nag", "standup-nag")

    with patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()):
        await hutbot.scheduling.schedule_reply(
            app, OPSGENIE_TOKENS, channel, config, "nag", User("U1", "d", "D", "T"), "x", "9.1")

    assert app.client.chat_postMessage.call_args.kwargs["text"] == "from standup-nag"


@pytest.mark.asyncio
async def test_a_reminder_renamed_mid_wait_registers_its_buttons_under_the_new_name():
    """A button posted by the reply must be answerable, which needs the name it is filed under."""
    app = AsyncMock()
    app.client.chat_getPermalink.return_value = {"permalink": ""}
    app.client.chat_postMessage.return_value = {"ts": "reply-ts"}
    configs = {"default": _config(),
               "nag": _config(wait_time=0, buttons=[{"label": "Go", "action": "config", "value": "pager"}]),
               "pager": _config(trigger="manual")}
    channel = _seed(configs)
    config = configs["nag"]
    await _rename("nag", "standup-nag")

    with patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()), \
         patch('hutbot.persistence.flush_button_cache', new=AsyncMock()):
        await hutbot.scheduling.schedule_reply(
            app, OPSGENIE_TOKENS, channel, config, "nag", User("U1", "d", "D", "T"), "x", "9.1")

    record = hutbot.state.pending_buttons[("C1", "reply-ts")]
    assert record['config_name'] == "standup-nag"


@pytest.mark.asyncio
async def test_applying_an_edit_in_the_ui_keeps_the_config_a_reminder_is_holding():
    """The UI used to swap the dict out, which stranded queued work on the old object."""
    _seed_user_caches()
    configs = {"default": _config(), "nag": _config(reply_message="before")}
    _seed(configs)
    held = configs["nag"]

    with patch('hutbot.persistence.save_configuration', new=AsyncMock()):
        ok, errors = await hutbot.webui_backend.ui_apply_config(
            _ui_app(), "C1", "nag", {**_config(), "reply_message": "after"})

    assert (ok, errors) == (True, {})
    assert configs["nag"] is held
    assert held["reply_message"] == "after"


@pytest.mark.asyncio
async def test_a_reminder_still_cleans_up_after_a_rename_then_a_ui_save():
    """Both moves at once: the rename re-keys it, the save must not lose the object."""
    _seed_user_caches()
    app = AsyncMock()
    app.client.chat_getPermalink.return_value = {"permalink": ""}
    app.client.chat_postMessage.return_value = {"ts": "reply-ts"}
    configs = {"default": _config(), "nag": _config(wait_time=0)}
    channel = _seed(configs)
    config = configs["nag"]
    hutbot.state._scheduled_replies_cache[("C1", "9.1", "nag")] = {
        'channel_id': "C1", 'ts': "9.1", 'config_name': "nag", 'user_id': "U1",
        'text': "x", 'send_at': "2026-01-01T00:00:00"}
    await _rename("nag", "standup-nag")
    with patch('hutbot.persistence.save_configuration', new=AsyncMock()):
        await hutbot.webui_backend.ui_apply_config(
            _ui_app(), "C1", "standup-nag", {**_config(), "reply_message": "edited"})

    # `wait_time_override` because the applied payload carries a real wait time — the
    # validator will not accept 0 — and this test is about the cleanup, not the waiting.
    with patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()):
        await hutbot.scheduling.schedule_reply(
            app, OPSGENIE_TOKENS, channel, config, "nag", User("U1", "d", "D", "T"), "x", "9.1",
            wait_time_override=0)

    # Nothing left behind to be restored and fired again after a restart.
    assert not hutbot.state._scheduled_replies_cache


@pytest.mark.asyncio
async def test_a_press_after_a_rename_resolves_the_source_from_the_record():
    """Slack keeps sending the name baked into the posted message; the record is the authority."""
    app = AsyncMock()
    configs = {"default": _config(),
               "nag": _config(date_format="%d.%m.%Y",
                              buttons=[{"label": "Ok", "action": "ack", "value": "ack from {{config}}"}]),
               }
    channel = _seed(configs)
    key = ("C1", "10.1")
    entry = {'posted_channel_id': "C1", 'message_ts': "10.1", 'def_channel_id': "C1",
             'config_name': "nag", 'buttons': configs["nag"]["buttons"], 'orig': {}}
    hutbot.state.pending_buttons[key] = {'task': None, **entry}
    hutbot.state._button_states_cache[key] = entry
    await _rename("nag", "standup-nag")

    # The payload still names `nag`, because it was written into the message when it was posted.
    body = {"channel": {"id": "C1"}, "container": {"message_ts": "10.1"}, "user": {"id": "U9"}}
    action = {"action_id": "hutbot_btn:0",
              "value": json.dumps({"channel": "C1", "config": "nag", "index": 0})}
    with patch('hutbot.persistence.flush_button_cache', new=AsyncMock()), \
         patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=User("U9", "b", "B", "T"))), \
         patch('hutbot.messaging._post_message', new=AsyncMock()) as post:
        await hutbot.buttons.handle_button_press(app, OPSGENIE_TOKENS, body, action)

    assert post.await_args.args[2] == "ack from standup-nag"


@pytest.mark.asyncio
async def test_a_press_on_a_record_without_a_source_name_still_uses_the_payload():
    """A record predating the field has only the payload to go on, and must still resolve."""
    app = AsyncMock()
    configs = {"default": _config(),
               "nag": _config(buttons=[{"label": "Ok", "action": "ack", "value": "thanks"}])}
    channel = _seed(configs)
    key = ("C1", "10.1")
    hutbot.state.pending_buttons[key] = {
        'task': None, 'posted_channel_id': "C1", 'message_ts': "10.1", 'def_channel_id': "C1",
        'orig': {}}
    body = {"channel": {"id": "C1"}, "container": {"message_ts": "10.1"}, "user": {"id": "U9"}}
    action = {"action_id": "hutbot_btn:0",
              "value": json.dumps({"channel": "C1", "config": "nag", "index": 0})}

    with patch('hutbot.persistence.flush_button_cache', new=AsyncMock()), \
         patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=User("U9", "b", "B", "T"))), \
         patch('hutbot.messaging._post_message', new=AsyncMock()) as post:
        await hutbot.buttons.handle_button_press(app, OPSGENIE_TOKENS, body, action)

    # No snapshot on the record, so the button came from the live config the payload names.
    assert post.await_args.args[2] == "thanks"


@pytest.mark.asyncio
async def test_a_rename_rewrites_everything_before_it_yields():
    """A press landing mid-rename must never see a config renamed but a record not yet moved."""
    configs = {"default": _config(),
               "nag": _config(buttons=[{"label": "Go", "action": "config", "value": "pager"}]),
               "pager": _config(trigger="manual")}
    _seed(configs)
    key = ("C1", "10.1")
    entry = {'posted_channel_id': "C1", 'message_ts': "10.1", 'def_channel_id': "C1",
             'config_name': "nag", 'buttons': [{"label": "Go", "action": "config", "value": "pager"}],
             'escalation_kind': "config", 'escalation_target': "pager", 'orig': {}}
    hutbot.state.pending_buttons[key] = {'task': None, **entry}
    hutbot.state._button_states_cache[key] = entry
    seen = []

    async def watch(*a, **k):
        # Runs at the first await of the rename: by now nothing may still say `pager`.
        seen.append({
            'config_gone': "pager" not in configs,
            'record_button': hutbot.state.pending_buttons[key]['buttons'][0]['value'],
            'record_escalation': hutbot.state.pending_buttons[key]['escalation_target'],
            'sibling_button': configs["nag"]["buttons"][0]["value"],
        })

    with patch('hutbot.persistence.save_configuration', new=watch), \
         patch('hutbot.persistence.flush_button_cache', new=AsyncMock()), \
         patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()):
        await hutbot.renaming.rename_config("C1", "pager", "escalate")

    assert seen == [{'config_gone': True, 'record_button': "escalate",
                     'record_escalation': "escalate", 'sibling_button': "escalate"}]
