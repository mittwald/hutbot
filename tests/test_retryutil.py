"""The shared retry policy, and the call sites whose failures must not be silent."""

from tests._common import *  # noqa: F401,F403

import aiohttp

import retryutil


class _SlackResponse(dict):
    """What `SlackApiError` carries in production: a mapping that also has a status and headers."""

    def __init__(self, error="", status_code=None, headers=None):
        super().__init__(error=error)
        self.status_code = status_code
        self.headers = headers or {}


def _slack_error(error="", status_code=None, headers=None):
    return SlackApiError(error or "boom", _SlackResponse(error, status_code, headers))


# ----- what counts as worth another attempt -----


@pytest.mark.parametrize("status,retryable", [
    (200, False), (400, False), (403, False), (404, False),
    (429, True), (500, True), (502, True), (503, True), (599, True), (600, False),
])
def test_is_retryable_status(status, retryable):
    assert retryutil.is_retryable_status(status) is retryable


@pytest.mark.parametrize("error,retryable", [
    (_slack_error("ratelimited"), True),
    (_slack_error("service_unavailable"), True),
    (_slack_error("", status_code=503), True),
    (_slack_error("channel_not_found"), False),
    (_slack_error("invalid_auth"), False),
    (_slack_error("msg_too_long"), False),
    (aiohttp.ClientConnectionError("reset"), True),
    (asyncio.TimeoutError(), True),
    (OSError("no route to host"), True),
    (retryutil.TransientHTTPError("x", 503), True),
    (ValueError("a bug"), False),
])
def test_is_retryable(error, retryable):
    assert retryutil.is_retryable(error) is retryable


@pytest.mark.parametrize("value,seconds", [
    ("30", 30.0), (" 5 ", 5.0), ("0", 0.0),
    (None, None), ("", None), ("Wed, 21 Oct 2015 07:28:00 GMT", None), ("-1", None),
])
def test_parse_retry_after(value, seconds):
    assert retryutil.parse_retry_after(value) == seconds


def test_retry_delay_prefers_what_the_peer_asked_for():
    assert retryutil.retry_delay(_slack_error("ratelimited", headers={"Retry-After": "30"}), 1) == 30
    assert retryutil.retry_delay(retryutil.TransientHTTPError("x", 429, 12.0), 1) == 12
    # …but never longer than the cap, which is what keeps a handler from being held open.
    assert retryutil.retry_delay(retryutil.TransientHTTPError("x", 429, 9999.0), 1) == retryutil.MAX_DELAY


def test_retry_delay_backs_off_without_a_header():
    first = retryutil.retry_delay(_slack_error("", status_code=500), 1, base_delay=10)
    second = retryutil.retry_delay(_slack_error("", status_code=500), 2, base_delay=10)
    assert 10 <= first <= 15 and 20 <= second <= 25


# ----- retry_async -----


@pytest.mark.asyncio
async def test_retry_async_returns_after_a_transient_failure():
    attempts = []

    async def operation():
        attempts.append(1)
        if len(attempts) < 3:
            raise aiohttp.ClientConnectionError("reset")
        return "done"

    assert await retryutil.retry_async(operation, what="x") == "done"
    assert len(attempts) == 3


@pytest.mark.asyncio
async def test_retry_async_does_not_retry_a_permanent_error():
    attempts = []

    async def operation():
        attempts.append(1)
        raise _slack_error("channel_not_found")

    with pytest.raises(SlackApiError):
        await retryutil.retry_async(operation, what="x")
    assert len(attempts) == 1


@pytest.mark.asyncio
async def test_retry_async_reraises_once_the_attempts_are_used_up():
    attempts = []

    async def operation():
        attempts.append(1)
        raise _slack_error("ratelimited")

    with pytest.raises(SlackApiError):
        await retryutil.retry_async(operation, what="x")
    assert len(attempts) == retryutil.DEFAULT_ATTEMPTS


@pytest.mark.asyncio
async def test_retry_async_never_retries_a_cancellation():
    attempts = []

    async def operation():
        attempts.append(1)
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await retryutil.retry_async(operation, what="x")
    assert len(attempts) == 1


@pytest.mark.asyncio
async def test_retry_async_waits_as_long_as_the_peer_asked():
    slept = []

    async def operation():
        raise _slack_error("ratelimited", status_code=429, headers={"Retry-After": "7"})

    with patch('retryutil.asyncio.sleep', new=AsyncMock(side_effect=lambda s: slept.append(s))):
        with pytest.raises(SlackApiError):
            await retryutil.retry_async(operation, what="x")
    # One wait fewer than attempts: nothing is waited for after the last one.
    assert slept == [7, 7]


# ----- Slack posting -----


@pytest.mark.asyncio
async def test_post_message_retries_a_rate_limit():
    app = AsyncMock()
    app.client.chat_postMessage = AsyncMock(side_effect=[
        _slack_error("ratelimited", status_code=429),
        {"ts": "1.1"},
    ])
    posted = await hutbot.messaging._post_message(app, "C1", "hi", None)
    assert posted == {"channel": "C1", "ts": "1.1"}
    assert app.client.chat_postMessage.await_count == 2


@pytest.mark.asyncio
async def test_post_message_does_not_retry_a_permanent_rejection():
    app = AsyncMock()
    app.client.chat_postMessage = AsyncMock(side_effect=_slack_error("channel_not_found"))
    assert await hutbot.messaging._post_message(app, "C1", "hi", None) is None
    assert app.client.chat_postMessage.await_count == 1


@pytest.mark.asyncio
async def test_post_message_retries_a_dropped_connection():
    """slack_sdk re-raises the transport error unwrapped, which the old loop never caught."""
    app = AsyncMock()
    app.client.chat_postMessage = AsyncMock(side_effect=[
        aiohttp.ClientConnectionError("reset"),
        {"ts": "1.1"},
    ])
    assert await hutbot.messaging._post_message(app, "C1", "hi", None) == {"channel": "C1", "ts": "1.1"}
    assert app.client.chat_postMessage.await_count == 2


@pytest.mark.asyncio
async def test_send_message_gives_up_without_raising():
    app = AsyncMock()
    app.client.chat_postEphemeral = AsyncMock(side_effect=_slack_error("ratelimited"))
    channel = _mk_channel()
    await send_message(app, channel, User("U1", "x", "X", "T"), "hi")
    assert app.client.chat_postEphemeral.await_count == retryutil.DEFAULT_ATTEMPTS


# ----- the user cache is filled whole or not at all -----


@contextlib.contextmanager
def _no_employee_directory():
    with patch('hutbot.slackcache.load_employees', new=AsyncMock(return_value={})), \
         patch('hutbot.slackcache.load_employee_mappings', return_value={}):
        yield


def _users_page(members, cursor=""):
    page = {"members": members}
    if cursor:
        page["response_metadata"] = {"next_cursor": cursor}
    return page


@pytest.mark.asyncio
async def test_user_cache_is_not_left_half_filled_by_a_failed_page():
    app = AsyncMock()
    app.client.users_list = AsyncMock(side_effect=[
        _users_page([{"id": "U1", "name": "alice", "real_name": "Alice",
                      "profile": {"email": "alice@example.com"}}], cursor="page2"),
        _slack_error("invalid_auth"),
    ])
    with _no_employee_directory():
        await hutbot.slackcache.update_user_cache(app)
    # Nothing committed, so the next lookup asks again instead of resolving half the
    # workspace to bare ids for the life of the process.
    assert hutbot.state.user_id_cache == {}
    assert hutbot.state.id_user_cache == {}


@pytest.mark.asyncio
async def test_user_cache_retries_after_a_failed_page():
    app = AsyncMock()
    page_one = _users_page([{"id": "U1", "name": "alice", "real_name": "Alice",
                             "profile": {"email": "alice@example.com"}}], cursor="page2")
    page_two = _users_page([{"id": "U2", "name": "bob", "real_name": "Bob",
                             "profile": {"email": "bob@example.com"}}])
    app.client.users_list = AsyncMock(side_effect=[
        page_one, _slack_error("ratelimited"), page_two,
    ])
    with _no_employee_directory():
        await hutbot.slackcache.update_user_cache(app)
    assert set(hutbot.state.user_id_cache) == {"alice", "bob"}


@pytest.mark.asyncio
async def test_channel_members_keep_the_previous_answer_when_a_page_fails():
    app = AsyncMock()
    app.client.conversations_members = AsyncMock(return_value={"members": ["U1", "U2"]})
    assert await get_channel_members(app, "C1") == {"U1", "U2"}
    hutbot.state._channel_members_cache["C1"] = (0.0, {"U1", "U2"})  # expired
    app.client.conversations_members = AsyncMock(side_effect=_slack_error("invalid_auth"))
    assert await get_channel_members(app, "C1") == {"U1", "U2"}


# ----- a scheduled reply is not dropped by a failed send -----


def _reply_config():
    config = DEFAULT_CONFIG.copy()
    config["reply_message"] = "hi"
    return config


@pytest.mark.asyncio
async def test_a_scheduled_reply_is_retried_when_slack_refuses_it():
    app = AsyncMock()
    config = _reply_config()
    channel = _mk_channel({"src": config})
    user = User("U2", "x", "X", "T")
    run = AsyncMock(side_effect=[
        (None, hutbot.actions.DELIVERY_FAILED_REASON),
        ({"channel": "C", "ts": "1", "text": "hi"}, ""),
    ])
    with patch('hutbot.slackcache.get_message_permalink', new=AsyncMock(return_value='')), \
         patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()), \
         patch('hutbot.actions.run_action_with_reason', new=run):
        await schedule_reply(app, OPSGENIE_TOKENS, channel, config, "src", user, "orig", "1.1", wait_time_override=0)
    assert run.await_count == 2


@pytest.mark.asyncio
async def test_a_declined_scheduled_reply_is_not_retried():
    """A condition saying no is a decision, and it would say the same thing a minute later."""
    app = AsyncMock()
    config = _reply_config()
    channel = _mk_channel({"src": config})
    user = User("U2", "x", "X", "T")
    run = AsyncMock(return_value=(None, "the message is empty"))
    with patch('hutbot.slackcache.get_message_permalink', new=AsyncMock(return_value='')), \
         patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()), \
         patch('hutbot.actions.run_action_with_reason', new=run):
        await schedule_reply(app, OPSGENIE_TOKENS, channel, config, "src", user, "orig", "1.1", wait_time_override=0)
    assert run.await_count == 1


@pytest.mark.asyncio
async def test_a_scheduled_reply_is_dropped_only_once_it_is_settled():
    app = AsyncMock()
    config = _reply_config()
    channel = _mk_channel({"src": config})
    user = User("U2", "x", "X", "T")
    key = (channel.id, "1.1", "src")
    hutbot.state.channel_config[channel.id] = channel.configs
    hutbot.state._scheduled_replies_cache[key] = {
        'channel_id': channel.id, 'ts': "1.1", 'config_name': "src",
        'user_id': user.id, 'text': "orig", 'send_at': "2026-01-01T00:00:00",
    }
    seen = []
    run = AsyncMock(side_effect=lambda *a, **k: (
        seen.append(key in hutbot.state._scheduled_replies_cache),
        (None, hutbot.actions.DELIVERY_FAILED_REASON) if len(seen) < 2 else ({"channel": "C", "ts": "1"}, ""),
    )[1])
    with patch('hutbot.slackcache.get_message_permalink', new=AsyncMock(return_value='')), \
         patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()), \
         patch('hutbot.actions.run_action_with_reason', new=run):
        await schedule_reply(app, OPSGENIE_TOKENS, channel, config, "src", user, "orig", "1.1", wait_time_override=0)
    # Still on the books while the retry was pending, gone once it went out.
    assert seen == [True, True]
    assert key not in hutbot.state._scheduled_replies_cache


@pytest.mark.asyncio
async def test_a_shutdown_leaves_a_scheduled_reply_for_the_next_process():
    app = AsyncMock()
    config = _reply_config()
    channel = _mk_channel({"src": config})
    user = User("U2", "x", "X", "T")
    key = (channel.id, "1.1", "src")
    hutbot.state.channel_config[channel.id] = channel.configs
    hutbot.state._scheduled_replies_cache[key] = {
        'channel_id': channel.id, 'ts': "1.1", 'config_name': "src",
        'user_id': user.id, 'text': "orig", 'send_at': "2026-01-01T00:00:00",
    }
    with patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()):
        task = asyncio.create_task(
            schedule_reply(app, OPSGENIE_TOKENS, channel, config, "src", user, "orig", "1.1", wait_time_override=600))
        hutbot.state.scheduled_messages[key] = ScheduledReply(task, user.id)
        await asyncio.sleep(0)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
    assert key in hutbot.state._scheduled_replies_cache
    assert key not in hutbot.state.scheduled_messages


@pytest.mark.asyncio
async def test_a_deliberate_cancellation_drops_the_scheduled_reply():
    """The cancelling caller owns the record now, so the reply must not come back on restart."""
    app = AsyncMock()
    config = _reply_config()
    channel = _mk_channel({"src": config})
    user = User("U2", "x", "X", "T")
    key = (channel.id, "1.1", "src")
    hutbot.state.channel_config[channel.id] = channel.configs
    hutbot.state._scheduled_replies_cache[key] = {
        'channel_id': channel.id, 'ts': "1.1", 'config_name': "src",
        'user_id': user.id, 'text': "orig", 'send_at': "2026-01-01T00:00:00",
    }
    with patch('hutbot.persistence.flush_replies_cache', new=AsyncMock()), \
         patch('hutbot.slackcache.get_user_by_id', new=AsyncMock(return_value=user)):
        task = asyncio.create_task(
            schedule_reply(app, OPSGENIE_TOKENS, channel, config, "src", user, "orig", "1.1", wait_time_override=600))
        hutbot.state.scheduled_messages[key] = ScheduledReply(task, user.id)
        await asyncio.sleep(0)
        await handle_thread_response(app, channel, User("U3", "y", "Y", "T"), "1.1")
        with contextlib.suppress(asyncio.CancelledError):
            await task
    assert key not in hutbot.state._scheduled_replies_cache


# ----- an escalation is not dropped by a failed send -----


def _pending_escalation(key):
    hutbot.state.pending_buttons[key] = {
        "task": None, "orig": {}, "posted_text": "Incident?",
        "posted_channel_id": key[0], "message_ts": key[1], "def_channel_id": key[0],
        "config_name": "src", "buttons": [{"label": "Ack", "action": "ack", "value": "ok"}],
        "escalation_kind": "config", "escalation_target": "alarm", "timeout": 300,
    }
    hutbot.state._button_states_cache[key] = {
        k: v for k, v in hutbot.state.pending_buttons[key].items() if k != "task"}


@pytest.mark.asyncio
async def test_an_escalation_is_retried_when_slack_refuses_it():
    app = AsyncMock()
    channel = _mk_channel({"src": DEFAULT_CONFIG.copy(), "alarm": DEFAULT_CONFIG.copy()})
    key = ("C12345", "R1")
    _pending_escalation(key)
    run = AsyncMock(side_effect=[
        (None, hutbot.actions.DELIVERY_FAILED_REASON),
        ({"channel": "C12345", "ts": "R2"}, ""),
    ])
    with patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.persistence.flush_button_cache', new=AsyncMock()), \
         patch('hutbot.actions.run_action_with_reason', new=run):
        await hutbot.buttons._escalation_task(app, OPSGENIE_TOKENS, key, 0)
    assert run.await_count == 2
    # The note replacing the buttons is written once, by the attempt that got through.
    assert app.client.chat_update.await_count == 1


@pytest.mark.asyncio
async def test_a_failed_escalation_is_written_off_only_after_its_attempts():
    app = AsyncMock()
    channel = _mk_channel({"src": DEFAULT_CONFIG.copy(), "alarm": DEFAULT_CONFIG.copy()})
    key = ("C12345", "R1")
    _pending_escalation(key)
    run = AsyncMock(return_value=(None, hutbot.actions.DELIVERY_FAILED_REASON))
    flush = AsyncMock()
    with patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.persistence.flush_button_cache', new=flush), \
         patch('hutbot.actions.run_action_with_reason', new=run):
        await hutbot.buttons._escalation_task(app, OPSGENIE_TOKENS, key, 0)
    assert run.await_count == hutbot.buttons.ESCALATION_ATTEMPTS
    # Written to disk once, after the escalation is over rather than before it starts.
    flush.assert_awaited_once()


@pytest.mark.asyncio
async def test_a_shutdown_mid_escalation_leaves_the_record_on_disk():
    app = AsyncMock()
    channel = _mk_channel({"src": DEFAULT_CONFIG.copy(), "alarm": DEFAULT_CONFIG.copy()})
    key = ("C12345", "R1")
    _pending_escalation(key)
    flush = AsyncMock()
    with patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.persistence.flush_button_cache', new=flush), \
         patch('hutbot.buttons.ESCALATION_RETRY_DELAY', 600), \
         patch('hutbot.actions.run_action_with_reason',
               new=AsyncMock(return_value=(None, hutbot.actions.DELIVERY_FAILED_REASON))):
        task = asyncio.create_task(hutbot.buttons._escalation_task(app, OPSGENIE_TOKENS, key, 0))
        # Let it fail its first attempt and settle into the wait before the next one.
        for _ in range(20):
            await asyncio.sleep(0)
        task.cancel()
        await task
    # Never flushed, so the file still carries the escalation for the next process.
    flush.assert_not_awaited()


@pytest.mark.asyncio
async def test_an_escalation_whose_action_raises_is_retried_not_abandoned():
    """`action_dm_user` catches `SlackApiError` only, so a dropped connection reaches the task."""
    app = AsyncMock()
    channel = _mk_channel({"src": DEFAULT_CONFIG.copy(), "alarm": DEFAULT_CONFIG.copy()})
    key = ("C12345", "R1")
    _pending_escalation(key)
    run = AsyncMock(side_effect=[
        aiohttp.ClientConnectionError("reset"),
        ({"channel": "C12345", "ts": "R2"}, ""),
    ])
    flush = AsyncMock()
    with patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.persistence.flush_button_cache', new=flush), \
         patch('hutbot.actions.run_action_with_reason', new=run):
        await hutbot.buttons._escalation_task(app, OPSGENIE_TOKENS, key, 0)
    assert run.await_count == 2
    # It reached the end of the escalation, so the consumed record is written off deliberately
    # rather than left for an unrelated flush to erase.
    flush.assert_awaited_once()


@pytest.mark.asyncio
async def test_an_escalation_whose_action_keeps_raising_is_written_off():
    app = AsyncMock()
    channel = _mk_channel({"src": DEFAULT_CONFIG.copy(), "alarm": DEFAULT_CONFIG.copy()})
    key = ("C12345", "R1")
    _pending_escalation(key)
    run = AsyncMock(side_effect=RuntimeError("a bug, not a blip"))
    flush = AsyncMock()
    with patch('hutbot.slackcache.get_channel_by_id', new=AsyncMock(return_value=channel)), \
         patch('hutbot.persistence.flush_button_cache', new=flush), \
         patch('hutbot.actions.run_action_with_reason', new=run):
        await hutbot.buttons._escalation_task(app, OPSGENIE_TOKENS, key, 0)
    assert run.await_count == hutbot.buttons.ESCALATION_ATTEMPTS
    flush.assert_awaited_once()


@pytest.mark.asyncio
async def test_stripping_the_buttons_is_retried():
    app = AsyncMock()
    app.client.chat_update = AsyncMock(side_effect=[_slack_error("ratelimited"), {"ok": True}])
    await hutbot.buttons._strip_buttons(app, "C1", "R1", {"posted_text": "Incident?"}, "_note_")
    assert app.client.chat_update.await_count == 2


# ----- state files survive a failed write -----


@pytest.mark.asyncio
async def test_configuration_is_written_atomically(tmp_path):
    path = tmp_path / "bot.json"
    hutbot.state.channel_config = {"C1": {"default": {"wait_time": 60}}}
    with patch.object(hutbot.constants, 'CONFIG_FILE_NAME', str(path)):
        await hutbot.persistence.save_configuration()
    assert json.loads(path.read_text()) == {"C1": {"default": {"wait_time": 60}}}
    assert not (tmp_path / "bot.json.tmp").exists()


class _DiesMidWrite:
    """An open file that truncates its target and then fails, the way a full disk does."""

    def __init__(self, path):
        self._path = path

    async def __aenter__(self):
        self._file = open(self._path, "w")
        return self

    async def __aexit__(self, *args):
        self._file.close()
        return False

    async def write(self, content):
        self._file.write(content[:5])
        self._file.flush()
        raise OSError("no space left on device")

    async def flush(self):
        pass

    def fileno(self):
        return self._file.fileno()


@pytest.mark.asyncio
async def test_a_write_that_dies_halfway_leaves_the_previous_file_intact(tmp_path):
    path = tmp_path / "bot.json"
    path.write_text('{"C1": {"default": {"wait_time": 60}}}')
    hutbot.state.channel_config = {"C1": {"default": {"wait_time": 999}}}
    with patch.object(hutbot.constants, 'CONFIG_FILE_NAME', str(path)), \
         patch('hutbot.persistence.aiofiles.open', new=lambda p, mode: _DiesMidWrite(p)):
        await hutbot.persistence.save_configuration()
    # The half-written bytes went to the temp file, so the configuration on disk is still the
    # last good one rather than five characters of JSON nothing can parse.
    assert json.loads(path.read_text()) == {"C1": {"default": {"wait_time": 60}}}
    assert not (tmp_path / "bot.json.tmp").exists()


@pytest.mark.asyncio
async def test_a_write_is_retried(tmp_path):
    path = tmp_path / "replies.json"
    opened = []
    real_open = hutbot.persistence.aiofiles.open

    def flaky(*args, **kwargs):
        opened.append(args)
        if len(opened) == 1:
            raise OSError("interrupted")
        return real_open(*args, **kwargs)

    with patch.object(hutbot.constants, 'SCHEDULED_REPLIES_CACHE_FILE', str(path)), \
         patch('hutbot.persistence.aiofiles.open', side_effect=flaky):
        await hutbot.persistence.flush_replies_cache()
    assert json.loads(path.read_text()) == []
    assert len(opened) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", [0o600, 0o640, 0o644])
async def test_a_state_file_keeps_the_mode_it_had(tmp_path, mode):
    """`os.replace` installs the *temp* file's mode, so the write has to carry the old one over —
    both ways: a 0600 file from a state import must not widen, and a 0644 one must not narrow."""
    path = tmp_path / "bot.json"
    path.write_text("{}")
    os.chmod(path, mode)
    hutbot.state.channel_config = {"C1": {"default": {"wait_time": 60}}}
    with patch.object(hutbot.constants, 'CONFIG_FILE_NAME', str(path)):
        await hutbot.persistence.save_configuration()
    assert os.stat(path).st_mode & 0o777 == mode


@pytest.mark.asyncio
async def test_a_new_state_file_is_private(tmp_path):
    """These files carry bearer calendar URLs and Slack ids; the umask has no say in it."""
    path = tmp_path / "bot.json"
    hutbot.state.channel_config = {"C1": {"default": {"wait_time": 60}}}
    with patch.object(hutbot.constants, 'CONFIG_FILE_NAME', str(path)):
        await hutbot.persistence.save_configuration()
    assert os.stat(path).st_mode & 0o777 == fileutil.DEFAULT_FILE_MODE


@pytest.mark.asyncio
async def test_the_employee_cache_keeps_its_mode(tmp_path):
    path = tmp_path / "employees.json"
    path.write_text("[]")
    os.chmod(path, 0o600)
    with patch('employee_list.get_employee_cache_file_name', return_value=str(path)):
        await employee_list.save_employees_to_disk([{"ad_name": "dave"}])
    assert json.loads(path.read_text()) == [{"ad_name": "dave"}]
    assert os.stat(path).st_mode & 0o777 == 0o600


# ----- the employee directory falls back to disk for anything it cannot read -----


@contextlib.contextmanager
def _employee_endpoint(payload):
    """A directory that authenticates and answers 200 with `payload`."""
    class _Response:
        def __init__(self, body):
            self.status = 200
            self.headers = {}
            self._body = body
        async def text(self): return "a-token"
        async def json(self): return self._body
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False

    class _Session:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        def post(self, url, json=None): return _Response(None)
        def get(self, url, headers=None): return _Response(payload)

    with patch('employee_list.get_env_var', side_effect=lambda name: "set"), \
         patch('employee_list.aiohttp.ClientSession', lambda *a, **k: _Session()):
        yield


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [
    {"users": []},          # an object where a list was expected
    [None],                 # a list with a hole in it
    ["not-a-record"],
])
async def test_a_malformed_employee_payload_falls_back_to_disk(payload):
    """This runs at startup: an exception here aborts the bot instead of using the cache."""
    from_disk = {"dave": {"ad_name": "dave"}}
    with _employee_endpoint(payload), \
         patch('employee_list.load_employees_from_disk', new=AsyncMock(return_value=from_disk)):
        assert await employee_list.load_employees() == from_disk
