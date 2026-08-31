"""The shared log-line format, and the bridge from the logging module onto it."""

import io
import logging

import pytest

import logutil


@pytest.fixture
def library_logger():
    """A logger named like the library it stands in for, at a level restored afterwards."""
    touched = []

    def make(name, level):
        logger = logging.getLogger(name)
        touched.append((logger, logger.level))
        logger.setLevel(level)
        return logger

    yield make
    for logger, level in touched:
        logger.setLevel(level)


@pytest.fixture
def clean_root_logger():
    """Hands back a root logger without our handlers, and restores whatever was there."""
    root = logging.getLogger()
    handlers = list(root.handlers)
    level = root.level
    root.handlers = []
    yield root
    root.handlers = handlers
    root.setLevel(level)


def _formatted_handlers(root):
    return [handler for handler in root.handlers if getattr(handler, "_hutbot_formatted", False)]


def test_own_lines_carry_a_timestamp_and_a_level(capsys):
    logutil.log("employees retrieved")
    logutil.log_warning("mapping skipped")
    logutil.log_error("cache unreadable")

    captured = capsys.readouterr()
    assert captured.out.endswith(" INFO: employees retrieved\n")
    assert " WARN: mapping skipped\n" in captured.err
    assert " ERROR: cache unreadable\n" in captured.err


def test_an_exception_is_logged_as_its_type_and_message(capsys):
    logutil.log_error("Failed to read the employee cache:", ValueError("bad json"))

    assert capsys.readouterr().err.endswith(" ERROR: Failed to read the employee cache: ValueError: bad json\n")


def test_logging_module_records_get_the_same_prefix_as_our_own_lines(clean_root_logger, library_logger):
    logutil.configure_stdlib_logging()
    stdout, stderr = (io.StringIO(), io.StringIO())
    for handler, stream in zip(_formatted_handlers(clean_root_logger), (stdout, stderr)):
        handler.setStream(stream)

    # What Bolt's socket-mode handler logs once its logger accepts INFO. The root logger's own
    # level is not consulted for a record that a lower logger already let through.
    bolt = library_logger("slack_bolt.AsyncApp", logging.INFO)
    bolt.info("⚡️ Bolt app is running!")

    assert stdout.getvalue().endswith(" INFO: ⚡️ Bolt app is running!\n")
    assert stderr.getvalue() == ""


def test_the_stream_split_and_the_level_names_match_our_own_lines(clean_root_logger, library_logger):
    logutil.configure_stdlib_logging()
    stdout, stderr = (io.StringIO(), io.StringIO())
    for handler, stream in zip(_formatted_handlers(clean_root_logger), (stdout, stderr)):
        handler.setStream(stream)

    library = library_logger("slack_sdk.socket_mode", logging.DEBUG)
    library.debug("connecting")
    library.info("a new session has been established")
    library.warning("rate limited")
    library.critical("connection lost for good")

    assert " DEBUG: connecting\n" in stdout.getvalue()
    assert " INFO: a new session has been established\n" in stdout.getvalue()
    # WARNING and CRITICAL are the logging module's spelling of the two levels our own lines
    # call WARN and ERROR; both belong on stderr, like `log_warning` and `log_error`.
    assert " WARN: rate limited\n" in stderr.getvalue()
    assert " ERROR: connection lost for good\n" in stderr.getvalue()
    assert "WARN" not in stdout.getvalue() and "ERROR" not in stdout.getvalue()


def test_a_library_that_sets_no_level_of_its_own_stays_quiet_below_warning(clean_root_logger, library_logger):
    logutil.configure_stdlib_logging()
    stdout, stderr = (io.StringIO(), io.StringIO())
    for handler, stream in zip(_formatted_handlers(clean_root_logger), (stdout, stderr)):
        handler.setStream(stream)

    # The root level is deliberately left alone, so per-connection chatter from a library that
    # inherits it does not turn up in the bot's output.
    inheriting = library_logger("aiohttp.access", logging.NOTSET)
    inheriting.info("GET /healthz")
    inheriting.warning("handler failed")

    assert stdout.getvalue() == ""
    assert " WARN: handler failed\n" in stderr.getvalue()


def test_configuring_twice_does_not_double_every_line(clean_root_logger):
    logutil.configure_stdlib_logging()
    logutil.configure_stdlib_logging()

    # One handler per stream, however often startup paths call it.
    assert len(_formatted_handlers(clean_root_logger)) == 2
