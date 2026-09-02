"""Log lines every module in this repo writes, and the prefix they all share.

Sits next to the package rather than inside it because both the bot (``hutbot``) and the
standalone scripts (``employee_list``, ``query_employees``, ``webui``) log, and none of them
should have to import another's domain module to do it.
"""

import contextlib
import contextvars
import datetime
import logging
import sys

LOG_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S"

# What the process was busy with when a line was written — the inbound event, the timer, the
# poll. A failure deep in a lookup otherwise names only the id it could not resolve, and the
# channel-gated debug lines that would say where it came from are off for every channel but
# the ones being debugged. The origin is carried in a context variable rather than passed
# down, because the handlers that know it are many frames above the calls that fail, and an
# asyncio task copies the context it was created in, so a timer keeps the origin of whatever
# scheduled it. It is printed on WARN, ERROR and DEBUG lines only: INFO lines are the bulk of
# the output and already name their channel.
_LOG_ORIGIN: contextvars.ContextVar[str] = contextvars.ContextVar("hutbot_log_origin", default="")

ORIGIN_LOG_LEVELS = ("WARN", "ERROR", "DEBUG")

# Our own lines say WARN and ERROR; the logging module spells the same levels differently.
STDLIB_LEVEL_NAMES = {"WARNING": "WARN", "CRITICAL": "ERROR"}


class _StdlibLogFormatter(logging.Formatter):
    """Formats a logging record the way `_log` prints our own lines."""

    def __init__(self) -> None:
        super().__init__(fmt="%(asctime)s %(levelname)s: %(message)s", datefmt=LOG_TIMESTAMP_FORMAT)

    def format(self, record: logging.LogRecord) -> str:
        # A library failure (a Slack call, an HTTP session) belongs to the event being handled
        # just as much as one of our own lines does, so it carries the origin too. The record
        # is handed to every handler in turn, so the level it arrived with is put back.
        original_level = record.levelname
        level = STDLIB_LEVEL_NAMES.get(original_level, original_level)
        record.levelname = level + _origin_suffix(level)
        try:
            return super().format(record)
        finally:
            record.levelname = original_level


def configure_stdlib_logging() -> None:
    """Give logging-module output the same prefix our own log lines carry.

    Bolt, slack_sdk and aiohttp log through the logging module, which without a handler of
    ours prints bare messages ("⚡️ Bolt app is running!") into a stream where every other
    line starts with a timestamp and a level. A record that gets this far is written to stdout
    below WARNING and to stderr from WARNING up, matching `log` / `log_warning` / `log_error`.

    Which records get this far stays with the loggers: the root level is left alone, so a
    library that does not raise its own logger keeps emitting only WARNING and above.
    """
    root = logging.getLogger()
    if any(getattr(handler, "_hutbot_formatted", False) for handler in root.handlers):
        return

    formatter = _StdlibLogFormatter()

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(formatter)
    stdout_handler.addFilter(lambda record: record.levelno < logging.WARNING)

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.WARNING)
    stderr_handler.setFormatter(formatter)

    for handler in (stdout_handler, stderr_handler):
        handler._hutbot_formatted = True
        root.addHandler(handler)


@contextlib.contextmanager
def log_origin(description: str):
    """Tag every WARN/ERROR/DEBUG line written inside this block with where the work came from.

    Wraps an inbound event or a background task at its outermost frame; the previous origin is
    restored on the way out, so nested blocks and concurrent tasks do not bleed into each other.
    """
    token = _LOG_ORIGIN.set(description)
    try:
        yield
    finally:
        _LOG_ORIGIN.reset(token)


def set_log_origin(description: str) -> None:
    """Refine the running task's origin, e.g. once a channel id has turned into a name.

    Unlike `log_origin` this does not restore the previous value — it is for a handler
    sharpening its own description, not for wrapping a nested piece of work.
    """
    _LOG_ORIGIN.set(description)


def get_log_origin() -> str:
    return _LOG_ORIGIN.get()


def _origin_suffix(level: str) -> str:
    origin = _LOG_ORIGIN.get()
    return f" [{origin}]" if origin and level in ORIGIN_LOG_LEVELS else ""


def _log(file, prefix: str, *args: object) -> None:
    parts = []
    for arg in args:
        part = str(arg)
        if isinstance(arg, BaseException):
            error_type = type(arg).__name__
            error_message = str(arg)
            part = f"{error_type}{': ' + error_message if error_message else ''}"
        parts.append(part)
    message = " ".join(parts)
    formatted_prefix = f"{datetime.datetime.now().strftime(LOG_TIMESTAMP_FORMAT)} {prefix}{_origin_suffix(prefix)}:"
    print(formatted_prefix, message, flush=True, file=file)


def log(*args: object) -> None:
    _log(sys.stdout, "INFO", *args)


def log_warning(*args: object) -> None:
    _log(sys.stderr, "WARN", *args)


def log_error(*args: object) -> None:
    _log(sys.stderr, "ERROR", *args)


def log_debug(*args: object) -> None:
    """An unconditional DEBUG line. Channel-gated debugging goes through `textutil.log_debug`."""
    _log(sys.stderr, "DEBUG", *args)
