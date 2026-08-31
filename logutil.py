"""Log lines every module in this repo writes, and the prefix they all share.

Sits next to the package rather than inside it because both the bot (``hutbot``) and the
standalone scripts (``employee_list``, ``query_employees``, ``webui``) log, and none of them
should have to import another's domain module to do it.
"""

import datetime
import logging
import sys

LOG_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S"

# Our own lines say WARN and ERROR; the logging module spells the same levels differently.
STDLIB_LEVEL_NAMES = {"WARNING": "WARN", "CRITICAL": "ERROR"}


class _StdlibLogFormatter(logging.Formatter):
    """Formats a logging record the way `_log` prints our own lines."""

    def __init__(self) -> None:
        super().__init__(fmt="%(asctime)s %(levelname)s: %(message)s", datefmt=LOG_TIMESTAMP_FORMAT)

    def format(self, record: logging.LogRecord) -> str:
        record.levelname = STDLIB_LEVEL_NAMES.get(record.levelname, record.levelname)
        return super().format(record)


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
    formatted_prefix = f"{datetime.datetime.now().strftime(LOG_TIMESTAMP_FORMAT)} {prefix}:"
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
