"""Matching the regular expressions channel members write, with a time limit.

`set pattern`, the `regex`/`not_regex` condition operators, the web UI and `config import` let any
member of a channel store a regular expression, which then runs against every message in that
channel and against template values that a message or a calendar feed supplies. The standard
library's `re` backtracks without any limit and holds the GIL while it does, so a single pattern
such as `(x+x+)+y` and a long enough message would stop the whole bot: every channel's reminders,
escalations, alerts and the OpsGenie heartbeat share one event loop.

So these patterns run through the `regex` module instead, which reads the same syntax (version 0
is the `re`-compatible one) and gives up after a deadline. A match that runs out of time counts as
no match, and the pattern is left out for a while afterwards rather than being tried again on
every message — a pattern that backtracks catastrophically once is broken, not unlucky.

Nearly a leaf, like ``buttonutil``: the routing, the condition chain, the preview and every
validator import it, so it imports nothing from the package but ``state``.
"""

import re
import time

import regex

from . import state

# How long one match may run. A real pattern against a real message takes microseconds, so this
# only ever stops a pattern that backtracks catastrophically, and it bounds what each such pattern
# can cost the event loop per message.
MATCH_TIMEOUT_SECONDS = 0.05
# How long a pattern that ran out of time is skipped (counted as no match) before it is tried again.
TIMED_OUT_PATTERN_HOLD_SECONDS = 600.0
# Longer than any pattern a person writes by hand; a cap on what a validator accepts.
MAX_PATTERN_LENGTH = 1000
# How many timed-out patterns are remembered at once, so the memory cannot grow without bound.
_MAX_HELD_PATTERNS = 256

_FLAGS = regex.VERSION0


class PatternTimeout(Exception):
    """A pattern took longer than `MATCH_TIMEOUT_SECONDS`, now or recently."""


def pattern_error(pattern: str) -> str:
    """Why `pattern` cannot be stored, or "" when it can.

    Checked with `re` first, so what was accepted before is still accepted with the same error
    wording, and then with `regex`, which is what will actually run it.
    """
    if len(pattern) > MAX_PATTERN_LENGTH:
        return f"patterns are limited to {MAX_PATTERN_LENGTH} characters"
    try:
        re.compile(pattern)
        regex.compile(pattern, _FLAGS)
    except (re.error, regex.error) as e:
        return str(e)
    return ""


def search(pattern: str, text: str, case_sensitive: bool = False) -> bool:
    """Whether `pattern` matches anywhere in `text`.

    Raises `regex.error` for a pattern that does not compile, and `PatternTimeout` when the match
    ran out of time — now, or within `TIMED_OUT_PATTERN_HOLD_SECONDS` before. Callers treat the
    latter as "no match" and fail closed.
    """
    timed_out = state._timed_out_patterns
    key = (pattern, bool(case_sensitive))
    held_since = timed_out.get(key)
    now = time.monotonic()
    if held_since is not None:
        if now - held_since < TIMED_OUT_PATTERN_HOLD_SECONDS:
            raise PatternTimeout(f"pattern `{pattern}` ran out of time recently and is skipped")
        timed_out.pop(key, None)
    flags = _FLAGS | (0 if case_sensitive else regex.IGNORECASE)
    try:
        return regex.search(pattern, text or "", flags, timeout=MATCH_TIMEOUT_SECONDS) is not None
    except TimeoutError as e:
        if len(timed_out) >= _MAX_HELD_PATTERNS:
            timed_out.pop(next(iter(timed_out)))
        timed_out[key] = time.monotonic()
        raise PatternTimeout(
            f"pattern `{pattern}` took longer than {MATCH_TIMEOUT_SECONDS:g}s to match") from e
