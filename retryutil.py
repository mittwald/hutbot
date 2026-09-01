"""One retry policy for every outbound call the bot makes.

Sits next to the package rather than inside it for the same reason ``logutil`` does: both the
bot (``hutbot``) and the standalone modules beside it (``employee_list``) make calls that fail
this way, and neither should have to import the other's domain code to retry one.

Every call that leaves this process — Slack, OpsGenie, the calendar feeds, the employee
directory, the state files — fails the same handful of ways: the connection drops, the peer
answers 429 or 5xx, or the request times out. All of those are worth another attempt; a
`channel_not_found` or a 401 is not, and retrying it only delays the error by the backoff.

`retry_async` is the one place that tells those apart. It re-raises the last error rather than
swallowing it, so each call site keeps the fallback it already had (a stale cache, the
employee list from disk, an error message to the user) and only gains the attempts before it.

Rate limits are honoured rather than guessed at: Slack and OpsGenie both answer 429 with a
`Retry-After` header, and the exponential backoff below would otherwise give up after a few
seconds on a limit that asks for thirty.
"""

import asyncio
import random

import aiohttp
from slack_sdk.errors import SlackApiError

from logutil import log_warning


DEFAULT_ATTEMPTS = 3
DEFAULT_BASE_DELAY = 1.0
# A `Retry-After` longer than this is not worth holding a scheduled reply or a Slack event
# handler open for; the call site's fallback is the better answer at that point.
MAX_DELAY = 60.0

# Slack answers a retryable condition with one of these in `error`. Everything else Slack
# names — `channel_not_found`, `invalid_auth`, `msg_too_long`, `invalid_blocks` — is a
# permanent no, and a second attempt would fail identically.
RETRYABLE_SLACK_ERROR_CODES = frozenset({
    'ratelimited',
    'rate_limited',
    'service_unavailable',
    'internal_error',
    'fatal_error',
    'request_timeout',
    'server_error',
    'backend_error',
})


class TransientHTTPError(Exception):
    """A raw HTTP response worth another attempt: 429, or any 5xx.

    Raised by the aiohttp call sites, which see a status code rather than an exception, so
    that a retryable response reaches `retry_async` the same way a dropped connection does.
    """

    def __init__(self, what: str, status: int, retry_after: float | None = None) -> None:
        super().__init__(f"{what}: HTTP {status}")
        self.status = status
        self.retry_after = retry_after


def is_retryable_status(status: int) -> bool:
    """Whether an HTTP status is worth another attempt."""
    return status == 429 or 500 <= status < 600


def parse_retry_after(value: object) -> float | None:
    """The `Retry-After` header as seconds, or None when it is absent or a date.

    Slack and OpsGenie both send the delta-seconds form. The HTTP-date form is legal and
    neither of them uses it, so it falls through to the exponential backoff rather than
    growing a date parser here.
    """
    if value is None:
        return None
    try:
        seconds = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    return seconds if seconds >= 0 else None


def _slack_response(error: SlackApiError):
    """`SlackApiError.response`, which is a `SlackResponse` in production and a plain dict
    in the tests that raise the error by hand."""
    return getattr(error, 'response', None)


def slack_error_code(error: SlackApiError) -> str:
    response = _slack_response(error)
    if response is None:
        return ''
    try:
        return str(response.get('error') or '')
    except AttributeError:
        return ''


def slack_status_code(error: SlackApiError) -> int | None:
    response = _slack_response(error)
    status = getattr(response, 'status_code', None)
    if status is None and isinstance(response, dict):
        status = response.get('status_code')
    try:
        return int(status) if status is not None else None
    except (TypeError, ValueError):
        return None


def slack_retry_after(error: SlackApiError) -> float | None:
    response = _slack_response(error)
    headers = getattr(response, 'headers', None)
    if headers is None and isinstance(response, dict):
        headers = response.get('headers')
    if not headers:
        return None
    try:
        # `SlackResponse.headers` lower-cases its keys; a hand-built dict in a test may not.
        value = headers.get('Retry-After', headers.get('retry-after'))
    except AttributeError:
        return None
    return parse_retry_after(value)


def is_retryable(error: BaseException) -> bool:
    """Whether another attempt could plausibly succeed."""
    if isinstance(error, TransientHTTPError):
        return True
    if isinstance(error, SlackApiError):
        status = slack_status_code(error)
        if status is not None and is_retryable_status(status):
            return True
        return slack_error_code(error) in RETRYABLE_SLACK_ERROR_CODES
    # A timeout, a dropped connection, a DNS failure, a refused socket. `aiohttp.ClientError`
    # covers what the aiohttp calls raise, `OSError` what slack_sdk lets through unwrapped
    # once its own connection-error handler has given up.
    return isinstance(error, (aiohttp.ClientError, asyncio.TimeoutError, OSError))


def retry_delay(error: BaseException, attempt: int, base_delay: float | None = None) -> float:
    """How long to wait before attempt number `attempt` + 1.

    A `Retry-After` from the peer wins; without one the delay doubles per attempt, with a
    little jitter so a burst of replies rate-limited together does not come back in lockstep.
    """
    base_delay = DEFAULT_BASE_DELAY if base_delay is None else base_delay
    requested = None
    if isinstance(error, TransientHTTPError):
        requested = error.retry_after
    elif isinstance(error, SlackApiError):
        requested = slack_retry_after(error)
    if requested is not None:
        return min(requested, MAX_DELAY)
    delay = base_delay * (2 ** (attempt - 1))
    return min(delay + random.uniform(0, base_delay / 2), MAX_DELAY)


async def retry_async(operation, *, what: str, attempts: int = DEFAULT_ATTEMPTS,
                      base_delay: float | None = None):
    """Await `operation()` until it succeeds, retrying only what is worth retrying.

    `what` names the call in the warning written between attempts. The last error is re-raised
    once the attempts are used up, so the caller's own `except` keeps deciding what a failed
    call means — this only buys the attempts.

    `base_delay` is read at call time rather than bound as a default, so the test suite can
    turn the waiting off in one place.
    """
    last_error: BaseException | None = None
    for attempt in range(1, attempts + 1):
        try:
            return await operation()
        except asyncio.CancelledError:
            # Shutdown, or a scheduled reply being cancelled. Never retried, never logged here.
            raise
        except Exception as e:
            last_error = e
            if attempt >= attempts or not is_retryable(e):
                raise
            delay = retry_delay(e, attempt, base_delay)
            log_warning(f"{what} failed, retrying in {delay:.1f}s ({attempt}/{attempts}):", e)
            await asyncio.sleep(delay)
    # Unreachable: the loop either returns or raises. Kept so the type checker sees an exit.
    raise last_error  # pragma: no cover
