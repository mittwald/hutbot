"""Test fixtures: isolate the shared hutbot.state between tests."""

from unittest.mock import patch

import pytest

import hutbot.state as state


@pytest.fixture(autouse=True)
def _reset_state():
    state.reset()
    yield
    state.reset()


@pytest.fixture(autouse=True)
def _no_retry_waiting():
    """Take the waiting out of every retry, so the suite exercises them at full speed.

    The retries themselves still happen — only their backoff is zeroed. A test that is about
    the waiting sets its own delay back.
    """
    import retryutil
    import hutbot.buttons
    import hutbot.scheduling
    with patch.object(retryutil, 'DEFAULT_BASE_DELAY', 0), \
         patch.object(hutbot.buttons, 'ESCALATION_RETRY_DELAY', 0), \
         patch.object(hutbot.scheduling, 'DELIVERY_RETRY_DELAY', 0):
        yield
