"""Test fixtures: isolate the shared hutbot.state between tests."""

import pytest

import hutbot.state as state


@pytest.fixture(autouse=True)
def _reset_state():
    state.reset()
    yield
    state.reset()
