"""Outlook calendar integration.

STUB ONLY. The real Microsoft Graph / Outlook integration is implemented in a
separate task. This module exposes the interface the bot's condition engine
relies on so the rest of the feature (scheduled triggers, conditions) can be
built and tested today.

Until the real implementation lands, calendar events are read from the
``HUTBOT_OUTLOOK_STUB_EVENTS`` environment variable (a JSON array of
``{"subject": str, "body": str}`` objects) or default to an empty list. Tests
patch ``find_calendar_events`` directly.
"""

import json
import os
import re

from employee_list import log_error, log_warning


def _load_stub_events() -> list[dict]:
    raw = os.environ.get("HUTBOT_OUTLOOK_STUB_EVENTS", "")
    if not raw.strip():
        return []
    try:
        events = json.loads(raw)
    except json.JSONDecodeError as e:
        log_error("Failed to decode HUTBOT_OUTLOOK_STUB_EVENTS:", e)
        return []
    if not isinstance(events, list):
        log_warning("HUTBOT_OUTLOOK_STUB_EVENTS must be a JSON array; ignoring.")
        return []
    return [e for e in events if isinstance(e, dict)]


async def find_calendar_events(subject_pattern: str = "", body_pattern: str = "") -> list[dict]:
    """Return calendar events, optionally filtered by subject/body regex.

    STUB: returns events from ``HUTBOT_OUTLOOK_STUB_EVENTS`` (or none). The real
    implementation will query the Outlook/Microsoft Graph calendar API.
    """
    events = _load_stub_events()
    if subject_pattern:
        try:
            sub_re = re.compile(subject_pattern, re.IGNORECASE)
            events = [e for e in events if sub_re.search(e.get("subject", ""))]
        except re.error as e:
            log_error(f"Invalid outlook subject pattern '{subject_pattern}':", e)
            return []
    if body_pattern:
        try:
            body_re = re.compile(body_pattern, re.IGNORECASE)
            events = [e for e in events if body_re.search(e.get("body", ""))]
        except re.error as e:
            log_error(f"Invalid outlook body pattern '{body_pattern}':", e)
            return []
    return events


async def calendar_condition_met(subject_pattern: str = "", body_pattern: str = "", negate: bool = False) -> bool:
    """True when a matching calendar event exists (or, if ``negate``, when none does)."""
    events = await find_calendar_events(subject_pattern, body_pattern)
    matched = len(events) > 0
    return matched != negate
