"""Slash-command parsing and handlers.

``process_command`` / ``parse_and_execute_command`` are the public entry points
used by ``hutbot.routing``.
"""

from .dispatch import parse_and_execute_command, process_command

__all__ = ["parse_and_execute_command", "process_command"]
