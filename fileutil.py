"""Writing the bot's state files so a failed write cannot destroy the last good one.

Sits next to the package for the same reason ``logutil`` and ``retryutil`` do: the package
writes the configuration and the two pending-work caches, ``employee_list`` writes the employee
cache, and all four are files whose loss or truncation the bot cannot recover from on its own.

One place, because the two rules that make such a write safe are both easy to get subtly wrong:
the bytes go to a sibling temp file and are renamed into place (so a crash leaves either the
old file or the new one, never five characters of JSON), and the temp file carries the mode of
the file it replaces (because ``os.replace`` installs the *temp* file's mode, so a default
umask would silently widen a 0600 state file to 0644).
"""

import asyncio
import json
import os

from logutil import log_error
import retryutil


# What a state file is created as when there is none to inherit a mode from. These files carry
# bearer calendar URLs, Slack ids and employee records; nothing outside this process reads them.
DEFAULT_FILE_MODE = 0o600


def _private_opener(path: str, flags: int) -> int:
    """Create the temp file readable by nobody else, before a single byte is in it."""
    return os.open(path, flags, DEFAULT_FILE_MODE)


async def _target_mode(path: str) -> int:
    """The mode to leave behind: whatever the file being replaced already had."""
    try:
        return (await asyncio.to_thread(os.stat, path)).st_mode & 0o777
    except (FileNotFoundError, NotADirectoryError):
        return DEFAULT_FILE_MODE


async def write_json_file(path: str, payload: object, what: str) -> bool:
    """Write `payload` to `path` as JSON, atomically, retrying a transient disk error.

    Returns whether it was written; a failure is logged, because the callers have nowhere
    better to put it either.
    """
    # aiofiles is imported here rather than at module scope so that this module stays importable
    # by anything that only needs the mode constants.
    import aiofiles

    content = json.dumps(payload, indent=2)
    temporary = f"{path}.tmp"
    mode = await _target_mode(path)

    async def attempt() -> None:
        async with aiofiles.open(temporary, 'w', opener=_private_opener) as f:
            await f.write(content)
            await f.flush()
            # The rename below is only atomic with respect to a crash if the bytes are on the
            # device before it happens; otherwise the new name can point at an empty file.
            await asyncio.to_thread(os.fsync, f.fileno())
        # Only now widened to what it is replacing — never before there is anything to read.
        await asyncio.to_thread(os.chmod, temporary, mode)
        await asyncio.to_thread(os.replace, temporary, path)

    try:
        await retryutil.retry_async(attempt, what=what)
        return True
    except Exception as e:
        log_error(f"{what} failed:", e)
        try:
            await asyncio.to_thread(os.unlink, temporary)
        except OSError:
            pass
        return False
