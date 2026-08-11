#!/usr/bin/env python3
"""Backward-compatible launcher for the former ``python bot.py`` entry point."""

import asyncio

from hutbot.__main__ import main


if __name__ == "__main__":
    asyncio.run(main())
