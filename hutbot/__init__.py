"""Hutbot — a Slack reminder/rule bot.

This package is the result of splitting the former monolithic ``bot.py`` into
cohesive modules. See ``hutbot/__main__.py`` for the entry point
(``python -m hutbot``).
"""

# Fallback version, used when HUTBOT_VERSION is unset (running from a checkout).
# Deployments get the real one from the chart, which passes the image tag.
__version__ = "1.0.0"
