"""The configuration UI inside Slack: the App Home tab and the modals it opens.

Split three ways on purpose. ``fields`` is the contract between the two halves — which
config field lives in which block, and how a validation error finds its way back to the
input that caused it. ``views`` builds Block Kit and touches nothing else, so it needs no
mocks to test. ``handlers`` is the only half that talks to Slack or writes anything, and it
writes exclusively through ``webui_backend``, the same layer the web UI saves through.

``handlers`` is deliberately not imported here: it pulls in ``webui_backend`` and everything
below it, and ``commands.info`` imports ``views`` alone for the Edit button on
``show config``.
"""

from . import fields

__all__ = ["fields"]
