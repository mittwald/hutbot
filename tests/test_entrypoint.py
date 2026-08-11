"""Compatibility checks for runtime entry points."""


def test_legacy_bot_entrypoint_delegates_to_package_main():
    import bot
    from hutbot.__main__ import main

    assert bot.main is main
