from tests._common import *  # noqa: F401,F403



def test_format_datetime_value_supports_python_format_timezone_and_locale():
    import hutbot
    config = {
        **DEFAULT_CONFIG.copy(),
        "date_format": "%A, %d %B %Y",
        "time_format": "%H:%M",
        "datetime_timezone": "Europe/Berlin",
        "datetime_locale": "de-DE",
    }

    assert hutbot.datetimefmt.format_datetime_value("2026-04-26T08:00:00Z", "datetime", config) == "Sonntag, 26 April 2026 10:00"



def test_format_datetime_value_supports_go_layout_args():
    import hutbot
    rendered = hutbot.datetimefmt.format_datetime_value(
        "2026-04-26T08:00:00Z",
        "datetime",
        DEFAULT_CONFIG.copy(),
        {"fmt": "02.01.2006 15:04", "tz": "UTC", "lc": "en-us"},
    )

    assert rendered == "26.04.2026 08:00"
