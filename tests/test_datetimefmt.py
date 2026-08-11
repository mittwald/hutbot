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



def test_describe_timezone_names_the_zone_and_its_current_offset():
    import hutbot
    assert hutbot.datetimefmt.describe_timezone("Asia/Tokyo") == "Asia/Tokyo (JST, UTC+09:00)"
    assert hutbot.datetimefmt.describe_timezone("Nowhere/Sometime") == "Nowhere/Sometime (unknown timezone)"



def test_describe_timezone_falls_back_to_the_server_timezone():
    import hutbot
    with patch.dict(os.environ, {"TZ": "Australia/Sydney"}):
        described = hutbot.datetimefmt.describe_timezone()

    assert described.startswith("Australia/Sydney (")
    assert described.endswith(", server local time)")



def test_get_local_timezone_name_prefers_tz_then_etc_timezone():
    import hutbot
    with patch.dict(os.environ, {"TZ": "America/New_York"}):
        assert hutbot.datetimefmt.get_local_timezone_name() == "America/New_York"

    with patch.dict(os.environ, {}, clear=True), \
         patch('builtins.open', mock_open(read_data="Etc/UTC\n")):
        assert hutbot.datetimefmt.get_local_timezone_name() == "Etc/UTC"



def test_get_local_timezone_name_reads_the_localtime_symlink():
    import hutbot
    with patch.dict(os.environ, {}, clear=True), \
         patch('builtins.open', side_effect=OSError), \
         patch('os.path.realpath', return_value="/usr/share/zoneinfo/Europe/Berlin"):
        assert hutbot.datetimefmt.get_local_timezone_name() == "Europe/Berlin"



def test_describe_locale_explains_what_names_a_config_gets():
    import hutbot
    assert hutbot.datetimefmt.describe_locale("de_DE") == "de_DE"
    assert hutbot.datetimefmt.describe_locale("fr_FR") == "fr_FR (no translations, English names)"

    with patch('hutbot.datetimefmt.get_server_locale_name', return_value="de_DE"):
        assert hutbot.datetimefmt.describe_locale() == "English names (server locale de_DE not applied)"

    with patch('hutbot.datetimefmt.get_server_locale_name', return_value=""):
        assert hutbot.datetimefmt.describe_locale() == "English names (no server locale set)"



def test_get_server_locale_name_uses_lc_time_then_the_environment():
    import hutbot
    with patch('locale.getlocale', return_value=("de_DE", "UTF-8")):
        assert hutbot.datetimefmt.get_server_locale_name() == "de_DE"

    with patch('locale.getlocale', return_value=(None, None)), \
         patch.dict(os.environ, {"LANG": "en_GB.UTF-8"}, clear=True):
        assert hutbot.datetimefmt.get_server_locale_name() == "en_GB"

    with patch('locale.getlocale', return_value=("C", None)), \
         patch.dict(os.environ, {"LANG": "C.UTF-8"}, clear=True):
        assert hutbot.datetimefmt.get_server_locale_name() == ""



def test_describe_timezone_does_not_repeat_the_abbreviation_in_the_zone_name():
    import hutbot
    with patch.dict(os.environ, {"TZ": "Etc/UTC"}), \
         patch('hutbot.datetimefmt.get_local_timezone', return_value=ZoneInfo("Etc/UTC")):
        assert hutbot.datetimefmt.describe_timezone() == "Etc/UTC (UTC+00:00, server local time)"
    assert hutbot.datetimefmt.describe_timezone("UTC") == "UTC (UTC+00:00)"



def frozen_datetime_module(moment: datetime.datetime):
    """Stand-in for the `datetime` module whose `now()` always returns `moment`."""
    class Frozen(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return moment.astimezone(tz) if tz else moment

    return SimpleNamespace(datetime=Frozen, date=datetime.date, time=datetime.time, timezone=datetime.timezone)



def test_work_hours_are_counted_in_the_configured_timezone():
    import hutbot
    # 23:30 in Berlin is 06:30 the next day in Tokyo: inside 6-18 Tokyo hours,
    # outside 6-18 Berlin hours.
    berlin_late_evening = datetime.datetime(2026, 4, 26, 23, 30, tzinfo=ZoneInfo("Europe/Berlin"))

    with patch.object(hutbot.datetimefmt, 'datetime', frozen_datetime_module(berlin_late_evening)):
        assert hutbot.datetimefmt.is_work_time("6", "18", {"datetime_timezone": "Asia/Tokyo"}) is True
        assert hutbot.datetimefmt.is_work_time("6", "18", {"datetime_timezone": "Europe/Berlin"}) is False
        # No configured timezone: the server's, as before.
        with patch('hutbot.datetimefmt.get_local_timezone', return_value=ZoneInfo("Asia/Tokyo")):
            assert hutbot.datetimefmt.is_work_time("6", "18", {}) is True



def test_work_days_are_counted_in_the_configured_timezone():
    import hutbot
    # Friday 23:30 in Berlin is already Saturday in Tokyo.
    berlin_friday_night = datetime.datetime(2026, 4, 24, 23, 30, tzinfo=ZoneInfo("Europe/Berlin"))

    with patch.object(hutbot.datetimefmt, 'datetime', frozen_datetime_module(berlin_friday_night)):
        assert hutbot.datetimefmt.is_work_day({"datetime_timezone": "Europe/Berlin"}) is True
        assert hutbot.datetimefmt.is_work_day({"datetime_timezone": "Asia/Tokyo"}) is False



def test_instance_default_locale_applies_to_configs_without_one():
    import hutbot
    with patch('hutbot.state.default_datetime_locale', "de_DE"):
        assert hutbot.datetimefmt.get_config_locale({}) == "de_DE"
        assert hutbot.datetimefmt.get_config_locale({"datetime_locale": "en-US"}) == "en_US"
        # An unusable config locale falls back to the default, not to English.
        assert hutbot.datetimefmt.get_config_locale({"datetime_locale": "nonsense!"}) == "de_DE"
        assert hutbot.datetimefmt.describe_locale("") == "de_DE (instance default)"
        assert hutbot.datetimefmt.describe_locale("en_US") == "en_US (no translations, English names)"

    rendered = hutbot.datetimefmt.format_datetime_value(
        "2026-04-26T08:00:00Z", "date", {"date_format": "%A, %d %B %Y", "datetime_timezone": "Europe/Berlin"},
    )
    assert rendered == "Sunday, 26 April 2026"
    with patch('hutbot.state.default_datetime_locale', "de_DE"):
        rendered = hutbot.datetimefmt.format_datetime_value(
            "2026-04-26T08:00:00Z", "date", {"date_format": "%A, %d %B %Y", "datetime_timezone": "Europe/Berlin"},
        )
    assert rendered == "Sonntag, 26 April 2026"



def test_resolve_default_locale_rejects_garbage():
    import hutbot
    assert hutbot.datetimefmt.resolve_default_locale(" de-de ") == "de_DE"
    assert hutbot.datetimefmt.resolve_default_locale("") == ""
    assert hutbot.datetimefmt.resolve_default_locale("Deutsch (Deutschland)") == ""



def test_describe_locale_flags_an_invalid_config_locale():
    import hutbot
    with patch('hutbot.state.default_datetime_locale', ""):
        assert hutbot.datetimefmt.describe_locale("nonsense!") == "nonsense! (invalid locale, English names)"
