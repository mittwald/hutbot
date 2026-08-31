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

    # `timedelta` is part of the stand-in because the `at` resolver does arithmetic with it.
    return SimpleNamespace(datetime=Frozen, date=datetime.date, time=datetime.time,
                           timezone=datetime.timezone, timedelta=datetime.timedelta)



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


# ----- the `at` template argument -----

BERLIN = {"datetime_timezone": "Europe/Berlin"}
# A Wednesday, well away from either clock change.
AT_NOW = datetime.datetime(2026, 8, 26, 17, 40, tzinfo=ZoneInfo("Europe/Berlin"))


@pytest.mark.parametrize("value,expected", [
    ("2026-08-27 09:00", "2026-08-27T09:00:00+02:00"),
    ("2026-08-27T09:00", "2026-08-27T09:00:00+02:00"),
    ("2026-08-27T09:00:30", "2026-08-27T09:00:30+02:00"),
    ("2026-08-27t09:00z", "2026-08-27T11:00:00+02:00"),
    ("2026-08-27T09:00:00Z", "2026-08-27T11:00:00+02:00"),
    ("2026-08-27T09:00+09:00", "2026-08-27T02:00:00+02:00"),
    ("2026-08-27 09:00:00+0200", "2026-08-27T09:00:00+02:00"),
    ("2026-08-27", "2026-08-27T00:00:00+02:00"),
    ("09:00", "2026-08-26T09:00:00+02:00"),
    ("9", "2026-08-26T09:00:00+02:00"),
    ("+2h", "2026-08-26T19:40:00+02:00"),
    ("-30m", "2026-08-26T17:10:00+02:00"),
    ("+90minutes", "2026-08-26T19:10:00+02:00"),
    ("+1d", "2026-08-27T17:40:00+02:00"),
    ("-1 week", "2026-08-19T17:40:00+02:00"),
    ("+2w", "2026-09-09T17:40:00+02:00"),
    ("+0h", "2026-08-26T17:40:00+02:00"),
    ("  +2H  ", "2026-08-26T19:40:00+02:00"),
])
def test_resolve_at_time_grammar(value, expected):
    import hutbot

    resolved = hutbot.datetimefmt.resolve_at_time(value, BERLIN, AT_NOW)

    assert resolved.isoformat() == expected


def test_a_naive_at_is_read_in_the_config_timezone_not_utc():
    """Deliberately the opposite of `parse_opsgenie_datetime`, which reads OpsGenie's UTC."""
    import hutbot

    berlin = hutbot.datetimefmt.resolve_at_time("2026-08-27 09:00", BERLIN, AT_NOW)
    tokyo = hutbot.datetimefmt.resolve_at_time("2026-08-27 09:00", {"datetime_timezone": "Asia/Tokyo"}, AT_NOW)

    assert berlin.isoformat() == "2026-08-27T09:00:00+02:00"
    assert tokyo.isoformat() == "2026-08-27T09:00:00+09:00"
    # The same text, the other reader, on purpose.
    assert hutbot.datetimefmt.parse_opsgenie_datetime("2026-08-27T09:00").isoformat() == "2026-08-27T09:00:00+00:00"


def test_a_date_only_at_is_local_midnight():
    import hutbot

    assert hutbot.datetimefmt.resolve_at_time("2026-08-27", BERLIN, AT_NOW).isoformat() == "2026-08-27T00:00:00+02:00"
    tokyo = hutbot.datetimefmt.resolve_at_time("2026-08-27", {"datetime_timezone": "Asia/Tokyo"}, AT_NOW)
    assert tokyo.isoformat() == "2026-08-27T00:00:00+09:00"


def test_at_falls_back_to_the_server_timezone():
    import hutbot

    with patch.dict(os.environ, {"TZ": "Asia/Tokyo"}):
        resolved = hutbot.datetimefmt.resolve_at_time("2026-08-27 09:00", {}, AT_NOW)

    assert resolved.isoformat() == "2026-08-27T09:00:00+09:00"


def test_at_defaults_now_to_the_clock():
    """The only clock-reading path; everything else injects `now`."""
    import hutbot

    with patch.object(hutbot.datetimefmt, 'datetime', frozen_datetime_module(AT_NOW)):
        resolved = hutbot.datetimefmt.resolve_at_time("+2h", BERLIN)

    assert resolved.isoformat() == "2026-08-26T19:40:00+02:00"


def test_at_a_naive_now_is_treated_as_utc():
    import hutbot

    resolved = hutbot.datetimefmt.resolve_at_time("+0h", BERLIN, datetime.datetime(2026, 8, 26, 15, 40))

    assert resolved.isoformat() == "2026-08-26T17:40:00+02:00"


def test_at_across_the_spring_forward():
    """`m`/`h` are elapsed time, `d`/`w` are wall clock — the difference shows up here."""
    import hutbot

    resolve = hutbot.datetimefmt.resolve_at_time
    berlin = ZoneInfo("Europe/Berlin")
    before_the_gap = datetime.datetime(2026, 3, 29, 1, 30, tzinfo=berlin)

    # 02:30 never happens that night; it resolves to the instant it would have been.
    skipped = resolve("2026-03-29 02:30", BERLIN, before_the_gap)
    assert skipped.utcoffset() == datetime.timedelta(hours=1)
    assert skipped.astimezone(datetime.timezone.utc).isoformat() == "2026-03-29T01:30:00+00:00"

    # Two real hours, so the wall clock jumps three.
    assert resolve("+2h", BERLIN, before_the_gap).isoformat() == "2026-03-29T04:30:00+02:00"

    late_the_night_before = datetime.datetime(2026, 3, 28, 23, 30, tzinfo=berlin)
    # `+1d` keeps the hour and lands on the next calendar day...
    assert resolve("+1d", BERLIN, late_the_night_before).isoformat() == "2026-03-29T23:30:00+02:00"
    # ...where `+24h` is 24 real hours and lands on the day after.
    assert resolve("+24h", BERLIN, late_the_night_before).isoformat() == "2026-03-30T00:30:00+02:00"


def test_at_across_the_fall_back():
    import hutbot

    resolve = hutbot.datetimefmt.resolve_at_time
    berlin = ZoneInfo("Europe/Berlin")
    first_pass = datetime.datetime(2026, 10, 25, 1, 30, tzinfo=berlin, fold=0)

    # 02:30 happens twice; the earlier pass is what a reader means.
    assert resolve("2026-10-25 02:30", BERLIN, first_pass).isoformat() == "2026-10-25T02:30:00+02:00"
    # Two real hours from the first 01:30 is the *second* 02:30.
    assert resolve("+2h", BERLIN, first_pass).isoformat() == "2026-10-25T02:30:00+01:00"
    day_before = datetime.datetime(2026, 10, 24, 2, 30, tzinfo=berlin)
    assert resolve("+1d", BERLIN, day_before).isoformat() == "2026-10-25T02:30:00+02:00"


@pytest.mark.parametrize("value,expected", [
    ("", "must be non-empty"),
    ("   ", "must be non-empty"),
    ("2026-13-40 09:00", "must be a real date and time"),
    ("2026-02-30", "must be a real date and time"),
    ("2026-08-27 25:00", "must be a real date and time"),
    ("9999-01-01", "must name a year between 1970 and 2100"),
    ("1969-12-31", "must name a year between 1970 and 2100"),
    ("+2y", "counted in `m`, `h`, `d` or `w`"),
    ("+30s", "counted in `m`, `h`, `d` or `w`"),
    ("+1mo", "counted in `m`, `h`, `d` or `w`"),
    ("+4000d", "must stay within 10 years of now"),
    ("-900w", "must stay within 10 years of now"),
    ("2h", "offsets need a sign"),
    ("30 min", "offsets need a sign"),
    ("tomorrow", "must look like"),
    ("now", "must look like"),
    ("monday", "must look like"),
    ("20260827", "must look like"),
    ("2026-W35-4", "must look like"),
    ("2026-08-27T09", "must look like"),
    ("1786453297", "must look like"),
    ("27.08.2026", "must look like"),
    ("08/27/2026", "must look like"),
    ("+1d2h", "must look like"),
    ("++2h", "must look like"),
    ("at(x);y", "must not contain"),
])
def test_at_rejects_what_it_cannot_read(value, expected):
    """The validator and the resolver must agree on exactly which values are usable."""
    import hutbot

    with pytest.raises(ValueError) as error:
        hutbot.datetimefmt.validate_at_time(value)
    assert expected in str(error.value)
    # The resolver never raises; it reports "no instant" instead, and callers must not
    # substitute "now" for it.
    assert hutbot.datetimefmt.resolve_at_time(value, BERLIN, AT_NOW) is None


def test_validate_at_time_returns_the_canonical_text():
    import hutbot

    assert hutbot.datetimefmt.validate_at_time("  +2h ") == "+2h"
    assert hutbot.datetimefmt.validate_at_time("2026-08-27  09:00") == "2026-08-27 09:00"


def test_at_survives_arithmetic_at_the_edge_of_the_range():
    """An offset that runs off the end of `datetime` reports no instant, it does not raise."""
    import hutbot

    late = datetime.datetime(9999, 12, 31, 23, 59, tzinfo=datetime.timezone.utc)
    resolved = hutbot.datetimefmt.resolve_at_time("+3653d", BERLIN, late)

    assert resolved is None


def test_format_timestamp_value_moves_the_instant_by_at():
    """`at` on a clock variable is counted from the timestamp, not from the clock."""
    import hutbot
    config = {**DEFAULT_CONFIG.copy(), "date_format": "%d.%m.%Y", "time_format": "%H:%M",
              "datetime_timezone": "Europe/Berlin"}
    ts = "1786453297.645799"

    def rendered(part, **args):
        return hutbot.datetimefmt.format_timestamp_value(ts, part, config, args or None)

    assert rendered("datetime") == "11.08.2026 15:01"
    assert rendered("datetime", at="+0m") == "11.08.2026 15:01"
    assert rendered("date", at="+2w") == "25.08.2026"
    assert rendered("datetime", at="+90m") == "11.08.2026 16:31"
    assert rendered("time", at="09:00") == "09:00"
    assert rendered("date", at="2026-09-01") == "01.09.2026"
    # `tz` still only decides how the moved instant is printed.
    assert rendered("datetime", at="+2h", tz="Asia/Tokyo") == "12.08.2026 00:01"


def test_format_timestamp_value_without_a_timestamp_reads_the_clock_for_an_absolute_at():
    """No message behind the run is no reason to drop a moment the writer named outright."""
    import hutbot
    config = {**DEFAULT_CONFIG.copy(), "date_format": "%d.%m.%Y", "datetime_timezone": "Europe/Berlin"}

    assert hutbot.datetimefmt.format_timestamp_value("", "date", config, {"at": "2026-09-01"}) == "01.09.2026"
    assert hutbot.datetimefmt.format_timestamp_value("", "date", config) == ""


@pytest.mark.parametrize("timestamp,at", [
    # Only a hand-edited config gets here: `validate_template_expressions` refuses both.
    ("1786453297.645799", "next week"),
    # An offset that runs off the end of `datetime`.
    ("253402300799", "+3653d"),
])
def test_format_timestamp_value_fails_closed_on_an_at_it_cannot_resolve(timestamp, at):
    """`<unknown>` rather than the present: answering about now would be a wrong answer."""
    import hutbot

    rendered = hutbot.datetimefmt.format_timestamp_value(timestamp, "datetime", BERLIN, {"at": at})

    assert rendered == hutbot.constants.UNKNOWN_PERIOD_PLACEHOLDER
