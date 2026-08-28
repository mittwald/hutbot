import json
import os
from unittest.mock import patch

from employee_list import (
    load_employee_fallbacks,
    load_employee_mappings,
    load_employees_from_disk,
    merge_employee_fallbacks,
)
from query_employees import find_employees, format_employee, invert_employee_mappings


def test_find_employees_matches_ad_name_fullname_team_and_alias():
    employees = {
        "jdoe": {
            "ad_name": "jdoe",
            "fullname": "John Doe",
            "group": "Support",
            "mail": "john.doe@example.com",
        },
        "asmith": {
            "ad_name": "asmith",
            "fullname": "Anna Smith",
            "group": "Platform",
            "mail": "anna.smith@example.com",
        },
    }
    mappings = {"john.slack": "jdoe"}

    assert [employee["ad_name"] for employee in find_employees(employees, "jdoe", mappings=mappings)] == ["jdoe"]
    assert [employee["ad_name"] for employee in find_employees(employees, "john doe", mappings=mappings)] == ["jdoe"]
    assert [employee["ad_name"] for employee in find_employees(employees, "support", mappings=mappings)] == ["jdoe"]
    assert [employee["ad_name"] for employee in find_employees(employees, "john.slack", mappings=mappings)] == ["jdoe"]


def test_find_employees_can_filter_team():
    employees = {
        "jdoe": {
            "ad_name": "jdoe",
            "fullname": "John Doe",
            "group": "Support",
        },
        "asmith": {
            "ad_name": "asmith",
            "fullname": "Anna Smith",
            "group": "Platform",
        },
    }

    assert [employee["ad_name"] for employee in find_employees(employees, "", team="Platform")] == ["asmith"]


def test_format_employee_includes_key_fields():
    employee = {
        "ad_name": "jdoe",
        "fullname": "John Doe",
        "group": "Support",
        "mail": "john.doe@example.com",
    }

    assert format_employee(employee) == "John Doe (jdoe) - team: Support - mail: john.doe@example.com"


def test_invert_employee_mappings_drops_ignored_users():
    mappings = {"john.slack": "jdoe", "ks-bereitschaft": "-"}

    assert invert_employee_mappings(mappings) == {"jdoe": {"john.slack"}}


def test_load_employee_mappings_keeps_the_ignore_sentinel():
    with patch.dict(os.environ, {"EMPLOYEE_LIST_MAPPINGS": "John.Slack=JDoe,KS-Bereitschaft=-"}):
        assert load_employee_mappings() == {"john.slack": "jdoe", "ks-bereitschaft": "-"}



def _employee(ad_name, fullname, group, is_deleted=False):
    return {"ad_name": ad_name, "fullname": fullname, "group": group, "is_deleted": is_deleted}


def _write_json(path, payload):
    path.write_text(json.dumps(payload), encoding="utf-8")


async def test_load_employee_fallbacks_reads_the_same_shape_as_the_cache(tmp_path):
    fallback = tmp_path / "employees-fallback.json"
    _write_json(fallback, [_employee("RMantler", "Rudi Mantler", "Support"),
                           _employee("gone", "Gone Away", "Support", is_deleted=True)])

    with patch.dict(os.environ, {"HUTBOT_EMPLOYEE_FALLBACK_FILE": str(fallback)}):
        fallbacks = await load_employee_fallbacks()

    # Keyed by the normalized ad_name, and retired entries are dropped the same way the
    # employee API's own deleted records are.
    assert list(fallbacks) == ["rmantler"]
    assert fallbacks["rmantler"]["group"] == "Support"


async def test_malformed_fallback_records_are_skipped_one_by_one(tmp_path):
    fallback = tmp_path / "employees-fallback.json"
    _write_json(fallback, [
        None,
        "rmantler",
        {"ad_name": 42, "fullname": "Numeric Name", "group": "Support"},
        {"ad_name": "badgroup", "fullname": "Bad Group", "group": ["Support"]},
        _employee("rmantler", "Rudi Mantler", "Support"),
    ])

    with patch.dict(os.environ, {"HUTBOT_EMPLOYEE_FALLBACK_FILE": str(fallback)}):
        fallbacks = await load_employee_fallbacks()

    # A record the operator typed wrong costs that record, never the file or the user cache.
    assert list(fallbacks) == ["rmantler"]


async def test_a_missing_or_broken_fallback_file_is_not_fatal(tmp_path):
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    not_a_list = tmp_path / "object.json"
    _write_json(not_a_list, {"ad_name": "rmantler"})

    for path in (tmp_path / "absent.json", broken, not_a_list):
        with patch.dict(os.environ, {"HUTBOT_EMPLOYEE_FALLBACK_FILE": str(path)}):
            assert await load_employee_fallbacks() == {}


def test_merge_employee_fallbacks_lets_the_employee_list_win():
    employees = {"jdoe": _employee("jdoe", "John Doe", "Support")}
    fallbacks = {"jdoe": _employee("jdoe", "John Doe", "Stale Team"),
                 "rmantler": _employee("rmantler", "Rudi Mantler", "Platform")}

    merged = merge_employee_fallbacks(employees, fallbacks)

    assert merged["jdoe"]["group"] == "Support"
    assert merged["rmantler"]["group"] == "Platform"
    assert merge_employee_fallbacks(employees, {}) == employees


async def test_load_employees_from_disk_fills_gaps_from_the_fallback_file(tmp_path):
    cache = tmp_path / "employees.json"
    _write_json(cache, [_employee("jdoe", "John Doe", "Support"),
                        _employee("rmantler", "Rudi Mantler", "Support", is_deleted=True)])
    fallback = tmp_path / "employees-fallback.json"
    _write_json(fallback, [_employee("rmantler", "Rudi Mantler", "Platform")])

    with patch.dict(os.environ, {"HUTBOT_EMPLOYEE_CACHE_FILE": str(cache),
                                 "HUTBOT_EMPLOYEE_FALLBACK_FILE": str(fallback)}):
        employees = await load_employees_from_disk()

    # The cache dropped the deleted record, so the fallback is what carries the team now.
    assert sorted(employees) == ["jdoe", "rmantler"]
    assert employees["rmantler"]["group"] == "Platform"
