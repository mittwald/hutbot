from query_employees import find_employees, format_employee


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
