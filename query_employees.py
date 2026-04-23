#!/usr/bin/env python3
import argparse
import asyncio
import json

from employee_list import (
    load_employee_mappings,
    load_employees,
    load_employees_from_disk,
    load_env_file,
    normalize_id,
    normalize_real_name,
    normalize_real_name_with_diagraphs,
    normalize_user_name,
)


def invert_employee_mappings(mappings: dict[str, str]) -> dict[str, set[str]]:
    aliases_by_employee: dict[str, set[str]] = {}
    for slack_name, employee_name in mappings.items():
        aliases = aliases_by_employee.setdefault(employee_name, set())
        aliases.add(slack_name)
    return aliases_by_employee


def build_search_terms(employee: dict, aliases: set[str]) -> set[str]:
    terms = set(aliases)

    ad_name = normalize_id(employee.get("ad_name", ""))
    fullname = employee.get("fullname", "").strip()
    mail = normalize_id(employee.get("mail", ""))
    team = normalize_id(employee.get("group", ""))

    if ad_name:
        terms.add(ad_name)
        terms.add(normalize_user_name(ad_name))
    if fullname:
        terms.add(normalize_real_name(fullname))
        terms.add(normalize_real_name_with_diagraphs(fullname))
    if mail:
        terms.add(mail)
        terms.add(normalize_id(mail.split("@")[0]))
        terms.add(normalize_user_name(mail.split("@")[0]))
    if team:
        terms.add(team)

    return {term for term in terms if term}


def matches_employee(employee: dict, query: str, team: str | None, aliases: set[str]) -> bool:
    employee_team = normalize_id(employee.get("group", ""))
    if team and employee_team != normalize_id(team):
        return False

    normalized_queries = {
        normalize_id(query),
        normalize_user_name(query),
        normalize_real_name(query),
        normalize_real_name_with_diagraphs(query),
    }
    normalized_queries = {normalized_query for normalized_query in normalized_queries if normalized_query}
    if not normalized_queries:
        return True

    for term in build_search_terms(employee, aliases):
        for normalized_query in normalized_queries:
            if normalized_query in term:
                return True
    return False


def find_employees(
    employees: dict[str, dict],
    query: str,
    team: str | None = None,
    mappings: dict[str, str] | None = None,
) -> list[dict]:
    aliases_by_employee = invert_employee_mappings(mappings or {})
    results = []

    for employee_key, employee in employees.items():
        aliases = aliases_by_employee.get(normalize_id(employee_key), set())
        if matches_employee(employee, query, team, aliases):
            results.append(employee)

    return sorted(
        results,
        key=lambda employee: (
            employee.get("fullname", "").casefold(),
            employee.get("ad_name", "").casefold(),
        ),
    )


def format_employee(employee: dict) -> str:
    ad_name = employee.get("ad_name", "").strip() or "<unknown>"
    fullname = employee.get("fullname", "").strip() or "<unknown>"
    team = employee.get("group", "").strip() or "<unknown>"
    mail = employee.get("mail", "").strip()

    details = f"{fullname} ({ad_name}) - team: {team}"
    if mail:
        details += f" - mail: {mail}"
    return details


async def _load_employees(cache_only: bool) -> dict[str, dict]:
    if cache_only:
        return await load_employees_from_disk()
    return await load_employees()


async def async_main() -> int:
    parser = argparse.ArgumentParser(
        description="Query Hutbot's employee list from the local terminal.",
    )
    parser.add_argument(
        "query",
        nargs="?",
        default="",
        help="Search term for ad_name, full name, email alias, or team.",
    )
    parser.add_argument(
        "--team",
        help="Restrict results to one exact team name.",
    )
    parser.add_argument(
        "--cache-only",
        action="store_true",
        help="Only read the local employee cache file.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print matching employees as JSON.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Maximum number of results to print. Use 0 for no limit.",
    )
    args = parser.parse_args()

    load_env_file()
    employees = await _load_employees(args.cache_only)
    mappings = load_employee_mappings()
    matches = find_employees(employees, args.query, args.team, mappings)

    if args.limit > 0:
        matches = matches[:args.limit]

    if args.json:
        print(json.dumps(matches, indent=2))
    elif matches:
        for employee in matches:
            print(format_employee(employee))
    else:
        print("No employees found.")
        return 1

    return 0


def main() -> None:
    raise SystemExit(asyncio.run(async_main()))


if __name__ == "__main__":
    main()
