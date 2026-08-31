"""OpsGenie integration: on-call resolution, template variables, alerts, heartbeat."""

import copy
import json
import asyncio
import datetime
import urllib.parse

import aiohttp
from slack_bolt.async_app import AsyncApp

from logutil import log, log_error, log_warning

from . import datetimefmt
from . import slackcache
from . import messaging
from . import state
from .constants import (
    DEFAULT_CONFIG,
    DEFAULT_OPSGENIE_PRIORITY,
    bot_slug,
    OPSGENIE_DATETIME_TEMPLATE_VARIABLES,
    OPSGENIE_PRIORITIES,
    UNKNOWN_EMAIL_ONCALL_PLACEHOLDER,
    UNKNOWN_NAME_ONCALL_PLACEHOLDER,
    UNKNOWN_PERIOD_PLACEHOLDER,
    UNKNOWN_OPSGENIE_SCHEDULE_PLACEHOLDER,
    UNKNOWN_USER_ONCALL_PLACEHOLDER,
)
from .models import OpsGenieContext, OpsGeniePeriod, User
from .textutil import log_debug


def get_opsgenie_priority(config: dict | None) -> str:
    priority = (config or {}).get('opsgenie_priority', DEFAULT_OPSGENIE_PRIORITY)
    priority = priority.strip().upper() if isinstance(priority, str) else ""
    return priority if priority in OPSGENIE_PRIORITIES else DEFAULT_OPSGENIE_PRIORITY


def get_opsgenie_placeholder_variables(config: dict | None = None) -> dict[str, str]:
    schedule_name = (config or {}).get("opsgenie_schedule_name", "").strip()
    variables = {
        "opsgenie_schedule_name": schedule_name or UNKNOWN_OPSGENIE_SCHEDULE_PLACEHOLDER,
        "opsgenie_current_email": UNKNOWN_EMAIL_ONCALL_PLACEHOLDER,
        "opsgenie_current_name": UNKNOWN_NAME_ONCALL_PLACEHOLDER,
        "opsgenie_current_user": UNKNOWN_USER_ONCALL_PLACEHOLDER,
        "opsgenie_next_email": UNKNOWN_EMAIL_ONCALL_PLACEHOLDER,
        "opsgenie_next_name": UNKNOWN_NAME_ONCALL_PLACEHOLDER,
        "opsgenie_next_user": UNKNOWN_USER_ONCALL_PLACEHOLDER,
    }
    for variable in OPSGENIE_DATETIME_TEMPLATE_VARIABLES:
        variables[variable] = UNKNOWN_PERIOD_PLACEHOLDER
        variables[f"__{variable}_raw"] = ""
    return variables


def fill_opsgenie_period_variables(variables: dict[str, str], config: dict, prefix: str, period: OpsGeniePeriod) -> None:
    if not period.recipient_email:
        return

    variables[f"opsgenie_{prefix}_email"] = period.recipient_email
    variables[f"opsgenie_{prefix}_name"] = period.recipient_email
    if period.slack_user:
        variables[f"opsgenie_{prefix}_user"] = f"<@{period.slack_user.id}>"
        variables[f"opsgenie_{prefix}_name"] = period.slack_user.real_name if period.slack_user.real_name else period.slack_user.name

    for bound, value in (("start", period.start), ("end", period.end)):
        for part in ("date", "time", "datetime"):
            variable = f"opsgenie_{prefix}_{bound}_{part}"
            variables[f"__{variable}_raw"] = value or ""
            variables[variable] = datetimefmt.format_template_datetime(value, variable, config)


async def resolve_slack_user_for_opsgenie_recipient(app: AsyncApp, recipient_email: str) -> User | None:
    slack_user = await slackcache.get_user_by_email(app, recipient_email)
    if not slack_user.id:
        log_warning(f"Failed to map OpsGenie recipient '{recipient_email}' to a Slack user.")
        return None
    return slack_user


async def resolve_opsgenie_on_call(app: AsyncApp, opsgenie_token: str, schedule_name: str) -> tuple[str, User | None]:
    schedule_name = schedule_name.strip()
    if not opsgenie_token:
        log_warning(f"Cannot resolve OpsGenie schedule '{schedule_name}': missing token.")
        return "", None

    encoded_schedule_name = urllib.parse.quote(schedule_name, safe="")
    url = f"https://api.opsgenie.com/v2/schedules/{encoded_schedule_name}/on-calls"
    headers = {
        "Authorization": f"GenieKey {opsgenie_token}",
    }
    params = {
        "scheduleIdentifierType": "name",
        "flat": "true",
    }

    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            async with session.get(url, headers=headers, params=params) as response:
                if response.status != 200:
                    log_error(f"Failed to retrieve on-call recipients for OpsGenie schedule '{schedule_name}': {response.status}")
                    return "", None
                payload = await response.json()
    except Exception as e:
        log_error(f"Failed to retrieve on-call recipients for OpsGenie schedule '{schedule_name}':", e)
        return "", None

    recipients = payload.get("data", {}).get("onCallRecipients", [])
    if not recipients:
        log_warning(f"OpsGenie schedule '{schedule_name}' returned no current on-call recipients.")
        return "", None

    recipient_email = recipients[0].strip()
    if not recipient_email:
        return "", None

    return recipient_email, await resolve_slack_user_for_opsgenie_recipient(app, recipient_email)


def merge_opsgenie_periods(periods: list[dict], current_index: int) -> tuple[str, str]:
    current_period = periods[current_index]
    recipient_name = current_period.get("recipient", {}).get("name", "").strip().casefold()
    merged_start = datetimefmt.parse_opsgenie_datetime(current_period.get("startDate", ""))
    merged_end = datetimefmt.parse_opsgenie_datetime(current_period.get("endDate", ""))
    if not recipient_name or merged_start is None or merged_end is None:
        return current_period.get("startDate", ""), current_period.get("endDate", "")

    first_period = current_period
    last_period = current_period

    for period in reversed(periods[:current_index]):
        period_recipient = period.get("recipient", {}).get("name", "").strip().casefold()
        period_start = datetimefmt.parse_opsgenie_datetime(period.get("startDate", ""))
        period_end = datetimefmt.parse_opsgenie_datetime(period.get("endDate", ""))
        if period_recipient != recipient_name or period_start is None or period_end is None or period_end != merged_start:
            break
        merged_start = period_start
        first_period = period

    for period in periods[current_index + 1:]:
        period_recipient = period.get("recipient", {}).get("name", "").strip().casefold()
        period_start = datetimefmt.parse_opsgenie_datetime(period.get("startDate", ""))
        period_end = datetimefmt.parse_opsgenie_datetime(period.get("endDate", ""))
        if period_recipient != recipient_name or period_start is None or period_end is None or period_start != merged_end:
            break
        merged_end = period_end
        last_period = period

    return first_period.get("startDate", ""), last_period.get("endDate", "")


def merge_opsgenie_periods_forward(periods: list[dict], current_index: int) -> tuple[str, str]:
    current_period = periods[current_index]
    recipient_name = current_period.get("recipient", {}).get("name", "").strip().casefold()
    merged_end = datetimefmt.parse_opsgenie_datetime(current_period.get("endDate", ""))
    if not recipient_name or merged_end is None:
        return current_period.get("startDate", ""), current_period.get("endDate", "")

    last_period = current_period
    for period in periods[current_index + 1:]:
        period_recipient = period.get("recipient", {}).get("name", "").strip().casefold()
        period_start = datetimefmt.parse_opsgenie_datetime(period.get("startDate", ""))
        period_end = datetimefmt.parse_opsgenie_datetime(period.get("endDate", ""))
        if period_recipient != recipient_name or period_start is None or period_end is None or period_start != merged_end:
            break
        merged_end = period_end
        last_period = period

    return current_period.get("startDate", ""), last_period.get("endDate", "")


def find_opsgenie_on_call_period(data: dict, recipient_email: str, now: datetime.datetime | None = None) -> tuple[str, str]:
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=datetime.timezone.utc)

    rotations = []
    for timeline_name in ("finalTimeline", "baseTimeline"):
        rotations.extend(data.get(timeline_name, {}).get("rotations", []))

    periods = [period for rotation in rotations for period in rotation.get("periods", [])]
    if not periods:
        return "", ""

    recipient_email = recipient_email.casefold()

    for rotation in rotations:
        rotation_periods = sorted(
            rotation.get("periods", []),
            key=lambda period: datetimefmt.parse_opsgenie_datetime(period.get("startDate", "")) or datetime.datetime.min.replace(tzinfo=datetime.timezone.utc),
        )
        for index, period in enumerate(rotation_periods):
            start = datetimefmt.parse_opsgenie_datetime(period.get("startDate", ""))
            end = datetimefmt.parse_opsgenie_datetime(period.get("endDate", ""))
            is_current = start is not None and end is not None and start <= now < end
            recipient_name = period.get("recipient", {}).get("name", "").strip().casefold()
            matches_recipient = bool(recipient_email and recipient_name == recipient_email)
            if is_current and matches_recipient:
                return merge_opsgenie_periods(rotation_periods, index)

    return "", ""


def find_opsgenie_upcoming_on_call_period(data: dict, now: datetime.datetime | None = None) -> tuple[str, str, str]:
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=datetime.timezone.utc)

    best_candidate = None
    for timeline_name in ("finalTimeline", "baseTimeline"):
        rotations = data.get(timeline_name, {}).get("rotations", [])
        for rotation in rotations:
            rotation_periods = sorted(
                rotation.get("periods", []),
                key=lambda period: datetimefmt.parse_opsgenie_datetime(period.get("startDate", "")) or datetime.datetime.min.replace(tzinfo=datetime.timezone.utc),
            )
            threshold = now
            include_threshold = False
            for index, period in enumerate(rotation_periods):
                start = datetimefmt.parse_opsgenie_datetime(period.get("startDate", ""))
                end = datetimefmt.parse_opsgenie_datetime(period.get("endDate", ""))
                if start is not None and end is not None and start <= now < end:
                    _, merged_end = merge_opsgenie_periods(rotation_periods, index)
                    threshold = datetimefmt.parse_opsgenie_datetime(merged_end) or end
                    include_threshold = True
                    break

            for index, period in enumerate(rotation_periods):
                start = datetimefmt.parse_opsgenie_datetime(period.get("startDate", ""))
                end = datetimefmt.parse_opsgenie_datetime(period.get("endDate", ""))
                recipient_email = period.get("recipient", {}).get("name", "").strip()
                if start is None or end is None or not recipient_email:
                    continue
                if start < threshold or (start == threshold and not include_threshold):
                    continue

                candidate = (start, rotation_periods, index, recipient_email)
                if best_candidate is None or candidate[0] < best_candidate[0]:
                    best_candidate = candidate

    if best_candidate is None:
        return "", "", ""

    _, rotation_periods, index, recipient_email = best_candidate
    start, end = merge_opsgenie_periods_forward(rotation_periods, index)
    return recipient_email, start, end


async def resolve_opsgenie_on_call_period(opsgenie_token: str, schedule_name: str, recipient_email: str) -> tuple[str, str]:
    schedule_name = schedule_name.strip()
    if not opsgenie_token:
        return "", ""

    encoded_schedule_name = urllib.parse.quote(schedule_name, safe="")
    url = f"https://api.opsgenie.com/v2/schedules/{encoded_schedule_name}/timeline"
    headers = {
        "Authorization": f"GenieKey {opsgenie_token}",
    }
    timeline_start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=90)
    params = {
        "identifierType": "name",
        "date": timeline_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "interval": "6",
        "intervalUnit": "months",
    }

    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            async with session.get(url, headers=headers, params=params) as response:
                if response.status != 200:
                    log_error(f"Failed to retrieve timeline for OpsGenie schedule '{schedule_name}': {response.status}")
                    return "", ""
                payload = await response.json()
    except Exception as e:
        log_error(f"Failed to retrieve timeline for OpsGenie schedule '{schedule_name}':", e)
        return "", ""

    return find_opsgenie_on_call_period(payload.get("data", {}), recipient_email)


async def resolve_opsgenie_upcoming_on_call_period(opsgenie_token: str, schedule_name: str) -> tuple[str, str, str]:
    schedule_name = schedule_name.strip()
    if not opsgenie_token:
        return "", "", ""

    encoded_schedule_name = urllib.parse.quote(schedule_name, safe="")
    url = f"https://api.opsgenie.com/v2/schedules/{encoded_schedule_name}/timeline"
    headers = {
        "Authorization": f"GenieKey {opsgenie_token}",
    }
    timeline_start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=90)
    params = {
        "identifierType": "name",
        "date": timeline_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "interval": "6",
        "intervalUnit": "months",
    }

    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            async with session.get(url, headers=headers, params=params) as response:
                if response.status != 200:
                    log_error(f"Failed to retrieve timeline for OpsGenie schedule '{schedule_name}': {response.status}")
                    return "", "", ""
                payload = await response.json()
    except Exception as e:
        log_error(f"Failed to retrieve timeline for OpsGenie schedule '{schedule_name}':", e)
        return "", "", ""

    return find_opsgenie_upcoming_on_call_period(payload.get("data", {}))


async def resolve_opsgenie_on_call_context(app: AsyncApp, opsgenie_token: str, schedule_name: str, include_next: bool = True) -> OpsGenieContext:
    schedule_name = schedule_name.strip()
    empty_period = OpsGeniePeriod("", None, "", "")
    current_period = empty_period
    next_period = empty_period

    recipient_email, slack_user = await resolve_opsgenie_on_call(app, opsgenie_token, schedule_name)
    if recipient_email:
        start, end = await resolve_opsgenie_on_call_period(opsgenie_token, schedule_name, recipient_email)
        current_period = OpsGeniePeriod(recipient_email, slack_user, start, end)

    if include_next:
        next_email, next_start, next_end = await resolve_opsgenie_upcoming_on_call_period(opsgenie_token, schedule_name)
        next_slack_user = await resolve_slack_user_for_opsgenie_recipient(app, next_email) if next_email else None
        next_period = OpsGeniePeriod(next_email, next_slack_user, next_start, next_end)

    return OpsGenieContext(schedule_name, current_period, next_period)


async def get_opsgenie_template_variables(app: AsyncApp, opsgenie_token: str, config: dict) -> dict[str, str]:
    schedule_name = config.get("opsgenie_schedule_name", "").strip()
    variables = get_opsgenie_placeholder_variables(config)
    if not schedule_name:
        return variables

    context = await resolve_opsgenie_on_call_context(app, opsgenie_token, schedule_name, include_next=True)
    fill_opsgenie_period_variables(variables, config, "current", context.current)
    fill_opsgenie_period_variables(variables, config, "next", context.next)

    return variables


async def send_current_on_call(app: AsyncApp, opsgenie_token: str, channel, config_name: str, schedule_name: str, user, thread_ts: str = "") -> None:
    config = channel.configs.get(config_name) or copy.deepcopy(DEFAULT_CONFIG)
    schedule_name = schedule_name.strip() or config.get("opsgenie_schedule_name", "").strip()
    if not schedule_name:
        await messaging.send_message(app, channel, user, f"No OpsGenie schedule configured. Use `{state.slash_command} [config] set opsgenie-schedule <name>` or `{state.slash_command} [config] on-call <schedule name>`.", thread_ts)
        return
    if not opsgenie_token:
        await messaging.send_message(app, channel, user, "OpsGenie is not configured. Missing `OPSGENIE_TOKEN`.", thread_ts)
        return

    recipient_email, slack_user = await resolve_opsgenie_on_call(app, opsgenie_token, schedule_name)
    if recipient_email:
        start, end = await resolve_opsgenie_on_call_period(opsgenie_token, schedule_name, recipient_email)
    else:
        recipient_email, start, end = await resolve_opsgenie_upcoming_on_call_period(opsgenie_token, schedule_name)
        if recipient_email:
            slack_user = await resolve_slack_user_for_opsgenie_recipient(app, recipient_email)

    if not recipient_email:
        await messaging.send_message(app, channel, user, f"Failed to resolve on-call user for OpsGenie schedule `{schedule_name}`.", thread_ts)
        return

    mention = f"<@{slack_user.id}>" if slack_user else recipient_email
    message = (
        f"*Schedule*: `{schedule_name}`\n"
        f"*On-call*: {mention}\n"
        f"*Start*: `{datetimefmt.format_datetime_value(start, 'datetime', config)}`\n"
        f"*End*: `{datetimefmt.format_datetime_value(end, 'datetime', config)}`"
    )
    await messaging.send_message(app, channel, user, message, thread_ts)


async def post_opsgenie_alert(app: AsyncApp, opsgenie_token: str, channel, config: dict | None, user: User, text: str, ts: str, permalink: str) -> None:
    log_debug(channel, f"> {text.replace(chr(10), '\\n')}")
    text = await messaging.clean_slack_text(app, channel, text)
    log_debug(channel, f"< {text}")
    user_name = user.real_name if user.real_name else user.name
    priority = get_opsgenie_priority(config)
    url = 'https://api.opsgenie.com/v2/alerts'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'GenieKey {opsgenie_token}'
    }
    # The alias is OpsGenie's dedup key, so it uses the slug rather than the
    # display name — that also keeps a dev instance from deduping against prod.
    slug = bot_slug(state.bot_name)
    async with aiohttp.ClientSession() as session:
        try:
            data = {
                "message": f"#{channel.name}: {text}",
                "alias": f"{slug}: {user_name} in #{channel.name} {ts}",
                "description": f"{user_name} in #{channel.name}: {text}",
                "tags": [state.bot_name],
                "details": {
                    "channel": f"#{channel.name}",
                    "sender": user_name,
                    "bot": slug,
                    "permalink": permalink,
                },
                "priority": priority,
            }
            async with session.post(url, headers=headers, data=json.dumps(data)) as response:
                if response.status != 202:
                    log_error(f"Failed to send alert for message {ts} in channel #{channel.name}, user @{user.name}: {response.status}")
                else:
                    log(f"Successfully sent OpsGenie alert for message {ts} in channel #{channel.name}, user @{user.name} with status code {response.status}")
        except Exception as e:
            log_error(f"Failed to send alert for message {ts} in channel #{channel.name}, user @{user.name}:", e)


async def send_heartbeat(opsgenie_token: str, opsgenie_heartbeat_name: str) -> None:
    url = 'https://api.opsgenie.com/v2/heartbeats/' + opsgenie_heartbeat_name + '/ping'
    headers = {
        'Authorization': f'GenieKey {opsgenie_token}'
    }
    log(f"Starting to send heartbeat to {url}...")
    async with aiohttp.ClientSession() as session:
        while True:
            try:
                async with session.get(url, headers=headers) as response:
                    if response.status != 202:
                        log_error(f"Failed to send heartbeat: {response.status}")
            except Exception as e:
                log_error("Exception while sending heartbeat:", e)
            await asyncio.sleep(60)
