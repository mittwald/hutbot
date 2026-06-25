"""Data types shared across the package: namedtuples + template expression."""

import collections
from dataclasses import dataclass

ScheduledReply = collections.namedtuple('ScheduledReply', ['task', 'user_id'])
User = collections.namedtuple('User', ['id', 'name', 'real_name', 'team'])
Usergroup = collections.namedtuple('Usergroup', ['id', 'handle', 'name'])
Channel = collections.namedtuple('Channel', ['id', 'name', 'configs'])
OpsGeniePeriod = collections.namedtuple('OpsGeniePeriod', ['recipient_email', 'slack_user', 'start', 'end'])
OpsGenieContext = collections.namedtuple('OpsGenieContext', ['schedule_name', 'current', 'next'])


@dataclass(frozen=True)
class TemplateExpression:
    variable: str
    args: dict[str, str]


class TemplateExpressionError(ValueError):
    pass
