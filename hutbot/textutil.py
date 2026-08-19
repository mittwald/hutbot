"""Logging + small text helpers with no Slack/network dependencies."""

import re
import sys
import datetime

from .models import Channel


def log_debug(channel: Channel | None, *args: object) -> None:
    if channel and any(c.get('debug') for c in channel.configs.values()):
        _log(sys.stderr, 'DEBUG', *args)


def _log(file, prefix, *args: object) -> None:
    parts = []
    for arg in args:
        part = str(arg)
        if isinstance(arg, BaseException):
            error_type = type(arg).__name__
            error_message = str(arg)
            part = f"{error_type}{': ' + error_message if error_message else ''}"
        parts.append(part)
    message = ' '.join(parts)
    prefix = f"{datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')} {prefix}:"
    print(prefix, message, flush=True, file=file)


# Quote characters accepted around any command argument. Backticks are included because
# Slack renders `like this` as code, so people reach for them naturally.
QUOTE_CHARACTERS = ('"', "'", '`')


def strip_quotes(text: str) -> str:
    if text and len(text) > 1 and text[0] == text[-1] and text[0] in QUOTE_CHARACTERS:
        text = text[1:-1]

    return text


# Slack turns any URL a user types into `<https://...>` or `<https://...|label>` before
# the slash command reaches the bot. `strip_quotes` does not touch that, and
# `messaging.clean_slack_text` would replace it with the literal string "[URL]".
SLACK_LINK_PATTERN = re.compile(r'^<(?P<url>[^|>]+)(?:\|[^>]*)?>$')


def unwrap_slack_link(text: str) -> str:
    """Strip Slack's `<url>` / `<url|label>` auto-link wrapping from a URL argument.

    Quotes come off on both sides of the unwrap, because Slack still auto-links a URL typed
    inside backticks — so the argument can arrive as ``` `<http://…>` ```.
    """
    text = strip_quotes((text or "").strip())
    match = SLACK_LINK_PATTERN.match(text)
    if match:
        text = match.group("url").strip()
    return strip_quotes(text)


def parse_quoted_tokens(text: str) -> tuple[list[str], str]:
    tokens = []
    i = 0
    while i < len(text):
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            break

        if text[i] in QUOTE_CHARACTERS:
            quote = text[i]
            i += 1
            value = []
            while i < len(text):
                if text[i] == "\\" and i + 1 < len(text) and text[i + 1] in (quote, "\\"):
                    value.append(text[i + 1])
                    i += 2
                    continue
                if text[i] == quote:
                    i += 1
                    break
                value.append(text[i])
                i += 1
            else:
                return [], "unterminated quoted value"
            if i < len(text) and not text[i].isspace():
                return [], "quoted values must be separated by whitespace"
            tokens.append("".join(value))
        else:
            start = i
            while i < len(text) and not text[i].isspace():
                i += 1
            tokens.append(text[start:i])

    return tokens, ""


def extract_message_text(event: dict) -> str:
    text = event.get('text', '')
    if isinstance(text, str) and text.strip():
        return text

    attachment_texts = []
    fallback_texts = []
    for attachment in event.get('attachments', []):
        if not isinstance(attachment, dict):
            continue

        for field in ('pretext', 'title', 'text'):
            value = attachment.get(field, '')
            if isinstance(value, str) and value.strip():
                attachment_texts.append(value)

        fallback = attachment.get('fallback', '')
        if isinstance(fallback, str) and fallback.strip():
            fallback_texts.append(fallback)

    if attachment_texts:
        return "\n".join(attachment_texts).strip()

    return "\n".join(fallback_texts).strip()
