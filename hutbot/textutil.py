"""Logging + small text helpers with no Slack/network dependencies."""

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


def strip_quotes(text: str) -> str:
    if text and ((text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'"))):
        text = text[1:-1]

    return text


def parse_quoted_tokens(text: str) -> tuple[list[str], str]:
    tokens = []
    i = 0
    while i < len(text):
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            break

        if text[i] in ("'", '"'):
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
