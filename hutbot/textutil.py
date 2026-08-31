"""Small text helpers with no Slack/network dependencies."""

import re

import logutil

from .models import Channel


def log_debug(channel: Channel | None, *args: object) -> None:
    """A DEBUG line, but only for a channel that has `debug` set on one of its configs."""
    if channel and any(c.get('debug') for c in channel.configs.values()):
        logutil.log_debug(*args)


# Quote characters accepted around any command argument. Backticks are included because
# Slack renders `like this` as code, so people reach for them naturally.
QUOTE_CHARACTERS = ('"', "'", '`')


def strip_quotes(text: str) -> str:
    if text and len(text) > 1 and text[0] == text[-1] and text[0] in QUOTE_CHARACTERS:
        text = text[1:-1]

    return text


# A slash command arrives as a single line, and the argument regexes stop at the first
# newline anyway, so a line break has to be typed as `\n`. Only `\n` and `\\` mean
# anything; every other backslash is passed through untouched, so a datetime format like
# `%Y\%m` or a regex in a template argument survives unharmed.
ESCAPE_SEQUENCE_PATTERN = re.compile(r'\\(.)', re.DOTALL)


def decode_escaped_newlines(text: str) -> str:
    r"""Turn `\n` into a real line break, and `\\n` into a literal backslash-n."""
    def replace(match: re.Match) -> str:
        escaped = match.group(1)
        if escaped == 'n':
            return '\n'
        if escaped == '\\':
            return '\\'
        return match.group(0)

    return ESCAPE_SEQUENCE_PATTERN.sub(replace, text or "")


def escape_newlines(text: str) -> str:
    r"""A value on one line, its line breaks shown as `\n` — the spelling commands use for them.

    For printing a stored template back to somebody: a real line break would break whatever
    layout it is printed in (a column-aligned table, a one-per-line list). Other backslashes
    are left alone, like `decode_escaped_newlines` leaves them.
    """
    return (text or "").replace("\n", "\\n")


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
