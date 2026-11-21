"""Make Jarvis's Slack-style replies survive Hermes's Markdown converter (transform_llm_output hook).

Jarvis and every specialist prompt write Slack mrkdwn: `*bold*`, `_italic_`, `•` bullets. Hermes's Slack adapter
(format_message, v0.23.1) treats the reply as standard Markdown and rewrites `*x*` to `_x_`, so every bold label was
posted in italics. This rewrites single-asterisk spans to `**x**`, which the adapter turns back into Slack bold.
`_italic_`, `**bold**`, bullets and links pass through unchanged, so running it twice changes nothing.

It also unwraps a Slack link the model put in backticks (`<mailto:a@b|a@b>` inside a code span shows the raw
syntax in Slack), leaving the link itself.

Pure function, no Hermes imports. It must never raise: with hold_stream the reply is withheld if the hook fails, so
the hook wrapper returns None (original text) on any error.
"""

from __future__ import annotations

import re

# Spans the emphasis rewrite must not touch: fenced code, inline code, Slack <...> links and mentions, Markdown links.
_PROTECTED = re.compile(
    r"```[\s\S]*?```"
    r"|`[^`\n]+`"
    r"|<(?:[@#!]|[a-zA-Z][a-zA-Z0-9+.\-]*:)[^>\n]*>"
    r"|(?<!!)\[[^\]\n]+\]\([^()\s]*\)")

# *x* with no space just inside either asterisk and not part of ** or a word (a*b*c, **x**, "a * b * c" stay).
_SINGLE_STAR = re.compile(r"(?<![*\w])\*([^\s*](?:[^*\n]*?[^\s*])?)\*(?![*\w])")

# A code span holding nothing but one Slack link: `<mailto:a@b|a@b>`, `<https://x|label>`.
_CODE_WRAPPED_LINK = re.compile(r"`(<[a-zA-Z][a-zA-Z0-9+.\-]*:[^>\n`]+>)`")


def _emphasis(text: str) -> str:
    return _SINGLE_STAR.sub(r"**\1**", text)


def slack_to_markdown(text: str) -> str:
    """Rewrite Slack-mrkdwn emphasis into the Markdown Hermes's Slack adapter expects."""
    if not text or "*" not in text and "`<" not in text:
        return text
    text = _CODE_WRAPPED_LINK.sub(r"\1", text)
    out, pos = [], 0
    for m in _PROTECTED.finditer(text):
        out.append(_emphasis(text[pos:m.start()]))
        out.append(m.group(0))
        pos = m.end()
    out.append(_emphasis(text[pos:]))
    return "".join(out)
