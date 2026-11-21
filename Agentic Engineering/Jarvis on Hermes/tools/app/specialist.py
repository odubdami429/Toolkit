"""One specialist agent: its own prompt, its own tools, its own Claude tool-use loop.

Jarvis (Hermes) calls a specialist through an MCP tool and gets back only the specialist's final reply, so the
specialist's tool calls and reasoning never enter Jarvis's context.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Callable

from urllib.parse import urlsplit

import anthropic

import org
import providers

MODEL = "claude-opus-5-5"
EFFORT = "high"          # Opus 5.5 defaults to medium; triage is intelligence-sensitive
MAX_TOKENS = 16000       # non-streaming request; keeps each call under the SDK's HTTP timeout
MAX_RESULT_CHARS = 40000  # Hermes spills larger tool results to disk, where the model can't read them
WALL_CLOCK_S = 480        # stay inside the Hermes MCP tool timeout (540 s)

log = logging.getLogger("jarvis_tools")
_client = anthropic.Anthropic(max_retries=3, timeout=300.0)


@dataclass(frozen=True)
class Specialist:
    key: str
    title: str
    prompt: str
    tools: list[dict]
    run_tool: Callable[..., dict]
    max_iterations: int = 50
    # run_tool takes act_as=<requester email> (tools that act as the requester, e.g. enterprise search)
    acts_as_requester: bool = False
    # Tools that return internal content (enterprise search, tickets, wiki). Their results feed the web-query screen.
    internal_tools: frozenset[str] = frozenset()


# Web-query screen. web_search and web_fetch run on Anthropic's side, so jarvis-tools can't stop a query; it can only
# flag one in the web_call audit line for the log review. Two kinds of flag: fixed patterns for internal identifiers,
# and distinctive tokens (anything with a dot, @ or digit: hosts, emails, ticket keys, serials) that so far appeared
# only in an internal tool result, not in the brief, a domain tool result or a web result. Names without such characters
# aren't caught.
def _alternation(values) -> str:
    return "|".join(re.escape(v) for v in values if v) or r"(?!)"


def _tenant_hosts() -> list[str]:
    """The provider tenant hosts configured in org.env (<PREFIX>_BASE_URL and <PREFIX>_CONSOLE_URL for every domain):
    internal by definition. A malformed or unset value is skipped here (the adapter itself fails on it)."""
    hosts = set()
    for d in providers.DOMAINS.values():
        for name in (f"{d.env_prefix}_BASE_URL", f"{d.env_prefix}_CONSOLE_URL"):
            try:
                url = org.base_url(name)
            except ValueError:
                continue
            if url:
                hosts.add(urlsplit(url).hostname or "")
    return sorted(hosts - {""})


_TENANT_HOSTS = _tenant_hosts()
_FLAG_PATTERNS = [
    ("org_email", re.compile(r"[\w.+-]+@(?:" + _alternation(org.ORG_EMAIL_DOMAINS) + r")\b", re.I)),
    ("ticket_key", re.compile(r"\b(?!(?:CVE|GHSA|SHA|RFC|TLS|AES|ISO|UTF|MD)-)[A-Z][A-Z0-9]{1,9}-\d{1,7}\b")),
    ("internal_host", re.compile(r"\b[\w-]+\.(?:corp|internal|intranet|local|lan)\b|" + _alternation(_TENANT_HOSTS),
                                 re.I)),
    ("serial_like", re.compile(r"\b(?=[A-Z0-9]*\d)(?=[A-Z0-9]*[G-Z])[A-Z0-9]{10,12}\b")),
]
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{3,}")
# The organisation's own public domains, and common public tools: mentioning them reveals nothing internal.
# The third-party names below are outside-world public intel/lookup services (what an analyst queries), not part
# of any deploying organisation's own stack.
_COMMON = frozenset(set(org.ORG_DOMAINS) | {
    "github.com", "virustotal.com", "mxtoolbox.com", "linkedin.com", "who.is", "whois.com", "urlscan.io"})


def _tokens(text: str) -> set[str]:
    out = set()
    for t in _TOKEN.findall(text or ""):
        t = t.strip(".-_").lower()
        if len(t) < 4 or not re.search(r"[.@\d]", t) or re.fullmatch(r"[\d.:/-]+", t) or t in _COMMON:
            continue
        out.add(t)
    return out


def screen_web_query(query: str, internal_only: set[str]) -> list[str]:
    """Reasons a web query may carry internal detail (empty when it looks public)."""
    reasons = [name for name, rx in _FLAG_PATTERNS if rx.search(query or "")]
    hits = sorted(_tokens(query) & internal_only)
    if hits:
        reasons.append("from_internal_result:" + ",".join(hits[:5]))
    return reasons


def _audit(event: str, **fields: Any) -> None:
    log.info(json.dumps({"jarvis_tools": event, **fields}, sort_keys=True, default=str))


def _text(content: list) -> str:
    # Joined with no separator: web search citations split one sentence across several text blocks.
    return "".join(b.text for b in content if getattr(b, "type", "") == "text").strip()


def run_specialist(spec: Specialist, question: str, context: str, actor: str, request_id: str, *,
                   note: str = "") -> str:
    """Run the specialist to completion and return its final reply for Jarvis. `note` is a server-written line
    (never model text) added after the requester line."""
    started = time.monotonic()
    brief = f"Request from Jarvis on behalf of Slack user {actor}."
    if note:
        brief += f"\n{note}"
    brief += f"\n\n<question>\n{question.strip()}\n</question>"
    if context.strip():
        brief += f"\n\n<context>\n{context.strip()}\n</context>"
    messages: list[dict] = [{"role": "user", "content": brief}]
    system = [{"type": "text", "text": spec.prompt, "cache_control": {"type": "ephemeral"}}]
    tool_calls = 0
    web_flagged = 0
    response = None
    seen_public, seen_internal = _tokens(brief), set()

    for iteration in range(1, spec.max_iterations + 1):
        if time.monotonic() - started > WALL_CLOCK_S:
            _audit("specialist_timeout", specialist=spec.key, request_id=request_id, actor=actor, iteration=iteration)
            return (f"The {spec.title} specialist ran out of time after {tool_calls} tool calls. "
                    + (f"Its last notes:\n{_text(response.content)}" if response else "It produced no answer."))
        try:
            response = _client.beta.messages.create(
                model=MODEL,
                max_tokens=MAX_TOKENS,
                system=system,
                tools=spec.tools,
                messages=messages,
                output_config={"effort": EFFORT},
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
            )
        except anthropic.RateLimitError:
            _audit("specialist_error", specialist=spec.key, request_id=request_id, error="rate_limited")
            return f"The {spec.title} specialist is rate-limited by the model API. Try again in a minute."
        except anthropic.APIStatusError as e:
            _audit("specialist_error", specialist=spec.key, request_id=request_id, error=f"http_{e.status_code}")
            return f"The {spec.title} specialist failed: model API returned HTTP {e.status_code}."
        except anthropic.APIConnectionError:
            _audit("specialist_error", specialist=spec.key, request_id=request_id, error="connection")
            return f"The {spec.title} specialist couldn't reach the model API."

        # Append the whole content (thinking and fallback blocks included): the history must stay append-only.
        messages.append({"role": "assistant", "content": response.content})
        usage = response.usage
        _audit("specialist_turn", specialist=spec.key, request_id=request_id, iteration=iteration,
               stop_reason=response.stop_reason, model=response.model,
               input_tokens=usage.input_tokens, output_tokens=usage.output_tokens,
               cache_read=getattr(usage, "cache_read_input_tokens", None),
               cache_write=getattr(usage, "cache_creation_input_tokens", None))

        for block in response.content:  # web_search / web_fetch already ran on Anthropic's side; audit them
            kind = getattr(block, "type", "")
            if kind == "server_tool_use":
                args = block.input if isinstance(block.input, dict) else {}
                flags = []
                if block.name in ("web_search", "web_fetch"):
                    flags = screen_web_query(str(args.get("query") or args.get("url") or ""),
                                             seen_internal - seen_public)
                web_flagged += bool(flags)
                _audit("web_call", specialist=spec.key, request_id=request_id, actor=actor, tool=block.name,
                       args=block.input, **({"possible_internal": flags} if flags else {}))
            elif kind.endswith("_tool_result"):  # web results are public: their tokens don't count as internal
                seen_public |= _tokens(json.dumps(getattr(block, "content", None), default=str))

        if response.stop_reason == "tool_use":
            results = []
            for block in response.content:
                if getattr(block, "type", "") != "tool_use":
                    continue
                tool_calls += 1
                t0 = time.monotonic()
                out = spec.run_tool(block.name, dict(block.input or {}))
                status = out.get("status") if isinstance(out, dict) else None
                _audit("tool_call", specialist=spec.key, request_id=request_id, actor=actor, tool=block.name,
                       args=block.input, status=status, ms=int((time.monotonic() - t0) * 1000))
                body = json.dumps(out, default=str)
                if block.name in spec.internal_tools:
                    seen_internal |= _tokens(body)
                else:
                    seen_public |= _tokens(body)
                if len(body) > MAX_RESULT_CHARS:
                    body = body[:MAX_RESULT_CHARS] + "…[truncated]"
                results.append({"type": "tool_result", "tool_use_id": block.id, "content": body,
                                "is_error": status == "error"})
            # Rolling cache breakpoint on the newest tool result, so the next turn re-reads the whole history from
            # the cache instead of paying for it again. Only one is kept (plus the system prompt's).
            for m in messages:
                if m["role"] == "user" and isinstance(m["content"], list):
                    for b in m["content"]:
                        b.pop("cache_control", None)
            if results:
                results[-1]["cache_control"] = {"type": "ephemeral"}
            messages.append({"role": "user", "content": results})  # all results in one message
            continue
        if response.stop_reason == "pause_turn":
            continue  # resend; the paused assistant turn is already appended
        if response.stop_reason == "refusal":
            details = getattr(response, "stop_details", None)
            category = getattr(details, "category", None) if details else None
            _audit("specialist_refusal", specialist=spec.key, request_id=request_id, category=category)
            return (f"The {spec.title} specialist's model declined this request"
                    + (f" (safety category: {category})." if category else "."))
        if response.stop_reason == "max_tokens":
            return _text(response.content) + "\n\n…(the specialist's answer was cut off at the output limit)"
        break  # end_turn or anything else: done

    else:
        _audit("specialist_iteration_cap", specialist=spec.key, request_id=request_id, cap=spec.max_iterations)
        return (f"The {spec.title} specialist hit its {spec.max_iterations}-step limit. Its last notes:\n"
                + _text(response.content if response else []))

    _audit("specialist_done", specialist=spec.key, request_id=request_id, actor=actor, tool_calls=tool_calls,
           web_flagged=web_flagged, seconds=round(time.monotonic() - started, 1))
    reply = _text(response.content) if response else ""
    return reply[:MAX_RESULT_CHARS] or f"The {spec.title} specialist returned no text."
