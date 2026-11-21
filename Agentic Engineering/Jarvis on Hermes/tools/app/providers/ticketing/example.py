"""Ticketing and wiki: EXAMPLE read adapter (skeleton).

Implements the read interface from ``providers/__init__.py`` against ``contract.TOOLS`` (with this adapter's
query-language primers filled in by ``contract.with_primer``). Generic input validation is real (required query,
length cap, ticket key and page id shapes) so the contract tests exercise it; every vendor call is a stub returning
``status: not_implemented``. Copy this file to ``<your_product>.py``, write your primers, replace each
``# TODO: call your vendor API``, register it in ``providers/__init__.py`` and make the contract tests pass.

Settings read here: ``TICKETING_BASE_URL``, ``TICKETING_CONSOLE_URL`` (links) and credentials ``TICKETING_API_TOKEN``
(+ ``TICKETING_USERNAME``) or ``TICKETING_CLIENT_ID`` + ``TICKETING_CLIENT_SECRET``.

Dependencies: ``org`` and the standard library. Target: Python 3.12.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Callable, Mapping

import org
from providers.ticketing import contract

log = logging.getLogger(__name__)

#: Replace with short primers for your product's ticket and wiki query languages (syntax, fields, an example each).
TICKET_QUERY_PRIMER = "(document your query syntax here)"
WIKI_QUERY_PRIMER = "(document your query syntax here)"

TOOLS = contract.with_primer(contract.with_primer(contract.TOOLS, "search_tickets", TICKET_QUERY_PRIMER),
                             "search_wiki", WIKI_QUERY_PRIMER)
TOOL_NAMES = contract.TOOL_NAMES

NOT_IMPLEMENTED_NEXT_STEP = "Say this lookup isn't implemented in this deployment; never invent results."
_KEY_IN_TEXT = re.compile(r"\b([A-Z][A-Z0-9_]{0,19}-[1-9][0-9]{0,8})\b", re.ASCII)


class ToolError(Exception):
    """Raised by input checks; ``result`` is the dict returned to the model."""

    def __init__(self, message: str, *, status: str = "error", next_step: str = "", **extra: Any):
        super().__init__(message)
        self.result = {"status": status, "message": message, **extra}
        if next_step:
            self.result["next_step"] = next_step


def invalid(message: str) -> ToolError:
    return ToolError(message, status="invalid_input", error_kind="INPUT",
                     next_step="Nothing was sent. Fix the input as described and call the tool again.")


def not_implemented(name: str, **echo: Any) -> dict:
    return {"status": "not_implemented", "tool": name,
            "message": f"{name} is not implemented by the example ticketing adapter.",
            "next_step": NOT_IMPLEMENTED_NEXT_STEP, **({"validated": echo} if echo else {})}


# --- client ----------------------------------------------------------------------------------------------------------

class ExampleClient:
    """Holds the site origin and credentials. A real adapter adds its HTTP client and GET-only allowlist here."""

    def __init__(self, base_url: str, console_url: str, credentials: dict[str, str]):
        self.base_url = base_url
        self.console_url = console_url or base_url
        self.__credentials = dict(credentials)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(base={self.base_url!r}, credentials=<redacted>)"

    __str__ = __repr__

    def _secrets_for_scrub(self) -> list[str]:
        return [v for v in self.__credentials.values() if v]

    # TODO: call your vendor API. Implement ONE `_request(path, params)` that allows only GET on a fixed set of
    # (path regex, query keys) - ticket search, one ticket, wiki search, one page - BEFORE any network I/O, never
    # follows redirects and caps the body size.


def credentials_from_env(env: Mapping[str, str], prefix: str) -> dict[str, str] | None:
    """The configured credential set for a domain prefix, or None. A client id needs a secret or a private key."""
    get = lambda k: str(env.get(f"{prefix}_{k}", "") or "").strip()  # noqa: E731
    if get("API_TOKEN"):
        return {"api_token": get("API_TOKEN"), "username": get("USERNAME")}
    if get("CLIENT_ID") and (get("CLIENT_SECRET") or get("PRIVATE_KEY_B64")):
        return {"client_id": get("CLIENT_ID"), "client_secret": get("CLIENT_SECRET"),
                "key_id": get("KEY_ID"), "private_key_b64": get("PRIVATE_KEY_B64")}
    return None


def client_from_env(env: Mapping[str, str]) -> ExampleClient | None:
    """A client when TICKETING_BASE_URL and credentials are set, else None. Never raises."""
    try:
        base = org.base_url(f"{contract.PREFIX}_BASE_URL", env=env)
        console = org.base_url(f"{contract.PREFIX}_CONSOLE_URL", env=env)
    except ValueError:
        log.warning("%s_BASE_URL / %s_CONSOLE_URL is not a bare https origin", contract.PREFIX, contract.PREFIX)
        return None
    creds = credentials_from_env(env, contract.PREFIX)
    return ExampleClient(base, console, creds) if base and creds else None


# --- input checks ----------------------------------------------------------------------------------------------------

def query_arg(args: dict, key: str = "query") -> str:
    v = args.get(key)
    if not isinstance(v, str) or not v.strip():
        raise invalid(f"`{key}` is required: a non-empty query string.")
    v = v.strip()
    if len(v) > contract.MAX_QUERY_CHARS:
        raise invalid(f"`{key}` is too long ({len(v)} characters, max {contract.MAX_QUERY_CHARS}).")
    return v


def ticket_key(raw: Any) -> str:
    """A ticket key (case-normalised), or one found in a link."""
    if isinstance(raw, bool) or not isinstance(raw, (str, int)) or not str(raw).strip():
        raise invalid("`ticket_key` is required, e.g. SEC-123.")
    s = str(raw).strip().strip("<>`\"'[]")
    if contract.TICKET_KEY_SHAPE.fullmatch(s.upper()):
        return s.upper()
    if s.lower().startswith("https://"):
        m = _KEY_IN_TEXT.search(s)
        if m:
            return m.group(1)
    raise invalid("`ticket_key` must be a ticket key like SEC-123 (project prefix, dash, number; no brackets).")


def page_id(raw: Any) -> str:
    s = str(raw).strip() if isinstance(raw, (str, int)) and not isinstance(raw, bool) else ""
    if contract.PAGE_ID_SHAPE.fullmatch(s):
        return s
    raise invalid("`page_id` must be the page ID returned by search_wiki. For a link or a title, find the page with "
                  "search_wiki first.")


# --- tools (stubs) ---------------------------------------------------------------------------------------------------

def _search_tickets(c: ExampleClient, args: dict) -> dict:
    q = query_arg(args)
    # TODO: call your vendor API: run the query verbatim, at most contract.SEARCH_LIMIT results with the summary
    # fields; none -> status no_results ("don't broaden the search"); a query syntax error -> status error with the
    # product's message so the model can fix the query.
    return not_implemented("search_tickets", query=q)


def _get_ticket_details(c: ExampleClient, args: dict) -> dict:
    key = ticket_key(args.get("ticket_key"))
    # TODO: call your vendor API: one ticket by key; 404 -> not_found. Description and comments to plain text, capped
    # (MAX_DESCRIPTION_CHARS, last MAX_COMMENTS comments of MAX_COMMENT_CHARS); links; url on TICKETING_CONSOLE_URL.
    return not_implemented("get_ticket_details", ticket_key=key)


def _search_wiki(c: ExampleClient, args: dict) -> dict:
    q = query_arg(args)
    # TODO: call your vendor API: run the query verbatim, at most contract.SEARCH_LIMIT pages with a short plain-text
    # excerpt; none -> no_results.
    return not_implemented("search_wiki", query=q)


def _get_wiki_page_details(c: ExampleClient, args: dict) -> dict:
    pid = page_id(args.get("page_id"))
    # TODO: call your vendor API: one page by id; 404 -> not_found. Body to plain text capped at MAX_PAGE_CHARS.
    return not_implemented("get_wiki_page_details", page_id=pid)


_DISPATCH: dict[str, Callable[[ExampleClient, dict], dict]] = {
    "search_tickets": _search_tickets,
    "get_ticket_details": _get_ticket_details,
    "search_wiki": _search_wiki,
    "get_wiki_page_details": _get_wiki_page_details,
}
assert frozenset(_DISPATCH) == TOOL_NAMES


def run_tool(client: ExampleClient | None, name: str, args: Any, **ctx: Any) -> dict:
    """Run one tool. Never raises; always returns a JSON-serialisable dict with `status`."""
    fn = _DISPATCH.get(name) if isinstance(name, str) else None
    try:
        if fn is None:
            result = {"status": "error", "error_kind": "UNKNOWN_TOOL",
                      "message": f"Unknown tool {str(name)[:80]!r}. Available: {', '.join(_DISPATCH)}."}
        elif not isinstance(args, dict):
            result = invalid("Tool input must be a JSON object.").result
        else:
            result = fn(client, args)
            if client is None:
                result = {"status": "error", "message": "Ticketing is not configured on this host.",
                          "next_step": "Say the ticket/wiki lookup is unavailable; never invent results."}
    except ToolError as e:
        result = e.result
    except Exception as e:  # noqa: BLE001 - run_tool must never raise
        log.warning("ticketing tool %s failed internally: %s", name, type(e).__name__)
        result = {"status": "error", "error_kind": "UNKNOWN", "message": f"Internal tool error ({type(e).__name__}).",
                  "next_step": "Say the lookup failed; a failure is not 'nothing found'."}
    return result
