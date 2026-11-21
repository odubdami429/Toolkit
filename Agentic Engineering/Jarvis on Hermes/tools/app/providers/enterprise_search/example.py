"""Enterprise search: EXAMPLE read adapter (skeleton).

Implements the read interface from ``providers/__init__.py`` against ``contract.TOOLS``, with the domain's extra
``act_as`` argument: ``run_tool(client, name, args, act_as)``. The act-as rule is real (no org-domain requester ->
``status: refused``), as is generic input validation (required fields, length caps, url-or-id); every vendor call is
a stub returning ``status: not_implemented``. Copy this file to ``<your_product>.py``, replace each
``# TODO: call your vendor API``, register it in ``providers/__init__.py`` and make the contract tests pass.

Settings read here: ``ENTERPRISE_SEARCH_BASE_URL``, ``ENTERPRISE_SEARCH_CONSOLE_URL`` and credentials
``ENTERPRISE_SEARCH_API_TOKEN`` or ``ENTERPRISE_SEARCH_CLIENT_ID`` + ``ENTERPRISE_SEARCH_CLIENT_SECRET``.

Dependencies: ``org`` and the standard library. Target: Python 3.12.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Mapping

import org
from providers.enterprise_search import contract

log = logging.getLogger(__name__)

TOOLS = contract.TOOLS
TOOL_NAMES = contract.TOOL_NAMES

NOT_IMPLEMENTED_NEXT_STEP = "Say this lookup isn't implemented in this deployment; never invent results."


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


def not_implemented(name: str, act_as: str, **echo: Any) -> dict:
    return {"status": "not_implemented", "tool": name, "acted_as": act_as,
            "message": f"{name} is not implemented by the example enterprise search adapter.",
            "next_step": NOT_IMPLEMENTED_NEXT_STEP, **({"validated": echo} if echo else {})}


# --- client ----------------------------------------------------------------------------------------------------------

class ExampleClient:
    """Holds the tenant origin and credentials. A real adapter adds its HTTP client and allowlist here."""

    def __init__(self, base_url: str, console_url: str, credentials: dict[str, str]):
        self.base_url = base_url
        self.console_url = console_url
        self.__credentials = dict(credentials)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(base={self.base_url!r}, credentials=<redacted>)"

    __str__ = __repr__

    def _secrets_for_scrub(self) -> list[str]:
        return [v for v in self.__credentials.values() if v]

    # TODO: call your vendor API. Implement ONE `_request(path, body, act_as)` that allows only the three fixed paths
    # (search, chat, read document), re-checks contract.may_act_as(act_as) and refuses otherwise BEFORE any network
    # I/O, sends the act-as identity the product's way, never follows redirects, and retries a short 429 at most once.


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
    """A client when ENTERPRISE_SEARCH_BASE_URL and credentials are set, else None. Never raises."""
    try:
        base = org.base_url(f"{contract.PREFIX}_BASE_URL", env=env)
        console = org.base_url(f"{contract.PREFIX}_CONSOLE_URL", env=env)
    except ValueError:
        log.warning("%s_BASE_URL / %s_CONSOLE_URL is not a bare https origin", contract.PREFIX, contract.PREFIX)
        return None
    creds = credentials_from_env(env, contract.PREFIX)
    return ExampleClient(base, console, creds) if base and creds else None


# --- input checks ----------------------------------------------------------------------------------------------------

def text_arg(args: dict, key: str, limit: int) -> str:
    v = args.get(key)
    if not isinstance(v, str) or not v.strip():
        raise invalid(f"`{key}` is required.")
    v = v.strip()
    if len(v) > limit:
        raise invalid(f"`{key}` is too long ({len(v)} characters, max {limit}).")
    return v


def document_spec(args: dict) -> dict:
    url, doc_id = args.get("url"), args.get("id")
    if isinstance(url, str) and url.strip().lower().startswith("https://"):
        if len(url.strip()) > contract.MAX_URL_CHARS:
            raise invalid(f"`url` is too long (max {contract.MAX_URL_CHARS} characters).")
        return {"url": url.strip()}
    if isinstance(doc_id, str) and doc_id.strip():
        if len(doc_id.strip()) > contract.MAX_ID_CHARS:
            raise invalid(f"`id` is too long (max {contract.MAX_ID_CHARS} characters).")
        return {"id": doc_id.strip()}
    raise invalid("Give `url` (an https link from a search result) or a document `id` from a result.")


# --- tools (stubs) ---------------------------------------------------------------------------------------------------

def _search(c: ExampleClient, args: dict, act_as: str) -> dict:
    q = text_arg(args, "query", contract.MAX_QUERY_CHARS)
    # TODO: call your vendor API as `act_as`: up to SEARCH_PAGE_SIZE results mapped to the contract fields; none ->
    # status no_results ("absence of internal context is itself a finding").
    return not_implemented("enterprise_search", act_as, query=q)


def _chat(c: ExampleClient, args: dict, act_as: str) -> dict:
    m = text_arg(args, "message", contract.MAX_CHAT_CHARS)
    # TODO: call your vendor API as `act_as`: one non-streaming, unsaved question; collect the answer text (capped)
    # and de-duplicated citations; an empty answer -> no_results.
    return not_implemented("enterprise_chat", act_as, message=m)


def _read_document(c: ExampleClient, args: dict, act_as: str) -> dict:
    spec = document_spec(args)
    # TODO: call your vendor API as `act_as`: one document by url or id with its content; missing or not visible ->
    # not_found ("don't guess its content"); content capped at MAX_DOC_CHARS.
    return not_implemented("enterprise_read_document", act_as, **spec)


_DISPATCH: dict[str, Callable[[ExampleClient, dict, str], dict]] = {
    "enterprise_search": _search,
    "enterprise_chat": _chat,
    "enterprise_read_document": _read_document,
}
assert frozenset(_DISPATCH) == TOOL_NAMES


def run_tool(client: ExampleClient | None, name: str, args: Any, act_as: str = "", **ctx: Any) -> dict:
    """Run one tool as `act_as` (the signed requester email). Never raises; always a dict with `status`."""
    fn = _DISPATCH.get(name) if isinstance(name, str) else None
    try:
        if fn is None:
            result = {"status": "error", "error_kind": "UNKNOWN_TOOL",
                      "message": f"Unknown tool {str(name)[:80]!r}. Available: {', '.join(_DISPATCH)}."}
        elif not isinstance(args, dict):
            result = invalid("Tool input must be a JSON object.").result
        elif not contract.may_act_as(act_as):
            result = {"status": "refused",
                      "message": f"Enterprise search acts as the requester and needs their {org.ORG_NAME} email "
                                 f"(@{org.ORG_EMAIL_DOMAIN}); none was verified for this request. Nothing was sent.",
                      "next_step": "Say enterprise search is unavailable for this request; never invent internal "
                                   "context."}
        else:
            result = fn(client, args, act_as)
            if client is None:
                result = {"status": "error", "message": "Enterprise search is not configured on this host.",
                          "next_step": "Say enterprise search is unavailable; never invent internal context."}
    except ToolError as e:
        result = e.result
    except Exception as e:  # noqa: BLE001 - run_tool must never raise
        log.warning("enterprise search tool %s failed internally: %s", name, type(e).__name__)
        result = {"status": "error", "error_kind": "UNKNOWN", "message": f"Internal tool error ({type(e).__name__}).",
                  "next_step": "Say the search failed; do not report a result."}
    return result
