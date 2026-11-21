"""Email security: EXAMPLE read adapter (skeleton).

Implements the read interface from ``providers/__init__.py`` against ``contract.TOOLS``:
``run_tool(client, name, args, requester="")`` (the server passes the verified requester, which message-content reads
require). Generic input validation is real; every vendor call is a stub returning ``status: not_implemented``. Copy this
file to ``<your_product>.py`` and replace each ``# TODO: call your vendor API``.

Settings read here: ``EMAIL_SECURITY_BASE_URL`` and credentials ``EMAIL_SECURITY_API_TOKEN`` or
``EMAIL_SECURITY_CLIENT_ID`` + ``EMAIL_SECURITY_CLIENT_SECRET`` / ``EMAIL_SECURITY_PRIVATE_KEY_B64``.

Dependencies: ``org`` and the standard library. Target: Python 3.12.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Callable, Mapping

import org
from providers.email_security import contract

log = logging.getLogger(__name__)

TOOLS = contract.TOOLS
TOOL_NAMES = contract.TOOL_NAMES

NOT_IMPLEMENTED_NEXT_STEP = "Say this lookup isn't implemented in this deployment; never invent results."
UUID_RE = re.compile(contract.UUID, re.I)
GROUP_RE = re.compile(contract.GROUP_ID)
EMAIL_RE = re.compile(r"[^@\s\"<>(),;:\\\[\]]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
                      r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+")
PLACEHOLDER = re.compile(r"(string|none|null|nil|n/?a|todo|tbd|unknown|undefined|id|message_id|uuid|email|sender|"
                         r"recipient|x{3,}|\?+|0{8}-0{4}-0{4}-0{4}-0{12})", re.I)
_PLACEHOLDER_JUSTIFICATION = re.compile(
    r"(test|testing|n/?a|none|asdf|todo|tbd|placeholder|because|review|reviewing|investigation)\.?", re.I)


class ToolError(Exception):
    def __init__(self, message: str, *, status: str = "error", next_step: str = "", **extra: Any):
        super().__init__(message)
        self.result = {"status": status, "message": message, **extra}
        if next_step:
            self.result["next_step"] = next_step


def invalid(message: str) -> ToolError:
    return ToolError(message, status="invalid_input",
                     next_step="Nothing was sent. Fix the input named in `message` and call again.")


def refused(message: str, next_step: str = "") -> ToolError:
    return ToolError(message, status="refused",
                     next_step=next_step or "A deliberate boundary; nothing was sent or changed. Report it and don't "
                                            "retry with altered inputs.")


def not_implemented(name: str, **echo: Any) -> dict:
    return {"status": "not_implemented", "tool": name,
            "message": f"{name} is not implemented by the example email security adapter.",
            "next_step": NOT_IMPLEMENTED_NEXT_STEP, **({"validated": echo} if echo else {})}


# --- client ----------------------------------------------------------------------------------------------------------

class ExampleClient:
    """Holds the tenant origin and credentials. A real adapter adds its HTTP client and request allowlist here."""

    def __init__(self, base_url: str, credentials: dict[str, str]):
        self.base_url = base_url
        self.__credentials = dict(credentials)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(base={self.base_url!r}, credentials=<redacted>)"

    __str__ = __repr__

    def _secrets_for_scrub(self) -> list[str]:
        return [v for v in self.__credentials.values() if v]

    # TODO: call your vendor API. One `_request` method with an exact (method, path, query keys, body shape)
    # allowlist checked before network I/O, no redirects, a body-size cap, and a single short 429 retry for GETs only.


def credentials_from_env(env: Mapping[str, str], prefix: str) -> dict[str, str] | None:
    get = lambda k: str(env.get(f"{prefix}_{k}", "") or "").strip()  # noqa: E731
    if get("API_TOKEN"):
        return {"api_token": get("API_TOKEN"), "username": get("USERNAME")}
    if get("CLIENT_ID") and (get("CLIENT_SECRET") or get("PRIVATE_KEY_B64")):
        return {"client_id": get("CLIENT_ID"), "client_secret": get("CLIENT_SECRET"),
                "key_id": get("KEY_ID"), "private_key_b64": get("PRIVATE_KEY_B64")}
    return None


def client_from_env(env: Mapping[str, str]) -> ExampleClient | None:
    """A client when EMAIL_SECURITY_BASE_URL and credentials are set, else None. Never raises."""
    try:
        base = org.base_url(f"{contract.PREFIX}_BASE_URL", env=env)
    except ValueError:
        log.warning("%s_BASE_URL is not a bare https origin", contract.PREFIX)
        return None
    creds = credentials_from_env(env, contract.PREFIX)
    return ExampleClient(base, creds) if base and creds else None


# --- shared input checks ---------------------------------------------------------------------------------------------

def first(args: dict, names: tuple[str, ...]) -> Any:
    for n in names:
        v = args.get(n)
        if v is not None and v != "":
            return v
    return None


def strip(raw: Any) -> str:
    s = re.sub(r"^[<(\"'`\s]+", "", str(raw).strip())
    s = re.sub(r"[>)\"'`\s.,;!]+$", "", s)
    return re.sub(r"^mailto:", "", s, flags=re.I)


def truthy(v: Any) -> bool:
    return v is True or str(v).strip().lower() in ("true", "1", "yes")


def message_id(raw: Any, label: str = "message_id") -> str:
    """One platform message id (a UUID), lowercased."""
    if raw is None or raw == "":
        raise invalid(f"`{label}` is required: the platform message id, a UUID from search results or the alert.")
    if isinstance(raw, (list, dict)):
        raise invalid(f"`{label}` takes one message id. Call the tool once per message.")
    s = strip(raw)
    if PLACEHOLDER.fullmatch(s):
        raise invalid(f"`{label}` is a placeholder ('{s[:40]}'). Pass the real message id; never invent one.")
    if UUID_RE.fullmatch(s):
        return s.lower()
    if "@" in s:
        raise invalid(f"'{s[:80]}' looks like an email address or an RFC Message-ID header, not a platform message "
                      "id. Find the message with email_search_messages and use one of its `message_ids`.")
    if GROUP_RE.fullmatch(s):
        raise invalid(f"'{s[:80]}' is not a message id (message ids are UUIDs); it may be a message GROUP id. Use one "
                      "of the group's `message_ids` from email_search_messages.")
    raise invalid(f"'{s[:80]}' is not a platform message id. Message ids are UUIDs.")


def int_arg(args: dict, name: str, default: int, lo: int, hi: int) -> int:
    raw = args.get(name)
    if raw is None or raw == "":
        return default
    if isinstance(raw, bool):
        raise invalid(f"`{name}` must be a number.")
    try:
        n = int(float(raw))
    except (TypeError, ValueError):
        raise invalid(f"`{name}` must be a number (got {str(raw)[:40]!r}).") from None
    return max(lo, min(hi, n))


def justification(args: dict, requester: str) -> str:
    j = args.get("justification")
    j = j.strip() if isinstance(j, str) else ""
    if len(j) < contract.MIN_JUSTIFICATION:
        raise invalid(f"`justification` is required (>= {contract.MIN_JUSTIFICATION} characters): why this message's "
                      "contents are being opened. It is recorded in the platform's access audit log.")
    if _PLACEHOLDER_JUSTIFICATION.fullmatch(j):
        raise invalid(f"`justification` ('{j}') is a placeholder. Say why this message is being opened.")
    if not requester:
        raise refused("No verified requester is bound to this request.",
                      "Say message contents can't be opened without a named requester.")
    return f"{j[:400]} (requested by {requester})"


# --- per-tool validation ---------------------------------------------------------------------------------------------

def validate_search(args: dict) -> dict:
    def text(names: tuple[str, ...], label: str, max_len: int) -> str | None:
        raw = first(args, names)
        if raw is None:
            return None
        if isinstance(raw, (list, dict, bool)):
            raise invalid(f"`{label}` takes a single string. Call the tool again for each value.")
        s = str(raw).strip().strip("\"'`")
        if not s:
            return None
        if label in ("sender", "recipient", "message_id_header") and PLACEHOLDER.fullmatch(s):
            raise invalid(f"`{label}` is a placeholder ('{s}'). Pass the real value or leave it out.")
        if len(s) > max_len:
            raise invalid(f"`{label}` is {len(s)} characters (max {max_len}).")
        return s

    filters: dict[str, str] = {}
    query = text(("query", "any"), "query", 200)
    for names, label, n in ((("sender", "from"), "sender", 320), (("subject",), "subject", 300),
                            (("recipient", "mailbox", "to"), "recipient", 320),
                            (("file_name", "attachment_name"), "file_name", 255),
                            (("message_id_header",), "message_id_header", 998),
                            (("attachment_hash", "hash"), "attachment_hash", 64)):
        v = text(names, label, n)
        if v:
            filters[label] = v
    if "message_id_header" in filters:
        filters["message_id_header"] = filters["message_id_header"].strip("<>").strip()
        if UUID_RE.fullmatch(filters["message_id_header"]):
            raise invalid("That is a platform message id, not an RFC Message-ID header. You already have the "
                          "message: call email_get_message_eml with it.")
    if "sender" in filters:
        filters["sender"] = re.sub(r"^mailto:", "", filters["sender"], flags=re.I)
    if "attachment_hash" in filters:
        h = filters["attachment_hash"].lower()
        if not re.fullmatch(r"[0-9a-f]+", h) or len(h) not in (32, 40, 64):
            raise invalid("`attachment_hash` must be hex: MD5 (32), SHA1 (40) or SHA256 (64).")
        filters["attachment_hash"] = h
    if query and filters:
        raise invalid(f"`query` (free text across all fields) can't be combined with {', '.join(filters)}. Use either "
                      "`query` alone or the specific fields.")
    directions: list[str] = []
    raw = first(args, ("direction",))
    if raw is not None:
        vals = raw if isinstance(raw, list) else re.split(r"[,\s]+", str(raw))
        for d in (str(v).strip().lower() for v in vals):
            if not d:
                continue
            if d in ("all", "any"):
                directions = []
                break
            if d not in contract.DIRECTIONS:
                raise invalid(f"`direction` '{d[:30]}' isn't a message direction. Use inbound, outbound or internal.")
            if d not in directions:
                directions.append(d)
    if query and directions:
        raise invalid("`query` (free text) can't be combined with `direction`. Drop one of them.")
    reported_only = truthy(args.get("reported_only"))
    if not filters and not query and not reported_only:
        raise invalid("Give at least one of sender, subject, recipient, file_name, attachment_hash, message_id_header "
                      "or query, or set reported_only to list user-reported mail. (`direction` narrows a search but "
                      "isn't enough on its own.)")
    return {"filters": filters, "query": query, "direction": directions, "reported_only": reported_only,
            "lookback_hours": int_arg(args, "lookback_hours", contract.DEFAULT_LOOKBACK, 1, contract.MAX_LOOKBACK),
            "limit": int_arg(args, "limit", contract.DEFAULT_LIMIT, 1, contract.MAX_LIMIT),
            "offset": int_arg(args, "offset", 0, 0, 100_000)}


def validate_action_status(args: dict) -> dict:
    task = group = None
    raw = first(args, ("task_id",))
    if raw is not None:
        s = strip(raw)
        if not UUID_RE.fullmatch(s):
            raise invalid(f"'{s[:60]}' is not a task id. Task ids are UUIDs that an accepted action returns.")
        task = s.lower()
    raw = first(args, ("group_id",))
    if raw is not None:
        s = strip(raw)
        if UUID_RE.fullmatch(s):
            raise invalid(f"'{s}' is a UUID: a message id or a task id, not a group id. Use `group_id` from "
                          "email_search_messages, or pass it as `task_id`.")
        if not GROUP_RE.fullmatch(s):
            raise invalid(f"'{s[:60]}' is not a message group id.")
        group = s
    if not task and not group:
        raise invalid("Give `task_id` to check whether one action finished, and/or `group_id` to list the manual-action "
                      "history of a message group.")
    return {"task_id": task, "group_id": group,
            "lookback_hours": int_arg(args, "lookback_hours", contract.DEFAULT_LOOKBACK, 1, contract.MAX_LOOKBACK),
            "limit": int_arg(args, "limit", contract.DEFAULT_LIMIT, 1, contract.MAX_LIMIT)}


# --- tools (stubs) ---------------------------------------------------------------------------------------------------

def _search_messages(c: ExampleClient, args: dict, requester: str) -> dict:
    v = validate_search(args)
    # TODO: call your vendor API: search message groups in the window; a full recipient address narrows each group to
    # that mailbox's copy. Return rows with message_ids for chaining and next_offset for paging.
    return not_implemented("email_search_messages", **v)


def _get_message_eml(c: ExampleClient, args: dict, requester: str) -> dict:
    mid = message_id(first(args, ("message_id", "id")))
    just = justification(args, requester)
    body = int_arg(args, "max_body_chars", contract.DEFAULT_BODY_CHARS, 500, contract.MAX_BODY_CHARS)
    raw_chars = int_arg(args, "max_raw_chars", contract.DEFAULT_RAW_CHARS, 1000, contract.MAX_RAW_CHARS)
    # TODO: call your vendor API: record the access justification first (if the platform requires one), then fetch the
    # metadata and the raw EML (size-capped) and parse it locally. Guardrails: never execute or render content; elide
    # base64 in raw excerpts; flag display/URL mismatches, IP hosts and punycode.
    return not_implemented("email_get_message_eml", message_id=mid, access_justification=just, max_body_chars=body,
                           include_raw=truthy(args.get("include_raw")), max_raw_chars=raw_chars)


def _get_analysis_report(c: ExampleClient, args: dict, requester: str) -> dict:
    mid = message_id(first(args, ("message_id", "id")))
    just = justification(args, requester)
    # TODO: call your vendor API: the platform's automated analysis of the message (justification first if the
    # platform counts the report as message contents). Normalise the verdict to contract.ANALYSIS_VERDICTS.
    return not_implemented("email_get_analysis_report", message_id=mid, access_justification=just)


def _get_action_status(c: ExampleClient, args: dict, requester: str) -> dict:
    v = validate_action_status(args)
    # TODO: call your vendor API: the task state (normalised to contract.TASK_STATES) and/or the group's manual-action
    # history with messages_affected.
    return not_implemented("email_get_action_status", **v)


_DISPATCH: dict[str, Callable[[ExampleClient, dict, str], dict]] = {
    "email_search_messages": _search_messages,
    "email_get_message_eml": _get_message_eml,
    "email_get_analysis_report": _get_analysis_report,
    "email_get_action_status": _get_action_status,
}
assert frozenset(_DISPATCH) == TOOL_NAMES


def run_tool(client: ExampleClient | None, name: str, args: Any, requester: str = "", **ctx: Any) -> dict:
    """Run one read tool. Never raises; always returns a JSON-serialisable dict with `status`."""
    fn = _DISPATCH.get(name) if isinstance(name, str) else None
    try:
        if fn is None:
            result = {"status": "error", "error_kind": "UNKNOWN_TOOL",
                      "message": f"Unknown tool {str(name)[:80]!r}. Available: {', '.join(_DISPATCH)}."}
        elif not isinstance(args, dict):
            result = invalid("Tool input must be a JSON object.").result
        else:
            result = fn(client, args, str(requester or "").strip()[:200])
            if client is None:
                result = {"status": "error", "message": "Email security is not configured on this host.",
                          "next_step": "Say the email security lookup is unavailable; never invent results."}
    except ToolError as e:
        result = e.result
    except Exception as e:  # noqa: BLE001 - run_tool must never raise
        log.warning("email tool %s failed internally: %s", name, type(e).__name__)
        result = {"status": "error", "error_kind": "UNKNOWN", "message": f"Internal tool error ({type(e).__name__}).",
                  "next_step": "Say the lookup failed. A failure is not evidence about the message."}
    return result
