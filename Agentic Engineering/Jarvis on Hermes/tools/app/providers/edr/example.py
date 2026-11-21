"""EDR: EXAMPLE read adapter (skeleton).

Implements the read interface from ``providers/__init__.py`` against ``contract.TOOLS``. Generic input validation is
real (required parameters, types, caps, one-value-per-call, time-window rules) so the contract tests exercise it;
every vendor call is a stub returning ``status: not_implemented``. Copy this file to ``<your_product>.py``, replace
each ``# TODO: call your vendor API`` with real calls, put your query-language primer in ``QUERY_PRIMER``, register the
adapter in ``providers/__init__.py`` and make the contract tests pass.

Settings read here: ``EDR_BASE_URL``, ``EDR_CONSOLE_URL`` (alert links), and credentials ``EDR_API_TOKEN`` or
``EDR_CLIENT_ID`` + ``EDR_CLIENT_SECRET`` / ``EDR_PRIVATE_KEY_B64``.

Dependencies: ``org`` and the standard library. Target: Python 3.12.
"""

from __future__ import annotations

import ipaddress
import logging
import math
import os
import re
from datetime import datetime
from typing import Any, Callable, Mapping

import org
from providers.edr import contract

log = logging.getLogger(__name__)

#: Replace with a short primer for your product's telemetry query language (syntax, common fields, an example).
QUERY_PRIMER = "(document your query syntax here)"

TOOLS = contract.with_primer(contract.TOOLS, "edr_query", QUERY_PRIMER)
TOOL_NAMES = contract.TOOL_NAMES

NOT_IMPLEMENTED_NEXT_STEP = "Say this lookup isn't implemented in this deployment; never invent results."
_HASH_RE = re.compile(r"[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}", re.ASCII)
_ISO_OFFSET = re.compile(r".*(?:Z|[+-]\d{2}:\d{2})", re.I | re.ASCII | re.S)
_CONSOLE_ID = contract.make_auto_id_pattern(os.environ.get(f"{contract.PREFIX}_CONSOLE_URL"))


class ToolError(Exception):
    """Raised by input checks; ``result`` is the dict returned to the model."""

    def __init__(self, message: str, *, status: str = "error", next_step: str = "", **extra: Any):
        super().__init__(message)
        self.result = {"status": status, "message": message, **extra}
        if next_step:
            self.result["next_step"] = next_step


def invalid(message: str) -> ToolError:
    return ToolError(message, status="invalid_input",
                     next_step="Nothing was sent. Fix the input named in `message` and call again.")


def not_implemented(name: str, **echo: Any) -> dict:
    return {"status": "not_implemented", "tool": name,
            "message": f"{name} is not implemented by the example EDR adapter.",
            "next_step": NOT_IMPLEMENTED_NEXT_STEP, **({"validated": echo} if echo else {})}


# --- client ----------------------------------------------------------------------------------------------------------

class ExampleClient:
    """Holds the tenant origin and credentials. A real adapter adds its HTTP client and request allowlist here."""

    def __init__(self, base_url: str, console_url: str, credentials: dict[str, str]):
        self.base_url = base_url
        self.console_url = console_url
        self.__credentials = dict(credentials)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(base={self.base_url!r}, credentials=<redacted>)"

    __str__ = __repr__

    def _secrets_for_scrub(self) -> list[str]:
        return [v for v in self.__credentials.values() if v]

    # TODO: call your vendor API. Implement ONE `_request(method, path, params, body)` that refuses anything not on an
    # exact allowlist of (method, path, query keys) BEFORE any network I/O, never follows redirects, caps the body
    # size, and logs only "METHOD /path -> status" (no headers, bodies or query values).


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
    """A client when EDR_BASE_URL and credentials are set, else None. Never raises."""
    try:
        base = org.base_url(f"{contract.PREFIX}_BASE_URL", env=env)
        console = org.base_url(f"{contract.PREFIX}_CONSOLE_URL", env=env)
    except ValueError:
        log.warning("%s_BASE_URL / %s_CONSOLE_URL is not a bare https origin", contract.PREFIX, contract.PREFIX)
        return None
    creds = credentials_from_env(env, contract.PREFIX)
    return ExampleClient(base, console, creds) if base and creds else None


# --- shared input checks ---------------------------------------------------------------------------------------------

def first(args: dict, names: tuple[str, ...]) -> Any:
    for n in names:
        v = args.get(n)
        if v is not None and v != "":
            return v
    return None


def text(v: Any) -> str:
    """A scalar as stripped text ("" for None, lists and objects)."""
    if v is None or isinstance(v, (list, dict, bool)):
        return ""
    return str(v).strip()


def truthy(v: Any) -> bool:
    return v is True or (isinstance(v, str) and v.strip().lower() == "true")


def number(args: dict, names: tuple[str, ...]) -> float | None:
    """A number parameter, None when absent. Refuses non-numbers."""
    raw = first(args, names)
    if raw is None:
        return None
    if isinstance(raw, bool):
        raise invalid(f"`{names[0]}` must be a number.")
    try:
        n = float(raw)
    except (TypeError, ValueError):
        raise invalid(f"`{names[0]}` must be a number (got {str(raw)[:40]!r}).") from None
    if math.isnan(n) or math.isinf(n):
        raise invalid(f"`{names[0]}` must be a finite number.")
    return n


def clamp_int(args: dict, names: tuple[str, ...], default: int, lo: int, hi: int) -> int:
    n = number(args, names)
    return default if n is None else int(max(lo, min(hi, n)))


def parse_iso(raw: Any, label: str) -> datetime:
    s = text(raw)
    if not _ISO_OFFSET.fullmatch(s) or s.endswith("\n"):
        raise invalid(f"`{label}` must include a timezone offset (Z or +HH:MM). Got: {s[:60]}")
    try:
        return datetime.fromisoformat(s.replace("z", "Z").replace("Z", "+00:00"))
    except ValueError:
        raise invalid(f"`{label}` is not valid ISO 8601: {s[:60]}") from None


# --- per-tool validation ---------------------------------------------------------------------------------------------

def parse_alert_ids(raw: Any) -> list[str]:
    """Alert IDs from a string (comma/space separated), a list, or console links to alerts."""
    items = raw if isinstance(raw, list) else re.split(r"[\s,;]+", text(raw))
    out: list[str] = []
    for item in items:
        s = text(item).strip("<>`\"'")
        if not s:
            continue
        if s.lower().startswith("https://"):
            m = _CONSOLE_ID.search(s)
            if not m:
                raise invalid(f"Not a link to an alert in this deployment's EDR console: {s[:120]}")
            s = m.group(1)
        if not contract.AUTO_ID_SHAPE.fullmatch(s):
            raise invalid(f"Not a valid alert ID or console link: {s[:120]}")
        out.append(s)
    return list(dict.fromkeys(out))


def validate_get_alert(args: dict) -> dict:
    ids = parse_alert_ids(args.get("threat_id")) if args.get("threat_id") not in (None, "", []) else []
    endpoint = text(args.get("endpoint_name"))
    file_hash = text(args.get("file_hash")).lower()
    name = text(args.get("threat_name"))
    if not (ids or endpoint or file_hash or name):
        raise invalid("Provide at least one of: threat_id (alert ID or console link), endpoint_name, file_hash, "
                      "threat_name.")
    if file_hash and not _HASH_RE.fullmatch(file_hash):
        raise invalid(f"`file_hash` must be a hex MD5, SHA1 or SHA256. Got: {file_hash[:80]}")
    for label, v in (("endpoint_name", endpoint), ("threat_name", name)):
        if len(v) > 200 or re.search(r"[\x00-\x1f]", v):
            raise invalid(f"`{label}` must be at most 200 printable characters.")
    lb = number(args, ("lookback_hours",))
    lookback = contract.DEFAULT_ALERT_LOOKBACK_H if lb is None or lb <= 0 else \
        min(max(lb, 0.25), contract.MAX_ALERT_LOOKBACK_H)
    return {"alert_ids": ids, "endpoint_name": endpoint or None, "file_hash": file_hash or None,
            "threat_name": name or None, "by_id": bool(ids), "lookback_hours": None if ids else lookback,
            "limit": clamp_int(args, ("limit",), contract.DEFAULT_ALERT_LIMIT, 1, contract.MAX_ALERT_LIMIT),
            "include_resolved": truthy(args.get("include_resolved")), "verbose": truthy(args.get("verbose"))}


def validate_list_open_alerts(args: dict) -> dict:
    order = text(args.get("order")).lower() or "attention"
    if order not in contract.OPEN_ALERT_ORDERS:
        raise invalid(f"`order` must be one of: {', '.join(contract.OPEN_ALERT_ORDERS)} (got {order[:40]!r}).")
    return {"list_limit": clamp_int(args, ("list_limit", "limit"), contract.DEFAULT_OPEN_LIST, 0,
                                    contract.MAX_OPEN_LIST), "order": order}


def validate_lookup_device(args: dict) -> dict:
    raw = first(args, ("query", "device", "endpoint", "hostname"))
    if isinstance(raw, list):
        if len(raw) != 1:
            raise invalid(f"One value per call (got {len(raw)}). Look devices up one at a time.")
        raw = raw[0]
    q = text(raw).strip("`\"'")
    if not q:
        raise invalid("`query` is required: a device ID, UUID, computer name (or part of one), serial, username or "
                      "email, or IPv4 address.")
    if re.search(r"[,;\n\r|]", q):
        raise invalid(f"`query` looks like a list ({q[:80]!r}). One value per call.")
    if re.search(r"[*%?]", q):
        raise invalid(f"`query` {q[:80]!r} contains a wildcard. Partial values already match; drop the wildcard.")
    if re.search(r"[\x00-\x1f\x7f]", q):
        raise invalid("`query` contains control characters.")
    if re.search(r"\u2026|\.\.\.$", q):
        raise invalid(f"`query` {q[:80]!r} looks truncated. Drop the ellipsis; partial values already match.")
    if not contract.MIN_DEVICE_QUERY <= len(q) <= contract.MAX_DEVICE_QUERY:
        raise invalid(f"`query` must be {contract.MIN_DEVICE_QUERY}-{contract.MAX_DEVICE_QUERY} characters.")
    mode = text(args.get("search_by")).lower() or "auto"
    if mode not in contract.DEVICE_SEARCH_BY:
        raise invalid(f"`search_by` must be one of: {', '.join(contract.DEVICE_SEARCH_BY)} (got {mode[:40]!r}).")
    if mode == "ip":
        try:
            if ipaddress.ip_address(q.replace("[.]", ".")).version != 4:
                raise ValueError
        except ValueError:
            raise invalid(f"{q[:80]!r} is not an IPv4 address.") from None
    if mode == "uuid" and not re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", q, re.I):
        raise invalid(f"{q[:80]!r} is not a UUID (32 hex characters, hyphens optional).")
    return {"query": q, "search_by": mode, "include_decommissioned": truthy(args.get("include_decommissioned")),
            "limit": clamp_int(args, ("limit",), contract.DEFAULT_DEVICE_LIMIT, 1, contract.MAX_DEVICE_LIMIT)}


def validate_query(args: dict) -> dict:
    q = args.get("query")
    if not isinstance(q, str) or not q.strip():
        raise invalid("`query` is required and must be a non-empty query string.")
    q = q.strip()
    if len(q) > contract.MAX_QUERY_CHARS:
        raise invalid(f"`query` is too long ({len(q)} characters, max {contract.MAX_QUERY_CHARS}).")
    rt = text(args.get("result_type")).lower() or "table"
    if rt not in contract.QUERY_RESULT_TYPES:
        raise invalid(f"`result_type` {rt[:40]!r} is not supported. Use 'table'.")
    lb = number(args, ("lookback_hours",))
    if lb is not None and lb > 0:
        window = {"lookback_hours": min(max(lb, contract.MIN_QUERY_LOOKBACK_H), contract.MAX_QUERY_LOOKBACK_H)}
    else:
        start = parse_iso(args["start_datetime"], "start_datetime") if args.get("start_datetime") else None
        end = parse_iso(args["end_datetime"], "end_datetime") if args.get("end_datetime") else None
        if start and end and start >= end:
            raise invalid("`start_datetime` must be earlier than `end_datetime`.")
        window = {"start_datetime": start.isoformat() if start else None,
                  "end_datetime": end.isoformat() if end else None,
                  "default_window_hours": contract.DEFAULT_QUERY_WINDOW_H}
    return {"query": q, **window, "result_type": rt,
            "max_rows": clamp_int(args, ("max_rows",), contract.DEFAULT_QUERY_ROWS, 1, contract.MAX_QUERY_ROWS)}


# --- tools (stubs) ---------------------------------------------------------------------------------------------------

def _get_alert(c: ExampleClient, args: dict) -> dict:
    v = validate_get_alert(args)
    # TODO: call your vendor API: alerts by ID (ignoring the window), or by the filters within [now - lookback, now],
    # open only unless include_resolved, newest first, `limit` rows. Map each record to the contract's neutral fields
    # (alert_id, console_url, file {...}, endpoint {...}, ...). Guardrails: the window comes from the server clock;
    # an empty answer is `not_found` with "do not retry the same filters"; an API failure is `error`, never
    # `not_found`.
    return not_implemented("edr_get_alert", **v)


def _list_open_alerts(c: ExampleClient, args: dict) -> dict:
    v = validate_list_open_alerts(args)
    # TODO: call your vendor API: open (new / in-progress) alerts in the requested order, up to a fetch cap; compute
    # the breakdowns over everything fetched and list `list_limit` of them. Guardrails: any failure is `error` with
    # "do NOT report the count as zero"; report `fetched` vs `total_open` when the fetch cap was hit.
    return not_implemented("edr_list_open_alerts", **v)


def _lookup_device(c: ExampleClient, args: dict) -> dict:
    v = validate_lookup_device(args)
    # TODO: call your vendor API: resolve `auto` by shape (device ID, UUID, IPv4, email/username, else name
    # substring); hide decommissioned devices unless asked; return the contract's neutral device fields.
    return not_implemented("edr_lookup_device", **v)


def _query(c: ExampleClient, args: dict) -> dict:
    v = validate_query(args)
    # TODO: call your vendor API: submit the query for the window (resolved on the server clock), poll until done
    # within a time budget, return columns/rows capped at max_rows. Guardrails: a query still running at the budget
    # is `status: timeout` (cancel it); a syntax/API error is `error` (NOT zero rows); never rewrite the user's query.
    return not_implemented("edr_query", **v)


_DISPATCH: dict[str, Callable[[ExampleClient, dict], dict]] = {
    "edr_get_alert": _get_alert,
    "edr_list_open_alerts": _list_open_alerts,
    "edr_lookup_device": _lookup_device,
    "edr_query": _query,
}
assert frozenset(_DISPATCH) == TOOL_NAMES


def run_tool(client: ExampleClient | None, name: str, args: Any, **ctx: Any) -> dict:
    """Run one read tool. Never raises; always returns a JSON-serialisable dict with `status`."""
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
                result = {"status": "error", "message": "The EDR is not configured on this host.",
                          "next_step": "Say the EDR lookup is unavailable; never invent results."}
    except ToolError as e:
        result = e.result
    except Exception as e:  # noqa: BLE001 - run_tool must never raise
        log.warning("edr tool %s failed internally: %s", name, type(e).__name__)
        result = {"status": "error", "error_kind": "UNKNOWN", "message": f"Internal tool error ({type(e).__name__}).",
                  "next_step": "Do NOT report a result. Say the EDR lookup failed and suggest the console."}
    return result
