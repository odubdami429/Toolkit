"""Brand protection: EXAMPLE read adapter (skeleton).

Implements the read interface from ``providers/__init__.py`` against ``contract.TOOLS``. Generic input validation is
real, including the scan-URL guardrails (``contract.check_scan_url``); every vendor call is a stub returning
``status: not_implemented``. Copy this file to ``<your_product>.py`` and replace each ``# TODO: call your vendor API``.

Settings read here: ``BRAND_PROTECTION_BASE_URL``, ``BRAND_PROTECTION_CONSOLE_URL`` (alert links), and credentials
``BRAND_PROTECTION_API_TOKEN`` or ``BRAND_PROTECTION_CLIENT_ID`` + ``BRAND_PROTECTION_CLIENT_SECRET`` /
``BRAND_PROTECTION_PRIVATE_KEY_B64``.

Dependencies: ``org`` and the standard library. Target: Python 3.12.
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime
from typing import Any, Callable, Mapping

import org
from providers.brand_protection import contract

log = logging.getLogger(__name__)

TOOLS = contract.TOOLS
TOOL_NAMES = contract.TOOL_NAMES

NOT_IMPLEMENTED_NEXT_STEP = "Say this lookup isn't implemented in this deployment; never invent results."
CONSOLE_HOST = contract.console_host(os.environ.get(f"{contract.PREFIX}_CONSOLE_URL"))
_SCAN_ID_RE = re.compile(contract.SCAN_ID)


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
            "message": f"{name} is not implemented by the example brand protection adapter.",
            "next_step": NOT_IMPLEMENTED_NEXT_STEP, **({"validated": echo} if echo else {})}


# --- client ----------------------------------------------------------------------------------------------------------

class ExampleClient:
    """Holds the tenant origin and credentials. A real adapter adds its HTTP client, token cache and request
    allowlist here (and shares this client with the writer so both use one cached token)."""

    def __init__(self, base_url: str, credentials: dict[str, str]):
        self.base_url = base_url
        self.__credentials = dict(credentials)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(base={self.base_url!r}, credentials=<redacted>)"

    __str__ = __repr__

    def _secrets_for_scrub(self) -> list[str]:
        return [v for v in self.__credentials.values() if v]

    # TODO: call your vendor API. One `_request` with an exact (method, path, query keys, body shape) allowlist checked
    # before network I/O, no redirects, a body-size cap; mint and cache tokens with a cooldown after a failed mint.


def credentials_from_env(env: Mapping[str, str], prefix: str) -> dict[str, str] | None:
    get = lambda k: str(env.get(f"{prefix}_{k}", "") or "").strip()  # noqa: E731
    if get("API_TOKEN"):
        return {"api_token": get("API_TOKEN"), "username": get("USERNAME")}
    if get("CLIENT_ID") and (get("CLIENT_SECRET") or get("PRIVATE_KEY_B64")):
        return {"client_id": get("CLIENT_ID"), "client_secret": get("CLIENT_SECRET"),
                "key_id": get("KEY_ID"), "private_key_b64": get("PRIVATE_KEY_B64")}
    return None


def client_from_env(env: Mapping[str, str]) -> ExampleClient | None:
    """A client when BRAND_PROTECTION_BASE_URL and credentials are set, else None. Never raises."""
    try:
        base = org.base_url(f"{contract.PREFIX}_BASE_URL", env=env)
    except ValueError:
        log.warning("%s_BASE_URL is not a bare https origin", contract.PREFIX)
        return None
    creds = credentials_from_env(env, contract.PREFIX)
    return ExampleClient(base, creds) if base and creds else None


# --- shared input checks ---------------------------------------------------------------------------------------------

def strip(raw: Any) -> str:
    s = re.sub(r"^[<(\"'`\s]+", "", str(raw).strip())
    return re.sub(r"[>)\"'`\s.,;!]+$", "", s)


def alert_id(raw: Any) -> str:
    """One alert id (ORG-NUMBER), or the id at the end of a console link."""
    if raw is None or raw == "":
        raise invalid("`alert_id` is required: an alert id such as ABC-9067, or its console link.")
    if isinstance(raw, (list, dict)):
        raise invalid("`alert_id` takes one alert id. Call the tool once per alert.")
    s = strip(raw)
    if "," in s:
        raise invalid("`alert_id` takes one alert id. Call the tool once per alert.")
    if re.match(r"(?i)https?://", s):
        host = contract.console_host(s)
        aid = contract.extract_alert_id(s)
        if not (CONSOLE_HOST and host == CONSOLE_HOST and aid):
            raise invalid(f"'{s[:120]}' is a URL, not an alert id or an alert console link. Pass the alert id (e.g. "
                          "ABC-9067); to look up alerts about a domain or URL, use brand_search_alerts `search_key`.")
        s = aid
    s = s.upper()
    if not contract.AUTO_ID_SHAPE.fullmatch(s):
        raise invalid(f"'{s[:60]}' is not an alert id. Alert ids look like ABC-9067.")
    if re.fullmatch(r"[A-Z]+-(0+|1234|12345)", s):
        raise invalid(f"'{s}' looks like a placeholder. Pass the real alert id; never invent one.")
    return s


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


def enum_list(args: dict, name: str, allowed: tuple[str, ...], *, single: bool = False) -> list[str] | None:
    raw = args.get(name)
    if raw is None or raw == "" or raw == []:
        return None
    items = raw if isinstance(raw, list) else re.split(r"[,\s]+", str(raw))
    vals = []
    for v in (str(i).strip().lower() for i in items):
        if not v:
            continue
        if v not in allowed:
            raise invalid(f"`{name}` '{v[:40]}' is not one of: {', '.join(allowed)}.")
        if v not in vals:
            vals.append(v)
    if single and len(vals) > 1:
        raise invalid(f"`{name}` takes one value.")
    return vals or None


def iso_date(args: dict, name: str) -> str | None:
    raw = args.get(name)
    if raw is None or raw == "":
        return None
    s = str(raw).strip()
    try:
        datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        raise invalid(f"`{name}` must be an ISO date or date-time (UTC), e.g. 2026-11-10.") from None
    return s


def text(args: dict, name: str, max_len: int = 300) -> str | None:
    raw = args.get(name)
    if raw is None or raw == "":
        return None
    if isinstance(raw, (list, dict, bool)):
        raise invalid(f"`{name}` takes a single string.")
    s = str(raw).strip()
    if len(s) > max_len:
        raise invalid(f"`{name}` is {len(s)} characters (max {max_len}).")
    return s or None


def scan_url(raw: Any, label: str) -> str:
    try:
        return contract.check_scan_url(raw, label)
    except contract.ScanUrlRejected as e:
        if e.status == "refused":
            raise refused(str(e), "Relay this; don't retry with another URL.") from None
        raise invalid(str(e)) from None


# --- per-tool validation ---------------------------------------------------------------------------------------------

def validate_search(args: dict) -> dict:
    sort = str(args.get("sort") or "newest").strip().lower()
    if sort not in contract.SORTS:
        raise invalid(f"`sort` must be one of: {', '.join(contract.SORTS)}.")
    created_after = iso_date(args, "created_after")
    lookback = args.get("lookback_days")
    return {"search_key": text(args, "search_key"), "search": text(args, "search"),
            "queue_state": enum_list(args, "queue_state", contract.QUEUE_STATES),
            "product": enum_list(args, "product", contract.PRODUCTS, single=True),
            "severity": enum_list(args, "severity", contract.SEVERITIES),
            "entity_state": enum_list(args, "entity_state", contract.ENTITY_STATES),
            "tags": text(args, "tags", 500), "created_after": created_after,
            "created_before": iso_date(args, "created_before"),
            "last_activity_after": iso_date(args, "last_activity_after"),
            "lookback_days": None if created_after or lookback in (None, "") else
            int_arg(args, "lookback_days", 7, 1, contract.MAX_LOOKBACK_DAYS),
            "sort": sort, "limit": int_arg(args, "limit", contract.DEFAULT_LIMIT, 1, contract.MAX_LIMIT),
            "page": int_arg(args, "page", 0, 0, contract.MAX_PAGE)}


def validate_submit_scan(args: dict) -> dict:
    url = scan_url(args.get("url"), "url")
    raw = args.get("associated_urls")
    items = raw if isinstance(raw, list) else re.split(r"[,\s]+", str(raw)) if raw not in (None, "") else []
    items = [i for i in items if str(i).strip()]
    if len(items) > contract.MAX_ASSOCIATED:
        raise invalid(f"`associated_urls` takes at most {contract.MAX_ASSOCIATED} URLs.")
    assoc: list[str] = []
    for i, u in enumerate(items):
        n = scan_url(u, f"associated_urls[{i}]")
        if n != url and n not in assoc:
            assoc.append(n)
    return {"url": url, "associated_urls": assoc}


def validate_scan_result(args: dict) -> dict:
    raw = args.get("scan_id")
    if raw is None or raw == "":
        raise invalid("`scan_id` is required: the id brand_submit_scan returned. It is not a URL.")
    if isinstance(raw, (list, dict, bool)):
        raise invalid("`scan_id` takes one scan id.")
    sid = strip(raw)
    if re.match(r"(?i)^[a-z][a-z0-9+.-]*://", sid) or re.match(r"(?i)^[a-z0-9-]+(\.[a-z0-9-]+)+(/|$)", sid):
        raise invalid("`scan_id` looks like a URL or domain. Call brand_submit_scan first and pass its scan_id.")
    if re.fullmatch(r"(?i)(scan[_-]?id|uuid|string|none|null|n/?a|todo|tbd|xxx+|\?+)", sid) or \
            re.fullmatch(r"(.)\1{7,}", sid.replace("-", "")):
        raise invalid(f"`scan_id` ('{sid[:40]}') is a placeholder. Pass the real scan_id; never invent one.")
    if not _SCAN_ID_RE.fullmatch(sid):
        raise invalid("`scan_id` must be 8-64 letters, digits, '.', '_' or '-'.")
    return {"scan_id": sid, "max_wait_seconds": int_arg(args, "max_wait_seconds", contract.DEFAULT_WAIT, 0,
                                                        contract.MAX_WAIT)}


# --- tools (stubs) ---------------------------------------------------------------------------------------------------

def _get_alert(c: ExampleClient, args: dict) -> dict:
    aid = alert_id(args.get("alert_id") if args.get("alert_id") not in (None, "") else args.get("id"))
    # TODO: call your vendor API: read the alert with its audit log. Guardrails: redact credential-looking fields
    # (dark-web leaks carry real passwords) by replacing them with their length; map states to contract.QUEUE_STATES.
    return not_implemented("brand_get_alert", alert_id=aid)


def _search_alerts(c: ExampleClient, args: dict) -> dict:
    v = validate_search(args)
    # TODO: call your vendor API: one page of alerts plus total_matching and a breakdown over the whole match.
    return not_implemented("brand_search_alerts", **v)


def _submit_scan(c: ExampleClient, args: dict) -> dict:
    v = validate_submit_scan(args)
    # TODO: call your vendor API: submit the normalised URL (and associated URLs); return status submitted + scan_id.
    return not_implemented("brand_submit_scan", **v)


def _get_scan_result(c: ExampleClient, args: dict) -> dict:
    v = validate_scan_result(args)
    # TODO: call your vendor API: poll until completed or max_wait_seconds; pending is never "clean". Redact
    # credential-looking fields in scan data.
    return not_implemented("brand_get_scan_result", **v)


_DISPATCH: dict[str, Callable[[ExampleClient, dict], dict]] = {
    "brand_get_alert": _get_alert,
    "brand_search_alerts": _search_alerts,
    "brand_submit_scan": _submit_scan,
    "brand_get_scan_result": _get_scan_result,
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
                result = {"status": "error", "message": "Brand protection is not configured on this host.",
                          "next_step": "Say the brand protection lookup is unavailable; never invent results."}
    except ToolError as e:
        result = e.result
    except Exception as e:  # noqa: BLE001 - run_tool must never raise
        log.warning("brand tool %s failed internally: %s", name, type(e).__name__)
        result = {"status": "error", "error_kind": "UNKNOWN", "message": f"Internal tool error ({type(e).__name__}).",
                  "next_step": "Say the lookup failed. A failure is not evidence either way."}
    return result
