"""Insider risk: EXAMPLE read adapter (skeleton).

Implements the read interface from ``providers/__init__.py`` against ``contract.TOOLS``. Generic input validation is
real; every vendor call is a stub returning ``status: not_implemented``. Copy this file to ``<your_product>.py`` and
replace each ``# TODO: call your vendor API``. ``irm_check_ai_entitlement`` is not part of this adapter (see
``ai_entitlement.py``).

Settings read here: ``INSIDER_RISK_BASE_URL``, ``INSIDER_RISK_CONSOLE_URL`` (alert links), and credentials
``INSIDER_RISK_API_TOKEN`` or ``INSIDER_RISK_CLIENT_ID`` + ``INSIDER_RISK_CLIENT_SECRET`` /
``INSIDER_RISK_PRIVATE_KEY_B64``.

Dependencies: ``org`` and the standard library. Target: Python 3.12.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Callable, Mapping

import org
from providers.insider_risk import contract

log = logging.getLogger(__name__)

TOOLS = contract.TOOLS
TOOL_NAMES = contract.TOOL_NAMES

NOT_IMPLEMENTED_NEXT_STEP = "Say this lookup isn't implemented in this deployment; never invent results."


def _console_origin() -> str:
    try:
        return org.base_url(f"{contract.PREFIX}_CONSOLE_URL")
    except ValueError:
        log.warning("%s_CONSOLE_URL is not a bare https origin; console links are off", contract.PREFIX)
        return ""


CONSOLE_URL = _console_origin()
CONSOLE_HOST = contract.console_host(CONSOLE_URL)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,6}")
_PLACEHOLDER_ID = re.compile(r"(?i)(session_?id|alert_?id|id|string|none|null|n/?a|todo|tbd|x{3,}|0{6,}|123456)")


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
            "message": f"{name} is not implemented by the example insider risk adapter.",
            "next_step": NOT_IMPLEMENTED_NEXT_STEP, **({"validated": echo} if echo else {})}


def console_url(session_id: str) -> str | None:
    """A console link for an alert. TODO: your console's alert route."""
    return f"{CONSOLE_URL}/alerts/{session_id}" if CONSOLE_URL else None


# --- client ----------------------------------------------------------------------------------------------------------

class ExampleClient:
    """Holds the tenant origin and credentials. A real adapter adds its HTTP client, token cache, a per-call request
    and time budget, and its request allowlist here (and shares this client with the writer)."""

    def __init__(self, base_url: str, credentials: dict[str, str]):
        self.base_url = base_url
        self.__credentials = dict(credentials)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(base={self.base_url!r}, credentials=<redacted>)"

    __str__ = __repr__

    def _secrets_for_scrub(self) -> list[str]:
        return [v for v in self.__credentials.values() if v]

    # TODO: call your vendor API. One `_request` with an exact (method, path, query keys, body shape) allowlist checked
    # before network I/O, no redirects, a body-size cap, a per-call request budget.


def credentials_from_env(env: Mapping[str, str], prefix: str) -> dict[str, str] | None:
    get = lambda k: str(env.get(f"{prefix}_{k}", "") or "").strip()  # noqa: E731
    if get("API_TOKEN"):
        return {"api_token": get("API_TOKEN"), "username": get("USERNAME")}
    if get("CLIENT_ID") and (get("CLIENT_SECRET") or get("PRIVATE_KEY_B64")):
        return {"client_id": get("CLIENT_ID"), "client_secret": get("CLIENT_SECRET"),
                "key_id": get("KEY_ID"), "private_key_b64": get("PRIVATE_KEY_B64")}
    return None


def client_from_env(env: Mapping[str, str]) -> ExampleClient | None:
    """A client when INSIDER_RISK_BASE_URL and credentials are set, else None. Never raises."""
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


def session_id(raw: Any, label: str = "session_id") -> str:
    """ONE alert id, or the id at the end of a console link. Lists and comma-separated ids are refused."""
    if raw is None or raw == "":
        raise invalid(f"`{label}` is required: one alert id or its console link.")
    if isinstance(raw, (list, tuple, dict)):
        raise invalid(f"`{label}` takes exactly one id. One alert per call, so each carries its own rationale.")
    s = re.sub(r"^[<(\"'`\s]+|[>)\"'`\s.,;!]+$", "", str(raw).strip())
    if re.search(r"[,\s]", s):
        raise invalid(f"`{label}` takes exactly one id. One alert per call, so each carries its own rationale.")
    if re.match(r"(?i)https?://", s):
        sid = contract.extract_session_id(s)
        if not (CONSOLE_HOST and contract.console_host(s) == CONSOLE_HOST and sid):
            raise invalid(f"'{s[:120]}' is not an alert console link. Pass the alert id.")
        s = sid
    if _PLACEHOLDER_ID.fullmatch(s):
        raise invalid(f"`{label}` is a placeholder ('{s[:40]}'). Pass the real alert id; never invent one.")
    if not contract.AUTO_ID_SHAPE.fullmatch(s):
        raise invalid(f"'{s[:80]}' is not an alert id (6-64 letters, digits, '_' or '-').")
    return s


def actor(args: dict) -> str | None:
    raw = first(args, ("actor", "email", "user"))
    if raw is None:
        return None
    if isinstance(raw, (list, dict, bool)):
        raise invalid("`actor` takes one email address. Call the tool once per person.")
    s = str(raw).strip().strip("<>").removeprefix("mailto:").lower()
    if "|" in s:
        s = s.split("|")[-1]
    if not _EMAIL_RE.fullmatch(s):
        raise invalid(f"`actor` '{s[:80]}' is not an email address. Pass the person's work email.")
    return s


def num(args: dict, name: str, default: int, lo: int, hi: int) -> int:
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


def id_list(args: dict, name: str) -> list[str] | None:
    raw = args.get(name)
    if raw is None or raw == "":
        return None
    items = raw if isinstance(raw, list) else str(raw).split(",")
    out = [str(i).strip() for i in items if str(i).strip()]
    for i in out:
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", i):
            raise invalid(f"`{name}` value '{i[:40]}' is not an id.")
    return out[:25] or None


# --- per-tool validation ---------------------------------------------------------------------------------------------

def validate_search_alerts(args: dict) -> dict:
    raw_state = str(args.get("state") or "unresolved").strip().lower()
    states: list[str] = []
    for s in (x.strip().replace(" ", "_") for x in raw_state.split(",")):
        if not s:
            continue
        if s in contract.STATE_SHORTCUTS:
            if len(raw_state.split(",")) > 1:
                raise invalid(f"`state` '{s}' can't be combined with other states.")
            states = [s]
            break
        if s not in contract.STATES:
            raise invalid(f"`state` '{s[:40]}' is not an alert state. Use {', '.join(contract.STATES)}, or 'all', "
                          "'unresolved', 'closed_all'.")
        states.append(s)
    sev = args.get("min_severity")
    min_sev = None
    if sev not in (None, ""):
        s = str(sev).strip().lower()
        if s.isdigit() and 0 <= int(s) <= 4:
            min_sev = int(s)
        elif s in contract.SEVERITY_NAMES:
            min_sev = contract.SEVERITY_NAMES[s]
        else:
            raise invalid("`min_severity` must be 0-4 or low, moderate, high, critical.")
    order = str(args.get("order_by") or "score").strip().lower()
    if order not in contract.ORDER_BY:
        raise invalid(f"`order_by` must be one of: {', '.join(contract.ORDER_BY)}.")
    return {"actor": actor(args), "state": states or ["unresolved"], "min_severity": min_sev,
            "lookback_hours": num(args, "lookback_hours", contract.DEFAULT_LOOKBACK, 1, contract.MAX_LOOKBACK),
            "rule_id": id_list(args, "rule_id"), "watchlist_id": id_list(args, "watchlist_id"), "order_by": order,
            "page_number": num(args, "page_number", 0, 0, contract.MAX_PAGE_NUMBER),
            "page_size": num(args, "page_size", contract.ALERTS_DEFAULT_PAGE, 1, contract.ALERTS_MAX_PAGE)}


def _filters(raw: Any) -> list[dict]:
    if raw is None or raw == "":
        return []
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            raise invalid("`filters` is not valid JSON: pass an array of {\"term\", \"operator\", \"value\"}.") \
                from None
    if not isinstance(raw, list):
        raise invalid("`filters` must be a JSON array of {\"term\", \"operator\", \"value\"}.")
    if len(raw) > contract.MAX_FILTERS:
        raise invalid(f"At most {contract.MAX_FILTERS} filters.")
    out = []
    for f in raw:
        f = f if isinstance(f, dict) else {}
        term = str(f.get("term") or "").strip()
        op = str(f.get("operator") or "").strip().upper()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.]{0,99}", term):
            raise invalid(f"Filter term '{term[:60]}' is not a field name.")
        if op not in contract.FILTER_OPERATORS:
            raise invalid(f"Filter operator '{op[:20]}' isn't supported. Use one of: "
                          f"{', '.join(contract.FILTER_OPERATORS)}.")
        val = f.get("value")
        if op not in ("EXISTS", "DOES_NOT_EXIST") and (val is None or str(val).strip() == ""):
            raise invalid(f"Filter '{term}' {op} needs a value.")
        if len(json.dumps(val, default=str)) > 2000:
            raise invalid(f"Filter value for '{term}' is too long.")
        out.append({"term": term, "operator": op, "value": val})
    return out


def validate_search_events(args: dict) -> dict:
    sev = args.get("min_risk_severity")
    min_sev = None
    if sev not in (None, ""):
        s = str(sev).strip().lower().replace(" ", "_")
        s = {"none": "no_risk_indicated", "no_risk": "no_risk_indicated", "medium": "moderate"}.get(s, s)
        if s not in contract.EVENT_SEVERITIES:
            raise invalid(f"`min_risk_severity` must be one of: {', '.join(contract.EVENT_SEVERITIES)}.")
        min_sev = s
    sha = args.get("sha256")
    if sha not in (None, ""):
        sha = str(sha).strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise invalid("`sha256` must be 64 hex characters.")
    else:
        sha = None
    text = {}
    for k in ("file_name", "file_category", "destination_category", "destination_name", "destination_domain",
              "event_action"):
        v = args.get(k)
        if v in (None, ""):
            continue
        if isinstance(v, (list, dict, bool)):
            raise invalid(f"`{k}` takes a single string; use `filters` with IS_ANY for several.")
        v = str(v).strip()
        if len(v) > 500:
            raise invalid(f"`{k}` is {len(v)} characters (max 500).")
        text[k] = v
    return {"actor": actor(args), **text, "sha256": sha, "min_risk_severity": min_sev,
            "lookback_hours": num(args, "lookback_hours", contract.DEFAULT_LOOKBACK, 1, contract.MAX_LOOKBACK),
            "untrusted_only": args.get("untrusted_only") in (True, "true", "True"),
            "page_size": num(args, "page_size", contract.EVENTS_DEFAULT_PAGE, 1, contract.EVENTS_MAX_PAGE),
            "filters": _filters(args.get("filters"))}


# --- tools (stubs) ---------------------------------------------------------------------------------------------------

def _search_alerts(c: ExampleClient, args: dict) -> dict:
    v = validate_search_alerts(args)
    # TODO: call your vendor API: resolve `actor` to the platform's actor id (report actor_resolution), then one page
    # of alerts. Map states to contract.STATES and severities to 0-4.
    return not_implemented("irm_search_alerts", **v)


def _get_alert(c: ExampleClient, args: dict) -> dict:
    sid = session_id(first(args, ("session_id", "alert_id", "id")))
    max_events = num(args, "max_events", contract.DEFAULT_EVENTS, 0, contract.MAX_EVENTS)
    # TODO: call your vendor API: the alert detail, its notes and the highest-risk file events (events_truncated when
    # cut). Include the console link.
    return not_implemented("irm_get_alert", session_id=sid, max_events=max_events, console_url=console_url(sid))


def _search_events(c: ExampleClient, args: dict) -> dict:
    v = validate_search_events(args)
    # TODO: call your vendor API: the file-event search, with the summary tallies over the whole page.
    return not_implemented("irm_search_events", **v)


_DISPATCH: dict[str, Callable[[ExampleClient, dict], dict]] = {
    "irm_search_alerts": _search_alerts,
    "irm_get_alert": _get_alert,
    "irm_search_events": _search_events,
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
                result = {"status": "error", "message": "Insider risk is not configured on this host.",
                          "next_step": "Say the insider risk lookup is unavailable; never invent results."}
    except ToolError as e:
        result = e.result
    except Exception as e:  # noqa: BLE001 - run_tool must never raise
        log.warning("irm tool %s failed internally: %s", name, type(e).__name__)
        result = {"status": "error", "error_kind": "UNKNOWN", "message": f"Internal tool error ({type(e).__name__}).",
                  "next_step": "Say the lookup failed. A failure is not evidence that nothing happened."}
    return result
