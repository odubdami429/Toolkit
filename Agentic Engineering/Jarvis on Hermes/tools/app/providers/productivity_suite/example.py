"""Productivity suite: EXAMPLE read adapter (skeleton).

Implements the read interface from ``providers/__init__.py`` against ``contract.TOOLS``. Generic input validation is
real (required parameters, types, caps, placeholders, the relative-window rules) so the contract tests exercise it;
every vendor call is a stub returning ``status: not_implemented``. Copy this file to ``<your_product>.py``, replace each
``# TODO: call your vendor API`` with real calls, register it in ``providers/__init__.py`` and make the contract tests
pass.

Settings read here: ``SUITE_BASE_URL`` and credentials ``SUITE_API_TOKEN`` or ``SUITE_CLIENT_ID`` +
``SUITE_CLIENT_SECRET`` / ``SUITE_PRIVATE_KEY_B64``.

Dependencies: ``org`` and the standard library. Target: Python 3.12.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from typing import Any, Callable, Mapping

import org
from providers.productivity_suite import contract

log = logging.getLogger(__name__)

TOOLS = contract.TOOLS
TOOL_NAMES = contract.TOOL_NAMES

NOT_IMPLEMENTED_NEXT_STEP = "Say this lookup isn't implemented in this deployment; never invent results."
_PLACEHOLDER = re.compile(r"(string|none|null|nil|n/?a|todo|tbd|unknown|undefined|user|username|email|the_user|"
                          r"example|test|foo|bar|x{3,}|\?+|.*@example\.(com|org|net))", re.I)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")


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


def refused(message: str) -> ToolError:
    return ToolError(message, status="refused",
                     next_step="A deliberate boundary; nothing was sent or changed. Report it and don't retry with "
                               "altered inputs.")


def not_implemented(name: str, **echo: Any) -> dict:
    return {"status": "not_implemented", "tool": name,
            "message": f"{name} is not implemented by the example productivity suite adapter.",
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

    # TODO: call your vendor API. Implement ONE `_request(method, path, params)` that refuses anything not on an exact
    # allowlist of (method, path regex, query keys) BEFORE any network I/O, never follows redirects, caps the body
    # size, and retries only a short 429 on a GET.


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
    """A client when SUITE_BASE_URL and credentials are set, else None. Never raises."""
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


def present(v: Any) -> bool:
    return v is not None and str(v).strip() != ""


def subject(raw: Any, label: str = "user") -> str:
    """One user reference (email or name) with Slack/ticket decoration stripped; refuses placeholders and
    metacharacters that could break out of a directory query or a request path."""
    if raw is None or raw == "":
        raise invalid(f"`{label}` is required.")
    if isinstance(raw, (list, dict)):
        raise invalid(f"`{label}` takes ONE value. Call the tool once per person, so each result is reported "
                      "separately.")
    if isinstance(raw, bool) or not isinstance(raw, (str, int, float)):
        raise invalid(f"`{label}` must be a string.")
    s = re.sub(r"^[<(\"'`\s]+", "", str(raw).strip())
    s = re.sub(r"[>)\"'`\s.,;!]+$", "", s)
    s = re.sub(r"^mailto:", "", s, flags=re.I)
    if "|" in s:  # Slack renders addresses as <mailto:x|x>
        s = s.split("|")[-1]
    if not s:
        raise invalid(f"`{label}` is empty.")
    if _PLACEHOLDER.fullmatch(s):
        raise invalid(f"`{label}` is a placeholder ('{s}'). Pass the real value; never invent one.")
    if len(s) > contract.MAX_SUBJECT:
        raise invalid(f"`{label}` is {len(s)} characters (max {contract.MAX_SUBJECT}).")
    if re.search(r"[\"'\\&#?+%]", s):
        raise invalid(f"`{label}` contains a quote, backslash, +, % or URL metacharacter ('{s}').")
    return s


def is_email(s: str) -> bool:
    return bool(_EMAIL_RE.fullmatch(s or ""))


def user_email(args: dict, label: str = "user") -> str:
    """Exactly one email address (the writes and suite_list_tokens take nothing else)."""
    u = subject(first(args, (label, "email", "user_email")), label)
    if not is_email(u):
        raise invalid(f"`{label}` '{u}' is not an email address. This tool only accepts an exact address: resolve the "
                      "person with suite_get_user first.")
    return u


def clamp_int(args: dict, names: tuple[str, ...], default: int, lo: int, hi: int) -> tuple[int, bool]:
    """(value clamped to [lo, hi], whether the input was above hi). Refuses non-numbers."""
    raw = first(args, names)
    if raw is None:
        return default, False
    if isinstance(raw, bool):
        raise invalid(f"`{names[0]}` must be a number.")
    try:
        n = int(float(raw))
    except (TypeError, ValueError):
        raise invalid(f"`{names[0]}` must be a number (got {str(raw)[:40]!r}).") from None
    return max(lo, min(hi, n)), n > hi


# --- per-tool validation ---------------------------------------------------------------------------------------------

def validate_get_user(args: dict) -> dict:
    s = subject(first(args, ("user", "email", "name", "user_email")))
    if is_email(s):
        return {"by": "email", "input": s}
    if "@" in s:
        raise invalid(f"`user` '{s}' looks like an email address but isn't a complete one. Pass the full address "
                      f"(name@{org.ORG_EMAIL_DOMAIN}).")
    words = s.split()
    if len(words) > 4:
        raise invalid("`user` has too many words to be a name. Pass an email or 'First Last'.")
    for w in words:
        if not re.fullmatch(r"[A-Za-z][A-Za-z\-]*", w):
            raise invalid(f"Name part '{w}' has characters a directory name search can't express (letters and "
                          "hyphens only). Look the person up by email instead.")
    return {"by": "name", "input": s}


def _filters(raw: Any) -> list[dict]:
    if isinstance(raw, str):
        txt = raw.strip()
        if not txt:
            return []
        if txt[0] not in "[{":
            raise invalid("`filters` must be structured: a list like [{\"parameter\":\"visibility\",\"operator\":"
                          "\"<>\",\"value\":\"private\"}] or an object like {\"app_name\":\"ExampleApp\"}.")
        try:
            raw = json.loads(txt)
        except ValueError:
            raise invalid("`filters` is not valid JSON.") from None
    if raw is None:
        return []
    if isinstance(raw, dict):
        flist = [{"parameter": k, "operator": "==", "value": v} for k, v in raw.items()]
    elif isinstance(raw, list):
        flist = raw
    else:
        raise invalid("`filters` must be a list or an object.")
    if len(flist) > contract.MAX_FILTERS:
        raise invalid(f"At most {contract.MAX_FILTERS} filters.")
    out = []
    for f in flist:
        f = f if isinstance(f, dict) else {}
        name = str(first(f, ("parameter", "param", "name", "key")) or "").strip()
        op = str(first(f, ("operator", "op")) or "==").strip()
        val = str(f.get("value") if f.get("value") is not None else "").strip()
        if not re.fullmatch(r"[a-z0-9_]{1,64}", name):
            raise invalid(f"Filter parameter '{name[:64]}' is not an event parameter name (lowercase word characters, "
                          "e.g. doc_id, visibility, app_name, client_id).")
        if op not in contract.FILTER_OPERATORS:
            raise invalid(f"Filter operator '{op[:10]}' isn't supported. Use one of: "
                          f"{' '.join(contract.FILTER_OPERATORS)}.")
        if not val:
            raise invalid(f"Filter '{name}' has no value.")
        if re.search(r"[,&#%+\"\\]", val) or len(val) > 200:
            raise invalid(f"Filter value for '{name}' has a character the filter syntax can't carry (, & # % + quote "
                          "backslash) or is over 200 characters. Use `match` instead.")
        out.append({"parameter": name, "operator": op, "value": val})
    return out


def validate_search_activity(args: dict) -> dict:
    app = str(first(args, ("application", "app", "log")) or "").strip().lower()
    app = contract.APPLICATION_ALIASES.get(app, app)
    if not app:
        raise invalid("`application` is required: which audit log to search. One of: "
                      f"{', '.join(contract.APPLICATIONS)}. Call once per application.")
    if app not in contract.APPLICATIONS:
        raise invalid(f"`application` '{app[:40]}' is not an audit application. Use one of: "
                      f"{', '.join(contract.APPLICATIONS)}.")
    for banned in contract.ABSOLUTE_TIME_PARAMS:
        if present(args.get(banned)):
            raise invalid(f"`{banned}` is not a parameter of this tool. Time is always relative: use `lookback_hours` "
                          "(and optionally `until_hours_ago`). Don't compute a date.")
    lookback, clamped = clamp_int(args, ("lookback_hours", "hours"), contract.DEFAULT_LOOKBACK_H, 1,
                                  contract.MAX_LOOKBACK_H)
    until, _ = clamp_int(args, ("until_hours_ago",), 0, 0, contract.MAX_LOOKBACK_H)
    if until >= lookback:
        raise invalid(f"`until_hours_ago` ({until}) must be smaller than `lookback_hours` ({lookback}). lookback_hours "
                      "is where the window STARTS, until_hours_ago is where it ENDS.")
    raw_user = first(args, ("user", "email", "actor", "user_email"))
    org_wide = not present(raw_user) or bool(
        re.fullmatch(r"all|\*|everyone|org|org-wide|all users", str(raw_user).strip(), re.I))
    user = None
    if not org_wide:
        user = subject(raw_user)
        if not is_email(user):
            raise invalid(f"`user` '{user}' is not an email address. Resolve the person to their "
                          f"@{org.ORG_EMAIL_DOMAIN} address first (suite_get_user accepts a name), or pass 'all'.")
    ev = first(args, ("event_name", "event"))
    if isinstance(ev, list):
        if len(ev) > 1:
            raise invalid("`event_name` takes ONE event name. Call the tool once per event name.")
        ev = ev[0] if ev else None
    event = None
    if present(ev):
        event = str(ev).strip()
        if re.search(r"[,\s]", event):
            raise invalid("`event_name` takes ONE event name. Call the tool once per event name.")
        if not re.fullmatch(r"[A-Za-z0-9_]{1,100}", event):
            raise invalid(f"`event_name` '{event[:60]}' is not an event name: word characters only, e.g. "
                          "login_success, suspicious_login, authorize, download.")
    ip = first(args, ("ip", "ip_address", "actor_ip"))
    if present(ip):
        ip = str(ip).strip().replace("[.]", ".")
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            raise invalid(f"`ip` '{ip[:60]}' is not a single IPv4/IPv6 address. CIDR ranges aren't supported.") \
                from None
    else:
        ip = None
    filters = _filters(first(args, ("filters", "filter")))
    match = first(args, ("match", "contains", "query"))
    match = str(match).strip().lower()[:contract.MAX_MATCH] if present(match) else None
    max_events, _ = clamp_int(args, ("max_events",), contract.DEFAULT_MAX_EVENTS, 0, contract.MAX_EVENTS)
    human_only = first(args, ("human_only",)) in (True, "true", "True")
    if org_wide and not (event or ip or filters) and lookback - until > contract.UNSCOPED_MAX_HOURS:
        raise invalid(f"An org-wide {app} search over {lookback - until} hours with no event_name, ip or filters "
                      "can't be read to the end. Add `user`, `event_name`, `ip` or `filters`, or keep the window to "
                      f"{contract.UNSCOPED_MAX_HOURS} hours.")
    return {"application": app, "user": user or "all", "lookback_hours": lookback, "until_hours_ago": until,
            "lookback_clamped": clamped, "event_name": event, "ip": ip, "filters": filters, "match": match,
            "human_only": human_only, "max_events": max_events}


# --- tools (stubs) ---------------------------------------------------------------------------------------------------

def _get_user(c: ExampleClient, args: dict) -> dict:
    v = validate_get_user(args)
    # TODO: call your vendor API: resolve by exact email (primary or alias) or a name prefix search capped at a few
    # candidates (several -> status ambiguous with candidates; none -> not_found). Return ONLY the allowlisted profile
    # fields named in the contract, plus `flags`. Guardrails: never return photos, phone lists, custom schemas or
    # password fields.
    return not_implemented("suite_get_user", **v)


def _search_activity(c: ExampleClient, args: dict) -> dict:
    v = validate_search_activity(args)
    # TODO: call your vendor API: one audit log, relative window [now - lookback_hours, now - until_hours_ago],
    # newest first, following pagination within a page and time budget. Guardrails: verify every returned row is
    # inside the window and carries the requested event (else the API ignored a parameter: return an error); dedupe;
    # compute aggregates over everything fetched; set counts.window_truncated when pages remain.
    return not_implemented("suite_search_activity", **v)


_DISPATCH: dict[str, Callable[[ExampleClient, dict], dict]] = {
    "suite_get_user": _get_user,
    "suite_search_activity": _search_activity,
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
                result = {"status": "error", "message": "The productivity suite is not configured on this host.",
                          "next_step": "Say the productivity suite lookup is unavailable; never invent results."}
    except ToolError as e:
        result = e.result
    except Exception as e:  # noqa: BLE001 - run_tool must never raise
        log.warning("suite tool %s failed internally: %s", name, type(e).__name__)
        result = {"status": "error", "error_kind": "UNKNOWN", "message": f"Internal tool error ({type(e).__name__}).",
                  "next_step": "Say the lookup failed. A failure is not evidence about the user."}
    return result
