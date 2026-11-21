"""Identity provider: EXAMPLE read adapter (skeleton).

Implements the read interface from ``providers/__init__.py`` against ``contract.TOOLS``, plus ``user_groups(client,
email)`` for the AI-tool entitlement check. Generic input validation is real (required parameters, one subject per
call, placeholders, caps, the relative-window and scope rules, outcome/severity whitelists) so the contract tests
exercise it; every vendor call is a stub returning ``status: not_implemented`` (``user_groups``: ``status: error``,
``message: not implemented``). Copy this file to ``<your_product>.py``, replace each ``# TODO: call your vendor API``,
register it in ``providers/__init__.py`` and make the contract tests pass.

Settings read here: ``IDP_BASE_URL``, ``IDP_CONSOLE_URL`` (admin links) and credentials ``IDP_API_TOKEN`` or
``IDP_CLIENT_ID`` + ``IDP_CLIENT_SECRET`` / ``IDP_PRIVATE_KEY_B64`` (+ ``IDP_KEY_ID``).

Dependencies: ``org`` and the standard library. Target: Python 3.12.
"""

from __future__ import annotations

import ipaddress
import logging
import math
import re
from typing import Any, Callable, Mapping

import org
from providers.idp import contract

log = logging.getLogger(__name__)

TOOLS = contract.TOOLS
TOOL_NAMES = contract.TOOL_NAMES

NOT_IMPLEMENTED_NEXT_STEP = "Say this lookup isn't implemented in this deployment; never invent results."
_PLACEHOLDER = re.compile(r"(string|none|null|nil|n/?a|todo|tbd|unknown|undefined|user|username|email|group|app|"
                          r"example|test|foo|bar|x{3,}|\?+)", re.I)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}", re.ASCII)
_EVENT_TYPE = re.compile(r"[a-z][a-z0-9_]*(\.[a-z0-9_]+)+(\.\*)?|[a-z][a-z0-9_]*\.\*", re.ASCII)


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
                     next_step="A deliberate boundary; nothing was sent or changed. If the change is genuinely "
                               "intended, a human must make it in the admin console.")


def not_implemented(name: str, **echo: Any) -> dict:
    return {"status": "not_implemented", "tool": name,
            "message": f"{name} is not implemented by the example identity provider adapter.",
            "next_step": NOT_IMPLEMENTED_NEXT_STEP, **({"validated": echo} if echo else {})}


# --- client ----------------------------------------------------------------------------------------------------------

class ExampleClient:
    """Holds the org origin and credentials. A real adapter adds its HTTP client, token handling and allowlist."""

    def __init__(self, base_url: str, console_url: str, credentials: dict[str, str]):
        self.base_url = base_url
        self.console_url = console_url
        self.__credentials = dict(credentials)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(base={self.base_url!r}, credentials=<redacted>)"

    __str__ = __repr__

    def _secrets_for_scrub(self) -> list[str]:
        return [v for v in self.__credentials.values() if v]

    # TODO: call your vendor API. Implement ONE `_request(method, path, params)` that refuses anything not on an exact
    # allowlist of (method, path regex, query keys) BEFORE any network I/O (reads: users, groups, apps, audit log;
    # never administrator-role endpoints), never follows redirects, honours rate limits within the call budget, and
    # mints/caches OAuth tokens when a client id is configured.


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
    """A client when IDP_BASE_URL and credentials are set, else None. Never raises."""
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


def present(v: Any) -> bool:
    return v is not None and str(v).strip() != ""


def is_email(s: str) -> bool:
    return bool(_EMAIL_RE.fullmatch(s or ""))


def subject(raw: Any, label: str) -> str:
    """One user/group/app reference with Slack/ticket decoration stripped; refuses lists, placeholders and characters
    that would break out of a directory filter expression."""
    if raw is None or raw == "":
        raise invalid(f"`{label}` is required.")
    if isinstance(raw, (list, dict)):
        raise invalid(f"`{label}` takes a single value. Call the tool once per subject.")
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
    if re.search(r"[\"\\]", s):
        raise invalid(f"`{label}` contains a quote or backslash, which is not valid in an identifier.")
    if re.search(r"[\x00-\x1f\x7f]", s):
        raise invalid(f"`{label}` contains control characters.")
    return s


def clamp_num(args: dict, names: tuple[str, ...], default: float, lo: float, hi: float) -> float:
    raw = first(args, names)
    if raw is None:
        return default
    if isinstance(raw, bool):
        raise invalid(f"`{names[0]}` must be a number.")
    try:
        n = float(raw)
    except (TypeError, ValueError):
        raise invalid(f"`{names[0]}` must be a number (got {str(raw)[:40]!r}).") from None
    if math.isnan(n) or math.isinf(n):
        raise invalid(f"`{names[0]}` must be a finite number.")
    n = max(lo, min(hi, n))
    return int(n) if float(n).is_integer() else n


# --- per-tool validation ---------------------------------------------------------------------------------------------

def lookup_kind(s: str) -> str:
    if is_email(s):
        return "email"
    return "name" if re.search(r"\s", s) else "id_or_name"


def validate_get_user(args: dict) -> dict:
    s = subject(first(args, ("user", "email", "login", "user_id", "id")), "user")
    if "@" in s and not is_email(s):
        raise invalid(f"`user` '{s}' looks like an email address but isn't a complete one.")
    return {"subject": s, "lookup_kind": lookup_kind(s)}


def validate_get_group(args: dict) -> dict:
    s = subject(first(args, ("group", "name", "group_id", "id")), "group")
    if is_email(s):
        raise invalid(f"'{s}' is an email address, not a group name. Use idp_get_user to look up a person's groups.")
    return {"subject": s, "max_members": int(clamp_num(args, ("max_members",), contract.DEFAULT_GROUP_MEMBERS, 1,
                                                       contract.MAX_GROUP_MEMBERS))}


def validate_get_app(args: dict) -> dict:
    s = subject(first(args, ("app", "label", "app_id", "id")), "app")
    if is_email(s):
        raise invalid(f"'{s}' is an email address, not an application. Use idp_get_user for a person's apps.")
    return {"subject": s, "max_users": int(clamp_num(args, ("max_users",), contract.DEFAULT_APP_USERS, 1,
                                                     contract.MAX_APP_USERS))}


def validate_search_logs(args: dict) -> dict:
    for banned in contract.ABSOLUTE_TIME_PARAMS:
        if present(args.get(banned)):
            raise invalid(f"`{banned}` is not a parameter of this tool. Time is always relative: use `lookback_hours` "
                          "(and optionally `until_hours_ago`). Don't compute a date.")
    lookback = clamp_num(args, ("lookback_hours", "hours"), contract.DEFAULT_LOG_LOOKBACK_H, 1,
                         contract.MAX_LOG_LOOKBACK_H)
    until = clamp_num(args, ("until_hours_ago",), 0, 0, contract.MAX_LOG_LOOKBACK_H)
    if until >= lookback:
        raise invalid(f"`until_hours_ago` ({until}) must be smaller than `lookback_hours` ({lookback}). lookback_hours "
                      "is where the window STARTS, until_hours_ago is where it ENDS.")
    raw_user = first(args, ("user", "email", "actor", "login"))
    user = subject(raw_user, "user") if present(raw_user) else None
    raw_types = first(args, ("event_types", "event_type"))
    types = raw_types if isinstance(raw_types, list) else (str(raw_types).split(",") if present(raw_types) else [])
    event_types = [t for t in (str(x).strip() for x in types) if t]
    if len(event_types) > contract.MAX_EVENT_TYPES:
        raise invalid(f"`event_types` has {len(event_types)} entries (max {contract.MAX_EVENT_TYPES}). Use a prefix "
                      "such as 'user.session.*'.")
    for t in event_types:
        if not _EVENT_TYPE.fullmatch(t):
            raise invalid(f"'{t[:80]}' is not a valid event type: dotted lowercase, e.g. 'user.session.start'; a "
                          "trailing '.*' is a prefix match. An unknown event type silently returns ZERO events, so a "
                          "guess looks exactly like a clean result.")
    outcome = str(first(args, ("outcome", "result")) or "").strip().lower() or None
    if outcome and outcome not in contract.LOG_OUTCOMES:
        raise invalid(f"`outcome` '{outcome[:40]}' is not valid. Use one of: {', '.join(contract.LOG_OUTCOMES)}.")
    severity = str(args.get("severity") or "").strip().lower() or None
    if severity and severity not in contract.LOG_SEVERITIES:
        raise invalid(f"`severity` '{severity[:40]}' is not valid. Use one of: {', '.join(contract.LOG_SEVERITIES)}.")
    ip = first(args, ("ip", "ip_address"))
    if present(ip):
        ip = str(ip).strip().replace("[.]", ".")
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            raise invalid(f"`ip` '{ip[:60]}' is not a single IPv4/IPv6 address. CIDR ranges aren't supported.") \
                from None
    else:
        ip = None
    q = first(args, ("q", "query", "search"))
    q = str(q).strip() if present(q) else None
    if q and len(q) > contract.MAX_LOG_Q:
        raise invalid(f"`q` is {len(q)} characters (max {contract.MAX_LOG_Q}).")
    if lookback - until > contract.UNSCOPED_MAX_LOOKBACK_H and not (user or event_types or ip or q):
        raise invalid(f"A window over {contract.UNSCOPED_MAX_LOOKBACK_H} hours needs a scope: `user`, `event_types`, "
                      "`ip` or `q`.")
    return {"lookback_hours": lookback, "until_hours_ago": until, "user": user, "event_types": event_types,
            "outcome": outcome, "severity": severity, "ip": ip, "q": q,
            "limit": int(clamp_num(args, ("limit",), contract.DEFAULT_LOG_PAGE, 1, contract.MAX_LOG_PAGE)),
            "max_events": int(clamp_num(args, ("max_events",), contract.DEFAULT_LOG_EVENTS, 0,
                                        contract.MAX_LOG_EVENTS))}


# --- tools (stubs) ---------------------------------------------------------------------------------------------------

def _get_user(c: ExampleClient, args: dict) -> dict:
    v = validate_get_user(args)
    # TODO: call your vendor API: resolve through a search/list endpoint (exact id, exact login-or-email, or name
    # prefix); several -> ambiguous with candidates; none -> not_found. Then groups, app assignments and MFA factors.
    # Map statuses to contract.USER_STATUSES and build `signals` and admin_url (IDP_CONSOLE_URL).
    return not_implemented("idp_get_user", **v)


def _get_group(c: ExampleClient, args: dict) -> dict:
    v = validate_get_group(args)
    # TODO: call your vendor API: resolve the group (exact id or name contains-match; several -> ambiguous), then the
    # TRUE member and app counts and a capped member list.
    return not_implemented("idp_get_group", **v)


def _get_app(c: ExampleClient, args: dict) -> dict:
    v = validate_get_app(args)
    # TODO: call your vendor API: resolve the app by id or label, then its OAuth settings (redirect URIs), assigned
    # groups and users (direct vs group-inherited).
    return not_implemented("idp_get_app", **v)


def _search_logs(c: ExampleClient, args: dict) -> dict:
    v = validate_search_logs(args)
    # TODO: call your vendor API: resolve `user` to an id first (so target-side events match too), build the filter,
    # page through [now - lookback, now - until] up to contract.MAX_LOG_PAGES, aggregate over everything fetched and
    # list `max_events`. Guardrails: set counts.truncated when pages remain; a failure is `error`, never zero events.
    return not_implemented("idp_search_logs", **v)


_DISPATCH: dict[str, Callable[[ExampleClient, dict], dict]] = {
    "idp_get_user": _get_user,
    "idp_get_group": _get_group,
    "idp_get_app": _get_app,
    "idp_search_logs": _search_logs,
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
                result = {"status": "error", "message": "The identity provider is not configured on this host.",
                          "next_step": "Say the identity provider lookup is unavailable; never invent results."}
    except ToolError as e:
        result = e.result
    except Exception as e:  # noqa: BLE001 - run_tool must never raise
        log.warning("idp tool %s failed internally: %s", name, type(e).__name__)
        result = {"status": "error", "error_kind": "UNKNOWN", "message": f"Internal tool error ({type(e).__name__}).",
                  "next_step": "Do NOT report a result. Say the identity provider lookup failed."}
    return result


def user_groups(client: ExampleClient | None, email: str) -> dict:
    """Resolve ONE user by exact login/email and list their group names (see the contract). Never raises. The
    example validates the email and returns status error / "not implemented"."""
    e = str(email or "").strip().strip("<>").removeprefix("mailto:").lower()

    def out(status: str, message: str = "") -> dict:
        r = {"status": status, "email": e, "user_status": None, "groups": [], "truncated": False}
        if message:
            r["message"] = message
        return r

    try:
        if not is_email(e):
            return out("error", "`email` must be an exact email address.")
        # TODO: call your vendor API: search users by exact login OR email; none -> not_found; several -> ambiguous;
        # one -> list group names up to a cap (truncated=True when the cap was hit); user_status in USER_STATUSES.
        return out("error", "not implemented")
    except Exception as ex:  # noqa: BLE001 - must never raise
        return out("error", f"Internal error ({type(ex).__name__}).")
