"""AI-tool entitlement check for the insider risk specialist: is an actor in one of the identity provider groups that
grant a sanctioned AI tool (the tools named in SANCTIONED_AI_TOOLS)?

Vendor-neutral: it works through the configured IdP adapter's ``user_groups(client, email)`` (see
``providers/__init__.py``), which resolves the user by exact email and returns their status and group names:

    {"status": "ok" | "not_found" | "error" | "ambiguous", "email": ..., "user_status": <provider status or None>,
     "groups": [group names], "truncated": bool, "message": optional str}

This module matches those names exactly against the sanctioned groups from the SANCTIONED_AI_GROUPS environment
variable (comma-separated); when it is empty every check is `unknown`. There is no model in the middle, so there is no
reply to misread or inject into, and only the account status and the matched sanctioned groups come back (none of the
user's other groups, apps or factors).

`result` is one of:
- `member`: the user resolved to exactly one account, it is ACTIVE, and at least one sanctioned group matched.
- `not_member`: the user resolved, is ACTIVE, and none of their groups is a sanctioned one.
- `unknown`: anything else (no such user, several users, not ACTIVE, group list truncated, IdP error, no sanctioned
  groups configured). Unknown is never treated as member.

Interface: ``TOOLS``, ``TOOL_NAMES``, ``run_tool(idp_module, idp_client, name, args)``.

Dependencies: org and the standard library. Target: Python 3.12.
"""

from __future__ import annotations

import json
import logging
import re
from types import ModuleType
from typing import Any

import org

log = logging.getLogger(__name__)

# Sanctioned AI-tool group names in the identity provider, matched exactly (case-sensitive). Fixed at startup.
SANCTIONED_GROUPS = org._csv(org._env("SANCTIONED_AI_GROUPS"))
ORG_DOMAIN = "@" + org.ORG_EMAIL_DOMAIN
ACTIVE_STATUSES = ("ACTIVE",)
_GROUPS_TEXT = ", ".join(SANCTIONED_GROUPS) if SANCTIONED_GROUPS else "none configured on this host"
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,6}", re.ASCII)

TOOL = {
    "name": "irm_check_ai_entitlement",
    "description": (
        f"Read-only identity provider check: is this {org.ORG_NAME} user entitled to a sanctioned AI tool? "
        f"Sanctioned AI tools here: {org.SANCTIONED_AI_TOOLS}. Resolves the user by exact email and checks membership "
        f"in the sanctioned AI-tool groups ({_GROUPS_TEXT}). Returns `result` member, not_member or unknown, the "
        "account status and the matched group names. Use it once per actor, only for a destination that is one of "
        "the sanctioned AI tools or a question about AI-tool entitlement. Unknown is never member."),
    "input_schema": {
        "type": "object",
        "properties": {"email": {"type": "string", "description": f"The actor's {ORG_DOMAIN} email."}},
        "required": ["email"],
    },
}
TOOLS = [TOOL]
TOOL_NAMES = frozenset({TOOL["name"]})


def _unknown(email: str, reason: str, *, status: str = "ok", account_status: Any = None) -> dict:
    return {"status": status, "email": email, "result": "unknown", "account_status": account_status,
            "matched_groups": [], "reason": reason, "sanctioned_groups": list(SANCTIONED_GROUPS)}


def _email(args: Any) -> str:
    raw = args.get("email") if isinstance(args, dict) else None
    return str(raw or "").strip().strip("<>").removeprefix("mailto:").lower()


def _check(idp: ModuleType, client: Any, args: Any) -> dict:
    email = _email(args)
    if not (_EMAIL_RE.fullmatch(email) and email.endswith(ORG_DOMAIN)):
        return _unknown(email, f"`email` must be the actor's {ORG_DOMAIN} address.", status="error")
    if not SANCTIONED_GROUPS:
        return _unknown(email, "No sanctioned AI-tool groups are configured on this host "
                               "(SANCTIONED_AI_GROUPS is empty), so entitlement cannot be determined.")
    r = idp.user_groups(client, email)
    r = r if isinstance(r, dict) else {"status": "error", "message": "unexpected identity provider answer"}
    kind, msg = r.get("status"), str(r.get("message") or "").strip()
    if kind == "not_found":
        return _unknown(email, "No identity provider user has this login or email.")
    if kind == "ambiguous":
        return _unknown(email, (msg + " " if msg else "") + "Several identity provider users match this email, so "
                        "membership is ambiguous.")
    if kind != "ok":
        return _unknown(email, f"Identity provider lookup failed: {msg or 'unknown error'}", status="error")
    status = r.get("user_status")
    if str(status or "").upper() not in ACTIVE_STATUSES:
        return _unknown(email, f"The identity provider account is {status}, not ACTIVE.", account_status=status)
    groups = [str(g) for g in (r.get("groups") or []) if g is not None]
    names = set(groups)
    matched = [g for g in SANCTIONED_GROUPS if g in names]
    if matched:
        return {"status": "ok", "email": email, "result": "member", "account_status": status,
                "matched_groups": matched, "reason": "Member of a sanctioned AI-tool group.",
                "sanctioned_groups": list(SANCTIONED_GROUPS)}
    if r.get("truncated"):
        return _unknown(email, f"The user has {len(groups)}+ groups and the list was cut off before a match.",
                        account_status=status)
    return {"status": "ok", "email": email, "result": "not_member", "account_status": status, "matched_groups": [],
            "reason": "Not in any sanctioned AI-tool group.", "sanctioned_groups": list(SANCTIONED_GROUPS)}


def _scrub(result: dict, client: Any) -> dict:
    """Last line of defence: no credential the IdP client holds ever reaches the output."""
    try:
        secrets = [s for s in client._secrets_for_scrub() if isinstance(s, str) and len(s) >= 6]
    except Exception:  # noqa: BLE001 - a client without the hook has nothing to scrub
        return result
    s = json.dumps(result, default=str)
    for sec in secrets:
        s = s.replace(json.dumps(sec)[1:-1], "[redacted]")
    return json.loads(s)


def run_tool(idp_module: ModuleType | None, idp_client: Any, name: str, args: Any) -> dict:
    """Run the entitlement check through the IdP adapter. Never raises; any failure is `result: unknown`."""
    if name not in TOOL_NAMES:
        return {"status": "error", "message": f"Unknown tool {name!r}.", "next_step": "Call an available tool."}
    email = _email(args)
    if idp_module is None or idp_client is None or not hasattr(idp_module, "user_groups"):
        result = _unknown(email, "The identity provider is not configured on this host.", status="error")
    else:
        try:
            result = _check(idp_module, idp_client, args)
        except Exception as e:  # noqa: BLE001 - run_tool must never raise
            log.warning("AI entitlement check failed internally: %s", type(e).__name__)
            result = _unknown(email, f"Internal error ({type(e).__name__}).", status="error")
    if result["status"] == "error":
        result["next_step"] = "Treat the entitlement as Unknown (never Member) and say why."
    return _scrub(result, idp_client)
