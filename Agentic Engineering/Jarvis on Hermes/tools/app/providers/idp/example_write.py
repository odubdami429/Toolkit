"""Identity provider: EXAMPLE write adapter (skeleton).

Implements the write interface from ``providers/__init__.py``: ``WRITE_TOOLS`` (``idp_set_user_suspension``,
``idp_clear_user_sessions``), ``LIST_TOOLS`` (none), ``writer_from_env`` and ``run_write_tool``. No automatic actions in
this domain, so there are no auto hooks: alert-bot requests never get these tools.

Generic validation is real: a verified requester, one user per call by exact email or id (names refused), the action
whitelist with near-miss explanations, ``reason`` length and placeholders, and the refusals that can be decided from
the input alone (service accounts, the requester's own account). The vendor calls are stubs returning
``status: not_implemented`` with ``written: false``; each carries the guardrail checklist the real call must keep.

Dependencies: the standard library. Target: Python 3.12.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Callable, Mapping

from providers.idp import contract
from providers.idp import example as ex

log = logging.getLogger(__name__)

WRITE_TOOLS = contract.WRITE_TOOLS
LIST_TOOLS = contract.LIST_TOOLS
WRITE_TOOL_NAMES = contract.WRITE_TOOL_NAMES

NOT_IMPLEMENTED_NEXT_STEP = "Say this action isn't implemented in this deployment; nothing was changed."
_PROTECTED = re.compile(contract.PROTECTED_ACCOUNT_PATTERN, re.I)
_PLACEHOLDER_REASON = re.compile(r"(test|testing|n/?a|none|asdf|todo|tbd|placeholder|requested|as requested|"
                                 r"per request)\b", re.I)
_OPAQUE_ID = re.compile(r"[A-Za-z0-9_-]{6,64}", re.ASCII)


class ExampleWriter:
    """The writer: in a real adapter, the read client's credential with the lifecycle/session scopes added (or a
    separate credential), and its own request allowlist (whoami, user search, user read, the two change calls)."""

    def __init__(self, client: ex.ExampleClient):
        self._client = client

    def __repr__(self) -> str:
        return f"{type(self).__name__}(base={self._client.base_url!r}, credentials=<redacted>)"

    __str__ = __repr__

    def _secrets_for_scrub(self) -> list[str]:
        return self._client._secrets_for_scrub()


def writer_from_env(env: Mapping[str, str], client: Any = None) -> ExampleWriter | None:
    """The writer, or None when the read client (and so the org/credentials) isn't configured."""
    return ExampleWriter(client) if isinstance(client, ex.ExampleClient) else None


# --- input checks ----------------------------------------------------------------------------------------------------

def exact_user(args: dict) -> dict:
    """Exactly one user by exact email/login or opaque user id. Names are refused."""
    raw = ex.first(args, ("user", "email", "login", "user_id"))
    s = ex.subject(raw, "user")
    if ex.is_email(s):
        return {"subject": s.lower(), "lookup": "email"}
    if "@" not in s and not re.search(r"\s", s) and _OPAQUE_ID.fullmatch(s) and re.search(r"\d", s):
        return {"subject": s, "lookup": "id"}
    raise ex.invalid(f"'{s}' is not an email or user id. This tool changes an account, so it only accepts an exact "
                     "identifier: resolve the person with idp_get_user first and pass their email.")


def reason(args: dict, action: str) -> str:
    raw = ex.first(args, ("reason", "note", "justification"))
    r = raw.strip() if isinstance(raw, str) else ""
    if len(r) < contract.MIN_REASON:
        raise ex.invalid(f"`reason` is required (>= {contract.MIN_REASON} characters): why this account is being "
                         f"{action}, with a ticket or alert reference if there is one. It is the audit record.")
    if _PLACEHOLDER_REASON.match(r):
        raise ex.invalid("`reason` looks like a placeholder. Give the real reason: it is the audit record.")
    return r[:contract.MAX_REASON]


def action(args: dict) -> str:
    a = re.sub(r"[\s_]+", "-", str(args.get("action") or "").strip().lower())
    a = "unsuspend" if a == "un-suspend" else a
    if not a:
        raise ex.invalid(f"`action` is required: {' or '.join(contract.SUSPENSION_ACTIONS)}.")
    if a not in contract.SUSPENSION_ACTIONS:
        why = contract.NEAR_MISS_ACTIONS.get(a)
        raise ex.invalid(f"`action` '{a[:40]}' is not supported. This tool only does suspend and unsuspend."
                         f"{' ' + why if why else ''} Do that in the admin console.")
    return a


def requester_email(requester: str) -> str:
    m = re.search(r"[^\s()<>@]+@[^\s()<>@]+\.[A-Za-z]{2,}", requester or "")
    return m.group(0).lower() if m else ""


def refuse_protected(subject: str, what: str) -> None:
    """Service accounts are never acted on: integrations run as them."""
    if _PROTECTED.match(subject.split("@", 1)[0]):
        raise ex.refused(f"{subject} is a service account. {what} would break whatever integration runs as it; a "
                         "human must do that in the admin console. Nothing was changed.")


# --- tools (stubs) ---------------------------------------------------------------------------------------------------

def _set_user_suspension(w: ExampleWriter, args: dict, requester: str) -> dict:
    act = action(args)
    u = exact_user(args)
    r = reason(args, "suspended" if act == "suspend" else "unsuspended")
    if act == "suspend":
        refuse_protected(u["subject"], "Suspending it")
    if u["lookup"] == "email" and u["subject"] == requester_email(requester):
        raise ex.refused(f"{u['subject']} is the requester's own account. Jarvis won't change the suspension of the "
                         "account of the person asking; another authorized writer or the console must.")
    # TODO: call your vendor API. Checklist:
    # [ ] whoami: read the credential's own user; if unreadable, refuse (can't prove the target isn't it)
    # [ ] resolve through a search: exactly one exact match (id, login or email) else not_found / ambiguous
    # [ ] refuse: the credential's own account; service accounts (re-check on the resolved login); the requester's
    #     own account (re-check on the resolved login/email); administrators where the product reports them
    # [ ] transitions: suspend of suspended -> no_change; deprovisioned / staged / provisioned -> refused;
    #     unsuspend of deprovisioned -> refused (reactivation); unsuspend of anything but suspended -> no_change
    # [ ] one lifecycle call on the resolved id; connect error -> written false; timeout/5xx -> written null,
    #     outcome_unknown; 4xx -> written false with a hint; never retried
    # [ ] read the status back: suspended/unsuspended only when confirmed, else uncertain
    return {"status": "not_implemented", "tool": "idp_set_user_suspension",
            "message": "idp_set_user_suspension is not implemented by the example identity provider adapter. Nothing "
                       "was changed.", "next_step": NOT_IMPLEMENTED_NEXT_STEP,
            "validated": {"action": act, **u}, "written": False, "requested_by": requester, "reason": r}


def _clear_sessions(w: ExampleWriter, args: dict, requester: str) -> dict:
    u = exact_user(args)
    r = reason(args, "signed out")
    refuse_protected(u["subject"], "Clearing its sessions")
    revoke = args.get("revoke_oauth_tokens")
    revoke = True if revoke is None else (revoke is True or str(revoke).strip().lower() == "true")
    # TODO: call your vendor API. Checklist:
    # [ ] whoami + resolve exactly one user as for suspension; refuse the credential's own account and service
    #     accounts (re-checked on the resolved login)
    # [ ] one call clearing every session (and OAuth tokens when revoke_oauth_tokens); timeout/5xx -> outcome_unknown
    # [ ] confirmed_by: the audit-log event that records it (most products can't list sessions to read back)
    return {"status": "not_implemented", "tool": "idp_clear_user_sessions",
            "message": "idp_clear_user_sessions is not implemented by the example identity provider adapter. Nothing "
                       "was changed.", "next_step": NOT_IMPLEMENTED_NEXT_STEP,
            "validated": {**u, "revoke_oauth_tokens": revoke}, "written": False, "requested_by": requester,
            "reason": r}


_DISPATCH: dict[str, Callable[[ExampleWriter, dict, str], dict]] = {
    "idp_set_user_suspension": _set_user_suspension,
    "idp_clear_user_sessions": _clear_sessions,
}
assert frozenset(_DISPATCH) == WRITE_TOOL_NAMES


def run_write_tool(w: ExampleWriter | None, name: str, args: Any, requester: str) -> dict:
    """Run idp_set_user_suspension or idp_clear_user_sessions. Never raises. `requester` is the verified
    "email (U…)" string the server supplies; a `requested_by` argument from the model is ignored."""
    fn = _DISPATCH.get(name) if isinstance(name, str) else None
    requester = str(requester or "").strip()[:200] if isinstance(requester, str) else ""
    try:
        if fn is None:
            result = {"status": "error", "error_kind": "UNKNOWN_TOOL",
                      "message": f"Unknown tool {str(name)[:80]!r}. Available: {', '.join(_DISPATCH)}."}
        elif not requester:
            result = {"status": "refused", "message": "No verified requester was supplied, so the change can't be "
                                                      "attributed.",
                      "next_step": "Nothing was changed. Recommend the change instead."}
        elif not isinstance(args, dict):
            result = ex.invalid("Tool input must be a JSON object.").result
        else:
            args = {k: v for k, v in args.items() if k not in ("requested_by", "requestedBy", "requester")}
            result = fn(w, args, requester)
            if w is None and result.get("status") == "not_implemented":
                result = {"status": "error", "message": "Identity provider writes are not configured on this host.",
                          "next_step": "Recommend the change; an administrator can make it in the admin console."}
    except ex.ToolError as e:
        result = e.result
    except Exception as e:  # noqa: BLE001 - run_write_tool must never raise
        log.warning("idp write tool %s failed internally: %s", name, type(e).__name__)
        result = {"status": "error", "error_kind": "UNKNOWN", "message": f"Internal tool error ({type(e).__name__}).",
                  "next_step": "Say the tool failed; check the account's status with idp_get_user before saying "
                               "anything changed."}
    if name in WRITE_TOOL_NAMES:
        result.setdefault("written", False)
        result.setdefault("requested_by", requester or None)
    return result
