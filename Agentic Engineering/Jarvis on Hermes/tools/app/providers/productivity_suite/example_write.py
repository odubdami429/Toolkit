"""Productivity suite: EXAMPLE write adapter (skeleton).

Implements the write interface from ``providers/__init__.py``: ``WRITE_TOOLS``, ``LIST_TOOLS`` (``suite_list_tokens``,
a read that needs the writer's user-security credential), ``writer_from_env`` and ``run_write_tool``. No automatic
actions in this domain, so there are no auto hooks: alert-bot requests never get these tools.

Generic validation is real: a verified requester for writes, one user per call, exact email, ``reason`` length and
placeholders, the service-account and org-wide-app refusals. The vendor calls are stubs returning
``status: not_implemented`` with ``written: false``.

Settings read here: ``SUITE_ORG_WIDE_APPS`` (comma-separated app names or client ids granted org-wide by an
administrator; never revoked per user).

Dependencies: ``org`` and the standard library. Target: Python 3.12.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Callable, Mapping

import org
from providers.productivity_suite import contract
from providers.productivity_suite import example as ex

log = logging.getLogger(__name__)

WRITE_TOOLS = contract.WRITE_TOOLS
LIST_TOOLS = contract.LIST_TOOLS
WRITE_TOOL_NAMES = contract.WRITE_TOOL_NAMES
LIST_TOOL_NAMES = contract.LIST_TOOL_NAMES

_PROTECTED = re.compile(contract.PROTECTED_ACCOUNT_PATTERN, re.I)
_PLACEHOLDER_REASON = re.compile(r"(test|testing|n/?a|none|asdf|todo|tbd|placeholder|requested|as requested|"
                                 r"per request)\b", re.I)


class ExampleWriter:
    """The writer: in a real adapter, a SEPARATE client whose credential carries the user-security scope (the read
    client must never carry it)."""

    def __init__(self, client: ex.ExampleClient, org_wide_apps: frozenset[str]):
        self._client = client
        self.org_wide_apps = org_wide_apps
        self.subject = None  # the admin identity the writes run as, when the product uses delegation

    def __repr__(self) -> str:
        return f"{type(self).__name__}(base={self._client.base_url!r}, credentials=<redacted>)"

    __str__ = __repr__

    def _secrets_for_scrub(self) -> list[str]:
        return self._client._secrets_for_scrub()


def writer_from_env(env: Mapping[str, str], client: Any = None) -> ExampleWriter | None:
    """The writer, or None when the read client (and so the tenant/credentials) isn't configured."""
    if not isinstance(client, ex.ExampleClient):
        return None
    apps = frozenset(a.lower() for a in org._csv(str(env.get(f"{contract.PREFIX}_ORG_WIDE_APPS", ""))))
    return ExampleWriter(client, apps)


# --- input checks ----------------------------------------------------------------------------------------------------

def _reason(args: dict, action: str) -> str:
    raw = ex.first(args, ("reason", "note", "justification"))
    reason = raw.strip() if isinstance(raw, str) else ""
    if len(reason) < contract.MIN_REASON:
        raise ex.invalid(f"`reason` is required (>= {contract.MIN_REASON} characters): why this {action} is being "
                         "done, with a ticket, alert or thread reference if there is one. It is the record of the "
                         "change.")
    if _PLACEHOLDER_REASON.match(reason):
        raise ex.invalid("`reason` looks like a placeholder. Give the real reason: it is the record of the change.")
    return reason[:contract.MAX_REASON]


def refuse_protected(email: str, action: str) -> None:
    """Service accounts are never acted on: integrations run as them."""
    if _PROTECTED.match(email.split("@", 1)[0]):
        raise ex.refused(f"{email} is a service account. {action} it would break whatever integration runs as it; a "
                         "human must do that in the admin console. Nothing was changed.")


def _client_id(args: dict, w: ExampleWriter) -> str:
    raw = ex.first(args, ("client_id", "app", "app_name", "application"))
    if raw is None or str(raw).strip() == "":
        raise ex.invalid("`client_id` is required: the OAuth client id of the grant to revoke (from "
                         "suite_list_tokens), or the app's exact display name.")
    if isinstance(raw, (list, dict)):
        raise ex.invalid("`client_id` takes ONE app. Call the tool once per grant, so each revocation is reported "
                         "separately.")
    app = str(raw).strip()
    if len(app) > 200 or re.search(r"[\"\\&#?/%]", app):
        raise ex.invalid(f"`client_id` '{app[:60]}' contains characters no OAuth client id or app name uses.")
    if app.lower() in w.org_wide_apps:
        raise ex.refused(f"'{app}' is granted org-wide by an administrator, not a token the user granted, so it can't "
                         "be revoked per user. That is managed in the admin console. Nothing was changed.")
    return app


# --- tools (stubs) ---------------------------------------------------------------------------------------------------

def _list_tokens(w: ExampleWriter, args: dict, requester: str) -> dict:
    user = ex.user_email(args)
    # TODO: call your vendor API: resolve the user in the directory, then list the grants they hold now. Return
    # tokens sorted broad-scope first, with broad scopes flagged (EXACT scope match against your product's list).
    return ex.not_implemented("suite_list_tokens", user=user)


def _revoke_token(w: ExampleWriter, args: dict, requester: str) -> dict:
    user = ex.user_email(args)
    app = _client_id(args, w)
    reason = _reason(args, "revocation")
    refuse_protected(user, "Revoking its grants would break")
    # TODO: call your vendor API. Guardrails: resolve the user (use the directory's primary address in the path, and
    # re-check refuse_protected on it); list grants; match client_id exactly (or one exact display name, else
    # ambiguous); none -> no_change; revoke ONE grant; read back and report revoked only when confirmed absent.
    return {**ex.not_implemented("suite_revoke_token", user=user, client_id=app), "written": False,
            "requested_by": requester, "reason": reason}


def _sign_out_user(w: ExampleWriter, args: dict, requester: str) -> dict:
    user = ex.user_email(args)
    reason = _reason(args, "sign-out")
    refuse_protected(user, "Signing it out would break")
    # TODO: call your vendor API. Guardrails: resolve the user (primary address, re-check refuse_protected); a
    # suspended account -> no_change; one bodiless sign-out call; 2xx is the only confirmation most products give.
    return {**ex.not_implemented("suite_sign_out_user", user=user), "written": False, "requested_by": requester,
            "reason": reason}


_DISPATCH: dict[str, Callable[[ExampleWriter, dict, str], dict]] = {
    "suite_list_tokens": _list_tokens,
    "suite_revoke_token": _revoke_token,
    "suite_sign_out_user": _sign_out_user,
}
assert frozenset(_DISPATCH) == WRITE_TOOL_NAMES | LIST_TOOL_NAMES


def run_write_tool(w: ExampleWriter | None, name: str, args: Any, requester: str) -> dict:
    """Run suite_list_tokens, suite_revoke_token or suite_sign_out_user. Never raises. `requester` is the verified
    "email (U…)" string the server supplies; a `requested_by` argument from the model is ignored."""
    fn = _DISPATCH.get(name) if isinstance(name, str) else None
    is_write = name in WRITE_TOOL_NAMES
    requester = str(requester or "").strip()[:200]
    try:
        if fn is None:
            result = {"status": "error", "error_kind": "UNKNOWN_TOOL",
                      "message": f"Unknown tool {str(name)[:80]!r}. Available: {', '.join(_DISPATCH)}."}
        elif is_write and not requester:
            result = {"status": "refused", "message": "No verified requester for this change.",
                      "next_step": "Nothing was changed. Recommend the change instead."}
        elif not isinstance(args, dict):
            result = ex.invalid("Tool input must be a JSON object.").result
        else:
            args = {k: v for k, v in args.items() if k not in ("requested_by", "requestedBy", "requester")}
            result = fn(w, args, requester)
            if w is None and result.get("status") == "not_implemented":
                result = {"status": "error", "message": "Productivity suite writes are not configured on this host.",
                          "next_step": "Recommend the change; an administrator can make it in the admin console."}
    except ex.ToolError as e:
        result = e.result
    except Exception as e:  # noqa: BLE001 - run_write_tool must never raise
        log.warning("suite write tool %s failed internally: %s", name, type(e).__name__)
        result = {"status": "error", "error_kind": "UNKNOWN", "message": f"Internal tool error ({type(e).__name__}).",
                  "next_step": "Say the tool failed."}
    if is_write:
        result.setdefault("written", False)
        result.setdefault("requested_by", requester or None)
    return result

