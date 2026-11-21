"""Email security: EXAMPLE write adapter (skeleton).

Implements the write interface (``WRITE_TOOLS``, ``LIST_TOOLS``, ``writer_from_env``, ``run_write_tool``) and re-exports
the contract's automatic-action hooks, with ``AUTO_ID_PATTERN`` built from ``EMAIL_SECURITY_CONSOLE_URL``.

Requester routes (see the contract): a verified requester means analyst-directed; ``requester == ""`` means
agent-initiated (the automatic route), where the action must follow from the verdict and ``restore`` is refused. The
"never remove mail sent from the organisation's own domains" gate needs the message's sender from the platform, so it
is marked TODO in the stub; ``email_block_sender`` refuses the organisation's own domains on input, always.

Validation is real; vendor calls are stubs returning ``status: not_implemented`` with ``written: false``.

Settings read here: ``EMAIL_SECURITY_PROTECTED_SENDER_DOMAINS`` (optional, comma-separated).

Dependencies: ``org`` and the standard library. Target: Python 3.12.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Callable, Mapping

import org
from providers.email_security import contract
from providers.email_security import example as ex

log = logging.getLogger(__name__)

WRITE_TOOLS = contract.WRITE_TOOLS
LIST_TOOLS = contract.LIST_TOOLS
WRITE_TOOL_NAMES = contract.WRITE_TOOL_NAMES

# Automatic-action hooks (policy lives in the contract).
AUTO_ID_PATTERN = contract.make_auto_id_pattern(os.environ.get(f"{contract.PREFIX}_CONSOLE_URL"))
AUTO_ID_SHAPE = contract.AUTO_ID_SHAPE
AUTO_NOTE = contract.AUTO_NOTE
auto_tools = contract.auto_tools
auto_check = contract.auto_check
auto_payload = contract.auto_payload
auto_requester = contract.auto_requester

_PLACEHOLDER_REASON = re.compile(r"(test|testing|n/?a|none|asdf|todo|tbd|placeholder|malicious|phish|phishing|spam|"
                                 r"bad|blocked?)\.?", re.I)


class ExampleWriter:
    """The writer. A real adapter gives it its own request allowlist: the action call on one message id, the list
    read and the single-entry add; never the whole-list overwrite."""

    def __init__(self, client: ex.ExampleClient, protected_domains: tuple[str, ...]):
        self._client = client
        self.protected_domains = protected_domains

    def __repr__(self) -> str:
        return f"{type(self).__name__}(base={self._client.base_url!r}, credentials=<redacted>)"

    __str__ = __repr__

    def _secrets_for_scrub(self) -> list[str]:
        return self._client._secrets_for_scrub()


def protected_domains(env: Mapping[str, str]) -> tuple[str, ...]:
    extra = tuple(d.lower().lstrip("@") for d in org._csv(str(env.get(f"{contract.PREFIX}_PROTECTED_SENDER_DOMAINS",
                                                                      ""))))
    return tuple(dict.fromkeys(contract.PROTECTED_SENDER_DOMAINS + extra))


def writer_from_env(env: Mapping[str, str], client: Any = None) -> ExampleWriter | None:
    if not isinstance(client, ex.ExampleClient):
        return None
    return ExampleWriter(client, protected_domains(env))


# --- input checks ----------------------------------------------------------------------------------------------------

def _reason(args: dict) -> str:
    raw = ex.first(args, ("reason", "justification", "note"))
    s = raw.strip() if isinstance(raw, str) else ""
    if len(s) < contract.MIN_REASON:
        raise ex.invalid(f"`reason` is required (>= {contract.MIN_REASON} characters). It is the audit record of why "
                         "this change was made: say what you concluded and on what evidence.")
    if _PLACEHOLDER_REASON.fullmatch(s):
        raise ex.invalid(f"`reason` ('{s}') is a placeholder, not a rationale. Write the real reason and the evidence.")
    return s[:contract.MAX_REASON]


def _confidence(args: dict) -> int | None:
    raw = args.get("confidence")
    if isinstance(raw, bool):
        return None
    try:
        c = float(raw)
    except (TypeError, ValueError):
        return None
    return round(c) if 0 <= c <= 100 else None


def domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].strip().lower().rstrip(".") if "@" in addr else ""


def sender_address(raw: Any) -> str:
    """One exact sender address, from 'Name <a@b>', <mailto:a@b|a@b> or a bare address."""
    if raw is None or raw == "":
        raise ex.invalid("`sender_email` is required: the exact sender address to block.")
    if isinstance(raw, (list, dict)):
        raise ex.invalid("`sender_email` takes ONE address. Call the tool once per sender.")
    s = str(raw).strip()
    ang = re.search(r"<([^<>]+@[^<>]+)>", s)
    if ang:
        s = ang.group(1)
    email = ex.strip(s).lower()
    if "|" in email:
        email = email.split("|")[-1]
    if ex.PLACEHOLDER.fullmatch(email):
        raise ex.invalid(f"`sender_email` is a placeholder ('{email}'). Pass the real address from the message.")
    if "*" in email or email.startswith("@") or "@" not in email:
        raise ex.invalid(f"'{email[:80]}' is not a single address. This tool blocks exact sender addresses only: no "
                         "wildcards or whole domains.")
    if not ex.EMAIL_RE.fullmatch(email) or len(email) > contract.MAX_ADDRESS:
        raise ex.invalid(f"'{email[:80]}' is not a valid email address.")
    return email


def check_block_target(email: str, protected: tuple[str, ...]) -> None:
    """The domain guardrails for email_block_sender, in order: the organisation's own domains, reserved test
    domains, protected platform senders."""
    domain = domain_of(email)
    if org.is_org_domain(domain):
        raise ex.refused(f"'{email}' is a {org.ORG_NAME} address. Blocklisting it would quarantine that account's mail "
                         f"to everyone in the company. If a {org.ORG_NAME} account is sending phish it is COMPROMISED: "
                         "escalate it for account containment instead.")
    if contract.RESERVED_SENDER_DOMAIN.fullmatch(domain):
        raise ex.invalid(f"'{email}' uses a reserved test domain. Nothing was written.")
    if any(domain == d or domain.endswith("." + d) for d in protected):
        raise ex.refused(f"'{email}' is on a protected sender domain ({domain}). Real mail from it is security-critical, "
                         "and a spoof of it already fails DMARC.")


def _audit(route: str, requester: str, reason: str, **extra: Any) -> dict:
    return {"route": route, "requested_by": requester or None, "reason": reason,
            **{k: v for k, v in extra.items() if v is not None}}


# --- tools (stubs) ---------------------------------------------------------------------------------------------------

def _action_message(w: ExampleWriter, args: dict, requester: str) -> dict:
    mid = ex.message_id(ex.first(args, ("message_id", "id")))
    raw_action = re.sub(r"[\s-]+", "_", str(ex.first(args, ("action",)) or "").strip().lower())
    if not raw_action:
        raise ex.invalid(f"`action` is required: one of {', '.join(contract.ACTIONS)}.")
    if raw_action in contract.REFUSED_ACTIONS:
        raise ex.refused(f"'{raw_action}' is irreversible or shares employee mail with a third party, and isn't "
                         "available to this tool. A person can do it in the platform console.")
    action = contract.ACTION_SYNONYMS.get(raw_action)
    if not action:
        raise ex.invalid(f"'{raw_action[:40]}' is not an action. Use one of: {', '.join(contract.ACTIONS)}.")
    verdict = str(ex.first(args, ("verdict", "classification")) or "").strip().lower()
    if verdict not in contract.VERDICTS:
        raise ex.invalid(f"`verdict` is required: one of {', '.join(contract.VERDICTS)}, your assessment of this "
                         "message.")
    reason = _reason(args)
    route = "analyst_directed" if requester else "agent_initiated"
    if route == "agent_initiated":
        if action == "restore":
            raise ex.refused("restore puts a removed message back in the user's mailbox and is never agent-initiated: "
                             "a named person has to ask for it.")
        if verdict not in contract.NEEDS_VERDICT[action]:
            raise ex.refused(f"'{action}' doesn't follow from a '{verdict}' verdict. Without a named requester it "
                             f"requires verdict {' or '.join(contract.NEEDS_VERDICT[action])}.")
    # TODO: call your vendor API. Guardrails: read the message first (not found -> not_found); if its sender's domain
    # is the organisation's own (org.is_org_domain) and route is agent_initiated and action != warning_banner ->
    # refused; then ONE action call (never retried). 2xx + task id -> status accepted (queued, not done); report the
    # message group's scope and whether the recipient already read, replied or forwarded it.
    return {**ex.not_implemented("email_action_message", message_id=mid, action=action), "written": False,
            "audit": _audit(route, requester, reason, verdict=verdict, confidence=_confidence(args))}


def _block_sender(w: ExampleWriter, args: dict, requester: str) -> dict:
    email = sender_address(ex.first(args, ("sender_email", "sender", "email", "address", "from")))
    check_block_target(email, w.protected_domains if isinstance(w, ExampleWriter) else contract.PROTECTED_SENDER_DOMAINS)
    reason = _reason(args)
    ev_raw = ex.first(args, ("message_id", "evidence_message_id"))
    evidence = ex.message_id(ev_raw) if ev_raw is not None else None
    route = "analyst_directed" if requester else "agent_initiated"
    # TODO: call your vendor API. Guardrails: find the sender blocklist (missing or non-editable -> error); read its
    # entries; already listed -> no_change; add ONE entry (never overwrite the list); warn if the address is also in
    # the list's overrides/exemptions.
    return {**ex.not_implemented("email_block_sender", sender_email=email), "written": False,
            "audit": _audit(route, requester, reason, evidence_message_id=evidence)}


_DISPATCH: dict[str, Callable[[ExampleWriter, dict, str], dict]] = {
    "email_action_message": _action_message,
    "email_block_sender": _block_sender,
}
assert frozenset(_DISPATCH) == WRITE_TOOL_NAMES


def run_write_tool(w: ExampleWriter | None, name: str, args: Any, requester: str = "") -> dict:
    """Run one write tool. Never raises; always returns a dict with `status` and `written`. `requester` is the
    verified Slack requester ("" = agent-initiated); the model can't set it."""
    fn = _DISPATCH.get(name) if isinstance(name, str) else None
    requester = str(requester or "").strip()[:200]
    try:
        if fn is None:
            result = {"status": "error", "error_kind": "UNKNOWN_TOOL",
                      "message": f"Unknown tool {str(name)[:80]!r}. Available: {', '.join(_DISPATCH)}."}
        elif not isinstance(args, dict):
            result = ex.invalid("Tool input must be a JSON object.").result
        else:
            args = {k: v for k, v in args.items() if k not in ("requested_by", "requestedBy", "requester")}
            result = fn(w, args, requester)
            if w is None and result.get("status") == "not_implemented":
                result = {"status": "error", "message": "Email security writes are not configured on this host.",
                          "next_step": "Recommend the action; a person can take it in the platform console."}
    except ex.ToolError as e:
        result = e.result
    except Exception as e:  # noqa: BLE001 - run_write_tool must never raise
        log.warning("email write tool %s failed internally: %s", name, type(e).__name__)
        result = {"status": "error", "written": None, "outcome_unknown": True, "error_kind": "UNKNOWN",
                  "message": f"Internal tool error ({type(e).__name__}).",
                  "next_step": "It isn't known whether a change was sent. Check the current state before saying more."}
    result.setdefault("written", False)
    return result
