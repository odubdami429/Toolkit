"""Email security domain contract (tool prefix ``email_``, env prefix ``EMAIL_SECURITY``).

Vendor-neutral specification of what the email security specialist can do with an email security platform (an
API-connected mail filter that sees every message, groups similar messages across mailboxes, and can remediate them):
search message groups, read one message, read the platform's own automated analysis, check remediation status, and two
writes (remediate a message group, block a sender). An adapter for a real product implements this contract (see
``example.py`` / ``example_write.py``) and must pass ``tests/test_contracts.py`` and
``tests/test_contract_email_security.py``.

Configuration
-------------
``EMAIL_SECURITY_PROVIDER``, ``EMAIL_SECURITY_BASE_URL`` (bare https origin of the platform API),
``EMAIL_SECURITY_CONSOLE_URL`` (console origin: alert-bot links under it carry message ids for automatic actions),
credentials as ``EMAIL_SECURITY_API_TOKEN`` (or client id + secret/private key). ``EMAIL_SECURITY_PROTECTED_SENDER_DOMAINS``
(optional, comma-separated) sets ``PROTECTED_SENDER_DOMAINS``: senders whose real mail is security-critical (your
suite's, identity provider's and email security platform's notification domains).

Credential scope: read messages and message contents, read analysis and action status; for writes, take remediation
actions and edit the sender blocklist. Nothing else (no list overwrite, no delete of calendar events, no sharing mail
with the vendor).

Identifiers (generic shapes)
----------------------------
* message id: a UUID (``AUTO_ID_SHAPE``), the platform's id for ONE copy of a message in one mailbox;
* group id: the platform's opaque id for a message group (one campaign or similar messages across mailboxes);
* task id: a UUID returned when a remediation action is accepted;
* message_id_header: the RFC 5322 ``Message-ID`` header (never a platform id).

Common envelope
---------------
``status`` is always present. Shared: ``invalid_input`` (nothing sent), ``not_found``, ``refused``, ``error``
(``message``, optional ``hint``, ``http_status``), ``not_implemented`` (the example skeleton). Most results carry
``next_step`` and ``now``.

Read tools (``run_tool(client, name, args, requester="")``: the server passes the verified requester)
-----------------------------------------------------------------------------------------------------------------
``email_search_messages`` -> ``status: ok``, ``query`` (effective filters and window), ``total``, ``next_offset``,
    ``message_groups [{group_id, subject, sender, first_seen, last_seen, mailbox_count, message_ids, state
    (delivered|quarantined|trashed|spam|graymail|banner|restored), analysis_verdict, user_reports, reads, replies,
    clicks}]``. Matching is exact and case-insensitive unless ``*`` is used; free-text ``query`` can't be combined
    with other fields or ``direction``; at least one field (or ``reported_only``) is required.
``email_get_message_eml`` -> ``status: ok``, ``message_id``, ``access_justification``, ``meta {mailbox, state,
    flagged_rules, actions_taken, read_at, replied_at, forwarded_at, group_id}``, the parsed EML (``headers``,
    ``authentication {spf, dkim, dmarc}``, ``received``, ``bodies``, ``links [{url, display_text, host,
    display_mismatch, ip_host, punycode}]``, ``forms``, ``attachments``, ``attached_messages``, ``signals``) and,
    with ``include_raw``, ``raw_excerpt`` (base64 elided).
``email_get_analysis_report`` -> ``status: ok``, ``verdict`` (one of ``ANALYSIS_VERDICTS``), ``summary``,
    ``explanation``, and for malicious mail ``attack_type`` and ``techniques``. A second opinion, never a verdict.
``email_get_action_status`` -> ``task {task_id, state (pending|started|retrying|succeeded|failed)}`` and/or
    ``group_history [{action, applied|reverted, at, by, messages_affected}]``.

Message contents (EML, analysis report) are opened only with a ``justification`` (>= ``MIN_JUSTIFICATION`` chars)
AND a verified requester; the adapter records both in the platform's access-audit log if it has one.

Write tools
-----------
Results carry ``written`` (true/false/null + ``outcome_unknown``) and ``audit {route (analyst_directed |
agent_initiated), requested_by, reason, verdict?, confidence?, evidence_message_id?}``.

``email_action_message(message_id, action, verdict, reason, confidence?)``
    ``action`` in ``ACTIONS``. The platform applies it to the WHOLE MESSAGE GROUP (every recipient's copy), not one
    mailbox. Asynchronous: ``status: accepted`` + ``task_id`` means queued, not done (check with
    email_get_action_status). Result also has ``message {subject, sender, mailbox, group_id, read_at, replied_at,
    forwarded_at, internal_sender}``.
``email_block_sender(sender_email, reason, message_id?)``
    Add ONE exact address to the platform's sender blocklist (future mail auto-quarantined org-wide). Add-only:
    ``blocked`` (with ``list {id, name, entries_before, entries_after_expected}``) or ``no_change`` (already listed).

Guardrails an implementation MUST enforce
-----------------------------------------
* Exact outbound allowlist (method, path, body shape) before any network I/O; writes are never retried.
* Requester routes: with a verified requester the call is analyst-directed (any action in ``ACTIONS``, any
  verdict). With ``requester == ""`` it is AGENT-INITIATED (the automatic route): the action must follow from the
  verdict (``NEEDS_VERDICT``), ``restore`` is refused, and removing mail sent from the organisation's own domains
  (``org.is_org_domain`` on the sender read from the platform) is refused (a warning banner is allowed).
* Never send irreversible or data-sharing actions (``REFUSED_ACTIONS``).
* ``email_block_sender``: one exact address (no wildcard, no bare domain); never the organisation's own domains;
  never ``PROTECTED_SENDER_DOMAINS``; refuse reserved test domains; read the list first (already listed ->
  ``no_change``); add one entry, never overwrite the list; no unblock.
* ``reason`` >= ``MIN_REASON`` characters, not a placeholder ("phishing", "spam", "test").

Automatic actions (alert-bot posts)
-----------------------------------
IDs come only from links under ``EMAIL_SECURITY_CONSOLE_URL`` in the alert bot's own signed post
(``make_auto_id_pattern``; the message id is the last path segment). Policy (``auto_check``):
``email_action_message`` quarantine for verdict malicious with confidence > 98 (key ``email|quarantine|<id>``) or
warning_banner for malicious or suspicious (key ``email|banner|<id>``); ``email_block_sender`` with confidence > 98
on a message from the post (key ``email|block|<id>``; ``auto_payload`` strips ``confidence``, which exists only on the
automatic schema). ``auto_requester`` is ``""`` so the writer applies its agent-initiated gates.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlsplit

PREFIX = "EMAIL_SECURITY"
TOOL_PREFIX = "email_"

MIN_REASON, MAX_REASON = 20, 500
MIN_JUSTIFICATION = 15
DEFAULT_LOOKBACK, MAX_LOOKBACK = 168, 2160
DEFAULT_LIMIT, MAX_LIMIT = 20, 50
DEFAULT_BODY_CHARS, MAX_BODY_CHARS = 8000, 30000
DEFAULT_RAW_CHARS, MAX_RAW_CHARS = 20000, 30000
MAX_ADDRESS = 254

ACTIONS = ("trash", "quarantine", "move_to_spam", "move_to_graymail", "warning_banner", "restore")
ACTION_SYNONYMS = {
    "trash": "trash", "delete": "trash", "remove": "trash", "trash_message": "trash",
    "quarantine": "quarantine", "quarantine_message": "quarantine", "isolate": "quarantine",
    "spam": "move_to_spam", "move_to_spam": "move_to_spam", "junk": "move_to_spam",
    "graymail": "move_to_graymail", "move_to_graymail": "move_to_graymail",
    "warning_banner": "warning_banner", "banner": "warning_banner", "warn": "warning_banner",
    "warning": "warning_banner",
    "restore": "restore", "release": "restore", "undo": "restore", "unquarantine": "restore",
    "restore_message": "restore",
}
#: Never sent by any implementation: irreversible, or sends employee mail to a third party.
REFUSED_ACTIONS = ("delete_calendar_events", "share_with_vendor", "share")
VERDICTS = ("malicious", "suspicious", "spam", "graymail", "benign", "simulation")
#: Without a verified requester (agent-initiated), the action must follow from one of these verdicts.
NEEDS_VERDICT = {
    "trash": ("malicious",), "quarantine": ("malicious",),
    "move_to_spam": ("spam", "graymail", "malicious"), "move_to_graymail": ("spam", "graymail", "malicious"),
    "warning_banner": ("suspicious", "malicious", "spam"), "restore": (),
}
ANALYSIS_VERDICTS = ("malicious", "spam", "graymail", "likely_benign", "benign", "unknown")
DIRECTIONS = ("inbound", "outbound", "internal")
TASK_STATES = ("pending", "started", "retrying", "succeeded", "failed")
#: Senders whose real mail is security-critical (your identity provider's MFA notices, your productivity suite's
#: alerts, your security vendors): a spoof of them already fails DMARC, so blocking the address would only quarantine
#: the real mail. Empty by default; each deployment lists its own in EMAIL_SECURITY_PROTECTED_SENDER_DOMAINS.
PROTECTED_SENDER_DOMAINS: tuple[str, ...] = ()
RESERVED_SENDER_DOMAIN = re.compile(r"(.*\.)?(invalid|test|example|localhost)|example\.(com|org|net)")

UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
GROUP_ID = r"[A-Za-z0-9._:-]{6,128}"

_JUSTIFICATION = {
    "type": "string",
    "description": (f"Why this message's contents are being opened (>= {MIN_JUSTIFICATION} characters), e.g. "
                    "'Ad-hoc review: suspected invoice fraud reported in Slack'. Recorded in the platform's access "
                    "audit log with the requester's name."),
}
_REASON = {"type": "string", "description": f"Why, with the evidence (>= {MIN_REASON} characters)."}

TOOLS: list[dict] = [
    {
        "name": "email_search_messages",
        "description": (
            "Search the email security platform's message GROUPS (one campaign or similar messages across mailboxes) "
            "by sender, subject, recipient, attachment name or hash, RFC Message-ID header, or free text `query` (free "
            f"text can't be combined with other fields), over `lookback_hours` (default {DEFAULT_LOOKBACK}, max "
            f"{MAX_LOOKBACK}). Matching is EXACT and case-insensitive unless you use *: *@domain.com finds a whole "
            "sending domain, *invoice* a subject containing it. `direction` (inbound/outbound/internal) narrows a "
            "search. `reported_only: true` lists user-reported mail. Each row returns `message_ids` for chaining, the "
            "platform's state and automated-analysis verdict, reads, replies, clicks and user reports; "
            "`mailbox_count` is how many recipients it reached. Read-only."),
        "input_schema": {"type": "object", "properties": {
            "sender": {"type": "string", "description": "From address; * wildcards allowed."},
            "subject": {"type": "string", "description": "Subject; exact unless * is used."},
            "recipient": {"type": "string", "description": "A full mailbox address, or a partial To/Cc/Bcc with *."},
            "file_name": {"type": "string", "description": "Attachment file name."},
            "attachment_hash": {"type": "string", "description": "Attachment MD5, SHA1 or SHA256."},
            "message_id_header": {"type": "string", "description": "The RFC Message-ID header (not a platform id)."},
            "query": {"type": "string", "description": "Free text across all fields; use alone."},
            "direction": {"type": "string", "description": "inbound, outbound or internal (comma-separate several)."},
            "reported_only": {"type": "boolean", "description": "Only user-reported mail (window on report time)."},
            "lookback_hours": {"type": "integer", "description": f"Default {DEFAULT_LOOKBACK}, max {MAX_LOOKBACK}."},
            "limit": {"type": "integer", "description": f"Groups per page, default {DEFAULT_LIMIT}, max {MAX_LIMIT}."},
            "offset": {"type": "integer", "description": "From next_offset, for the next page."},
        }},
    },
    {
        "name": "email_get_message_eml",
        "description": (
            "Read ONE message: the email security platform's metadata (mailbox, state, flagged rules, actions taken, "
            "whether the recipient read, replied or forwarded it) plus the raw EML parsed: headers, SPF/DKIM/DMARC, "
            "the Received chain, decoded body text, every link (with display_mismatch, ip_host and punycode flags), "
            "forms, attachments, attached .eml messages and a `signals` summary. Needs a `justification` and a named "
            "requester. Set `include_raw: true` only when you need the headers verbatim. Images and QR codes aren't "
            "visible. Read-only."),
        "input_schema": {"type": "object", "properties": {
            "message_id": {"type": "string", "description": "Platform message id (a UUID) from `message_ids`."},
            "justification": _JUSTIFICATION,
            "max_body_chars": {"type": "integer", "description": f"Body text budget, default {DEFAULT_BODY_CHARS}, "
                                                                 f"max {MAX_BODY_CHARS}."},
            "include_raw": {"type": "boolean", "description": "Also return a raw excerpt (base64 elided)."},
            "max_raw_chars": {"type": "integer", "description": f"Raw excerpt size, default {DEFAULT_RAW_CHARS}, max "
                                                                f"{MAX_RAW_CHARS}."},
        }, "required": ["message_id", "justification"]},
    },
    {
        "name": "email_get_analysis_report",
        "description": (
            "The email security platform's own automated analysis of one message: its verdict ("
            + ", ".join(ANALYSIS_VERDICTS) + "), summary and full explanation, and for malicious mail the attack type "
            "and techniques. A second opinion to weigh against the message itself, never a substitute for reading "
            "it. Needs a `justification` and a named requester. Read-only."),
        "input_schema": {"type": "object", "properties": {
            "message_id": {"type": "string", "description": "Platform message id (a UUID)."},
            "justification": _JUSTIFICATION,
        }, "required": ["message_id", "justification"]},
    },
    {
        "name": "email_get_action_status",
        "description": (
            "Did an email security platform action happen? `task_id` (from an accepted action) returns the task "
            "state: pending, started or retrying (in progress), succeeded (done) or failed. `group_id` returns the "
            "manual-action history of the whole message group (quarantine, trash, banner, restore; applied or "
            "reverted; messages_affected). Give at least one. Read-only."),
        "input_schema": {"type": "object", "properties": {
            "task_id": {"type": "string", "description": "A task id (a UUID) returned by an action."},
            "group_id": {"type": "string", "description": "A message group id from search results."},
            "lookback_hours": {"type": "integer", "description": f"Group history window, default {DEFAULT_LOOKBACK}, "
                                                                 f"max {MAX_LOOKBACK}."},
            "limit": {"type": "integer", "description": f"Group history rows, default {DEFAULT_LIMIT}, max "
                                                        f"{MAX_LIMIT}."},
        }},
    },
]

LIST_TOOLS: list[dict] = []

WRITE_TOOLS: list[dict] = [
    {
        "name": "email_action_message",
        "description": (
            "WRITE. Take a remediation action starting from one platform message id: " + ", ".join(ACTIONS) + ". "
            "The platform applies it to the WHOLE message group, every recipient's copy, not one mailbox. Needs your "
            f"`verdict` and a `reason` (>= {MIN_REASON} characters, the audit record). Asynchronous: status "
            "`accepted` with a `task_id` means queued, not done; check it with email_get_action_status. The "
            "requester is recorded automatically. Never deletes calendar events or shares mail with the vendor."),
        "input_schema": {
            "type": "object",
            "properties": {
                "message_id": {"type": "string", "description": "The platform message id (a UUID) from search results "
                               "or the alert; not the group id or the Message-ID header."},
                "action": {"type": "string", "enum": list(ACTIONS)},
                "verdict": {"type": "string", "enum": list(VERDICTS), "description": "Your assessment of the message."},
                "reason": _REASON,
                "confidence": {"type": "integer", "description": "Your confidence 0-100 (audit only)."},
            },
            "required": ["message_id", "action", "verdict", "reason"],
        },
    },
    {
        "name": "email_block_sender",
        "description": (
            "WRITE, add-only. Add ONE exact sender address to the email security platform's sender blocklist: future "
            "mail from it is auto-quarantined org-wide. Does nothing to mail already delivered (that is "
            "email_action_message, which reaches the WHOLE message group). No wildcards or domains; refuses the "
            "organisation's own addresses and protected platform senders. Can't unblock. Needs a `reason` (>= "
            f"{MIN_REASON} characters). Returns `blocked` or `no_change`. The requester is recorded automatically."),
        "input_schema": {
            "type": "object",
            "properties": {
                "sender_email": {"type": "string", "description": "The exact From address to block."},
                "reason": _REASON,
                "message_id": {"type": "string", "description": "Optional: the platform message id that is the "
                               "evidence."},
            },
            "required": ["sender_email", "reason"],
        },
    },
]

TOOL_NAMES = frozenset(t["name"] for t in TOOLS)
LIST_TOOL_NAMES = frozenset(t["name"] for t in LIST_TOOLS)
WRITE_TOOL_NAMES = frozenset(t["name"] for t in WRITE_TOOLS)
ALL_TOOL_NAMES = TOOL_NAMES | LIST_TOOL_NAMES | WRITE_TOOL_NAMES


def tool(name: str) -> dict[str, Any] | None:
    return next((t for t in TOOLS + LIST_TOOLS + WRITE_TOOLS if t["name"] == name), None)


# --- automatic actions on alert-bot posts ----------------------------------------------------------------------------

AUTO_ID_SHAPE = re.compile(UUID)
AUTO_NOTE = ("Automatic actions (quarantine and sender block for Malicious above 98%, warning banner for Malicious at "
             "98% or below and Suspicious) are enabled for these message IDs from the post: ")
_NEVER = re.compile(r"(?!)(x)")


def console_host(console_url: str | None) -> str:
    """The lowercase host[:port] of a console origin, or "" when unset or not an http(s) URL."""
    raw = str(console_url or "").strip()
    if not raw:
        return ""
    try:
        parts = urlsplit(raw if "://" in raw else "https://" + raw)
    except ValueError:
        return ""
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password \
            or not re.fullmatch(r"[a-z0-9.-]+(:\d{1,5})?", parts.netloc.lower()):
        return ""
    return parts.netloc.lower()


def console_id_pattern(console_url: str | None, id_regex: str) -> re.Pattern:
    """IDs (group 1) that are the last path segment of a link under the console origin; never matches when unset."""
    host = console_host(console_url)
    if not host:
        return _NEVER
    return re.compile(r"(?i:https?://" + re.escape(host) + r")/(?:[^\s<>|\"'`?]*/)?(" + id_regex
                      + r")/?(?=$|[\s<>|\"'`?#),;\]]|\.(?:\s|$))")


def make_auto_id_pattern(console_url: str | None) -> re.Pattern:
    """Message ids in links under EMAIL_SECURITY_CONSOLE_URL (e.g. <console>/messages/<uuid>)."""
    return console_id_pattern(console_url, UUID)


def auto_tools() -> list[dict]:
    """WRITE_TOOLS as offered on an alert-bot request, with descriptions saying they're automatic only."""
    out = []
    for t in WRITE_TOOLS:
        t = {**t, "input_schema": json.loads(json.dumps(t.get("input_schema", {})))}
        if t["name"] == "email_block_sender":
            t["description"] = ("AUTOMATIC ONLY. Blocks an attacker-controlled sender of a message from the alert "
                                "bot's post, for Malicious above 98% only: pass that `message_id` and your "
                                "`confidence`. " + t["description"])
            t["input_schema"].setdefault("properties", {})["confidence"] = {
                "type": "integer", "description": "Your verdict confidence (0-100); must be above 98."}
        else:
            t["description"] = ("AUTOMATIC ONLY. For a message from the alert bot's post: quarantine for Malicious "
                                "above 98% (pass `confidence`), or warning_banner for Malicious at 98% or below and "
                                "Suspicious. Anything else is refused. " + t["description"])
        out.append(t)
    return out


def _conf(args: dict) -> float:
    raw = args.get("confidence")
    if isinstance(raw, bool):
        return -1.0
    try:
        return float(raw)
    except (TypeError, ValueError):
        return -1.0


def auto_check(name: str, args: Any, allowed: frozenset[str]) -> tuple[list[str] | None, str | None]:
    """(keys, None) if this automatic action is within policy, else (None, reason)."""
    args = args if isinstance(args, dict) else {}
    verdict = str(args.get("verdict", "")).strip().lower()
    mid = str(args.get("message_id", "")).strip().lower()
    if name not in WRITE_TOOL_NAMES:
        return None, "This action can't run automatically."
    if not AUTO_ID_SHAPE.fullmatch(mid) or mid not in allowed:
        return None, "Only message IDs from the alert bot's own post can be actioned automatically."
    if name == "email_action_message":
        action = str(args.get("action", "")).strip().lower()
        if action == "quarantine" and verdict == "malicious" and _conf(args) > 98:
            return [f"email|quarantine|{mid}"], None
        if action == "warning_banner" and verdict in ("malicious", "suspicious"):
            return [f"email|banner|{mid}"], None
        return None, ("Automatic actions are quarantine (Malicious above 98%) or warning_banner (Malicious or "
                      "Suspicious) only.")
    if _conf(args) > 98:  # email_block_sender
        return [f"email|block|{mid}"], None
    return None, "Automatic sender blocks need Malicious above 98% (pass `confidence`)."


def auto_payload(name: str, args: Any) -> dict:
    """Arguments for run_write_tool on an accepted automatic action: email_block_sender's automatic-only
    `confidence` is dropped; everything else unchanged."""
    args = args if isinstance(args, dict) else {}
    return {k: v for k, v in args.items() if k != "confidence"} if name == "email_block_sender" else args


def auto_requester(actor: str) -> str:
    """Empty: the writer then applies its agent-initiated gates (action follows verdict, no restore, never removes
    mail sent from the organisation's own domains)."""
    return ""
