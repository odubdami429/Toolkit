"""Brand protection domain contract (tool prefix ``brand_``, env prefix ``BRAND_PROTECTION``).

Vendor-neutral specification of what the brand protection specialist can do with a brand-protection platform (a
service that finds lookalike domains, impersonating social accounts, fake apps, leaked credentials and similar, queues
them as alerts, and can request takedowns): read and search alerts, submit a URL to the platform's phishing scanner and
read its verdict, and one write (archive an alert or record a takedown). An adapter implements this contract (see
``example.py`` / ``example_write.py``) and must pass ``tests/test_contracts.py`` and
``tests/test_contract_brand_protection.py``.

Configuration
-------------
``BRAND_PROTECTION_PROVIDER``, ``BRAND_PROTECTION_BASE_URL`` (bare https origin of the API),
``BRAND_PROTECTION_CONSOLE_URL`` (console origin: links under it carry alert ids), credentials as
``BRAND_PROTECTION_API_TOKEN`` or ``BRAND_PROTECTION_CLIENT_ID`` + ``_CLIENT_SECRET``. Credential scope: read alerts,
submit scans, read scan results, update one alert's state with a comment. Nothing else.

Identifiers (generic shapes)
----------------------------
* alert id: ``ORG-NUMBER`` (``AUTO_ID_SHAPE``: 2-10 capital letters, a hyphen, 1-9 digits), or a console link whose
  last path segment is one;
* scan id: 8-64 letters, digits, ``.``, ``_`` or ``-``.

Neutral enums
-------------
``QUEUE_STATES``: in_review (the platform's own analysts are reviewing), needs_confirmation (waiting on the customer),
actioned (enforcement requested), taken_down (enforcement succeeded), monitoring, archived (dismissed).
``PRODUCTS``, ``SEVERITIES``, ``ENTITY_STATES``, ``SORTS`` as below; an adapter maps its product's values onto these.

Common envelope
---------------
``status`` always; shared ``invalid_input``, ``not_found``, ``refused``, ``error``, ``not_implemented``; most results
carry ``next_step``.

Read tools
----------
``brand_get_alert(alert_id)`` -> ``status: ok``, ``alert {id, entity, entity_type (url|domain|social|app|email|phone|
    credential), product, platform, queue_state, entity_state, severity, score, tags, summary, latest_note,
    created_at, last_activity, console_url, entity_content {registrar, hosting, ip, mx, nameservers, contact_email,
    developer, bundle}, audit_log [{at, actor, kind (state_change|enforcement|comment), detail}]}``. Leaked credentials
    in dark-web alerts MUST be redacted (any credential-looking field replaced by its length).
``brand_search_alerts(...)`` -> ``status: ok``, ``total_matching``, ``breakdown {queue_state, severity, product}``,
    ``alerts [{id, entity, product, platform, queue_state, entity_state, severity, tags, created_at, last_activity,
    note}]``, ``page``, ``has_more``.
``brand_submit_scan(url, associated_urls?)`` -> ``status: submitted``, ``scan_id``, ``url_submitted``,
    ``associated_urls``. No verdict.
``brand_get_scan_result(scan_id, max_wait_seconds?)`` -> ``status: completed`` with ``suspiciousness``
    (high|medium|low|na|none), ``category``, ``results``, ``verdict_text``, ``covers``; or ``status: pending`` (no
    verdict yet; never report it as clean).

Write tool
----------
``brand_update_alert(alert_id, state, note, mode?, verdict?, confidence?)``: ``state`` is ``archived`` or
``taken_down`` (``UPDATE_STATES``). Statuses: ``updated`` (``confirmed_state``), ``no_change`` (already there),
``refused``, ``uncertain`` (accepted but not confirmed), ``error``. Every result: ``written`` (true/false/null +
``outcome_unknown``), ``alert_id``, ``entity``, ``from``, ``to``, ``mode``, ``requested_by``, ``console_url``,
``comment`` (as written).

Guardrails an implementation MUST enforce
-----------------------------------------
* One alert per call; a verified requester (refused without one). The comment starts with a stamp naming the
  requester; attribution phrases in the model's note are removed. Any ``requested_by`` argument is ignored.
* ``note`` >= ``MIN_NOTE`` characters (capped at ``MAX_NOTE``), not a placeholder; written to the alert as a comment IN
  THE SAME REQUEST as the state change, so the state never changes without its reason.
* Read the alert first: already in the target state -> ``no_change``; archive only from ``ARCHIVE_FROM``, taken_down
  only from ``TAKEDOWN_FROM``; never reopen, never archive out of an enforcement outcome, never revive an archived
  alert. Confirm the new state from the response or a read-back before reporting ``updated``.
* ``mode`` ``auto`` (the specialist's own call): only ``archived``, only with a false-positive ``verdict``;
  ``taken_down`` is always analyst-requested.
* ``brand_submit_scan`` URL guardrails (``check_scan_url``): http(s) or bare domain only (defanged input accepted); no
  credentials in the URL (``user@host``); no IPv6 literals; no private, loopback or reserved IPs, ``localhost`` or
  internal suffixes (``PRIVATE_SUFFIXES``); never the organisation's own domains (``org.is_org_domain``: they are
  protected assets, scanning them proves nothing); no placeholder domains; at most ``MAX_ASSOCIATED`` associated
  URLs, each checked the same way; at most ``MAX_URL_LEN`` characters. Scans only on request, never as part of an
  alert review.

Automatic actions (alert-bot posts)
-----------------------------------
IDs from links under ``BRAND_PROTECTION_CONSOLE_URL`` in the alert bot's own post (last path segment). Policy: only
``brand_update_alert`` with ``state`` archived, ``mode`` auto, ``verdict`` false_positive, ``confidence`` >= 98 and the
alert id in the allowed set; key ``brand|archive|<id>``. ``auto_requester`` names the alert bot; ``auto_payload`` is
unchanged (confidence is recorded on the comment).
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any
from urllib.parse import urlsplit

import org

PREFIX = "BRAND_PROTECTION"
TOOL_PREFIX = "brand_"

MIN_NOTE, MAX_NOTE, MAX_COMMENT = 25, 1500, 2000
DEFAULT_LIMIT, MAX_LIMIT, MAX_PAGE = 20, 50, 500
DEFAULT_WAIT, MAX_WAIT = 45, 90
MAX_ASSOCIATED, MAX_URL_LEN = 20, 2000
MAX_LOOKBACK_DAYS = 3650

QUEUE_STATES = ("in_review", "needs_confirmation", "actioned", "taken_down", "monitoring", "archived")
UPDATE_STATES = ("archived", "taken_down")
ARCHIVE_FROM = ("needs_confirmation", "in_review", "monitoring")
TAKEDOWN_FROM = ("needs_confirmation", "in_review", "monitoring", "actioned")
MODES = ("analyst_requested", "auto")
FP_VERDICTS = ("false_positive", "fp", "benign", "close_as_benign", "likely_benign")
PRODUCTS = ("domains", "social_media", "mobile_apps", "ecommerce", "crypto", "email", "paid_ads", "telco", "darkweb")
SEVERITIES = ("high", "medium", "low")
ENTITY_STATES = ("active", "down", "parked", "suspicious", "unclassified", "unrelated", "related", "unknown")
SORTS = ("newest", "oldest", "last_activity", "severity")
SUSPICIOUSNESS = ("high", "medium", "low", "na", "none")

ALERT_ID = r"[A-Z]{2,10}-\d{1,9}"
SCAN_ID = r"[A-Za-z0-9._-]{8,64}"
PRIVATE_SUFFIXES = (".local", ".localhost", ".internal", ".intranet", ".lan", ".corp", ".home", ".test", ".invalid",
                    ".example")
PLACEHOLDER_HOSTS = frozenset({"example.com", "example.org", "example.net", "example.edu", "domain.com",
                               "yourdomain.com", "mydomain.com", "test.com", "foo.com", "bar.com", "somesite.com",
                               "malicious.com", "evil.com", "phishing.com", "url.com", "website.com"})

TOOLS: list[dict] = [
    {
        "name": "brand_get_alert",
        "description": (
            "Read one brand-protection alert by id (e.g. ABC-9067) or its console link: the flagged entity (URL, "
            "domain, social account, app, email or phone), product and platform, queue_state, entity_state, the "
            "platform's severity, score, tags and summary, the latest note, entity_content (for domains: registrar, "
            "hosting, IP, MX, nameservers, contact email; for apps: developer and bundle), and the audit log (queue "
            "moves, enforcement requests, comments). Leaked credentials in dark-web alerts are redacted. The "
            "platform's own severity, tags and summary are not evidence for your verdict. Read-only."),
        "input_schema": {"type": "object", "properties": {
            "alert_id": {"type": "string", "description": "Alert id (ORG-NUMBER, e.g. ABC-9067) or its console link."}},
            "required": ["alert_id"]},
    },
    {
        "name": "brand_search_alerts",
        "description": (
            "Search brand-protection alerts. Returns the total number matching (`total_matching`), a breakdown, and "
            "up to `limit` compact rows (id, entity, product, platform, queue_state, entity_state, severity, tags, "
            "created_at, last_activity, note). Use it to find the alert(s) for a domain, URL or handle "
            "(`search_key`), check for prior or related alerts, and answer queue questions. With no filters it lists "
            "all alerts, newest first. Read one alert's full detail with brand_get_alert. Read-only."),
        "input_schema": {"type": "object", "properties": {
            "search_key": {"type": "string", "description": "Substring match on the alert's entity (URL, domain, "
                                                            "handle, email or phone)."},
            "search": {"type": "string", "description": "Matches alert display URLs and other indexed alert text."},
            "queue_state": {"type": "string", "description": "Comma-separated: " + ", ".join(QUEUE_STATES) + "."},
            "product": {"type": "string", "description": "One of: " + ", ".join(PRODUCTS) + "."},
            "severity": {"type": "string", "description": "Comma-separated: " + ", ".join(SEVERITIES) + "."},
            "entity_state": {"type": "string", "description": "Comma-separated: " + ", ".join(ENTITY_STATES) + "."},
            "tags": {"type": "string", "description": "Comma-separated platform tag names, e.g. Credential Theft."},
            "created_after": {"type": "string", "description": "ISO date/time (UTC), e.g. 2026-11-10."},
            "created_before": {"type": "string", "description": "ISO date/time (UTC)."},
            "last_activity_after": {"type": "string", "description": "ISO date/time (UTC): activity at or after."},
            "lookback_days": {"type": "integer", "description": "Shortcut for created_after: alerts created in the "
                                                                "last N days. Ignored if created_after is set."},
            "sort": {"type": "string", "enum": list(SORTS), "description": "Default newest."},
            "limit": {"type": "integer", "description": f"Rows to return (default {DEFAULT_LIMIT}, max {MAX_LIMIT})."},
            "page": {"type": "integer", "description": "0-indexed page, for more rows."}}},
    },
    {
        "name": "brand_submit_scan",
        "description": (
            "Submit a domain or URL to the brand-protection platform's phishing scanner and get back a `scan_id`. "
            "Does NOT return a verdict: follow it with brand_get_scan_result. On request only, never as part of an "
            "alert review. Refuses the organisation's own hosts, internal or private hosts, URLs with credentials and "
            "placeholder domains."),
        "input_schema": {"type": "object", "properties": {
            "url": {"type": "string", "description": "The domain or URL. A bare domain is fine; defanged IOCs (hxxps, "
                                                     "[.]) are accepted."},
            "associated_urls": {"type": "string", "description": "Optional: other URLs seen with it (redirect chain, "
                                                                 f"sibling pages), comma-separated, max "
                                                                 f"{MAX_ASSOCIATED}."}},
            "required": ["url"]},
    },
    {
        "name": "brand_get_scan_result",
        "description": (
            "Get the brand-protection scanner's verdict for a scan_id from brand_submit_scan, waiting for a running "
            "scan. `status` completed: `suspiciousness` is high, medium, low, na or none. `status` pending: no "
            "verdict yet, never report it as clean. Takes a scan_id, never a URL. Read-only."),
        "input_schema": {"type": "object", "properties": {
            "scan_id": {"type": "string", "description": "The scan_id brand_submit_scan returned."},
            "max_wait_seconds": {"type": "integer", "description": f"How long to wait for a pending scan (default "
                                                                   f"{DEFAULT_WAIT}, max {MAX_WAIT}; 0 checks once)."}},
            "required": ["scan_id"]},
    },
]

LIST_TOOLS: list[dict] = []

WRITE_TOOLS: list[dict] = [
    {
        "name": "brand_update_alert",
        "description": (
            "WRITE. Move ONE brand-protection alert to `archived` (dismissed: a false positive or benign) or "
            "`taken_down` (enforcement succeeded), and record `note` on the alert as a comment in the same request. "
            "Archives only from " + ", ".join(ARCHIVE_FROM) + "; taken_down also from actioned. It can't reopen an "
            "alert, set any other state, or archive an actioned or taken_down alert. Reads the alert first: already "
            "in that state returns `no_change`, a disallowed move returns `refused`, neither writes. The comment names "
            "the verified requester automatically; never pass who asked. Returns `updated` with the confirmed state, "
            "or `uncertain` / `error` with `written` (true, false, or null = unknown)."),
        "input_schema": {
            "type": "object",
            "properties": {
                "alert_id": {"type": "string", "description": "The alert id (e.g. ABC-9067) or its console link."},
                "state": {"type": "string", "enum": list(UPDATE_STATES)},
                "note": {"type": "string", "description": f"Why (at least {MIN_NOTE} characters): the conclusion and "
                                                          "its evidence. Becomes the alert comment."},
                "mode": {"type": "string", "enum": list(MODES),
                         "description": "analyst_requested (default): a person asked for this change. auto: your own "
                                        "false-positive verdict, only when the brief enables automatic archiving; "
                                        "archived only."},
                "verdict": {"type": "string", "description": "Required for mode auto: false_positive."},
                "confidence": {"type": "number", "description": "Your review's confidence (0-100), recorded on the "
                                                                "comment for mode auto."},
            },
            "required": ["alert_id", "state", "note"],
        },
    },
]

TOOL_NAMES = frozenset(t["name"] for t in TOOLS)
LIST_TOOL_NAMES = frozenset(t["name"] for t in LIST_TOOLS)
WRITE_TOOL_NAMES = frozenset(t["name"] for t in WRITE_TOOLS)
ALL_TOOL_NAMES = TOOL_NAMES | LIST_TOOL_NAMES | WRITE_TOOL_NAMES


def tool(name: str) -> dict[str, Any] | None:
    return next((t for t in TOOLS + LIST_TOOLS + WRITE_TOOLS if t["name"] == name), None)


# --- scan URL guardrails ---------------------------------------------------------------------------------------------

class ScanUrlRejected(ValueError):
    """``status`` is ``invalid_input`` (fix the input) or ``refused`` (a boundary; don't retry with another URL)."""

    def __init__(self, message: str, status: str = "invalid_input"):
        super().__init__(message)
        self.status = status


def check_scan_url(raw: Any, label: str = "url") -> str:
    """Normalise a URL or bare domain for the third-party scanner and refuse anything that must not be sent there.
    Returns the normalised URL; raises ScanUrlRejected."""
    if isinstance(raw, (list, dict, bool)):
        raise ScanUrlRejected(f"`{label}` takes one URL or domain.")
    s = str("" if raw is None else raw).strip()
    s = re.sub(r"^[<(\"'\s]+", "", s)
    s = re.sub(r"[>)\"'\s.,;!]+$", "", s)
    s = re.sub(r"(?i)^h(xx)p(s?)(:|\[:\])", lambda m: "http" + m.group(2) + ":", s)
    s = re.sub(r"(?i)\[\.\]|\(\.\)|\{\.\}|\s+dot\s+", ".", s)
    s = re.sub(r"\[://\]|\[//\]", "://", s)
    if not s:
        raise ScanUrlRejected(f"`{label}` is required: a domain or URL.")
    if not re.match(r"(?i)^[a-z][a-z0-9+.-]*://", s):
        scheme = re.match(r"(?i)^([a-z][a-z0-9+.-]*):(?!\d)", s)
        if scheme:
            raise ScanUrlRejected(f"`{label}` uses the '{scheme.group(1)}:' scheme. The scanner takes http(s) URLs or a "
                                  "bare domain only.")
        s = "https://" + s
    m = re.fullmatch(r"(?is)([a-z][a-z0-9+.-]*)://([^/?#]*)(.*)", s)
    if not m:
        raise ScanUrlRejected(f"`{label}` is not a parseable URL.")
    scheme, authority, rest = m.group(1).lower(), m.group(2), m.group(3) or ""
    if scheme not in ("http", "https"):
        raise ScanUrlRejected(f"`{label}` uses the '{scheme}' scheme. The scanner takes http/https URLs only.")
    if "@" in authority:
        raise ScanUrlRejected(f"`{label}` contains embedded credentials (user@host). Never send credentials to a "
                              "third-party scanner.")
    host, port = authority.lower(), ""
    if host.startswith("["):
        raise ScanUrlRejected(f"`{label}` is a literal IPv6 address. Scan the hostname instead.")
    pm = re.fullmatch(r"(.*?):(\d+)", host)
    if pm:
        host, port = pm.group(1), ":" + pm.group(2)
    host = host.rstrip(".")
    if not host:
        raise ScanUrlRejected(f"`{label}` has no hostname.")
    if not re.fullmatch(r"[a-z0-9._-]+", host):
        raise ScanUrlRejected(f"`{label}` has an invalid hostname '{host[:80]}'.")
    is_ip = False
    try:
        ip = ipaddress.IPv4Address(host)
        is_ip = True
        if not ip.is_global:
            raise ScanUrlRejected(f"Refusing to scan '{host}': it is a private, loopback or reserved address. The "
                                  "scanner fetches it from its own network, and submitting it leaks internal "
                                  "infrastructure to a vendor.", "refused")
    except ipaddress.AddressValueError:
        pass
    if host == "localhost" or (re.fullmatch(r"[\d.]+", host) and not is_ip):
        raise ScanUrlRejected(f"Refusing to scan '{host}': not a public host.", "refused")
    # Before the reserved-suffix rule, so the organisation's own domains are always named as such.
    if org.is_org_domain(host):
        raise ScanUrlRejected(f"'{host}' is a {org.ORG_NAME} protected asset; scanning it proves nothing.", "refused")
    if host.endswith(PRIVATE_SUFFIXES):
        raise ScanUrlRejected(f"Refusing to scan '{host}': '{host[host.rfind('.'):]}' is an internal or reserved "
                              "suffix, not a public domain.", "refused")
    if "." not in host:
        raise ScanUrlRejected(f"`{label}` '{host}' has no TLD. Pass a fully qualified domain.")
    if host in PLACEHOLDER_HOSTS or host.removeprefix("www.") in PLACEHOLDER_HOSTS:
        raise ScanUrlRejected(f"Refusing to scan the placeholder domain '{host}'. Pass the real domain; never invent "
                              "one.")
    out = scheme + "://" + host + port + rest
    if len(out) > MAX_URL_LEN:
        raise ScanUrlRejected(f"`{label}` is {len(out)} characters (max {MAX_URL_LEN}).")
    return out


# --- automatic actions on alert-bot posts ----------------------------------------------------------------------------

AUTO_ID_SHAPE = re.compile(ALERT_ID)
AUTO_NOTE = ("Automatic archive (false positive at 98% or higher, mode auto) is enabled for these alert IDs from the "
             "post: ")
_NEVER = re.compile(r"(?!)(x)")


def console_host(console_url: str | None) -> str:
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


def make_auto_id_pattern(console_url: str | None) -> re.Pattern:
    """Alert ids (group 1) that are the last path segment of a link under BRAND_PROTECTION_CONSOLE_URL; a
    never-matching pattern when unset."""
    host = console_host(console_url)
    if not host:
        return _NEVER
    return re.compile(r"(?i:https?://" + re.escape(host) + r")/(?:[^\s<>|\"'`?]*/)?(" + ALERT_ID
                      + r")/?(?=$|[\s<>|\"'`?#),;\]]|\.(?:\s|$))")


def extract_alert_id(value: Any) -> str:
    """The alert id in a bare id or a link (last path segment), uppercased; "" when there is none."""
    s = str(value or "").strip()
    if re.match(r"(?i)https?://", s):
        try:
            parts = urlsplit(s)
        except ValueError:
            return ""
        segs = [p for p in (parts.path + "/" + parts.fragment).split("/") if p]
        s = segs[-1] if segs else ""
    s = s.upper()
    return s if AUTO_ID_SHAPE.fullmatch(s) else ""


def auto_tools() -> list[dict]:
    return [{**t, "input_schema": json.loads(json.dumps(t.get("input_schema", {}))),
             "description": ("AUTOMATIC ARCHIVE ONLY. Archives a brand-protection alert from the alert bot's post as "
                             "a false positive: state archived, mode auto, verdict false_positive, confidence >= 98. "
                             "Anything else is refused. " + t["description"])}
            for t in WRITE_TOOLS]


def auto_check(name: str, args: Any, allowed: frozenset[str]) -> tuple[list[str] | None, str | None]:
    """(["brand|archive|<id>"], None) if within the automatic policy, else (None, reason)."""
    args = args if isinstance(args, dict) else {}
    raw_conf = args.get("confidence")
    try:
        conf = -1.0 if isinstance(raw_conf, bool) else float(raw_conf)
    except (TypeError, ValueError):
        conf = -1.0
    verdict = str(args.get("verdict", "")).strip().lower()
    aid = extract_alert_id(args.get("alert_id"))
    if name != "brand_update_alert" or str(args.get("state", "")).strip().lower() != "archived":
        return None, "Alert-bot requests may only archive automatically."
    if str(args.get("mode", "")).strip().lower() != "auto" or verdict != "false_positive" or not conf >= 98:
        return None, "Automatic archive needs mode auto, verdict false_positive and confidence >= 98."
    if not aid or aid not in allowed:
        return None, "Only alert IDs from the alert bot's own post can be archived automatically."
    return [f"brand|archive|{aid}"], None


def auto_payload(name: str, args: Any) -> dict:
    """Unchanged: `confidence` is part of the schema and recorded on the comment."""
    return args if isinstance(args, dict) else {}


def auto_requester(actor: str) -> str:
    """Names the alert bot in the alert comment."""
    return f"{actor} (alert bot, automatic)"
