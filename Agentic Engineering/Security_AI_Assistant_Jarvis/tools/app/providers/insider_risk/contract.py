"""Insider risk domain contract (tool prefix ``irm_``, env prefix ``INSIDER_RISK``).

Vendor-neutral specification of what the insider risk specialist can do with an insider-risk platform (one that watches
file movement to cloud storage, email, removable media, AI tools and so on, and groups risky activity into alerts):
search alerts, read one alert with its highest-risk file events, search the raw file-event stream, and one write
(close an alert with a disposition and a note). ``irm_check_ai_entitlement`` (``ai_entitlement.py``) is also offered to
this specialist; it is answered by the identity provider's ``user_groups``, not by this adapter. An adapter implements
this contract (see ``example.py`` / ``example_write.py``) and must pass ``tests/test_contracts.py`` and
``tests/test_contract_insider_risk.py``.

Configuration
-------------
``INSIDER_RISK_PROVIDER``, ``INSIDER_RISK_BASE_URL`` (bare https origin of the API), ``INSIDER_RISK_CONSOLE_URL``
(console origin: links under it carry alert ids), credentials as ``INSIDER_RISK_API_TOKEN`` or
``INSIDER_RISK_CLIENT_ID`` + ``_CLIENT_SECRET``. Credential scope: read alerts and file events, add a note to an alert
and change one alert's state. Never the bulk or close-by-criteria endpoints.

Identifiers
-----------
``session_id`` is the platform's id for one alert (an alert session grouping related activity): generic shape
``AUTO_ID_SHAPE`` (6-64 letters, digits, ``_`` or ``-``), or a console link whose last path segment is one. Never a
list.

Neutral enums
-------------
Alert ``STATES``: open, in_progress, open_new_data (reopened by new activity), closed, closed_true_positive,
closed_benign_true_positive, closed_false_positive. Close ``DISPOSITIONS`` (``irm_close_alert``): false_positive (the
activity did not happen as alerted or was misattributed), true_positive (genuine insider risk), benign_true_positive
(real but sanctioned), closed (no verdict); ``DISPOSITION_STATE`` maps them to the closed states. Alert severity 0-4
(none, low, moderate, high, critical); file-event ``EVENT_SEVERITIES``.

Common envelope
---------------
``status`` always; shared ``invalid_input``, ``not_found``, ``refused``, ``error``, ``not_implemented``. Every result
echoes ``now`` in a real adapter; most carry ``next_step``. An empty result is never evidence that nothing happened.

Read tools
----------
``irm_search_alerts`` -> ``status: ok``, ``total_count``, ``has_more``, ``actor_resolution``, ``filters_applied``,
    ``alerts [{session_id, actor, state, state_set_by, state_history, closed_in_multiple_states, auto_closed_by_agent,
    risk_score, risk_severity, begin_time, end_time, activity_summary, event_counts, risk_indicators, triggered_rules,
    note_count, proposed_disposition}]``. Defaults: unresolved alerts from the last 7 days.
``irm_get_alert`` -> ``status: ok``, ``alert {session_id, actor, current_state, state_history, state_set_by,
    risk_score, risk_severity, risk_indicators, triggered_rules, notes, proposed_disposition, summary, console_url}``,
    ``events [{time, action, file_name, file_category, sha256, size_bytes, destination_category, destination_name,
    destination_domain, destination_user_emails, destination_account, destination_user_classification,
    browser_logged_in_user, paste_visible_bytes, paste_total_bytes, file_acquired_from, source_tab_titles,
    destination_urls, risk_severity}]`` (highest risk first), ``events_truncated``.
``irm_search_events`` -> ``status: ok``, ``events`` (same fields), ``summary {top_destinations, top_actions,
    top_actors, top_file_categories, top_destination_users, top_destination_user_classifications, total_bytes,
    total_paste_visible_bytes}``, ``total_count``, ``truncated``.

Write tool
----------
``irm_close_alert(session_id, disposition, note, mode?, confidence?)``. Statuses: ``closed`` (read-back shows the
closed state), ``partial`` (note written, close not confirmed: ``state_confirmed`` false, ``confirmed_state`` = what the
platform shows), ``failed`` (nothing changed), ``refused``, ``invalid_input``, ``error``. Fields: ``written``
(true/false/null + ``outcome_unknown``), ``note_attached``, ``state_confirmed``, ``state_change_accepted``,
``previous_state``, ``confirmed_state``, ``console_url``, ``audit {mode, requested_by, reason, from_state, to_state,
confidence, note_written}``.

Guardrails an implementation MUST enforce
-----------------------------------------
* One alert per call, never bulk (a list or comma-separated ids is refused; bulk and close-by-criteria endpoints are
  never on the request allowlist).
* A verified requester (refused without one). The note starts with a stamp naming the requester (``[Jarvis] Closed
  <disposition> on analyst request (<requester>)`` or ``[Jarvis] Auto-closed ...`` for mode auto); attribution phrases
  in the model's note are removed; any ``requested_by`` argument is ignored.
* ``note`` ``MIN_NOTE``-``MAX_NOTE`` characters (including the stamp), plain text, not a placeholder.
* READ FIRST: the alert must exist and be open; one already in any closed state is refused (never re-close: it would
  bury the analyst's disposition); an unknown current state is refused.
* NOTE FIRST, THEN STATE: write the note; if it can't be recorded, do not change the state. Then change the state.
* READ BACK (several times with back-off: platforms apply state changes asynchronously); report ``closed`` only when a
  read-back shows the new state.
* Only closed states can be set (never reopen, never set open/in_progress/open_new_data).
* ``mode`` ``auto``: ``confidence`` required, only ``AUTO_DISPOSITIONS``.

Automatic actions (alert-bot posts)
-----------------------------------
IDs from links under ``INSIDER_RISK_CONSOLE_URL`` in the alert bot's own post (last path segment). Policy: only
``irm_close_alert`` with ``mode`` auto, ``disposition`` false_positive or benign_true_positive, ``confidence`` >= 98
and the id in the allowed set; key ``irm|close|<id>``. ``auto_requester`` names the alert bot; ``auto_payload`` is
unchanged (confidence is recorded in the note).
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlsplit

PREFIX = "INSIDER_RISK"
TOOL_PREFIX = "irm_"

MIN_NOTE, MAX_NOTE = 20, 2000
DEFAULT_LOOKBACK, MAX_LOOKBACK = 168, 8760
ALERTS_DEFAULT_PAGE, ALERTS_MAX_PAGE = 25, 50
MAX_PAGE_NUMBER = 1000
DEFAULT_EVENTS, MAX_EVENTS = 20, 100
EVENTS_DEFAULT_PAGE, EVENTS_MAX_PAGE = 50, 200
MAX_FILTERS = 25

STATES = ("open", "in_progress", "open_new_data", "closed", "closed_true_positive", "closed_benign_true_positive",
          "closed_false_positive")
OPEN_STATES = ("open", "in_progress", "open_new_data")
CLOSED_STATES = ("closed", "closed_true_positive", "closed_benign_true_positive", "closed_false_positive")
STATE_SHORTCUTS = ("all", "unresolved", "closed_all")
DISPOSITIONS = ("false_positive", "true_positive", "benign_true_positive", "closed")
DISPOSITION_STATE = {"false_positive": "closed_false_positive", "true_positive": "closed_true_positive",
                     "benign_true_positive": "closed_benign_true_positive", "closed": "closed"}
AUTO_DISPOSITIONS = ("false_positive", "benign_true_positive")
#: Phrasings an analyst (or a model) uses for each disposition.
DISPOSITION_ALIASES = {
    "false_positive": "false_positive", "false positive": "false_positive", "fp": "false_positive",
    "true_positive": "true_positive", "true positive": "true_positive", "tp": "true_positive",
    "benign_true_positive": "benign_true_positive", "benign true positive": "benign_true_positive",
    "true_positive_benign": "benign_true_positive", "benign": "benign_true_positive",
    "sanctioned": "benign_true_positive",
    "closed": "closed", "close": "closed", "resolved": "closed", "resolve": "closed",
}
MODES = ("analyst_requested", "auto")
SEVERITY_NAMES = {"none": 0, "no_risk": 0, "no_risk_indicated": 0, "low": 1, "moderate": 2, "medium": 2, "high": 3,
                  "critical": 4}
EVENT_SEVERITIES = ("no_risk_indicated", "low", "moderate", "high", "critical")
ORDER_BY = ("end_time", "score")
FILTER_OPERATORS = ("IS", "IS_NOT", "IS_ANY", "IS_NONE", "EXISTS", "DOES_NOT_EXIST", "GREATER_THAN", "LESS_THAN",
                    "ON_OR_AFTER", "ON_OR_BEFORE", "CONTAINS", "DOES_NOT_CONTAIN")

SESSION_ID = r"[A-Za-z0-9_-]{6,64}"

TOOLS: list[dict] = [
    {
        "name": "irm_search_alerts",
        "description": (
            "Find insider-risk alerts. IMPORTANT DEFAULTS: only UNRESOLVED alerts from the LAST 7 DAYS. For any "
            "history question pass state \"all\" and a wider lookback_hours (720 = 30 days, 2160 = 90 days). Returns "
            "one compact row per alert: session_id, actor, current `state`, `state_set_by`, the full "
            "`state_history`, `auto_closed_by_agent`, risk_score, risk_severity (0-4), times, activity_summary, "
            "event_counts, every risk indicator name, triggered_rules, note_count and the platform's proposed "
            "disposition; plus total_count, has_more, actor_resolution and filters_applied. No destination identity: "
            "use irm_get_alert or irm_search_events for that. An empty result is not evidence that nothing happened. "
            "Read-only."),
        "input_schema": {"type": "object", "properties": {
            "actor": {"type": "string", "description": "The person's work email (resolved to the platform's actor)."},
            "state": {"type": "string", "description": "Comma-separated: " + ", ".join(STATES) + "; or 'all', "
                                                       "'unresolved' (default), 'closed_all'."},
            "min_severity": {"type": "string", "description": "Alert severity floor: 0-4 or low, moderate, high, "
                                                              "critical."},
            "lookback_hours": {"type": "number", "description": f"Default {DEFAULT_LOOKBACK} (7 days), max "
                                                                f"{MAX_LOOKBACK}."},
            "rule_id": {"type": "string", "description": "Alert rule id(s), comma-separated."},
            "watchlist_id": {"type": "string", "description": "Watchlist id(s), comma-separated."},
            "order_by": {"type": "string", "enum": list(ORDER_BY), "description": "Default score (descending)."},
            "page_number": {"type": "integer", "description": "0-based page."},
            "page_size": {"type": "integer", "description": f"Default {ALERTS_DEFAULT_PAGE}, max {ALERTS_MAX_PAGE}."},
        }},
    },
    {
        "name": "irm_get_alert",
        "description": (
            "Full detail on ONE insider-risk alert: current_state, state_history, state_set_by, risk score and "
            "severity (0-4), risk indicators, the rules that fired, existing analyst notes, the platform's proposed "
            "disposition and summary, and the highest-risk file events (sorted by risk, `events_truncated` flags a "
            "cut). Each event carries the destination identity (destination_user_emails, destination_account, "
            "destination_user_classification, browser_logged_in_user), paste sizes, file_acquired_from, "
            "source_tab_titles and destination_urls. Call it first for any alert you triage. Read-only."),
        "input_schema": {"type": "object", "properties": {
            "session_id": {"type": "string", "description": "The alert's id or its console link. Not an actor id."},
            "max_events": {"type": "integer", "description": f"Events to return, highest risk first (default "
                                                             f"{DEFAULT_EVENTS}, max {MAX_EVENTS}; 0 = alert detail "
                                                             "only)."}},
            "required": ["session_id"]},
    },
    {
        "name": "irm_search_events",
        "description": (
            "Search the insider-risk platform's file-event stream, including movement that never triggered an alert: "
            "\"what else did this person move?\", trace a file or hash, test whether an alert is the tail of "
            "something larger. A single value matches exactly; several (in `filters`) match any. Returns compact "
            "events (same destination-identity, paste and source fields as irm_get_alert) and a `summary` with "
            "top destinations, actions, actors, file categories, destination users and classifications, and total "
            "bytes / paste bytes. File-event severity is " + ", ".join(EVENT_SEVERITIES) + ". An empty result is not "
            "evidence that nothing happened. Read-only."),
        "input_schema": {"type": "object", "properties": {
            "actor": {"type": "string", "description": "The person's work email."},
            "lookback_hours": {"type": "number", "description": f"Default {DEFAULT_LOOKBACK} (7 days), max "
                                                                f"{MAX_LOOKBACK}."},
            "min_risk_severity": {"type": "string", "description": "low, moderate, high or critical (that level and "
                                                                   "above)."},
            "file_name": {"type": "string", "description": "Exact file name."},
            "file_category": {"type": "string", "description": "e.g. Document, Spreadsheet, SourceCode, Pdf, Image, "
                                                               "Archive."},
            "sha256": {"type": "string", "description": "64-hex SHA-256 of the file."},
            "destination_category": {"type": "string", "description": "e.g. Cloud Storage, Email, Social Media, "
                                                                      "Removable Media, AI Tools."},
            "destination_name": {"type": "string", "description": "e.g. a cloud storage service or an AI tool."},
            "destination_domain": {"type": "string", "description": "e.g. assistant.example.net."},
            "event_action": {"type": "string", "description": "e.g. file-uploaded, file-downloaded, "
                                                              "application-read, removable-media-created."},
            "untrusted_only": {"type": "boolean", "description": "Only events to untrusted destinations."},
            "page_size": {"type": "integer", "description": f"Default {EVENTS_DEFAULT_PAGE}, max {EVENTS_MAX_PAGE}."},
            "filters": {"type": "string", "description": f"Optional raw JSON array (max {MAX_FILTERS}) of {{\"term\", "
                                                         "\"operator\", \"value\"}: terms are the adapter's file-event "
                                                         "field names (documented in the adapter's tool description); operators "
                                                         + ", ".join(FILTER_OPERATORS) + "."},
        }},
    },
]

LIST_TOOLS: list[dict] = []

WRITE_TOOLS: list[dict] = [
    {
        "name": "irm_close_alert",
        "description": (
            "WRITE. Close ONE insider-risk alert and record why. Writes `note` to the alert FIRST (prefixed with a "
            "stamp naming the verified requester; never write who asked), then sets the closed state for "
            "`disposition`, then reads the alert back. Refuses an alert that is already closed, and can't reopen one. "
            "Returns `closed` only when the read-back shows the new state; `partial` when the note was written but "
            "the close isn't confirmed (state_confirmed false, confirmed_state = what the platform shows); `failed` "
            "when nothing was changed. Only after an analyst confirmed the disposition, or for an automatic close "
            "the brief enables (mode auto)."),
        "input_schema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "ONE alert id or its console link. Never a list."},
                "disposition": {"type": "string", "enum": list(DISPOSITIONS),
                                "description": "false_positive = the alerted activity did not happen as described or "
                                               "was misattributed; true_positive = genuine exfiltration / insider "
                                               "risk; benign_true_positive = real but sanctioned; closed = no "
                                               "verdict."},
                "note": {"type": "string", "description": f"{MIN_NOTE}-{MAX_NOTE} characters of plain text (not Slack "
                                                          "mrkdwn): the verdict, its confidence and the evidence. "
                                                          "Becomes the permanent audit trail."},
                "mode": {"type": "string", "enum": list(MODES),
                         "description": "analyst_requested (default): an analyst decided the disposition. auto: your "
                                        "own >=98% call, false_positive or benign_true_positive only, when the brief "
                                        "enables automatic closes."},
                "confidence": {"type": "number", "description": "Your confidence (0-100). Required for mode auto; "
                                                                "recorded in the note."},
            },
            "required": ["session_id", "disposition", "note"],
        },
    },
]

TOOL_NAMES = frozenset(t["name"] for t in TOOLS)
LIST_TOOL_NAMES = frozenset(t["name"] for t in LIST_TOOLS)
WRITE_TOOL_NAMES = frozenset(t["name"] for t in WRITE_TOOLS)
ALL_TOOL_NAMES = TOOL_NAMES | LIST_TOOL_NAMES | WRITE_TOOL_NAMES


def tool(name: str) -> dict[str, Any] | None:
    return next((t for t in TOOLS + LIST_TOOLS + WRITE_TOOLS if t["name"] == name), None)


def normalise_disposition(raw: Any) -> str | None:
    """A DISPOSITIONS value from an analyst's phrasing, or None."""
    s = str(raw or "").strip().lower()
    return DISPOSITION_ALIASES.get(s.replace("-", " ")) or DISPOSITION_ALIASES.get(s.replace("-", "_")) \
        or DISPOSITION_ALIASES.get(s.replace(" ", "_"))


# --- automatic actions on alert-bot posts ----------------------------------------------------------------------------

AUTO_ID_SHAPE = re.compile(SESSION_ID)
AUTO_NOTE = ("Automatic close (false_positive or benign_true_positive at 98% or higher, mode auto) is enabled for these "
             "alert IDs from the post: ")
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
    """Alert ids (group 1) that are the last path segment of a link under INSIDER_RISK_CONSOLE_URL (a fragment route
    such as <console>/app/#/alerts/<id> counts); a never-matching pattern when unset."""
    host = console_host(console_url)
    if not host:
        return _NEVER
    return re.compile(r"(?i:https?://" + re.escape(host) + r")/(?:[^\s<>|\"'`?]*/)?(" + SESSION_ID
                      + r")/?(?=$|[\s<>|\"'`?#),;\]]|\.(?:\s|$))")


def extract_session_id(value: Any) -> str:
    """The id in a bare id or a link (last path or fragment segment); "" when there is none."""
    s = str(value or "").strip()
    if re.match(r"(?i)https?://", s):
        try:
            parts = urlsplit(s)
        except ValueError:
            return ""
        segs = [p for p in (parts.path + "/" + parts.fragment).split("/") if p]
        s = segs[-1] if segs else ""
    return s if AUTO_ID_SHAPE.fullmatch(s) else ""


def auto_tools() -> list[dict]:
    return [{**t, "input_schema": json.loads(json.dumps(t.get("input_schema", {}))),
             "description": ("AUTOMATIC CLOSE ONLY. Closes an insider-risk alert from the alert bot's post: mode auto, "
                             "disposition false_positive or benign_true_positive, confidence >= 98. Anything else is "
                             "refused. " + t["description"])}
            for t in WRITE_TOOLS]


def auto_check(name: str, args: Any, allowed: frozenset[str]) -> tuple[list[str] | None, str | None]:
    """(["irm|close|<id>"], None) if within the automatic policy, else (None, reason)."""
    args = args if isinstance(args, dict) else {}
    raw_conf = args.get("confidence")
    try:
        conf = -1.0 if isinstance(raw_conf, bool) else float(raw_conf)
    except (TypeError, ValueError):
        conf = -1.0
    sid = extract_session_id(args.get("session_id"))
    disposition = str(args.get("disposition", "")).strip().lower()
    if name != "irm_close_alert":
        return None, "Alert-bot requests may only close automatically."
    if str(args.get("mode", "")).strip().lower() != "auto" or disposition not in AUTO_DISPOSITIONS \
            or not conf >= 98:
        return None, ("Automatic close needs mode auto, disposition false_positive or benign_true_positive and "
                      "confidence >= 98.")
    if not sid or sid not in allowed:
        return None, "Only alert IDs from the alert bot's own post can be closed automatically."
    return [f"irm|close|{sid}"], None


def auto_payload(name: str, args: Any) -> dict:
    """Unchanged: `confidence` is part of the schema and recorded in the note."""
    return args if isinstance(args, dict) else {}


def auto_requester(actor: str) -> str:
    """Names the alert bot in the alert note."""
    return f"{actor} (alert bot, automatic)"
