"""Insider risk: EXAMPLE write adapter (skeleton).

Implements the write interface (``WRITE_TOOLS``, ``LIST_TOOLS``, ``writer_from_env`` wrapping the read client,
``run_write_tool``) and re-exports the contract's automatic-action hooks, with ``AUTO_ID_PATTERN`` built from
``INSIDER_RISK_CONSOLE_URL``.

Validation is real (verified requester, ONE alert id, ``disposition``, ``note`` length/placeholders/attribution,
``mode`` and the automatic-mode limits); the vendor calls are stubs returning ``status: not_implemented`` with
``written: false``. The order a real implementation must follow is in ``_close_alert``: read first, note first, then
state, then read back.

Dependencies: ``org`` and the standard library. Target: Python 3.12.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Callable, Mapping

from providers.insider_risk import contract
from providers.insider_risk import example as ex

log = logging.getLogger(__name__)

WRITE_TOOLS = contract.WRITE_TOOLS
LIST_TOOLS = contract.LIST_TOOLS
WRITE_TOOL_NAMES = contract.WRITE_TOOL_NAMES

AUTO_ID_PATTERN = contract.make_auto_id_pattern(os.environ.get(f"{contract.PREFIX}_CONSOLE_URL"))
AUTO_ID_SHAPE = contract.AUTO_ID_SHAPE
AUTO_NOTE = contract.AUTO_NOTE
auto_tools = contract.auto_tools
auto_check = contract.auto_check
auto_payload = contract.auto_payload
auto_requester = contract.auto_requester

STAMP = "[Jarvis]"
_PLACEHOLDER_NOTE = re.compile(r"(?i)^(test|testing|n/?a|none|asdf|todo|tbd|placeholder|update|change|editor test|"
                               r"lorem ipsum)\b")
ATTRIBUTION = re.compile(r"(?i)\b(?:requested|asked|approved|authori[sz]ed|ordered|directed)\s+by\s+[^.;\n]{1,80}")


class ExampleWriter:
    """Wraps the read client (same credential and token cache). A real adapter's allowlist has exactly three
    routes: read one alert, add a note to one alert, change one alert's state to a closed state; bulk and
    close-by-criteria endpoints are refused by name."""

    def __init__(self, reader: ex.ExampleClient):
        self._reader = reader

    def __repr__(self) -> str:
        return f"{type(self).__name__}(base={self._reader.base_url!r}, credentials=<redacted>)"

    __str__ = __repr__

    def _secrets_for_scrub(self) -> list[str]:
        return self._reader._secrets_for_scrub()


def writer_from_env(env: Mapping[str, str], client: Any = None) -> ExampleWriter | None:
    return ExampleWriter(client) if isinstance(client, ex.ExampleClient) else None


def _no_write(e: ex.ToolError) -> ex.ToolError:
    e.result.update(written=False, note_attached=False, state_confirmed=False)
    return e


def validate_close(args: dict, requester: str) -> dict:
    if not (isinstance(requester, str) and len(requester.strip()) >= 3):
        raise _no_write(ex.refused("No verified requester was supplied, so nothing can be written.",
                                   "Recommend the close instead; an analyst can do it in the console."))
    raw_id = ex.first(args, ("session_id", "alert_id"))
    for k in ("session_ids", "alert_ids", "ids"):
        if args.get(k) not in (None, "", []):
            raise _no_write(ex.invalid("This tool closes one alert per call so every closure carries its own "
                                       "rationale: pass ONE `session_id`."))
    try:
        sid = ex.session_id(raw_id)
    except ex.ToolError as e:
        raise _no_write(e) from None
    raw = ex.first(args, ("disposition", "verdict"))
    if raw is None:
        raise _no_write(ex.invalid(f"`disposition` is required: one of {', '.join(contract.DISPOSITIONS)}."))
    disposition = contract.normalise_disposition(raw)
    if not disposition:
        s = str(raw).strip().lower().replace(" ", "_")
        if s in contract.OPEN_STATES:
            raise _no_write(ex.refused(f"'{s}' is an open state, but this tool only closes alerts. It can't reopen one "
                                       "or set open, in_progress or open_new_data.",
                                       "A person can do that in the console. Nothing was written."))
        raise _no_write(ex.invalid(f"`disposition` must be one of {', '.join(contract.DISPOSITIONS)}: false_positive = "
                                   "the activity did not happen as alerted, true_positive = real insider risk, "
                                   "benign_true_positive = real activity but sanctioned, closed = no verdict. Got: "
                                   f"'{str(raw)[:40]}'."))
    note_raw = ex.first(args, ("note", "justification", "reason", "comment"))
    note = ATTRIBUTION.sub("", note_raw).strip(" ,;-") if isinstance(note_raw, str) else ""
    note = re.sub(r"[ \t]{2,}", " ", note).strip()
    if len(note) < contract.MIN_NOTE:
        raise _no_write(ex.invalid(f"`note` is required (at least {contract.MIN_NOTE} characters of plain-text triage "
                                   "rationale). It is written to the alert as the audit trail BEFORE the alert is "
                                   "closed: give the verdict, its confidence and the evidence. Who asked is added by "
                                   "the tool; don't write it."))
    if len(note) > contract.MAX_NOTE:
        raise _no_write(ex.invalid(f"`note` is {len(note)} characters; the cap is {contract.MAX_NOTE}. Shorten it."))
    if _PLACEHOLDER_NOTE.match(note) or re.fullmatch(r"(.)\1{9,}", note.replace(" ", "")):
        raise _no_write(ex.invalid("`note` looks like a placeholder. Write the real rationale; it's the permanent audit "
                                   "trail on the alert."))
    mode = str(ex.first(args, ("mode",)) or "analyst_requested").strip().lower()
    if mode not in contract.MODES:
        raise _no_write(ex.invalid(f"`mode` must be one of: {', '.join(contract.MODES)}."))
    raw_conf = args.get("confidence")
    confidence = None
    if raw_conf is not None and not isinstance(raw_conf, bool):
        try:
            n = float(raw_conf)
            confidence = (int(n) if n == int(n) else round(n, 1)) if 0 <= n <= 100 else None
        except (TypeError, ValueError):
            confidence = None
    if mode == "auto":
        if confidence is None:
            raise _no_write(ex.invalid("`confidence` (a number 0-100) is required for an automatic close; it is "
                                       "recorded in the note."))
        if disposition not in contract.AUTO_DISPOSITIONS:
            raise _no_write(ex.refused(f"{disposition} is never set automatically: an automatic close is only for a "
                                       "high-confidence false_positive or benign_true_positive.",
                                       "Recommend the disposition instead. Nothing was written."))
    return {"session_id": sid, "disposition": disposition, "state": contract.DISPOSITION_STATE[disposition],
            "note": note, "mode": mode, "confidence": confidence, "requester": requester.strip()[:200]}


def note_text(v: dict) -> tuple[str, bool]:
    """(the note written to the alert, truncated?): a stamp naming the verified requester, then the rationale."""
    who = v["requester"]
    if v["mode"] == "auto":
        head = (f"{STAMP} Auto-closed {v['disposition']} at {v['confidence']}% confidence (automatic, Jarvis review; "
                f"{who}).")
    else:
        head = f"{STAMP} Closed {v['disposition']} on analyst request ({who})."
    room = contract.MAX_NOTE - len(head) - 1
    if len(v["note"]) > room:
        return f"{head} {v['note'][:room - 1]}…", True
    return f"{head} {v['note']}", False


def _close_alert(w: ExampleWriter, args: dict, requester: str) -> dict:
    v = validate_close(args, requester)
    text, truncated = note_text(v)
    # TODO: call your vendor API, in this order:
    #   1. READ the alert: not found -> not_found; current state in contract.CLOSED_STATES -> refused (never re-close);
    #      unknown state -> refused. Nothing written.
    #   2. NOTE FIRST: add `text`. If it fails, return `failed` (written false, or null on 5xx/network) WITHOUT
    #      changing the state.
    #   3. STATE: change to v["state"]. A 4xx -> `partial` (note written, state unchanged).
    #   4. READ BACK with back-off (e.g. 1 s, 2 s, 4 s); `closed` only when a read-back shows v["state"], else
    #      `partial` with outcome_unknown. Never retry the state change.
    return {**ex.not_implemented("irm_close_alert"), "written": False, "note_attached": False,
            "state_confirmed": False, "session_id": v["session_id"], "console_url": ex.console_url(v["session_id"]),
            "audit": {"mode": v["mode"], "requested_by": v["requester"], "reason": v["note"],
                      "to_state": v["state"], "disposition": v["disposition"], "confidence": v["confidence"],
                      "note_written": text, "note_truncated": truncated or None}}


_DISPATCH: dict[str, Callable[[ExampleWriter, dict, str], dict]] = {"irm_close_alert": _close_alert}
assert frozenset(_DISPATCH) == WRITE_TOOL_NAMES


def run_write_tool(w: ExampleWriter | None, name: str, args: Any, requester: str) -> dict:
    """Run the write tool. Never raises; always returns a dict with `status` and `written`."""
    fn = _DISPATCH.get(name) if isinstance(name, str) else None
    try:
        if fn is None:
            result = {"status": "error", "error_kind": "UNKNOWN_TOOL",
                      "message": f"Unknown tool {str(name)[:80]!r}. Available: {', '.join(_DISPATCH)}."}
        elif not isinstance(args, dict):
            result = ex.invalid("Tool input must be a JSON object.").result
        else:
            args = {k: val for k, val in args.items() if k not in ("requested_by", "requestedBy", "requester")}
            result = fn(w, args, str(requester or ""))
            if w is None and result.get("status") == "not_implemented":
                result = {"status": "error", "message": "Insider risk writes are not configured on this host.",
                          "next_step": "Recommend the close; an analyst can do it in the console."}
    except ex.ToolError as e:
        result = e.result
    except Exception as e:  # noqa: BLE001 - must never raise
        log.warning("irm write tool %s failed internally: %s", name, type(e).__name__)
        result = {"status": "error", "written": None, "outcome_unknown": True, "error_kind": "UNKNOWN",
                  "message": f"Internal tool error ({type(e).__name__}).",
                  "next_step": "It's unknown whether the alert changed. Check it with irm_get_alert before saying "
                               "more."}
    result.setdefault("written", False)
    return result
