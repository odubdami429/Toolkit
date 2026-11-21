"""Brand protection: EXAMPLE write adapter (skeleton).

Implements the write interface (``WRITE_TOOLS``, ``LIST_TOOLS``, ``writer_from_env`` wrapping the read client,
``run_write_tool``) and re-exports the contract's automatic-action hooks, with ``AUTO_ID_PATTERN`` built from
``BRAND_PROTECTION_CONSOLE_URL``.

Validation is real (verified requester, one alert, ``state``, ``note`` length/placeholders/attribution, ``mode`` and
the automatic-mode limits); the vendor calls are stubs returning ``status: not_implemented`` with ``written: false``.

Dependencies: ``org`` and the standard library. Target: Python 3.12.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Callable, Mapping

from providers.brand_protection import contract
from providers.brand_protection import example as ex

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
_PLACEHOLDER_NOTE = re.compile(r"(?i)^(test|testing|n/?a|none|asdf|todo|tbd|placeholder|update|change)\b")
#: Who asked comes from the server, never the model: attribution the model wrote into its note is removed.
ATTRIBUTION = re.compile(r"(?i)\b(?:requested|asked|approved|authori[sz]ed|ordered|directed)\s+by\s+[^.;\n]{1,80}")


class ExampleWriter:
    """Wraps the read client (same credential and token cache). A real adapter's one write method refuses any other
    id shape or body before network I/O: exactly {state, comment} for one alert id."""

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
    e.result["written"] = False
    return e


def validate_update(args: dict, requester: str) -> dict:
    if not (isinstance(requester, str) and len(requester.strip()) >= 3):
        raise _no_write(ex.refused("No verified requester was supplied, so nothing can be written.",
                                   "Recommend the change instead; an authorized analyst can make it in the console."))
    aid = ex.alert_id(args.get("alert_id") if args.get("alert_id") not in (None, "") else args.get("id"))
    state = str(args.get("state") if args.get("state") not in (None, "") else args.get("queue_state") or "")
    state = state.strip().lower()
    if not state:
        raise ex.invalid(f"`state` is required and must be one of: {', '.join(contract.UPDATE_STATES)}.")
    if state not in contract.UPDATE_STATES:
        known = (f"'{state}' is a real queue state, but this tool is limited to archived and taken_down."
                 if state in contract.QUEUE_STATES else f"'{state[:40]}' is not a queue state.")
        raise ex.refused(f"{known} It can't reopen an alert, move it to in_review, needs_confirmation or monitoring, "
                         "or mark it actioned.", "A person can do that in the console. Nothing was written.")
    note_raw = args.get("note")
    if note_raw in (None, ""):
        note_raw = args.get("comment") if args.get("comment") not in (None, "") else args.get("reason")
    note = ATTRIBUTION.sub("", note_raw).strip(" ,;-") if isinstance(note_raw, str) else ""
    note = re.sub(r"\s{2,}", " ", note)
    if len(note) < contract.MIN_NOTE:
        raise ex.invalid(f"`note` is required (at least {contract.MIN_NOTE} characters). It's written to the alert as a "
                         "comment and is the only record of why the alert changed: say what was concluded and on what "
                         "evidence. Who asked is added by the tool; don't write it.")
    if _PLACEHOLDER_NOTE.match(note):
        raise ex.invalid("`note` looks like a placeholder. Write the real rationale; it's the permanent audit trail on "
                         "the alert.")
    note = note[:contract.MAX_NOTE]
    mode = str(args.get("mode") or "analyst_requested").strip().lower()
    if mode not in contract.MODES:
        raise ex.invalid(f"`mode` must be one of: {', '.join(contract.MODES)}.")
    confidence = None
    raw_conf = args.get("confidence")
    if raw_conf is not None and not isinstance(raw_conf, bool):
        try:
            n = float(raw_conf)
            if 0 <= n <= 100:
                confidence = int(n) if n == int(n) else round(n, 1)
        except (TypeError, ValueError):
            pass  # cosmetic field: never block a write over it
    if mode == "auto":
        if state == "taken_down":
            raise ex.refused("taken_down records that enforcement succeeded, which only a person can confirm. It's "
                             "never set automatically.", "Recommend it; set it only when an analyst asks.")
        verdict = re.sub(r"[\s-]+", "_", str(args.get("verdict") or "").strip().lower())
        if not verdict:
            raise ex.invalid("`verdict` is required for an automatic archive: archiving on your own determination is "
                             "only for a false positive. Pass verdict 'false_positive'.")
        if verdict not in contract.FP_VERDICTS:
            raise ex.refused(f"Refusing to archive automatically on verdict '{verdict[:40]}'. Only a false-positive "
                             "verdict may be archived on your own determination.",
                             "Recommend the disposition instead. Nothing was written.")
    return {"alert_id": aid, "state": state, "note": note, "mode": mode, "confidence": confidence,
            "requester": requester.strip()[:200]}


def comment_text(v: dict) -> str:
    """The comment written with the state change: a stamp naming the verified requester, then the note."""
    who = v["requester"]
    if v["state"] == "taken_down":
        head = f"{STAMP} taken_down - requested by {who} via Slack."
    elif v["mode"] == "analyst_requested":
        head = f"{STAMP} archived - close requested by {who} via Slack."
    elif v["confidence"] is not None:
        head = f"{STAMP} archived - false positive, {v['confidence']}% confidence (automatic, Jarvis review; {who})."
    else:
        head = f"{STAMP} archived - false positive, Jarvis determination (automatic; {who})."
    return f"{head} {v['note']}"[:contract.MAX_COMMENT]


def _update_alert(w: ExampleWriter, args: dict, requester: str) -> dict:
    v = validate_update(args, requester)
    comment = comment_text(v)
    # TODO: call your vendor API. Guardrails: read the alert first (current == target -> no_change; current not in
    # contract.ARCHIVE_FROM / TAKEDOWN_FROM -> refused; neither writes); ONE update carrying {state, comment}; a 5xx or
    # network error -> written null + outcome_unknown, never retried; confirm the state from the response or one
    # read-back before reporting `updated`, else `uncertain`.
    return {**ex.not_implemented("brand_update_alert"), "written": False, "alert_id": v["alert_id"], "to": v["state"],
            "mode": v["mode"], "requested_by": v["requester"], "comment": comment}


_DISPATCH: dict[str, Callable[[ExampleWriter, dict, str], dict]] = {"brand_update_alert": _update_alert}
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
                result = {"status": "error", "message": "Brand protection writes are not configured on this host.",
                          "next_step": "Recommend the change; an analyst can make it in the console."}
    except ex.ToolError as e:
        result = e.result
    except Exception as e:  # noqa: BLE001 - must never raise
        log.warning("brand write tool %s failed internally: %s", name, type(e).__name__)
        result = {"status": "error", "written": None, "outcome_unknown": True, "error_kind": "UNKNOWN",
                  "message": f"Internal tool error ({type(e).__name__}).",
                  "next_step": "It's unknown whether the alert changed. Check it with brand_get_alert before saying "
                               "more."}
    result.setdefault("written", False)
    return result
