"""EDR: EXAMPLE write adapter (skeleton).

Implements the write interface from ``providers/__init__.py``: ``WRITE_TOOLS``, ``LIST_TOOLS`` (none),
``writer_from_env`` and ``run_write_tool``, plus the domain's automatic-action hooks re-exported from the contract
(``AUTO_ID_PATTERN`` built from ``EDR_CONSOLE_URL``, ``AUTO_ID_SHAPE``, ``AUTO_NOTE``, ``auto_tools``, ``auto_check``,
``auto_payload``, ``auto_requester``).

Generic validation is real: a verified requester, batch caps, ID and hash shapes, duplicate and placeholder checks,
justification/note lengths, the path-exclusion refusals and the one-endpoint rule. The vendor calls are stubs
returning ``status: not_implemented``; each carries the guardrail checklist the real call must keep.

Dependencies: ``org`` and the standard library. Target: Python 3.12.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Callable, Mapping

from providers.edr import contract
from providers.edr import example as ex

log = logging.getLogger(__name__)

WRITE_TOOLS = contract.WRITE_TOOLS
LIST_TOOLS = contract.LIST_TOOLS
WRITE_TOOL_NAMES = contract.WRITE_TOOL_NAMES

# Automatic actions (see the contract). The server reads these from this module.
AUTO_ID_PATTERN = contract.make_auto_id_pattern(os.environ.get(f"{contract.PREFIX}_CONSOLE_URL"))
AUTO_ID_SHAPE = contract.AUTO_ID_SHAPE
AUTO_NOTE = contract.AUTO_NOTE
auto_tools = contract.auto_tools
auto_check = contract.auto_check
auto_payload = contract.auto_payload
auto_requester = contract.auto_requester

NOT_IMPLEMENTED_NEXT_STEP = "Say this action isn't implemented in this deployment; nothing was changed."
_SHA1 = re.compile(r"[0-9a-f]{40}", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_MD5 = re.compile(r"[0-9a-f]{32}", re.ASCII)
_PLACEHOLDER = re.compile(r"^(test|testing|n/?a|none|asdf|todo|tbd|placeholder)\b", re.I | re.ASCII)
_ATTRIB = re.compile(r"[ \t\-,;:]*\b(?:requested\s+by|requester\s*[:=])\s*:?\s*\S+", re.I)

# Locations a path exclusion must never cover: anything written there would run unalerted.
_RISKY_POSIX = [re.compile(x, re.I) for x in (
    r"^/(private/)?tmp(/|$)", r"^/(private/)?var/tmp(/|$)", r"^/(private/)?var/folders(/|$)", r"^/dev/shm(/|$)",
    r"^/Users/Shared(/|$)", r"^/Volumes(/|$)", r"^/(media|mnt|run/media)(/|$)",
    r"^/(Users|home)/[^/]+/(Downloads|Desktop|Documents|Library/Caches|\.Trash|\.cache|tmp)(/|$)",
)]
_RISKY_WIN = [re.compile(x, re.I) for x in (
    r"^\\\\", r"^[a-z]:\\users\\public(\\|$)", r"^[a-z]:\\windows\\temp(\\|$)", r"^[a-z]:\\\$recycle\.bin(\\|$)",
    r"^[a-z]:\\users\\[^\\]+\\(downloads|desktop|documents)(\\|$)",
    r"^[a-z]:\\users\\[^\\]+\\appdata\\local\\temp(\\|$)", r"^[a-z]:\\programdata\\?$",
)]
# Trees too broad to exclude as a folder.
_BROAD_POSIX = [re.compile(x, re.I) for x in (
    r"^/(Applications|Library|System|System/Library|usr|usr/bin|usr/sbin|usr/lib|usr/local|usr/local/bin|bin|sbin"
    r"|opt|opt/homebrew|opt/homebrew/bin|etc|var|private|Users|home|root|Library/Application Support"
    r"|Library/LaunchAgents|Library/LaunchDaemons|Library/Frameworks)$",
    r"^/(Users|home)/[^/]+$",
    r"^/(Users|home)/[^/]+/(Library|\.local|\.local/bin|Applications|bin|go|\.npm|\.cargo)$",
)]
_BROAD_WIN = [re.compile(x, re.I) for x in (
    r"^[a-z]:$",
    r"^[a-z]:\\(windows|windows\\system32|windows\\syswow64|program files|program files \(x86\)|programdata|users)$",
    r"^[a-z]:\\users\\[^\\]+$",
    r"^[a-z]:\\users\\[^\\]+\\appdata(\\(local|roaming|locallow))?$",
)]


class ExampleWriter:
    """The writer: in a real adapter, a client whose role carries the write rights (keep them off the read client)."""

    def __init__(self, client: ex.ExampleClient):
        self._client = client

    def __repr__(self) -> str:
        return f"{type(self).__name__}(base={self._client.base_url!r}, credentials=<redacted>)"

    __str__ = __repr__

    def _secrets_for_scrub(self) -> list[str]:
        return self._client._secrets_for_scrub()


def writer_from_env(env: Mapping[str, str], client: Any = None) -> ExampleWriter | None:
    """The writer, or None when the read client (and so the tenant/credentials) isn't configured."""
    return ExampleWriter(client) if isinstance(client, ex.ExampleClient) else None


# --- input checks ----------------------------------------------------------------------------------------------------

def strip_attribution(s: str) -> str:
    """Drop any who-asked claim the model wrote; the verified requester is appended instead."""
    return re.sub(r"[ \t]{2,}", " ", _ATTRIB.sub("", s)).strip()


def attributed(s: str, requester: str, max_len: int | None = None) -> str:
    """Model text with the verified requester appended; with max_len the model's part is cut first."""
    suffix = f" [Requested by {requester} via Jarvis]"
    body = strip_attribution(s)
    if max_len is not None and len(body) > max_len - len(suffix):
        body = body[: max(0, max_len - len(suffix) - 1)] + "\u2026"
    return body + suffix


def justification(args: dict, what: str) -> str:
    j = args.get("justification")
    j = j.strip() if isinstance(j, str) else ""
    if len(j) < contract.MIN_JUSTIFICATION:
        raise ex.invalid(f"`justification` is required (>= {contract.MIN_JUSTIFICATION} characters): {what}. It is "
                         "the permanent audit trail.")
    if _PLACEHOLDER.search(j):
        raise ex.invalid("`justification` looks like a placeholder. Write the real rationale: it is the permanent "
                         "audit trail.")
    return j


def split_values(raw: Any, sep: str = r"[\s,;]+") -> list[str]:
    items = raw if isinstance(raw, list) else re.split(sep, ex.text(raw))
    return [s for s in (ex.text(x) for x in items) if s]


def os_type(args: dict) -> str:
    o = ex.text(args.get("os_type")).lower()
    if o not in contract.OS_TYPES:
        raise ex.invalid(f"`os_type` is required and must be one of: {', '.join(contract.OS_TYPES)} (got "
                         f"{o[:40]!r}). Use the OS of the endpoint the detection fired on.")
    return o


def hashes(args: dict, cap: int, algos: tuple[str, ...], verb: str) -> tuple[list[str], list[str]]:
    """(unique hashes, duplicates collapsed). Refuses MD5, other algorithms, malformed and placeholder hashes."""
    raw = [h.lower() for h in split_values(args.get("hashes"))]
    if not raw:
        raise ex.invalid(f"`hashes` is required: one or more file hashes ({'/'.join(a.upper() for a in algos)}) to "
                         f"{verb}.")
    unique = list(dict.fromkeys(raw))
    dupes = list(dict.fromkeys(h for i, h in enumerate(raw) if raw.index(h) != i))
    if len(unique) > cap:
        raise ex.invalid(f"Refusing {len(unique)} hashes in one call (max {cap}). Every entry is fleet-wide; split "
                         "into smaller analyst-reviewed batches.")
    md5 = [h for h in unique if _MD5.fullmatch(h)]
    if md5:
        raise ex.invalid(f"MD5 is not accepted: {', '.join(md5)}. Provide the "
                         f"{' or '.join(a.upper() for a in algos)} from the alert record; never convert or guess.")
    shapes = {"sha1": _SHA1, "sha256": _SHA256}
    wrong = [h for h in unique if not any(shapes[a].fullmatch(h) for a in algos)]
    if wrong:
        raise ex.invalid(f"Not valid {' or '.join(a.upper() for a in algos)} hashes: {', '.join(wrong)}.")
    degenerate = [h for h in unique if re.fullmatch(r"(.)\1+", h)]
    if degenerate:
        raise ex.invalid(f"Refusing placeholder hash(es): {', '.join(degenerate)}. Pass the real hash.")
    return unique, dupes


def validate_close(args: dict) -> dict:
    raw = args.get("alert_ids")
    if raw is None or raw == "" or raw == []:
        raise ex.invalid("`alert_ids` is required: a list of alert IDs (alert_id from edr_get_alert).")
    ids = [ex.text(i) for i in (raw if isinstance(raw, list) else [raw])]
    if len(ids) > contract.MAX_CLOSE_BATCH:
        raise ex.invalid(f"Refusing to close {len(ids)} alerts in one call (max {contract.MAX_CLOSE_BATCH}). Split "
                         "into smaller analyst-confirmed batches.")
    bad = [i or "(empty)" for i in ids if not contract.AUTO_ID_SHAPE.fullmatch(i)]
    if bad:
        raise ex.invalid(f"These do not look like alert IDs: {', '.join(x[:80] for x in bad)}")
    dupes = list(dict.fromkeys(i for n, i in enumerate(ids) if ids.index(i) != n))
    if dupes:
        raise ex.invalid(f"Duplicate alert_ids: {', '.join(dupes)}")
    verdict = ex.text(args.get("verdict")).lower()
    if verdict not in contract.CLOSE_VERDICTS:
        raise ex.invalid(f"`verdict` must be one of: {', '.join(contract.CLOSE_VERDICTS)} (got {verdict[:40]!r}).")
    note = args.get("note")
    note = note.strip() if isinstance(note, str) else ""
    if len(note) < contract.MIN_CLOSE_NOTE:
        raise ex.invalid(f"`note` is required (>= {contract.MIN_CLOSE_NOTE} characters of triage rationale): it "
                         "becomes the audit trail on the alert.")
    return {"alert_ids": ids, "verdict": verdict, "note": note}


def validate_hash_exclusion(args: dict) -> dict:
    hs, dupes = hashes(args, contract.MAX_EXCLUSION_HASHES, contract.EXCLUSION_HASH_ALGOS, "allowlist")
    o = os_type(args)
    j = justification(args, "what the file is, why it is benign, and the ticket")
    return {"hashes": hs, "os_type": o, "justification": j, "duplicates_collapsed": dupes}


def validate_hash_blocklist(args: dict) -> dict:
    hs, dupes = hashes(args, contract.MAX_BLOCKLIST_HASHES, ("sha1", "sha256"), "block")
    oses = [o.lower() for o in split_values(args.get("os_type"))]
    if not oses:
        raise ex.invalid(f"`os_type` is required: one or more of {', '.join(contract.OS_TYPES)}, or \"all\". A hash is "
                         "blocked per OS.")
    if "all" in oses:
        oses = list(contract.BLOCKLIST_ALL_OS)
    oses = list(dict.fromkeys(oses))
    bad = [o for o in oses if o not in contract.OS_TYPES]
    if bad:
        raise ex.invalid(f"Invalid `os_type` value(s): {', '.join(b[:40] for b in bad)}. Allowed: "
                         f"{', '.join(contract.OS_TYPES)}, or \"all\".")
    if len(hs) * len(oses) > contract.MAX_BLOCKLIST_ENTRIES:
        raise ex.invalid(f"{len(hs)} hash(es) x {len(oses)} OS = {len(hs) * len(oses)} entries, over the "
                         f"{contract.MAX_BLOCKLIST_ENTRIES} cap. Narrow the hashes or the OS list.")
    j = justification(args, "what the file is, the intel or detection proving it malicious, and the ticket")
    return {"hashes": hs, "os_types": oses, "justification": j, "duplicates_collapsed": dupes}


def _path_problem(orig: str, is_win: bool, path_type: str) -> tuple[str | None, str]:
    """(problem or None, normalised value)."""
    val = orig
    if re.search(r"[\x00-\x1f]", val):
        return "contains control characters", val
    if re.search(r"[*?]", val):
        return "wildcards (* ?) are not allowed; exclude the exact path", val
    if re.search(r"(^|[\\/])\.\.?([\\/]|$)", val):
        return "contains . or .. segments; pass the resolved absolute path", val
    if val.startswith("~") or re.search(r"%[^%]+%|\$[A-Za-z_{]", val):
        return "uses ~ or an environment variable; pass the expanded absolute path from the alert", val
    if re.search(r"\u2026|\.\.\.$", val):
        return "looks truncated; pass the full path", val
    sep = "\\" if is_win else "/"
    if is_win:
        val = val.replace("/", "\\")
        if not re.match(r"[a-z]:\\", val, re.I) and not val.startswith("\\\\"):
            return "not an absolute Windows path (expected C:\\...)", val
        if "\\\\" in val[2:]:
            return "contains an empty path segment", val
    else:
        if not val.startswith("/"):
            return "not an absolute path (must start with /)", val
        if "//" in val:
            return "contains an empty path segment", val
    if path_type == "file" and val.endswith(sep):
        return f"ends with {sep} but path_exclusion_type is \"file\"", val
    bare = val.rstrip("\\/")
    if not bare:
        return "is the filesystem root", val
    if any(rx.search(bare) for rx in (_RISKY_WIN if is_win else _RISKY_POSIX)):
        return ("is in a user-writable, temp, shared, removable or network location; use a hash exclusion for the "
                "specific file instead"), val
    segs = [s for s in bare.split(sep) if s]
    if path_type != "file":
        if any(rx.search(bare) for rx in (_BROAD_WIN if is_win else _BROAD_POSIX)) or len(segs) < (3 if is_win else 2):
            return (f"is too broad to exclude as a {path_type} tree; exclude the specific file or the app's own "
                    "folder"), val
        return None, bare + sep
    if len(segs) < 2:
        return "a file directly under the root is not a plausible target", val
    return None, bare


def validate_path_exclusion(args: dict) -> dict:
    o = os_type(args)
    is_win = o == "windows"
    path_type = ex.text(args.get("path_exclusion_type")).lower() or "file"
    if path_type not in contract.PATH_EXCLUSION_TYPES:
        raise ex.invalid(f"`path_exclusion_type` must be one of: {', '.join(contract.PATH_EXCLUSION_TYPES)} (default "
                         "file). Folder types only when the analyst explicitly asked to exclude a directory.")
    mode = ex.text(args.get("mode")).lower() or "suppress"
    if mode not in contract.PATH_EXCLUSION_MODES:
        raise ex.invalid(f"`mode` {mode[:40]!r} is not allowed from this tool: only suppress (alerts). Modes that "
                         "stop monitoring a path must be created by an analyst in the console.")
    paths = [re.sub(r"^[`\"'<]+|[`\"'>]+$", "", p).strip() for p in split_values(args.get("paths"), r"[\r\n|]+")]
    paths = [p for p in paths if p]
    if not paths:
        raise ex.invalid("`paths` is required: one or more absolute file paths exactly as on the alert. Separate "
                         "several with newlines, not commas.")
    problems, values = [], []
    for p in paths:
        why, value = _path_problem(p, is_win, path_type)
        if why:
            problems.append(f"'{p[:200]}': {why}")
        else:
            values.append(value)
    if problems:
        raise ex.invalid(f"Refusing {len(problems)} path(s):\n- " + "\n- ".join(problems))
    seen: set[str] = set()
    unique = []
    for v in values:  # windows and macos paths compare case-insensitively
        key = v if o == "linux" else v.lower()
        if key not in seen:
            seen.add(key)
            unique.append(v)
    if len(unique) > contract.MAX_EXCLUSION_PATHS:
        raise ex.invalid(f"Refusing {len(unique)} path exclusions in one call (max {contract.MAX_EXCLUSION_PATHS}). "
                         "Every path exclusion is a permanent fleet-wide gap; split into smaller batches.")
    j = justification(args, "what the file is and who signs it, why it is benign, and why a path and not a hash")
    return {"paths": unique, "os_type": o, "path_exclusion_type": path_type, "mode": mode, "justification": j}


def validate_endpoint(args: dict, verb: str) -> dict:
    raw = ex.first(args, ("endpoint", "device_id", "computer_name", "hostname"))
    if isinstance(raw, list):
        if len(raw) != 1:
            raise ex.invalid(f"Exactly one endpoint per call (got {len(raw)}). {verb} hosts one at a time so each is "
                             "confirmed individually.")
        raw = raw[0]
    target = ex.text(raw).strip("`\"'").strip()
    if not target:
        raise ex.invalid("`endpoint` is required: the device ID, the UUID, or the endpoint's exact computer name.")
    if re.search(r"[,;\n\r|]", target):
        raise ex.invalid(f"`endpoint` looks like a list ({target[:80]!r}). Exactly one endpoint per call.")
    if re.search(r"[*%?]", target):
        raise ex.invalid(f"`endpoint` {target[:80]!r} contains a wildcard. Give the exact computer name: this action "
                         "never targets a pattern.")
    if re.search(r"\u2026$|\.\.\.$", target):
        raise ex.invalid(f"`endpoint` {target[:80]!r} looks truncated. Give the full computer name or the device ID.")
    if re.search(r"[\x00-\x1f\x7f]", target):
        raise ex.invalid("`endpoint` contains control characters.")
    if not contract.MIN_ENDPOINT_NAME <= len(target) <= contract.MAX_ENDPOINT_NAME:
        raise ex.invalid(f"`endpoint` {target[:80]!r} is not a plausible device ID or computer name "
                         f"({contract.MIN_ENDPOINT_NAME}-{contract.MAX_ENDPOINT_NAME} characters).")
    return {"endpoint": target}


# --- tools (stubs) ---------------------------------------------------------------------------------------------------

def _stub(name: str, requester: str, **validated: Any) -> dict:
    return {"status": "not_implemented", "tool": name,
            "message": f"{name} is not implemented by the example EDR adapter. Nothing was changed.",
            "next_step": NOT_IMPLEMENTED_NEXT_STEP, "validated": validated, "requested_by": requester}


def _close_alert(w: ExampleWriter, p: dict, requester: str, ctx: dict) -> dict:
    v = validate_close(p)
    v["note"] = attributed(v["note"], requester)
    # TODO: call your vendor API. Checklist:
    # [ ] one request that sets the verdict and resolves exactly these IDs (the filter lists the IDs, nothing broader)
    # [ ] attach `note` (already attributed) to each alert; a failed note is note_attached: false, not a failure
    # [ ] IDs that matched no open alert -> `not_found` / `skipped`; never report them as closed
    # [ ] timeout or 5xx after sending -> status error, outcome_unknown: true, "verify with edr_get_alert"
    return _stub("edr_close_alert", requester, **v)


def _add_hash_exclusion(w: ExampleWriter, p: dict, requester: str, ctx: dict) -> dict:
    v = validate_hash_exclusion(p)
    v["description"] = attributed(v["justification"], requester, contract.MAX_DESCRIPTION)
    # TODO: call your vendor API. Checklist:
    # [ ] read the existing exclusion list for these hashes + OS first; if that read fails, REFUSE (create nothing)
    # [ ] skip hashes already excluded (report in `skipped` with who added them and when); add-only, never edit/delete
    # [ ] one create per remaining hash, scoped fleet-wide as the contract says; stop at the time budget
    # [ ] report created / skipped / failed / unknown; status ok | partial | failed | error
    return _stub("edr_add_hash_exclusion", requester, **v)


def _add_hash_blocklist(w: ExampleWriter, p: dict, requester: str, ctx: dict) -> dict:
    v = validate_hash_blocklist(p)
    v["description"] = attributed(v["justification"], requester, contract.MAX_DESCRIPTION)
    # TODO: call your vendor API. Checklist:
    # [ ] read the existing blocklist for these hashes first; if that read fails, REFUSE (create nothing)
    # [ ] skip hash+OS pairs already blocked; add-only; one entry per hash x OS (<= MAX_BLOCKLIST_ENTRIES)
    # [ ] never retried; report created / skipped / failed / unknown
    return _stub("edr_add_hash_blocklist", requester, **v)


def _add_path_exclusion(w: ExampleWriter, p: dict, requester: str, ctx: dict) -> dict:
    v = validate_path_exclusion(p)
    v["description"] = attributed(v["justification"], requester, contract.MAX_DESCRIPTION)
    # TODO: call your vendor API. Checklist:
    # [ ] read existing path exclusions first (case-insensitive compare except on linux); refuse if the read fails
    # [ ] skip paths already excluded; add-only; mode is always suppress-alerts
    # [ ] report created / skipped / failed / unknown
    return _stub("edr_add_path_exclusion", requester, **v)


def _network_contain(w: ExampleWriter, p: dict, requester: str, ctx: dict) -> dict:
    v = validate_endpoint(p, "Contain")
    v["justification"] = attributed(justification(p, "why this endpoint must be isolated (the alert ID or "
                                                     "activity)"), requester)
    v["confirm_server"] = ex.truthy(p.get("confirm_server"))
    # TODO: call your vendor API. Checklist:
    # [ ] resolve the endpoint: exact device ID / UUID / full computer name; no exact match, several live matches, or
    #     only decommissioned devices -> refuse (status error, "Nothing was contained")
    # [ ] a server (contract.SERVER_MACHINE_TYPES) without confirm_server -> refuse
    # [ ] already contained -> already_contained (no request)
    # [ ] the action's filter names that ONE device ID only: never a name, group, site or any fleet-matching filter
    # [ ] affected > 1 -> status error, message starting "ALARM: ..." (reproduced verbatim); affected 0 -> failed
    # [ ] best-effort read-back: contained | pending; timeout/5xx -> outcome_unknown; never retried
    return _stub("edr_network_contain", requester, **v)


def _initiate_scan(w: ExampleWriter, p: dict, requester: str, ctx: dict) -> dict:
    v = validate_endpoint(p, "Scan")
    v["justification"] = attributed(justification(p, "why this host needs a full disk scan (the alert ID or "
                                                     "activity)"), requester)
    # TODO: call your vendor API. Checklist:
    # [ ] resolve exactly ONE live device as for containment; refuse otherwise
    # [ ] a scan already running -> already_running (no request)
    # [ ] filter names that ONE device ID; affected > 1 -> "ALARM" error; affected 0 -> failed
    # [ ] started | requested; never retried (a second call can start a second scan)
    return _stub("edr_initiate_scan", requester, **v)


def _on_error(e: ex.ToolError, p: dict, ctx: dict, requester: str) -> dict:
    return e.result


#: name -> (tool, error formatter). tool(writer, args, requester, ctx) -> dict.
_DISPATCH: dict[str, tuple[Callable[..., dict], Callable[..., dict] | None]] = {
    "edr_close_alert": (_close_alert, _on_error),
    "edr_add_hash_exclusion": (_add_hash_exclusion, _on_error),
    "edr_add_hash_blocklist": (_add_hash_blocklist, _on_error),
    "edr_add_path_exclusion": (_add_path_exclusion, _on_error),
    "edr_network_contain": (_network_contain, _on_error),
    "edr_initiate_scan": (_initiate_scan, _on_error),
}
assert frozenset(_DISPATCH) == WRITE_TOOL_NAMES


def run_write_tool(w: ExampleWriter | None, name: str, args: Any, requester: str) -> dict:
    """Run one write tool. Never raises. ``requester`` is the verified requester the server supplies ("email (U…)",
    or ``auto_requester(actor)`` for automatic closes); any requested_by argument from the model is ignored."""
    entry = _DISPATCH.get(name) if isinstance(name, str) else None
    requester = str(requester or "").strip()[:200] if isinstance(requester, str) else ""
    try:
        if entry is None:
            result = {"status": "error", "error_kind": "UNKNOWN_TOOL",
                      "message": f"Unknown tool {str(name)[:80]!r}. Available: {', '.join(_DISPATCH)}."}
        elif not requester:
            result = {"status": "refused", "message": "No verified requester for this write; nothing was sent.",
                      "next_step": "Say the action could not be attributed to a verified analyst and was not "
                                   "performed. Recommend it instead."}
        elif not isinstance(args, dict):
            result = ex.invalid("Tool input must be a JSON object.").result
        else:
            fn, on_error = entry
            p = {k: v for k, v in args.items() if k not in ("requested_by", "requestedBy", "requester")}
            try:
                result = fn(w, p, requester, {})
            except ex.ToolError as e:
                result = on_error(e, p, {}, requester) if on_error else e.result
            if w is None and result.get("status") == "not_implemented":
                result = {"status": "error", "message": "EDR writes are not configured on this host.",
                          "next_step": "Recommend the action; an analyst can take it in the EDR console."}
    except Exception as e:  # noqa: BLE001 - run_write_tool must never raise
        log.warning("edr write tool %s failed internally: %s", name, type(e).__name__)
        result = {"status": "error", "error_kind": "UNKNOWN", "message": f"Internal tool error ({type(e).__name__}).",
                  "next_step": "Say the action failed; verify the target's state with a read before saying anything "
                               "changed."}
    if isinstance(result, dict) and name in WRITE_TOOL_NAMES:
        result.setdefault("requested_by", requester or None)
    return result
