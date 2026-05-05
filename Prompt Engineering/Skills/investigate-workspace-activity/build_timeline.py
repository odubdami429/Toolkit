#!/usr/bin/env python3
"""
Merge a user's pulled CSVs into a single chronological timeline of
material events — the kind that belong in an investigation report.
Drops noise (Drive views, every Gmail delivery, OAuth `activity`
refreshes) and keeps the narrative-shaping events.

Usage:
    python3 build_timeline.py user@companyDomain
    python3 build_timeline.py user@companyDomain --days 30 --start 2026-04-15 --end 2026-04-30
    python3 build_timeline.py user@companyDomain --format md   # markdown table for paste-in
"""

import argparse
import csv
import json
import os
import sys


DRIVE_KEEP = {
    "download", "copy", "export",
    "change_user_access", "change_acl_editors",
    "change_document_visibility", "change_document_access_scope",
    "transfer_ownership", "trash", "create",
}

LOGIN_KEEP = {
    "login_success", "login_failure", "suspicious_login",
    "login_verification", "2sv_disable", "2sv_enroll",
    "password_edit",
}

TOKEN_KEEP = {"authorize", "revoke", "deny"}

GMAIL_KEEP_EVENT_TYPES = {
    "email_forwarding_change", "filter_creation",
}


def user_subfolder(email):
    local = email.split("@", 1)[0]
    parts = [p for p in local.split(".") if p]
    if len(parts) >= 2:
        return f"{parts[0]}_{parts[-1]}_G_Logs"
    return f"{parts[0] if parts else 'user'}_G_Logs"


def read_csv(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        first = f.readline()
        if first.startswith("#"):
            return []
        f.seek(0)
        return list(csv.DictReader(f))


def in_window(t, start, end):
    if start and t < start:
        return False
    if end and t > end:
        return False
    return True


def material_drive(r):
    if r.get("event_name") not in DRIVE_KEEP:
        return None
    title = (r.get("doc_title") or "")[:60]
    target = (r.get("target_user") or "").strip()
    new_val = (r.get("new_value") or "").strip()
    desc = f"{r['event_name']}: '{title}'"
    if target:
        desc += f" → {target}"
    if new_val:
        desc += f" ({new_val[:30]})"
    return desc


def material_login(r):
    if r.get("event_name") not in LOGIN_KEEP:
        return None
    desc = f"{r['event_name']} from {r.get('ip_address','?')}"
    lt = r.get("login_type")
    if lt:
        desc += f" ({lt})"
    return desc


def material_token(r):
    if r.get("event_name") not in TOKEN_KEEP:
        return None
    app = r.get("app_name") or "(unnamed)"
    cid = r.get("client_id", "")[:50]
    scope = r.get("scope", "") or r.get("scope_data", "")
    desc = f"{r['event_name']}: app='{app}' client_id={cid}"
    if scope:
        desc += f" scope='{scope[:80]}'"
    return desc


def material_gmail(r):
    """Gmail Reports API is mostly inbound delivery; surface only
    forwarding / filter / unusual-event-type changes."""
    et = r.get("event_type") or ""
    en = r.get("event_name") or ""
    met = r.get("mail_event_type") or ""
    if (et in GMAIL_KEEP_EVENT_TYPES or en in GMAIL_KEEP_EVENT_TYPES
            or met in GMAIL_KEEP_EVENT_TYPES):
        fwd = r.get("forwarding_email") or r.get("destination_email") or ""
        return f"{en or et}: forwarding_email='{fwd}' mail_event_type='{met}'"
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("user")
    ap.add_argument("--logs-dir", default="logs")
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--start", help="ISO start (YYYY-MM-DD or full timestamp)")
    ap.add_argument("--end",   help="ISO end")
    ap.add_argument("--format", choices=["tsv", "md"], default="tsv")
    ap.add_argument("--out",
                    help="Output file. Default: <user_dir>/<user_slug>_timeline_<days>d.{tsv,md}")
    args = ap.parse_args()

    user_dir = os.path.join(args.logs_dir, user_subfolder(args.user))
    if not os.path.isdir(user_dir):
        sys.exit(f"No log folder for {args.user}: expected {user_dir}")

    user_slug = args.user.replace("@", "_at_").replace(".", "_")
    sources = {
        "drive": (os.path.join(user_dir, f"{user_slug}_drive_{args.days}d.csv"), material_drive),
        "login": (os.path.join(user_dir, f"{user_slug}_login_{args.days}d.csv"), material_login),
        "token": (os.path.join(user_dir, f"{user_slug}_token_{args.days}d.csv"), material_token),
        "gmail": (os.path.join(user_dir, f"{user_slug}_gmail_{args.days}d.csv"), material_gmail),
    }

    events = []
    for source_name, (path, materializer) in sources.items():
        rows = read_csv(path)
        for r in rows:
            if r.get("actor_impersonation") == "True":
                continue
            t = r.get("time", "")
            if not t or not in_window(t, args.start, args.end):
                continue
            desc = materializer(r)
            if not desc:
                continue
            events.append((t, source_name, desc, r.get("ip_address", "")))

    events.sort(key=lambda e: e[0])

    if args.out:
        out_path = args.out
    else:
        ext = "md" if args.format == "md" else "tsv"
        out_path = os.path.join(user_dir, f"{user_slug}_timeline_{args.days}d.{ext}")

    with open(out_path, "w") as f:
        if args.format == "md":
            f.write("| Time (UTC) | Source | IP | Event |\n")
            f.write("|---|---|---|---|\n")
            for t, src, desc, ip in events:
                safe_desc = desc.replace("|", "\\|")
                f.write(f"| {t} | {src} | {ip} | {safe_desc} |\n")
        else:
            f.write("time\tsource\tip\tdescription\n")
            for t, src, desc, ip in events:
                f.write(f"{t}\t{src}\t{ip}\t{desc}\n")

    print(f"User: {args.user}")
    print(f"Window: {args.start or '(start of pull)'} → {args.end or '(end of pull)'}")
    print(f"Material events: {len(events)}")
    print(f"Output: {out_path}")


if __name__ == "__main__":
    main()
