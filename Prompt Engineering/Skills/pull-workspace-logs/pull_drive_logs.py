#!/usr/bin/env python3
"""
Pull all Drive (+ login) audit logs for a user and write CSV files
for downstream parsing by a Claude skill. OAuth/token events are
handled by pull_oauth_logs.py.

Output: one CSV file per application under --out. Nested parameters
(including messageValue.parameter[]) are flattened into columns. Any
extra parameters not in COMMON_PARAMS are preserved in
other_params_json (lossless).

Usage:
    python3 pull_drive_logs.py user@companyDomain [--days 30] [--out logs/]
    python3 pull_drive_logs.py user@companyDomain --apps drive
"""

import argparse
import csv
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone


DEFAULT_APPS = ["drive", "login"]


COMMON_PARAMS = [
    # Drive
    "doc_id", "doc_title", "doc_type", "owner", "visibility",
    "target_user", "new_value", "old_value", "actor_is_collaborator_account",
    "originating_app_id", "api_method",
    # Login
    "login_type", "login_challenge_method",
    # Token / OAuth
    "app_name", "client_id", "scope", "scope_data",
    # Gmail (email log search) + user_accounts
    "subject", "rfc2822_message_id", "source", "destination",
    "flattened_destinations", "payload_size", "num_message_attachments",
    "is_spam", "spam_info", "smtp_response_code", "action_type",
    "mail_event_type", "success",
    "forwarding_email", "destination_email",
]


def gws_pull(user, app, start_time, end_time=None, page_limit=100000):
    params = {
        "userKey": user,
        "applicationName": app,
        "startTime": start_time,
        "maxResults": 1000,
    }
    if end_time:
        params["endTime"] = end_time
    cmd = [
        "gws", "admin-reports", "activities", "list",
        "--params", json.dumps(params),
        "--page-all", "--page-limit", str(page_limit),
        "--format", "json",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(f"[gws error] app={app}: {proc.stderr.strip()[:300]}\n")
        return None, 0
    items = []
    pages = 0
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            page = json.loads(line)
        except json.JSONDecodeError:
            continue
        items.extend(page.get("items", []))
        pages += 1
    return items, pages


def param_value(p):
    for k in ("value", "boolValue", "intValue", "multiValue"):
        if k in p:
            v = p[k]
            return json.dumps(v) if isinstance(v, list) else v
    return ""


def flatten_params(parameters):
    """Flatten parameters (incl. nested messageValue.parameter arrays) into a dict."""
    out = {}
    for p in parameters or []:
        n = p.get("name")
        if "messageValue" in p and "parameter" in p["messageValue"]:
            nested = flatten_params(p["messageValue"]["parameter"])
            for k, v in nested.items():
                out.setdefault(k, v)
            continue
        if "multiMessageValue" in p:
            collected = [flatten_params(mv.get("parameter", []))
                         for mv in p["multiMessageValue"]]
            out[n] = json.dumps(collected)
            continue
        v = param_value(p)
        if v != "" or n not in out:
            out[n] = v
    return out


def flatten(items):
    rows = []
    for it in items:
        time = it.get("id", {}).get("time", "")
        unique_qualifier = it.get("id", {}).get("uniqueQualifier", "")
        actor = it.get("actor", {})
        app_info = actor.get("applicationInfo", {}) or {}
        ip = it.get("ipAddress", "")
        for ev in it.get("events", []):
            params = flatten_params(ev.get("parameters", []))
            row = {
                "time": time,
                "unique_qualifier": unique_qualifier,
                "actor_email": actor.get("email", ""),
                "actor_profile_id": actor.get("profileId", ""),
                "actor_app_name": app_info.get("applicationName", ""),
                "actor_oauth_client_id": app_info.get("oauthClientId", ""),
                "actor_impersonation": app_info.get("impersonation", False),
                "ip_address": ip,
                "event_type": ev.get("type", ""),
                "event_name": ev.get("name", ""),
            }
            for k in COMMON_PARAMS:
                row[k] = params.pop(k, "")
            row["other_params_json"] = json.dumps(params, sort_keys=True) if params else ""
            rows.append(row)
    return rows


def user_subfolder(email):
    """Derive `firstName_lastName_G_Logs` from an email's local part."""
    local = email.split("@", 1)[0]
    parts = [p for p in local.split(".") if p]
    if len(parts) >= 2:
        return f"{parts[0]}_{parts[-1]}_G_Logs"
    return f"{parts[0] if parts else 'user'}_G_Logs"


def write_csv(path, rows):
    if not rows:
        with open(path, "w") as f:
            f.write("# no events\n")
        return 0
    fields = list(rows[0].keys())
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    return len(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("user")
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--apps", default=",".join(DEFAULT_APPS),
                    help=f"Comma-separated apps (default: {','.join(DEFAULT_APPS)})")
    ap.add_argument("--out", default="logs",
                    help="Output directory (default: logs)")
    args = ap.parse_args()

    out_dir = os.path.join(args.out, user_subfolder(args.user))
    os.makedirs(out_dir, exist_ok=True)
    now = datetime.now(timezone.utc)
    start = (now - timedelta(days=args.days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    user_slug = args.user.replace("@", "_at_").replace(".", "_")

    print(f"User:   {args.user}")
    print(f"Window: last {args.days}d  ({start} -> {end})")
    print(f"Out:    {out_dir}/")

    manifest = {
        "user": args.user,
        "start_time": start,
        "end_time": end,
        "days": args.days,
        "files": {},
    }

    for app in [a.strip() for a in args.apps.split(",") if a.strip()]:
        print(f"\nPulling {app}...", end=" ", flush=True)
        items, pages = gws_pull(
            args.user, app, start,
            end_time=end if app == "gmail" else None,
        )
        out_path = os.path.join(out_dir, f"{user_slug}_{app}_{args.days}d.csv")
        if items is None:
            print(f"FAILED — leaving any existing {out_path} intact")
            manifest["files"][app] = {"path": out_path, "error": "pull failed"}
            continue
        rows = flatten(items)
        n = write_csv(out_path, rows)
        print(f"{len(items)} items -> {n} rows ({pages} pages) -> {out_path}")
        manifest["files"][app] = {
            "path": out_path,
            "items": len(items),
            "rows": n,
            "pages": pages,
        }

    manifest_path = os.path.join(out_dir, f"{user_slug}_drive_manifest_{args.days}d.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
    print(f"\nManifest: {manifest_path}")


if __name__ == "__main__":
    main()
