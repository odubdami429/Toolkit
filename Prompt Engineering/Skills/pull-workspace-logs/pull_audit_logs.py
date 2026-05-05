#!/usr/bin/env python3
"""
Pull arbitrary Workspace audit applications for a user and write each
to its own CSV. Defaults cover drive, login, token, user_accounts,
gmail, and admin; override with --apps.

Usage:
    python3 pull_audit_logs.py user@companyDomain [--days 7] [--out ./audit_csv]
    python3 pull_audit_logs.py user@companyDomain --apps drive,login
"""

import argparse
import csv
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone


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
        return []
    items = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            page = json.loads(line)
        except json.JSONDecodeError:
            continue
        items.extend(page.get("items", []))
    return items


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
            collected = []
            for mv in p["multiMessageValue"]:
                collected.append(flatten_params(mv.get("parameter", [])))
            out[n] = json.dumps(collected)
            continue
        v = param_value(p)
        if v != "" or n not in out:
            out[n] = v
    return out


def user_subfolder(email):
    """Derive `firstName_lastName_G_Logs` from an email's local part."""
    local = email.split("@", 1)[0]
    parts = [p for p in local.split(".") if p]
    if len(parts) >= 2:
        return f"{parts[0]}_{parts[-1]}_G_Logs"
    return f"{parts[0] if parts else 'user'}_G_Logs"


def flatten(items):
    rows = []
    for it in items:
        time = it.get("id", {}).get("time", "")
        unique_qualifier = it.get("id", {}).get("uniqueQualifier", "")
        actor = it.get("actor", {})
        app_info = actor.get("applicationInfo", {}) or {}
        ip = it.get("ipAddress", "")
        for ev in it.get("events", []):
            ev_name = ev.get("name", "")
            ev_type = ev.get("type", "")
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
                "event_type": ev_type,
                "event_name": ev_name,
            }
            for k in COMMON_PARAMS:
                row[k] = params.pop(k, "")
            row["other_params_json"] = json.dumps(params, sort_keys=True) if params else ""
            rows.append(row)
    return rows


def write_csv(path, rows):
    if not rows:
        with open(path, "w", newline="") as f:
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
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--out", default=os.path.expanduser("~/Documents/WorkspaceLogs"))
    ap.add_argument("--apps", default="drive,login,token,user_accounts,gmail,admin",
                    help="Comma-separated list of applicationName values")
    args = ap.parse_args()

    out_dir = os.path.join(args.out, user_subfolder(args.user))
    os.makedirs(out_dir, exist_ok=True)
    now = datetime.now(timezone.utc)
    start = (now - timedelta(days=args.days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    user_slug = args.user.replace("@", "_at_").replace(".", "_")

    print(f"User:   {args.user}")
    print(f"Window: last {args.days}d (since {start})")
    print(f"Out:    {out_dir}")

    for app in [a.strip() for a in args.apps.split(",") if a.strip()]:
        print(f"\nPulling {app}...", end=" ", flush=True)
        # gmail Email Log Search requires both startTime and endTime
        items = gws_pull(args.user, app, start, end_time=end if app == "gmail" else None)
        rows = flatten(items)
        out_path = os.path.join(out_dir, f"{user_slug}_{app}_{args.days}d.csv")
        n = write_csv(out_path, rows)
        print(f"{len(items)} items -> {n} rows -> {out_path}")


if __name__ == "__main__":
    main()
