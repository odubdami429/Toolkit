#!/usr/bin/env python3
"""
Rank a user's top internal collaborators based on Drive sharing
events and Gmail delivery events. Helps decide who to pivot to
during an investigation.

Drive signal: target_user on access-change events authored by the
subject (sharing OUT to peer).
Gmail signal: peers who appear in flattened_destinations alongside
the subject (i.e. who they're co-recipients with on threads).

Usage:
    python3 top_collaborators.py user@companyDomain
    python3 top_collaborators.py user@companyDomain --days 30 --top 10
"""

import argparse
import csv
import os
import sys
from collections import Counter


def user_subfolder(email):
    local = email.split("@", 1)[0]
    parts = [p for p in local.split(".") if p]
    if len(parts) >= 2:
        return f"{parts[0]}_{parts[-1]}_G_Logs"
    return f"{parts[0] if parts else 'user'}_G_Logs"


def read_csv(path):
    if not os.path.exists(path):
        return []
    rows = []
    with open(path) as f:
        first = f.readline()
        if first.startswith("#"):
            return []
        f.seek(0)
        for r in csv.DictReader(f):
            rows.append(r)
    return rows


def is_internal(email):
    return email.lower().endswith("@companyDomain")


def collect_drive_targets(rows, subject):
    counts = Counter()
    for r in rows:
        if r.get("actor_email", "").lower() != subject.lower():
            continue
        if r.get("actor_impersonation") == "True":
            continue
        tgt = (r.get("target_user") or "").strip().lower()
        if tgt and "@" in tgt and tgt != subject.lower():
            counts[tgt] += 1
    return counts


def collect_gmail_corecipients(rows, subject):
    counts = Counter()
    for r in rows:
        fd = (r.get("flattened_destinations") or "").lower()
        if not fd or subject.lower() not in fd:
            continue
        for piece in fd.split(","):
            addr = piece.split("::", 1)[-1].strip()
            if (addr and "@" in addr and addr != subject.lower()
                    and "gmail-ui" not in addr):
                counts[addr] += 1
    return counts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("user")
    ap.add_argument("--logs-dir", default=os.path.expanduser("~/Documents/WorkspaceLogs"),
                    help="Parent directory containing <first>_<last>_G_Logs/")
    ap.add_argument("--days", type=int, default=30,
                    help="Window the CSVs were pulled at (used to find filenames)")
    ap.add_argument("--top", type=int, default=10)
    args = ap.parse_args()

    user_dir = os.path.join(args.logs_dir, user_subfolder(args.user))
    if not os.path.isdir(user_dir):
        sys.exit(f"No log folder for {args.user}: expected {user_dir}")

    user_slug = args.user.replace("@", "_at_").replace(".", "_")
    drive_csv = os.path.join(user_dir, f"{user_slug}_drive_{args.days}d.csv")
    gmail_csv = os.path.join(user_dir, f"{user_slug}_gmail_{args.days}d.csv")

    drive_rows = read_csv(drive_csv)
    gmail_rows = read_csv(gmail_csv)

    drive_counts = collect_drive_targets(drive_rows, args.user)
    gmail_counts = collect_gmail_corecipients(gmail_rows, args.user)

    combined = Counter()
    for k, v in drive_counts.items():
        combined[k] += v
    for k, v in gmail_counts.items():
        combined[k] += v

    print(f"Subject: {args.user}")
    print(f"Drive events from {drive_csv}: {len(drive_rows)} rows")
    print(f"Gmail events from {gmail_csv}: {len(gmail_rows)} rows")
    print()

    print(f"=== Top {args.top} collaborators (combined Drive shares + Gmail co-recipients) ===")
    print(f"{'rank':<4} {'peer':<45} {'total':<7} {'drive':<7} {'gmail':<7} {'internal':<10}")
    for i, (peer, total) in enumerate(combined.most_common(args.top), 1):
        d = drive_counts.get(peer, 0)
        g = gmail_counts.get(peer, 0)
        flag = "internal" if is_internal(peer) else "EXTERNAL"
        print(f"{i:<4} {peer[:45]:<45} {total:<7} {d:<7} {g:<7} {flag:<10}")

    print()
    print("=== External recipients only (often more interesting for exfil pivots) ===")
    ext = [(p, c) for p, c in combined.most_common() if not is_internal(p)]
    if not ext:
        print("  (none)")
    else:
        for peer, total in ext[:args.top]:
            d = drive_counts.get(peer, 0)
            g = gmail_counts.get(peer, 0)
            print(f"  {peer[:55]:<55} total={total:<5} drive={d:<5} gmail={g:<5}")


if __name__ == "__main__":
    main()
