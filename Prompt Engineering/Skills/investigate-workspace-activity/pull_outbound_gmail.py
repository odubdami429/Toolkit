#!/usr/bin/env python3
"""
Surface outbound Gmail activity for a user from the existing gmail
audit CSV (pulled by pull_gmail_logs.py). The Reports API gmail
application is dominantly inbound (`delivery_type` events into the
user's UI); this script applies outbound heuristics on top of that
data and writes a filtered CSV plus a per-recipient-domain summary.

Heuristics for "outbound":
  - `flattened_destinations` does NOT begin with `gmail-ui::<subject>`
    (i.e. not a delivery into the subject's UI),
  - AND `flattened_destinations` contains at least one address that
    isn't the subject themselves,
  - AND `actor_email` matches the subject (when populated).

Limitations: if the Reports API didn't capture outbound for the
domain (some configs route outbound through different log paths),
this script will return 0 rows. In that case use admin-console
Email Log Search or Vault — see the printed note.

Usage:
    python3 pull_outbound_gmail.py user@companyDomain
    python3 pull_outbound_gmail.py user@companyDomain --days 30
    python3 pull_outbound_gmail.py user@companyDomain --refresh   # re-pull gmail first
"""

import argparse
import csv
import os
import subprocess
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
        return [], []
    with open(path) as f:
        first = f.readline()
        if first.startswith("#"):
            return [], []
        f.seek(0)
        reader = csv.DictReader(f)
        rows = list(reader)
        return rows, reader.fieldnames or []


def domain_of(addr):
    if "@" not in addr:
        return ""
    return addr.split("@", 1)[1].strip().lower().rstrip(">").rstrip(",")


def looks_outbound(row, subject):
    fd = (row.get("flattened_destinations") or "").lower()
    subj = subject.lower()
    if not fd:
        return False
    # Drop pure deliveries to subject's UI
    if fd.startswith(f"gmail-ui::{subj}"):
        return False
    # Need at least one non-subject @ address in destinations
    has_other = False
    for piece in fd.split(","):
        addr = piece.split("::", 1)[-1].strip()
        if addr and "@" in addr and addr != subj and "gmail-ui" not in addr:
            has_other = True
            break
    if not has_other:
        return False
    actor = (row.get("actor_email") or "").lower()
    if actor and actor != subj:
        return False
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("user")
    ap.add_argument("--logs-dir", default="logs")
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--refresh", action="store_true",
                    help="Re-run pull_gmail_logs.py before filtering")
    ap.add_argument("--out", help="Output CSV path (default in user dir)")
    args = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    user_dir = os.path.join(args.logs_dir, user_subfolder(args.user))
    user_slug = args.user.replace("@", "_at_").replace(".", "_")
    gmail_csv = os.path.join(user_dir, f"{user_slug}_gmail_{args.days}d.csv")

    if args.refresh or not os.path.exists(gmail_csv):
        print(f"Refreshing {gmail_csv} via pull_gmail_logs.py...", file=sys.stderr)
        rc = subprocess.run(
            [sys.executable, os.path.join(here, "pull_gmail_logs.py"),
             args.user, "--days", str(args.days), "--out", args.logs_dir],
            cwd=here,
        ).returncode
        if rc != 0:
            sys.exit(f"pull_gmail_logs.py failed (exit {rc})")

    rows, fields = read_csv(gmail_csv)
    if not rows:
        sys.exit(f"No rows in {gmail_csv}")

    outbound = [r for r in rows if looks_outbound(r, args.user)]
    out_path = args.out or os.path.join(
        user_dir, f"{user_slug}_gmail_outbound_{args.days}d.csv")

    if not outbound:
        with open(out_path, "w", newline="") as f:
            f.write("# no outbound events detected via heuristic\n")
        print(f"No outbound events found via Reports-API heuristic.")
        print()
        print("This is a known limitation: the gmail Reports API surfaces "
              "primarily inbound delivery events for the queried user. To "
              "audit outbound mail definitively, use one of:")
        print("  - Admin console -> Reporting -> Email Log Search (filter from:<user>)")
        print("  - Vault search across the user's Sent label")
        print("  - Gmail API messages.list with q='in:sent' (requires per-user auth)")
        print(f"\nWrote stub: {out_path}")
        return

    with open(out_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(outbound)

    # Per-domain summary
    by_dom = Counter()
    for r in outbound:
        fd = r.get("flattened_destinations") or ""
        for piece in fd.split(","):
            addr = piece.split("::", 1)[-1].strip().lower()
            d = domain_of(addr)
            if d and d != args.user.split("@", 1)[1].lower():
                by_dom[d] += 1

    print(f"Subject: {args.user}")
    print(f"Outbound events detected: {len(outbound)}")
    print(f"Output: {out_path}\n")
    print("Top recipient domains:")
    for d, c in by_dom.most_common(15):
        flag = " EXTERNAL" if d != "companyDomain" else ""
        print(f"  {c:>5}  {d}{flag}")


if __name__ == "__main__":
    main()
