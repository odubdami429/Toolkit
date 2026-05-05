#!/usr/bin/env python3
"""
List every IP address seen for a user across Workspace audit logs.

For each IP, reports: total events, first/last seen, which apps it
appeared in, and ASN if Google included one.

Usage:
    python3 user_ips.py user@companyDomain [--days 30] [--csv ips.csv]
"""

import argparse
import csv
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone


DEFAULT_APPS = ["drive", "login", "token", "gmail", "user_accounts", "admin"]
ENRICH_FIELDS = ["country", "region", "city", "org", "hostname"]


def load_cache(path):
    if path and os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def save_cache(path, cache):
    if not path:
        return
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cache, f, sort_keys=True)
    os.replace(tmp, path)


def lookup_ipinfo(ip, token=None, timeout=5):
    url = f"https://ipinfo.io/{ip}/json"
    if token:
        url += f"?token={token}"
    req = urllib.request.Request(url, headers={"User-Agent": "user-ips/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError) as exc:
        return {"error": str(exc)[:120]}
    return {k: data.get(k, "") for k in ENRICH_FIELDS}


def enrich_ips(ips, cache, cache_path, token, workers=8):
    todo = [ip for ip in ips if ip not in cache]
    if not todo:
        return
    print(f"  enriching {len(todo)} new IPs (cache hits: {len(ips) - len(todo)})...",
          file=sys.stderr)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for ip, info in zip(todo, ex.map(lambda i: lookup_ipinfo(i, token), todo)):
            cache[ip] = info
    save_cache(cache_path, cache)


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
        sys.stderr.write(f"[gws warn] app={app}: {proc.stderr.strip()[:200]}\n")
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


def user_subfolder(email):
    """Derive `firstName_lastName_G_Logs` from an email's local part."""
    local = email.split("@", 1)[0]
    parts = [p for p in local.split(".") if p]
    if len(parts) >= 2:
        return f"{parts[0]}_{parts[-1]}_G_Logs"
    return f"{parts[0] if parts else 'user'}_G_Logs"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("user")
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--apps", default=",".join(DEFAULT_APPS))
    ap.add_argument("--out", default=os.path.expanduser("~/Documents/WorkspaceLogs"),
                    help="Parent output directory (default: ~/Documents/WorkspaceLogs); "
                         "a firstName_lastName_G_Logs subfolder is created inside")
    ap.add_argument("--csv", help="Optional override for the output CSV path")
    ap.add_argument("--no-enrich", action="store_true",
                    help="Skip ipinfo.io enrichment")
    ap.add_argument("--cache", default=os.path.expanduser("~/Documents/WorkspaceLogs/.ipinfo_cache.json"),
                    help="Path to persistent IP enrichment cache (default: ~/Documents/WorkspaceLogs/.ipinfo_cache.json)")
    args = ap.parse_args()

    out_dir = os.path.join(args.out, user_subfolder(args.user))
    os.makedirs(out_dir, exist_ok=True)
    user_slug = args.user.replace("@", "_at_").replace(".", "_")
    if not args.csv:
        args.csv = os.path.join(out_dir, f"{user_slug}_ips_{args.days}d.csv")

    now = datetime.now(timezone.utc)
    start = (now - timedelta(days=args.days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    print(f"User:   {args.user}", file=sys.stderr)
    print(f"Window: last {args.days}d  (since {start})", file=sys.stderr)
    print(f"Out:    {args.csv}", file=sys.stderr)

    by_ip = defaultdict(lambda: {
        "count": 0,
        "first": None,
        "last": None,
        "apps": set(),
        "asn": set(),
        "is_proxy": False,
        "actors": set(),
    })

    for app in [a.strip() for a in args.apps.split(",") if a.strip()]:
        print(f"  pulling {app}...", end=" ", flush=True, file=sys.stderr)
        items = gws_pull(args.user, app, start, end_time=end if app == "gmail" else None)
        print(f"{len(items)} events", file=sys.stderr)
        for it in items:
            ip = it.get("ipAddress")
            if not ip:
                continue
            t = it.get("id", {}).get("time", "")
            entry = by_ip[ip]
            entry["count"] += 1
            entry["apps"].add(app)
            if entry["first"] is None or t < entry["first"]:
                entry["first"] = t
            if entry["last"] is None or t > entry["last"]:
                entry["last"] = t
            ni = it.get("networkInfo") or {}
            asn = ni.get("ipAsn")
            if isinstance(asn, list):
                for a in asn:
                    if a:
                        entry["asn"].add(str(a))
            elif asn:
                entry["asn"].add(str(asn))
            if ni.get("anonymousProxy"):
                entry["is_proxy"] = True
            actor = it.get("actor", {})
            app_name = actor.get("applicationInfo", {}).get("applicationName")
            entry["actors"].add(app_name or "(direct)")

    rows = sorted(by_ip.items(), key=lambda kv: kv[1]["count"], reverse=True)

    enrichment = {}
    if not args.no_enrich and rows:
        cache = load_cache(args.cache)
        token = os.environ.get("IPINFO_TOKEN")
        enrich_ips([ip for ip, _ in rows], cache, args.cache, token)
        enrichment = cache

    def info(ip, key):
        return (enrichment.get(ip) or {}).get(key, "") or ""

    print(f"\nTotal distinct IPs: {len(rows)}\n")
    header = (
        f"{'count':>6}  {'country':<3} {'city':<18} {'org':<32} "
        f"{'apps':<22} {'actor_via':<28} ip"
    )
    print(header)
    print("-" * len(header))
    for ip, e in rows:
        proxy_flag = " [PROXY]" if e["is_proxy"] else ""
        print(
            f"{e['count']:>6}  "
            f"{info(ip, 'country'):<3} "
            f"{info(ip, 'city')[:18]:<18} "
            f"{info(ip, 'org')[:32]:<32} "
            f"{','.join(sorted(e['apps']))[:22]:<22} "
            f"{','.join(sorted(e['actors']))[:28]:<28} "
            f"{ip}{proxy_flag}"
        )

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["ip", "count", "first_seen", "last_seen", "asn",
                        "country", "region", "city", "org", "hostname",
                        "apps", "actors", "anonymous_proxy"])
            for ip, e in rows:
                w.writerow([
                    ip, e["count"], e["first"] or "", e["last"] or "",
                    ",".join(sorted(e["asn"])),
                    info(ip, "country"), info(ip, "region"),
                    info(ip, "city"), info(ip, "org"), info(ip, "hostname"),
                    ",".join(sorted(e["apps"])),
                    ",".join(sorted(e["actors"])),
                    "true" if e["is_proxy"] else "false",
                ])
        print(f"\nWrote {args.csv}", file=sys.stderr)


if __name__ == "__main__":
    main()
