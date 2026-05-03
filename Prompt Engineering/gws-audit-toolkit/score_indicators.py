#!/usr/bin/env python3
"""
Apply the investigate-workspace-activity skill's risk-indicator
catalog to a user's pulled CSVs. Emits JSON of triggered indicators
ranked by severity, plus a list of indicators explicitly checked but
where no evidence was found.

The output is meant to feed directly into the investigation report.

Usage:
    python3 score_indicators.py user@companyDomain
    python3 score_indicators.py user@companyDomain --days 30 --out findings.json
"""

import argparse
import csv
import datetime as dt
import json
import os
import re
import sys
from collections import Counter, defaultdict


FREE_EMAIL_DOMAINS = {
    "gmail.com", "outlook.com", "hotmail.com", "live.com",
    "proton.me", "protonmail.com", "icloud.com", "me.com",
    "yahoo.com", "yahoo.co.uk", "aol.com", "ya.ru", "mail.ru",
    "tutanota.com", "fastmail.com", "pm.me", "duck.com",
}

BROAD_OAUTH_SCOPES = [
    "https://www.googleapis.com/auth/drive",          # full Drive
    "https://mail.google.com/",                       # full Gmail
    "https://www.googleapis.com/auth/gmail.readonly", # all mail read
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.compose",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/admin.directory",
    "https://www.googleapis.com/auth/contacts",
]

DRIVE_EXFIL_EVENTS = {"download", "copy", "export"}
DRIVE_BURST_THRESHOLD = 50          # events
DRIVE_BURST_WINDOW_SEC = 3600       # 1 hour
GMAIL_LARGE_PAYLOAD = 25_000_000    # 25 MB


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


def parse_iso(t):
    try:
        return dt.datetime.strptime(t[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.timezone.utc)
    except (ValueError, TypeError):
        return None


def domain_of(addr):
    if "@" not in addr:
        return ""
    return addr.split("@", 1)[1].strip().lower().rstrip(">").rstrip(",")


def load_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        return json.load(open(path))
    except json.JSONDecodeError:
        return default


def is_sanctioned(client_id, app_name, sanctioned):
    cid = (client_id or "").strip().lower()
    name = (app_name or "").strip().lower()
    for app in sanctioned.get("apps", []):
        if cid and app.get("client_id", "").lower() == cid:
            return True
        if name and app.get("name", "").lower() == name:
            return True
    return False


def matches_baseline(country, org, baseline_entry):
    if not baseline_entry:
        return None  # unknown
    if country in (baseline_entry.get("expected_countries") or []):
        return True
    expected_orgs = baseline_entry.get("expected_orgs_substring") or []
    for sub in expected_orgs:
        if sub.lower() in (org or "").lower():
            return True
    return False


# --- Per-source scorers ---

def score_drive(rows, subject):
    findings = []
    rows = [r for r in rows
            if r.get("actor_email", "").lower() == subject.lower()
            and r.get("actor_impersonation") != "True"]

    # Mass burst of download/copy/export
    exfil = sorted(
        [(parse_iso(r["time"]), r) for r in rows
         if r.get("event_name") in DRIVE_EXFIL_EVENTS and parse_iso(r["time"])],
        key=lambda x: x[0]
    )
    if exfil:
        max_burst, burst_window = 0, []
        for i in range(len(exfil)):
            j = i
            while j < len(exfil) and (exfil[j][0] - exfil[i][0]).total_seconds() <= DRIVE_BURST_WINDOW_SEC:
                j += 1
            n = j - i
            if n > max_burst:
                max_burst = n
                burst_window = exfil[i:j]
        if max_burst >= DRIVE_BURST_THRESHOLD:
            findings.append({
                "severity": "HIGH",
                "category": "Drive",
                "indicator": "Mass download/export/copy burst",
                "detail": f"{max_burst} events within 1 hour starting {burst_window[0][0].isoformat()}",
                "evidence_count": max_burst,
                "samples": [{"time": r[1]["time"], "event": r[1]["event_name"],
                             "doc_title": r[1].get("doc_title", "")[:80]}
                            for r in burst_window[:5]],
            })

    # External shares
    ext_shares = []
    for r in rows:
        tgt = (r.get("target_user") or "").strip().lower()
        if (r.get("event_name") in {"change_user_access", "change_acl_editors", "transfer_ownership"}
                and tgt and "@" in tgt and "companyDomain" not in tgt):
            ext_shares.append(r)
    free_provider_shares = [r for r in ext_shares if domain_of(r["target_user"]) in FREE_EMAIL_DOMAINS]
    if free_provider_shares:
        findings.append({
            "severity": "HIGH",
            "category": "Drive",
            "indicator": "Drive share to free email provider",
            "detail": f"{len(free_provider_shares)} share(s) to free providers (gmail.com, outlook.com, etc.)",
            "evidence_count": len(free_provider_shares),
            "samples": [{"time": r["time"], "doc_title": r.get("doc_title", "")[:80],
                         "target": r["target_user"], "new_value": r.get("new_value", "")}
                        for r in free_provider_shares[:5]],
        })
    other_external = [r for r in ext_shares if r not in free_provider_shares]
    if other_external:
        findings.append({
            "severity": "MED",
            "category": "Drive",
            "indicator": "Drive share to non-companyName external recipient",
            "detail": f"{len(other_external)} share(s) to non-companyName domains",
            "evidence_count": len(other_external),
            "samples": [{"time": r["time"], "doc_title": r.get("doc_title", "")[:80],
                         "target": r["target_user"]} for r in other_external[:5]],
        })

    # Ownership transfer (any external)
    transfers = [r for r in rows if r.get("event_name") == "transfer_ownership"]
    ext_transfers = [r for r in transfers
                     if (r.get("target_user") or "").lower() and "companyDomain" not in (r.get("target_user") or "").lower()
                     and "@" in (r.get("target_user") or "")]
    if ext_transfers:
        findings.append({
            "severity": "HIGH",
            "category": "Drive",
            "indicator": "Ownership transfer to external account",
            "detail": f"{len(ext_transfers)} transfer(s)",
            "evidence_count": len(ext_transfers),
            "samples": [{"time": r["time"], "doc_title": r.get("doc_title", "")[:80],
                         "target": r["target_user"]} for r in ext_transfers[:5]],
        })
    return findings


def score_gmail(rows, subject):
    findings = []
    # Forwarding rule changes — top compromise signal
    fwd = []
    for r in rows:
        if r.get("actor_impersonation") == "True":
            continue
        met = r.get("mail_event_type") or ""
        en = r.get("event_name") or ""
        if ("forward" in met.lower() or "forward" in en.lower()
                or r.get("forwarding_email") or r.get("destination_email")):
            fwd.append(r)
    if fwd:
        findings.append({
            "severity": "HIGH",
            "category": "Gmail",
            "indicator": "Auto-forwarding rule added or modified",
            "detail": f"{len(fwd)} forwarding-related event(s)",
            "evidence_count": len(fwd),
            "samples": [{"time": r["time"], "event_name": r.get("event_name", ""),
                         "mail_event_type": r.get("mail_event_type", ""),
                         "forwarding_email": r.get("forwarding_email") or r.get("destination_email", "")}
                        for r in fwd[:5]],
        })

    # Outbound to free providers (heuristic; many gmail Reports datasets are
    # inbound-only — see investigation report caveats)
    outbound_to_free = []
    big_to_external = []
    for r in rows:
        fd = (r.get("flattened_destinations") or "").lower()
        # subject-as-source hint
        src = (r.get("source") or "").lower()
        looks_outbound = subject.lower() in src or (
            subject.lower() not in fd and "gmail-ui" not in fd and fd
        )
        if not looks_outbound:
            continue
        for piece in fd.split(","):
            addr = piece.split("::", 1)[-1].strip()
            d = domain_of(addr)
            if d in FREE_EMAIL_DOMAINS:
                outbound_to_free.append(r)
                break
        try:
            ps = int(r.get("payload_size") or 0)
        except ValueError:
            ps = 0
        if ps >= GMAIL_LARGE_PAYLOAD:
            ext_dest = any(
                domain_of(p.split("::", 1)[-1].strip()) and
                "companyDomain" not in p
                for p in fd.split(",") if p.strip()
            )
            if ext_dest:
                big_to_external.append((ps, r))

    if outbound_to_free:
        findings.append({
            "severity": "MED",
            "category": "Gmail",
            "indicator": "Outbound mail to free email providers",
            "detail": f"{len(outbound_to_free)} message(s) to gmail/outlook/proton/etc.",
            "evidence_count": len(outbound_to_free),
            "samples": [{"time": r["time"], "subject": (r.get("subject") or "")[:60],
                         "destinations": (r.get("flattened_destinations") or "")[:120]}
                        for r in outbound_to_free[:5]],
        })
    if big_to_external:
        big_to_external.sort(reverse=True)
        findings.append({
            "severity": "HIGH",
            "category": "Gmail",
            "indicator": "Large outbound payload to external recipient",
            "detail": f"{len(big_to_external)} message(s) ≥25MB to external",
            "evidence_count": len(big_to_external),
            "samples": [{"time": r["time"], "payload_size": ps,
                         "subject": (r.get("subject") or "")[:60],
                         "destinations": (r.get("flattened_destinations") or "")[:120]}
                        for ps, r in big_to_external[:5]],
        })

    return findings


def score_token(rows, subject, sanctioned):
    findings = []
    auth = [r for r in rows if r.get("event_name") == "authorize"]

    # Unfamiliar (app, client_id) pairs
    seen = defaultdict(list)
    for r in auth:
        seen[(r.get("app_name", ""), r.get("client_id", ""))].append(r)
    unfamiliar = []
    broad_unfamiliar = []
    scope_re = re.compile(r"https?://[^\s\"',\[\]]+")
    for (app, cid), evts in seen.items():
        if is_sanctioned(cid, app, sanctioned):
            continue
        scopes_text = " ".join((e.get("scope", "") + " " + e.get("scope_data", "")) for e in evts)
        granted_scopes = {s.lower() for s in scope_re.findall(scopes_text)}
        is_broad = any(s.lower() in granted_scopes for s in BROAD_OAUTH_SCOPES)
        record = {
            "app_name": app,
            "client_id": cid,
            "events": len(evts),
            "first_seen": min(e["time"] for e in evts),
            "last_seen": max(e["time"] for e in evts),
            "scope_sample": (evts[0].get("scope") or evts[0].get("scope_data") or "")[:200],
            "is_broad_scope": is_broad,
        }
        if is_broad:
            broad_unfamiliar.append(record)
        else:
            unfamiliar.append(record)

    if broad_unfamiliar:
        findings.append({
            "severity": "HIGH",
            "category": "OAuth",
            "indicator": "New OAuth grant with broad scope (mail/drive/admin) to unsanctioned app",
            "detail": f"{len(broad_unfamiliar)} unsanctioned app(s) with broad scopes",
            "evidence_count": sum(r["events"] for r in broad_unfamiliar),
            "samples": broad_unfamiliar[:5],
        })
    if unfamiliar:
        findings.append({
            "severity": "MED",
            "category": "OAuth",
            "indicator": "OAuth grant to unsanctioned app",
            "detail": f"{len(unfamiliar)} app(s) not in sanctioned_apps.json",
            "evidence_count": sum(r["events"] for r in unfamiliar),
            "samples": unfamiliar[:5],
        })

    # Revokes — informational, low severity
    revokes = [r for r in rows if r.get("event_name") == "revoke"]
    if revokes:
        findings.append({
            "severity": "LOW",
            "category": "OAuth",
            "indicator": "OAuth grants revoked",
            "detail": f"{len(revokes)} revoke event(s)",
            "evidence_count": len(revokes),
            "samples": [{"time": r["time"], "app_name": r.get("app_name", ""),
                         "client_id": r.get("client_id", "")[:60]} for r in revokes[:5]],
        })
    return findings


def score_login(rows, subject, baseline_entry, ips_by_addr):
    findings = []

    suspicious = [r for r in rows if r.get("event_name") == "suspicious_login"]
    if suspicious:
        findings.append({
            "severity": "HIGH",
            "category": "Login",
            "indicator": "suspicious_login event",
            "detail": f"{len(suspicious)} event(s)",
            "evidence_count": len(suspicious),
            "samples": [{"time": r["time"], "ip": r.get("ip_address", "")} for r in suspicious[:5]],
        })

    # 2SV / password changes
    sec_changes = [r for r in rows
                   if r.get("event_name") in {"2sv_disable", "2sv_enroll", "password_edit"}]
    if sec_changes:
        findings.append({
            "severity": "HIGH",
            "category": "Login",
            "indicator": "2SV/password security setting changed",
            "detail": f"{len(sec_changes)} event(s)",
            "evidence_count": len(sec_changes),
            "samples": [{"time": r["time"], "event": r.get("event_name"),
                         "ip": r.get("ip_address", "")} for r in sec_changes[:5]],
        })

    # Failed attempts immediately preceding success
    rows_sorted = sorted([r for r in rows if r.get("event_name") in {"login_failure", "login_success"}
                          and parse_iso(r["time"])],
                         key=lambda r: parse_iso(r["time"]))
    sus_pairs = []
    for i, r in enumerate(rows_sorted):
        if r["event_name"] != "login_success":
            continue
        t = parse_iso(r["time"])
        prior_failures = [p for p in rows_sorted[:i]
                          if p["event_name"] == "login_failure"
                          and (t - parse_iso(p["time"])).total_seconds() <= 600]
        if len(prior_failures) >= 3:
            sus_pairs.append((r, len(prior_failures)))
    if sus_pairs:
        findings.append({
            "severity": "MED",
            "category": "Login",
            "indicator": "Failed-login burst followed by success (≥3 fails in 10min)",
            "detail": f"{len(sus_pairs)} occurrence(s)",
            "evidence_count": len(sus_pairs),
            "samples": [{"time": r["time"], "ip": r.get("ip_address", ""),
                         "preceding_failures": n} for r, n in sus_pairs[:5]],
        })

    # Country / org outside baseline
    if baseline_entry is not None:
        outside = []
        for r in rows:
            if r.get("event_name") not in {"login_success", "login_verification"}:
                continue
            ip = r.get("ip_address", "")
            info = ips_by_addr.get(ip, {})
            country = info.get("country", "")
            org = info.get("org", "")
            ok = matches_baseline(country, org, baseline_entry)
            if ok is False:
                outside.append({"time": r["time"], "ip": ip,
                                "country": country, "org": org})
        if outside:
            findings.append({
                "severity": "HIGH",
                "category": "Login",
                "indicator": "Login from country/org outside user's baseline",
                "detail": f"{len(outside)} login event(s) outside expected geography/network",
                "evidence_count": len(outside),
                "samples": outside[:5],
            })

    return findings


def score_ips(ips_rows, baseline_entry):
    findings = []

    # Anonymous proxy
    proxies = [r for r in ips_rows if r.get("anonymous_proxy") == "true"]
    if proxies:
        findings.append({
            "severity": "MED",
            "category": "IP",
            "indicator": "Anonymous proxy / VPN IP",
            "detail": f"{len(proxies)} IP(s) flagged anonymous_proxy=true",
            "evidence_count": len(proxies),
            "samples": [{"ip": r["ip"], "country": r.get("country", ""),
                         "org": r.get("org", "")} for r in proxies[:5]],
        })

    # One-off IP that hit login + drive + token (or 3+ apps) within window
    hijack_candidates = []
    for r in ips_rows:
        try:
            count = int(r.get("count", "0"))
        except ValueError:
            count = 0
        apps = set((r.get("apps") or "").split(","))
        apps.discard("")
        if count <= 3 and len(apps) >= 3 and "login" in apps:
            hijack_candidates.append({
                "ip": r["ip"], "count": count, "apps": sorted(apps),
                "country": r.get("country", ""), "org": r.get("org", ""),
                "first_seen": r.get("first_seen", ""), "last_seen": r.get("last_seen", ""),
            })
    if hijack_candidates:
        findings.append({
            "severity": "HIGH",
            "category": "IP",
            "indicator": "Single-event IP with broad app coverage (possible session hijack)",
            "detail": f"{len(hijack_candidates)} IP(s) with ≤3 events spanning login + ≥2 other apps",
            "evidence_count": len(hijack_candidates),
            "samples": hijack_candidates[:5],
        })

    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("user")
    ap.add_argument("--logs-dir", default="logs")
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--sanctioned", help="Path to sanctioned_apps.json")
    ap.add_argument("--baseline", help="Path to ip_baseline.json")
    ap.add_argument("--out", help="Output JSON path (default: <user_dir>/<user_slug>_indicators_<days>d.json)")
    args = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    sanctioned_path = args.sanctioned or os.path.join(here, "sanctioned_apps.json")
    baseline_path = args.baseline or os.path.join(here, "ip_baseline.json")

    sanctioned = load_json(sanctioned_path, {"apps": []})
    baseline = load_json(baseline_path, {"users": {}, "_default": None})
    user_baseline = (baseline.get("users", {}).get(args.user.lower())
                     or baseline.get("users", {}).get(args.user)
                     or baseline.get("_default"))

    user_dir = os.path.join(args.logs_dir, user_subfolder(args.user))
    if not os.path.isdir(user_dir):
        sys.exit(f"No log folder for {args.user}: expected {user_dir}")
    user_slug = args.user.replace("@", "_at_").replace(".", "_")

    drive = read_csv(os.path.join(user_dir, f"{user_slug}_drive_{args.days}d.csv"))
    gmail = read_csv(os.path.join(user_dir, f"{user_slug}_gmail_{args.days}d.csv"))
    token = read_csv(os.path.join(user_dir, f"{user_slug}_token_{args.days}d.csv"))
    login = read_csv(os.path.join(user_dir, f"{user_slug}_login_{args.days}d.csv"))
    ips_csv_path = os.path.join(user_dir, f"{user_slug}_ips_{args.days}d.csv")
    ips_rows = read_csv(ips_csv_path)
    ips_by_addr = {r["ip"]: r for r in ips_rows}

    findings = []
    findings += score_drive(drive, args.user)
    findings += score_gmail(gmail, args.user)
    findings += score_token(token, args.user, sanctioned)
    findings += score_login(login, args.user, user_baseline, ips_by_addr)
    findings += score_ips(ips_rows, user_baseline)

    sev_order = {"HIGH": 0, "MED": 1, "LOW": 2}
    findings.sort(key=lambda f: (sev_order.get(f["severity"], 9), -f.get("evidence_count", 0)))

    no_evidence_for = []
    triggered_indicators = {f["indicator"] for f in findings}
    for cat, name in [
        ("Drive", "Mass download/export/copy burst"),
        ("Drive", "Drive share to free email provider"),
        ("Drive", "Drive share to non-companyName external recipient"),
        ("Drive", "Ownership transfer to external account"),
        ("Gmail", "Auto-forwarding rule added or modified"),
        ("Gmail", "Outbound mail to free email providers"),
        ("Gmail", "Large outbound payload to external recipient"),
        ("OAuth", "New OAuth grant with broad scope (mail/drive/admin) to unsanctioned app"),
        ("OAuth", "OAuth grant to unsanctioned app"),
        ("Login", "suspicious_login event"),
        ("Login", "2SV/password security setting changed"),
        ("Login", "Failed-login burst followed by success (≥3 fails in 10min)"),
        ("Login", "Login from country/org outside user's baseline"),
        ("IP", "Anonymous proxy / VPN IP"),
        ("IP", "Single-event IP with broad app coverage (possible session hijack)"),
    ]:
        if name not in triggered_indicators:
            no_evidence_for.append({"category": cat, "indicator": name})

    summary = Counter(f["severity"] for f in findings)
    output = {
        "subject": args.user,
        "window_days": args.days,
        "user_baseline": user_baseline,
        "sources_loaded": {
            "drive": len(drive), "gmail": len(gmail), "token": len(token),
            "login": len(login), "ips": len(ips_rows),
        },
        "summary": {
            "high": summary.get("HIGH", 0),
            "med": summary.get("MED", 0),
            "low": summary.get("LOW", 0),
            "total": len(findings),
        },
        "indicators": findings,
        "no_evidence_for": no_evidence_for,
    }

    out_path = args.out or os.path.join(user_dir, f"{user_slug}_indicators_{args.days}d.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, default=str)

    print(f"Subject: {args.user}")
    print(f"Indicators: HIGH={summary.get('HIGH',0)}  MED={summary.get('MED',0)}  LOW={summary.get('LOW',0)}")
    print(f"Sources loaded: {output['sources_loaded']}")
    print(f"Output: {out_path}")
    if findings:
        print("\nTop findings:")
        for f_ in findings[:5]:
            print(f"  [{f_['severity']:<4}] {f_['category']:<6} {f_['indicator']} — {f_['detail']}")


if __name__ == "__main__":
    main()
