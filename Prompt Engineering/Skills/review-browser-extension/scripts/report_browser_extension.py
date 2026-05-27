#!/usr/bin/env python3
"""
Generate a markdown security report for a reviewed browser extension.
Usage: python3 report_browser_extension.py <working_dir>

Reads:  <working_dir>/metadata.json, <working_dir>/analysis.json
Writes: <working_dir>/<slug>_security_review_<date>.md
Prints report path as the last line of stdout.
"""

import argparse
import json
import pathlib
import sys
from datetime import datetime, timezone


RISK_VERDICT = {
    "HIGH":   "🔴 HIGH RISK — do not install without security team review",
    "MEDIUM": "🟡 MEDIUM RISK — verify capabilities match stated purpose",
    "LOW":    "🟢 LOW RISK — minor concerns only",
    "CLEAN":  "✅ CLEAN — no significant security concerns found",
}

VERDICT_TEXT = {
    "HIGH":   "**BLOCK** — HIGH-severity findings require manual code review or security team sign-off before installation.",
    "MEDIUM": "**REVIEW REQUIRED** — Verify the listed permissions and capabilities match the extension's stated purpose.",
    "LOW":    "**CONDITIONAL APPROVE** — LOW-severity findings only. Review permissions against use case before installing.",
    "CLEAN":  "**APPROVE** — No blocking security concerns. Standard installation approval applies.",
}

PERM_DESCRIPTIONS = {
    "<all_urls>": "Access content on all websites",
    "*://*/*":    "Access content on all websites",
    "http://*/*": "Access content on all HTTP websites",
    "https://*/*": "Access content on all HTTPS websites",
    "tabs":       "Read URLs and titles of all open tabs",
    "history":    "Access full browsing history",
    "bookmarks":  "Read and modify bookmarks",
    "downloads":  "Monitor and manage file downloads",
    "cookies":    "Read and write cookies for all sites",
    "identity":   "Access OAuth tokens via Identity API",
    "nativeMessaging": "Communicate with native applications",
    "clipboardRead": "Read the system clipboard",
    "debugger":   "Attach debugger to any tab (full page access)",
    "proxy":      "Configure and intercept proxy settings",
    "webRequest": "Observe all HTTP requests",
    "webRequestBlocking": "Block or modify HTTP requests",
    "scripting":  "Inject JavaScript into pages (MV3)",
    "management": "Manage other installed extensions",
    "browsingData": "Clear browsing data (cookies, cache, history)",
    "declarativeNetRequestFeedback": "Observe all intercepted requests",
    "webNavigation": "Monitor all navigation events",
    "storage":    "Read/write extension local storage",
    "unlimitedStorage": "Unlimited local storage",
    "notifications": "Show desktop notifications",
    "contextMenus": "Add right-click context menu entries",
    "alarms":     "Schedule periodic tasks",
    "activeTab":  "Access current tab when user interacts",
    "declarativeNetRequest": "Block/redirect requests via rules",
}

PERM_RISK = {
    "HIGH":   ["<all_urls>", "*://*/*", "http://*/*", "https://*/*",
               "nativeMessaging", "cookies", "identity", "clipboardRead",
               "debugger", "proxy", "webRequestBlocking"],
    "MEDIUM": ["webRequest", "tabs", "history", "bookmarks", "downloads",
               "scripting", "management", "browsingData",
               "declarativeNetRequestFeedback", "webNavigation"],
}


def perm_severity(p: str) -> str:
    if p in PERM_RISK["HIGH"]:
        return "HIGH"
    if p in PERM_RISK["MEDIUM"]:
        return "MEDIUM"
    return "LOW"


def fmt_num(n) -> str:
    try:
        return f"{int(n):,}"
    except Exception:
        return str(n)


def build_report(metadata: dict, analysis: dict) -> str:
    name = metadata["name"]
    browser = metadata["browser"].capitalize()
    version = metadata["version"]
    risk = analysis["risk_score"]
    counts = analysis["findings_count"]
    findings = analysis["findings"]
    ps = analysis.get("permissions_summary", {})
    file_inv = analysis.get("file_inventory", {})
    urls = analysis.get("urls_found", [])
    mv = analysis.get("manifest_version", 2)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    last_updated = metadata.get("last_updated", "")[:10]
    verified = "✓ Recommended" if metadata.get("publisher_verified") else "✗ Not recommended/verified"
    store_url = metadata.get("store_url", "")

    L = []

    L += [
        f"# Browser Extension Security Review: `{name}` ({browser})",
        "",
        f"**Extension:** {name} v{version} ({browser})",
        f"**Publisher:** {metadata.get('publisher', 'Unknown')} [{verified}]",
        f"**Overall risk:** {RISK_VERDICT[risk]}",
        f"**Findings:** {counts['HIGH']} HIGH · {counts['MEDIUM']} MEDIUM · {counts['LOW']} LOW",
        f"**Installs:** {fmt_num(metadata.get('install_count', 0))}  "
        f"| **Rating:** {metadata.get('average_rating', 0):.1f}/5 ({fmt_num(metadata.get('rating_count', 0))} ratings)",
        f"**Last updated:** {last_updated}  | **Manifest version:** MV{mv}",
        f"**Store:** {store_url}",
        f"**Reviewed:** {now}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
    ]

    high_findings = [f for f in findings if f["severity"] == "HIGH"]
    if risk == "CLEAN":
        L.append(
            f"`{name}` v{version} passed all automated checks. No dangerous permissions, "
            "credential theft vectors, or suspicious code patterns were detected."
        )
    elif risk == "HIGH":
        cats = sorted(set(f["category"] for f in high_findings))
        top = "; ".join(f["title"] for f in high_findings[:3])
        L.append(
            f"`{name}` v{version} has **{counts['HIGH']} HIGH-severity finding(s)** "
            f"in: {', '.join(cats)}. Do not install without manual review. "
            f"Key concerns: {top}."
        )
    elif risk == "MEDIUM":
        L.append(
            f"`{name}` v{version} has **{counts['MEDIUM']} MEDIUM-severity finding(s)**. "
            "These may be legitimate for the extension's stated purpose — "
            "verify that the flagged permissions and capabilities match what the extension is supposed to do."
        )
    else:
        L.append(
            f"`{name}` v{version} has **{counts['LOW']} LOW-severity finding(s)** only. "
            "Likely benign — review context before installing."
        )

    # Metadata table
    L += ["", "---", "", "## Extension Metadata", ""]
    L += [
        "| Field | Value |",
        "|---|---|",
        f"| Name | {name} |",
        f"| Version | {version} |",
        f"| Browser | {browser} |",
        f"| Publisher | {metadata.get('publisher', 'N/A')} |",
        f"| Verified/Recommended | {verified} |",
        f"| Installs | {fmt_num(metadata.get('install_count', 0))} |",
        f"| Rating | {metadata.get('average_rating', 0):.1f}/5 ({fmt_num(metadata.get('rating_count', 0))} ratings) |",
        f"| Last Updated | {last_updated} |",
        f"| Manifest Version | MV{mv} |",
        f"| Store URL | {store_url} |",
        f"| Description | {(metadata.get('description','') or 'N/A')[:140]} |",
        "",
    ]

    # ---- PERMISSIONS (primary section) ----
    L += ["## Permissions Analysis", ""]
    L += [
        "> Browser extension permissions define what the extension can access. "
        "This is the most important section for assessing risk.",
        "",
    ]

    # Declared permissions table
    all_perms = ps.get("all_permissions", [])
    host_perms = ps.get("host_permissions", [])

    if all_perms or host_perms:
        L += ["### Declared Permissions", ""]
        if all_perms:
            L += ["| Permission | Risk | What it can access |", "|---|---|---|"]
            for p in sorted(all_perms):
                sev = perm_severity(p)
                desc = PERM_DESCRIPTIONS.get(p, f"Browser permission: {p}")
                L.append(f"| `{p}` | **{sev}** | {desc} |")
            L.append("")

        if host_perms:
            L += ["### Host Permissions (Site Access)", ""]
            L += ["| Host Pattern | Risk | Meaning |", "|---|---|---|"]
            for hp in host_perms:
                if hp in ("<all_urls>", "*://*/*", "http://*/*", "https://*/*"):
                    L.append(f"| `{hp}` | **HIGH** | Reads/modifies content on every website |")
                else:
                    L.append(f"| `{hp}` | **LOW** | Access limited to this domain only |")
            L.append("")
    else:
        L += ["### Declared Permissions", "", "No API permissions declared.", ""]

    # Content scripts
    L += ["### Content Scripts", ""]
    cs_cov = ps.get("content_scripts_coverage", "none")
    if cs_cov == "none":
        L.append("No content scripts declared — extension does not inject JavaScript into web pages.")
    else:
        run_ats = ps.get("content_scripts_run_at", [])
        domains = ps.get("content_scripts_domains", [])
        L += [
            f"- **Coverage:** {'All websites' if cs_cov == 'all_urls' else 'Specific domains'}",
            f"- **Runs at:** {', '.join(run_ats) if run_ats else 'document_idle (default)'}",
        ]
        if cs_cov == "specific_domains" and domains:
            L.append(f"- **Domains:** {', '.join(domains[:10])}")
            if len(domains) > 10:
                L.append(f"  _(and {len(domains)-10} more)_")
    L.append("")

    # CSP
    L += ["### Content Security Policy", ""]
    csp = ps.get("csp", "")
    if csp:
        L.append(f"```\n{csp}\n```")
        csp_issues = [f for f in findings if f["category"] == "csp"]
        if csp_issues:
            for ci in csp_issues:
                L.append(f"- ⚠️ **{ci['severity']}:** {ci['title']}")
    else:
        L.append("Default CSP (no custom policy declared).")
    L.append("")

    # MV2/MV3 note
    L += ["### Manifest Version", ""]
    if mv == 3:
        L.append("**MV3** — current standard. Restricted network interception (declarativeNetRequest), ephemeral service workers.")
    else:
        L.append(
            "**MV2** — deprecated by Chrome (enforcement TBD). Supports persistent background pages and "
            "blocking webRequest, which provide broader capabilities than MV3."
        )
    L.append("")

    # File inventory
    L += ["## File Inventory", ""]
    L += [
        "| Metric | Value |",
        "|---|---|",
        f"| Total files | {file_inv.get('total_files', 0)} |",
        f"| JavaScript files | {file_inv.get('js_files', 0)} |",
    ]
    SKIP_COMMON = {".js", ".json", ".md", ".txt", "", ".map", ".ts", ".svg",
                   ".png", ".ico", ".gif", ".woff", ".woff2", ".ttf", ".css",
                   ".html", ".htm", ".dtd", ".properties", ".ftl"}
    for ext_type, count in sorted(file_inv.get("type_counts", {}).items()):
        if ext_type not in SKIP_COMMON:
            L.append(f"| `{ext_type or '(no ext)'}` files | {count} |")
    L.append("")

    unexpected = file_inv.get("unexpected", [])
    if unexpected:
        L += [f"**Unexpected file types ({len(unexpected)}):**", ""]
        for uf in unexpected:
            L.append(f"- `{uf}`")
        L.append("")

    # Data flow analysis
    df = analysis.get("data_flows", {})
    if df:
        FLOW_VERDICT_LABELS = {
            "LOCAL_ONLY":        ("✅ LOCAL ONLY",        "No outbound network calls or cloud services detected. User data stays on-device."),
            "READ_ONLY_BACKEND": ("🔵 READ-ONLY BACKEND", "Extension reads from a backend (config, remote messages) but sends no user-identifying data."),
            "SUBSCRIPTION_ONLY": ("🟡 SUBSCRIPTION CHECK","Only user identifiers (uid/email) are sent — used for subscription/license checks. No browsing or page content leaves the browser."),
            "SENDS_USER_CONTENT":("🔴 SENDS USER CONTENT","User-generated content (highlights, search queries, page text) or Firebase writes detected. Review what is uploaded."),
            "UNKNOWN":           ("⚪ UNKNOWN",            "Dynamic network calls found — manual review required to confirm what data is transmitted."),
        }
        dv_label, dv_desc = FLOW_VERDICT_LABELS.get(df.get("verdict", "UNKNOWN"), ("⚪ UNKNOWN", ""))
        L += ["## Data Flow Analysis", ""]
        L += [
            f"**Verdict: {dv_label}**",
            "",
            dv_desc,
            "",
        ]
        if df.get("verdict_reasons"):
            for r in df["verdict_reasons"]:
                L.append(f"- {r}")
            L.append("")

        L += ["| Signal | Value |", "|---|---|"]
        ssk = df.get("sync_storage_keys", [])
        lsk = df.get("local_storage_keys", [])
        fb_svc = df.get("firebase_services", [])
        fb_wr = df.get("firebase_writes", [])
        auth_m = df.get("auth_methods", [])
        endpts = df.get("outbound_endpoints", [])
        ud = df.get("user_data_in_outbound", {})

        L.append(f"| `storage.sync` keys (→ Google) | {', '.join(f'`{k}`' for k in ssk) if ssk else 'none detected'} |")
        L.append(f"| `storage.local` keys (on-device) | {', '.join(f'`{k}`' for k in lsk[:8]) if lsk else 'none detected'} |")
        L.append(f"| Firebase services | {', '.join(fb_svc) if fb_svc else 'none'} |")
        L.append(f"| Firebase writes | {', '.join(fb_wr) if fb_wr else 'none'} |")
        L.append(f"| Auth methods | {', '.join(auth_m) if auth_m else 'none'} |")
        L.append(f"| uid in outbound | {'yes' if ud.get('uid') else 'no'} |")
        L.append(f"| email in outbound | {'yes' if ud.get('email') else 'no'} |")
        L.append(f"| page/highlight content in outbound | {'yes' if ud.get('page_content') else 'no'} |")
        L.append(f"| search queries in outbound | {'yes' if ud.get('search_queries') else 'no'} |")
        L.append("")

        if endpts:
            L += ["**Hardcoded outbound endpoints:**", ""]
            for ep in endpts[:15]:
                L.append(f"- `{ep}`")
            if len(endpts) > 15:
                L.append(f"- _(and {len(endpts)-15} more — see analysis.json)_")
            L.append("")

        btoa = df.get("btoa_payloads", [])
        if btoa:
            L += ["**btoa() payloads (base64-encoded before sending):**", ""]
            for bp in btoa[:5]:
                L.append(f"- `{bp}`")
            L.append("")

    # All findings table
    L += ["## Security Findings", ""]
    non_perm = [f for f in findings if f["category"] not in ("permission", "host_permission", "csp", "manifest_version")]
    perm_findings = [f for f in findings if f["category"] in ("permission", "host_permission", "csp", "manifest_version")]

    if not findings:
        L.append("No findings.")
    else:
        # Permission findings table
        if perm_findings:
            L += ["**Permission / manifest findings:**", ""]
            L += ["| Severity | Finding | Detail |", "|---|---|---|"]
            for f in perm_findings:
                L.append(f"| **{f['severity']}** | {f['title']} | {f.get('detail', '')[:80]} |")
            L.append("")

        if non_perm:
            L += ["**Code / file findings:**", ""]
            L += ["| Severity | Category | Finding | File | Line |", "|---|---|---|---|---|"]
            for f in non_perm:
                fname = (f.get("file") or "")[-50:]
                linenum = str(f.get("line") or "")
                L.append(
                    f"| **{f['severity']}** | {f['category']} | {f['title']} | "
                    f"`{fname}` | {linenum} |"
                )
            L.append("")

    # Findings detail
    hm = [f for f in findings if f["severity"] in ("HIGH", "MEDIUM")
          and f["category"] not in ("permission", "host_permission")]
    if hm:
        L += ["## Findings Detail", ""]
        for f in hm:
            L += [f"### [{f['severity']}] {f['title']}", ""]
            L.append(f"- **Category:** {f['category']}")
            if f.get("file"):
                loc = f"`{f['file']}`"
                if f.get("line"):
                    loc += f", line {f['line']}"
                L.append(f"- **Location:** {loc}")
            L.append(f"- **Detail:** {f.get('detail', '')}")
            if f.get("context") and f["context"] != "[content masked]":
                L += ["```", f["context"], "```"]
            L.append("")

    # Network endpoints
    if urls:
        L += ["## Hardcoded Network Endpoints", ""]
        L.append(f"URLs found in extension source ({len(urls)} unique):")
        L.append("")
        for url in urls[:30]:
            L.append(f"- `{url}`")
        if len(urls) > 30:
            L.append(f"- _(and {len(urls)-30} more — see analysis.json)_")
        L.append("")

    # Verdict
    L += ["## Verdict", "", VERDICT_TEXT[risk], ""]

    # Caveats
    L += [
        "## Caveats",
        "",
        "- **Static analysis only.** Runtime behavior, server-side logic, and obfuscated payloads are not detectable.",
        "- **Permissions are not intent.** A permission like `tabs` or `webRequest` can be legitimate "
          "(ad blockers, password managers). Always verify against the extension's stated purpose.",
        "- **Content scripts not fully analyzed.** Only JS pattern-matching is performed; "
          "semantic analysis of what data is actually sent/read requires manual review.",
        f"- **Version-specific.** This review covers v{version} only. Re-review after updates.",
        "",
        f"_Generated by the review-browser-extension skill · {now}_",
    ]

    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("working_dir")
    args = ap.parse_args()

    work_dir = pathlib.Path(args.working_dir)
    metadata = json.loads((work_dir / "metadata.json").read_text())
    analysis = json.loads((work_dir / "analysis.json").read_text())

    report_text = build_report(metadata, analysis)

    browser = metadata.get("browser", "browser")
    name_slug = metadata.get("extension_id", "ext")
    ver = metadata.get("version", "0.0.0")
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    filename = f"{browser}_{name_slug}_{ver}_security_review_{date}.md"

    out_path = work_dir / filename
    out_path.write_text(report_text)

    risk = analysis["risk_score"]
    counts = analysis["findings_count"]
    print(f"[+] Report → {out_path}")
    print(f"[+] Risk: {risk} — HIGH:{counts['HIGH']} MED:{counts['MEDIUM']} LOW:{counts['LOW']}")
    print(out_path)


if __name__ == "__main__":
    main()
