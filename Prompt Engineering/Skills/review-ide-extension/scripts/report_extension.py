#!/usr/bin/env python3
"""
Generate a markdown security report for a reviewed VS Code extension.
Usage: python3 report_extension.py <working_dir>

Reads:  <working_dir>/metadata.json, <working_dir>/analysis.json
Writes: <working_dir>/<slug>_security_review_<date>.md
Prints the report path as the last line of stdout.
"""

import argparse
import json
import pathlib
import sys
from datetime import datetime, timezone


RISK_VERDICT = {
    "HIGH":   "🔴 HIGH RISK — do not install without manual code review",
    "MEDIUM": "🟡 MEDIUM RISK — review findings before installing",
    "LOW":    "🟢 LOW RISK — minor concerns only",
    "CLEAN":  "✅ CLEAN — no significant security concerns found",
}

APPROVE = {
    "HIGH":   "**BLOCK** — HIGH-severity findings require resolution or security team sign-off before installation.",
    "MEDIUM": "**REVIEW REQUIRED** — Verify the listed capabilities match the extension's stated purpose.",
    "LOW":    "**CONDITIONAL APPROVE** — LOW-severity findings only; review context before installing.",
    "CLEAN":  "**APPROVE** — No blocking security concerns. Standard installation approval applies.",
}


def fmt_num(n) -> str:
    try:
        return f"{int(n):,}"
    except Exception:
        return str(n)


def build_report(metadata: dict, analysis: dict) -> str:
    ext_id = metadata["extension_id"]
    version = metadata["version"]
    risk = analysis["risk_score"]
    counts = analysis["findings_count"]
    findings = analysis["findings"]
    pkg_info = analysis.get("package_info", {})
    urls = analysis.get("urls_found", [])
    file_inv = analysis.get("file_inventory", {})

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    last_updated = metadata.get("last_updated", "")[:10]
    pub_verified = "✓ Verified" if metadata.get("publisher_verified") else "✗ Unverified"

    L = []  # output lines

    L += [
        f"# VS Code Extension Security Review: `{ext_id}`",
        "",
        f"**Extension:** `{ext_id}` v{version}",
        f"**Display name:** {metadata.get('display_name', 'N/A')}",
        f"**Publisher:** {metadata.get('publisher_display_name', metadata.get('publisher_name', ''))} [{pub_verified}]",
        f"**Overall risk:** {RISK_VERDICT[risk]}",
        f"**Findings:** {counts['HIGH']} HIGH · {counts['MEDIUM']} MEDIUM · {counts['LOW']} LOW",
        f"**Installs:** {fmt_num(metadata.get('install_count', 0))}  "
        f"| **Rating:** {metadata.get('average_rating', 0):.1f}/5 ({fmt_num(metadata.get('rating_count', 0))} ratings)",
        f"**Last updated:** {last_updated}",
        f"**Reviewed:** {now}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
    ]

    # Narrative summary
    high_findings = [f for f in findings if f["severity"] == "HIGH"]
    med_findings = [f for f in findings if f["severity"] == "MEDIUM"]
    if risk == "CLEAN":
        L.append(
            f"`{ext_id}` v{version} passed all automated checks. "
            "No dangerous code patterns, secrets, suspicious files, or supply chain flags were detected. "
            "Standard due diligence (verify publisher, review recent changelog) still applies before installation."
        )
    elif risk == "HIGH":
        categories = sorted(set(f["category"] for f in high_findings))
        top = ", ".join(f['title'] for f in high_findings[:3])
        L.append(
            f"`{ext_id}` v{version} has **{counts['HIGH']} HIGH-severity finding(s)** "
            f"in: {', '.join(categories)}. "
            f"Do not install without manually reviewing the flagged code. "
            f"Key concerns: {top}."
        )
    elif risk == "MEDIUM":
        L.append(
            f"`{ext_id}` v{version} has **{counts['MEDIUM']} MEDIUM-severity finding(s)**. "
            "These may be legitimate for the extension's stated purpose — "
            "verify that the flagged capabilities (network access, process execution, etc.) "
            "are expected given what the extension is supposed to do."
        )
    else:
        L.append(
            f"`{ext_id}` v{version} has **{counts['LOW']} LOW-severity finding(s)** only. "
            "These are common in VS Code extensions and are likely benign, "
            "but are documented for completeness."
        )

    # Metadata table
    L += ["", "---", "", "## Extension Metadata", ""]
    L += [
        "| Field | Value |",
        "|---|---|",
        f"| Extension ID | `{ext_id}` |",
        f"| Version | {version} |",
        f"| Publisher | {metadata.get('publisher_name', '')} |",
        f"| Verified Publisher | {pub_verified} |",
        f"| Installs | {fmt_num(metadata.get('install_count', 0))} |",
        f"| Rating | {metadata.get('average_rating', 0):.1f}/5 ({fmt_num(metadata.get('rating_count', 0))} ratings) |",
        f"| Last Updated | {last_updated} |",
        f"| Categories | {', '.join(metadata.get('categories', [])) or 'N/A'} |",
        f"| Description | {(metadata.get('short_description', '') or 'N/A')[:140]} |",
        "",
    ]

    # Package analysis
    L += ["## Package Analysis", ""]

    act_events = pkg_info.get("activation_events", [])
    L.append(f"**Activation events ({len(act_events)}):**")
    if act_events:
        L.append("")
        for ev in act_events[:12]:
            L.append(f"- `{ev}`")
        if len(act_events) > 12:
            L.append(f"- _(and {len(act_events) - 12} more)_")
    else:
        L.append("None declared.")
    L.append("")

    cmds = pkg_info.get("commands", [])
    L.append(f"**Registered commands ({len(cmds)}):**")
    if cmds:
        L.append("")
        for cmd in cmds[:12]:
            L.append(f"- `{cmd}`")
        if len(cmds) > 12:
            L.append(f"- _(and {len(cmds) - 12} more)_")
    L.append("")

    deps = pkg_info.get("dependencies", {})
    L.append(f"**Bundled dependencies ({len(deps)}):**")
    if deps:
        L.append("")
        L += ["| Package | Version |", "|---|---|"]
        for pkg_name, ver in list(deps.items())[:20]:
            L.append(f"| `{pkg_name}` | `{ver}` |")
        if len(deps) > 20:
            L.append(f"| _(and {len(deps) - 20} more)_ | |")
    L.append("")

    # File inventory
    L += ["## File Inventory", ""]
    L += [
        "| Metric | Value |",
        "|---|---|",
        f"| Total files | {file_inv.get('total_files', 0)} |",
        f"| JavaScript files (scanned) | {file_inv.get('js_files', 0)} |",
    ]
    SKIP_COMMON = {".js", ".json", ".md", ".txt", "", ".map", ".ts", ".svg",
                   ".png", ".ico", ".gif", ".woff", ".woff2", ".ttf", ".css", ".html"}
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

    # All findings summary table
    L += ["## Security Findings", ""]
    if not findings:
        L.append("No findings.")
    else:
        L += [
            "| Severity | Category | Finding | File | Line |",
            "|---|---|---|---|---|",
        ]
        for f in findings:
            fname = (f.get("file") or "")[-50:]
            linenum = str(f.get("line") or "")
            L.append(
                f"| **{f['severity']}** | {f['category']} | {f['title']} | "
                f"`{fname}` | {linenum} |"
            )
    L.append("")

    # Detail block for HIGH and MEDIUM
    hm = [f for f in findings if f["severity"] in ("HIGH", "MEDIUM")]
    if hm:
        L += ["## Findings Detail", ""]
        for f in hm:
            L += [
                f"### [{f['severity']}] {f['title']}",
                "",
                f"- **Category:** {f['category']}",
            ]
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
        L.append(f"The following URLs were found in the extension source ({len(urls)} unique):")
        L.append("")
        for url in urls[:30]:
            L.append(f"- `{url}`")
        if len(urls) > 30:
            L.append(f"- _(and {len(urls) - 30} more — see analysis.json)_")
        L.append("")

    # Verdict
    L += ["## Verdict", "", APPROVE[risk], ""]

    # Caveats
    L += [
        "## Caveats",
        "",
        "- **Static analysis only.** Runtime behavior, environment-conditional logic, "
          "and sophisticated obfuscation are not detectable by this tool.",
        "- **node_modules excluded.** Only the extension's own source files were scanned. "
          "Third-party dependencies require a separate audit (e.g. `npm audit`).",
        "- **False positives.** Patterns like `child_process` and `fs` are common in legitimate "
          "language-server extensions. All HIGH/MEDIUM findings should be verified in context.",
        f"- **Version-specific.** This review covers v{version} only. Re-review after updates.",
        "",
        f"_Generated by the review-ide-extension skill · {now}_",
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

    pub = metadata.get("publisher_name", "unknown")
    name = metadata.get("extension_name", "unknown")
    ver = metadata.get("version", "0.0.0")
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    filename = f"{pub}_{name}_{ver}_security_review_{date}.md"

    out_path = work_dir / filename
    out_path.write_text(report_text)

    risk = analysis["risk_score"]
    counts = analysis["findings_count"]
    print(f"[+] Report → {out_path}")
    print(f"[+] Risk: {risk} — HIGH:{counts['HIGH']} MED:{counts['MEDIUM']} LOW:{counts['LOW']}")
    print(out_path)  # machine-readable last line


if __name__ == "__main__":
    main()
