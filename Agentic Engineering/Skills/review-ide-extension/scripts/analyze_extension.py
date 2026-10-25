#!/usr/bin/env python3
"""
Static security analysis of an extracted VS Code extension.
Usage: python3 analyze_extension.py <working_dir>

Reads:  <working_dir>/metadata.json, <working_dir>/vsix/
Writes: <working_dir>/analysis.json
Prints the analysis.json path as the last line of stdout.
"""

import argparse
import json
import pathlib
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Dict, Tuple


# ---------------------------------------------------------------------------
# Pattern definitions  (regex, description, category, severity)
# ---------------------------------------------------------------------------

CODE_PATTERNS = [
    # HIGH: code execution
    (r"\beval\s*\(", "eval() — arbitrary code execution", "code_execution", "HIGH"),
    (r"\bnew\s+Function\s*\(", "new Function() — indirect eval", "code_execution", "HIGH"),
    (r"require\s*\(\s*['\"]child_process['\"]\s*\)", "child_process import", "code_execution", "HIGH"),
    (r"\.execSync\s*\(", ".execSync() — synchronous command execution", "code_execution", "HIGH"),
    (r"\.spawnSync\s*\(", ".spawnSync() — synchronous process spawn", "code_execution", "HIGH"),
    (r"\.execFile\s*\(", ".execFile() — execute a file", "code_execution", "HIGH"),
    (r"\bvm\.run(?:In(?:New|This)Context|Script)\s*\(", "vm module — sandbox escape risk", "code_execution", "HIGH"),
    (r"process\.binding\s*\(", "process.binding() — internal Node.js binding", "code_execution", "HIGH"),
    # HIGH: raw sockets
    (r"require\s*\(\s*['\"]net['\"]\s*\)", "net module — raw TCP sockets", "network", "HIGH"),
    (r"require\s*\(\s*['\"]dgram['\"]\s*\)", "dgram module — raw UDP sockets", "network", "HIGH"),
    # HIGH: subprocess (without execSync already covered above)
    (r"\b(?:cp|childProcess|child_process)\s*\.\s*exec\s*\(", ".exec() — command execution", "code_execution", "HIGH"),
    (r"\b(?:cp|childProcess|child_process)\s*\.\s*spawn\s*\(", ".spawn() — process spawn", "code_execution", "HIGH"),
    # MEDIUM: HTTP/network
    (r"require\s*\(\s*['\"]https?['\"]\s*\)", "http/https module import", "network", "MEDIUM"),
    (r"\bfetch\s*\(", "fetch() — outbound HTTP request", "network", "MEDIUM"),
    (r"require\s*\(\s*['\"]axios['\"]\s*\)", "axios HTTP client import", "network", "MEDIUM"),
    (r"\baxios\s*\.\s*(?:get|post|put|delete|patch|request)\s*\(", "axios HTTP call", "network", "MEDIUM"),
    (r"\bnew\s+WebSocket\s*\(", "WebSocket connection", "network", "MEDIUM"),
    (r"require\s*\(\s*['\"](?:node-fetch|got|superagent|needle|undici|phin)['\"]\s*\)", "HTTP client import", "network", "MEDIUM"),
    (r"require\s*\(\s*['\"]dns['\"]\s*\)", "dns module — DNS lookups", "network", "MEDIUM"),
    # MEDIUM: dynamic loading
    (r"require\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*[^'\"()\n]*\)", "dynamic require() — runtime module loading", "dynamic_loading", "MEDIUM"),
    (r"\bFunction\s*\(\s*['\"]", "Function() constructor called with string arg", "code_execution", "MEDIUM"),
    # MEDIUM: env/process
    (r"process\.env\b", "process.env — reads environment variables", "env_access", "MEDIUM"),
    # LOW: filesystem
    (r"require\s*\(\s*['\"]fs(?:/promises)?['\"]\s*\)", "fs module import — filesystem access", "filesystem", "LOW"),
    (r"\.writeFile(?:Sync)?\s*\(", "writeFile — writes to disk", "filesystem", "LOW"),
    (r"\.unlink(?:Sync)?\s*\(", "unlink — deletes files", "filesystem", "LOW"),
    (r"\.rmdir(?:Sync)?\s*\(", "rmdir — deletes directories", "filesystem", "LOW"),
    (r"\.chmod(?:Sync)?\s*\(", "chmod — changes file permissions", "filesystem", "LOW"),
]

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID"),
    (r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key\s*[:=]\s*['\"]?[A-Za-z0-9+/]{40}", "AWS secret access key"),
    (r"gh[pousr]_[A-Za-z0-9_]{36,255}", "GitHub token"),
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private key"),
    (r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "JWT token"),
    (r"(?i)(?:api[_\-]?key|apikey)\s*[:=]\s*['\"]([A-Za-z0-9_\-\.]{20,})['\"]", "Hardcoded API key"),
    (r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{8,})['\"]", "Hardcoded password"),
    (r"(?i)(?:secret|token)\s*[:=]\s*['\"]([^'\"]{16,})['\"]", "Hardcoded secret/token"),
    (r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}", "Bearer token"),
    (r"(?:https?://)[^:@\s\"'<>(){}[\],]{3,}:[^@\s\"'<>(){}[\],]{3,}@", "Credentials in URL"),
]

SUSPICIOUS_FILE_TYPES = {
    ".exe": ("Windows executable", "HIGH"),
    ".dll": ("Windows DLL", "HIGH"),
    ".so": ("Unix shared library", "HIGH"),
    ".dylib": ("macOS dynamic library", "HIGH"),
    ".sh": ("Shell script", "MEDIUM"),
    ".bat": ("Windows batch file", "MEDIUM"),
    ".cmd": ("Windows command file", "MEDIUM"),
    ".ps1": ("PowerShell script", "MEDIUM"),
    ".vbs": ("VBScript", "MEDIUM"),
}

KNOWN_MALICIOUS_PACKAGES = {"event-stream", "flatmap-stream", "crossenv", "cross-env.js"}

URL_SKIP_PATTERNS = [
    "schema.", "schemas.", "example.com", "localhost", "127.0.0.1",
    "json-schema.org", "www.w3.org", "openssl.org", "ietf.org",
    "mozilla.org/en-US", "developer.mozilla", "nodejs.org/api",
    "code.visualstudio.com", "marketplace.visualstudio.com",
]


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    detail: str
    file: str = ""
    line: int = 0
    context: str = ""


def scan_js_file(filepath: pathlib.Path, base_dir: pathlib.Path) -> Tuple[List[Finding], List[str]]:
    """Returns (findings, urls_found)."""
    findings = []
    urls_found = []
    rel_path = str(filepath.relative_to(base_dir))

    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return [], []

    lines = content.split("\n")

    # Obfuscation: single very long line
    for i, line in enumerate(lines, 1):
        if len(line) > 500:
            findings.append(Finding(
                severity="MEDIUM",
                category="obfuscation",
                title="Very long line — possible obfuscation or minification",
                detail=f"Line {i} is {len(line):,} chars",
                file=rel_path,
                line=i,
                context=line[:100] + "...",
            ))
            break

    # Obfuscation: large base64 blob
    b64_re = re.compile(r"['\"][A-Za-z0-9+/]{200,}={0,2}['\"]")
    for m in b64_re.finditer(content):
        line_num = content[: m.start()].count("\n") + 1
        findings.append(Finding(
            severity="LOW",
            category="obfuscation",
            title="Large base64 blob",
            detail=f"Base64 string of length {len(m.group()) - 2}",
            file=rel_path,
            line=line_num,
            context=m.group()[:60] + "...",
        ))
        break  # one per file

    # String.fromCharCode obfuscation
    if content.count("String.fromCharCode") > 3:
        findings.append(Finding(
            severity="MEDIUM",
            category="obfuscation",
            title="Heavy String.fromCharCode usage — obfuscation indicator",
            detail=f"Found {content.count('String.fromCharCode')} occurrences",
            file=rel_path,
        ))

    # Code patterns
    for pattern, desc, category, severity in CODE_PATTERNS:
        for m in re.finditer(pattern, content):
            line_num = content[: m.start()].count("\n") + 1
            line_text = lines[line_num - 1].strip()[:120] if line_num <= len(lines) else ""
            findings.append(Finding(
                severity=severity,
                category=category,
                title=desc,
                detail=f"Matched: {m.group()!r}",
                file=rel_path,
                line=line_num,
                context=line_text,
            ))

    # Secret detection
    for pattern, desc in SECRET_PATTERNS:
        for m in re.finditer(pattern, content):
            line_num = content[: m.start()].count("\n") + 1
            matched = m.group()
            masked = matched[:8] + "…" + matched[-4:] if len(matched) > 14 else matched
            findings.append(Finding(
                severity="HIGH",
                category="secret",
                title=f"Potential secret: {desc}",
                detail=f"Matched (masked): {masked}",
                file=rel_path,
                line=line_num,
                context="[content masked]",
            ))

    # URL extraction
    for m in re.finditer(r"https?://[^\s'\"<>(){}[\]\\,;`]+", content):
        url = m.group().rstrip(".,;)")
        if not any(skip in url for skip in URL_SKIP_PATTERNS):
            urls_found.append(url)

    return findings, urls_found


def analyze_package_json(pkg: dict) -> Tuple[List[Finding], dict]:
    findings = []
    info: dict = {}

    activation_events = pkg.get("activationEvents", [])
    info["activation_events"] = activation_events
    if "*" in activation_events:
        findings.append(Finding(
            severity="HIGH",
            category="permission",
            title='activationEvents: "*" — activates on every VS Code event',
            detail="Extension runs on every workspace open regardless of relevance.",
            file="extension/package.json",
        ))

    contributes = pkg.get("contributes", {})
    info["commands"] = [c.get("command", "") for c in contributes.get("commands", [])]

    deps = {**pkg.get("dependencies", {}), **pkg.get("bundledDependencies", {})}
    info["dependencies"] = deps
    for pkg_name in deps:
        if pkg_name in KNOWN_MALICIOUS_PACKAGES:
            findings.append(Finding(
                severity="HIGH",
                category="supply_chain",
                title=f"Known malicious/compromised package: {pkg_name}",
                detail=f"'{pkg_name}' has a documented supply chain compromise history.",
                file="extension/package.json",
            ))

    # Suspicious install/postinstall scripts
    for script_name, script_cmd in pkg.get("scripts", {}).items():
        if any(danger in (script_cmd or "") for danger in ["curl ", "wget ", "eval ", "base64 "]):
            findings.append(Finding(
                severity="HIGH",
                category="supply_chain",
                title=f"Suspicious npm script: {script_name}",
                detail=f"Contains: {script_cmd[:120]}",
                file="extension/package.json",
            ))

    info["extension_kind"] = pkg.get("extensionKind", [])
    info["scripts"] = list(pkg.get("scripts", {}).keys())
    return findings, info


def inventory_files(vsix_dir: pathlib.Path) -> Tuple[List[Finding], dict]:
    findings = []
    inv: dict = {"total_files": 0, "js_files": 0, "unexpected": [], "type_counts": {}}

    for f in vsix_dir.rglob("*"):
        if not f.is_file():
            continue
        inv["total_files"] += 1
        suffix = f.suffix.lower()
        inv["type_counts"][suffix] = inv["type_counts"].get(suffix, 0) + 1
        if suffix == ".js":
            inv["js_files"] += 1
        if suffix in SUSPICIOUS_FILE_TYPES:
            rel = str(f.relative_to(vsix_dir))
            inv["unexpected"].append(rel)
            label, sev = SUSPICIOUS_FILE_TYPES[suffix]
            findings.append(Finding(
                severity=sev,
                category="suspicious_file",
                title=f"{label} bundled in extension",
                detail=f"File: {rel}",
                file=rel,
            ))

    return findings, inv


def compute_risk(findings: List[Finding]) -> str:
    for sev in ("HIGH", "MEDIUM", "LOW"):
        if any(f.severity == sev for f in findings):
            return sev
    return "CLEAN"


def deduplicate(findings: List[Finding]) -> List[Finding]:
    seen = set()
    out = []
    for f in findings:
        key = (f.title, f.file)
        if key not in seen:
            seen.add(key)
            out.append(f)
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    out.sort(key=lambda x: (order.get(x.severity, 3), x.file, x.line))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("working_dir", help="Directory produced by fetch_extension.py")
    args = ap.parse_args()

    work_dir = pathlib.Path(args.working_dir)
    if not work_dir.exists():
        print(f"[ERROR] Not found: {work_dir}", file=sys.stderr)
        sys.exit(1)

    meta_path = work_dir / "metadata.json"
    if not meta_path.exists():
        print("[ERROR] metadata.json missing — run fetch_extension.py first.", file=sys.stderr)
        sys.exit(1)

    metadata = json.loads(meta_path.read_text())
    vsix_dir = work_dir / "vsix"
    all_findings: List[Finding] = []
    all_urls: List[str] = []

    # 1. File inventory
    print("[*] Inventorying files ...", flush=True)
    file_findings, file_inv = inventory_files(vsix_dir)
    all_findings.extend(file_findings)
    print(f"    {file_inv['total_files']} total files, {file_inv['js_files']} JS files", flush=True)

    # 2. package.json
    pkg_info: dict = {}
    pkg_candidates = sorted(vsix_dir.rglob("package.json"))
    # Prefer extension/package.json
    extension_pkg = vsix_dir / "extension" / "package.json"
    pkg_path = extension_pkg if extension_pkg.exists() else (pkg_candidates[0] if pkg_candidates else None)
    if pkg_path:
        try:
            pkg = json.loads(pkg_path.read_text(encoding="utf-8", errors="replace"))
            pkg_findings, pkg_info = analyze_package_json(pkg)
            all_findings.extend(pkg_findings)
            print(
                f"[*] package.json: {len(pkg_info.get('activation_events', []))} activation events, "
                f"{len(pkg_info.get('commands', []))} commands, "
                f"{len(pkg_info.get('dependencies', {}))} deps",
                flush=True,
            )
        except Exception as e:
            print(f"[!] Could not parse package.json: {e}", flush=True)

    # 3. JS scanning (skip node_modules)
    js_files = [f for f in vsix_dir.rglob("*.js") if "node_modules" not in str(f)]
    print(f"[*] Scanning {len(js_files)} JS files (node_modules excluded) ...", flush=True)
    for js_file in js_files:
        f_findings, f_urls = scan_js_file(js_file, vsix_dir)
        all_findings.extend(f_findings)
        all_urls.extend(f_urls)

    urls_deduped = sorted(set(all_urls))[:60]

    # 4. Trust signals
    if metadata.get("install_count", 0) < 100:
        all_findings.append(Finding(
            severity="MEDIUM",
            category="trust",
            title="Very low install count",
            detail=f"Only {metadata.get('install_count', 0):,} installs — minimal community vetting.",
        ))
    if not metadata.get("publisher_verified"):
        all_findings.append(Finding(
            severity="LOW",
            category="trust",
            title="Publisher not verified by Microsoft",
            detail=f"Publisher '{metadata.get('publisher_name', '')}' lacks the Verified Publisher badge.",
        ))
    last_updated = metadata.get("last_updated", "")
    if last_updated:
        try:
            updated = datetime.fromisoformat(last_updated.replace("Z", "+00:00"))
            days_old = (datetime.now(timezone.utc) - updated).days
            if days_old > 730:
                all_findings.append(Finding(
                    severity="LOW",
                    category="trust",
                    title="Extension not updated in 2+ years",
                    detail=f"Last updated {days_old} days ago ({last_updated[:10]}).",
                ))
        except Exception:
            pass

    # 5. Finalize
    deduped = deduplicate(all_findings)
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in deduped:
        if f.severity in counts:
            counts[f.severity] += 1

    analysis = {
        "extension_id": metadata["extension_id"],
        "version": metadata["version"],
        "risk_score": compute_risk(deduped),
        "findings_count": counts,
        "findings": [asdict(f) for f in deduped],
        "package_info": pkg_info,
        "file_inventory": file_inv,
        "urls_found": urls_deduped,
    }

    out_path = work_dir / "analysis.json"
    out_path.write_text(json.dumps(analysis, indent=2))

    risk = analysis["risk_score"]
    print(f"[+] Risk: {risk} — HIGH:{counts['HIGH']} MED:{counts['MEDIUM']} LOW:{counts['LOW']}")
    print(f"[+] Analysis → {out_path}")
    print(out_path)  # machine-readable last line


if __name__ == "__main__":
    main()
