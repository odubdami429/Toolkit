#!/usr/bin/env python3
"""
Static security analysis of an extracted browser extension.
Usage: python3 analyze_browser_extension.py <working_dir>

Reads:  <working_dir>/metadata.json, <working_dir>/ext/
Writes: <working_dir>/analysis.json
Prints analysis.json path as the last line of stdout.
"""

import argparse
import json
import pathlib
import re
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import List, Tuple, Dict


# ---------------------------------------------------------------------------
# Permission risk taxonomy
# ---------------------------------------------------------------------------

HIGH_PERMISSIONS = {
    "<all_urls>", "*://*/*", "http://*/*", "https://*/*",
    "nativeMessaging", "cookies", "identity", "clipboardRead",
    "debugger", "proxy", "webRequestBlocking",
}

MEDIUM_PERMISSIONS = {
    "webRequest", "tabs", "history", "bookmarks", "downloads",
    "scripting", "management", "browsingData",
    "declarativeNetRequestFeedback", "webNavigation",
}

LOW_PERMISSIONS = {
    "storage", "unlimitedStorage", "notifications", "contextMenus",
    "alarms", "activeTab", "idle", "gcm",
    "system.cpu", "system.memory", "system.storage",
    "declarativeNetRequest",
}

HIGH_HOST_PATTERNS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}


def classify_permission(perm: str) -> str:
    if perm in HIGH_PERMISSIONS:
        return "HIGH"
    if perm in MEDIUM_PERMISSIONS:
        return "MEDIUM"
    if perm in LOW_PERMISSIONS:
        return "LOW"
    # Broad host match patterns
    if re.match(r"\*://\*", perm) or perm in HIGH_HOST_PATTERNS:
        return "HIGH"
    if re.match(r"https?://", perm):
        return "LOW"  # Specific domain — lower risk
    return "LOW"


# ---------------------------------------------------------------------------
# Code patterns
# ---------------------------------------------------------------------------

BROWSER_CODE_PATTERNS = [
    # HIGH: credential/cookie theft vectors
    (r"document\.cookie\b", "document.cookie access — cookie theft risk", "credential", "HIGH"),
    (r"addEventListener\s*\(\s*['\"]key(?:down|press|up)['\"]", "Keyboard event listener — potential keylogger", "credential", "HIGH"),
    (r"querySelector(?:All)?\s*\([^)]*(?:password|passwd)", "Password field selector — credential access", "credential", "HIGH"),
    (r"chrome\.identity\.(?:getAuthToken|launchWebAuthFlow)", "chrome.identity OAuth token access", "credential", "HIGH"),
    (r"(?:chrome|browser)\.cookies\.(?:get|getAll|set|remove)\s*\(", "Cookie API access", "credential", "HIGH"),
    (r"(?:chrome|browser)\.runtime\.(?:connectNative|sendNativeMessage)\s*\(", "Native messaging — communicates with native apps", "native", "HIGH"),
    (r"navigator\.clipboard\.(?:read|readText)\s*\(", "Clipboard read access", "credential", "HIGH"),
    # HIGH: code execution
    (r"\beval\s*\(", "eval() — arbitrary code execution", "code_execution", "HIGH"),
    (r"\bnew\s+Function\s*\(", "new Function() — indirect eval", "code_execution", "HIGH"),
    # MEDIUM: network/data collection
    (r"(?:chrome|browser)\.tabs\.query\s*\(", "chrome.tabs.query — reads tab URLs and titles", "data_collection", "MEDIUM"),
    (r"(?:chrome|browser)\.webRequest\.onBeforeRequest", "webRequest listener — intercepts network requests", "network", "MEDIUM"),
    (r"(?:chrome|browser)\.history\.search\s*\(", "History API — reads browsing history", "data_collection", "MEDIUM"),
    (r"(?:chrome|browser)\.storage\.sync\.set\s*\(", "storage.sync.set — data synced to Google account", "data_collection", "MEDIUM"),
    (r"window\.postMessage\s*\(", "postMessage — cross-origin communication", "network", "MEDIUM"),
    (r"\bXMLHttpRequest\b|\bnew\s+XHR\b", "XMLHttpRequest — outbound HTTP", "network", "MEDIUM"),
    (r"\bfetch\s*\(", "fetch() — outbound HTTP request", "network", "MEDIUM"),
    (r"require\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*[^'\"()\n]*\)", "dynamic require() — runtime module loading", "dynamic_loading", "MEDIUM"),
    # LOW
    (r"\blocalStorage\b", "localStorage access", "storage", "LOW"),
    (r"\bsessionStorage\b", "sessionStorage access", "storage", "LOW"),
]

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID"),
    (r"gh[pousr]_[A-Za-z0-9_]{36,255}", "GitHub token"),
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private key"),
    (r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "JWT token"),
    (r"(?i)(?:api[_\-]?key|apikey)\s*[:=]\s*['\"]([A-Za-z0-9_\-\.]{20,})['\"]", "Hardcoded API key"),
    (r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{8,})['\"]", "Hardcoded password"),
    (r"(?i)(?:secret|token)\s*[:=]\s*['\"]([^'\"]{16,})['\"]", "Hardcoded secret/token"),
    (r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}", "Bearer token"),
    (r"(?:https?://)[^:@\s\"'<>(){}[\],]{3,}:[^@\s\"'<>(){}[\],]{3,}@", "Credentials in URL"),
]

URL_SKIP = [
    "schema.", "example.com", "localhost", "127.0.0.1",
    "json-schema.org", "www.w3.org", "mozilla.org/en-US",
    "developer.mozilla", "developer.chrome.com",
    "googleapis.com/chrome/", "chromewebstore.google.com",
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


# ---------------------------------------------------------------------------
# Manifest analysis
# ---------------------------------------------------------------------------

def analyze_manifest(manifest: dict, base_file: str) -> Tuple[List[Finding], dict]:
    findings: List[Finding] = []
    summary: dict = {
        "all_permissions": [],
        "host_permissions": [],
        "content_scripts_coverage": "none",
        "content_scripts_run_at": [],
        "content_scripts_domains": [],
        "has_background": False,
        "background_type": "none",
        "csp": "",
    }

    mv = manifest.get("manifest_version", 2)

    # --- Permissions ---
    raw_perms = list(manifest.get("permissions", []))
    raw_host = list(manifest.get("host_permissions", []))  # MV3 separates these

    # In MV2, host patterns can appear in permissions[]
    perms = []
    host_perms = list(raw_host)
    for p in raw_perms:
        if re.match(r"(?:\*|https?|ftp)://", p) or p in ("<all_urls>",):
            host_perms.append(p)
        else:
            perms.append(p)

    summary["all_permissions"] = perms
    summary["host_permissions"] = host_perms

    for perm in perms:
        sev = classify_permission(perm)
        if sev in ("HIGH", "MEDIUM"):
            desc = _perm_description(perm)
            findings.append(Finding(
                severity=sev,
                category="permission",
                title=f"Permission: {perm}",
                detail=desc,
                file=base_file,
            ))

    for hp in host_perms:
        if hp in HIGH_HOST_PATTERNS or re.match(r"\*://\*", hp):
            findings.append(Finding(
                severity="HIGH",
                category="host_permission",
                title=f"Host permission: {hp} — access to all websites",
                detail="Extension can read and modify content on every website the user visits.",
                file=base_file,
            ))
        else:
            findings.append(Finding(
                severity="LOW",
                category="host_permission",
                title=f"Host permission: {hp}",
                detail="Access limited to specific domain(s).",
                file=base_file,
            ))

    # webRequestBlocking (MV2 only — highest risk combo)
    if "webRequest" in perms and "webRequestBlocking" in perms:
        findings.append(Finding(
            severity="HIGH",
            category="permission",
            title="webRequest + webRequestBlocking — can intercept and modify all HTTP traffic",
            detail="This combination allows the extension to read, modify, or block any HTTP request/response "
                   "including authentication headers and response bodies.",
            file=base_file,
        ))

    # --- Content scripts ---
    cs_list = manifest.get("content_scripts", [])
    if cs_list:
        summary["has_background"] = True
        all_domains = []
        run_ats = []
        for cs in cs_list:
            matches = cs.get("matches", [])
            all_domains.extend(matches)
            run_ats.append(cs.get("run_at", "document_idle"))
            is_all_urls = any(
                m in ("<all_urls>", "*://*/*", "http://*/*", "https://*/*") for m in matches
            )
            if is_all_urls:
                summary["content_scripts_coverage"] = "all_urls"
                findings.append(Finding(
                    severity="HIGH",
                    category="content_script",
                    title="Content script runs on all websites (<all_urls>)",
                    detail="Extension JavaScript executes in the context of every website the user visits.",
                    file=base_file,
                ))
            elif matches and summary["content_scripts_coverage"] != "all_urls":
                summary["content_scripts_coverage"] = "specific_domains"
                findings.append(Finding(
                    severity="LOW",
                    category="content_script",
                    title=f"Content script on specific domains: {', '.join(matches[:5])}",
                    detail="Extension injects JavaScript only on listed domains.",
                    file=base_file,
                ))
            if cs.get("run_at") == "document_start":
                findings.append(Finding(
                    severity="HIGH",
                    category="content_script",
                    title="Content script runs at document_start",
                    detail="Script executes before the page DOM is built — can intercept data before the page loads.",
                    file=base_file,
                ))
            if cs.get("all_frames"):
                findings.append(Finding(
                    severity="MEDIUM",
                    category="content_script",
                    title="Content script runs in all iframes (all_frames: true)",
                    detail="Extension code executes inside every iframe on matched pages.",
                    file=base_file,
                ))
        summary["content_scripts_run_at"] = list(set(run_ats))
        summary["content_scripts_domains"] = list(set(all_domains))[:20]

    # --- Background ---
    bg = manifest.get("background", {})
    if bg:
        summary["has_background"] = True
        if bg.get("service_worker"):
            summary["background_type"] = "service_worker"
        elif bg.get("scripts") or bg.get("page"):
            summary["background_type"] = "scripts"
            findings.append(Finding(
                severity="LOW",
                category="background",
                title="MV2 background scripts (persistent)",
                detail="Background scripts run persistently. MV3 service workers are ephemeral by comparison.",
                file=base_file,
            ))

    # --- CSP ---
    csp = manifest.get("content_security_policy", "")
    if isinstance(csp, dict):
        csp = " ".join(csp.values())
    summary["csp"] = csp
    if "unsafe-eval" in csp:
        findings.append(Finding(
            severity="HIGH",
            category="csp",
            title="CSP allows unsafe-eval",
            detail=f"Content Security Policy permits eval(). CSP: {csp[:120]}",
            file=base_file,
        ))
    if "unsafe-inline" in csp:
        findings.append(Finding(
            severity="MEDIUM",
            category="csp",
            title="CSP allows unsafe-inline scripts",
            detail=f"Inline JavaScript allowed by CSP. CSP: {csp[:120]}",
            file=base_file,
        ))
    # External script sources in CSP
    for ext_src in re.findall(r"https?://[^\s;]+", csp):
        if not any(safe in ext_src for safe in ["'self'", "googleapis.com/chrome"]):
            findings.append(Finding(
                severity="MEDIUM",
                category="csp",
                title=f"CSP loads scripts from external domain: {ext_src[:60]}",
                detail="Extension can execute code from a third-party server.",
                file=base_file,
            ))

    # --- MV2 note ---
    if mv == 2:
        findings.append(Finding(
            severity="LOW",
            category="manifest_version",
            title="Manifest V2 (deprecated)",
            detail="MV2 is deprecated by Chrome and supports broader capabilities than MV3 "
                   "(blocking webRequest, persistent background pages). Migrate to MV3 preferred.",
            file=base_file,
        ))

    return findings, summary


def _perm_description(perm: str) -> str:
    DESC = {
        "tabs": "Read URLs and titles of all open tabs",
        "history": "Access full browsing history",
        "bookmarks": "Read and modify bookmarks",
        "downloads": "Monitor and manage file downloads",
        "cookies": "Read and write cookies for all sites",
        "identity": "Access OAuth tokens via Chrome Identity API",
        "nativeMessaging": "Communicate with native apps installed on the system",
        "clipboardRead": "Read the system clipboard",
        "debugger": "Attach debugger to any tab — grants full page access",
        "proxy": "Configure and intercept proxy settings",
        "webRequest": "Observe all HTTP requests",
        "webRequestBlocking": "Block or modify HTTP requests",
        "scripting": "Inject JavaScript into pages (MV3)",
        "management": "Manage other installed extensions",
        "browsingData": "Clear browsing data including cookies and cache",
        "declarativeNetRequestFeedback": "Observe all intercepted requests",
        "webNavigation": "Monitor all navigation events",
    }
    return DESC.get(perm, f"Browser permission: {perm}")


# ---------------------------------------------------------------------------
# JS file scanning
# ---------------------------------------------------------------------------

def scan_js_file(filepath: pathlib.Path, base_dir: pathlib.Path) -> Tuple[List[Finding], List[str]]:
    findings: List[Finding] = []
    urls: List[str] = []
    rel = str(filepath.relative_to(base_dir))

    if "_locales" in rel:
        return [], []

    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return [], []

    lines = content.split("\n")

    # Obfuscation
    for i, line in enumerate(lines, 1):
        if len(line) > 500:
            findings.append(Finding(
                severity="MEDIUM", category="obfuscation",
                title="Very long line — possible obfuscation or minification",
                detail=f"Line {i} is {len(line):,} chars",
                file=rel, line=i, context=line[:100] + "...",
            ))
            break

    b64_re = re.compile(r"['\"][A-Za-z0-9+/]{200,}={0,2}['\"]")
    for m in b64_re.finditer(content):
        ln = content[: m.start()].count("\n") + 1
        findings.append(Finding(
            severity="LOW", category="obfuscation",
            title="Large base64 blob",
            detail=f"Base64 string of length {len(m.group()) - 2}",
            file=rel, line=ln, context=m.group()[:60] + "...",
        ))
        break

    if content.count("String.fromCharCode") > 3:
        findings.append(Finding(
            severity="MEDIUM", category="obfuscation",
            title="Heavy String.fromCharCode usage — obfuscation indicator",
            detail=f"{content.count('String.fromCharCode')} occurrences",
            file=rel,
        ))

    # Code patterns
    for pattern, desc, category, severity in BROWSER_CODE_PATTERNS:
        for m in re.finditer(pattern, content):
            ln = content[: m.start()].count("\n") + 1
            ctx = lines[ln - 1].strip()[:120] if ln <= len(lines) else ""
            findings.append(Finding(
                severity=severity, category=category, title=desc,
                detail=f"Matched: {m.group()!r}",
                file=rel, line=ln, context=ctx,
            ))

    # Secrets
    for pattern, desc in SECRET_PATTERNS:
        for m in re.finditer(pattern, content):
            ln = content[: m.start()].count("\n") + 1
            matched = m.group()
            masked = matched[:8] + "…" + matched[-4:] if len(matched) > 14 else matched
            findings.append(Finding(
                severity="HIGH", category="secret",
                title=f"Potential secret: {desc}",
                detail=f"Matched (masked): {masked}",
                file=rel, line=ln, context="[content masked]",
            ))

    # URLs
    for m in re.finditer(r"https?://[^\s'\"<>(){}[\]\\,;`]+", content):
        url = m.group().rstrip(".,;)")
        if not any(skip in url for skip in URL_SKIP):
            urls.append(url)

    return findings, urls


def inventory_files(ext_dir: pathlib.Path) -> Tuple[List[Finding], dict]:
    findings: List[Finding] = []
    inv = {"total_files": 0, "js_files": 0, "type_counts": {}, "unexpected": []}

    SUSPICIOUS = {
        ".exe": ("Windows executable", "HIGH"),
        ".dll": ("Windows DLL", "HIGH"),
        ".so": ("Unix shared library", "HIGH"),
        ".dylib": ("macOS dynamic library", "HIGH"),
        ".sh": ("Shell script", "MEDIUM"),
        ".bat": ("Windows batch file", "MEDIUM"),
        ".ps1": ("PowerShell script", "MEDIUM"),
    }

    for f in ext_dir.rglob("*"):
        if not f.is_file():
            continue
        inv["total_files"] += 1
        suffix = f.suffix.lower()
        inv["type_counts"][suffix] = inv["type_counts"].get(suffix, 0) + 1
        if suffix == ".js":
            inv["js_files"] += 1
        if suffix in SUSPICIOUS:
            rel = str(f.relative_to(ext_dir))
            label, sev = SUSPICIOUS[suffix]
            inv["unexpected"].append(rel)
            findings.append(Finding(
                severity=sev, category="suspicious_file",
                title=f"{label} bundled in extension",
                detail=f"File: {rel}", file=rel,
            ))

    return findings, inv


# ---------------------------------------------------------------------------
# Data flow analysis
# ---------------------------------------------------------------------------

# Firebase SDK function names → service label
FIREBASE_SERVICE_PATTERNS = [
    (r"\bgetDatabase\s*\(", "realtime-database"),
    (r"\bgetFirestore\s*\(", "firestore"),
    (r"\bgetAuth\s*\(", "auth"),
    (r"\bgetFunctions\s*\(", "cloud-functions"),
    (r"\bgetStorage\s*\(", "firebase-storage"),
    (r"\bgetMessaging\s*\(", "firebase-messaging"),
    (r"\bgetAnalytics\s*\(", "firebase-analytics"),
    (r"\bgetRemoteConfig\s*\(", "remote-config"),
]

# Firebase auth sign-in methods
AUTH_METHOD_PATTERNS = [
    (r"\bsignInWithEmailAndPassword\b", "email-password"),
    (r"\bsignInWithPopup\b|\bsignInWithRedirect\b", "oauth-popup/redirect"),
    (r"\bsignInAnonymously\b", "anonymous"),
    (r"\bsignInWithCustomToken\b", "custom-token"),
    (r"\bsignInWithCredential\b", "credential"),
    (r"\bsignInWithPhoneNumber\b", "phone"),
    (r"\bcreateUserWithEmailAndPassword\b", "email-password-register"),
]

# Firebase write operations (data flows TO Firebase)
FIREBASE_WRITE_PATTERNS = [
    (r"\bsetDoc\s*\(", "Firestore setDoc"),
    (r"\baddDoc\s*\(", "Firestore addDoc"),
    (r"\bupdateDoc\s*\(", "Firestore updateDoc"),
    (r"\bwriteBatch\b", "Firestore batch write"),
    (r"\.ref\s*\([^)]+\)\s*\.set\s*\(", "Realtime DB .set()"),
    (r"\.ref\s*\([^)]+\)\s*\.update\s*\(", "Realtime DB .update()"),
    (r"\.ref\s*\([^)]+\)\s*\.push\s*\(", "Realtime DB .push()"),
    (r"\buploadBytes\s*\(", "Firebase Storage upload"),
    (r"\buploadString\s*\(", "Firebase Storage upload"),
]

# Indicators that user *content* (not just IDs) may be leaving the browser
CONTENT_EXFIL_PATTERNS = [
    (r"storage\.sync\.set[^;]{0,200}(?:query|search|highlight|url|href|title|history|text)", "Search/highlight data in sync storage"),
    (r"fetch\s*\([^)]*(?:query|search|highlight|selection|text)[^)]*\)", "User content in fetch() call"),
    (r"\.send\s*\([^)]*(?:query|highlight|selection|url)[^)]*\)", "User content in XHR send"),
    (r"btoa\s*\([^)]*(?:highlight|query|search|text|page|url)[^)]*\)", "User content base64-encoded for transmission"),
]

# User identifier patterns in outbound URLs/payloads
USER_ID_PATTERNS = [
    (r"(?:fetch|get|post|send)\s*\([^)]*(?:uid|userId|user_id)[^)]*\)", "uid in network call"),
    (r"[?&]uid=", "uid as URL parameter"),
    (r"[?&]email=", "email as URL parameter"),
    (r"[?&]user(?:Id|_id|Email)=", "user identifier as URL parameter"),
    (r"btoa\s*\([^)]*email[^)]*\)", "email base64-encoded"),
]


def analyze_data_flows(js_files: List[pathlib.Path], ext_dir: pathlib.Path) -> dict:
    """
    Trace what data the extension collects and where it sends it.
    Produces a structured data_flows dict for analysis.json and the report.
    """
    flows: dict = {
        "sync_storage_keys": [],       # keys written to chrome.storage.sync (→ Google)
        "local_storage_keys": [],      # keys written to chrome.storage.local (stays local)
        "outbound_endpoints": [],      # unique base URLs of fetch/XHR calls
        "firebase_services": [],       # which Firebase services are initialised
        "firebase_writes": [],         # Firebase write operations found
        "auth_methods": [],            # how users authenticate
        "user_data_in_outbound": {     # does user-identifying data appear in network calls?
            "uid": False,
            "email": False,
            "page_content": False,
            "search_queries": False,
        },
        "btoa_payloads": [],           # what gets base64-encoded (potential hidden exfil)
        "verdict": "UNKNOWN",          # LOCAL_ONLY | SUBSCRIPTION_ONLY | SENDS_USER_CONTENT | UNKNOWN
        "verdict_reasons": [],
    }

    combined = ""
    for js_file in js_files:
        if "_locales" in str(js_file):
            continue
        try:
            combined += js_file.read_text(encoding="utf-8", errors="replace") + "\n"
        except Exception:
            pass

    if not combined:
        return flows

    # --- chrome.storage.sync keys ---
    # Literal string keys passed directly
    for m in re.finditer(r'storage\.sync\.set\s*\(\s*\{([^}]{1,600})\}', combined):
        block = m.group(1)
        for km in re.finditer(r'["\']([^"\']{2,80})["\']', block):
            k = km.group(1)
            if k not in flows["sync_storage_keys"]:
                flows["sync_storage_keys"].append(k)
    # Computed key: [{variable}: value] — extract the variable's string value
    for m in re.finditer(r'\[\s*([A-Za-z_$][A-Za-z0-9_$]{0,30})\s*\]\s*:', combined):
        varname = m.group(1)
        vm = re.search(rf'(?:const|var|let)\s+{re.escape(varname)}\s*=\s*["\']([^"\']+)["\']', combined)
        if vm and vm.group(1) not in flows["sync_storage_keys"]:
            flows["sync_storage_keys"].append(vm.group(1))

    # --- chrome.storage.local keys ---
    for m in re.finditer(r'storage\.local\.set\s*\(\s*\{([^}]{1,600})\}', combined):
        block = m.group(1)
        for km in re.finditer(r'["\']([^"\']{2,80})["\']', block):
            k = km.group(1)
            if k not in flows["local_storage_keys"]:
                flows["local_storage_keys"].append(k)
    for m in re.finditer(r'storage\.local\.set\s*\(.*?\[\s*([A-Za-z_$][A-Za-z0-9_$]{0,30})\s*\]', combined):
        varname = m.group(1)
        vm = re.search(rf'(?:const|var|let)\s+{re.escape(varname)}\s*=\s*["\']([^"\']+)["\']', combined)
        if vm and vm.group(1) not in flows["local_storage_keys"]:
            flows["local_storage_keys"].append(vm.group(1))

    # --- Hardcoded outbound endpoints ---
    seen_endpoints = set()
    for m in re.finditer(r"""fetch\s*\(\s*["'`]([^"'`\s]{8,200})["'`]""", combined):
        url = m.group(1)
        base = re.match(r"(https?://[^/?#\s]{4,80})", url)
        if base and base.group(1) not in seen_endpoints:
            seen_endpoints.add(base.group(1))
            flows["outbound_endpoints"].append(base.group(1))
    # Dynamic fetch with concat / template literal
    for m in re.finditer(r"""fetch\s*\(\s*["'`][^"'`]{4,100}["'`]\s*(?:\.concat\s*\(|\+)""", combined):
        ctx = combined[m.start(): m.start()+200]
        url_m = re.search(r"""["'`](https?://[^"'`\s]{4,80})["'`]""", ctx)
        if url_m:
            base = url_m.group(1).rstrip("/?&")
            if base not in seen_endpoints:
                seen_endpoints.add(base)
                flows["outbound_endpoints"].append(base + " [+dynamic params]")

    # --- Firebase services ---
    seen_services = set()
    for pattern, label in FIREBASE_SERVICE_PATTERNS:
        if re.search(pattern, combined) and label not in seen_services:
            seen_services.add(label)
            flows["firebase_services"].append(label)

    # --- Firebase writes ---
    seen_writes = set()
    for pattern, label in FIREBASE_WRITE_PATTERNS:
        if re.search(pattern, combined) and label not in seen_writes:
            seen_writes.add(label)
            flows["firebase_writes"].append(label)

    # --- Auth methods ---
    seen_auth = set()
    for pattern, label in AUTH_METHOD_PATTERNS:
        if re.search(pattern, combined) and label not in seen_auth:
            seen_auth.add(label)
            flows["auth_methods"].append(label)

    # --- User data in outbound calls ---
    for pattern, _ in USER_ID_PATTERNS:
        if re.search(pattern, combined):
            if "email" in pattern:
                flows["user_data_in_outbound"]["email"] = True
            else:
                flows["user_data_in_outbound"]["uid"] = True

    # --- Content exfil indicators ---
    for pattern, desc in CONTENT_EXFIL_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            if "search" in desc.lower() or "query" in desc.lower():
                flows["user_data_in_outbound"]["search_queries"] = True
                flows["verdict_reasons"].append(desc)
            elif "highlight" in desc.lower() or "text" in desc.lower() or "page" in desc.lower():
                flows["user_data_in_outbound"]["page_content"] = True
                flows["verdict_reasons"].append(desc)

    # --- btoa() payloads ---
    for m in re.finditer(r'btoa\s*\(([^)]{0,300})\)', combined):
        payload_expr = m.group(1).strip()
        if len(payload_expr) > 5:
            flows["btoa_payloads"].append(payload_expr[:120])

    # --- Compute verdict ---
    sends_content = (
        flows["user_data_in_outbound"]["page_content"]
        or flows["user_data_in_outbound"]["search_queries"]
    )
    has_firebase_writes = bool(flows["firebase_writes"])
    sends_ids = (
        flows["user_data_in_outbound"]["uid"]
        or flows["user_data_in_outbound"]["email"]
    )
    has_outbound = bool(flows["outbound_endpoints"]) or bool(flows["firebase_services"])

    if sends_content or has_firebase_writes:
        flows["verdict"] = "SENDS_USER_CONTENT"
        if not flows["verdict_reasons"]:
            flows["verdict_reasons"].append(
                "Firebase writes or content-bearing fetch calls detected"
            )
    elif sends_ids and has_outbound:
        flows["verdict"] = "SUBSCRIPTION_ONLY"
        flows["verdict_reasons"].append(
            "Only user identifiers (uid/email) sent — no highlight/search content detected in outbound calls"
        )
    elif has_outbound and not sends_ids:
        flows["verdict"] = "READ_ONLY_BACKEND"
        flows["verdict_reasons"].append(
            "Extension reads from backend (config/messages) but sends no user-identifying data"
        )
    elif not has_outbound and not flows["firebase_services"]:
        flows["verdict"] = "LOCAL_ONLY"
        flows["verdict_reasons"].append("No outbound network calls or cloud services detected")
    else:
        flows["verdict"] = "UNKNOWN"
        flows["verdict_reasons"].append(
            "Dynamic network calls present — manual review required to confirm what data is sent"
        )

    # Deduplicate lists
    flows["sync_storage_keys"] = list(dict.fromkeys(flows["sync_storage_keys"]))[:20]
    flows["local_storage_keys"] = list(dict.fromkeys(flows["local_storage_keys"]))[:20]
    flows["outbound_endpoints"] = list(dict.fromkeys(flows["outbound_endpoints"]))[:20]
    flows["btoa_payloads"] = list(dict.fromkeys(flows["btoa_payloads"]))[:10]

    return flows


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


def compute_risk(findings: List[Finding]) -> str:
    for sev in ("HIGH", "MEDIUM", "LOW"):
        if any(f.severity == sev for f in findings):
            return sev
    return "CLEAN"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("working_dir")
    args = ap.parse_args()

    work_dir = pathlib.Path(args.working_dir)
    meta = json.loads((work_dir / "metadata.json").read_text())
    ext_dir = work_dir / "ext"

    print(f"[*] Analyzing {meta['name']} ({meta['browser']}) v{meta['version']} ...", flush=True)

    all_findings: List[Finding] = []
    all_urls: List[str] = []

    # 1. File inventory
    print("[*] Inventorying files ...", flush=True)
    file_findings, file_inv = inventory_files(ext_dir)
    all_findings.extend(file_findings)
    print(f"    {file_inv['total_files']} total, {file_inv['js_files']} JS", flush=True)

    # 2. Manifest
    mv = 2
    perm_summary = {}
    mf_path = ext_dir / "manifest.json"
    if mf_path.exists():
        manifest = json.loads(mf_path.read_text(encoding="utf-8", errors="replace"))
        mv = manifest.get("manifest_version", 2)
        mf_findings, perm_summary = analyze_manifest(manifest, "manifest.json")
        all_findings.extend(mf_findings)
        print(
            f"[*] MV{mv} | {len(perm_summary.get('all_permissions', []))} permissions | "
            f"{len(perm_summary.get('host_permissions', []))} host perms | "
            f"content scripts: {perm_summary.get('content_scripts_coverage', 'none')}",
            flush=True,
        )

    # 3. JS scanning
    js_files = [f for f in ext_dir.rglob("*.js") if "_locales" not in str(f)]
    print(f"[*] Scanning {len(js_files)} JS files ...", flush=True)
    for js_file in js_files:
        f_findings, f_urls = scan_js_file(js_file, ext_dir)
        all_findings.extend(f_findings)
        all_urls.extend(f_urls)

    # 4. Data flow analysis
    print("[*] Analyzing data flows ...", flush=True)
    data_flows = analyze_data_flows(js_files, ext_dir)
    print(
        f"    Data flow verdict: {data_flows['verdict']} | "
        f"Firebase: {data_flows['firebase_services']} | "
        f"Writes: {data_flows['firebase_writes']}",
        flush=True,
    )

    # 6. Trust signals
    if meta.get("install_count", 0) < 1000:
        all_findings.append(Finding(
            severity="MEDIUM", category="trust",
            title="Very low install count",
            detail=f"Only {meta.get('install_count', 0):,} installs — minimal community vetting.",
        ))
    elif meta.get("install_count", 0) < 10000:
        all_findings.append(Finding(
            severity="LOW", category="trust",
            title="Low install count",
            detail=f"{meta.get('install_count', 0):,} installs — limited community vetting.",
        ))

    last_updated = meta.get("last_updated", "")
    if last_updated:
        try:
            updated = datetime.fromisoformat(last_updated.replace("Z", "+00:00"))
            days_old = (datetime.now(timezone.utc) - updated).days
            if days_old > 730:
                all_findings.append(Finding(
                    severity="LOW", category="trust",
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
        "extension_id": meta["extension_id"],
        "browser": meta["browser"],
        "version": meta["version"],
        "manifest_version": mv,
        "risk_score": compute_risk(deduped),
        "findings_count": counts,
        "findings": [asdict(f) for f in deduped],
        "permissions_summary": perm_summary,
        "file_inventory": file_inv,
        "urls_found": sorted(set(all_urls))[:60],
        "data_flows": data_flows,
    }

    out_path = work_dir / "analysis.json"
    out_path.write_text(json.dumps(analysis, indent=2))

    risk = analysis["risk_score"]
    print(f"[+] Risk: {risk} — HIGH:{counts['HIGH']} MED:{counts['MEDIUM']} LOW:{counts['LOW']}")
    print(f"[+] Data flows: {data_flows['verdict']}")
    print(f"[+] Analysis → {out_path}")
    print(out_path)


if __name__ == "__main__":
    main()
