---
name: eml-security-analyzer
description: "Analyze .eml email files for security threats and phishing indicators. Use this skill whenever the user uploads or mentions a .eml file, asks to check if an email is safe, wants phishing analysis, email header inspection, attachment risk assessment, or link safety checks. Also trigger when the user says things like 'is this email legit', 'should I trust this email', 'analyze this email', 'check this email for phishing', 'is this spam', or mentions suspicious emails. Accepts three input formats: .eml files, raw email headers (pasted as text), and Proofpoint TAP JSON logs. Produces two reports: a detailed technical report for security engineers and a plain-language summary for non-technical end users. Even if the user doesn't explicitly say 'security analysis', trigger this skill any time a .eml file, email header block, or Proofpoint log is involved."
---

# EML Security Analyzer

Analyze email artifacts to determine whether they are safe, suspicious, or malicious. Produce two distinct outputs — one for a security engineer and one for a non-technical end user.

## Supported input formats

This skill accepts three input formats. Detect which one you're working with before proceeding to parsing.

### Format A: `.eml` file
A full MIME email file uploaded by the user. Contains headers, body, and any attachments. This is the richest input — you can analyze everything.

**How to detect:** File with `.eml` extension in `/mnt/user-data/uploads/`, or user says "EML file."

### Format B: Raw email headers
A block of header text pasted into the conversation or provided in a text file. Contains header lines (From, To, Received, Authentication-Results, etc.) but no body content or attachments.

**How to detect:** Text block starting with header-like lines (`Received:`, `From:`, `To:`, `Subject:`, `Date:`, `DKIM-Signature:`, `Authentication-Results:`, etc.). May also be a `.txt` or `.msg` file containing only headers.

**What you can and can't do:** You have full header analysis (authentication, routing, spoofing checks) but no body content, URL, or attachment analysis. Clearly state in both reports that body/URL/attachment analysis was not possible because only headers were provided.

### Format C: Proofpoint TAP JSON log
A structured JSON object from Proofpoint's Threat Activity Platform containing pre-parsed metadata: connection info, envelope, headers, authentication module results, spam scores, URL extractions, message part hashes, and disposition actions.

**How to detect:** JSON object with fields like `connection`, `envelope`, `msg`, `msgParts`, `filter.modules.spf`, `filter.modules.dkimv`, `filter.modules.dmarc`, `filter.modules.spam`, `filter.disposition`, or `filter.quarantine`. May be pasted inline or uploaded as `.json`.

**What you can and can't do:** You get authentication results, spam scores, extracted URLs, attachment metadata (hashes, MIME types, sizes), and Proofpoint's own disposition — but you don't have the raw email body text to analyze for social engineering language. URL analysis is possible from the extracted URL list. Note in the reports that body content analysis was limited to what Proofpoint extracted.

### Parsing strategy by format

| Format | Headers | Auth results | Body text | URLs | Attachments |
|---|---|---|---|---|---|
| `.eml` file | Full — parse with `email` library | Extract from headers | Full — extract from MIME parts | Full — extract from HTML + plain text | Full — filenames, types, sizes, hashes |
| Raw headers | Full — parse line by line | Extract from headers | **Not available** | **Not available** | **Not available** |
| Proofpoint JSON | From `msg.header` / `msg.normalizedHeader` | From `filter.modules.spf/dkimv/dmarc` | **Limited** — only `msgParts[].textExtracted` (often base64 summary, not full text) | From `msgParts[].urls[]` — pre-extracted | From `msgParts[]` — filename, MIME type, size, SHA256, MD5 |

## Step 0 — Detect input format and parse

Before anything else, determine which format you have and parse accordingly.

### Parsing Format A: `.eml` file

Use Python's built-in `email` library. It handles MIME structure, encodings, and nested parts without external dependencies.

```python
import email
from email import policy

with open(EML_PATH, 'rb') as f:
    msg = email.message_from_binary_file(f, policy=policy.default)
```

Extract these artifacts into a structured dict for analysis:

### 1a. Headers (the most important evidence)

```python
headers = {}
headers['from'] = msg['From']
headers['to'] = msg['To']
headers['reply_to'] = msg['Reply-To']
headers['return_path'] = msg['Return-Path']
headers['subject'] = msg['Subject']
headers['date'] = msg['Date']
headers['message_id'] = msg['Message-ID']

# Full Received chain — read bottom-to-top for true routing
headers['received'] = msg.get_all('Received', [])

# Authentication results
headers['auth_results'] = msg.get_all('Authentication-Results', [])
headers['dkim_signature'] = msg.get_all('DKIM-Signature', [])
headers['spf'] = [h for h in msg.get_all('Received-SPF', []) or []]
headers['dmarc'] = [h for h in headers['auth_results'] if 'dmarc' in h.lower()]

# ARC headers (forwarded mail authentication)
headers['arc_auth'] = msg.get_all('ARC-Authentication-Results', [])

# Other security-relevant headers
headers['x_mailer'] = msg.get('X-Mailer', '')
headers['x_originating_ip'] = msg.get('X-Originating-IP', '')
headers['x_spam_status'] = msg.get('X-Spam-Status', '')
headers['x_spam_score'] = msg.get('X-Spam-Score', '')
headers['content_type'] = msg.get_content_type()
```

### 1b. Body content

```python
bodies = {'plain': [], 'html': []}
for part in msg.walk():
    ct = part.get_content_type()
    if ct == 'text/plain':
        bodies['plain'].append(part.get_content())
    elif ct == 'text/html':
        bodies['html'].append(part.get_content())
```

### 1c. URLs (from both plain text and HTML)

```python
import re
from html.parser import HTMLParser

# Plain text URLs
url_pattern = re.compile(r'https?://[^\s<>"\')\]]+')
urls_plain = []
for body in bodies['plain']:
    urls_plain.extend(url_pattern.findall(body))

# HTML href URLs + display text (critical for mismatch detection)
class LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []  # list of (href, display_text)
        self._current_href = None
        self._current_text = []

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            href = dict(attrs).get('href', '')
            self._current_href = href
            self._current_text = []

    def handle_data(self, data):
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag):
        if tag == 'a' and self._current_href is not None:
            display = ''.join(self._current_text).strip()
            self.links.append((self._current_href, display))
            self._current_href = None

urls_html = []
for body in bodies['html']:
    parser = LinkExtractor()
    parser.feed(body)
    urls_html.extend(parser.links)
```

### 1d. Attachments

```python
attachments = []
for part in msg.walk():
    fn = part.get_filename()
    if fn:
        attachments.append({
            'filename': fn,
            'content_type': part.get_content_type(),
            'size': len(part.get_payload(decode=True) or b''),
        })
```

### Parsing Format B: Raw email headers

When the user provides raw headers (pasted text or a text file), parse them line by line. Headers are `Key: Value` pairs; continuation lines start with whitespace.

```python
import re

def parse_raw_headers(header_text):
    """Parse a raw header block into a dict of key -> list of values."""
    headers = {}
    current_key = None
    current_value = []

    for line in header_text.splitlines():
        if not line.strip():
            continue  # skip blank lines
        if line[0] in (' ', '\t'):
            # continuation line
            if current_key:
                current_value.append(line.strip())
        else:
            # save previous header
            if current_key:
                full_value = ' '.join(current_value)
                headers.setdefault(current_key.lower(), []).append(full_value)
            # parse new header
            match = re.match(r'^([\w-]+):\s*(.*)', line)
            if match:
                current_key = match.group(1)
                current_value = [match.group(2)]
            else:
                current_key = None
                current_value = []

    # save last header
    if current_key:
        full_value = ' '.join(current_value)
        headers.setdefault(current_key.lower(), []).append(full_value)

    return headers
```

Extract the same header fields as the EML parser (From, To, Reply-To, Return-Path, Subject, Date, Message-ID, Received chain, Authentication-Results, DKIM-Signature, Received-SPF, etc.). Then proceed to Step 1 analysis — but **skip body, URL, and attachment analysis entirely** and note in both reports that these were unavailable.

### Parsing Format C: Proofpoint TAP JSON

When the input is a Proofpoint JSON log, map the structured fields to the same analysis categories:

```python
import json

# If uploaded as a file:
with open(JSON_PATH, 'r') as f:
    pp = json.load(f)

# If pasted inline, parse from the conversation text.

# Map to analysis fields:
headers = {
    'from': pp['msg']['parsedAddresses']['from'][0],
    'from_display': pp['msg']['parsedAddresses'].get('fromDisplayNames', [''])[0],
    'to': pp['msg']['parsedAddresses']['to'][0],
    'reply_to': pp['msg']['parsedAddresses'].get('reply-to', [None])[0],
    'return_path': pp['envelope']['from'],
    'subject': pp['msg']['normalizedHeader']['subject'][0],
    'message_id': pp['msg']['header']['message-id'][0],
    'date': pp['ts'],
}

connection = {
    'ip': pp['connection']['ip'],
    'host': pp['connection']['host'],
    'helo': pp['connection']['helo'],
    'country': pp['connection']['country'],
    'tls': pp['connection'].get('tls', {}),
}

auth = {
    'spf': pp['filter']['modules'].get('spf', {}),
    'dkim': pp['filter']['modules'].get('dkimv', []),
    'dmarc': pp['filter']['modules'].get('dmarc', {}),
}

spam = pp['filter']['modules'].get('spam', {})
disposition = pp['filter'].get('disposition', 'unknown')
quarantine = pp['filter'].get('quarantine', {})

# URLs — pre-extracted by Proofpoint, available in msgParts
urls = []
for part in pp.get('msgParts', []):
    for url_obj in part.get('urls', []):
        urls.append(url_obj)

# Attachments — from msgParts (non-inline parts with filenames)
attachments = []
for part in pp.get('msgParts', []):
    if part.get('disposition') != 'inline' or part.get('detectedName', '').endswith(('.html', '.txt')) is False:
        attachments.append({
            'filename': part.get('detectedName', 'unknown'),
            'content_type': part.get('detectedMime', 'unknown'),
            'size': part.get('sizeDecodedBytes', 0),
            'sha256': part.get('sha256', ''),
            'md5': part.get('md5', ''),
        })
```

**Key differences when working with Proofpoint JSON:**

- Authentication results come from `filter.modules` (pre-parsed, structured) rather than raw header text. You don't need to regex-parse Authentication-Results headers.
- Spam/threat scores are directly available in `filter.modules.spam.scores` — use these as strong evidence in your verdict. Proofpoint's `disposition` field tells you what actually happened to the message (delivered, quarantined, discarded).
- URLs are pre-extracted in `msgParts[].urls[]` with domain, path, query, and full URL already separated. Check these the same way you'd check URLs from an EML.
- Body text is usually **not available** in full form. The `textExtracted` field in msgParts is often a truncated or encoded summary. Note this limitation in both reports.
- Include Proofpoint's disposition chain (`filter.actions`) in the security engineer report — it shows exactly which modules fired and what action each took.

## Why two reports?

Security engineers need the raw evidence: full header chains, authentication results, IOCs, and MITRE ATT&CK mappings so they can triage, escalate, and write detection rules. End users just need a clear verdict and simple instructions so they know what to do next. Collapsing both audiences into one report serves neither well.

## Step 1 — Analyze each artifact for risk signals

Work through this checklist systematically. For each check, record a finding with a severity (critical / high / medium / low / info) and a short explanation.

### Header analysis

| Check | What to look for |
|---|---|
| **From vs Return-Path mismatch** | If the envelope sender (Return-Path) differs from the display From address, that is suspicious — it can indicate spoofing. |
| **From vs Reply-To mismatch** | Replies going to a different domain than the sender's — classic phishing pattern to intercept responses. |
| **SPF result** | Look for `spf=pass`. A fail or softfail means the sending IP wasn't authorized by the domain's DNS records. |
| **DKIM result** | Look for `dkim=pass`. A fail means the message was altered in transit or the signature is forged. |
| **DMARC result** | Look for `dmarc=pass`. A fail means the domain owner's anti-spoofing policy was violated. |
| **Received chain consistency** | Read bottom-to-top. Check that the originating server matches the claimed sending domain. Look for unexpected hops, residential IPs, or known-bad hosting. |
| **X-Originating-IP** | If present, check if it's from an unexpected geography or a known VPN/proxy/hosting range. |
| **Display name spoofing** | "John Smith <random@evil.com>" — the display name looks legitimate but the email address doesn't match. |
| **Lookalike domains** | Check the From domain for homoglyph attacks (rn→m, l→1), inserted hyphens, or typosquatting (e.g., `micr0soft.com`, `arnazon.com`). |
| **Date anomalies** | Timestamp far in the future/past, or timezone inconsistent with claimed sender location. |

### Body analysis

| Check | What to look for |
|---|---|
| **Urgency / pressure language** | "Your account will be suspended", "Act within 24 hours", "Verify immediately" — social engineering pressure tactics. |
| **Credential harvesting cues** | Requests to enter passwords, SSNs, credit card numbers, MFA codes, or click to "verify your identity". |
| **Authority impersonation** | Claims to be from IT, HR, CEO, legal, law enforcement, banks, or cloud providers (Microsoft 365, Google Workspace). |
| **Grammar / style inconsistencies** | Broken grammar from an entity that should be professional; inconsistent branding; generic greetings ("Dear Customer") from a service that knows your name. |
| **Hidden text / zero-width characters** | Invisible characters inserted to evade text-based detection filters. |

### URL analysis

| Check | What to look for |
|---|---|
| **Display text vs href mismatch** | The link says "https://microsoft.com" but the href goes to `https://m1cr0soft-login.evil.com`. This is a top phishing indicator. |
| **Shortened URLs** | bit.ly, tinyurl, t.co, etc. — these hide the true destination. |
| **Lookalike domains in URLs** | Same homoglyph / typosquatting checks as for the From address. |
| **Suspicious TLDs** | `.xyz`, `.top`, `.buzz`, `.click`, `.info` etc. in unexpected contexts. |
| **IP-based URLs** | `http://192.168.x.x/login` or `http://[hex-encoded]/` — legitimate services use domain names. |
| **Excessive subdomains** | `login.microsoft.com.evil-site.com` — the real domain is `evil-site.com`. |
| **Data URIs / javascript: URIs** | These can execute code or embed payloads without a server. |

### Attachment analysis

| Check | What to look for |
|---|---|
| **Dangerous file types** | `.exe`, `.scr`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.js`, `.hta`, `.msi`, `.dll`, `.iso`, `.img`, `.lnk` — these can execute code directly. |
| **Double extensions** | `invoice.pdf.exe` — hides the true executable extension behind a benign-looking one. |
| **Macro-enabled Office docs** | `.docm`, `.xlsm`, `.pptm`, `.dotm` — these can contain malicious macros. Older `.doc`/`.xls` formats can also contain macros. |
| **Archive containing executables** | `.zip`, `.rar`, `.7z` containing any of the dangerous types above — a common bypass for email gateways. |
| **HTML attachments** | Can contain credential-harvesting forms or redirect scripts that execute locally. |
| **Password-protected archives** | "The password is in the email body" — this is almost always malicious, designed to evade scanning. |
| **Mismatched content type** | The MIME type says `application/pdf` but the filename is `.exe`. |

## Step 2 — Assign an overall verdict

Based on all findings, assign one of these verdicts:

| Verdict | Criteria |
|---|---|
| **MALICIOUS** | Clear phishing indicators, known-bad patterns, or dangerous payloads. At least one critical-severity finding, or multiple high-severity findings that together form a clear attack pattern. |
| **SUSPICIOUS** | Multiple medium-severity findings or patterns that don't conclusively prove malice but warrant caution. Could be a poorly configured legitimate sender or a sophisticated attack with few obvious tells. |
| **LIKELY SAFE** | Authentication passes, no URL mismatches, no dangerous attachments, no social engineering language. Minor informational findings only. Note: no email can be declared 100% safe — "likely safe" is the strongest positive verdict. |

## Step 3 — Generate the two reports

### Report A: Security Engineer Report

Save as a Markdown file. Use this structure:

```
# Email Security Analysis Report

## Verdict: [MALICIOUS / SUSPICIOUS / LIKELY SAFE]
**Confidence:** [High / Medium / Low]
**Analysis Date:** [timestamp]
**Analyzed File:** [filename]

## Executive Summary
[2-3 sentence overview of what this email is and why it received this verdict.]

## Email Metadata
| Field | Value |
|---|---|
| From | [full address] |
| Reply-To | [full address or N/A] |
| Return-Path | [full address] |
| To | [full address] |
| Subject | [subject line] |
| Date | [date header] |
| Message-ID | [message ID] |
| X-Mailer | [if present] |
| X-Originating-IP | [if present] |

## Authentication Results
| Mechanism | Result | Details |
|---|---|---|
| SPF | [pass/fail/softfail/none] | [raw result] |
| DKIM | [pass/fail/none] | [raw result] |
| DMARC | [pass/fail/none] | [raw result] |

## Received Chain Analysis
[Bottom-to-top walkthrough of each hop, noting the originating IP, each relay, and any anomalies.]

## Findings

### Critical
[List critical findings with evidence]

### High
[List high findings with evidence]

### Medium
[List medium findings with evidence]

### Low / Informational
[List low findings]

## Indicators of Compromise (IOCs)
[List any IOCs found — malicious URLs, suspicious IPs, sender domains, file hashes of attachments. Format as a table for easy ingestion into SIEM/SOAR tools.]

| IOC Type | Value | Context |
|---|---|---|
| URL | [url] | [where found] |
| Domain | [domain] | [role] |
| IP | [ip] | [from header] |
| SHA256 | [hash] | [attachment name] |

## MITRE ATT&CK Mapping
[Map findings to relevant techniques — e.g., T1566.001 Spearphishing Attachment, T1566.002 Spearphishing Link, T1204.001 User Execution: Malicious Link, etc.]

## Recommended Actions
[Specific next steps: block sender, quarantine similar messages, submit samples, update detection rules, etc.]

## Raw Headers
[Include full raw headers in a code block for reference.]
```

**Format-specific additions to Report A:**

- **For raw headers only (Format B):** Add a prominent note at the top: "⚠️ This analysis is based on email headers only. Body content, URLs, and attachments were not available for analysis." Skip the URL analysis, body analysis, and attachment analysis sections — don't include empty sections, just omit them.

- **For Proofpoint JSON (Format C):** Replace the "Raw Headers" section with a "Proofpoint Disposition Detail" section that includes the full action chain (`filter.actions`), all spam/threat scores, and the final disposition. Also include the quarantine details if the message was quarantined. Add Proofpoint scores to the Authentication Results table or as a separate "Proofpoint Threat Scores" table. If body text was not fully available, note that body-level social engineering analysis was limited.

### Report B: End-User Summary

Save as a separate Markdown file. This report is for someone who may not know what phishing is. Write at a 6th-grade reading level. No jargon. No acronyms unless explained.

Keep it short — the whole report should fit on one screen without scrolling. Brevity is more important than thoroughness here; the security engineer report has the details.

Use this structure:

```
# Is This Email Safe?

## [EMOJI + VERDICT]
Use one of:
- 🚨 **This email is dangerous — do not interact with it.**
- ⚠️ **This email looks suspicious — be very careful.**
- ✅ **This email appears to be safe.**

## What We Found
[Two short paragraphs MAX. First paragraph: what the email is and who sent it (one or two sentences). Second paragraph: the single most important thing the reader needs to know — the key risk or why it's OK (one sentence).

Example for phishing: "This email claims to be from Microsoft, but it was actually sent from a completely different company. The links inside lead to a fake login page designed to steal your password."

Example for safe: "This is a marketing email from Redmondmag.com, a well-known tech website. The sender's identity checked out, and there are no dangerous links or attachments."]

## What You Should Do

[Numbered steps, 3 max. One short line each — start with a bold action word.]

1. **Do/Don't** [action]
2. **Do/Don't** [action]
3. **Do/Don't** [action]

## Warning Signs We Checked

[Bare checklist — emoji + short label only, no explanations. Use ⚠️ for "mixed" items instead of writing a caveat.]

- ✅ / ❌ The sender is who they claim to be
- ✅ / ❌ The links go where they say they go
- ✅ / ❌ No dangerous attachments
- ✅ / ❌ No requests for passwords or personal info
- ✅ / ❌ / ⚠️ No urgency or scare tactics
```

## Step 4 — Present both files

Save both reports to `/mnt/user-data/outputs/` and present them to the user:

- `email-security-report.md` — the security engineer report
- `email-safety-summary.md` — the end-user summary

Use descriptive filenames that include the subject or sender if helpful (e.g., `security-report-microsoft-alert-phish.md`).

After presenting, give a brief verbal summary of the verdict and the top 2-3 findings so the user gets the key takeaway without needing to open the files.

## Edge cases and guidance

- **Multiple EML files**: Analyze each one separately. Produce a pair of reports for each.
- **Corrupted or unparseable EML**: Report what you can parse and clearly state what was unreadable.
- **Legitimate emails with minor issues**: Many real companies have misconfigured SPF/DKIM. Don't over-alarm — note it as informational and weigh it in context with other signals.
- **Encrypted/signed emails (S/MIME, PGP)**: Note the encryption/signature, extract what metadata you can, and explain that the body content could not be analyzed because it's encrypted.
- **Nested .eml attachments**: If an EML contains another EML as an attachment, analyze both and note the nesting.
- **Non-English emails**: Analyze in whatever language the email is in. Write the reports in English unless the user requests otherwise.
