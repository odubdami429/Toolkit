---
name: review-browser-extension
description: Security review of a browser extension — download, unpack, and statically analyze a Chrome or Firefox extension for dangerous permissions, content script scope, code execution risks, keylogger patterns, cookie/credential theft vectors, hardcoded secrets, and supply chain risks. Produces a risk-scored report with permissions front-and-center. Use when an employee requests approval to install a Chrome or Firefox browser extension, or when you need to vet any extension before approving it. Trigger on phrases like "review Chrome extension X", "can we install this browser extension", "is X safe to install in Chrome/Firefox", "security review of browser extension X", or any request with a chromewebstore.google.com or addons.mozilla.org URL.
---

# Review Browser Extension

Downloads a Chrome or Firefox browser extension, unpacks it, and runs static security analysis — with a focus on the extension's declared permissions, content script coverage, and code-level risks (credential theft, keyloggers, cookie access, eval, secrets). Produces a risk-scored markdown report.

## Inputs

1. **Extension URL or ID:**
   - **Chrome Web Store URL:** `https://chromewebstore.google.com/detail/{name}/{id}` → extracts the 32-char ID
   - **Firefox AMO URL:** `https://addons.mozilla.org/en-US/firefox/addon/{slug}/` → extracts the slug
   - **Bare Chrome ID:** 32 lowercase letters (e.g. `cjpalhdlnbpafiamejdnhcphjbkeiagm`)
   - **Bare Firefox slug:** alphanumeric-with-hyphens (use `--browser firefox`)
2. **Output directory:** defaults to `~/Documents/browser_extension_reviews`

## Supported browsers

| Browser | Source | File format |
|---|---|---|
| Chrome / Edge / Brave | Chrome Web Store | CRX (stripped to ZIP) |
| Firefox | Firefox AMO | XPI (ZIP) |

## Bundled scripts

```
~/.claude/skills/review-browser-extension/
├── SKILL.md
└── scripts/
    ├── fetch_browser_extension.py     # download CRX/XPI + build metadata.json
    ├── analyze_browser_extension.py   # manifest + code analysis → analysis.json
    └── report_browser_extension.py    # analysis.json + metadata.json → .md report
```

| Script | What it does | Output |
|---|---|---|
| `fetch_browser_extension.py <url-or-id> [--browser chrome\|firefox] [--out DIR]` | Detects browser, downloads CRX/XPI, strips CRX header, extracts ZIP, scrapes store metadata | `{out}/{browser}_{name}_{version}/` with `metadata.json` + `ext/` |
| `analyze_browser_extension.py <working_dir>` | Parses manifest.json for permissions/CSP/content scripts, scans JS for dangerous patterns and secrets | `analysis.json` |
| `report_browser_extension.py <working_dir>` | Formats findings into a structured report (permissions first) | `{browser}_{id}_{version}_security_review_{date}.md` |

### Working directory convention

Always use `~/Documents/browser_extension_reviews` as the `--out` path. Output lands at:
`~/Documents/browser_extension_reviews/{browser}_{name-slug}_{version}/`

```bash
SKILL=~/.claude/skills/review-browser-extension/scripts
OUT=~/Documents/browser_extension_reviews
```

---

## Workflow

### 0. Verify scripts are present

```bash
test -f "$SKILL/fetch_browser_extension.py" && \
test -f "$SKILL/analyze_browser_extension.py" && \
test -f "$SKILL/report_browser_extension.py" && \
echo "OK" || echo "MISSING — reinstall plugin"
```

### 1. Fetch the extension

```bash
# Chrome (URL or bare ID — auto-detected):
WORK_DIR=$(python3 "$SKILL/fetch_browser_extension.py" <url-or-id> --out "$OUT" | tail -1)

# Firefox (URL or slug):
WORK_DIR=$(python3 "$SKILL/fetch_browser_extension.py" <url-or-slug> --out "$OUT" --browser firefox | tail -1)

echo "Working dir: $WORK_DIR"
```

- `tail -1` captures the machine-readable working directory path.
- If the download fails for Chrome, the extension may be unpublished or region-restricted.
- CRX files are ~2–20 MB typically. Extensions > 50 MB are unusual — flag to the analyst.

### 2. Analyze

```bash
python3 "$SKILL/analyze_browser_extension.py" "$WORK_DIR"
```

Outputs a one-line risk summary. Writes `$WORK_DIR/analysis.json`.

The analyzer now includes **data flow analysis** — it automatically traces what data leaves the browser:
- `chrome.storage.sync` keys (synced to Google's servers)
- `chrome.storage.local` keys (stays on-device)
- Hardcoded outbound endpoints (fetch/XHR)
- Firebase services initialized and write operations detected
- Whether user identifiers (uid, email) or user content (highlights, search queries, page text) appear in outbound calls
- `btoa()` payloads (data base64-encoded before transmission)

Data flow verdict in `analysis.json["data_flows"]["verdict"]`:
| Verdict | Meaning |
|---|---|
| `LOCAL_ONLY` | No network calls or cloud services — all data stays on-device |
| `READ_ONLY_BACKEND` | Reads from backend (config/remote messages) but sends nothing identifying |
| `SUBSCRIPTION_ONLY` | Only uid/email sent — for license checks, not content collection |
| `SENDS_USER_CONTENT` | User content or Firebase writes detected — review what is uploaded |
| `UNKNOWN` | Dynamic calls present — manual review required |

### 3. Generate report

```bash
REPORT=$(python3 "$SKILL/report_browser_extension.py" "$WORK_DIR" | tail -1)
echo "Report: $REPORT"
```

### 4. Present to analyst

Return in chat:

1. **Risk verdict** — one-line: e.g. `MEDIUM — 0 HIGH · 3 MEDIUM · 2 LOW`
2. **Top 3–5 findings** — especially any HIGH-severity permissions or credential-access patterns
3. **Permissions summary** — list the HIGH and MEDIUM permissions with their descriptions (most critical for browser extensions)
4. **Data flow verdict** — one-line from `analysis.json["data_flows"]["verdict"]`, e.g. `SUBSCRIPTION_ONLY — only uid sent for license checks`
5. **Verdict** — BLOCK / REVIEW REQUIRED / CONDITIONAL APPROVE / APPROVE
6. **Report path** — `$REPORT`
7. **One follow-up offer** — the most relevant next step, e.g.:
   - "Want me to cross-check the URLs the extension phones home to?"
   - "Want me to review the Firefox version for comparison?"
   - "Want me to look at what the content scripts actually do in the JS?"

Do **not** paste the full report into chat — the file is the artifact.

---

## What the analyzer checks

### Permissions — the primary risk indicator for browser extensions

Unlike VS Code extensions where the main risk is in code patterns, **browser extension permissions are often the most telling security signal**. An extension with `<all_urls>` + `webRequestBlocking` + `cookies` can intercept and steal everything regardless of its JavaScript code quality.

| Permission | Risk | What it enables |
|---|---|---|
| `<all_urls>`, `*://*/*` | HIGH | Read/modify content on every website |
| `webRequestBlocking` | HIGH | Block or rewrite HTTP requests and responses |
| `nativeMessaging` | HIGH | Communicate with native apps on the OS |
| `cookies` | HIGH | Read/write all cookies for all sites |
| `identity` | HIGH | Access OAuth tokens |
| `clipboardRead` | HIGH | Read clipboard (captures passwords copied to clipboard) |
| `debugger` | HIGH | Full access to any tab via Chrome DevTools Protocol |
| `proxy` | HIGH | Redirect all browser traffic |
| `webRequest` | MEDIUM | Observe (not modify) network requests |
| `tabs` | MEDIUM | Read URLs and titles of all open tabs |
| `history` | MEDIUM | Access full browsing history |
| `scripting` | MEDIUM | Inject JS into pages (MV3 replacement for content scripts) |
| `management` | MEDIUM | Control other extensions |
| `browsingData` | MEDIUM | Wipe cookies, cache, and history |
| `storage` | LOW | Extension-local key-value storage |
| `activeTab` | LOW | Access ONLY the current tab when user clicks the extension |
| `notifications` | LOW | Desktop notifications |

### Content script coverage

Content scripts run in the context of web pages — a content script on `<all_urls>` can read/modify any page the user visits.

| Risk | Condition |
|---|---|
| HIGH | `matches: ["<all_urls>"]` or `*://*/*` |
| HIGH | `run_at: "document_start"` — runs before the page DOM is built |
| MEDIUM | `all_frames: true` — runs inside iframes too |
| LOW | Specific domain matches |

### Code patterns

| Severity | Pattern | Why it matters |
|---|---|---|
| HIGH | `document.cookie` | Reads all cookies (session tokens, auth cookies) |
| HIGH | `keydown/keypress/keyup` listeners | Possible keylogger |
| HIGH | Password field selectors | Harvests credentials |
| HIGH | `chrome.identity.getAuthToken` | Steals OAuth tokens |
| HIGH | `chrome.cookies.getAll` | Bulk cookie theft |
| HIGH | `connectNative`/`sendNativeMessage` | Talks to native apps |
| HIGH | `navigator.clipboard.readText` | Reads clipboard (copied passwords) |
| HIGH | `eval()` | Arbitrary code execution |
| MEDIUM | `chrome.tabs.query` | Tab URL/title enumeration |
| MEDIUM | `chrome.webRequest.onBeforeRequest` | Network request observation |
| MEDIUM | `chrome.history.search` | History access |
| MEDIUM | `chrome.storage.sync.set` | Data synced to Google account |
| MEDIUM | `fetch()`, `XMLHttpRequest` | Outbound HTTP calls |

---

## Reading findings — context for common patterns

### When HIGH permissions are expected

Some extensions legitimately need powerful permissions:

- **Ad blockers** (uBlock Origin, AdBlock): `webRequest`/`webRequestBlocking` + `<all_urls>` — needed to intercept and block ad requests. Expected and legitimate.
- **Password managers** (Bitwarden, 1Password): `tabs` + `cookies` + `<all_urls>` content scripts — need to detect login forms on any site. Expected.
- **VPN / proxy extensions**: `proxy` + `<all_urls>` — core to their function.
- **Developer tools** (React DevTools, Redux DevTools): `debugger` + `tabs` — core to their function.

The key question: **does the extension's stated purpose justify the permissions it claims?**

A "PDF converter" claiming `cookies` + `<all_urls>` + `nativeMessaging` is suspicious.
A password manager claiming the same is expected.

### MV2 vs MV3

MV2 extensions with `webRequestBlocking` can read and modify every HTTP response body, including bank pages, OAuth flows, and API responses. This is the highest-risk permission combination in Chrome extensions. MV3 replaces this with `declarativeNetRequest` (rule-based, no access to response bodies).

If an extension uses MV2 `webRequestBlocking` for a stated purpose that doesn't require it (e.g., a color theme), that's a red flag.

### Low install count

Install count < 1,000 warrants extra scrutiny — the extension has minimal community vetting, and supply chain attacks often target low-visibility extensions. Check:
- When was it published? (very new + powerful permissions = higher risk)
- Does it have a GitHub repo? Is it maintained?
- Does the publisher have other published extensions?

---

## Risk scoring

| Score | Meaning | Action |
|---|---|---|
| HIGH | At least one HIGH-severity finding | Block — require manual code review or security sign-off |
| MEDIUM | No HIGH, at least one MEDIUM | Review required — verify capabilities match purpose |
| LOW | No HIGH/MEDIUM, only LOW | Conditional approve — review context |
| CLEAN | No findings | Approve — standard process |

---

## Examples

**"can we install uBlock Origin in Chrome?"**
→ Chrome ID: `cjpalhdlnbpafiamejdnhcphjbkeiagm`. Expect HIGH permissions (`<all_urls>`, `webRequestBlocking`) — but these are legitimate for an ad blocker. Lead the summary with this context: "webRequestBlocking is HIGH-risk but expected for ad blockers."

**"is the Bitwarden extension safe?"**
→ Firefox slug: `bitwarden-password-manager`, Chrome ID: `nngceckbapebfimnlniiiahkandclblb`. Expect `tabs`, `<all_urls>`, content scripts — all legitimate for a password manager that needs to detect login forms. MEDIUM likely.

**"review this extension: `https://chromewebstore.google.com/detail/abc.../abcdefghijklmnopqrstuvwxyzabcdef`"**
→ Extract the ID from the URL, run full workflow. If it has low installs + HIGH permissions + no obvious legitimate purpose, lead with the mismatch.

**"security review of React DevTools"**
→ Chrome: `fmkadmapgofadopljbjfkapdkoienihi`. Expect `debugger` permission — HIGH but core to a devtools extension. Document it clearly and note it's expected.

**"there's an extension called 'PDF Converter Pro' — is it OK?"**
→ Search for the Chrome ID via the URL. If it claims `cookies` + `nativeMessaging` + `<all_urls>` for a PDF converter, that's a strong red flag — flag as HIGH and recommend blocking.
