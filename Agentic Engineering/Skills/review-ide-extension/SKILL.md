---
name: review-ide-extension
description: Security review of a VS Code extension — download, unpack, and statically analyze an extension for dangerous code patterns (eval, child_process, network calls), hardcoded secrets, suspicious bundled files, excessive permissions, and supply chain risks. Produces a risk-scored report. Use when an employee requests approval to install a VS Code extension, or when you need to vet any VS Code extension before approving it. Trigger on phrases like "review extension X", "can we install X extension", "is X safe to install", "vet this VS Code extension", "security review of X for VS Code", or any request to evaluate a marketplace extension ID in publisher.name format.
---

# Review IDE Extension

Downloads a VS Code extension from the marketplace, unpacks it, runs static security analysis, and produces a risk-scored markdown report — covering code patterns, secrets, suspicious files, permissions, and trust signals.

## Inputs

1. **Extension ID:** `publisher.name` format (e.g. `ms-python.python`, `esbenp.prettier-vscode`).
   - If the user provides a **VS Code Marketplace URL** (`marketplace.visualstudio.com/items?itemName=X`), extract `X` as the ID.
   - If the user provides an **Open VSX URL** (`open-vsx.org/extension/<namespace>/<name>`), form the ID as `<namespace>.<name>`.
   - If they only give a display name, ask for the full ID.
2. **Output directory:** defaults to `~/Documents/extension_reviews`. Change only if the user specifies.

## Supported registries

`fetch_extension.py` auto-detects the correct registry:
1. Tries **VS Code Marketplace** first.
2. Falls back to **Open VSX** (`open-vsx.org`) if not found there.
3. Use `--registry open-vsx` to skip the Marketplace and go directly to Open VSX (useful when the user provides an open-vsx.org URL).

## Prerequisites

- Python 3, `requests` (both available on this machine).
- Internet access to `marketplace.visualstudio.com`, `*.vsassets.io`, and `open-vsx.org`.

## Bundled scripts

```
~/.claude/skills/review-ide-extension/
├── SKILL.md
└── scripts/
    ├── fetch_extension.py     # query marketplace API, download + extract VSIX
    ├── analyze_extension.py   # static analysis → analysis.json
    └── report_extension.py    # analysis.json + metadata.json → markdown report
```

| Script | What it does | Output |
|---|---|---|
| `fetch_extension.py <id> [--out DIR]` | Queries the VS Code Gallery API, downloads the VSIX, and extracts it. | `<out>/<publisher>_<name>_<version>/` directory with `metadata.json` and `vsix/` |
| `analyze_extension.py <working_dir>` | Scans JS files for dangerous patterns, secrets, suspicious file types, package.json risks, and trust signals. | `analysis.json` in the working dir |
| `report_extension.py <working_dir>` | Combines metadata + analysis into a structured markdown report. | `<pub>_<name>_<ver>_security_review_<date>.md` in the working dir |

### Working directory convention

Always use `~/Documents/extension_reviews` as the `--out` path so reports land consistently at:
`~/Documents/extension_reviews/<publisher>_<name>_<version>/`

For brevity, every code block below assumes:
```bash
SKILL=~/.claude/skills/review-ide-extension/scripts
OUT=~/Documents/extension_reviews
```

---

## Workflow

### 0. Confirm scripts are present

```bash
test -f "$SKILL/fetch_extension.py" && \
test -f "$SKILL/analyze_extension.py" && \
test -f "$SKILL/report_extension.py" && \
echo "OK" || echo "MISSING — reinstall plugin"
```

If `MISSING`, stop and ask the analyst to reinstall.

### 1. Fetch the extension

```bash
# VS Code Marketplace or Open VSX (auto-detect):
WORK_DIR=$(python3 "$SKILL/fetch_extension.py" <publisher.name> --out "$OUT" | tail -1)

# Force Open VSX (use when given an open-vsx.org URL):
WORK_DIR=$(python3 "$SKILL/fetch_extension.py" <publisher.name> --out "$OUT" --registry open-vsx | tail -1)

echo "Working dir: $WORK_DIR"
```

`tail -1` captures the machine-readable working directory path printed as the last line.

- If the script exits non-zero, the extension ID was not found or the download failed. Double-check the ID format (`publisher.name`, not just the display name) and retry once. If it still fails, report the error to the analyst.
- If the VSIX is larger than ~50 MB, warn the analyst — large extensions take longer to scan.

### 2. Run analysis

```bash
python3 "$SKILL/analyze_extension.py" "$WORK_DIR"
```

This writes `$WORK_DIR/analysis.json` and prints a one-line risk summary. If it exits non-zero, check that step 1 completed successfully and the `vsix/` directory exists.

### 3. Generate report

```bash
REPORT=$(python3 "$SKILL/report_extension.py" "$WORK_DIR" | tail -1)
echo "Report: $REPORT"
```

### 4. Present findings to the analyst

In chat, return:

1. **Risk verdict** — the one-line risk score and counts (e.g. `HIGH — 3 HIGH · 2 MEDIUM · 1 LOW`).
2. **Top findings** — the 3–5 most severe findings, verbatim from the report. If the verdict is `CLEAN`, say so plainly.
3. **Approve/Block recommendation** from the Verdict section.
4. **Report path** — `$REPORT` so the analyst can open it.
5. **One follow-up offer** — the most relevant next step, e.g.:
   - "Want me to dig into the `child_process` calls and verify they're spawning a language server?"
   - "Want me to check the extension's GitHub repo for recent security-relevant commits?"
   - "Want me to run a dependency audit on the bundled `node_modules`?"

Do **not** paste the full report into chat — the file is the artifact.

---

## What the analyzer checks

### Code patterns
| Severity | Pattern | Why it matters |
|---|---|---|
| HIGH | `eval()`, `new Function()` | Arbitrary JS execution |
| HIGH | `child_process` import, `.execSync()`, `.spawnSync()`, `.execFile()` | Shell command execution |
| HIGH | `vm.runInNewContext()` etc. | Node.js sandbox escape |
| HIGH | `net` / `dgram` module import | Raw TCP/UDP socket access |
| MEDIUM | `http`/`https` module, `fetch()`, `axios`, `WebSocket` | Outbound network calls |
| MEDIUM | Dynamic `require(variable)` | Runtime module loading — hard to audit |
| MEDIUM | `process.env` access | Reads secrets from environment |
| LOW | `fs` module, `writeFile`, `unlink`, `rmdir` | Filesystem write/delete |

### Secret detection
Scans for AWS access keys, GitHub tokens, JWT tokens, private keys, hardcoded passwords, and generic API keys/tokens.

### File inventory
Flags unexpected file types: `.exe`, `.dll`, `.so`, `.dylib`, `.sh`, `.bat`, `.ps1`.

### Package.json checks
- `activationEvents: ["*"]` — extension runs on every workspace open
- Known malicious npm packages (event-stream, flatmap-stream, etc.)
- Suspicious install/postinstall scripts (curl, wget, eval, base64)

### Trust signals
- Publisher verified status (Microsoft Verified Publisher badge)
- Install count < 100 (minimal community vetting)
- Not updated in 2+ years

---

## Reading the findings

### Context for common HIGH findings

Many legitimate extensions use `child_process` — language servers (Python, Java, Go, Rust, C++) spawn a backend process. The key question is: **what is being executed?** If the spawn call invokes a known language server binary with static arguments, it's expected. If it constructs a shell command from user input or a remote string, it's a real risk.

When you see `child_process` or `exec` findings, look at the context line in the report and verify:
- Is the command a static string or template literal with known values?
- Does the extension's stated purpose (language support, build tool) justify process spawning?

Similarly, `fs` and `http` findings are expected for extensions that read/write workspace files or call an API. Flag them to the analyst but don't block on them alone.

### Obfuscation findings

A single long-line finding usually means the JS was minified (common and benign). Multiple obfuscation indicators together (long lines + `String.fromCharCode` + base64 blobs) are more concerning and warrant manual review.

### Secrets findings

JWT and bearer-token patterns produce false positives (example tokens in documentation strings). Check the line number in the report — if it's in a comment or a string that looks like a placeholder, it's likely benign. A real embedded credential will have a valid format and appear in active code.

---

## Risk scoring

| Score | Meaning | Action |
|---|---|---|
| HIGH | At least one HIGH-severity finding | Block — require manual code review or security sign-off |
| MEDIUM | No HIGH, at least one MEDIUM | Review required — verify capabilities match purpose |
| LOW | No HIGH/MEDIUM, only LOW findings | Conditional approve — review context |
| CLEAN | No findings | Approve — standard process |

---

## Behaviors and caveats

- **One extension per review.** If asked about multiple extensions, run the workflow once per extension.
- **Re-fetch on version change.** The VSIX is cached in the working dir by version. If the analyst asks about a newer version, the working dir will differ (different version string in path) and the scripts will re-download.
- **node_modules not scanned.** Only the extension's own code (outside `node_modules/`) is scanned. For deep supply-chain review, run `npm audit` in the extracted `vsix/extension/` directory separately.
- **Static analysis only.** Runtime behavior, sophisticated obfuscation, and zero-day exploits are not detectable. Treat findings as a triage signal, not a verdict.
- **Don't fabricate.** If the analysis returns `CLEAN`, say so. Don't manufacture concern from LOW-only findings.

---

## Examples

**"can we install esbenp.prettier-vscode?"**
→ Run full workflow. Prettier is a well-known, high-install extension — expect CLEAN or LOW. Surface the verdict.

**"review the Pylance extension before we allow it"**
→ ID is `ms-python.vscode-pylance`. Run full workflow. Language server extensions typically have `child_process` — contextualize it.

**"is this extension safe: eamodio.gitlens"**
→ Run full workflow on `eamodio.gitlens`. GitLens is a popular git extension — network calls to GitHub API are expected.

**"our IT team wants to approve or block the extension redhat.java"**
→ Run full workflow on `redhat.java`. JDT Language Server spawns a JVM process — `child_process` HIGH finding is expected and benign for this extension's purpose.

**"unknown extension xyz.somethingobscure — is it legit?"**
→ Pay extra attention to: install count (< 100 is a red flag), publisher verification, last updated date, and any network endpoints that don't match the extension's stated purpose. Lead the summary with trust signals.
