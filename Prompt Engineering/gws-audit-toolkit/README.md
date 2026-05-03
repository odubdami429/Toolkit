# Google Workspace Audit Toolkit

Python scripts + two Claude Code skills for pulling a single user's Google Workspace audit logs (Drive, Gmail, login, OAuth tokens, IPs) and running structured security investigations against them.

## What's in here

### Pullers (raw data → CSV)

| File | Purpose |
|---|---|
| `pull_drive_logs.py` | Pulls drive + login activity for a user |
| `pull_gmail_logs.py` | Pulls gmail + user_accounts + admin activity |
| `pull_oauth_logs.py` | Pulls token (OAuth grants/revokes/authorizes) |
| `pull_audit_logs.py` | Generic Workspace audit puller (any application) |
| `user_ips.py` | Distinct IPs with country/city/org enrichment via ipinfo.io |

### Analysis helpers (CSV → findings)

| File | Purpose |
|---|---|
| `score_indicators.py` | Per-source risk scoring against `sanctioned_apps.json` + `ip_baseline.json`. Emits a JSON of HIGH/MED/LOW indicators plus a `no_evidence_for` list. |
| `build_timeline.py` | Merges drive/gmail/login/token CSVs into a chronological "material events" file (markdown or TSV). |
| `top_collaborators.py` | Ranks the subject's internal/external peers (Drive shares + Gmail co-recipients) — useful for pivot decisions. |
| `pull_outbound_gmail.py` | Heuristic-filters the gmail CSV to outbound mail, with per-domain summary. The Reports API gmail data is mostly inbound, so this surfaces what's reachable. |
| `md_to_pdf.py` | Stdlib markdown → HTML → Chrome-headless PDF. No external deps. |

### Reference data

| File | Purpose |
|---|---|
| `sanctioned_apps.json` | Known-good OAuth `client_id`s. Anything outside this gets flagged "unsanctioned" by the scorer. Update as new apps are vetted. |
| `ip_baseline.json` | Per-user expected geography/ASN. Drives unfamiliar-country/-org indicators. Update when people relocate. |

### Claude Code skills

| File | Purpose |
|---|---|
| `.claude/skills/pull-workspace-logs/SKILL.md` | Orchestrates all the pullers above. |
| `.claude/skills/investigate-workspace-activity/SKILL.md` | Takes a scenario + subject, runs the analysis helpers, correlates events, and writes a structured investigation report (markdown — render to PDF via `md_to_pdf.py`). |

Output lands in `logs/<first>_<last>_G_Logs/` next to wherever you run the scripts.

## Setup checklist

Work top-to-bottom; each step assumes the previous one is done.

### 1. Install Claude Code

Download from https://claude.com/claude-code (CLI, desktop app, or IDE extension — any will work; the toolkit's skills are file-based and read by all of them). Sign in with your Anthropic account.

### 2. Get the toolkit

Either unzip `gws-audit-toolkit.zip` somewhere stable (e.g. `~/code/gws-audit-toolkit`) or `git clone` the repo. **Note the absolute path** — you'll need it in step 6.

### 3. Install the `gws` CLI

From https://github.com/googleworkspace/cli — follow the install instructions in that repo's README. Then authenticate with the audit + usage scopes:

```bash
gws auth login --scopes admin.reports.audit.readonly,admin.reports.usage.readonly
gws auth status   # confirm "Authenticated as <admin>@companyDomain"
```

### 4. GCP IAM permission

The Reports API call goes through a GCP project. Ask your GCP admin (or self-grant if you have access) for:

- `roles/serviceusage.serviceUsageConsumer` on the project `gws` is configured to use.

Symptom if missing: `Caller does not have required permission to use project X`.

### 5. Local prerequisites

- **Python 3.9+** — verify with `python3 --version`. Stdlib only, no `pip install` needed.
- **Google Chrome / Chromium / Edge** installed somewhere standard — required by `md_to_pdf.py` (renders via headless Chrome). Skip only if you don't care about PDF output.
- **(Optional) ipinfo.io token** for IP enrichment beyond the free 50k/month tier:
  ```bash
  export IPINFO_TOKEN=<your_token>
  ```
  `user_ips.py` caches results at `logs/.ipinfo_cache.json` so repeat IPs are free.

### 6. Install the Claude skills

```bash
mkdir -p ~/.claude/skills
cp -r <toolkit-root>/.claude/skills/pull-workspace-logs ~/.claude/skills/
cp -r <toolkit-root>/.claude/skills/investigate-workspace-activity ~/.claude/skills/
```

Then **edit `~/.claude/skills/pull-workspace-logs/SKILL.md`** and replace every `<TOOLKIT_ROOT>` with the absolute path from step 2 (e.g. `/Users/yourname/code/gws-audit-toolkit`). The skill needs the path so it `cd`s there before running the scripts. (`investigate-workspace-activity` operates on whatever output directory the pull skill produced and doesn't need a path edit.)

### 7. Customize the reference data

- **`ip_baseline.json`** — add an entry for yourself and anyone your team will be investigating regularly:
  ```json
  "your.name@companyDomain": {
    "expected_countries": ["CA"],
    "expected_orgs_substring": ["..."],
    "primary_city": "Toronto",
    "notes": "..."
  }
  ```
  Without an entry the scorer falls back to a `[US, CA]` default — fine for ad-hoc work, less sharp for repeated runs on the same person.
- **`sanctioned_apps.json`** — review the included list (BetterCloud, Code42, Glean, Chrome, gws CLI, phishing reporter, G2, Zoom for G Suite). Add any other OAuth apps your org has vetted. Anything not in this list gets flagged "unsanctioned" by `score_indicators.py`.

### 8. Verify it works

Smoke-test against your own account (you're the safest target):

```bash
cd <toolkit-root>
python3 pull_drive_logs.py your.name@companyDomain --days 7 --apps login
python3 score_indicators.py your.name@companyDomain --days 7
```

You should see a manifest JSON, a CSV, and an indicators JSON drop into `logs/<first>_<last>_G_Logs/`. Then ask Claude:

> investigate suspected unusual login activity for your.name@companyDomain

You should see the `investigate-workspace-activity` skill trigger and produce both `<first>_<last>_investigation_login_anomaly_<date>.md` and `.pdf` in that same folder.

## Usage

### Standalone scripts

Pull data:
```bash
python3 pull_drive_logs.py user@companyDomain --days 30
python3 pull_gmail_logs.py user@companyDomain --days 30
python3 pull_oauth_logs.py user@companyDomain --days 30
python3 user_ips.py        user@companyDomain --days 30
```

Analyze it:
```bash
python3 score_indicators.py   user@companyDomain --days 30
python3 build_timeline.py     user@companyDomain --days 30 --format md
python3 top_collaborators.py  user@companyDomain --days 30 --top 10
python3 pull_outbound_gmail.py user@companyDomain --days 30
python3 md_to_pdf.py logs/<user>_G_Logs/investigation_<scenario>_<date>.md
```

Output goes to `logs/<first>_<last>_G_Logs/`. Each puller writes a manifest JSON with row counts and timestamps; analysis helpers write next to the CSVs.

Common flags:
- `--days N` — window size (default 30; Gmail caps at 30)
- `--out DIR` — parent output directory (default `logs`)
- `--apps a,b,c` — comma-separated app list (overrides defaults)

### Via the Claude Code skills

Once installed, just ask Claude in any conversation.

**Pulling logs** (`pull-workspace-logs`):

> pull workspace logs for nick.huanca@companyDomain

> what IPs did dami use this week

> audit alice.smith for the last 7 days

**Investigating a scenario** (`investigate-workspace-activity`) — produces a structured markdown report in the user's log folder:

> investigate suspected data exfiltration by nick.huanca@companyDomain

> unusual login activity for dami.odubanjo this week

> alice.smith's account may be compromised — build me a case summary

The investigate skill auto-pulls fresh logs if needed, correlates events across sources, scores risk indicators, and writes a report suitable for Slack, a Google Doc, or a ticket attachment.

## Caveats

- **Gmail caps at 30 days per call.** Longer windows need chunking (the scripts warn but don't auto-chunk).
- **OAuth-impersonated traffic dominates raw event counts.** Glean, Code42, etc. show up as the user. Filter `actor_impersonation == false` for human signals.
- **Gmail recipients live in `flattened_destinations`** (format `<source>::<address>`), not `destination`.
- **Token CSVs are huge** — often 50k+ rows over 30 days. Filter to `event_name=authorize` and dedupe by `client_id` when scanning OAuth grants.
- **Empty `user_accounts` / `admin` CSVs are normal** for end users (no settings or admin changes happened).
- **These logs contain real subjects, recipient addresses, and document titles.** Don't paste them into external services without redacting.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `403 insufficient authentication scopes` | Re-run `gws auth login` with the two scopes above |
| `Caller does not have required permission to use project` | Missing `serviceUsageConsumer` IAM role on the GCP project |
| `Start time and end time should both be provided` | You're hitting Gmail without `endTime` — use `pull_gmail_logs.py` (handles this) rather than `pull_audit_logs.py` for gmail-only |
| Truncated output / fewer rows than expected | API rate-limited; run scripts sequentially, not in parallel |
| `pull failed — leaving any existing CSV intact` | gws errored on that app; check `gws auth status` and rerun |
