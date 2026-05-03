---
name: pull-workspace-logs
description: Run the local Google Workspace audit log puller scripts (pull_drive_logs.py, pull_gmail_logs.py, pull_audit_logs.py, user_ips.py) for a given user email and report what was gathered. Use whenever the user wants to pull, gather, fetch, dump, or audit a companyName employee's Google Workspace logs — Drive, Gmail, login, OAuth tokens, IPs — for security investigation, exfiltration triage, or routine review. Trigger on phrases like "pull workspace logs for X", "audit X's gws logs", "gather drive/gmail/login logs for X@companyDomain", "what IPs did X use", or any request that names an @companyDomain email together with Google Workspace audit data. Also trigger when the user references a previous run and asks to refresh or re-pull.
---

# Pull Workspace Logs

Orchestrates four local Python scripts that pull Google Workspace audit logs for a single user via the `gws` CLI, write CSVs into `logs/<first>_<last>_G_Logs/`, and emit a manifest JSON describing what was produced.

## Why this exists

Investigators routinely need a user's full Workspace audit picture (Drive activity, Gmail metadata, login events, OAuth grants, IP fingerprint) and don't want to remember four separate scripts and their flags. This skill turns "pull workspace logs for X" into one orchestrated run with a clean output folder layout the parsing skills downstream expect.

## Scripts

All scripts live at `<TOOLKIT_ROOT>` (set during setup — see the toolkit's README.md). Each writes to `logs/<first>_<last>_G_Logs/` (auto-derived from the email's local part) and produces a manifest JSON.

| Script | What it pulls |
|---|---|
| `pull_drive_logs.py <email>` | drive + login |
| `pull_gmail_logs.py <email>` | gmail + user_accounts + admin |
| `pull_oauth_logs.py <email>` | token (OAuth grants/revokes/authorizes) |
| `pull_audit_logs.py <email> --apps <list>` | any Workspace app (generic) |
| `user_ips.py <email>` | distinct IPs with country/city/org enrichment |

Common flags: `--days N` (default 30), `--out DIR` (default `logs`).

## Workflow

### 1. Confirm scope before running

- **Email:** if the user gives only a first name, ask for the full email unless the conversation already supplied it. Don't guess.
- **Window:** default to `--days 30`. If the user asks for "this week", use 7. If they ask for "this month", use 30. If they ask for >30d and the request includes Gmail, warn that the Gmail Reports API caps at 30 days per call.
- **Scope:** if the user only asked for one signal (e.g. "just IPs"), run only the matching script. Don't pull everything by default when they were specific.

### 2. Run the scripts

Run sequentially — the Reports API rate-limits parallel calls and you risk truncated CSVs:

```bash
cd <TOOLKIT_ROOT>
python3 pull_drive_logs.py <email> --days <N>
python3 pull_gmail_logs.py <email> --days <N>
python3 pull_oauth_logs.py <email> --days <N>
python3 user_ips.py        <email> --days <N>
```

Use `pull_audit_logs.py --apps <list>` only when the user wants a non-default app set (e.g. only `groups,calendar`).

If a script reports a `gws` auth error, stop and point the user at `gws auth status` — don't try to fix the auth inline.

### 3. Report results compactly

After all runs, summarize in this format:

```
logs/<first>_<last>_G_Logs/
  drive:        <N>     rows
  login:        <N>     rows
  token:        <N>     rows
  gmail:        <N>     rows
  user_accounts: <N> rows
  admin:        <N>     rows
  ips:          <N> distinct (top: <ASN / country>)
```

Then surface the **single most useful observation** from the IP table — usually: which IP is the user's "real" device (the one with `(direct)` actor across login + drive + gmail + token), and any IP from a country the user wouldn't normally use.

### 4. Offer one next step, not a menu

Suggest the most relevant follow-up given what you saw, e.g.:
- "Want me to scan the gmail CSV for external recipients?"
- "Want me to pivot to a 7-day window so we can see hour-level patterns?"
- "Want to run the same pull on <related user>?"

Do not list all possible next steps.

## Behaviors and caveats

- **Avoid re-pulling.** If the user asks for analysis on data already in `logs/<first>_<last>_G_Logs/`, read those CSVs instead of re-running. The manifest JSON has timestamps so you can tell freshness.
- **Token CSVs are huge** (often 50k+ rows over 30 days). When scanning for new OAuth grants, filter to `event_name=authorize` and dedupe by `client_id` rather than reading the whole file.
- **Empty CSVs are normal.** `user_accounts` and `admin` are usually empty for end users — that means no settings/admin changes, not a failed pull.
- **OAuth-impersonated traffic dominates.** When looking for human-driven exfil signals, filter `actor_impersonation == false` (column in every CSV). Glean, Code42, etc. account for the bulk of raw events.
- **Gmail recipient field.** Real recipients live in `flattened_destinations` (format `<source>::<address>`). The `destination` column is usually empty.
- **Privacy.** These logs include real subjects, recipients, and document titles. Don't paste them into third-party services without warning the user.

## Examples

**"pull workspace logs for nick.huanca@companyDomain"**
→ Run all four scripts at `--days 30`, then summarize counts + the IP fingerprint.

**"audit dami.odubanjo for the last 7 days"**
→ Same scripts at `--days 7`.

**"just get me dami's drive logs"**
→ Only `pull_drive_logs.py`. Don't run the others.

**"what new OAuth apps has nick authorized this month?"**
→ Only `pull_oauth_logs.py --days 30`, then filter the resulting CSV to `event_name=authorize` and dedupe by `client_id`.

**"what IPs did nick use this week"**
→ Only `user_ips.py --days 7`, then read the resulting CSV and surface countries + the direct-actor IP.

**"refresh nick's logs"**
→ Re-run all four scripts on the same user. Mention if the output folder already existed (files will be overwritten).
