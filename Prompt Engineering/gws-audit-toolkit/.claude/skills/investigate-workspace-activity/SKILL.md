---
name: investigate-workspace-activity
description: Investigate a Google Workspace audit-log scenario for a single companyName employee — correlate events across drive/gmail/login/token/IP CSVs and produce a structured investigation report suitable for Slack, a Google Doc, or a ticket attachment. Use whenever the user describes an investigation scenario like "suspected data exfiltration by X", "unusual login activity for X", "X's account may be compromised", "look into Y for X", or any open-ended ask to "investigate", "triage", "review the logs for", or "build a case summary on" a specific @companyDomain user. Also trigger when an analyst pastes an alert or IOC and asks what to make of it for a given user, or when they reference an earlier pull and now want a verdict rather than raw data.
---

# Investigate Workspace Activity

Takes a scenario description + a target companyName employee, decides which Workspace audit log sources are relevant, pulls/reads the CSVs, correlates events across them, and produces a structured investigation report.

## When to use this vs. raw queries

If the analyst just wants to *see* what someone did (list, filter, count), reach for the CSVs directly. Use this skill when they want a *judgment call*: was this exfil? is the account compromised? what's the next move? The output is a report, not a CSV.

## Inputs to confirm

Before running, make sure you have:

1. **Subject (target user):** full @companyDomain email — don't guess from a first name.
2. **Scenario:** the analyst's framing in their own words. Capture verbatim — it determines which sources to load and how to weight findings.
3. **Window:** default 30d. If the scenario references a specific date, anchor a 14-day window around it. If they say "lately" or "this week", use 7d.

If any are missing, ask one focused clarifying question rather than guessing.

## Helper scripts

The toolkit ships with a few scripts that do the heavy lifting — prefer them over reimplementing the logic each run.

| Script | What it does | When to use |
|---|---|---|
| `score_indicators.py <user> --days N` | Per-source risk scoring against `sanctioned_apps.json` + `ip_baseline.json`. Emits `<user>_indicators_Nd.json` with `summary`, `indicators`, and `no_evidence_for`. | Run first on every investigation — its output drives the report's Risk-Indicators table and tells you which sources had nothing to flag. |
| `build_timeline.py <user> --days N --format md` | Merges drive/gmail/login/token CSVs into a chronological "material events" file. Filters Drive views and inbound gmail noise; keeps shares, downloads, OAuth grants, login events, forwarding rule changes. | Use to populate the Timeline section. Default output is markdown table — paste-ready. |
| `top_collaborators.py <user> --days N` | Ranks internal/external peers by Drive shares + Gmail co-recipients. | Use when deciding who to pivot to, or to spot an external recipient that's unusual for the subject. |
| `pull_outbound_gmail.py <user> --days N` | Filters the existing gmail CSV down to events that *look* outbound (heuristic — Reports API gmail is mostly inbound). Emits per-domain summary. | Use when the scenario is exfil/insider-threat. If it returns 0 rows, document the limitation in the report's Caveats. |
| `md_to_pdf.py <report.md>` | Stdlib markdown → HTML → Chrome-headless PDF. | **Always run after writing the .md** — the analyst's standing preference is both .md AND .pdf as the final deliverable for every investigation. |

Two reference files the scripts read:

- `sanctioned_apps.json` — known-good OAuth `client_id`s (BetterCloud, Code42, Glean, Chrome, gws CLI, phishing reporter, G2, Zoom for G Suite). Anything not in here gets flagged as "unsanctioned" — not necessarily malicious, but worth a look. Update it as new apps are vetted.
- `ip_baseline.json` — per-user expected countries/ASNs (e.g., dami → CA/Distributel, owen → CA/TELUS, nick → US/Netskope). The login scorer uses this to flag unfamiliar geos. Add users / update as people relocate.

If a referenced script doesn't exist in the working directory, fall back to reading the CSVs directly using the catalog in §5 — but mention the gap so the toolkit can be patched.

## Workflow

### 1. Map scenario to log sources

Don't always load everything — focused analysis beats exhaustive analysis.

| Scenario archetype | Primary sources | Secondary sources |
|---|---|---|
| Data exfiltration / pre-departure | drive, gmail, token | ips |
| Account compromise / takeover | login, token, user_accounts | ips, gmail |
| Unusual login activity | login, ips | token |
| Phishing / credential theft | login, token, user_accounts | gmail |
| Insider threat (broad / unspecified) | all | — |

If the scenario doesn't fit, infer from keywords: "download/share/forward" → drive/gmail; "VPN/country/device" → ips/login; "OAuth/app/permission" → token.

### 2. Make sure logs exist

Check for `logs/<first>_<last>_G_Logs/` and inspect the most recent manifest JSONs. If the data is missing, older than the requested window, or shorter than needed, invoke the **pull-workspace-logs** skill first. Don't re-pull when fresh data already exists — the manifest's `start_time`/`end_time` tell you the coverage.

### 3. Run the scoring + timeline scripts

For most scenarios, this is two commands:

```
python3 score_indicators.py <subject> --days <N>
python3 build_timeline.py <subject> --days <N> --format md
```

For exfil/insider scenarios, also:

```
python3 pull_outbound_gmail.py <subject> --days <N>
python3 top_collaborators.py <subject> --days <N>
```

Read the resulting `_indicators_Nd.json` — that's your Risk-Indicators table and your `no_evidence_for` list (use it to fill in the "we checked X and found nothing" parts of the report so silence is documented, not assumed).

### 4. Load and filter (when going beyond the scripts)

If the scripts don't surface what you need (e.g., the scenario calls for keyword searches on email subjects, or a specific document title), drop to the CSVs:

- Filter `actor_impersonation == false` for human-driven events. Glean, Code42, BetterCloud account for the bulk of raw events as the user — they're noise unless they're directly relevant (e.g., a *new* OAuth grant *to* one of those apps within the window).
- Restrict to the investigation window.
- For drive specifically, filter `actor_email == <subject>` to drop stuff *other* people did to the user's docs.
- For gmail recipients, look at `flattened_destinations` (format `<source>::<address>`), not `destination` (usually empty). The Reports API gmail data is mostly inbound — see `pull_outbound_gmail.py` for the outbound heuristic.

### 5. Correlate across sources

The timeline script gives you the chronological view. For each high/med indicator, look at what else happened ±15 minutes around it. Examples worth the cross-check:

- A sensitive Drive download → was there a fresh OAuth grant or a login from an unusual IP just before?
- A new OAuth `authorize` → did it come from an IP that only appears once?
- A new auto-forwarding rule → followed by a burst of inbound mail being filtered/forwarded?

### 6. Risk indicator catalog

`score_indicators.py` already implements most of what's below — this catalog is the reference for what each indicator means and when to override the script's verdict. If you find a real signal the script missed, file it as a follow-up so the script gets smarter.

#### Drive
- **Mass download/export burst** — >50 events in <1h, especially `download`, `copy`, or `export` (HIGH)
- **External share to free email domain** — gmail.com, outlook.com, proton.me, icloud, yahoo (HIGH)
- **Ownership transfer to external account** (HIGH)
- **`copy` to a personal-looking destination** (MED)
- **Off-hours bulk activity** relative to user's normal working hours (MED)

#### Gmail
- **Auto-forwarding rule added** — `forwarding_email` set, or `mail_event_type=email_forwarding_change` (HIGH — top compromise signal)
- **External recipient + large payload** — `flattened_destinations` ends in non-corporate domain AND `payload_size` > 25MB (HIGH)
- **Burst of outbound sends to personal addresses** — >10 to free providers in <1h (MED)
- **Subject keywords** ("confidential", "personal", customer names) — tie-breaker only, not a finding on its own

#### Token (OAuth)
- **New `authorize` for unfamiliar `client_id`** — `sanctioned_apps.json` is the source of truth. Anything outside it gets flagged "unsanctioned" (MED). Bump to HIGH if scopes are broad.
- **Broad scope grants** — exact-match against `https://www.googleapis.com/auth/drive`, `gmail.readonly`, full mail/contacts, admin. NB: `drive.file` is *per-file* and is NOT broad — don't conflate via substring matching. (HIGH when granted)
- **Authorize from unusual IP** — cross-reference IPs CSV (HIGH)

#### Login
- **`suspicious_login` event** — always escalate (HIGH)
- **Failed attempts immediately preceding success** (MED)
- **2SV/MFA disabled or method changed** (HIGH)
- **Login from a country/ASN never seen before** (MED-HIGH)
- **Impossible travel** — two logins from far-apart countries within physically implausible timeframe (HIGH)

#### IPs
- **Anonymous proxy / known VPN ASN** — flagged in `anonymous_proxy` column or obvious from `org` (MED)
- **Country not in the user's normal pattern** (MED-HIGH)
- **Single-event IP with broad coverage** — one-off IP that hit login + drive + token in <5 min suggests session hijack (HIGH)

### 7. Write the report (and render to PDF)

Save to `logs/<first>_<last>_G_Logs/<first>_<last>_investigation_<scenario_slug>_<YYYY-MM-DD>.md`. Note the user's name **prefixes the filename itself**, not just the folder — the analyst's standing preference is filenames like `kurt_hundeck_investigation_login_anomaly_2026-05-02.md` so reports stay identifiable when pulled out of their folders (attached to tickets, posted to Slack, dropped into a Drive folder of mixed reports). Pick a short kebab-case slug from the scenario (e.g. `data_exfil`, `account_takeover`, `login_anomaly`).

Pull the Risk-Indicators table directly from `<user>_indicators_Nd.json`. Pull the Timeline rows from the top of `<user>_timeline_Nd.md` (filter to material events around your findings — don't paste all 3000+).

**Then immediately render the PDF:** `python3 md_to_pdf.py <path>.md`. The analyst's standing preference is both formats — the .md is editable / pasteable, the .pdf is the ticket / Doc / Slack-share artifact. Don't wait to be asked.

Use this template:

````markdown
# Workspace Investigation: <Subject Name>

**Subject:** `<email>`
**Scenario:** <one-line restatement of the analyst's framing>
**Window:** <start> → <end> (<N> days)
**Generated:** <ISO timestamp>
**Sources analyzed:** <list>
**Analyst:** <if known>

---

## Executive summary

<2–4 sentences. Lead with the verdict: did the data support the scenario, contradict it, or come back inconclusive? Quantify when possible: "47 sensitive files copied to a personal Gmail address on 2026-04-29 17:14 UTC from a Toronto residential IP." If inconclusive, say so plainly — don't pad.>

## Key findings

1. **<Headline finding>** — <evidence with timestamp, file/email/IP/client_id specifics, source CSV>
2. ...

(3–7 bullets max. Each finding should be a discrete fact, not a category.)

## Risk indicators triggered

| Severity | Indicator | Detail |
|---|---|---|
| HIGH | <name> | <quote, timestamp, value> |
| MED | ... | ... |

## Timeline

| Time (UTC) | Source | Event |
|---|---|---|
| 2026-04-29 14:02 | login | suspicious_login from 5.34.180.91 (RU, anonymous proxy) |
| 2026-04-29 14:05 | token | authorize for client_id 1234... (drive scope) |
| ... | ... | ... |

(10–20 most material events. Don't dump everything — pick the ones that build the narrative.)

## Recommended next steps

- <Concrete action, ranked by urgency>
- <Action 2>
- ...

Common ones: revoke OAuth grant for client_id X, kill active sessions, force password reset + 2SV re-enrollment, expand window to 90d, pivot to <related user>, escalate to IR / Legal / People Ops.

## Caveats

- <Anything that could change the verdict — short window, source missing, OAuth-impersonated traffic that couldn't be filtered cleanly, etc.>
````

### 8. Surface results to the analyst

In chat, return:

- The paths to **both** the `.md` and `.pdf` files.
- The 1-line executive summary.
- The single highest-severity finding.
- **One** follow-up offer (e.g. "Want me to expand to 90 days?", "Want me to format this as a Slack-ready post?", "Want to pivot to <related user> — `top_collaborators.py` ranked these peers...").

Don't paste the full report into chat — the point is the files.

## Behaviors and caveats

- **One scenario, one subject, one report.** If the analyst asks about two people, run twice.
- **Don't fabricate.** If a CSV has no evidence for an indicator, write "no evidence" — silence is informative. Don't say "appears normal" if you didn't actually look.
- **Quote, don't paraphrase, when citing logs.** Include doc titles, recipient addresses, client_ids, IPs, timestamps verbatim. The report needs to stand up in a ticket.
- **Verdict honesty.** If the data is inconclusive, the executive summary must say so. Don't manufacture concern to justify the work; don't downplay genuine risk to be tidy.
- **Privacy.** The report contains real email subjects, recipients, and document titles. Flag this before the analyst pastes it anywhere external.
- **Sanctioned-app list isn't gospel.** It reflects what's been seen in past runs (BetterCloud, Code42, Glean, Google Chrome, gws CLI, phishing reporter). New legitimate apps roll out — flag them as "unfamiliar" rather than "malicious", and let the analyst confirm.

## Examples

**"investigate suspected data exfiltration by John.Doe@companyDomain"**
→ 30d window. Load drive, gmail, token; cross-check ips. Focus on bulk downloads, external sends to free providers, and new OAuth grants with broad scopes. Output report to `logs/nick_huanca_G_Logs/investigation_data_exfil_<date>.md`.

**"unusual login activity for dami.odubanjo this week"**
→ 7d window. Load login + ips. Look for new countries, `suspicious_login` events, impossible travel. Don't load Drive/Gmail unless something jumps out.

**"Jane.smith's account may be compromised"**
→ 30d. Load login, token, user_accounts, gmail. Top signals: forwarding rules added, new OAuth grants (especially mail/drive scopes), 2SV changes, `suspicious_login` events.

**"can you build me a case summary for the dami.odubanjo investigation we did earlier"**
→ Logs already exist. Skip pull, read existing CSVs, write the report.

**"there's a Doppel alert for nick — what's his recent activity look like?"**
→ Treat as account-compromise scenario at 14d. Pull the alert details from the analyst's message into the **Scenario** field of the report verbatim.
