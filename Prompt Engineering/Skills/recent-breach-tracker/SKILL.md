---
name: recent-breach-tracker
description: "Discover and compile a structured list of recent cybersecurity breaches and incidents. Use this skill whenever the user wants a roundup, digest, or list of recent breaches — not a deep dive into one specific incident, but a broad scan of what's been happening. Trigger on phrases like 'recent breaches', 'latest breaches', 'breach roundup', 'what got hacked recently', 'cybersecurity news this week/month', 'breach digest', 'new data leaks', 'any new breaches', 'security incidents this quarter', 'what companies were breached', 'breach tracker', 'breach list', or any request for a collection of multiple incidents. Also trigger when the user asks to 'stay current on breaches', 'catch me up on security incidents', or 'what should I be worried about'. If the user names a specific single breach and wants a deep report, use the security-breach-intel skill instead — this skill is for casting a wide net across many incidents."
---

# Recent Breach Tracker

Scan multiple sources to compile a structured, up-to-date list of recent cybersecurity breaches and incidents. This skill is about breadth — finding and cataloging many incidents — not depth on any single one.

## How this skill relates to security-breach-intel

These two skills work as a pair:

- **This skill (recent-breach-tracker):** "What breaches have happened recently?" → produces a list/table of incidents
- **security-breach-intel:** "Tell me everything about the [Company X] breach" → produces a deep-dive report on one incident

After producing a breach list with this skill, offer the user the option to deep-dive into any specific incident, which would then use the security-breach-intel report format.

## Research workflow

### Step 1 — Determine the time window

If the user specified a time range ("this week", "last 30 days", "Q1 2025"), use it. If they didn't, default to the **last 30 days** and mention the window you chose so they can adjust.

### Step 2 — Run broad discovery searches

Execute multiple searches to catch breaches across different sectors and attack types. Don't rely on a single query — breaches are reported unevenly and no one source catches everything.

Run at least these searches (adjust date references to match the target window):

1. `recent data breaches [current month] [current year]` — general roundup
2. `ransomware attacks [current month] [current year]` — ransomware-specific
3. `CISA cybersecurity advisories [current year]` — government-tracked incidents
4. `data leak exposed records [current month] [current year]` — data exposure events
5. `cyber attack company [current month] [current year]` — corporate targeting

If the user asked about a specific sector (healthcare, finance, government, etc.), add sector-specific searches:

6. `[sector] data breach [current month] [current year]`

### Step 3 — Deduplicate and filter

Multiple searches will return overlapping results. Deduplicate by incident — if three articles cover the same breach, that's one entry in the list, not three. Also filter out:

- Incidents outside the target time window
- Non-breach security news (product launches, vulnerability disclosures without known exploitation, opinion pieces)
- Duplicate coverage of the same incident under different headlines

### Step 4 — Classify each incident

For every unique incident found, quickly assess:

- **Severity:** Critical / High / Medium / Low (based on scope, data sensitivity, and impact)
- **Type:** Ransomware, Data Exfiltration, Supply Chain, Phishing/BEC, Insider Threat, Web Application Attack, Zero-Day Exploit, DDoS, Misconfiguration/Exposure, Unknown
- **Sector:** The industry of the affected organization
- **Status:** Ongoing, Contained, Under Investigation, Resolved

### Step 5 — Produce the breach list

Format all findings using the **Recent Breach List** template below.

## Recent Breach List template

Structure the output exactly as follows. Use markdown formatting.

```
# Recent Breach Tracker
**Period covered:** [start date] — [end date]
**Report generated:** [current date]
**Total incidents found:** [count]

---

## Summary

A 2–3 sentence overview of the threat landscape for this period. Note any dominant trends (e.g., "Ransomware continued to dominate, with healthcare and education sectors disproportionately targeted" or "Multiple supply-chain incidents traced back to a single compromised vendor").

## Breach List

| # | Date Reported | Organization | Sector | Type | Severity | Records / Impact | Status | Summary |
|---|---------------|-------------|--------|------|----------|-----------------|--------|---------|
| 1 | YYYY-MM-DD | Company A | Finance | Ransomware | Critical | 2M customer records | Ongoing | Brief one-sentence description |
| 2 | YYYY-MM-DD | Company B | Healthcare | Data Exfiltration | High | Patient PII exposed | Under Investigation | Brief one-sentence description |
| ... | ... | ... | ... | ... | ... | ... | ... | ... |

## Breakdown by Type

| Attack Type | Count | Notable Incidents |
|-------------|-------|-------------------|
| Ransomware | X | Company A, Company D |
| Data Exfiltration | X | Company B |
| Supply Chain | X | Company C |
| ... | ... | ... |

## Breakdown by Sector

| Sector | Count | Notable Incidents |
|--------|-------|-------------------|
| Healthcare | X | Company B, Company E |
| Finance | X | Company A |
| Government | X | Agency F |
| ... | ... | ... |

## Key Trends

Bullet each significant pattern observed in this period:
- [Trend 1 — e.g., "Three separate healthcare breaches exploited the same unpatched CVE"]
- [Trend 2 — e.g., "Ransomware groups increasingly using double-extortion tactics"]
- [Trend 3 — e.g., "Spike in credential-stuffing attacks following a major combo-list leak"]

## Sources Consulted

List the primary sources used to compile this tracker:
- [Source name] — [URL]
- [Source name] — [URL]
- ...
```

## Severity classification guide

Use these definitions consistently:

- **Critical:** Massive scale (millions of records), highly sensitive data (SSNs, financial, health records), critical infrastructure affected, or active ongoing exfiltration with no containment
- **High:** Large scale (hundreds of thousands of records), sensitive PII exposed, significant operational disruption, or confirmed threat actor involvement
- **Medium:** Moderate scale (thousands to tens of thousands of records), limited PII exposure, contained relatively quickly, or primarily internal systems affected
- **Low:** Small scale, non-sensitive data, quickly contained, or limited to a denial-of-service with no data loss

## Quality guidelines

- **Recency matters.** Prioritize the most recent sources. A breach list is only useful if it's current.
- **Don't pad the list.** Only include incidents you found credible evidence for. A shorter accurate list beats a longer speculative one.
- **One row per incident.** If a breach has multiple phases or disclosures, it's still one row — note the complexity in the summary column.
- **Be honest about coverage gaps.** If your searches skewed toward a particular sector or geography, note that. "This list may underrepresent incidents in [region/sector] due to limited English-language reporting" is useful context.
- **Link to depth.** After presenting the list, remind the user they can request a full Breach Intelligence Report on any specific incident for deeper analysis (IOCs, timeline, attribution).
- **Respect copyright.** Summarize findings in your own words. Don't reproduce article text.

## Handling follow-ups

Common follow-up patterns:

- **"Tell me more about #3"** → Switch to the security-breach-intel skill format and produce a full deep-dive report on that incident.
- **"Filter to just healthcare"** → Re-present the list filtered to the requested sector.
- **"Anything new since last time?"** → Run fresh searches and report only incidents not in the previous list.
- **"Go back further"** → Expand the time window and re-run discovery.
- **"Export this"** → Offer to produce the list as a markdown file or formatted table the user can copy.
