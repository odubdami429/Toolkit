---
name: security-breach-intel
description: "Gather, analyze, and report on current security breaches, cyber attacks, and data incidents. Use this skill whenever the user asks about a recent security breach, data leak, cyber attack, ransomware incident, or any cybersecurity event — whether they name a specific incident (e.g., 'tell me about the MOVEit breach') or ask broadly (e.g., 'what breaches happened this week', 'latest cyber attacks'). Also trigger when the user asks for IOCs (indicators of compromise), threat actor attribution, breach timelines, incident summaries, or security intelligence reports. Trigger on phrases like 'security breach', 'data breach', 'cyber attack', 'ransomware attack', 'threat intel', 'IOCs for', 'who was behind the attack on', 'breach report', 'incident report', 'what happened with [company] hack', 'APT', 'threat actor', or any request to investigate or summarize a cybersecurity incident. Even if the user doesn't use security jargon — e.g., 'I heard [company] got hacked, what do we know?' — this skill applies."
---

# Security Breach Intelligence Gatherer

Collect, correlate, and structure information about cybersecurity breaches and incidents into a standardized intelligence report.

## When to use this skill

Any time a user wants current information about a security breach or cyber incident. This includes:

- A specific named breach (e.g., "the SolarWinds attack", "the LastPass breach")
- Broad queries about recent incidents (e.g., "major breaches in the last month")
- Requests for IOCs, threat actor profiles, or attack timelines
- Follow-up questions about an incident already being discussed

## Research workflow

### Step 1 — Scope the incident

Identify what the user is asking about. If they named a specific company or incident, you have your target. If they asked broadly ("latest breaches"), you'll need to search for recent incidents first and either summarize the landscape or let them pick one to dive into.

### Step 2 — Gather information via web search

Run multiple targeted searches to build a complete picture. Don't stop at one search — a single query rarely covers all facets of an incident. Use searches like:

- `"[company/incident name] breach 2025"` — general coverage
- `"[company/incident name] threat actor attribution"` — who did it
- `"[company/incident name] IOC indicators of compromise"` — technical indicators
- `"[company/incident name] breach timeline"` — sequence of events
- `"[company/incident name] CVE vulnerability exploited"` — attack vector details
- `"[company/incident name] CISA advisory"` — government advisories

Prioritize authoritative sources: vendor advisories, CISA/government alerts, reputable security firms (Mandiant, CrowdStrike, Recorded Future, Unit 42, Sophos, ESET, Secureworks), and established cybersecurity journalism (BleepingComputer, The Record, Krebs on Security, Dark Reading, SecurityWeek, The Hacker News).

Be skeptical of unverified claims. If attribution is disputed or unconfirmed, say so explicitly.

### Step 3 — Cross-reference and validate

Compare information across multiple sources. Breaches are fast-moving events where early reports are often incomplete or inaccurate. Note:

- Where sources agree vs. disagree
- What is confirmed vs. suspected vs. speculated
- Whether information has been updated or corrected since initial reporting
- The recency of each source (a report from day 1 may contradict day 30 findings)

### Step 4 — Produce the report

Format all findings into the **Breach Intelligence Report** template below. Every section is required — if information is unavailable for a section, explicitly state what is unknown and why (e.g., "No public attribution has been made as of [date]" rather than omitting the section).

## Breach Intelligence Report template

Structure the output exactly as follows. Use markdown formatting.

```
# Breach Intelligence Report: [Incident Name / Affected Organization]
**Report generated:** [current date]
**Confidence level:** [High / Medium / Low — based on source quality and agreement]

---

## Suspected Attacker Group

Identify the attributed or suspected threat actor(s). Include:
- Group name(s) and known aliases
- Nation-state affiliation (if any)
- Known TTPs (tactics, techniques, and procedures) associated with this group
- Confidence level of attribution (confirmed by law enforcement, assessed by security firms, or unconfirmed/speculative)
- If no attribution exists, state that clearly and note any circumstantial evidence

## What Happened?

A concise narrative of the incident covering:
- What type of attack was it (ransomware, data exfiltration, supply chain, zero-day exploit, phishing, etc.)
- What was the initial access vector (how did the attacker get in)
- What systems, data, or services were affected
- Scope of impact (number of records, customers affected, systems compromised, financial cost if known)
- What vulnerability or weakness was exploited (include CVE IDs if applicable)

## Current State of Events

What is happening right now:
- Is the incident contained or ongoing?
- Has the organization disclosed the breach publicly?
- Are law enforcement agencies involved? (FBI, CISA, Europol, etc.)
- Have patches or mitigations been released?
- Is there any legal action, regulatory investigation, or class action?
- What remediation steps has the affected organization taken?

## Indicators of Compromise (IOCs)

List all known IOCs, organized by type. If no IOCs have been publicly shared, state that explicitly.

| Type | Value | Context |
|------|-------|---------|
| IP Address | x.x.x.x | C2 server observed in [source] |
| Domain | malicious-domain.com | Phishing infrastructure |
| File Hash (SHA256) | abc123... | Malware payload |
| File Hash (MD5) | def456... | Dropper component |
| Email Address | attacker@domain.com | Phishing sender |
| URL | https://... | Malware delivery URL |
| CVE | CVE-YYYY-NNNNN | Exploited vulnerability |
| MITRE ATT&CK | T1566.001 | Technique observed |
| Filename | malware.exe | Malicious file dropped |
| Registry Key | HKLM\... | Persistence mechanism |
| User Agent | Mozilla/5.0... | Unusual UA string in logs |

Only include IOCs that have been publicly reported by credible sources. Cite the source for each IOC.

## Timeline of Events

A chronological sequence of key events. Use ISO date format where possible. Include the source for each entry.

| Date | Event | Source |
|------|-------|--------|
| YYYY-MM-DD | Initial compromise believed to have occurred | [source] |
| YYYY-MM-DD | Attacker activity first detected | [source] |
| YYYY-MM-DD | Organization publicly discloses breach | [source] |
| ... | ... | ... |

If exact dates are unknown, use approximations and note the uncertainty (e.g., "~2025-01-15 (estimated based on forensic analysis)").

## Sources

List all sources consulted, with URLs and publication dates. Prefer direct links. Organize by type:

**Government / Official Advisories:**
- [Title] — [URL] (published [date])

**Security Vendor Reports:**
- [Title] — [URL] (published [date])

**News Coverage:**
- [Title] — [URL] (published [date])

**Victim Organization Statements:**
- [Title] — [URL] (published [date])
```

## Quality guidelines

- **Be precise about uncertainty.** "Suspected" vs. "confirmed" vs. "assessed with moderate confidence" are meaningfully different in threat intelligence. Use the right qualifier.
- **Date everything.** Breach reporting evolves rapidly. Always note when a piece of information was reported and whether it may have been superseded.
- **Don't fabricate IOCs.** If no IOCs have been publicly released, say so. Inventing plausible-looking hashes or IPs is worse than having an empty table.
- **Distinguish primary from secondary sources.** A CISA advisory is more authoritative than a blog post summarizing the CISA advisory.
- **Note conflicting information.** If Source A says 10,000 records were exposed and Source B says 10 million, report both and note the discrepancy.
- **MITRE ATT&CK mapping.** Where possible, map observed techniques to MITRE ATT&CK framework IDs. This helps defenders operationalize the intelligence.
- **Respect copyright.** Do not reproduce large blocks of text from sources. Summarize findings in your own words, cite the source, and link to it.

## Handling broad queries

If the user asks about "recent breaches" or "what's going on in cybersecurity" without naming a specific incident:

1. Search for recent breach news across multiple sources
2. Present a summary table of the top 3–5 most significant recent incidents with a one-line description each
3. Ask the user which one(s) they want a full report on, or offer to generate reports for all of them
4. Generate the full Breach Intelligence Report for each selected incident

## Handling follow-up questions

After generating a report, the user may ask follow-up questions like "are there any new IOCs?" or "has the attribution changed?" In this case, run fresh searches focused on the specific question and update the relevant section of the report. Note what changed and when.
