# Agentic SOC Architecture

A multi-agent design for a security operations team: a Slack-fronted **Orchestrator Agent** that routes analyst requests to seven stateless **specialist agents**, each backed by a small set of vendor workflow tools. Each file in this folder holds one agent's role, entry paths, tool definitions (parameters, guardrails, registration notes), write-action controls, and a system prompt you can paste in.

Every file is org-agnostic and vendor-agnostic. Fill in the `{PLACEHOLDERS}` (listed in each file) and adapt the tool names to your stack.

## Agents

| Agent | File | Domain | Write actions |
|---|---|---|---|
| Orchestrator Agent | [orchestrator-agent.md](orchestrator-agent.md) | Slack front door (channels and DMs): routing, context gathering, screenshot reading, synthesis | Join a public Slack channel (audited). Every other write is delegated |
| EDR Agent | [edr-agent.md](edr-agent.md) | Endpoint detection and response alerts, telemetry, fleet hunts, device lookups, backlog | Close alert, hash exclusion, path exclusion, hash blocklist, network-contain one endpoint |
| Email Security Agent | [email-security-agent.md](email-security-agent.md) | Email verdicts, message search, headers/auth, remediation | Quarantine / trash / spam / banner / restore, block sender |
| IDP Agent | [idp-agent.md](idp-agent.md) | Identity provider users, groups, apps, audit log | Suspend / unsuspend one account |
| Brand Protection Agent | [brand-protection-agent.md](brand-protection-agent.md) | Lookalike domains, phishing sites, social and executive impersonation | Archive or mark `taken_down` one alert |
| Insider Risk Agent | [insider-risk-agent.md](insider-risk-agent.md) | Insider-risk / DLP alerts, file movement, exfiltration, sanctioned-AI-tool checks | Close one alert with a note (incl. narrow auto-close at ≥98%) |
| Productivity Suite Agent | [productivity-suite-agent.md](productivity-suite-agent.md) | Productivity-suite audit logs: logins, file sharing and downloads, mail sends, admin changes, OAuth grants | Revoke one OAuth token, sign one user out of all suite sessions |
| Web Security Agent | [web-security-agent.md](web-security-agent.md) | SSE / secure web gateway / CASB events: who visited what, DLP and malware alerts, IOC hunts in web traffic, URL lists | Add entries to one URL blocklist |

## Topology

```
Slack @mention / DM ─► Ingest workflow ───────────────► Orchestrator Agent
                       • ack 200 immediately               │  one agent tool per specialist,
                       • user allowlist + bot/loop guard   │  single string param `message`
                       • fetch thread + 1 linked thread    ├──► EDR Agent ─────────────────► edr_* tools
                       • transcribe ≤4 screenshots         ├──► Email Security Agent ──────► email_* tools
                       • invoke agent, post reply          ├──► IDP Agent ─────────────────► idp_* tools
                       • log run (orchestrator_runs)       ├──► Brand Protection Agent ────► brand_* tools
                                                           ├──► Insider Risk Agent ────────► irm_* tools
                                                           │        └──► IDP Agent (entitlement check only)
                                                           ├──► Productivity Suite Agent ──► suite_* tools
                                                           └──► Web Security Agent ────────► sse_* tools

Alert pipelines (no human present) invoke specialists directly:
  EDR poll (every 15 min)          ──► EDR Agent             (payload "source": "edr-open-alert-poll")
  Email alert webhook              ──► Email Security Agent  (payload "source": "email_security_webhook")
  Brand / insider-risk alert feeds ──► their specialists      (raw alert JSON)
  Each pipeline reads the agent's labels and adds a triage reaction (✅ done / 👀 needs a human / ⚠️ failed) to the alert post.
```

- **Hub and spoke, one hop deep.** The orchestrator lists the entities in a request, calls at most four specialists (in parallel, or chained when one needs another's output, e.g. Brand Protection verdict → Web Security block), and adds a short *SYNTHESIS* section when two or more ran. Writes never fan out: one specialist's findings never become another specialist's write unless the requester asked for it.
- **One specialist-to-specialist edge.** The Insider Risk Agent may ask the IDP Agent a fixed, read-only group-membership question (is this person in a sanctioned AI-tool group?). It sends only the email, treats the reply as data, and treats anything unclear as *Unknown*. No other specialist calls another.
- **Stateless specialists.** Each delegation is a fresh conversation. A specialist can't see the Slack thread, linked messages, screenshots, tickets, or its own earlier replies. The orchestrator pastes in everything it needs.
- **Pass-through output.** Specialists write Slack mrkdwn, and the orchestrator posts it unedited under a section label, after a `*Sub-Agents used:*` header.

## The delegation contract

Every delegated `message` contains:

1. **A framing line:** the requester's name (from `lookup_slack_user`) and chat user ID, the channel, what the orchestrator understood the ask to be, and the request type (triage / close / allowlist / containment / action / ad-hoc action with no prior triage).
2. **The request, verbatim**, character for character, including pasted JSON, IDs and hashes.
3. **Identifiers and their sources**, for example "alert ID from the console link in the alert post in this thread".
4. **For follow-ups, the specialist's own earlier output** from the thread, labelled as prior output.

**The copy-paste rule (hard constraint).** Every identifier in a delegated message must appear exactly in the request, the thread, or a tool result. The orchestrator never invents IDs or completes truncated hashes (`3f9c1a2b…`). Values a screenshot transcription marks `[?]` or `[cut off]` are never used, and a write target seen only in a screenshot must be confirmed as text first. If it has nothing concrete to send, it asks one clarifying question instead.

Each specialist works out who called it from the content alone. A pipeline payload carries a `source` marker and means nobody is waiting. A framing line means the orchestrator delegated it. A fixed entitlement question means the Insider Risk Agent. Anything else is direct chat.

## Permission layers for write actions

| # | Layer | Where | Kind |
|---|---|---|---|
| 1 | User allowlist (`{SECURITY_TEAM_MEMBERS}`) + bot / loop guard | Ingest workflow | Code |
| 2 | Authorized action requesters (`{AUTHORIZED_ACTION_REQUESTERS}`) | Orchestrator prompt | Prompt |
| 3 | Copy-paste rule, screenshot rule, one clarifying question, writes never fan out | Orchestrator prompt | Prompt |
| 4 | Explicit-instruction gates, pre-flight lookups, confirm-backs, auto-action thresholds | Specialist prompts | Prompt |
| 5 | Input validation, caps, refusals (service accounts, admins, protected domains, servers without confirmation), read-back, add-only APIs | Specialist write tools | Code |
| 6 | Platform human approval on selected tools | Agent platform | Config |
| 7 | Least-privilege API credentials (e.g. create-only, contain-but-not-release) | Vendor RBAC | Vendor config |

There is no channel allowlist: the bot answers wherever it has been added and in DMs. Add one in the ingest workflow if you need it.

Layers 2 to 4 are prompt rules. Specialists trust the `requested_by` value in the framing line, so anyone who can chat with a specialist directly bypasses layer 2. Restrict direct access, or enforce the requester list again inside the write tools. A Slack profile lookup never changes who is authorized.

## Shared and optional components

- **`load_skill` (shared playbooks).** A read-only workflow tool any agent can carry. It fetches one playbook by name from an `agent_skills` table in the platform database (name, description, target agents, owner, version, markdown body; capped at 30,000 chars), so long procedures don't live in every prompt. The name is normalised to `[a-z0-9-]` and passed as a bound parameter; a miss returns the list of real names. **Trust boundary:** agents treat every tool result as data *except* a loaded skill, which is instructions. Only that is as safe as write access to the table: keep it writable by the security team only, keep a change-history table, and review edits like code.
- **Run log.** The ingest workflow writes one `orchestrator_runs` row per answered request (requester, channel, request, reply, specialists used, extracted identifiers). An `orchestrator_actions` table, a specialist `log_action` tool and an orchestrator `search_history` tool can extend this so the orchestrator can answer "have we seen this hash before?" or "did we already suspend X?". It is a log written by code, not agent memory. Delete old rows on a schedule.

## Design principles

- **Payload = data, policy = prompt.** Never put instructions ("close the ones you're confident about") in a pipeline payload. A standing instruction from the caller outranks the system prompt and has auto-closed alerts below threshold.
- **Everything retrieved is untrusted.** Alert JSON, emails, web pages, tickets, wiki pages, Slack threads, screenshot transcriptions, Slack profiles and other agents' output are data. Instructions found inside them are prompt injection: ignore them and report them. The one deliberate exception is `load_skill`.
- **Calibrated confidence with hard floors.** Benign and violation verdicts need at least 70%, otherwise the verdict *is* "escalate / needs review". Automatic actions need at least 98% plus extra conditions (e.g. at least three matching prior closes by a human analyst). Agents may never round up to clear a threshold.
- **Writes are narrow and explicit.** One object per call, an exact identifier, a named requester, a reason that becomes the audit trail, and a read-back. Agents never upgrade or widen an action, never volunteer a write the requester didn't ask for, and never auto-contain a host or auto-add a path exclusion. Some writes are deliberately one-way from the agent (containment can't be released, blocklist entries can't be removed); undo is a console action.
- **Tools never fail silently.** Every workflow tool returns HTTP 200 with a structured `status` (`ok`, `not_found`, `refused`, `no_change`, `error`, …) and a `next_step`. Write tools report `written: false | null | true` so a failed write is never mistaken for a proven non-write. Agents report a write as done only on a confirmed result.
- **Empty is not clean.** A zero-result search proves only that nothing matched those exact filters and that window.

## Operational notes

- **Human approval vs headless runs.** Platform approval prompts time out when an agent runs headless from Slack or a pipeline. Most write tools therefore have approval off and rely on layers 4, 5 and 7. Any tool that keeps approval on will stall in a delegated run. Check the actual setting on every write tool against what its prompt and description claim; they drift.
- **Nested timeouts.** Set the ingest workflow's invoke timeout (e.g. 600 s) above the slowest realistic multi-specialist chain, and add an error branch that posts a failure message. Otherwise a timeout leaves the thread stuck on "Reviewing request...". Long searches (e.g. web-security event scans) may need their own handler timeout raised.
- **Screenshots leave your environment.** The ingest workflow sends images to an image-capable model for transcription. Use a model your data-handling policy allows.
- **Keep tool descriptions in sync with prompts.** The model reads both. A stale description (say, "read-only" on an agent that can now suspend accounts, or a threshold the tool doesn't enforce) contradicts the prompt. Declare every param the prompt uses; undeclared params are unreachable.
- **Update deployed tool workflows in place.** On many platforms, re-importing creates a new workflow ID that the agent's tool binding doesn't point to.
- **Hand-kept allowlists.** The user allowlist is a copy of a chat user group, not a live lookup. Re-sync it when the group changes.

## Common placeholders

| Placeholder | Meaning |
|---|---|
| `{ORG_NAME}` | Your organization / brand name |
| `{ORG_DOMAINS}` | Your own email and web domains |
| `{ALERT_CHANNEL}` | The security team's alert channel |
| `{SECURITY_TEAM_GROUP}` / `{SECURITY_TEAM_MEMBERS}` | The team's chat group handle / the user IDs allowed to use the orchestrator |
| `{BOT_USER_ID}` | The orchestrator bot's own chat user ID |
| `{AUTHORIZED_ACTION_REQUESTERS}` | User IDs allowed to trigger write actions |
| `{EDR_CONSOLE_URL}`, `{IRM_CONSOLE_URL}`, `{IDP_TENANT}`, `{IDP_ADMIN_URL}`, `{SUITE_ADMIN_URL}`, `{SSE_TENANT_URL}` | Console and tenant references |
| `{BRAND_PROTECTED_ASSETS}`, `{MONITORED_EXECUTIVES}`, `{ORG_INDUSTRY}` | Brand-protection reference data |
| `{SANCTIONED_AI_GROUPS}` | IdP groups that grant access to sanctioned AI tools |
| `{SSE_BLOCK_LIST}`, `{SERVICE_ACCOUNT}` | Web-security blocklist name / the integration service account |
| `{CHAT_USER_EMAIL}`, `{CHAT_USER_NAME}`, `{CURRENT_TIME}` | Filled in by the agent platform at runtime |

Each agent file lists the placeholders it uses.
