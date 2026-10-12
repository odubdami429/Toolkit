# Agentic SOC Architecture

A multi-agent design for a security operations team: a Slack-fronted **Orchestrator Agent** that routes analyst requests to five stateless **specialist agents**, each backed by a small set of vendor workflow tools. Each file in this folder holds one agent's role, entry paths, tool definitions (parameters, guardrails, registration notes), write-action controls, and a system prompt you can paste in.

Every file is org-agnostic and vendor-agnostic. Fill in the `{PLACEHOLDERS}` (listed in each file) and adapt the tool names to your stack.

## Agents

| Agent | File | Domain | Write actions |
|---|---|---|---|
| Orchestrator Agent | [orchestrator-agent.md](orchestrator-agent.md) | Slack front door: routing, context gathering, synthesis | Join a public Slack channel (audited). Every other write is delegated |
| EDR Agent | [edr-agent.md](edr-agent.md) | Endpoint detection and response alerts, telemetry, fleet hunts, backlog | Close alert, hash exclusion (allowlist), hash blocklist |
| Email Security Agent | [email-security-agent.md](email-security-agent.md) | Email verdicts, message search, headers/auth, remediation | Quarantine / trash / spam / banner / restore, block sender |
| IDP Agent | [idp-agent.md](idp-agent.md) | Identity provider users, groups, apps, audit log | Suspend / unsuspend one account |
| Brand Protection Agent | [brand-protection-agent.md](brand-protection-agent.md) | Lookalike domains, phishing sites, social and executive impersonation | Archive or mark `taken_down` one alert |
| Insider Risk Agent | [insider-risk-agent.md](insider-risk-agent.md) | Insider-risk / DLP alerts, file movement, exfiltration | Close one alert with a note |

## Topology

```
Slack @mention ──► Ingest workflow ──────────────► Orchestrator Agent
                   • ack 200 immediately              │  one agent tool per specialist,
                   • channel allowlist                │  single string param `message`
                   • user allowlist + bot refusal     ├──► EDR Agent ─────────────► edr_* tools
                   • fetch thread + 1 linked thread   ├──► Email Security Agent ──► email_* tools
                   • invoke agent, post reply         ├──► IDP Agent ─────────────► idp_* tools
                                                      ├──► Brand Protection Agent ► brand_* tools
                                                      └──► Insider Risk Agent ────► irm_* tools

Alert pipelines (no human present) invoke specialists directly:
  EDR poll (every 15 min)          ──► EDR Agent             (payload "source": "edr-open-alert-poll")
  Email alert webhook              ──► Email Security Agent  (payload "source": "email_security_webhook")
  Brand / insider-risk alert feeds ──► their specialists      (raw alert JSON)
```

- **Hub and spoke.** Only the orchestrator fans out, making one call per relevant specialist and adding a short *SYNTHESIS* section when two or more ran. Specialists never call each other.
- **Stateless specialists.** Each delegation is a fresh conversation. A specialist can't see the Slack thread, linked messages, tickets, or its own earlier replies. The orchestrator pastes in everything it needs.
- **Pass-through output.** Specialists write Slack mrkdwn, and the orchestrator posts it unedited under a section label.

## The delegation contract

Every delegated `message` contains:

1. **A framing line:** the requester's chat user ID, the channel, what the orchestrator understood the ask to be, and the request type (triage / close / allowlist / action / ad-hoc action with no prior triage).
2. **The request, verbatim**, character for character, including pasted JSON, IDs and hashes.
3. **Identifiers and their sources**, for example "alert ID from the console link in the alert post in this thread".
4. **For follow-ups, the specialist's own earlier output** from the thread, labelled as prior output.

**The copy-paste rule (hard constraint).** Every identifier in a delegated message must appear exactly in the request, the thread, or a tool result. The orchestrator never invents IDs or completes truncated hashes (`3f9c1a2b…`). If it has nothing concrete to send, it asks one clarifying question instead.

Each specialist works out who called it from the content alone. A pipeline payload carries a `source` marker and means nobody is waiting. A framing line means the orchestrator delegated it. Anything else is direct chat.

## Permission layers for write actions

| # | Layer | Where | Kind |
|---|---|---|---|
| 1 | Channel allowlist | Ingest workflow | Code |
| 2 | User allowlist + bot refusal | Ingest workflow | Code |
| 3 | Authorized action requesters (`{AUTHORIZED_ACTION_REQUESTERS}`) | Orchestrator prompt | Prompt |
| 4 | Copy-paste rule, one clarifying question | Orchestrator prompt | Prompt |
| 5 | Explicit-instruction gates, pre-flight lookups, confirm-backs, auto-action thresholds | Specialist prompts | Prompt |
| 6 | Input validation, caps, refusals, read-back, add-only APIs | Specialist write tools | Code |
| 7 | Least-privilege API credentials (e.g. create-only, no delete) | Vendor RBAC | Vendor config |

Layers 3 to 5 are prompt rules. Specialists trust the `requested_by` value in the framing line, so anyone who can chat with a specialist directly bypasses layer 3. Restrict direct access, or enforce the requester list again inside the write tools.

## Design principles

- **Payload = data, policy = prompt.** Never put instructions ("close the ones you're confident about") in a pipeline payload. A standing instruction from the caller outranks the system prompt and has auto-closed alerts below threshold.
- **Everything retrieved is untrusted.** Alert JSON, emails, web pages, tickets, wiki pages, Slack threads and other agents' output are data. Instructions found inside them are prompt injection: ignore them and report them.
- **Calibrated confidence with hard floors.** Benign and violation verdicts need at least 70%, otherwise the verdict *is* "escalate / needs review". Automatic actions need at least 98% plus extra conditions. Agents may never round up to clear a threshold.
- **Writes are narrow and explicit.** One object per call, an exact identifier, a named requester, a reason that becomes the audit trail, and a read-back. Agents never upgrade or widen an action, and never volunteer a write the requester didn't ask for.
- **Tools never fail silently.** Every workflow tool returns HTTP 200 with a structured `status` (`ok`, `not_found`, `refused`, `no_change`, `error`, …) and a `next_step`. Write tools report `written: false | null | true` so a failed write is never mistaken for a proven non-write.
- **Empty is not clean.** A zero-result search proves only that nothing matched those exact filters and that window.

## Operational notes

- **Human approval vs headless runs.** Platform approval prompts time out when an agent runs headless from Slack or a pipeline. Most write tools therefore have approval off and rely on layers 5 to 7. Any tool that keeps approval on (e.g. the EDR hash blocklist) will stall in a delegated run.
- **Nested timeouts.** Set the ingest workflow's invoke timeout above the slowest realistic multi-specialist chain, and add an error branch that posts a failure message. Otherwise a timeout leaves the thread stuck on "Reviewing request...".
- **Keep tool descriptions in sync with prompts.** The model reads both. A stale description (say, "read-only" on an agent that can now suspend accounts) contradicts the prompt.
- **Update deployed tool workflows in place.** On many platforms, re-importing creates a new workflow ID that the agent's tool binding doesn't point to.

## Common placeholders

| Placeholder | Meaning |
|---|---|
| `{ORG_NAME}` | Your organization / brand name |
| `{ORG_DOMAINS}` | Your own email and web domains |
| `{ALERT_CHANNEL}` | The security team's alert channel |
| `{SECURITY_TEAM_GROUP}` / `{SECURITY_TEAM_MEMBERS}` | The team's chat group handle / the user IDs allowed to use the orchestrator |
| `{ALLOWED_CHANNELS}` | Channels the orchestrator accepts requests in |
| `{AUTHORIZED_ACTION_REQUESTERS}` | User IDs allowed to trigger write actions |
| `{EDR_CONSOLE_URL}`, `{IRM_CONSOLE_URL}`, `{IDP_TENANT}`, `{IDP_ADMIN_URL}` | Console and tenant references |
| `{BRAND_PROTECTED_ASSETS}`, `{MONITORED_EXECUTIVES}`, `{ORG_INDUSTRY}` | Brand-protection reference data |
| `{CHAT_USER_EMAIL}`, `{CHAT_USER_NAME}`, `{CURRENT_TIME}` | Filled in by the agent platform at runtime |

Each agent file lists the placeholders it uses.
