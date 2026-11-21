# Hermes on the Jarvis host

Jarvis is a Slack security agent: a [Hermes](https://github.com/NousResearch/hermes-agent) gateway (v0.23.1,
`nousresearch/hermes-agent@sha256:276d4468…bda08`, pinned in `install.sh`) run by systemd on one host, plus the
jarvis-tools specialist server (`../tools`). This directory holds the Hermes side: config, persona (`SOUL.md`), the
`jarvis_guard` plugin, the systemd units and their scripts.

Nothing in here is specific to one organisation. Deployment-specific values live in two gitignored files you create
from the `.example` templates, plus one Secrets Manager secret.

## Setup

### 1. `managed/org.env` (shared by both containers)

`cp managed/org.env.example managed/org.env` and fill it in. It is passed with `--env-file` to Hermes **and**
jarvis-tools, and used to render `SOUL.md`. No secrets: jarvis-preflight refuses credential-looking keys. Values are
literal (no quotes).

| Key | What |
|---|---|
| `ORG_NAME` | Display name in prompts and messages |
| `ORG_EMAIL_DOMAINS` | Work email domains, primary first (enterprise search only acts as a requester on the primary one) |
| `ORG_EXTRA_DOMAINS` | Other domains you own; never treated as indicators or sent to a third-party scanner |
| `ORG_SECURITY_TEAM` | Team name without "team" (`Security` → "Escalate to the Security team") |
| `JARVIS_WRITERS` | Slack user IDs who may have Jarvis take security-tool actions and create channels. Each must be in `SLACK_ALLOWED_USERS`; never a trigger bot. Empty = read-only deployment |
| `JARVIS_TRIGGER_BOTS` | Bot user ID(s) of your alert pipeline that may start triage turns (empty = no bot triggers) |
| `JARVIS_ALERT_BOT_NAME` | How prompts name the alert pipeline ("alert bot") |
| `JARVIS_SECURITY_GROUP` | Slack user group (`S…`) tagged on alerts that need a person and invited to new channels. Required |
| `JARVIS_SECURITY_GROUP_FALLBACK` | User IDs invited when the group can't be read (empty: channel creation refuses in that case) |
| `<PREFIX>_PROVIDER` | One per domain (`EDR`, `IDP`, `SUITE`, `EMAIL_SECURITY`, `BRAND_PROTECTION`, `INSIDER_RISK`, `TICKETING`, `ENTERPRISE_SEARCH`): the adapter key registered in `tools/app/providers/__init__.py` (`example` = the shipped skeleton, which answers `not_implemented`; or your own). Empty or `none` disables the domain; an unknown key stops jarvis-tools at startup. See [Domains and adapters](#domains-and-adapters) |
| `<PREFIX>_BASE_URL` | The product's API origin: bare `https://` origin, fixed at startup, never taken from model input |
| `<PREFIX>_CONSOLE_URL` | The product's web console origin. Used to recognise alert links in alert-bot posts for automatic actions; empty = recognise none |
| other `<PREFIX>_*` | Extra non-secret settings an adapter reads (tenant or account ids, ...), documented in the adapter's module |
| `SANCTIONED_AI_GROUPS` | Identity provider groups that sanction GenAI use (the insider risk AI-entitlement check). Exact, case-sensitive |

### 2. `managed/.env` (Hermes only)

`cp managed/.env.example managed/.env`. Mounted read-only at `/etc/hermes/.env`, applied last with override.

| Key | What |
|---|---|
| `SLACK_ALLOWED_USERS` | Slack user IDs who may talk to Jarvis (reads). Trigger bots must be listed too (the adapter's early sender check), but the guard never treats them as people |
| `JARVIS_SLACK_TEAM_ID` | Your workspace ID. The guard denies every tool call from any other workspace |
| `SLACK_ALLOW_BOTS` | `mentions` (alert-bot triggers on) or `none`. Never `all` |
| `JARVIS_BOT_CHANNELS` | Channel IDs where trigger bots may start turns (never DMs) |
| `JARVIS_BOT_TRIGGERS_PER_HOUR` | Cap on bot-started turns, across all bots and channels (default 20) |
| `JARVIS_AUDIT_CHANNEL` | Where the Slack write tools post their audit lines (usually your alert channel) |
| the rest | Hermes hardening pins (mention rules, safe mode off, media strictness, no config migration); keep them |

`JARVIS_WRITERS` and `JARVIS_TRIGGER_BOTS` must **not** be in this file (preflight refuses): jarvis-tools needs them
too, so they live in `org.env`.

### 3. Optional `managed/host.env`

Read by both systemd units (`EnvironmentFile=-…`) for `jarvis-secrets`: `JARVIS_SECRET_ID` (default
`jarvis/prod/hermes`) and `AWS_REGION` (default `us-east-1`). Omit it to use the defaults.

### 4. The secret

One Secrets Manager secret, a JSON object (Key/value tab). `jarvis-secrets` (ExecStartPre of both units) splits it
into `/run/jarvis/hermes.env` and `/run/jarvis/tools.env` (tmpfs, root 0400, deleted on stop), so security-tool
credentials never reach the Hermes container. Every security-tool key is optional and uses the same generic names for
every domain, where `<prefix>` is `edr`, `idp`, `suite`, `email_security`, `brand_protection`, `insider_risk`,
`ticketing` or `enterprise_search`. Each adapter documents which of them it reads; a domain without its credentials
isn't offered. The start-up journal line lists, per domain, which credential fields are set (never their values).

| Key | Goes to | Notes |
|---|---|---|
| `slack_bot_token` (`xoxb-`), `slack_app_token` (`xapp-`) | Hermes | required |
| `anthropic_api_key` (`sk-ant-`) | both | required |
| `<prefix>_api_token` → `<PREFIX>_API_TOKEN` | tools | static API token or key |
| `<prefix>_username` → `<PREFIX>_USERNAME` | tools | the account a token belongs to (for basic-auth style APIs) |
| `<prefix>_client_id` → `<PREFIX>_CLIENT_ID` | tools | OAuth client id; needs `<prefix>_client_secret` or `<prefix>_private_key` |
| `<prefix>_client_secret` → `<PREFIX>_CLIENT_SECRET` | tools | OAuth client secret (client-credentials grant) |
| `<prefix>_key_id` → `<PREFIX>_KEY_ID` | tools | id of the signing key, for JWT client assertions |
| `<prefix>_private_key` → `<PREFIX>_PRIVATE_KEY_B64` | tools | PEM private key (must contain `-----BEGIN … PRIVATE KEY-----`); shipped base64 because env files can't carry newlines |
| `jarvis_writes_enabled` | tools | `false` turns off every security-tool write tool |
| `jarvis_auto_close_enabled` | tools | `false` turns off automatic actions on alert-bot posts |
| `jarvis_slack_writes_enabled` | Hermes | `false` turns off `create_slack_channel` and `join_slack_channel` |

The bearer token between the containers and the guard's HMAC key are generated per boot, not stored in the secret.

### 5. Slack app

Create it from `slack-app-manifest.yaml` (api.slack.com/apps → From a manifest). Generate an app-level token with
`connections:write`, install the app, and consider restricting token use to the host's egress IP.
`channels:join`, `groups:write` and `usergroups:read` are only for the channel tools; drop them if you don't want those.

### 6. Install and start

Copy this directory and `../tools` to the host and run `sudo ./install.sh`. It refuses if `managed/org.env` or
`managed/.env` is missing, renders `SOUL.md`, installs everything root-owned under `/opt/jarvis/hermes`, builds
`jarvis-tools:local`, installs the units and does **not** start them.

```sh
sudo systemctl start jarvis-hermes        # also starts jarvis-tools
sudo journalctl -u jarvis-hermes -f       # unit, secrets, preflight
sudo journalctl -t jarvis-hermes -f       # gateway + jarvis_guard JSON lines
sudo journalctl -t jarvis-tools -f        # specialists
```

DM the app, or @-mention it in a channel it has been added to. Only allowlisted users get an answer. After editing
`org.env` or `.env`, rerun `install.sh` and restart both units.

### SOUL.md rendering

`SOUL.md` in this directory is a template. `install.sh` fills its `{{NAME}}` placeholders and installs the result as
`/opt/jarvis/hermes/SOUL.md`; jarvis-preflight refuses to start if a `{{` is left. Placeholders: `ORG_NAME`,
`ORG_EMAIL_DOMAIN` (primary), `ORG_EMAIL_DOMAINS`, `ORG_DOMAINS`, `ORG_SECURITY_TEAM`, `ALERT_BOT_NAME` (from
`JARVIS_ALERT_BOT_NAME`), `JARVIS_SECURITY_GROUP` (from `org.env`), and `JARVIS_AUDIT_CHANNEL`, `JARVIS_BOT_CHANNELS`
(from `managed/.env`). An unknown placeholder, or one whose setting is empty, stops the install. The names match
`tools/app/org.py`, which renders the specialist prompts the same way.

## Domains and adapters

The design follows the [Agentic SOC reference architecture](https://github.com/odubdami429/Toolkit/tree/main/Agentic%20Engineering/Agentic%20SOC%20Architecture):
vendor-neutral domain **contracts**, one **adapter** per domain that implements a contract for your product, and
**contract tests** every adapter must pass. This repository ships no product integrations: only the contracts and an
`example` skeleton adapter per domain.

Jarvis delegates work in security tools to specialist sub-agents served by jarvis-tools over MCP
(`http://jarvis-tools:8080/mcp` on the `jarvis` Docker network). Specialists are named for a security **domain**, not
a product: each is its own Claude loop with a domain prompt and only that domain's tools, and Jarvis sees only the
final answer. The adapter behind a domain is picked with `<PREFIX>_PROVIDER` in `org.env`. A domain is enabled when its
provider, its `<PREFIX>_BASE_URL` **and** its credentials (in the secret) are all set; otherwise its tools aren't
offered, and `SOUL.md` tells Jarvis to say the integration isn't set up.

| Domain (`tools/app/providers/<domain>/`) | Specialist tool | Tool names | Env prefix |
|---|---|---|---|
| `edr` | `ask_edr_specialist` | `edr_*` | `EDR` |
| `idp` | `ask_idp_specialist` | `idp_*` | `IDP` |
| `productivity_suite` | `ask_suite_specialist` | `suite_*` | `SUITE` |
| `email_security` | `ask_email_security_specialist` | `email_*` | `EMAIL_SECURITY` |
| `brand_protection` | `ask_brand_protection_specialist` | `brand_*` | `BRAND_PROTECTION` |
| `insider_risk` | `ask_insider_risk_specialist` | `irm_*` | `INSIDER_RISK` |
| web research | `ask_web_research` | `web_search`, `web_fetch` (Anthropic server-side tools) | none |
| `ticketing` | direct tools (no specialist) | `search_tickets`, `get_ticket_details`, `search_wiki`, `get_wiki_page_details` | `TICKETING` |
| `enterprise_search` | direct tools (no specialist) | `enterprise_search`, `enterprise_chat`, `enterprise_read_document` | `ENTERPRISE_SEARCH` |

What each specialist does:

| Tool | Reads | Writes (writers only) |
|---|---|---|
| `ask_edr_specialist` | alerts, open-alert backlog, devices, telemetry query; web, tickets/wiki, enterprise search | close alert, hash/path allowlist, hash block, network contain, full disk scan |
| `ask_idp_specialist` | users, groups, apps, sign-in/admin event log | suspend/unsuspend, clear sessions |
| `ask_suite_specialist` | directory profile, suite activity logs, current OAuth grants | revoke an app's token, sign out |
| `ask_email_security_specialist` | message search, raw message, the platform's analysis report, action status | quarantine/trash/banner/restore, block sender |
| `ask_brand_protection_specialist` | alerts, alert search, URL scan; web, tickets/wiki, enterprise search | archive / mark taken down |
| `ask_insider_risk_specialist` | alerts, file events, AI entitlement (via the identity provider); web, tickets/wiki, enterprise search | close one alert with a disposition and note |
| `ask_web_research` | public web search/fetch | none |

Jarvis also calls read-only tools directly: `search_tickets(query)`, `get_ticket_details(ticket_key)`,
`search_wiki(query)`, `get_wiki_page_details(page_id)` (the configured ticketing account's view; queries are in the
deployment's ticketing/wiki query language, which the adapter documents in the tool descriptions) and
`enterprise_search`, `enterprise_chat`, `enterprise_read_document`. The enterprise search contract requires acting as
the requester: the guard looks up the requester's work email from their Slack ID and signs it, and adapters must refuse
anything not on the primary `ORG_EMAIL_DOMAINS` domain. Alert-bot turns have no enterprise search (a bot has no email).

**Security-tool writes.** `edr_close_alert`, `edr_add_hash_exclusion`, `edr_add_hash_blocklist`,
`edr_add_path_exclusion`, `edr_network_contain`, `edr_initiate_scan`, `idp_set_user_suspension`,
`idp_clear_user_sessions`, `suite_revoke_token`, `suite_sign_out_user`, `email_action_message`, `email_block_sender`,
`brand_update_alert`, `irm_close_alert`. jarvis-tools offers them only when the **signed** requester is in
`JARVIS_WRITERS` and `jarvis_writes_enabled` isn't `false`. Each adapter has its own writer client; each distinct
action runs at most once per request and at most 6 per request; nothing is retried; the verified requester must be
written into the product's note or comment. Logged as `write_call_start` / `write_call`.

### Contracts

`tools/app/providers/<domain>/contract.py` is the vendor-neutral spec for a domain: the read tool schemas (`TOOLS`),
`WRITE_TOOLS` and `LIST_TOOLS` (reads that need the writer's credential), the return envelope of every tool (status
values and key fields), the guardrails an implementation **must** enforce, the credential/RBAC scope it needs, and,
for domains with automatic actions, the policy hooks (`AUTO_ID_SHAPE`, `AUTO_NOTE`, `auto_tools()`, `auto_check()`,
`auto_payload()`, `auto_requester()`, `make_auto_id_pattern(console_url)`). Tool names and parameters are fixed, so the
domain prompt (`tools/specialists/<domain>/prompt.md`), `SOUL.md` and the guard never change when you swap adapters.
Where a product query language is needed (`edr_query`, `search_tickets`, `search_wiki`), the adapter appends its own
primer to the tool description with the contract helper `with_primer(tools, name, primer)`.

### The example adapters

`providers/<domain>/example.py` (and `example_write.py` for domains with writes) are skeletons: `client_from_env(env)`
returns a small client when `<PREFIX>_BASE_URL` and credentials are set, `run_tool` validates input generically
(required parameters, types, caps from the contract) and then returns `{"status": "not_implemented", ...}` telling the
model to say the lookup isn't implemented and never invent results. Each stub carries a `# TODO: call your vendor API`
comment and the guardrail checklist for that tool. With `<PREFIX>_PROVIDER=example`, Jarvis runs end to end and
answers honestly that nothing is wired up.

### Implementing and registering an adapter

1. Copy `providers/<domain>/example.py` to `providers/<domain>/<name>.py` (and `example_write.py` to
   `<name>_write.py` if the domain has writes) and implement each stub against your product's API, keeping the
   contract's tool names, parameters and return envelopes. Read `<PREFIX>_BASE_URL` and the generic credential env
   vars (`<PREFIX>_API_TOKEN`, `_USERNAME`, `_CLIENT_ID`, `_CLIENT_SECRET`, `_KEY_ID`, `_PRIVATE_KEY_B64`); document
   any extra non-secret `<PREFIX>_*` settings in the module docstring. `run_tool` / `run_write_tool` must never raise
   and always return a dict with `status`. Allow only fixed API paths, don't follow redirects, ignore proxy env and
   scrub credentials from output.
2. For automatic actions, re-export the contract's hooks from the write module and set
   `AUTO_ID_PATTERN = contract.make_auto_id_pattern(os.environ.get("<PREFIX>_CONSOLE_URL"))`; the contract decides
   which alert IDs in the signed `alert_post` are eligible. Nothing in Hermes changes.
3. Register it in `DOMAINS` in `tools/app/providers/__init__.py` (`"<name>": (read module, write module or None)`).
4. Run the contract tests: `tools/app/tests/test_contracts.py` (every domain/adapter: tool names, schemas, never
   raising on garbage input, writes refusing without a requester, the automatic-action accept/refuse matrix, console
   link ID extraction) and `tools/app/tests/test_contract_<domain>.py` (domain-specific rules). Add your own tests
   against a fake HTTP layer next to them.
5. Optionally add `tools/specialists/<domain>/providers/<name>.md`: adapter-specific prompt notes (query-language
   primer, ID and URL formats, verdict fields, console links, retention). The server appends it to the vendor-neutral
   domain prompt. Same placeholders as `SOUL.md`.
6. Put its credentials in the secret under the generic `<prefix>_*` keys, set `<PREFIX>_PROVIDER=<name>`,
   `<PREFIX>_BASE_URL` and `<PREFIX>_CONSOLE_URL` in `org.env`, rerun `install.sh` and restart.

## The guard plugin (`plugins/jarvis_guard`)

- **Requester binding.** Every tool call (`pre_tool_call`) is denied unless the turn is bound to exactly one Slack
  requester in the pinned workspace who is in `SLACK_ALLOWED_USERS` (and isn't a trigger bot), or a trigger bot in one
  of `JARVIS_BOT_CHANNELS`. Identity in the process env is treated as tampering. `skill_manage` and `clarify` are
  always blocked.
- **Signing.** Every jarvis-tools call gets a `jarvis_auth` argument the model can't supply: `{actor, actor_email,
  alert_post, session_key, tool_call_id, ts, sig}`, where `sig` is HMAC-SHA256 with the per-boot key over
  `tool|actor|session_key|tool_call_id|ts|actor_email|sha256_hex(alert_post)`. `alert_post` is the trigger bot's own
  unedited thread-root post (up to 20000 characters) on alert-bot calls and `""` otherwise. jarvis-tools refuses calls
  without a valid, fresh, unused one, so specialists fail closed if the guard is missing. The guard knows no provider
  or alert-ID format.
- **Bot triggers.** `pre_gateway_dispatch` drops every bot message except a trigger bot in a bot channel of the
  pinned workspace, under the hourly cap.
- **Slack tools.** `lookup_slack_user`, `resolve_slack_link`, `read_slack_channel` (read-only client; requester must
  be in the channel; private content only shown in that channel or a DM). `create_slack_channel` (writers only;
  private `YYYY-MM-DD-<topic>` channel, invites the live members of `JARVIS_SECURITY_GROUP`, or
  `JARVIS_SECURITY_GROUP_FALLBACK` if the group can't be read; refuses if the group is unset or has more than 15
  members) and `join_slack_channel` (any allowlisted person; public channels the requester is in). Both on their own
  client, capped per thread (1 create, 2 joins per 10 minutes), audited in `JARVIS_AUDIT_CHANNEL`.
- **Formatting.** Rewrites Slack-style `*bold*` so Hermes doesn't turn it into italics; keeps user IDs next to
  mentioned names.
- **Load canary.** The guard logs a `loaded` line with a per-start nonce; `jarvis-guard-canary` (ExecStartPost) stops
  the unit if Slack connects first or Hermes reports a load problem.

## Alert-bot flow

1. Your alert pipeline posts an alert in a `JARVIS_BOT_CHANNELS` channel and @-mentions Jarvis (the message text or
   blocks must contain `<@JARVIS_BOT_USER_ID>`).
2. The guard admits it only if the bot is in `JARVIS_TRIGGER_BOTS` and the hourly cap isn't reached (`bot_trigger`
   line).
3. Jarvis calls the specialist for the alert's domain with the whole post. The guard reads the bot's own **unedited**
   thread-root post from Slack and signs it whole as `alert_post` (logging only its length and a hash prefix, as
   `alert_root`). jarvis-tools verifies the signature and asks the domain's adapter which alert IDs the post contains:
   IDs in links under the configured `<PREFIX>_CONSOLE_URL` that match the contract's `AUTO_ID_SHAPE`. The model and
   the alert text can't add any.
4. On those IDs only, specialists may take automatic actions within limits jarvis-tools enforces: EDR closes a benign
   alert at ≥ 98% as false positive; email security quarantines and blocks the sender above 98% malicious, banners
   malicious ≤ 98% and suspicious; brand protection archives a benign alert at ≥ 98%; insider risk closes as false
   positive / benign true positive at ≥ 98%. Each alert once, at most 10 an hour per domain; never an allowlist,
   block (except email security's sender block), contain or scan. Off switch: `jarvis_auto_close_enabled=false`.
5. Jarvis replies in the thread with the triage, tagging `<!subteam^JARVIS_SECURITY_GROUP>` only when an alert still
   needs a person. A writer can then @-mention Jarvis in the thread to act.

To add a channel: add its ID to `JARVIS_BOT_CHANNELS`, invite Jarvis, rerun `install.sh`, restart. To turn bot
triggers off: `SLACK_ALLOW_BOTS=none`, empty `JARVIS_TRIGGER_BOTS`, and remove the bot from `SLACK_ALLOWED_USERS`.

## Kill switches

| What | How |
|---|---|
| Security-tool writes | secret `jarvis_writes_enabled=false`, `sudo systemctl restart jarvis-tools` |
| Automatic actions on alert posts | secret `jarvis_auto_close_enabled=false`, restart jarvis-tools |
| Slack channel create/join | secret `jarvis_slack_writes_enabled=false`, `sudo systemctl restart jarvis-hermes` |
| Bot triggers | `SLACK_ALLOW_BOTS=none` in `managed/.env`, reinstall, restart |
| Everything | `sudo systemctl stop jarvis-hermes jarvis-tools` (130 s drain), then revoke the `xapp` token |

## Audit log lines

All JSON, one per line, in journald outside the containers.

- `journalctl -t jarvis-hermes`: `jarvis_guard` = `loaded`, `pre_tool_call` (allow/block with reason and binding),
  `bot_trigger`, `alert_root`, `slack_tool`, `slack_write`, `jarvis_whoami`, `mention_ids_patched`.
- `journalctl -t jarvis-tools`: `specialist_start`, `specialist_turn`, `tool_call`, `web_call`, `direct_call`,
  `write_call_start`, `write_call`, `auto_action`, `auto_close_start`, `auto_close`, `refused`, `specialist_done`.

## What's on the host

| Path | What |
|---|---|
| `/opt/jarvis/hermes/` | Everything below, root-owned, mounted read-only |
| `config.yaml`, `managed/config.yaml` | The same file twice: user layer and managed overlay (`/etc/hermes/config.yaml`) |
| `managed/.env`, `managed/org.env`, `managed/host.env` | The deployment files above |
| `SOUL.md` | The rendered persona |
| `empty.env` | Mounted over the data-volume `.env`, so nothing on the volume can set env |
| `plugins/jarvis_guard/` | The guard plugin |
| `bin/jarvis-secrets` | Secret → per-container env files on tmpfs |
| `bin/jarvis-preflight` | Refuses to start on loosened config, forbidden or misplaced env keys, writers outside the allowlist, credentials in `org.env`, an unrendered `SOUL.md`, planted `hooks/` or pairing entries |
| `bin/jarvis-hermes-run`, `bin/jarvis-tools-run` | `docker run` as UID 10000 / 10001, read-only rootfs, `--cap-drop ALL`, no-new-privileges, `org.env` then the secrets env file |
| `bin/jarvis-guard-canary` | The load canary |
| `bin/jarvis-hermes-config-dump` | Effective config, plugin list and Slack tool surface, from a no-network container |
| `/var/lib/jarvis/hermes` | HERMES_HOME (sessions, `state.db`, logs) on a separate data volume |

## Security model

- Two containers, two credential sets: Hermes holds Slack and Anthropic; jarvis-tools holds the security-tool
  credentials. Preflight refuses a security-tool credential in `hermes.env` and any credential-looking key in
  `org.env`.
- Who may read: `SLACK_ALLOWED_USERS` in the pinned workspace. Who may act: `JARVIS_WRITERS`, checked by jarvis-tools
  from the signed requester (security-tool writes) and by the guard (channel creation). A trigger bot is never a writer.
- Text from Slack, alerts, tickets and tool results is data; prompts say so and every action needs an analyst's own
  words or an alert ID found in the signed alert post.
- Adapter clients must allow only fixed paths in code, don't follow redirects, ignore proxy env and scrub credentials
  from output. Tenant URLs come from `org.env`, never from model input.
- Config is root-owned and read-only; the managed overlay pins the security keys; preflight checks a fixed list.
- Web research queries leave your network; prompts allow public indicators only, and every query is logged.

## Test checklist

- Unit tests: `python -m pytest -q hermes/tests` (standard library + pytest). jarvis-tools:
  `docker run --rm --entrypoint sh -e HOME=/tmp jarvis-tools:local -c 'cd /app && pip install -q --user pytest && python -m pytest -q'`.
- **S-1 binding:** ask "who am I?" so Jarvis calls `jarvis_whoami`; check the `pre_tool_call` line's `actor_id`,
  `session_key`, `platform`. Two people in one thread mid-turn → `block`, "no single requester".
- **S-4 surface:** `sudo /opt/jarvis/hermes/bin/jarvis-hermes-config-dump`; the Slack surface is `skills`,
  `jarvis_guard` and the jarvis_tools MCP tools only.
- **S-6 admin commands:** from a normal user try `/yolo`, `!yolo`, `@jarvis /approvals off`, `/model`, `/debug`.
  `allow_admin_from` is a non-existent ID, so nobody is an admin.
- **S-14 canary:** break the plugin (syntax error, slow `register()`); the unit must stop right after Slack connects.
- **S-18 preflight:** plant a forbidden env key, a `hooks/` dir, a loosened config, a credential in `org.env` or a
  `{{` in `SOUL.md` and restart; preflight must refuse.

## Known gaps

- No golden effective-config diff; preflight checks a fixed list of keys.
- Bundled Hermes backend plugins are loaded (their toolsets are off for Slack); `plugins.disabled` stays empty so
  nobody can disable `jarvis_guard` that way.
- The guard has no per-request budgets beyond the bot-trigger cap and the Slack write caps; jarvis-tools caps its own
  tools.
- If the guard fails to load, the gateway is connected and unguarded for about a second before the canary stops it.
  jarvis-tools refuses unsigned calls, so no security-tool data is reachable in that window.
- Specialists share Hermes's Anthropic key.
- Only skeleton adapters ship: every security-tool lookup answers `not_implemented` until you implement and register
  your own adapters.
- The brand protection specialist judges pages from `web_fetch` (no JavaScript, no login walls).
- `SLACK_ALLOWED_USERS` and the security group fallback are static lists; edit them when the team changes.
- Egress is not restricted by this directory; one secret holds every credential.
