# Jarvis on Hermes

Jarvis is a Slack assistant for a security team. It runs on [Hermes](https://github.com/NousResearch/hermes-agent)
(NousResearch's agent gateway) and hands work to security-domain specialist sub-agents (EDR, identity, email
security, ...) served by a separate MCP server, `jarvis-tools`. This repository has everything needed to run it on one AWS EC2 host:

| Path | What |
|---|---|
| `*.tf`, `scripts/cloud-init.yml` | Terraform for the host: a small dedicated VPC, the EC2 instance, the data volume and an empty Secrets Manager secret |
| [`hermes/`](hermes/README.md) | Hermes config, the agent persona (`SOUL.md`), the `jarvis_guard` plugin, systemd units and host scripts |
| `tools/` | `jarvis-tools`: the specialist MCP server (Python), domain contracts, example adapter skeletons, contract tests and specialist prompts |

This is a **template**: it ships no product integrations and names no security vendor. Each security domain has a
vendor-neutral contract and an `example` skeleton adapter that answers `not_implemented`; you implement and register an
adapter per domain for your own stack. The design follows the
[Agentic SOC reference architecture](https://github.com/odubdami429/Toolkit/tree/main/Agentic%20Engineering/Agentic%20SOC%20Architecture).

Nothing about an organisation, a product or a tenant is hardcoded. Organisation details (name, email domains, who may
act, Slack IDs), the adapter chosen for each domain and its URLs go in `hermes/managed/org.env`; Slack and Hermes
settings go in `hermes/managed/.env`; credentials go in the secret. Copy the `.example` files to get started.

## Architecture

```
Slack (Socket Mode) ──► jarvis-hermes container (UID 10000, no security-tool credentials)
                          ├─ main agent: SOUL.md + config.yaml (Anthropic model)
                          ├─ jarvis_guard plugin: requester/workspace checks, signing, Slack tools
                          └─ MCP over a private Docker bridge (bearer token + HMAC-signed jarvis_auth)
                               ▼
                        jarvis-tools container (UID 10001, holds the security-tool credentials)
                          ├─ ask_<domain>_specialist: one Claude tool-use loop per security domain
                          │     └─ domain tools (edr_*, idp_*, ...) ──► your adapter ──► product API
                          └─ direct reads: tickets, wiki, enterprise search
```

### Domains, contracts and adapters

Specialists are organised by security domain, never by product. Each domain has a fixed, vendor-neutral tool surface
(`edr_get_alert`, `idp_get_user`, `email_block_sender`, ...) specified in `tools/app/providers/<domain>/contract.py`,
and a vendor-neutral prompt. An *adapter* implements that contract for one product. You pick one adapter per domain in
`hermes/managed/org.env` (`EDR_PROVIDER=...`); leave it empty to disable the domain. A domain is live only when its
adapter, `<PREFIX>_BASE_URL` and credentials are all set; otherwise its tools say "not configured".

| Domain | Specialist | Tool prefix | Reads | Writes (authorized writers only) |
|---|---|---|---|---|
| EDR | `ask_edr_specialist` | `edr_` | alerts, backlog, device inventory, telemetry queries | close alert, hash/path allowlist, hash blocklist, network contain, full scan |
| Identity provider | `ask_idp_specialist` | `idp_` | users, groups, apps, sign-in/admin audit log | suspend/unsuspend, clear sessions |
| Productivity suite | `ask_suite_specialist` | `suite_` | directory, activity logs, current OAuth grants | revoke a grant, sign out |
| Email security | `ask_email_security_specialist` | `email_` | message search, raw message, platform analysis, action status | quarantine/trash/banner/restore, block sender |
| Brand protection | `ask_brand_protection_specialist` | `brand_` | alerts, URL scans | archive, mark taken down |
| Insider risk | `ask_insider_risk_specialist` | `irm_` | alerts, file events, sanctioned-AI entitlement (via the IdP) | close an alert with a disposition and note |
| Web research | `ask_web_research` | `web_` | public threat intel (Anthropic server-side search/fetch) | none |
| Ticketing / wiki | direct tools | `search_tickets`, `get_ticket_details`, `search_wiki`, `get_wiki_page_details` | tickets and wiki pages | none |
| Enterprise search | direct tools | `enterprise_` | internal docs and chat, as the requester | none |

Each contract documents its tools' return envelopes, the guardrails an implementation must enforce, the credential
scope it needs and, where the domain has one, its automatic-action policy for alert-bot posts.

### Implementing an adapter

1. Copy `tools/app/providers/<domain>/example.py` (and `example_write.py` for write actions) to `<name>.py` /
   `<name>_write.py` and implement each stub against your product's API, keeping the contract's tool names,
   parameters and return envelopes so the domain prompt works unchanged.
2. Register it in `DOMAINS` in `tools/app/providers/__init__.py`.
3. Make the contract tests pass: `tools/app/tests/test_contracts.py` (all domains) and
   `tools/app/tests/test_contract_<domain>.py` (domain rules).
4. Optionally add `tools/specialists/<domain>/providers/<name>.md` with product-specific prompt notes (query-language
   primer, ID and console-link formats, enum values). It is appended to the domain prompt at startup.
5. Put its credentials in the secret under the generic keys `<prefix>_api_token`, `<prefix>_username`,
   `<prefix>_client_id`, `<prefix>_client_secret`, `<prefix>_key_id`, `<prefix>_private_key` (they arrive in
   jarvis-tools as `<PREFIX>_API_TOKEN`, ..., `<PREFIX>_PRIVATE_KEY_B64`), then set `<PREFIX>_PROVIDER=<name>`,
   `<PREFIX>_BASE_URL` and `<PREFIX>_CONSOLE_URL` in `org.env`.

See [`hermes/README.md`](hermes/README.md#domains-and-adapters) for the full adapter interface.

Layout:

```
tools/app/server.py, specialist.py, org.py   MCP server, specialist loop, org settings
tools/app/providers/<domain>/contract.py     vendor-neutral domain contract
tools/app/providers/<domain>/example*.py     skeleton adapters (copy these)
tools/specialists/<domain>/prompt.md         vendor-neutral domain prompt
tools/specialists/<domain>/providers/*.md    optional adapter prompt addenda
tools/app/tests/                             contract and server tests
```

## Security model (summary)

- **Host:** no public IP, no key pair, no inbound rules, sshd disabled, HTTPS egress only through one NAT gateway
  (static IP for product and Slack token allowlists). IMDSv2 is required with hop limit 1, and containers can't reach
  `169.254.0.0/16`. Access is SSM Session Manager only.
- **Containers:** read-only root filesystems, `--cap-drop ALL`, `no-new-privileges`, non-root UIDs, pinned images.
- **Credential separation:** security-tool credentials go only to the jarvis-tools container. `jarvis-preflight` refuses to
  start Hermes if one shows up in its environment.
- **Who may ask:** only Slack users in `SLACK_ALLOWED_USERS`, only in the pinned workspace, only with an @-mention.
  Only users in `JARVIS_WRITERS` can trigger writes, and the server decides this from the guard-signed requester,
  never from model text. Writes are capped and audited, and the secret holds kill switches for them.
- **Alert bots:** an alert pipeline's bot (`JARVIS_TRIGGER_BOTS`) can start triage only in `JARVIS_BOT_CHANNELS`,
  under an hourly cap. Automatic actions apply only to alert IDs the guard reads from the bot's own unedited post.
- **Fail closed:** jarvis-tools refuses any call without a valid, fresh, unused `jarvis_auth` signature. A canary
  stops Hermes if the guard plugin didn't load before Slack connected.

See [`hermes/README.md`](hermes/README.md) for the details.

## Controls not in place yet

These are worth adding before relying on this in production:

- **Egress allowlist.** Any HTTPS destination is reachable through the NAT. A forward proxy or Route 53 DNS Firewall
  would stop a prompt-injected agent sending data anywhere. The hosts the deployment needs are listed below.
- **Secret isolation.** Everything is in one secret, read by the instance role. Use a customer-managed KMS key
  (`secret_kms_key_id`) with a key policy limited to the instance role and break-glass admins, and alert on
  `GetSecretValue` from anywhere else. Consider separate Anthropic keys for Hermes and the specialists.
- **Off-host audit trail.** The guard and jarvis-tools write JSON audit lines to journald on the host only. Ship them
  somewhere immutable (for example Vector to S3 Object Lock, or your SIEM).
- **Endpoint coverage and backups.** Add your runtime security sensor or vulnerability scanner, and AWS Backup
  snapshots of the data volume.

## Deploy

### 1. Infrastructure

```sh
cp backend.hcl.example backend.hcl            # S3 state location (or delete backend.tf for local state)
cp terraform.tfvars.example terraform.tfvars  # region, account guard, sizing, optional KMS key / boundary
terraform init -backend-config=backend.hcl
terraform apply
```

This creates:

- A VPC (default `10.251.0.0/24`, one AZ) with a public subnet for the NAT gateway and a private subnet for the host,
  plus VPC flow logs to CloudWatch.
- An AL2023 arm64 instance (default `t4g.large`) with Docker installed by cloud-init.
- A separate data volume mounted at `/var/lib/jarvis`. It holds HERMES_HOME and is kept when the instance is
  replaced.
- An empty secret (default `jarvis/prod/hermes`).

Session Manager logging is account-wide and isn't created here; point `ssm_session_log_group_name` at your existing
log group. Outputs: `instance_id`, `nat_public_ip` (the static egress IP), `secret_name` and `ssm_session_command`.

### 2. Slack app and secret

1. Create a Slack app from `hermes/slack-app-manifest.yaml`. Generate an app-level token with `connections:write`,
   install the app, and restrict token use to `nat_public_ip`.
2. Put the credentials in the secret as JSON. The key names are listed in `hermes/README.md` and checked by
   `hermes/bin/jarvis-secrets`. Never put secrets in SSM Run Command parameters: CloudTrail records them. Scripts on
   the host read the secret themselves.

   ```sh
   aws secretsmanager put-secret-value --secret-id jarvis/prod/hermes --secret-string file://jarvis-secret.json
   ```

### 3. Configure and install on the host

```sh
cp hermes/managed/org.env.example hermes/managed/org.env   # org identity, writers, alert bot, adapters and URLs
cp hermes/managed/.env.example    hermes/managed/.env      # Slack allowlist, workspace, channels, Hermes pins
# copy the repo to the host (SSM), then as root:
sudo hermes/install.sh
sudo systemctl start jarvis-hermes                         # also starts jarvis-tools
```

`install.sh` renders `SOUL.md` from `org.env`, builds the `jarvis-tools` image, and installs the systemd units. It
doesn't start anything. Hermes isn't in cloud-init, because changing `user_data` replaces the instance. After
`terraform apply -replace` (for example to pick up a new AMI), rerun `install.sh` and start the units again.

## Egress the host needs

Use these for an egress allowlist and for product IP allowlists (with `nat_public_ip`):

- Slack: `slack.com`, `wss-*.slack.com` (Socket Mode). Anthropic: `api.anthropic.com` (web search and fetch run on
  Anthropic's side).
- Docker Hub for the Hermes and Python base images (`registry-1.docker.io`, `auth.docker.io`,
  `production.cloudflare.docker.com`) or an ECR mirror; PyPI (`pypi.org`, `files.pythonhosted.org`) when building
  jarvis-tools.
- AWS APIs: Secrets Manager, SSM, `ssmmessages`, `ec2messages`, CloudWatch Logs.
- Each enabled adapter's API hosts: the `<PREFIX>_BASE_URL` values in `org.env`, plus any fixed endpoints your
  adapter calls (token endpoints, regional API hosts); document them in the adapter.

## Tests

```sh
python -m pytest -q hermes/tests                       # guard plugin (stdlib + pytest)
# jarvis-tools, including the contract tests every adapter must pass
docker build -t jarvis-tools:local tools && \
  docker run --rm --entrypoint sh -e HOME=/tmp jarvis-tools:local \
    -c 'cd /app && pip install -q --user pytest && python -m pytest -q'
```

## Cost

At list price in us-east-1, it costs roughly $90/month while running: the NAT gateway is about $33 plus data, a
`t4g.large` about $49, and EIP, EBS, the secret and logs about $10. Stopping the instance saves the instance cost;
the NAT gateway keeps billing.

## Teardown

`terraform destroy` removes everything, including the data volume (Hermes sessions and state). Snapshot it first
if you need it.
