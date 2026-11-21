# Specialist prompts

Each folder here holds the system prompt for one Jarvis specialist, named for what it does (`edr`, `idp`,
`productivity_suite`, `email_security`, `brand_protection`, `insider_risk`, `web_research`), never for a product.

## How a prompt is composed

The server (`tools/app/server.py`) builds a specialist's system prompt at startup from:

1. `<domain>/prompt.md`: the vendor-neutral domain prompt. It is written against the domain contract in
   `tools/app/providers/<domain>/contract.py`: the tool names, parameters, enum values, return fields and statuses
   it relies on all come from there.
2. `<domain>/providers/<adapter>.md` (optional): an addendum for the configured adapter (`<PREFIX>_PROVIDER` in
   `org.env`). If the file exists, it is appended after the domain prompt; if not, the domain prompt stands alone.

Both files are rendered with `{{NAME}}` placeholders from `tools/app/org.py`. The allowed names are `ORG_NAME`,
`ORG_EMAIL_DOMAIN`, `ORG_EMAIL_DOMAINS`, `ORG_DOMAINS`, `ORG_SECURITY_TEAM` and `ALERT_BOT_NAME`. An unknown
placeholder fails at startup.

## What belongs where

The domain prompt holds the policy: workflow, gates, thresholds, automatic-action rules, output formats. It must
contain no product or vendor names, and every tool name, parameter, enum value and return field it mentions must
exist in the domain contract.

An adapter documents product-specific details in its tool descriptions first (the contracts' `with_primer` puts a
query-language primer into `edr_query`, `search_tickets` and `search_wiki`). An addendum is for whatever the model
still needs that doesn't fit there:

- query-language syntax and worked examples of the standard queries;
- ID and console-link formats;
- how the product's own values map onto the contract's neutral enums (states, verdicts, severities, event names);
- product limits, such as telemetry or audit-log retention.

An addendum never changes policy. It can't relax a gate, a threshold or an automatic-action rule: those stay in the
domain prompt and in the contract's guardrails.

This repository ships no addenda. Don't create a `providers/` folder here unless you're adding a real addendum,
because the server treats any `<adapter>.md` file in that folder as one.
