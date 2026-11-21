"""Deployment-specific settings for jarvis-tools, read once from the environment at import.

Nothing about the organisation or a vendor tenant is hardcoded in the vendor modules: they read it from here. The
values come from `hermes/managed/org.env` (see `org.env.example`), which systemd passes to both containers with
`--env-file`. Vendor base URLs are fixed at startup and never taken from model input.

Prompt placeholders: specialist prompts (and SOUL.md, rendered by install.sh) may contain `{{NAME}}` placeholders,
filled by `render()`. An unknown placeholder is an error, so a typo fails at startup instead of reaching the model.
"""

from __future__ import annotations

import os
import re
from typing import Mapping
from urllib.parse import urlsplit


def _csv(value: str) -> tuple[str, ...]:
    return tuple(v.strip() for v in (value or "").split(",") if v.strip())


def _env(name: str, default: str = "", env: Mapping[str, str] | None = None) -> str:
    return str((os.environ if env is None else env).get(name, default)).strip()


def base_url(name: str, default: str = "", env: Mapping[str, str] | None = None) -> str:
    """An https origin (no path, query or credentials) from the environment, or "" if unset. Raises on a bad value,
    so a misconfigured tenant fails at startup."""
    raw = _env(name, default, env).rstrip("/")
    if not raw:
        return ""
    parts = urlsplit(raw)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password \
            or parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError(f"{name} must be a bare https origin such as https://tenant.example.com (got {raw!r})")
    return f"https://{parts.netloc}"


# --- Organisation ------------------------------------------------------------------------------------------------

#: Display name used in prompts and messages ("Search {ORG_NAME}'s internal knowledge").
ORG_NAME = _env("ORG_NAME", "Example Corp")
#: Work email domains, primary first. The primary one is the only domain a requester email may have (enterprise search acts as the requester).
ORG_EMAIL_DOMAINS = tuple(d.lower().lstrip("@") for d in _csv(_env("ORG_EMAIL_DOMAINS", "example.com")))
ORG_EMAIL_DOMAIN = ORG_EMAIL_DOMAINS[0] if ORG_EMAIL_DOMAINS else "example.com"
#: All of the organisation's own domains (email domains plus web hosts such as a link shortener): never "external",
#: never sent to a third-party scanner.
ORG_DOMAINS = tuple(dict.fromkeys(ORG_EMAIL_DOMAINS + tuple(
    d.lower() for d in _csv(_env("ORG_EXTRA_DOMAINS")))))
#: Name of the team that owns Jarvis, used in messages ("Escalate to the Security team").
ORG_SECURITY_TEAM = _env("ORG_SECURITY_TEAM", "Security")

# --- Who may act -------------------------------------------------------------------------------------------------

#: Slack user IDs allowed to have Jarvis take vendor actions (and create channels). Empty means nobody.
WRITERS = frozenset(_csv(_env("JARVIS_WRITERS")))
#: Slack bot user IDs of the alert pipeline that may start triage turns (and get automatic actions).
TRIGGER_BOTS = frozenset(_csv(_env("JARVIS_TRIGGER_BOTS")))
#: Human-readable name of the alert pipeline, for briefs ("started by the alert bot").
ALERT_BOT_NAME = _env("JARVIS_ALERT_BOT_NAME", "alert bot")
#: The generative-AI tools the organisation sanctions (names and their web domains), granted through the
#: SANCTIONED_AI_GROUPS identity-provider groups. Used by the insider-risk prompt.
SANCTIONED_AI_TOOLS = _env("SANCTIONED_AI_TOOLS", "none configured")

# --- Prompt rendering --------------------------------------------------------------------------------------------

_PLACEHOLDER = re.compile(r"\{\{\s*([A-Z][A-Z0-9_]*)\s*\}\}")


def placeholders() -> dict[str, str]:
    return {
        "ORG_NAME": ORG_NAME,
        "ORG_EMAIL_DOMAIN": ORG_EMAIL_DOMAIN,
        "ORG_EMAIL_DOMAINS": ", ".join(ORG_EMAIL_DOMAINS),
        "ORG_DOMAINS": ", ".join(ORG_DOMAINS),
        "ORG_SECURITY_TEAM": ORG_SECURITY_TEAM,
        "ALERT_BOT_NAME": ALERT_BOT_NAME,
        "SANCTIONED_AI_TOOLS": SANCTIONED_AI_TOOLS,
    }


def render(text: str, values: Mapping[str, str] | None = None) -> str:
    """Fill `{{NAME}}` placeholders. Raises KeyError on an unknown name."""
    vals = placeholders() if values is None else values

    def sub(m: re.Match) -> str:
        name = m.group(1)
        if name not in vals:
            raise KeyError(f"unknown prompt placeholder {{{{{name}}}}}")
        return vals[name]

    return _PLACEHOLDER.sub(sub, text)


def is_org_email(email: str) -> bool:
    """True for name@<primary work domain> exactly (no subdomains, no lookalikes)."""
    e = (email or "").strip().lower()
    return bool(re.fullmatch(r"[a-z0-9._%+'-]+@" + re.escape(ORG_EMAIL_DOMAIN), e, re.ASCII))


def is_org_domain(host: str) -> bool:
    """True if host is one of the organisation's domains or a subdomain of one."""
    h = (host or "").strip().lower().rstrip(".")
    return any(h == d or h.endswith("." + d) for d in ORG_DOMAINS)
