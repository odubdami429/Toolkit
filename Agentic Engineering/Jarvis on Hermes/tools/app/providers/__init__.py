"""Provider registry: security domains on the left, vendor adapters on the right.

Jarvis's specialists are named for what they do (EDR, identity provider, email security, ...), never for a vendor.
Each domain has a small, fixed tool surface (`edr_get_alert`, `idp_get_user`, ...) defined in
`providers/<domain>/contract.py`; the domain prompt is written against it. A *provider* is an adapter module that
implements that contract for one product. This repository ships only `example` skeleton adapters (they validate
input and return `not_implemented`); write your own adapter per domain, register it here, and select it in
`org.env`:

    EDR_PROVIDER=your_edr             # empty or "none" disables the domain

Adding a provider: copy `providers/<domain>/example.py` (and `example_write.py`) to `providers/<domain>/<name>.py`,
implement the stubs against your product's API, register it in `DOMAINS`, make `tests/test_contracts.py` pass for it,
and optionally add `tools/specialists/<domain>/providers/<name>.md` with product-specific prompt notes (query-language
primer, ID formats, console links).

Read module interface (required):
    TOOLS: list[dict]                       the contract's tool definitions (names prefixed with the domain's prefix)
    TOOL_NAMES: frozenset[str]
    client_from_env(env) -> client | None   None when the tenant or credentials aren't configured
    run_tool(client, name, args, **ctx) -> dict   never raises; always a dict with "status"

Write module interface (optional; the domain is read-only without one):
    WRITE_TOOLS: list[dict]
    LIST_TOOLS: list[dict]                  reads that need the writer's credential (offered to every requester)
    writer_from_env(env, client) -> writer | None
    run_write_tool(writer, name, args, requester) -> dict   never raises

Automatic actions on alert-bot posts (optional, in the write module):
    AUTO_ID_PATTERN: re.Pattern             finds alert IDs in console links in the alert bot's post (group 1 = ID)
    AUTO_ID_SHAPE: re.Pattern               fullmatch validator for one ID
    AUTO_NOTE: str                          brief line; the server appends the eligible IDs
    auto_tools() -> list[dict]              WRITE_TOOLS as offered on alert-bot requests (automatic-only wording)
    auto_check(name, args, allowed) -> (keys | None, reason | None)
                                            keys: one dedupe key per alert acted on, e.g. ["edr|close|123"]
    auto_requester(actor) -> str            the requester string passed to run_write_tool for automatic actions
"""

from __future__ import annotations

import importlib
import os
from dataclasses import dataclass
from types import ModuleType
from typing import Any, Mapping


@dataclass(frozen=True)
class Domain:
    key: str                  # also the prompt folder: tools/specialists/<key>/
    env_prefix: str           # <PREFIX>_PROVIDER, <PREFIX>_BASE_URL, ...
    title: str                # human name used in replies ("*Specialists used:* EDR, Identity provider")
    tool_prefix: str          # model-facing tool names start with this
    providers: Mapping[str, tuple[str, str | None]]  # provider -> (read module, write module or None)


DOMAINS: dict[str, Domain] = {d.key: d for d in (
    Domain("edr", "EDR", "EDR", "edr_", {"example": ("providers.edr.example", "providers.edr.example_write")}),
    Domain("idp", "IDP", "Identity provider", "idp_", {"example": ("providers.idp.example", "providers.idp.example_write")}),
    Domain("productivity_suite", "SUITE", "Productivity suite", "suite_", {"example": ("providers.productivity_suite.example", "providers.productivity_suite.example_write")}),
    Domain("email_security", "EMAIL_SECURITY", "Email security", "email_", {"example": ("providers.email_security.example", "providers.email_security.example_write")}),
    Domain("brand_protection", "BRAND_PROTECTION", "Brand protection", "brand_", {"example": ("providers.brand_protection.example", "providers.brand_protection.example_write")}),
    Domain("insider_risk", "INSIDER_RISK", "Insider risk", "irm_", {"example": ("providers.insider_risk.example", "providers.insider_risk.example_write")}),
    Domain("ticketing", "TICKETING", "Ticketing and wiki", "", {"example": ("providers.ticketing.example", None)}),
    Domain("enterprise_search", "ENTERPRISE_SEARCH", "Enterprise search", "enterprise_", {"example": ("providers.enterprise_search.example", None)}),
)}


@dataclass(frozen=True)
class Adapter:
    domain: Domain
    provider: str
    read: ModuleType
    write: ModuleType | None

    @property
    def can_auto_act(self) -> bool:
        return self.write is not None and hasattr(self.write, "auto_check")


def provider_name(domain: str, env: Mapping[str, str] | None = None) -> str:
    """The configured provider for a domain, or "" when the domain is disabled. Raises on an unknown provider, so a
    typo fails at startup instead of silently disabling a domain."""
    d = DOMAINS[domain]
    raw = str((os.environ if env is None else env).get(f"{d.env_prefix}_PROVIDER", "")).strip().lower()
    if raw in ("", "none", "off", "disabled"):
        return ""
    if raw not in d.providers:
        raise ValueError(f"{d.env_prefix}_PROVIDER={raw!r} is not a known {domain} provider "
                         f"(known: {', '.join(sorted(d.providers))})")
    return raw


def load(domain: str, env: Mapping[str, str] | None = None) -> Adapter | None:
    """The adapter configured for a domain, or None when the domain is disabled."""
    name = provider_name(domain, env)
    if not name:
        return None
    read_mod, write_mod = DOMAINS[domain].providers[name]
    return Adapter(DOMAINS[domain], name, importlib.import_module(read_mod),
                   importlib.import_module(write_mod) if write_mod else None)


def describe(env: Mapping[str, str] | None = None) -> dict[str, Any]:
    """{domain: provider or None} for the startup log."""
    return {k: (provider_name(k, env) or None) for k in DOMAINS}
