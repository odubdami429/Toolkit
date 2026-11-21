"""Test settings. org.py and the provider adapters read the environment at import, so set it before any test module
imports them. Values are fictional (the reserved .example TLD for the organisation; made-up tenants on the reserved .test TLD)."""

import os
import sys
from pathlib import Path

# Tests live in app/tests/; the code they test is in app/ (server.py, org.py, providers/).
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

TEST_ENV = {
    # Organisation
    "ORG_NAME": "Acme Corp",
    "ORG_EMAIL_DOMAINS": "acme.example,acme-mail.example",
    "ORG_EXTRA_DOMAINS": "acme.link.example",
    "ORG_SECURITY_TEAM": "Security",
    "JARVIS_WRITERS": "U00000000A1,U00000000A2,U00000000A3",
    "JARVIS_TRIGGER_BOTS": "U00000000B1",
    "JARVIS_ALERT_BOT_NAME": "alert bot",
    # Providers: every domain uses the example skeleton adapter with fictional tenants
    "EDR_PROVIDER": "example",
    "EDR_BASE_URL": "https://edr.example.test",
    "EDR_CONSOLE_URL": "https://console.edr.example.test",
    "EDR_API_TOKEN": "test-edr-token",
    "IDP_PROVIDER": "example",
    "IDP_BASE_URL": "https://idp.example.test",
    "IDP_CONSOLE_URL": "https://console.idp.example.test",
    "IDP_API_TOKEN": "test-idp-token",
    "SUITE_PROVIDER": "example",
    "SUITE_BASE_URL": "https://suite.example.test",
    "SUITE_CONSOLE_URL": "https://console.suite.example.test",
    "SUITE_API_TOKEN": "test-suite-token",
    "EMAIL_SECURITY_PROVIDER": "example",
    "EMAIL_SECURITY_BASE_URL": "https://email.example.test",
    "EMAIL_SECURITY_CONSOLE_URL": "https://console.email.example.test",
    "EMAIL_SECURITY_API_TOKEN": "test-email-token",
    "BRAND_PROTECTION_PROVIDER": "example",
    "BRAND_PROTECTION_BASE_URL": "https://brand.example.test",
    "BRAND_PROTECTION_CONSOLE_URL": "https://console.brand.example.test",
    "BRAND_PROTECTION_API_TOKEN": "test-brand-token",
    "INSIDER_RISK_PROVIDER": "example",
    "INSIDER_RISK_BASE_URL": "https://irm.example.test",
    "INSIDER_RISK_CONSOLE_URL": "https://console.irm.example.test",
    "INSIDER_RISK_API_TOKEN": "test-irm-token",
    "TICKETING_PROVIDER": "example",
    "TICKETING_BASE_URL": "https://tickets.example.test",
    "TICKETING_CONSOLE_URL": "https://console.tickets.example.test",
    "TICKETING_API_TOKEN": "test-tickets-token",
    "ENTERPRISE_SEARCH_PROVIDER": "example",
    "ENTERPRISE_SEARCH_BASE_URL": "https://search.example.test",
    "ENTERPRISE_SEARCH_CONSOLE_URL": "https://console.search.example.test",
    "ENTERPRISE_SEARCH_API_TOKEN": "test-search-token",
    "SANCTIONED_AI_GROUPS": "ai-assistant-users,ai-platform-users",
    "SANCTIONED_AI_TOOLS": "Example AI Assistant (assistant.example.net)",
    # Per-boot keys
    "JARVIS_TOOLS_TOKEN": "test-tools-token",
    "JARVIS_GUARD_HMAC_KEY": "test-hmac-key",
}
os.environ.update(TEST_ENV)
