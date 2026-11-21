"""Tests for the specialist loop's web-query screen. A scripted fake stands in for the model API."""

from __future__ import annotations

import json
import logging
import os
from types import SimpleNamespace as NS

os.environ.setdefault("ANTHROPIC_API_KEY", "test-key")

import pytest  # noqa: E402

import specialist as sp  # noqa: E402


@pytest.mark.parametrize("query,reason", [
    ("pat.example@acme.example breach", "org_email"),
    ("ops@acme-mail.example inbox", "org_email"),
    ("SEC-1234 phishing kit", "ticket_key"),
    ("ABC-9067 lookalike", "ticket_key"),
    ("build-07.corp exposed", "internal_host"),
    ("C1Q7MD3QVL malware", "serial_like"),
])
def test_fixed_patterns_flag(query, reason):
    assert reason in sp.screen_web_query(query, set())


@pytest.mark.parametrize("env_name", [
    f"{d.env_prefix}_{suffix}" for d in sp.providers.DOMAINS.values() for suffix in ("BASE_URL", "CONSOLE_URL")
    if os.environ.get(f"{d.env_prefix}_{suffix}")])
def test_configured_tenant_hosts_flag(env_name):
    host = os.environ[env_name].split("//", 1)[1]
    assert host in sp._TENANT_HOSTS
    assert "internal_host" in sp.screen_web_query(f"{host} login page", set())


def test_tenant_hosts_cover_every_domain_and_skip_bad_values(monkeypatch):
    monkeypatch.setenv("EDR_BASE_URL", "http://not-https.example/path")
    monkeypatch.setenv("TICKETING_CONSOLE_URL", "https://wiki-console.acme-tenant.example")
    monkeypatch.delenv("IDP_BASE_URL")
    hosts = sp._tenant_hosts()
    assert "wiki-console.acme-tenant.example" in hosts
    assert "not-https.example" not in hosts and all(hosts)


@pytest.mark.parametrize("query", [
    "acme-careers-login.com whois", "CVE-2026-12345 exploit", "SHA-256 of mimikatz",
    "44d88612fea8a8f36de82e1278abb02f hash reputation", "site:acme.example jobs", "acme.link.example/abc redirect", "RFC-5322 header",
    "Wile Coyote linkedin impersonation", "",
])
def test_public_queries_pass(query):
    assert sp.screen_web_query(query, set()) == []


def test_token_only_seen_internally_is_flagged():
    internal_only = sp._tokens("Vendor acme-payroll.net onboarded per SEC-9; contact ops@acme-payroll.net")
    assert sp.screen_web_query("acme-payroll.net reputation", internal_only) == [
        "from_internal_result:acme-payroll.net"]


def test_tokens_skip_dates_versions_and_common_sites():
    assert sp._tokens("2026-11-17 v1.2 10.5 virustotal.com acme.example acme.link.example word") == {"v1.2"}


# --- the loop -------------------------------------------------------------------------------------------------------

def _resp(content, stop):
    return NS(content=content, stop_reason=stop, model="claude-opus-5-5",
              usage=NS(input_tokens=1, output_tokens=1, cache_read_input_tokens=0, cache_creation_input_tokens=0))


class FakeClient:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.beta = NS(messages=NS(create=lambda **kw: next(self.responses)))


def test_loop_flags_internal_token_in_web_query(monkeypatch, caplog):
    responses = [
        _resp([NS(type="tool_use", id="t1", name="search_tickets", input={"query": "text ~ acme-careers-login.com"}),
               NS(type="tool_use", id="t2", name="brand_get_alert", input={"alert_id": "ABC-1"})], "tool_use"),
        _resp([NS(type="server_tool_use", id="w1", name="web_search", input={"query": "acme-payroll.net phishing"}),
               NS(type="web_search_tool_result", tool_use_id="w1", content=[{"url": "https://news.example/x"}]),
               NS(type="server_tool_use", id="w2", name="web_search",
                  input={"query": "acme-careers-login.com whois"}),
               NS(type="server_tool_use", id="w3", name="web_search", input={"query": "registrar-x.biz abuse"}),
               NS(type="text", text="Done.")], "end_turn"),
    ]
    monkeypatch.setattr(sp, "_client", FakeClient(responses))

    def run_tool(name, args):
        if name == "search_tickets":  # internal: mentions the brief's domain plus an internal-only vendor
            return {"status": "ok", "issues": "acme-careers-login.com seen before; vendor acme-payroll.net onboarded"}
        return {"status": "ok", "entity_content": {"registrar": "registrar-x.biz"}}

    spec = sp.Specialist(key="brand_protection", title="Brand protection", prompt="p", tools=[], run_tool=run_tool,
                         internal_tools=frozenset({"search_tickets"}))
    with caplog.at_level(logging.INFO, logger="jarvis_tools"):
        out = sp.run_specialist(spec, "review acme-careers-login.com", "", "U00000000A1", "req1")
    assert out == "Done."
    lines = [json.loads(r.getMessage()) for r in caplog.records if r.getMessage().startswith("{")]
    web = {line["args"]["query"]: line.get("possible_internal") for line in lines if line["jarvis_tools"] == "web_call"}
    assert web == {"acme-payroll.net phishing": ["from_internal_result:acme-payroll.net"],
                   "acme-careers-login.com whois": None,   # in the brief: public
                   "registrar-x.biz abuse": None}          # from a vendor result: not internal
    done = next(line for line in lines if line["jarvis_tools"] == "specialist_done")
    assert done["web_flagged"] == 1 and done["tool_calls"] == 2
    # Every domain tool call is audited as tool_call, with its status.
    calls = [(line["tool"], line["status"]) for line in lines if line["jarvis_tools"] == "tool_call"]
    assert calls == [("search_tickets", "ok"), ("brand_get_alert", "ok")]
    assert not [line for line in lines if line["jarvis_tools"] not in (
        "tool_call", "web_call", "specialist_turn", "specialist_done")]
