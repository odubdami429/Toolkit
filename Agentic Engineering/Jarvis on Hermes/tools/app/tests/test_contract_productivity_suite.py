"""Contract tests for the productivity suite domain: the contract's tool surface and the example adapters' validation."""

from __future__ import annotations

import json
import os

import pytest

import providers
from providers.productivity_suite import contract as c
from providers.productivity_suite import example as ex
from providers.productivity_suite import example_write as exw

REQ = "jane.doe@acme.example (U00000000A1)"
# Banned vendor words, stored reversed so this file never contains them.
BANNED = [w[::-1] for w in ("lenitnes", "atko", "swg", "liamg", "emilbus", "leppod", "24edoc", "rdycni", "naissalta",
                            "arij", "ecneulfnoc", "naelg", "looter", "elgoog")]
ALL = c.TOOLS + c.LIST_TOOLS + c.WRITE_TOOLS
GARBAGE = [None, "x", 1, [], [{"user": "a"}], {"user": None}, {"user": ["a@acme.example", "b@acme.example"]},
           {"user": {"x": 1}}, {"user": True}, {"application": 5}, {"lookback_hours": "soon"}]


@pytest.fixture()
def client():
    cl = ex.client_from_env(os.environ)
    assert cl is not None
    return cl


@pytest.fixture()
def writer(client):
    w = exw.writer_from_env(os.environ, client)
    assert w is not None
    return w


# --- surface ---------------------------------------------------------------------------------------------------------

def test_registry_loads_the_example_adapters():
    ad = providers.load("productivity_suite")
    assert ad.read is ex and ad.write is exw and not ad.can_auto_act
    assert not hasattr(exw, "auto_check")


def test_tool_names_prefixed_unique_and_as_specified():
    names = [t["name"] for t in ALL]
    assert len(names) == len(set(names))
    assert all(n.startswith(c.TOOL_PREFIX) for n in names)
    assert c.TOOL_NAMES == {"suite_get_user", "suite_search_activity"}
    assert c.LIST_TOOL_NAMES == {"suite_list_tokens"}
    assert c.WRITE_TOOL_NAMES == {"suite_revoke_token", "suite_sign_out_user"}
    assert ex.TOOLS is c.TOOLS and exw.WRITE_TOOLS is c.WRITE_TOOLS and exw.LIST_TOOLS is c.LIST_TOOLS


@pytest.mark.parametrize("t", ALL, ids=lambda t: t["name"])
def test_schemas_are_valid_objects(t):
    s = t["input_schema"]
    assert s["type"] == "object" and isinstance(s["properties"], dict)
    assert set(s.get("required", [])) <= set(s["properties"])
    assert isinstance(t["description"], str) and len(t["description"]) > 40
    for p in s["properties"].values():
        assert "type" in p or "anyOf" in p


def test_no_vendor_words_in_the_surface():
    blob = json.dumps(ALL).lower() + (c.__doc__ or "").lower() + (ex.__doc__ or "").lower()
    for w in BANNED:
        assert w not in blob, w


def test_required_params():
    req = {t["name"]: set(t["input_schema"].get("required", [])) for t in ALL}
    assert req == {"suite_get_user": {"user"}, "suite_search_activity": {"application"}, "suite_list_tokens": {"user"},
                   "suite_revoke_token": {"user", "client_id", "reason"}, "suite_sign_out_user": {"user", "reason"}}


# --- client ----------------------------------------------------------------------------------------------------------

def test_client_from_env():
    assert ex.client_from_env({}) is None
    assert ex.client_from_env({"SUITE_BASE_URL": "https://suite.example.test"}) is None
    assert ex.client_from_env({"SUITE_API_TOKEN": "t" * 10}) is None
    assert ex.client_from_env({"SUITE_BASE_URL": "http://suite.example.test", "SUITE_API_TOKEN": "t" * 10}) is None
    assert ex.client_from_env({"SUITE_BASE_URL": "https://suite.example.test", "SUITE_CLIENT_ID": "id"}) is None
    cl = ex.client_from_env({"SUITE_BASE_URL": "https://suite.example.test", "SUITE_CLIENT_ID": "id",
                             "SUITE_CLIENT_SECRET": "very-secret-value"})
    assert cl is not None and "very-secret-value" not in repr(cl) and "very-secret-value" in cl._secrets_for_scrub()
    assert exw.writer_from_env(os.environ, None) is None


# --- reads never raise -----------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", sorted(c.TOOL_NAMES) + ["nope", None, 3])
def test_run_tool_always_returns_a_status(client, name):
    for args in GARBAGE + [{}]:
        out = ex.run_tool(client, name, args)
        assert isinstance(out, dict) and out.get("status")
        json.dumps(out)
    assert ex.run_tool(client, "nope", {})["status"] == "error"


def test_valid_reads_are_not_implemented(client):
    out = ex.run_tool(client, "suite_get_user", {"user": "Jane Doe"})
    assert out["status"] == "not_implemented" and "never invent" in out["next_step"]
    assert out["validated"]["by"] == "name"
    out = ex.run_tool(client, "suite_get_user", {"user": "<mailto:jane.doe@acme.example|jane.doe@acme.example>"})
    assert out["status"] == "not_implemented" and out["validated"] == {"by": "email", "input": "jane.doe@acme.example"}
    out = ex.run_tool(client, "suite_search_activity", {"application": "oauth", "user": "jane.doe@acme.example",
                                                        "lookback_hours": 99999, "event_name": "authorize"})
    assert out["status"] == "not_implemented"
    v = out["validated"]
    assert v["application"] == "token" and v["lookback_hours"] == c.MAX_LOOKBACK_H and v["lookback_clamped"]
    assert ex.run_tool(None, "suite_get_user", {"user": "jane.doe@acme.example"})["status"] == "error"


@pytest.mark.parametrize("args", [
    {"user": "test"}, {"user": "jane@"}, {"user": "a b c d e"}, {"user": "O'Brien"}, {"user": "x" * 300},
    {"user": "jane+1@acme.example"}, {"user": ["a@acme.example"]},
])
def test_get_user_rejects(client, args):
    assert ex.run_tool(client, "suite_get_user", args)["status"] == "invalid_input"


@pytest.mark.parametrize("args", [
    {}, {"application": "bogus"}, {"application": "login", "since": "2026-01-01"},
    {"application": "login", "user": "jane.doe@acme.example", "lookback_hours": 5, "until_hours_ago": 5},
    {"application": "login", "user": "Jane Doe"},
    {"application": "login", "user": "jane.doe@acme.example", "event_name": "a,b"},
    {"application": "login", "user": "jane.doe@acme.example", "event_name": ["a", "b"]},
    {"application": "login", "user": "jane.doe@acme.example", "ip": "10.0.0.0/8"},
    {"application": "login", "user": "jane.doe@acme.example", "filters": "visibility<>private"},
    {"application": "login", "user": "jane.doe@acme.example", "filters": [{"parameter": "Bad Name", "value": "x"}]},
    {"application": "login", "user": "jane.doe@acme.example", "filters": [{"parameter": "a", "operator": "~",
                                                                            "value": "x"}]},
    {"application": "login", "user": "jane.doe@acme.example", "filters": [{"parameter": "a", "value": "x,y"}]},
    {"application": "login", "user": "jane.doe@acme.example", "filters": {f"p{i}": "v" for i in range(6)}},
    {"application": "login", "lookback_hours": 48},  # org-wide, unscoped, > 24 h
])
def test_search_activity_rejects(client, args):
    assert ex.run_tool(client, "suite_search_activity", args)["status"] == "invalid_input"


def test_search_activity_org_wide_rules(client):
    ok = ex.run_tool(client, "suite_search_activity", {"application": "login", "lookback_hours": 24})
    assert ok["status"] == "not_implemented" and ok["validated"]["user"] == "all"
    ok = ex.run_tool(client, "suite_search_activity", {"application": "login", "user": "all", "lookback_hours": 168,
                                                       "event_name": "suspicious_login", "ip": "203.0.113.9",
                                                       "filters": {"login_type": "saml"}, "max_events": 500})
    assert ok["status"] == "not_implemented"
    assert ok["validated"]["max_events"] == c.MAX_EVENTS and ok["validated"]["filters"][0]["operator"] == "=="


# --- writes ----------------------------------------------------------------------------------------------------------

REVOKE = {"user": "jane.doe@acme.example", "client_id": "1234567890.apps.example", "reason": "Ticket SEC-1: "
          "unapproved app with mail read scope"}
SIGN_OUT = {"user": "jane.doe@acme.example", "reason": "Ticket SEC-2: suspected session theft from a new ASN"}


@pytest.mark.parametrize("name,args", [("suite_revoke_token", REVOKE), ("suite_sign_out_user", SIGN_OUT)])
def test_writes_refuse_without_requester(writer, name, args):
    for req in ("", None, "   "):
        out = exw.run_write_tool(writer, name, args, req)
        assert out["status"] == "refused" and out["written"] is False


@pytest.mark.parametrize("name", sorted(c.WRITE_TOOL_NAMES | c.LIST_TOOL_NAMES) + ["nope"])
def test_run_write_tool_never_raises(writer, name):
    for args in GARBAGE + [{}]:
        for req in ("", REQ):
            out = exw.run_write_tool(writer, name, args, req)
            assert isinstance(out, dict) and out.get("status")
            if name in c.WRITE_TOOL_NAMES:
                assert out["written"] in (False, None)


def test_valid_writes_are_not_implemented_and_record_the_requester(writer):
    out = exw.run_write_tool(writer, "suite_revoke_token", {**REVOKE, "requested_by": "someone else"}, REQ)
    assert out["status"] == "not_implemented" and out["written"] is False
    assert out["requested_by"] == REQ and out["reason"] == REVOKE["reason"]
    out = exw.run_write_tool(writer, "suite_sign_out_user", SIGN_OUT, REQ)
    assert out["status"] == "not_implemented" and out["requested_by"] == REQ
    out = exw.run_write_tool(writer, "suite_list_tokens", {"user": "jane.doe@acme.example"}, "")
    assert out["status"] == "not_implemented"


@pytest.mark.parametrize("args", [
    {**REVOKE, "reason": "too short"}, {**REVOKE, "reason": "as requested by the analyst in the thread"},
    {**REVOKE, "client_id": ""}, {**REVOKE, "client_id": ["a", "b"]}, {**REVOKE, "client_id": "a/b?c"},
    {**REVOKE, "user": "Jane Doe"}, {**REVOKE, "user": ["jane.doe@acme.example"]},
])
def test_revoke_rejects(writer, args):
    assert exw.run_write_tool(writer, "suite_revoke_token", args, REQ)["status"] == "invalid_input"


def test_service_accounts_and_org_wide_apps_are_refused(client):
    w = exw.writer_from_env({"SUITE_ORG_WIDE_APPS": "Enterprise Indexer, sec-tool-client"}, client)
    for user in ("svc-backup@acme.example", "service.sync@acme.example", "SVC_x@acme.example"):
        assert exw.run_write_tool(w, "suite_sign_out_user", {**SIGN_OUT, "user": user}, REQ)["status"] == "refused"
        assert exw.run_write_tool(w, "suite_revoke_token", {**REVOKE, "user": user}, REQ)["status"] == "refused"
    assert exw.run_write_tool(w, "suite_sign_out_user", {**SIGN_OUT, "user": "service@acme.example"},
                              REQ)["status"] == "not_implemented"
    for app in ("enterprise indexer", "SEC-TOOL-CLIENT"):
        out = exw.run_write_tool(w, "suite_revoke_token", {**REVOKE, "client_id": app}, REQ)
        assert out["status"] == "refused" and out["written"] is False


def test_sign_out_rejects(writer):
    assert exw.run_write_tool(writer, "suite_sign_out_user", {"user": "jane.doe@acme.example"},
                              REQ)["status"] == "invalid_input"
    assert exw.run_write_tool(writer, "suite_sign_out_user", "nope", REQ)["status"] == "invalid_input"
