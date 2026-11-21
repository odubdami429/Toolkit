"""Identity-provider domain: contract shape, user_groups, and the example adapter's validation."""

import codecs
import json
import os
import re

import pytest

from providers import DOMAINS
from providers.idp import contract
from providers.idp import example as ex
from providers.idp import example_write as exw
from providers.insider_risk import ai_entitlement

BANNED = [codecs.decode(w, "rot13") for w in (
    "fragvarybar", "fragvary", "bxgn", "tbbtyr", "tjf", "fhoyvzr", "qbccry", "pbqr42", "vaplqe", "ngynffvna", "wven",
    "wdy", "pbasyhrapr", "pdy", "tyrna", "cbjredhrel", "qrrc ivfvovyvgl", "fqy", "fgbelyvar", "zdy", "ergbby",
    "pebjqfgevxr", "qrsraqre", "f1")]
REQ = "analyst@acme.example (U00000000A1)"
REASON = "Suspected account takeover, alert 123, ticket SEC-42."


@pytest.fixture(scope="module")
def client():
    c = ex.client_from_env(os.environ)
    assert c is not None
    return c


@pytest.fixture(scope="module")
def writer(client):
    w = exw.writer_from_env(os.environ, client)
    assert w is not None
    return w


def run(name, args):
    return ex.run_tool(ex.client_from_env(os.environ), name, args)


def w(name, args, requester=REQ):
    return exw.run_write_tool(exw.writer_from_env({}, ex.client_from_env(os.environ)), name, args, requester)


# --- contract shape ------------------------------------------------------------------------------------------------

def test_registry_and_names():
    assert DOMAINS["idp"].providers["example"] == ("providers.idp.example", "providers.idp.example_write")
    assert DOMAINS["idp"].env_prefix == contract.PREFIX and DOMAINS["idp"].tool_prefix == contract.TOOL_PREFIX
    names = [t["name"] for t in ex.TOOLS + exw.LIST_TOOLS + exw.WRITE_TOOLS]
    assert len(names) == len(set(names)) and all(n.startswith("idp_") for n in names)
    assert set(ex.TOOL_NAMES) == {"idp_get_user", "idp_get_group", "idp_get_app", "idp_search_logs"}
    assert set(exw.WRITE_TOOL_NAMES) == {"idp_set_user_suspension", "idp_clear_user_sessions"}
    assert exw.LIST_TOOLS == []


def test_no_automatic_actions():
    assert not hasattr(exw, "auto_check") and not hasattr(exw, "AUTO_ID_PATTERN")


def test_schemas_and_parameters():
    params = {}
    for t in ex.TOOLS + exw.WRITE_TOOLS:
        s = t["input_schema"]
        assert s["type"] == "object" and isinstance(s["properties"], dict)
        assert set(s.get("required", [])) <= set(s["properties"]), t["name"]
        params[t["name"]] = (set(s["properties"]), set(s.get("required", [])))
    assert params["idp_get_user"] == ({"user"}, {"user"})
    assert params["idp_get_group"] == ({"group", "max_members"}, {"group"})
    assert params["idp_get_app"] == ({"app", "max_users"}, {"app"})
    assert params["idp_search_logs"] == ({"lookback_hours", "until_hours_ago", "user", "event_types", "outcome",
                                          "severity", "ip", "q", "limit", "max_events"}, set())
    assert params["idp_set_user_suspension"] == ({"user", "action", "reason"}, {"user", "action", "reason"})
    assert params["idp_clear_user_sessions"] == ({"user", "reason", "revoke_oauth_tokens"}, {"user", "reason"})
    sl = contract.tool("idp_search_logs")["input_schema"]["properties"]
    assert sl["outcome"]["enum"] == list(contract.LOG_OUTCOMES) and all(o == o.lower() for o in contract.LOG_OUTCOMES)
    assert sl["severity"]["enum"] == list(contract.LOG_SEVERITIES)


def test_no_vendor_names():
    blob = json.dumps(ex.TOOLS + exw.WRITE_TOOLS).lower() + (contract.__doc__ + ex.__doc__ + exw.__doc__).lower()
    assert not [x for x in BANNED if re.search(r"\b" + re.escape(x) + r"\b", blob)]
    assert "admin_url" in contract.__doc__


def test_client_from_env():
    assert ex.client_from_env({}) is None
    assert ex.client_from_env({"IDP_BASE_URL": "https://idp.example.test"}) is None
    assert ex.client_from_env({"IDP_BASE_URL": "https://idp.example.test", "IDP_CLIENT_ID": "x"}) is None
    assert ex.client_from_env({"IDP_BASE_URL": "https://idp.example.test", "IDP_CLIENT_ID": "x",
                               "IDP_PRIVATE_KEY_B64": "a2V5"}) is not None
    assert ex.client_from_env({"IDP_BASE_URL": "https://idp.example.test/path", "IDP_API_TOKEN": "t"}) is None
    assert exw.writer_from_env({}, None) is None


# --- never raises --------------------------------------------------------------------------------------------------

GARBAGE = [None, "x", 3, [], {}, {"user": None}, {"user": ["a", "b"]}, {"user": {"a": 1}}, {"group": True},
           {"lookback_hours": "soon"}, {"max_events": float("inf")}, {"event_types": 7}, {"action": ["suspend"]},
           {"reason": 12}, {"ip": "1.2.3.4/24"}]


def test_run_tool_never_raises(client):
    for name in list(ex.TOOL_NAMES) + ["idp_nope", None]:
        for args in GARBAGE:
            for c in (client, None):
                r = ex.run_tool(c, name, args)
                assert isinstance(r, dict) and isinstance(r.get("status"), str), (name, args)
                json.dumps(r)


def test_run_write_tool_never_raises(writer):
    for name in list(exw.WRITE_TOOL_NAMES) + ["idp_nope"]:
        for args in GARBAGE:
            for wr in (writer, None):
                for req in (REQ, "", None):
                    r = exw.run_write_tool(wr, name, args, req)
                    assert isinstance(r, dict) and isinstance(r.get("status"), str), (name, args, req)
                    json.dumps(r)


# --- read validation -----------------------------------------------------------------------------------------------

def test_subject_validation():
    for bad in ({}, {"user": ""}, {"user": ["a@acme.example", "b@acme.example"]}, {"user": "email"},
                {"user": "TODO"}, {"user": 'a"b'}, {"user": "x" * 300}, {"user": "half@"}, {"user": "a\x01b"}):
        assert run("idp_get_user", bad)["status"] == "invalid_input", bad
    r = run("idp_get_user", {"user": "<mailto:jane.doe@acme.example|jane.doe@acme.example>"})
    assert r["status"] == "not_implemented"
    assert r["validated"] == {"subject": "jane.doe@acme.example", "lookup_kind": "email"}
    assert r["next_step"] == "Say this lookup isn't implemented in this deployment; never invent results."
    assert run("idp_get_user", {"user": "Jane Doe"})["validated"]["lookup_kind"] == "name"


def test_group_and_app_validation():
    assert run("idp_get_group", {"group": "a@acme.example"})["status"] == "invalid_input"
    assert run("idp_get_app", {"app": "a@acme.example"})["status"] == "invalid_input"
    assert run("idp_get_group", {"group": "Engineering", "max_members": 10 ** 6})["validated"]["max_members"] == \
        contract.MAX_GROUP_MEMBERS
    assert run("idp_get_group", {"group": "Engineering"})["validated"]["max_members"] == \
        contract.DEFAULT_GROUP_MEMBERS
    assert run("idp_get_app", {"app": "Payroll", "max_users": 0})["validated"]["max_users"] == 1
    assert run("idp_get_app", {"app": "Payroll", "max_users": "many"})["status"] == "invalid_input"


def test_search_logs_validation():
    for bad in ({"since": "2026-01-01"}, {"start_date": "x"}, {"lookback_hours": 24, "until_hours_ago": 24},
                {"event_types": "User.Session.Start"}, {"event_types": "login"},
                {"event_types": ",".join(f"user.e{i}" for i in range(21))}, {"outcome": "SUCCEEDED"},
                {"severity": "critical"}, {"ip": "10.0.0.0/8"}, {"ip": "not-an-ip"}, {"q": "x" * 129},
                {"lookback_hours": 100}):
        assert run("idp_search_logs", bad)["status"] == "invalid_input", bad
    v = run("idp_search_logs", {})["validated"]
    assert v["lookback_hours"] == contract.DEFAULT_LOG_LOOKBACK_H and v["until_hours_ago"] == 0
    assert v["max_events"] == contract.DEFAULT_LOG_EVENTS and v["limit"] == contract.DEFAULT_LOG_PAGE
    v = run("idp_search_logs", {"lookback_hours": 99999, "user": "jane@acme.example", "outcome": "FAILURE",
                                "severity": "WARN", "ip": "203.0.113[.]7", "event_types": "user.session.*, "
                                "user.authentication.auth_via_mfa", "max_events": 9999})["validated"]
    assert v["lookback_hours"] == contract.MAX_LOG_LOOKBACK_H and v["outcome"] == "failure"
    assert v["severity"] == "warn" and v["ip"] == "203.0.113.7" and v["max_events"] == contract.MAX_LOG_EVENTS
    assert v["event_types"] == ["user.session.*", "user.authentication.auth_via_mfa"]
    assert run("idp_search_logs", {"lookback_hours": 100, "q": "reset"})["status"] == "not_implemented"
    assert run("idp_search_logs", {"lookback_hours": 100, "until_hours_ago": 40})["status"] == "not_implemented"


# --- user_groups ---------------------------------------------------------------------------------------------------

def test_user_groups_stub(client):
    r = ex.user_groups(client, " <Jane.Doe@ACME.example> ")
    assert r == {"status": "error", "email": "jane.doe@acme.example", "user_status": None, "groups": [],
                 "truncated": False, "message": "not implemented"}
    bad = ex.user_groups(client, "not an email")
    assert bad["status"] == "error" and bad["groups"] == [] and bad["truncated"] is False and bad["message"]
    for odd in (None, 5, ["a@acme.example"]):
        assert ex.user_groups(client, odd)["status"] == "error"
    assert set(r) <= {"status", "email", "user_status", "groups", "truncated", "message"}
    assert r["status"] in contract.USER_GROUPS_STATUSES


def test_ai_entitlement_through_the_example_is_unknown(client):
    r = ai_entitlement.run_tool(ex, client, next(iter(ai_entitlement.TOOL_NAMES)), {"email": "jane@acme.example"})
    assert r["status"] == "error" and r["result"] == "unknown" and "not implemented" in r["reason"]


# --- write validation ----------------------------------------------------------------------------------------------

def test_writes_refuse_without_a_requester():
    for name, args in (("idp_set_user_suspension", {"user": "jane@acme.example", "action": "suspend",
                                                     "reason": REASON}),
                       ("idp_clear_user_sessions", {"user": "jane@acme.example", "reason": REASON})):
        for req in ("", None, "  "):
            r = w(name, args, req)
            assert r["status"] == "refused" and r["written"] is False, (name, req)


def test_suspension_validation():
    base = {"user": "jane@acme.example", "action": "suspend", "reason": REASON}
    for bad in ({**base, "action": ""}, {**base, "action": "delete"}, {**base, "action": "deactivate"},
                {**base, "user": "Jane Doe"}, {**base, "user": "jdoe"}, {**base, "user": ["a@acme.example"]},
                {**base, "reason": "short"}, {**base, "reason": "as requested by the analyst on call"},
                {**base, "reason": "test " + "x" * 30}):
        r = w("idp_set_user_suspension", bad)
        assert r["status"] == "invalid_input" and r["written"] is False, bad
    r = w("idp_set_user_suspension", {**base, "action": "deactivate"})
    assert "offboarding" in r["message"]
    r = w("idp_set_user_suspension", {**base, "action": "Un_Suspend", "requested_by": "mallory"})
    assert r["status"] == "not_implemented" and r["written"] is False
    assert r["validated"] == {"action": "unsuspend", "subject": "jane@acme.example", "lookup": "email"}
    assert r["requested_by"] == REQ and r["reason"] == REASON
    assert w("idp_set_user_suspension", {**base, "user": "00abc12345"})["validated"]["lookup"] == "id"
    assert exw.run_write_tool(None, "idp_set_user_suspension", base, REQ)["status"] == "error"


@pytest.mark.parametrize("login", ["svc-backup@acme.example", "service.sync@acme.example", "SVC_ci@acme.example"])
def test_service_accounts_are_refused(login):
    r = w("idp_set_user_suspension", {"user": login, "action": "suspend", "reason": REASON})
    assert r["status"] == "refused" and r["written"] is False
    r = w("idp_clear_user_sessions", {"user": login, "reason": REASON})
    assert r["status"] == "refused"
    # Unsuspending a service account restores it, so it is not refused up front.
    assert w("idp_set_user_suspension", {"user": login, "action": "unsuspend", "reason": REASON})["status"] == \
        "not_implemented"


def test_requester_own_account_is_refused():
    r = w("idp_set_user_suspension", {"user": "Analyst@acme.example", "action": "suspend", "reason": REASON})
    assert r["status"] == "refused" and "own account" in r["message"]
    assert w("idp_set_user_suspension", {"user": "other@acme.example", "action": "suspend",
                                         "reason": REASON})["status"] == "not_implemented"


def test_clear_sessions_validation():
    assert w("idp_clear_user_sessions", {"user": "Jane Doe", "reason": REASON})["status"] == "invalid_input"
    assert w("idp_clear_user_sessions", {"user": "jane@acme.example", "reason": "x"})["status"] == "invalid_input"
    r = w("idp_clear_user_sessions", {"user": "jane@acme.example", "reason": REASON})
    assert r["status"] == "not_implemented" and r["validated"]["revoke_oauth_tokens"] is True
    r = w("idp_clear_user_sessions", {"user": "jane@acme.example", "reason": REASON, "revoke_oauth_tokens": False})
    assert r["validated"]["revoke_oauth_tokens"] is False
