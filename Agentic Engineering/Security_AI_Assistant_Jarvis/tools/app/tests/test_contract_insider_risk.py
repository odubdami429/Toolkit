"""Contract tests for the insider risk domain: tool surface, example validation, the close write, auto policy."""

from __future__ import annotations

import json
import os

import pytest

import providers
from providers.insider_risk import ai_entitlement
from providers.insider_risk import contract as c
from providers.insider_risk import example as ex
from providers.insider_risk import example_write as exw

REQ = "jane.doe@acme.example (U00000000A1)"
CONSOLE = os.environ["INSIDER_RISK_CONSOLE_URL"]
SID = "1063501912683821806_1789484488969_0"
SID2 = "a1b2c3d4-alert-77"
BANNED = [w[::-1] for w in ("lenitnes", "atko", "swg", "liamg", "emilbus", "leppod", "24edoc", "rdycni", "naissalta",
                            "arij", "ecneulfnoc", "naelg", "looter", "elgoog")]
ALL = c.TOOLS + c.LIST_TOOLS + c.WRITE_TOOLS
GARBAGE = [None, "x", 1, [], [{"session_id": SID}], {"session_id": None}, {"session_id": [SID, SID2]},
           {"session_id": {"x": 1}}, {"actor": ["a@acme.example"]}, {"page_size": "many"}, {"filters": "{bad"},
           {"disposition": 5, "note": None}]
NOTE = "Upload to the sanctioned corporate drive; destination account is the actor's own work login."


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
    ad = providers.load("insider_risk")
    assert ad.read is ex and ad.write is exw and ad.can_auto_act


def test_tool_names_prefixed_unique_and_as_specified():
    names = [t["name"] for t in ALL] + list(ai_entitlement.TOOL_NAMES)
    assert len(names) == len(set(names)) and all(n.startswith(c.TOOL_PREFIX) for n in names)
    assert c.TOOL_NAMES == {"irm_search_alerts", "irm_get_alert", "irm_search_events"}
    assert c.WRITE_TOOL_NAMES == {"irm_close_alert"} and c.LIST_TOOLS == []
    assert "irm_check_ai_entitlement" not in c.ALL_TOOL_NAMES  # answered by the IdP, not this adapter


@pytest.mark.parametrize("t", ALL + c.auto_tools() + ai_entitlement.TOOLS, ids=lambda t: t["name"])
def test_schemas_are_valid_objects(t):
    s = t["input_schema"]
    assert s["type"] == "object" and isinstance(s["properties"], dict)
    assert set(s.get("required", [])) <= set(s["properties"])
    assert all("type" in p for p in s["properties"].values())
    assert len(t["description"]) > 40


def test_close_alert_uses_neutral_disposition():
    s = c.tool("irm_close_alert")["input_schema"]
    assert s["required"] == ["session_id", "disposition", "note"]
    assert s["properties"]["disposition"]["enum"] == ["false_positive", "true_positive", "benign_true_positive",
                                                      "closed"]
    assert set(c.DISPOSITION_STATE.values()) == set(c.CLOSED_STATES)
    assert set(c.AUTO_DISPOSITIONS) == {"false_positive", "benign_true_positive"}


def test_no_vendor_words_in_the_surface():
    blob = (json.dumps(ALL + c.auto_tools() + ai_entitlement.TOOLS) + c.AUTO_NOTE + (c.__doc__ or "")
            + (ai_entitlement.__doc__ or "")).lower()
    for w in BANNED:
        assert w not in blob, w


def test_ai_entitlement_depends_only_on_the_idp_user_groups_contract():
    src = open(ai_entitlement.__file__, encoding="utf-8").read()
    imports = [ln for ln in src.splitlines() if ln.startswith(("import ", "from "))]
    assert all("providers" not in ln for ln in imports), imports
    assert "user_groups" in src


def test_client_from_env():
    assert ex.client_from_env({}) is None
    assert ex.client_from_env({"INSIDER_RISK_BASE_URL": "https://irm.example.test",
                               "INSIDER_RISK_CLIENT_ID": "id"}) is None
    cl = ex.client_from_env({"INSIDER_RISK_BASE_URL": "https://irm.example.test", "INSIDER_RISK_CLIENT_ID": "id",
                             "INSIDER_RISK_PRIVATE_KEY_B64": "a2V5LW1hdGVyaWFs"})
    assert cl is not None and "a2V5LW1hdGVyaWFs" not in repr(cl)
    assert exw.writer_from_env(os.environ, None) is None


# --- reads -----------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", sorted(c.TOOL_NAMES) + ["nope", None])
def test_run_tool_always_returns_a_status(client, name):
    for args in GARBAGE + [{}]:
        out = ex.run_tool(client, name, args)
        assert isinstance(out, dict) and out.get("status")
        json.dumps(out)


def test_get_alert_ids(client):
    run = lambda v, **k: ex.run_tool(client, "irm_get_alert", {"session_id": v, **k})  # noqa: E731
    out = run(SID, max_events=500)
    assert out["status"] == "not_implemented" and out["validated"]["max_events"] == c.MAX_EVENTS
    assert out["validated"]["console_url"].startswith(CONSOLE)
    assert run(f"{CONSOLE}/app/#/alerts/review-alerts/{SID}")["validated"]["session_id"] == SID
    for bad in (f"{SID},{SID2}", f"{SID} {SID2}", [SID], "abc", "session_id", "https://evil.net/alerts/" + SID,
                "https://irm.example.test/alerts/" + SID, "bad/char!", ""):
        assert run(bad)["status"] == "invalid_input", bad
    assert ex.run_tool(None, "irm_get_alert", {"session_id": SID})["status"] == "error"


def test_search_alerts_validation(client):
    run = lambda a: ex.run_tool(client, "irm_search_alerts", a)  # noqa: E731
    out = run({})
    assert out["status"] == "not_implemented"
    v = out["validated"]
    assert v["state"] == ["unresolved"] and v["lookback_hours"] == c.DEFAULT_LOOKBACK and v["order_by"] == "score"
    v = run({"state": "open, closed_false_positive", "min_severity": "HIGH", "page_size": 99,
             "actor": "<mailto:Jane.Doe@acme.example>", "lookback_hours": 99999})["validated"]
    assert v["state"] == ["open", "closed_false_positive"] and v["min_severity"] == 3 and v["page_size"] == 50
    assert v["actor"] == "jane.doe@acme.example" and v["lookback_hours"] == c.MAX_LOOKBACK
    for bad in ({"state": "CLOSED_FP_X"}, {"state": "all,open"}, {"min_severity": "9"}, {"order_by": "name"},
                {"actor": "Jane Doe"}, {"rule_id": "a b"}, {"page_size": "x"}):
        assert run(bad)["status"] == "invalid_input", bad


def test_search_events_validation(client):
    run = lambda a: ex.run_tool(client, "irm_search_events", a)  # noqa: E731
    f = [{"term": "destination.user.email", "operator": "is_any", "value": ["a@x.net", "b@x.net"]},
         {"term": "file.size", "operator": "EXISTS"}]
    out = run({"actor": "jane.doe@acme.example", "sha256": "A" * 64, "min_risk_severity": "Medium",
               "filters": json.dumps(f), "page_size": 1000, "destination_domain": "assistant.example.net"})
    assert out["status"] == "not_implemented"
    v = out["validated"]
    assert v["sha256"] == "a" * 64 and v["min_risk_severity"] == "moderate" and v["page_size"] == c.EVENTS_MAX_PAGE
    assert v["filters"][0]["operator"] == "IS_ANY"
    for bad in ({"sha256": "abc"}, {"min_risk_severity": "extreme"}, {"filters": "not json"},
                {"filters": json.dumps({"term": "x"})}, {"filters": json.dumps([{"term": "x", "operator": "LIKE",
                                                                                  "value": 1}])},
                {"filters": json.dumps([{"term": "x", "operator": "IS"}])},
                {"filters": json.dumps([{"term": "x y", "operator": "IS", "value": 1}])},
                {"filters": json.dumps([{"term": "x", "operator": "EXISTS"}] * (c.MAX_FILTERS + 1))},
                {"file_name": ["a", "b"]}, {"actor": "nobody"}):
        assert run(bad)["status"] == "invalid_input", bad


# --- write -----------------------------------------------------------------------------------------------------------

CL = {"session_id": SID, "disposition": "benign_true_positive", "note": NOTE}
AUTO = {**CL, "mode": "auto", "confidence": 99}


@pytest.mark.parametrize("name", sorted(c.WRITE_TOOL_NAMES) + ["nope"])
def test_run_write_tool_never_raises(writer, name):
    for args in GARBAGE + [{}]:
        for req in ("", REQ):
            out = exw.run_write_tool(writer, name, args, req)
            assert isinstance(out, dict) and out.get("status") and out["written"] in (False, None)


def test_close_refuses_without_requester(writer):
    for req in ("", None, " "):
        out = exw.run_write_tool(writer, "irm_close_alert", CL, req)
        assert out["status"] == "refused" and out["written"] is False and out["note_attached"] is False


def test_close_valid_records_stamped_note(writer):
    out = exw.run_write_tool(writer, "irm_close_alert", {**CL, "note": NOTE + " Approved by the CISO.",
                                                         "requested_by": "x"}, REQ)
    assert out["status"] == "not_implemented" and out["written"] is False and out["state_confirmed"] is False
    a = out["audit"]
    assert a["requested_by"] == REQ and a["to_state"] == "closed_benign_true_positive" and a["mode"] == \
        "analyst_requested"
    assert a["note_written"].startswith(f"[Jarvis] Closed benign_true_positive on analyst request ({REQ}).")
    assert "CISO" not in a["note_written"]
    out = exw.run_write_tool(writer, "irm_close_alert", AUTO, c.auto_requester("U00000000B1"))
    assert out["audit"]["note_written"].startswith("[Jarvis] Auto-closed benign_true_positive at 99% confidence")
    for alias, disp in (("fp", "false_positive"), ("False Positive", "false_positive"), ("sanctioned",
                        "benign_true_positive"), ("TP", "true_positive"), ("resolved", "closed")):
        out = exw.run_write_tool(writer, "irm_close_alert", {**CL, "disposition": alias}, REQ)
        assert out["audit"]["disposition"] == disp, alias
    out = exw.run_write_tool(writer, "irm_close_alert", {**CL, "session_id": f"{CONSOLE}/app/#/alerts/{SID}"}, REQ)
    assert out["session_id"] == SID
    long = exw.run_write_tool(writer, "irm_close_alert", {**CL, "note": "y" * 5 + " z" * 990}, REQ)
    assert len(long["audit"]["note_written"]) <= c.MAX_NOTE and long["audit"]["note_truncated"] is True


@pytest.mark.parametrize("patch,status", [
    ({"disposition": ""}, "invalid_input"), ({"disposition": "maybe"}, "invalid_input"),
    ({"disposition": "open"}, "refused"), ({"disposition": "in_progress"}, "refused"),
    ({"note": "short"}, "invalid_input"), ({"note": "test test test test test"}, "invalid_input"),
    ({"note": "x" * 2001}, "invalid_input"), ({"note": "a" * 25}, "invalid_input"),
    ({"mode": "fast"}, "invalid_input"), ({"mode": "auto"}, "invalid_input"),
    ({"mode": "auto", "confidence": 99, "disposition": "true_positive"}, "refused"),
    ({"mode": "auto", "confidence": 99, "disposition": "closed"}, "refused"),
    ({"session_id": f"{SID},{SID2}"}, "invalid_input"), ({"session_id": [SID, SID2]}, "invalid_input"),
    ({"session_ids": [SID, SID2]}, "invalid_input"),
])
def test_close_rejects(writer, patch, status):
    out = exw.run_write_tool(writer, "irm_close_alert", {**CL, **patch}, REQ)
    assert out["status"] == status and out["written"] is False


# --- automatic actions -----------------------------------------------------------------------------------------------

ALLOWED = frozenset({SID})


@pytest.mark.parametrize("args", [AUTO, {**AUTO, "disposition": "false_positive"}, {**AUTO, "confidence": 98},
                                  {**AUTO, "session_id": f"{CONSOLE}/app/#/alerts/review-alerts/{SID}"}])
def test_auto_check_accepts(args):
    assert c.auto_check("irm_close_alert", args, ALLOWED) == ([f"irm|close|{SID}"], None)
    assert exw.auto_check is c.auto_check


@pytest.mark.parametrize("name,args", [
    ("irm_close_alert", {**AUTO, "confidence": 97}), ("irm_close_alert", {**AUTO, "confidence": "high"}),
    ("irm_close_alert", {**AUTO, "mode": "analyst_requested"}), ("irm_close_alert", {**AUTO, "disposition": "closed"}),
    ("irm_close_alert", {**AUTO, "disposition": "true_positive"}), ("irm_close_alert", {**AUTO, "disposition": "fp"}),
    ("irm_close_alert", {**AUTO, "session_id": SID2}), ("irm_close_alert", {**AUTO, "session_id": ""}),
    ("irm_close_alert", {**AUTO, "session_id": f"{SID},{SID}"}), ("irm_get_alert", AUTO), ("irm_close_alert", None),
])
def test_auto_check_refuses(name, args):
    keys, why = c.auto_check(name, args, ALLOWED)
    assert keys is None and why


def test_auto_payload_tools_requester():
    assert c.auto_payload("irm_close_alert", AUTO) == AUTO
    assert c.auto_requester("U00000000B1") == "U00000000B1 (alert bot, automatic)"
    assert c.auto_tools()[0]["description"].startswith("AUTOMATIC CLOSE ONLY")


def test_make_auto_id_pattern():
    pat = c.make_auto_id_pattern(CONSOLE)
    post = (f"Alert {CONSOLE}/app/#/alerts/review-alerts/{SID} and <{CONSOLE}/alerts/{SID2}|open>; "
            f"elsewhere https://irm.example.test/alerts/other_id_1 https://console.irm.example.test.evil.net/x/id_22222 "
            f"bare {SID}")
    assert [m.group(1) for m in pat.finditer(post)] == [SID, SID2]
    assert [m.group(1) for m in exw.AUTO_ID_PATTERN.finditer(post)] == [SID, SID2]
    for unset in (None, "", "console irm"):
        assert list(c.make_auto_id_pattern(unset).finditer(post)) == []
