"""Contract tests for the email security domain: tool surface, example validation, requester routes, auto policy."""

from __future__ import annotations

import json
import os

import pytest

import providers
from providers.email_security import contract as c
from providers.email_security import example as ex
from providers.email_security import example_write as exw

REQ = "jane.doe@acme.example (U00000000A1)"
MID = "0b9f6d1e-2c3a-4d5e-8f70-123456789abc"
MID2 = "1c0a7e2f-3d4b-4e6f-9a81-23456789abcd"
TASK = "2d1b8f30-4e5c-4f70-8b92-3456789abcde"
CONSOLE = os.environ["EMAIL_SECURITY_CONSOLE_URL"]
BANNED = [w[::-1] for w in ("lenitnes", "atko", "swg", "liamg", "emilbus", "leppod", "24edoc", "rdycni", "naissalta",
                            "arij", "ecneulfnoc", "naelg", "looter", "elgoog")]
ALL = c.TOOLS + c.LIST_TOOLS + c.WRITE_TOOLS
GARBAGE = [None, "x", 1, [], [{"message_id": MID}], {"message_id": None}, {"message_id": [MID, MID2]},
           {"message_id": {"x": 1}}, {"message_id": True}, {"limit": "many"}, {"sender": ["a", "b"]},
           {"action": 7, "verdict": None}]
JUST = "Ad-hoc review: suspected invoice fraud reported in Slack"
REASON = "Credential phish: lookalike login page, sender domain registered yesterday"


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
    ad = providers.load("email_security")
    assert ad.read is ex and ad.write is exw and ad.can_auto_act


def test_tool_names_prefixed_unique_and_as_specified():
    names = [t["name"] for t in ALL]
    assert len(names) == len(set(names)) and all(n.startswith(c.TOOL_PREFIX) for n in names)
    assert c.TOOL_NAMES == {"email_search_messages", "email_get_message_eml", "email_get_analysis_report",
                            "email_get_action_status"}
    assert c.WRITE_TOOL_NAMES == {"email_action_message", "email_block_sender"} and c.LIST_TOOLS == []
    assert ex.TOOLS is c.TOOLS and exw.WRITE_TOOLS is c.WRITE_TOOLS


@pytest.mark.parametrize("t", ALL + c.auto_tools(), ids=lambda t: t["name"])
def test_schemas_are_valid_objects(t):
    s = t["input_schema"]
    assert s["type"] == "object" and isinstance(s["properties"], dict)
    assert set(s.get("required", [])) <= set(s["properties"])
    assert all("type" in p for p in s["properties"].values())
    assert len(t["description"]) > 40


def test_required_params_and_enums():
    req = {t["name"]: set(t["input_schema"].get("required", [])) for t in ALL}
    assert req["email_get_message_eml"] == {"message_id", "justification"}
    assert req["email_action_message"] == {"message_id", "action", "verdict", "reason"}
    assert req["email_block_sender"] == {"sender_email", "reason"}
    props = c.tool("email_action_message")["input_schema"]["properties"]
    assert props["action"]["enum"] == list(c.ACTIONS) and props["verdict"]["enum"] == list(c.VERDICTS)
    assert set(c.NEEDS_VERDICT) == set(c.ACTIONS) and c.NEEDS_VERDICT["restore"] == ()


def test_no_vendor_words_in_the_surface():
    blob = json.dumps(ALL + c.auto_tools()).lower() + c.AUTO_NOTE.lower() + (c.__doc__ or "").lower()
    for w in BANNED:
        assert w not in blob, w


def test_client_from_env():
    assert ex.client_from_env({}) is None
    assert ex.client_from_env({"EMAIL_SECURITY_BASE_URL": "https://email.example.test"}) is None
    assert ex.client_from_env({"EMAIL_SECURITY_BASE_URL": "https://email.example.test/api",
                               "EMAIL_SECURITY_API_TOKEN": "tok-123456"}) is None
    cl = ex.client_from_env({"EMAIL_SECURITY_BASE_URL": "https://email.example.test",
                             "EMAIL_SECURITY_API_TOKEN": "tok-123456"})
    assert cl is not None and "tok-123456" not in repr(cl)
    assert exw.writer_from_env(os.environ, None) is None


# --- reads -----------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", sorted(c.TOOL_NAMES) + ["nope", None])
def test_run_tool_always_returns_a_status(client, name):
    for args in GARBAGE + [{}]:
        for req in ("", REQ):
            out = ex.run_tool(client, name, args, requester=req)
            assert isinstance(out, dict) and out.get("status")
            json.dumps(out)


def test_search_validation(client):
    run = lambda a: ex.run_tool(client, "email_search_messages", a, requester=REQ)  # noqa: E731
    assert run({})["status"] == "invalid_input"
    assert run({"direction": "inbound"})["status"] == "invalid_input"
    assert run({"query": "invoice", "sender": "a@b.example"})["status"] == "invalid_input"
    assert run({"query": "invoice", "direction": "inbound"})["status"] == "invalid_input"
    assert run({"direction": "sideways", "sender": "*@evil.example"})["status"] == "invalid_input"
    assert run({"attachment_hash": "abc"})["status"] == "invalid_input"
    assert run({"message_id_header": MID})["status"] == "invalid_input"
    assert run({"sender": "sender"})["status"] == "invalid_input"
    assert run({"sender": "*@evil.example", "limit": "lots"})["status"] == "invalid_input"
    out = run({"sender": "mailto:bad@evil.example", "direction": "inbound,internal", "limit": 999, "lookback_hours": 0})
    assert out["status"] == "not_implemented"
    v = out["validated"]
    assert v["filters"]["sender"] == "bad@evil.example" and v["direction"] == ["inbound", "internal"]
    assert v["limit"] == c.MAX_LIMIT and v["lookback_hours"] == 1
    assert run({"reported_only": True})["status"] == "not_implemented"
    assert run({"attachment_hash": "A" * 64})["validated"]["filters"]["attachment_hash"] == "a" * 64


def test_message_content_reads_need_justification_and_requester(client):
    for name in ("email_get_message_eml", "email_get_analysis_report"):
        ok = {"message_id": MID.upper(), "justification": JUST}
        out = ex.run_tool(client, name, ok, requester=REQ)
        assert out["status"] == "not_implemented" and out["validated"]["message_id"] == MID
        assert REQ in out["validated"]["access_justification"]
        assert ex.run_tool(client, name, ok, requester="")["status"] == "refused"
        assert ex.run_tool(client, name, {**ok, "justification": "review"}, requester=REQ)["status"] == "invalid_input"
        assert ex.run_tool(client, name, {**ok, "justification": "short"}, requester=REQ)["status"] == "invalid_input"
        for bad in ("not-a-uuid", "someone@acme.example", "<abc@mail.example>", "uuid", "09GttBHb6KLd6qxynHLpVn7"):
            assert ex.run_tool(client, name, {**ok, "message_id": bad}, requester=REQ)["status"] == "invalid_input"


def test_action_status_validation(client):
    run = lambda a: ex.run_tool(client, "email_get_action_status", a)  # noqa: E731
    assert run({})["status"] == "invalid_input"
    assert run({"task_id": "nope"})["status"] == "invalid_input"
    assert run({"group_id": MID})["status"] == "invalid_input"
    assert run({"task_id": TASK})["status"] == "not_implemented"
    assert run({"group_id": "grp_0001-abc", "limit": 500})["validated"]["limit"] == c.MAX_LIMIT


# --- writes ----------------------------------------------------------------------------------------------------------

Q = {"message_id": MID, "action": "quarantine", "verdict": "malicious", "reason": REASON, "confidence": 99}


@pytest.mark.parametrize("name", sorted(c.WRITE_TOOL_NAMES) + ["nope"])
def test_run_write_tool_never_raises(writer, name):
    for args in GARBAGE + [{}]:
        for req in ("", REQ):
            out = exw.run_write_tool(writer, name, args, req)
            assert isinstance(out, dict) and out.get("status") and out["written"] in (False, None)


def test_action_message_analyst_directed(writer):
    out = exw.run_write_tool(writer, "email_action_message", {**Q, "requested_by": "x"}, REQ)
    assert out["status"] == "not_implemented" and out["written"] is False
    assert out["audit"] == {"route": "analyst_directed", "requested_by": REQ, "reason": REASON,
                            "verdict": "malicious", "confidence": 99}
    # Analyst-directed: any action, any verdict, including restore.
    assert exw.run_write_tool(writer, "email_action_message", {**Q, "action": "release", "verdict": "benign"},
                              REQ)["status"] == "not_implemented"


def test_action_message_agent_initiated_gates(writer):
    run = lambda a: exw.run_write_tool(writer, "email_action_message", a, "")  # noqa: E731
    assert run(Q)["status"] == "not_implemented" and run(Q)["audit"]["route"] == "agent_initiated"
    assert run({**Q, "action": "restore"})["status"] == "refused"
    assert run({**Q, "verdict": "suspicious"})["status"] == "refused"  # quarantine needs malicious
    assert run({**Q, "action": "trash", "verdict": "spam"})["status"] == "refused"
    assert run({**Q, "action": "warning_banner", "verdict": "suspicious"})["status"] == "not_implemented"
    assert run({**Q, "action": "junk", "verdict": "graymail"})["status"] == "not_implemented"
    assert run({**Q, "action": "warning_banner", "verdict": "benign"})["status"] == "refused"


@pytest.mark.parametrize("patch,status", [
    ({"action": ""}, "invalid_input"), ({"action": "explode"}, "invalid_input"),
    ({"action": "delete_calendar_events"}, "refused"), ({"action": "share_with_vendor"}, "refused"),
    ({"verdict": "maybe"}, "invalid_input"), ({"reason": "phishing"}, "invalid_input"),
    ({"reason": "too short"}, "invalid_input"), ({"message_id": "abc"}, "invalid_input"),
])
def test_action_message_rejects(writer, patch, status):
    assert exw.run_write_tool(writer, "email_action_message", {**Q, **patch}, REQ)["status"] == status


B = {"sender_email": "billing@invoices-evil.net", "reason": REASON}


def test_block_sender(writer):
    out = exw.run_write_tool(writer, "email_block_sender", {**B, "message_id": MID}, REQ)
    assert out["status"] == "not_implemented" and out["written"] is False
    assert out["audit"]["evidence_message_id"] == MID and out["audit"]["route"] == "analyst_directed"
    out = exw.run_write_tool(writer, "email_block_sender", {**B, "sender_email": "Bad Guy <Billing@Invoices-Evil.net>"},
                             "")
    assert out["status"] == "not_implemented" and out["validated"]["sender_email"] == "billing@invoices-evil.net"
    assert out["audit"]["route"] == "agent_initiated"
    # Outside-world mailbox providers are ordinary senders: a single address there may be blocked.
    assert exw.run_write_tool(writer, "email_block_sender", {**B, "sender_email": "scammer@mailbox-provider.net"},
                              REQ)["status"] == "not_implemented"


@pytest.mark.parametrize("sender,status", [
    ("ceo@acme.example", "refused"), ("it@mail.acme-mail.example", "refused"), ("x@acme.link.example", "refused"),
    ("a@evil.test", "invalid_input"), ("a@example.com", "invalid_input"), ("*@evil.net", "invalid_input"),
    ("@evil.net", "invalid_input"), ("evil.net", "invalid_input"), ("sender", "invalid_input"),
    ("a@@b", "invalid_input"), (["a@evil.net", "b@evil.net"], "invalid_input"), ("", "invalid_input"),
])
def test_block_sender_refusals(writer, sender, status):
    for req in ("", REQ):
        out = exw.run_write_tool(writer, "email_block_sender", {**B, "sender_email": sender}, req)
        assert out["status"] == status and out["written"] is False


def test_protected_domains_are_configurable(client):
    w = exw.writer_from_env({"EMAIL_SECURITY_PROTECTED_SENDER_DOMAINS": "idp-vendor.net, @suite-vendor.net"}, client)
    for s in ("mfa@idp-vendor.net", "x@notify.suite-vendor.net"):
        assert exw.run_write_tool(w, "email_block_sender", {**B, "sender_email": s}, REQ)["status"] == "refused"
    # Nothing is protected by default beyond the organisation's own domains.
    assert c.PROTECTED_SENDER_DOMAINS == ()


def test_block_sender_rejects_bad_reason_and_evidence(writer):
    assert exw.run_write_tool(writer, "email_block_sender", {**B, "reason": "spam"}, REQ)["status"] == "invalid_input"
    assert exw.run_write_tool(writer, "email_block_sender", {**B, "message_id": "nope"}, REQ)["status"] == \
        "invalid_input"


# --- automatic actions -----------------------------------------------------------------------------------------------

ALLOWED = frozenset({MID})


@pytest.mark.parametrize("name,args,key", [
    ("email_action_message", Q, f"email|quarantine|{MID}"),
    ("email_action_message", {**Q, "message_id": MID.upper()}, f"email|quarantine|{MID}"),
    ("email_action_message", {**Q, "action": "warning_banner", "confidence": 50}, f"email|banner|{MID}"),
    ("email_action_message", {**Q, "action": "warning_banner", "verdict": "suspicious", "confidence": None},
     f"email|banner|{MID}"),
    ("email_block_sender", {"sender_email": "a@evil.net", "reason": REASON, "message_id": MID, "confidence": 99},
     f"email|block|{MID}"),
])
def test_auto_check_accepts(name, args, key):
    assert c.auto_check(name, args, ALLOWED) == ([key], None)
    assert exw.auto_check is c.auto_check


@pytest.mark.parametrize("name,args", [
    ("email_action_message", {**Q, "confidence": 98}),
    ("email_action_message", {**Q, "confidence": "high"}),
    ("email_action_message", {**Q, "confidence": True}),
    ("email_action_message", {**Q, "verdict": "suspicious"}),
    ("email_action_message", {**Q, "action": "trash"}),
    ("email_action_message", {**Q, "action": "restore"}),
    ("email_action_message", {**Q, "action": "move_to_spam", "verdict": "spam"}),
    ("email_action_message", {**Q, "action": "warning_banner", "verdict": "spam"}),
    ("email_action_message", {**Q, "message_id": MID2}),
    ("email_action_message", {**Q, "message_id": ""}),
    ("email_block_sender", {"sender_email": "a@evil.net", "reason": REASON, "message_id": MID, "confidence": 98}),
    ("email_block_sender", {"sender_email": "a@evil.net", "reason": REASON, "confidence": 99}),
    ("email_block_sender", {"sender_email": "a@evil.net", "reason": REASON, "message_id": MID2, "confidence": 99}),
    ("email_search_messages", Q),
    ("email_action_message", "garbage"),
])
def test_auto_check_refuses(name, args):
    keys, why = c.auto_check(name, args, ALLOWED)
    assert keys is None and why


def test_auto_payload_tools_and_requester():
    b = {"sender_email": "a@evil.net", "reason": REASON, "message_id": MID, "confidence": 99}
    assert c.auto_payload("email_block_sender", b) == {k: v for k, v in b.items() if k != "confidence"}
    assert c.auto_payload("email_action_message", Q) == Q
    assert c.auto_payload("email_block_sender", None) == {}
    assert c.auto_requester("U00000000B1") == "" and exw.auto_requester("x") == ""
    tools = {t["name"]: t for t in c.auto_tools()}
    assert set(tools) == c.WRITE_TOOL_NAMES and all(t["description"].startswith("AUTOMATIC ONLY") for t in tools.values())
    assert "confidence" in tools["email_block_sender"]["input_schema"]["properties"]
    assert "confidence" not in c.tool("email_block_sender")["input_schema"]["properties"]  # contract left untouched


def test_auto_payload_passes_writer_gates(writer):
    """What the server runs automatically (auto_payload + requester "") is accepted by the writer's gates."""
    b = {"sender_email": "a@invoices-evil.net", "reason": REASON, "message_id": MID, "confidence": 99}
    for name, args in (("email_block_sender", b), ("email_action_message", Q),
                       ("email_action_message", {**Q, "action": "warning_banner", "verdict": "suspicious"})):
        assert c.auto_check(name, args, ALLOWED)[0]
        out = exw.run_write_tool(writer, name, c.auto_payload(name, args), c.auto_requester("U00000000B1"))
        assert out["status"] == "not_implemented"


def test_make_auto_id_pattern():
    pat = c.make_auto_id_pattern(CONSOLE)
    post = (f"Flagged: {CONSOLE}/messages/{MID} and <{CONSOLE}/messages/{MID2}|view>. "
            f"Other: https://email.example.test/messages/{TASK} https://console.email.example.test.evil.net/m/{TASK} "
            f"bare {TASK} {CONSOLE}/messages/{TASK}/details")
    assert [m.group(1) for m in pat.finditer(post)] == [MID, MID2]
    assert [m.group(1) for m in exw.AUTO_ID_PATTERN.finditer(post)] == [MID, MID2]
    assert all(c.AUTO_ID_SHAPE.fullmatch(m.group(1)) for m in pat.finditer(post))
    assert [m.group(1) for m in pat.finditer(f"{CONSOLE.upper()}/messages/{MID}.")] == [MID]
    for unset in (None, "", "   ", "not a url", "ftp://console.email.example.test"):
        assert list(c.make_auto_id_pattern(unset).finditer(post)) == []
