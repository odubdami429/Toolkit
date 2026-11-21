"""Contract tests for the brand protection domain: tool surface, scan-URL guardrails, the update write, auto policy."""

from __future__ import annotations

import json
import os

import pytest

import providers
from providers.brand_protection import contract as c
from providers.brand_protection import example as ex
from providers.brand_protection import example_write as exw

REQ = "jane.doe@acme.example (U00000000A1)"
CONSOLE = os.environ["BRAND_PROTECTION_CONSOLE_URL"]
BANNED = [w[::-1] for w in ("lenitnes", "atko", "swg", "liamg", "emilbus", "leppod", "24edoc", "rdycni", "naissalta",
                            "arij", "ecneulfnoc", "naelg", "looter", "elgoog")]
ALL = c.TOOLS + c.LIST_TOOLS + c.WRITE_TOOLS
GARBAGE = [None, "x", 1, [], [{"alert_id": "ABC-1"}], {"alert_id": None}, {"alert_id": ["ABC-1", "ABC-2"]},
           {"alert_id": {"x": 1}}, {"url": ["a.example"]}, {"scan_id": 12}, {"limit": "many"}, {"state": 3}]
NOTE = "Lookalike page is a parked registrar template with no brand content or forms."


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
    ad = providers.load("brand_protection")
    assert ad.read is ex and ad.write is exw and ad.can_auto_act


def test_tool_names_prefixed_unique_and_as_specified():
    names = [t["name"] for t in ALL]
    assert len(names) == len(set(names)) and all(n.startswith(c.TOOL_PREFIX) for n in names)
    assert c.TOOL_NAMES == {"brand_get_alert", "brand_search_alerts", "brand_submit_scan", "brand_get_scan_result"}
    assert c.WRITE_TOOL_NAMES == {"brand_update_alert"} and c.LIST_TOOLS == []


@pytest.mark.parametrize("t", ALL + c.auto_tools(), ids=lambda t: t["name"])
def test_schemas_are_valid_objects(t):
    s = t["input_schema"]
    assert s["type"] == "object" and isinstance(s["properties"], dict)
    assert set(s.get("required", [])) <= set(s["properties"])
    assert all("type" in p for p in s["properties"].values())
    assert len(t["description"]) > 40


def test_update_alert_uses_neutral_state_param():
    s = c.tool("brand_update_alert")["input_schema"]
    assert s["required"] == ["alert_id", "state", "note"]
    assert s["properties"]["state"]["enum"] == ["archived", "taken_down"] and "queue_state" not in s["properties"]
    assert set(c.ARCHIVE_FROM) <= set(c.QUEUE_STATES) and set(c.TAKEDOWN_FROM) <= set(c.QUEUE_STATES)


def test_no_vendor_words_in_the_surface():
    blob = json.dumps(ALL + c.auto_tools()).lower() + c.AUTO_NOTE.lower() + (c.__doc__ or "").lower() \
        + " ".join(c.QUEUE_STATES)
    for w in BANNED:
        assert w not in blob, w


def test_client_from_env():
    assert ex.client_from_env({}) is None
    assert ex.client_from_env({"BRAND_PROTECTION_CLIENT_ID": "id", "BRAND_PROTECTION_CLIENT_SECRET": "s" * 8}) is None
    cl = ex.client_from_env({"BRAND_PROTECTION_BASE_URL": "https://brand.example.test",
                             "BRAND_PROTECTION_CLIENT_ID": "id", "BRAND_PROTECTION_CLIENT_SECRET": "secret-xyz"})
    assert cl is not None and "secret-xyz" not in repr(cl)
    assert exw.writer_from_env(os.environ, None) is None


# --- reads -----------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", sorted(c.TOOL_NAMES) + ["nope", None])
def test_run_tool_always_returns_a_status(client, name):
    for args in GARBAGE + [{}]:
        out = ex.run_tool(client, name, args)
        assert isinstance(out, dict) and out.get("status")
        json.dumps(out)


def test_get_alert_ids_and_links(client):
    run = lambda v: ex.run_tool(client, "brand_get_alert", {"alert_id": v})  # noqa: E731
    assert run("abc-9067")["validated"]["alert_id"] == "ABC-9067"
    assert run(f"{CONSOLE}/alerts/ABC-37157")["validated"]["alert_id"] == "ABC-37157"
    assert run(f"<{CONSOLE}/domains/ABC-37157/>")["validated"]["alert_id"] == "ABC-37157"
    for bad in ("https://evil.example.net/alerts/ABC-1", "https://brand.example.test/alerts/ABC-1", "ABC", "ABC-0",
                "ABC-1234", "123", "ABC-1,ABC-2", ""):
        assert run(bad)["status"] == "invalid_input", bad
    assert ex.run_tool(None, "brand_get_alert", {"alert_id": "ABC-9067"})["status"] == "error"


def test_search_validation(client):
    run = lambda a: ex.run_tool(client, "brand_search_alerts", a)  # noqa: E731
    out = run({"queue_state": "needs_confirmation, in_review", "severity": "HIGH", "limit": 500, "page": -3})
    assert out["status"] == "not_implemented"
    v = out["validated"]
    assert v["queue_state"] == ["needs_confirmation", "in_review"] and v["severity"] == ["high"]
    assert v["limit"] == c.MAX_LIMIT and v["page"] == 0 and v["sort"] == "newest"
    for bad in ({"queue_state": "resolved"}, {"product": "domains,email"}, {"product": "tv"}, {"sort": "random"},
                {"created_after": "last tuesday"}, {"severity": "urgent"}, {"limit": "lots"}, {"search_key": "x" * 400}):
        assert run(bad)["status"] == "invalid_input", bad
    assert run({"lookback_days": 3})["validated"]["lookback_days"] == 3
    assert run({"lookback_days": 3, "created_after": "2026-11-01"})["validated"]["lookback_days"] is None


@pytest.mark.parametrize("url,normalised", [
    ("yourbrand-careers-login.net", "https://yourbrand-careers-login.net"),
    ("hxxps://login-yourbrand[.]co/path?q=1", "https://login-yourbrand.co/path?q=1"),
    ("http://203.0.113.0.example-cdn.net:8080/x", "http://203.0.113.0.example-cdn.net:8080/x"),
    ("<https://Login-YourBrand.co/>", "https://login-yourbrand.co/"),
    ("8.8.8.8", "https://8.8.8.8"),
])
def test_scan_url_normalisation(client, url, normalised):
    assert c.check_scan_url(url) == normalised
    out = ex.run_tool(client, "brand_submit_scan", {"url": url})
    assert out["status"] == "not_implemented" and out["validated"]["url"] == normalised


@pytest.mark.parametrize("url,status", [
    ("acme.example", "refused"), ("https://jobs.acme.example/apply", "refused"), ("acme.link.example", "refused"),
    ("https://mail.acme-mail.example", "refused"),
    ("https://user:pass@login-yourbrand.co", "invalid_input"), ("https://user@login-yourbrand.co", "invalid_input"),
    ("http://10.1.2.3/admin", "refused"), ("192.168.0.1", "refused"), ("127.0.0.1", "refused"),
    ("http://169.254.169.254/latest", "refused"), ("localhost", "refused"), ("http://[::1]/", "invalid_input"),
    ("intranet.corp", "refused"), ("wiki.internal", "refused"), ("host.local", "refused"), ("evil.test", "refused"),
    ("example.com", "invalid_input"), ("www.example.org", "invalid_input"), ("evil.com", "invalid_input"),
    ("ftp://files.yourbrand-login.net", "invalid_input"), ("javascript:alert(1)", "invalid_input"),
    ("nodot", "invalid_input"), ("", "invalid_input"), ("bad host.net", "invalid_input"),
    ("https://" + "a" * 2000 + ".net", "invalid_input"),
])
def test_scan_url_guardrails(client, url, status):
    assert ex.run_tool(client, "brand_submit_scan", {"url": url})["status"] == status
    with pytest.raises(c.ScanUrlRejected) as e:
        c.check_scan_url(url)
    assert e.value.status == status


def test_scan_associated_urls(client):
    run = lambda a: ex.run_tool(client, "brand_submit_scan", a)  # noqa: E731
    out = run({"url": "login-yourbrand.co", "associated_urls": "login-yourbrand.co, cdn-yourbrand.net/kit.js"})
    assert out["validated"]["associated_urls"] == ["https://cdn-yourbrand.net/kit.js"]
    assert run({"url": "login-yourbrand.co", "associated_urls": ["ok-site.net", "10.0.0.1"]})["status"] == "refused"
    assert run({"url": "login-yourbrand.co", "associated_urls": "acme.example"})["status"] == "refused"
    many = ",".join(f"site{i}.net" for i in range(c.MAX_ASSOCIATED + 1))
    assert run({"url": "login-yourbrand.co", "associated_urls": many})["status"] == "invalid_input"


def test_scan_result_validation(client):
    run = lambda a: ex.run_tool(client, "brand_get_scan_result", a)  # noqa: E731
    out = run({"scan_id": "scan_8f3a2b1c", "max_wait_seconds": 999})
    assert out["status"] == "not_implemented" and out["validated"]["max_wait_seconds"] == c.MAX_WAIT
    for bad in ("", "https://evil.net", "evil.net/x", "scan_id", "aaaaaaaa", "short", "has space here", "x" * 65):
        assert run({"scan_id": bad})["status"] == "invalid_input", bad


# --- write -----------------------------------------------------------------------------------------------------------

A = {"alert_id": "ABC-37157", "state": "archived", "note": NOTE}
AUTO = {**A, "mode": "auto", "verdict": "false_positive", "confidence": 99}


@pytest.mark.parametrize("name", sorted(c.WRITE_TOOL_NAMES) + ["nope"])
def test_run_write_tool_never_raises(writer, name):
    for args in GARBAGE + [{}]:
        for req in ("", REQ):
            out = exw.run_write_tool(writer, name, args, req)
            assert isinstance(out, dict) and out.get("status") and out["written"] in (False, None)


def test_update_refuses_without_requester(writer):
    for req in ("", None, "  "):
        out = exw.run_write_tool(writer, "brand_update_alert", A, req)
        assert out["status"] == "refused" and out["written"] is False


def test_update_valid_and_comment(writer):
    out = exw.run_write_tool(writer, "brand_update_alert", {**A, "note": NOTE + " Requested by Bob Smith."}, REQ)
    assert out["status"] == "not_implemented" and out["written"] is False and out["requested_by"] == REQ
    assert out["comment"].startswith(f"[Jarvis] archived - close requested by {REQ}") and "Bob" not in out["comment"]
    out = exw.run_write_tool(writer, "brand_update_alert", {**A, "state": "taken_down"}, REQ)
    assert out["comment"].startswith("[Jarvis] taken_down")
    req = c.auto_requester("U00000000B1")
    out = exw.run_write_tool(writer, "brand_update_alert", AUTO, req)
    assert out["status"] == "not_implemented" and "99% confidence (automatic" in out["comment"]
    out = exw.run_write_tool(writer, "brand_update_alert", {**A, "alert_id": f"{CONSOLE}/alerts/ABC-37157"}, REQ)
    assert out["alert_id"] == "ABC-37157"


@pytest.mark.parametrize("patch,status", [
    ({"state": ""}, "invalid_input"), ({"state": "monitoring"}, "refused"), ({"state": "in_review"}, "refused"),
    ({"state": "open"}, "refused"), ({"note": "too short"}, "invalid_input"),
    ({"note": "test " + "x" * 30}, "invalid_input"), ({"note": "Requested by Bob Smith"}, "invalid_input"),
    ({"mode": "yolo"}, "invalid_input"), ({"mode": "auto"}, "invalid_input"),
    ({"mode": "auto", "verdict": "malicious"}, "refused"), ({"mode": "auto", "state": "taken_down",
                                                             "verdict": "false_positive"}, "refused"),
    ({"alert_id": "ABC-1,ABC-2"}, "invalid_input"), ({"alert_id": "https://evil.net/ABC-1"}, "invalid_input"),
])
def test_update_rejects(writer, patch, status):
    out = exw.run_write_tool(writer, "brand_update_alert", {**A, **patch}, REQ)
    assert out["status"] == status and out["written"] is False


# --- automatic actions -----------------------------------------------------------------------------------------------

ALLOWED = frozenset({"ABC-37157"})


@pytest.mark.parametrize("args", [AUTO, {**AUTO, "confidence": 98}, {**AUTO, "confidence": "98.5"},
                                  {**AUTO, "alert_id": "abc-37157"},
                                  {**AUTO, "alert_id": f"{CONSOLE}/domains/ABC-37157"}])
def test_auto_check_accepts(args):
    assert c.auto_check("brand_update_alert", args, ALLOWED) == (["brand|archive|ABC-37157"], None)
    assert exw.auto_check is c.auto_check


@pytest.mark.parametrize("name,args", [
    ("brand_update_alert", {**AUTO, "confidence": 97.9}), ("brand_update_alert", {**AUTO, "confidence": None}),
    ("brand_update_alert", {**AUTO, "confidence": True}), ("brand_update_alert", {**AUTO, "mode": "analyst_requested"}),
    ("brand_update_alert", {**AUTO, "verdict": "benign"}), ("brand_update_alert", {**AUTO, "state": "taken_down"}),
    ("brand_update_alert", {**AUTO, "alert_id": "ABC-1"}), ("brand_update_alert", {**AUTO, "alert_id": ""}),
    ("brand_update_alert", {**AUTO, "alert_id": "https://evil.net/x/ABC-37157x"}),
    ("brand_update_alert", {k: v for k, v in AUTO.items() if k != "state"} | {"queue_state": "archived"}),
    ("brand_get_alert", AUTO), ("brand_update_alert", None),
])
def test_auto_check_refuses(name, args):
    keys, why = c.auto_check(name, args, ALLOWED)
    assert keys is None and why


def test_auto_payload_tools_requester():
    assert c.auto_payload("brand_update_alert", AUTO) == AUTO and c.auto_payload("x", None) == {}
    assert c.auto_requester("U00000000B1") == "U00000000B1 (alert bot, automatic)"
    assert [t["name"] for t in c.auto_tools()] == ["brand_update_alert"]
    assert c.auto_tools()[0]["description"].startswith("AUTOMATIC ARCHIVE ONLY")


def test_make_auto_id_pattern():
    pat = c.make_auto_id_pattern(CONSOLE)
    post = (f"New alert {CONSOLE}/domains/ABC-37157 (lookalike) and <{CONSOLE}/alerts/XYZ-9|XYZ-9>; "
            "elsewhere https://brand.example.test/alerts/DEF-1 https://console.brand.example.test.evil.net/a/DEF-2 "
            f"bare GHI-3, {CONSOLE}/alerts/JKL-4/history {CONSOLE}/alerts/MNO-5.")
    assert [m.group(1) for m in pat.finditer(post)] == ["ABC-37157", "XYZ-9", "MNO-5"]
    assert [m.group(1) for m in exw.AUTO_ID_PATTERN.finditer(post)] == ["ABC-37157", "XYZ-9", "MNO-5"]
    for unset in (None, "", "nonsense value"):
        assert list(c.make_auto_id_pattern(unset).finditer(post)) == []
