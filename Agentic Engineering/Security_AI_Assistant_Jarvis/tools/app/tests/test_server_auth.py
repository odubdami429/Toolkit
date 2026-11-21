"""server.py: jarvis_auth (signing, alert-post hash, replay), the requester binding, per-domain write gating,
automatic actions on alert-bot posts, specialist assembly and the MCP surface.

These test the SERVER, not an adapter. Where real product behaviour matters (a write that succeeds, a read that
records its context) a fake writer or read function is injected with monkeypatch; where the example adapters'
validation and `not_implemented` answers suffice, the real example adapters (configured by conftest) are used.
Alert posts are built from the configured <PREFIX>_CONSOLE_URL; IDs anywhere else must never count.

Runs where server.py can find specialists/ (the image's /app, or the staged test dir)."""

from __future__ import annotations

import codecs
import dataclasses
import hashlib
import hmac
import json
import logging
import os
import re
import time
from pathlib import Path

import pytest

import server

WRITER, READER, WRITER2 = "U00000000A1", "U00000000C1", "U00000000A2"  # READER is allowlisted but not a writer
BOT = "U00000000B1"
EMAIL = "pat.writer@acme.example"
REQUESTER = f"{EMAIL} ({WRITER})"
SESSION = "agent:main:slack:dm:T00000000:D1"
JUST = "Confirmed malware on this host by the analyst; ticket SEC-1 has the evidence."


def signed(tool="enterprise_search", actor=WRITER, email=EMAIL, call_id=None, ts=None, alert_post=""):
    call_id = call_id or os.urandom(6).hex()
    ts = int(time.time()) if ts is None else ts
    msg = "|".join([tool, actor, SESSION, call_id, str(ts), email,
                    hashlib.sha256(alert_post.encode()).hexdigest()]).encode()
    return {"actor": actor, "actor_email": email, "alert_post": alert_post, "session_key": SESSION,
            "tool_call_id": call_id, "ts": ts, "sig": hmac.new(server.HMAC_KEY, msg, hashlib.sha256).hexdigest()}


def run(coro_fn, *args):
    return server.anyio.run(coro_fn, *args)


# Vendor names that must never reach the model-facing surface or these modules (rot13: this file stays clean too).
_BANNED_WORDS = [codecs.decode(w, "rot13") for w in (
    "fragvary", "bxgn", "tbbtyr", "fhoyvzr", "qbccry", "pbqr42", "vaplqe", "ngynffvna", "wven", "pbasyhrapr",
    "cbjredhrel", "qrrc ivfvovyvgl", "fgbelyvar", "ergbby", "pebjqfgevxr")]
_BANNED_SHORT = [codecs.decode(w, "rot13") for w in ("tjf", "wdy", "pdy", "fqy", "zdy", "f1", "tyrna")]
_VENDOR = re.compile("|".join([re.escape(w) for w in _BANNED_WORDS]
                              + [r"\b" + re.escape(w) + r"\b" for w in _BANNED_SHORT]), re.I)


# --- verify_auth --------------------------------------------------------------------------------------------------

def test_valid_signature_with_email():
    assert server.verify_auth("enterprise_search", signed()) == (WRITER, None)


def test_email_is_covered_by_the_signature():
    auth = signed()
    auth["actor_email"] = "ceo@acme.example"
    assert server.verify_auth("enterprise_search", auth)[1] == "bad jarvis_auth signature"


def test_actor_session_and_ts_are_covered_by_the_signature():
    for field, value in (("actor", WRITER2), ("session_key", SESSION + "x"), ("ts", int(time.time()) + 1),
                         ("tool_call_id", "other-call")):
        auth = signed()
        auth[field] = value
        assert server.verify_auth("enterprise_search", auth)[1] == "bad jarvis_auth signature", field


def test_alert_post_is_covered_by_the_signature():
    auth = signed("ask_edr_specialist", actor=BOT, email="", alert_post="threat 1")
    assert server.verify_auth("ask_edr_specialist", auth) == (BOT, None)
    forged = signed("ask_edr_specialist", actor=BOT, email="", alert_post="threat 1")
    forged["alert_post"] = "threat 1 and threat 2"
    assert server.verify_auth("ask_edr_specialist", forged)[1] == "bad jarvis_auth signature"
    missing = signed("ask_edr_specialist", actor=BOT, email="", alert_post="threat 1")
    del missing["alert_post"]
    assert server.verify_auth("ask_edr_specialist", missing)[1] == "bad jarvis_auth signature"


def test_alert_post_is_signed_as_its_sha256():
    post = "New alert https://console.edr.example.test/alerts/ABCDE12345"
    auth = signed("ask_edr_specialist", actor=BOT, email="", alert_post=post)
    msg = "|".join(["ask_edr_specialist", BOT, SESSION, auth["tool_call_id"], str(auth["ts"]), "",
                    hashlib.sha256(post.encode()).hexdigest()]).encode()
    assert auth["sig"] == hmac.new(b"test-hmac-key", msg, hashlib.sha256).hexdigest()
    raw = dict(auth, sig=hmac.new(b"test-hmac-key", msg.replace(hashlib.sha256(post.encode()).hexdigest().encode(),
                                                                 post.encode()), hashlib.sha256).hexdigest())
    assert server.verify_auth("ask_edr_specialist", raw)[1] == "bad jarvis_auth signature"  # raw post: not accepted
    assert server.verify_auth("ask_edr_specialist", auth) == (BOT, None)


def test_empty_post_signs_hash_of_empty_string():
    auth = signed(tool="search_tickets", email="")
    del auth["alert_post"]  # absent and "" are the same: sha256 of ""
    assert server.verify_auth("search_tickets", auth)[1] is None


def test_wrong_key_wrong_tool_stale_and_replay():
    auth = signed()
    msg = "|".join(["enterprise_search", WRITER, SESSION, auth["tool_call_id"], str(auth["ts"]), EMAIL,
                    hashlib.sha256(b"").hexdigest()]).encode()
    auth["sig"] = hmac.new(b"some-other-key", msg, hashlib.sha256).hexdigest()
    assert server.verify_auth("enterprise_search", auth)[1] == "bad jarvis_auth signature"
    assert server.verify_auth("search_tickets", signed())[1] == "bad jarvis_auth signature"
    assert server.verify_auth("enterprise_search", signed(ts=int(time.time()) - 3600))[1] == "stale jarvis_auth"
    assert server.verify_auth("enterprise_search", signed(ts=int(time.time()) + 3600))[1] == "stale jarvis_auth"
    auth = signed(call_id="fixed-call-id")
    assert server.verify_auth("enterprise_search", auth)[1] is None
    assert server.verify_auth("enterprise_search", auth)[1] == "replayed jarvis_auth"
    # A fresh signature cannot reuse a spent call ID either.
    assert server.verify_auth("enterprise_search", signed(call_id="fixed-call-id"))[1] == "replayed jarvis_auth"


def test_missing_and_incomplete_auth():
    assert server.verify_auth("enterprise_search", None)[1].startswith("missing")
    assert server.verify_auth("enterprise_search", "not a dict")[1].startswith("missing")
    for field in ("actor", "session_key", "tool_call_id", "ts", "sig"):
        auth = signed()
        del auth[field]
        assert server.verify_auth("enterprise_search", auth)[1] == "incomplete jarvis_auth", field
    auth = signed()
    auth["ts"] = str(auth["ts"])
    assert server.verify_auth("enterprise_search", auth)[1] == "incomplete jarvis_auth"


def test_refused_call_never_reaches_the_specialist(monkeypatch, caplog):
    called = []
    monkeypatch.setattr(server, "run_specialist", lambda *a, **k: called.append(a) or "ran")
    bad = signed("ask_idp_specialist")
    bad["sig"] = "0" * 64
    with caplog.at_level(logging.INFO, logger="jarvis_tools"):
        out = json.loads(run(server._run_specialist, "ask_idp_specialist", server.SPECIALISTS["idp"], "q", "", bad))
    assert out["status"] == "refused" and out["reason"] == "bad jarvis_auth signature" and called == []
    assert any('"jarvis_tools": "refused"' in r.getMessage() for r in caplog.records)


def test_direct_caps_per_thread():
    key = "agent:main:slack:dm:T00000000:CAPTEST"
    assert [server._direct_budget_ok(key, "enterprise_chat") for _ in range(3)] == [True, True, False]
    assert server._direct_budget_ok(key + "-other", "enterprise_chat") is True
    assert server.DIRECT_CAPS == {"search_tickets": 6, "get_ticket_details": 6, "search_wiki": 4,
                                  "get_wiki_page_details": 6, "enterprise_search": 4, "enterprise_chat": 2,
                                  "enterprise_read_document": 3}


def test_direct_budget_exceeded_is_reported(monkeypatch):
    monkeypatch.setattr(server, "_direct_calls", {})
    outs = [json.loads(run(server.enterprise_chat, "hi", signed("enterprise_chat"))) for _ in range(3)]
    assert [o["status"] for o in outs[:2]] != ["budget_exceeded"] * 2
    assert outs[2]["status"] == "budget_exceeded" and "2 per 10 minutes" in outs[2]["message"]


# --- registry and tool surface ------------------------------------------------------------------------------------

SPECIALIST_TOOLS = {"ask_edr_specialist", "ask_idp_specialist", "ask_suite_specialist",
                    "ask_email_security_specialist", "ask_brand_protection_specialist", "ask_insider_risk_specialist",
                    "ask_web_research"}
DIRECT_TOOLS = set(server.DIRECT_CAPS)
WRITE_NAMES = {
    "edr": {"edr_close_alert", "edr_add_hash_exclusion", "edr_add_hash_blocklist", "edr_add_path_exclusion",
            "edr_network_contain", "edr_initiate_scan"},
    "idp": {"idp_set_user_suspension", "idp_clear_user_sessions"},
    "productivity_suite": {"suite_revoke_token", "suite_sign_out_user"},
    "email_security": {"email_action_message", "email_block_sender"},
    "brand_protection": {"brand_update_alert"},
    "insider_risk": {"irm_close_alert"}}


def _mcp_tools():
    return {t.name: t for t in run(server.mcp.list_tools)}


def _all_model_facing_tools() -> list[dict]:
    tools = []
    for spec in server.SPECIALISTS.values():
        tools += [t for t in spec.tools if "description" in t]
    for dw in server.DOMAIN_WRITES.values():
        tools += dw.tools + dw.list_tools + (dw.module.auto_tools() if dw.can_auto_act else [])
    return tools


def test_every_tool_is_registered():
    assert set(_mcp_tools()) == SPECIALIST_TOOLS | DIRECT_TOOLS


def test_tool_names_and_descriptions_are_vendor_neutral():
    mcp = _mcp_tools()
    names = set(mcp) | {t["name"] for spec in server.SPECIALISTS.values() for t in spec.tools}
    texts = [t.description or "" for t in mcp.values()] + [json.dumps(t) for t in _all_model_facing_tools()]
    texts += [server.NO_ENTERPRISE_SEARCH_NOTE, server.mcp.instructions or "", json.dumps(server.NO_ACT_AS)]
    texts += [dw.module.AUTO_NOTE for dw in server.DOMAIN_WRITES.values() if dw.can_auto_act]
    assert names and not [n for n in names if _VENDOR.search(n)]
    assert not [m.group(0) for t in texts if (m := _VENDOR.search(t))]


def test_server_modules_are_vendor_neutral():
    here = Path(server.__file__).resolve().parent
    for f in ("server.py", "specialist.py", "web_tools.py"):
        text = (here / f).read_text(encoding="utf-8")
        assert not [m.group(0) for m in _VENDOR.finditer(text)], f
        assert "vendor" + "_call" not in text, f  # the audit event is tool_call


def test_specialist_tool_descriptions_offer_writes():
    tools = _mcp_tools()
    for name in SPECIALIST_TOOLS - {"ask_web_research"}:
        assert "authorized writers" in tools[name].description and "read-only" not in tools[name].description.lower()
    assert "Read-only" in tools["ask_web_research"].description


def test_direct_tool_parameters_and_descriptions():
    tools = _mcp_tools()
    params = {n: set(tools[n].input_schema["properties"]) - {"jarvis_auth"} for n in DIRECT_TOOLS}
    assert params == {"search_tickets": {"query"}, "get_ticket_details": {"ticket_key"}, "search_wiki": {"query"},
                      "get_wiki_page_details": {"page_id"}, "enterprise_search": {"query"},
                      "enterprise_chat": {"message"}, "enterprise_read_document": {"url", "id"}}
    adapter = {t["name"]: t["description"] for t in server.TICKETING_TOOLS + server.ENTERPRISE_SEARCH_TOOLS}
    assert set(adapter) == DIRECT_TOOLS
    for n in DIRECT_TOOLS:  # the configured adapter's description (it documents its query syntax), marked read-only
        assert tools[n].description == "Read-only. " + adapter[n]


def test_direct_description_fallback_when_a_domain_is_off(monkeypatch):
    monkeypatch.setattr(server, "TICKETING_TOOLS", [])
    monkeypatch.setattr(server, "ENTERPRISE_SEARCH_TOOLS", [])
    for n in DIRECT_TOOLS:
        assert server._direct_description(n) == server._DIRECT_FALLBACK[n]
        assert not _VENDOR.search(server._DIRECT_FALLBACK[n])


def test_specialists_by_domain():
    assert set(server.SPECIALISTS) == {"edr", "idp", "productivity_suite", "email_security", "brand_protection",
                                       "insider_risk", "web_research"}
    assert {k: s.max_iterations for k, s in server.SPECIALISTS.items()} == {
        "edr": 50, "idp": 30, "productivity_suite": 30, "email_security": 30, "brand_protection": 40,
        "insider_risk": 40, "web_research": 10}
    assert server.SPECIALISTS["web_research"].title == "Web research"
    for k, s in server.SPECIALISTS.items():
        if k != "web_research":
            assert s.title == server.providers.DOMAINS[k].title
    internal = {"search_tickets", "get_ticket_details", "search_wiki", "get_wiki_page_details", "enterprise_search",
                "enterprise_chat", "enterprise_read_document"}
    for k in ("edr", "brand_protection", "insider_risk"):
        s = server.SPECIALISTS[k]
        names = [t["name"] for t in s.tools]
        assert len(names) == len(set(names)), k
        assert internal | {"web_search", "web_fetch"} <= set(names)
        assert s.acts_as_requester and s.internal_tools == internal
        assert set(server.ADAPTERS[k].read.TOOL_NAMES) <= set(names)
    assert "irm_check_ai_entitlement" in {t["name"] for t in server.SPECIALISTS["insider_risk"].tools}
    for k in ("idp", "productivity_suite", "email_security"):
        s = server.SPECIALISTS[k]
        assert not s.acts_as_requester and not s.internal_tools
        assert {t["name"] for t in s.tools} == set(server.ADAPTERS[k].read.TOOL_NAMES)
    assert {t["name"] for t in server.SPECIALISTS["web_research"].tools} == {"web_search", "web_fetch"}
    # Specialists get the adapter's tools (with the adapter's query-language primer), never write tools by default.
    edr_query = next(t for t in server.SPECIALISTS["edr"].tools if t["name"] == "edr_query")
    assert edr_query == next(t for t in server.ADAPTERS["edr"].read.TOOLS if t["name"] == "edr_query")
    for k, names in WRITE_NAMES.items():
        assert not names & {t["name"] for t in server.SPECIALISTS[k].tools}


def test_specialist_prompts_are_fully_rendered():
    for k, spec in server.SPECIALISTS.items():
        assert spec.prompt and "{{" not in spec.prompt and "}}" not in spec.prompt, k
        base = server.org.render((server.HERE / "specialists" / k / "prompt.md").read_text(encoding="utf-8"))
        ad = server.ADAPTERS.get(k)
        addendum = server.HERE / "specialists" / k / "providers" / f"{ad.provider}.md" if ad else None
        if addendum is not None and addendum.is_file():
            assert spec.prompt == base + "\n\n" + server.org.render(addendum.read_text(encoding="utf-8")), k
        else:
            assert spec.prompt == base, k
    assert server.org.ORG_NAME == "Acme Corp" and "Acme Corp" in server.SPECIALISTS["brand_protection"].prompt


def test_prompt_adds_only_the_configured_providers_addendum(monkeypatch, tmp_path):
    root = tmp_path / "specialists"
    (root / "edr" / "providers").mkdir(parents=True)
    (root / "edr" / "prompt.md").write_text("You are the EDR specialist for {{ORG_NAME}}.", encoding="utf-8")
    (root / "edr" / "providers" / "example.md").write_text("Query primer for {{ORG_NAME}}.", encoding="utf-8")
    (root / "edr" / "providers" / "other.md").write_text("Never included.", encoding="utf-8")
    (root / "web_research").mkdir()
    (root / "web_research" / "prompt.md").write_text("Web for {{ORG_NAME}}.", encoding="utf-8")
    monkeypatch.setattr(server, "HERE", tmp_path)
    assert server.ADAPTERS["edr"].provider == "example"
    assert server._prompt("edr") == "You are the EDR specialist for Acme Corp.\n\nQuery primer for Acme Corp."
    assert server._prompt("web_research") == "Web for Acme Corp."
    monkeypatch.setitem(server.ADAPTERS, "edr", None)  # domain off: base prompt only
    assert server._prompt("edr") == "You are the EDR specialist for Acme Corp."
    monkeypatch.undo()
    monkeypatch.setattr(server, "HERE", tmp_path)
    (root / "edr" / "providers" / "example.md").unlink()  # no addendum for this provider
    assert server._prompt("edr") == "You are the EDR specialist for Acme Corp."
    (root / "edr" / "providers" / "example.md").write_text("{{NOT_A_PLACEHOLDER}}", encoding="utf-8")
    with pytest.raises(KeyError):  # a typo fails at startup, never reaches the model
        server._prompt("edr")


def test_writers_come_from_env_and_exclude_the_trigger_bot():
    writers = {w.strip() for w in os.environ["JARVIS_WRITERS"].split(",") if w.strip()}
    assert writers and server.WRITE_AUTHORIZED == writers
    assert server.AUTO_ACTORS == {os.environ["JARVIS_TRIGGER_BOTS"]} == {BOT}
    assert not server.WRITE_AUTHORIZED & server.AUTO_ACTORS
    assert READER not in server.WRITE_AUTHORIZED and WRITER in server.WRITE_AUTHORIZED
    # Both switches default off: only the literal "true" turns them on.
    assert server.WRITES_ENABLED is False and server.AUTO_ENABLED is False


def test_write_surface_by_domain():
    assert {k: {t["name"] for t in v.tools} for k, v in server.DOMAIN_WRITES.items()} == WRITE_NAMES
    lists = {k: {t["name"] for t in v.list_tools} for k, v in server.DOMAIN_WRITES.items() if v.list_tools}
    assert lists == {"productivity_suite": {"suite_list_tokens"}}
    assert {k for k, v in server.DOMAIN_WRITES.items() if v.can_auto_act} == {
        "edr", "email_security", "brand_protection", "insider_risk"}


def test_example_adapters_are_configured_from_env():
    """conftest configures every domain with the example adapter, so every client and writer exists."""
    for k in server.providers.DOMAINS:
        assert server.ADAPTERS[k] is not None and server.ADAPTERS[k].provider == "example", k
        assert server.CLIENTS[k] is not None and server._available(k), k
    for k, dw in server.DOMAIN_WRITES.items():
        assert dw.writer is not None, k
    assert server._available(server.WEB)


def test_partial_auto_hooks_mean_no_automatic_actions():
    dw = server.DOMAIN_WRITES["edr"]
    partial = type("M", (), {"auto_check": staticmethod(lambda *a: (["k"], None))})
    assert not dataclasses.replace(dw, module=partial).can_auto_act
    assert dw.can_auto_act


# --- helpers for specialist requests -------------------------------------------------------------------------------

@pytest.fixture
def clean(monkeypatch):
    monkeypatch.setattr(server, "_auto_done", {})
    monkeypatch.setattr(server, "_direct_calls", {})
    return monkeypatch


class FakeWriter:
    def __init__(self):
        self.calls = []


def fake_writes(monkeypatch, domain, status="ok", enable=True):
    """A writer that records every call and reports success: stands in for a real product's write adapter."""
    w = FakeWriter()

    def run(writer, name, args, requester):
        writer.calls.append((name, args, requester))
        return {"status": status, "written": True}

    monkeypatch.setitem(server.DOMAIN_WRITES, domain, dataclasses.replace(server.DOMAIN_WRITES[domain], writer=w,
                                                                           run=run))
    if enable:
        monkeypatch.setattr(server, "WRITES_ENABLED", True)
    return w


def fake_reads(monkeypatch, domain="edr"):
    """Replace the specialist's read router with one that echoes what it was given."""
    spec = dataclasses.replace(server.SPECIALISTS[domain],
                               run_tool=lambda n, a, act_as="", requester="": {"status": "ok", "read": n,
                                                                                "act_as": act_as,
                                                                                "requester": requester})
    monkeypatch.setitem(server.SPECIALISTS, domain, spec)
    return spec


def record_reads(monkeypatch, domain):
    """Replace the domain adapter's run_tool with one recording (name, args, context keywords)."""
    got = []

    def fake(client, name, args, **ctx):
        got.append((name, args, ctx))
        return {"status": "ok"}

    monkeypatch.setattr(server.ADAPTERS[domain].read, "run_tool", fake)
    return got


def ask(monkeypatch, domain, actor=WRITER, email=EMAIL, alert_post="", tool=None):
    """Run a specialist request with the model loop stubbed; returns what the loop would have been given."""
    seen = {}

    def fake_run_specialist(s, question, context, a, request_id, *, note=""):
        seen.update(names={t["name"] for t in s.tools}, tools={t["name"]: t for t in s.tools}, run=s.run_tool,
                    note=note, spec=s, actor=a)
        return "ok"

    monkeypatch.setattr(server, "run_specialist", fake_run_specialist)
    tool = tool or next(n for n, (d, _) in server.SPECIALIST_TOOLS.items() if d == domain)
    auth = signed(tool, actor=actor, email=email, alert_post=alert_post)
    seen["out"] = run(server._run_specialist, tool, server.SPECIALISTS[domain], "q", "", auth)
    return seen


# --- unconfigured domains -----------------------------------------------------------------------------------------

def test_unconfigured_domain_returns_not_configured(monkeypatch):
    for domain in server.SPECIALIST_DOMAINS:
        monkeypatch.setitem(server.CLIENTS, domain, None)
    called = []
    monkeypatch.setattr(server, "run_specialist", lambda *a, **k: called.append(a) or "ran")
    for tool, (domain, _) in server.SPECIALIST_TOOLS.items():
        if domain == "web_research":
            continue
        out = json.loads(run(server._run_specialist, tool, server.SPECIALISTS[domain], "q", "", signed(tool)))
        title = server.providers.DOMAINS[domain].title
        assert out == {"status": "error", "error": f"{title} is not configured on this host",
                       "next_step": f"Say the {title} specialist is unavailable; never invent results."}
    assert called == []
    # Auth is still checked first.
    out = json.loads(run(server._run_specialist, "ask_edr_specialist", server.SPECIALISTS["edr"], "q", "", None))
    assert out["status"] == "refused"


def test_disabled_adapter_is_not_configured(monkeypatch):
    monkeypatch.setitem(server.ADAPTERS, "idp", None)
    out = json.loads(run(server._run_specialist, "ask_idp_specialist", server.SPECIALISTS["idp"], "q", "",
                         signed("ask_idp_specialist")))
    assert "not configured" in out["error"]
    assert "not configured" in server._domain_read("idp", "idp_get_user", {"user": "a@acme.example"})["error"]


def test_unconfigured_internal_tools_inside_a_specialist(monkeypatch):
    monkeypatch.setitem(server.CLIENTS, "ticketing", None)
    monkeypatch.setitem(server.CLIENTS, "enterprise_search", None)
    r = server._specialist_read("edr", "search_tickets", {"query": "x"}, act_as=EMAIL)
    assert r["status"] == "error" and "Ticketing and wiki is not configured" in r["error"]
    r = server._specialist_read("edr", "enterprise_search", {"query": "x"}, act_as=EMAIL)
    assert r["status"] == "error" and "Enterprise search is not configured" in r["error"]


def test_unconfigured_direct_tool(monkeypatch):
    monkeypatch.setitem(server.CLIENTS, "ticketing", None)
    out = json.loads(run(server._run_direct, "search_tickets", {"query": "x"}, signed("search_tickets")))
    assert out["status"] == "error" and "not configured" in out["error"]
    monkeypatch.setitem(server.CLIENTS, "enterprise_search", None)
    out = json.loads(run(server.enterprise_chat, "hi", signed("enterprise_chat")))
    assert out["status"] == "error" and "not configured" in out["error"]
    out = json.loads(run(server.enterprise_chat, "hi", None))
    assert out["status"] == "refused"


def test_mcp_specialist_tool_runs_through_auth(monkeypatch):
    monkeypatch.setitem(server.CLIENTS, "edr", None)
    out = json.loads(run(server.ask_edr_specialist, "q", "", signed("ask_edr_specialist")))
    assert "not configured" in out["error"]
    out = json.loads(run(server.ask_edr_specialist, "q", "", signed("ask_idp_specialist")))  # signed for another tool
    assert out["status"] == "refused"


def test_web_research_needs_no_client(monkeypatch):
    for k in server.providers.DOMAINS:
        monkeypatch.setitem(server.CLIENTS, k, None)
    seen = ask(monkeypatch, "web_research", tool="ask_web_research")
    assert seen["out"] == "ok" and seen["names"] == {"web_search", "web_fetch"} and seen["note"] == ""
    assert seen["run"]("anything", {})["status"] == "error"


# --- reads: routing and the requester binding --------------------------------------------------------------------

def test_reads_route_to_the_example_adapters():
    """With the example adapters the server returns their validation and not_implemented answers unchanged."""
    r = server._domain_read("edr", "edr_get_alert", {})
    assert r["status"] == "invalid_input"
    r = server._domain_read("edr", "edr_get_alert", {"threat_id": "https://console.edr.example.test/alerts/ABCDE12345"})
    assert r["status"] == "not_implemented" and r["tool"] == "edr_get_alert"
    assert r["validated"]["alert_ids"] == ["ABCDE12345"]
    for domain in server.SPECIALIST_DOMAINS:
        for t in server.SPECIALISTS[domain].tools:
            if "input_schema" in t:
                out = server._specialist_read(domain, t["name"], {}, act_as=EMAIL, requester=REQUESTER)
                assert isinstance(out, dict) and out.get("status"), (domain, t["name"])


def test_reads_get_only_their_domains_context(monkeypatch):
    """Only enterprise search gets act_as and only email security gets the requester; others get no context."""
    expected = {"edr": ("edr_get_alert", {}), "idp": ("idp_get_user", {}), "productivity_suite": ("suite_get_user", {}),
                "brand_protection": ("brand_get_alert", {}), "insider_risk": ("irm_get_alert", {}),
                "ticketing": ("search_tickets", {}), "email_security": ("email_get_message_eml",
                                                                         {"requester": REQUESTER}),
                "enterprise_search": ("enterprise_search", {"act_as": EMAIL})}
    for domain, (name, ctx) in expected.items():
        got = record_reads(monkeypatch, domain)
        assert server._domain_read(domain, name, {"x": 1}, act_as=EMAIL, requester=REQUESTER) == {"status": "ok"}
        assert got == [(name, {"x": 1}, ctx)], domain


def test_email_security_reads_carry_the_requester(clean):
    got = record_reads(clean, "email_security")
    seen = ask(clean, "email_security")
    seen["run"]("email_get_message_eml", {})
    assert got[-1][2] == {"requester": REQUESTER}
    seen = ask(clean, "email_security", actor=BOT, email="")
    seen["run"]("email_get_message_eml", {})
    assert got[-1][2] == {"requester": BOT}


def test_email_content_reads_reach_the_example_adapter_with_the_requester(clean):
    seen = ask(clean, "email_security")
    r = seen["run"]("email_get_analysis_report", {"message_id": "01a19cdd-ebcd-7cdd-b7e6-4c3790e8b98c",
                                                  "justification": "Analyst triage of a reported phish, SEC-1."})
    assert r["status"] == "not_implemented", r


def test_enterprise_search_acts_as_the_signed_requester(clean):
    got = record_reads(clean, "enterprise_search")
    for domain in ("edr", "brand_protection", "insider_risk"):
        seen = ask(clean, domain)
        assert seen["run"]("enterprise_search", {"query": "x"}) == {"status": "ok"}
    assert [(n, c) for n, _, c in got] == [("enterprise_search", {"act_as": EMAIL})] * 3
    out = json.loads(run(server.enterprise_search, "hash", signed("enterprise_search")))
    assert out == {"status": "ok"} and got[-1][2] == {"act_as": EMAIL}


def test_enterprise_search_through_the_example_adapter(clean):
    out = json.loads(run(server.enterprise_search, "hash", signed("enterprise_search")))
    assert out["status"] == "not_implemented" and out["acted_as"] == EMAIL
    out = json.loads(run(server.enterprise_read_document, "", "", signed("enterprise_read_document")))
    assert out["status"] == "invalid_input"


@pytest.mark.parametrize("who", ["", "  ", "pat@evil.example", "pat@sub.acme.example", "pat@acme-mail.example",
                                 "Pat.Writer@acme.example", "pat@acme.example ", "pat@acme.example.evil.example"])
def test_enterprise_search_refused_without_an_org_requester(clean, who):
    """The server refuses before the adapter is called, whatever the adapter would do."""
    got = record_reads(clean, "enterprise_search")
    for name, args in (("enterprise_search", {"query": "x"}), ("enterprise_chat", {"message": "x"}),
                       ("enterprise_read_document", {"url": "https://docs.example.test/1"})):
        r = server._specialist_read("edr", name, args, act_as=who)
        assert r["status"] == "refused" and "acts as the requester" in r["message"], (name, who)
        out = json.loads(run(server._run_direct, name, args, signed(name, email=who)))
        assert out["status"] == "refused", (name, who)
    assert got == []


def test_enterprise_search_refused_for_the_alert_bot(clean):
    got = record_reads(clean, "enterprise_search")
    out = json.loads(run(server.enterprise_search, "x", signed("enterprise_search", actor=BOT, email="")))
    assert out["status"] == "refused" and got == []
    seen = ask(clean, "edr", actor=BOT, email="")
    assert not seen["names"] & server.ENTERPRISE_SEARCH_TOOL_NAMES
    assert seen["run"]("enterprise_search", {"query": "x"})["status"] == "refused"  # even if the model calls it
    assert got == []


def test_ticketing_reads_route_to_the_ticketing_adapter(clean):
    got = record_reads(clean, "ticketing")
    seen = ask(clean, "brand_protection")
    seen["run"]("search_tickets", {"query": "q"})
    run(server.get_ticket_details, "SEC-1", signed("get_ticket_details"))
    assert [(n, a, c) for n, a, c in got] == [("search_tickets", {"query": "q"}, {}),
                                               ("get_ticket_details", {"ticket_key": "SEC-1"}, {})]


def test_ticketing_through_the_example_adapter(clean):
    out = json.loads(run(server.get_ticket_details, "SEC-1", signed("get_ticket_details")))
    assert out["status"] == "not_implemented"
    out = json.loads(run(server.get_ticket_details, "not a key", signed("get_ticket_details")))
    assert out["status"] == "invalid_input"


def test_domain_reads_route_to_the_domain_adapter(clean):
    got = record_reads(clean, "productivity_suite")
    seen = ask(clean, "productivity_suite", actor=READER, email="a@acme.example")
    assert {"suite_get_user", "suite_search_activity"} <= seen["names"]
    assert seen["run"]("suite_get_user", {"user": "a@acme.example"}) == {"status": "ok"}
    assert got == [("suite_get_user", {"user": "a@acme.example"}, {})]


def test_adapter_that_raises_or_returns_junk_is_contained(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("adapter bug")

    monkeypatch.setattr(server.ADAPTERS["edr"].read, "run_tool", boom)
    r = server._domain_read("edr", "edr_get_alert", {})
    assert r["status"] == "error" and "no usable result" in r["message"]
    for junk in (None, "text", {"no": "status"}, ["x"]):
        monkeypatch.setattr(server.ADAPTERS["edr"].read, "run_tool", lambda *a, j=junk, **k: j)
        assert server._domain_read("edr", "edr_get_alert", {})["status"] == "error"


def test_ai_entitlement_routed_to_the_idp_adapter(clean):
    # Unconfigured identity provider: unknown, never member.
    clean.setitem(server.CLIENTS, "idp", None)
    r = server._specialist_read("insider_risk", "irm_check_ai_entitlement", {"email": "a@acme.example"})
    assert r["result"] == "unknown" and r["status"] == "error"
    clean.setitem(server.ADAPTERS, "idp", None)
    clean.setitem(server.CLIENTS, "idp", object())
    assert server._specialist_read("insider_risk", "irm_check_ai_entitlement",
                                   {"email": "a@acme.example"})["result"] == "unknown"
    clean.undo()
    # The example adapter's user_groups is a stub: unknown with the reason.
    r = server._specialist_read("insider_risk", "irm_check_ai_entitlement", {"email": "a@acme.example"})
    assert r["result"] == "unknown" and "not implemented" in r["reason"]
    # A product's user_groups answers: member, through the IdP client (not the insider risk one).
    idp_client = server.CLIENTS["idp"]
    asked = []

    def user_groups(client, email):
        asked.append((client, email))
        return {"status": "ok", "email": email, "user_status": "ACTIVE", "groups": ["ai-assistant-users"],
                "truncated": False}

    clean.setattr(server.ADAPTERS["idp"].read, "user_groups", user_groups)
    seen = ask(clean, "insider_risk")
    r = seen["run"]("irm_check_ai_entitlement", {"email": "a@acme.example"})
    assert r["result"] == "member" and asked == [(idp_client, "a@acme.example")]
    # Only the insider risk specialist routes it.
    assert server._specialist_read("edr", "irm_check_ai_entitlement", {"email": "a@acme.example"})["status"] != "ok"


def test_no_enterprise_search_for_the_alert_bot(clean):
    for domain, read in (("edr", "edr_get_alert"), ("brand_protection", "brand_search_alerts"),
                         ("insider_risk", "irm_search_alerts")):
        seen = ask(clean, domain, actor=BOT, email="")
        assert not seen["names"] & server.ENTERPRISE_SEARCH_TOOL_NAMES
        assert {read, "search_tickets", "search_wiki"} <= seen["names"]
        assert f"started by the {server.org.ALERT_BOT_NAME}" in seen["note"]
        assert seen["note"].endswith(server.NO_ENTERPRISE_SEARCH_NOTE)
        # The prompt carries the check the note points to.
        assert "no-enterprise-search internal-context check" in " ".join(server.SPECIALISTS[domain].prompt.split())


def test_people_keep_enterprise_search(clean):
    for domain in ("edr", "brand_protection", "insider_risk"):
        seen = ask(clean, domain, actor=READER, email="a@acme.example")
        assert server.ENTERPRISE_SEARCH_TOOL_NAMES <= seen["names"] and seen["note"] == ""
    # A person without a signed email has nobody to act as: same as the alert bot, minus the alert-bot line.
    seen = ask(clean, "edr", actor=READER, email="")
    assert not seen["names"] & server.ENTERPRISE_SEARCH_TOOL_NAMES and seen["note"] == server.NO_ENTERPRISE_SEARCH_NOTE


# --- writes: generic gating ---------------------------------------------------------------------------------------

SID = "1063501912683821806_1789484488969_0"
MID = "01a19cdd-ebcd-7cdd-b7e6-4c3790e8b98c"
MID2 = "01a19cdd-aaaa-7cdd-b7e6-4c3790e8b98c"
NOTE = "Benign: signed internal updater, 99% confidence, ticket SEC-1."

# One valid analyst-requested write per domain: the example writers accept these (not_implemented) and fake writers
# record them.
WRITE_CASES = {
    "edr": ("edr_initiate_scan", {"endpoint": "HOST-0001", "justification": JUST}),
    "idp": ("idp_clear_user_sessions", {"user": "a@acme.example", "reason": JUST}),
    "productivity_suite": ("suite_sign_out_user", {"user": "a@acme.example", "reason": JUST}),
    "email_security": ("email_block_sender", {"sender_email": "a@evil-sender.net", "reason": JUST}),
    "brand_protection": ("brand_update_alert", {"alert_id": "ABC-1", "state": "taken_down", "note": NOTE}),
    "insider_risk": ("irm_close_alert", {"session_id": SID, "disposition": "true_positive", "note": NOTE}),
}


@pytest.mark.parametrize("domain", sorted(WRITE_CASES))
def test_writes_only_for_authorized_writers(clean, domain):
    w = fake_writes(clean, domain)
    fake_reads(clean, domain)
    name, args = WRITE_CASES[domain]
    seen = ask(clean, domain)
    assert WRITE_NAMES[domain] <= seen["names"]
    assert seen["run"](name, args)["status"] == "ok"
    assert w.calls == [(name, args, REQUESTER)]
    read = sorted(server.ADAPTERS[domain].read.TOOL_NAMES)[0]
    assert seen["run"](read, {})["read"] == read

    seen = ask(clean, domain, actor=READER, email="a@acme.example")
    assert not WRITE_NAMES[domain] & seen["names"]
    r = seen["run"](name, args)
    assert r["status"] == "refused" and "limited to authorized writers" in r["message"]
    assert len(w.calls) == 1


@pytest.mark.parametrize("domain", sorted(WRITE_CASES))
def test_writes_reach_the_example_writer_with_the_verified_requester(clean, domain):
    """The real example writers: the combined "email (Slack ID)" requester passes their requester gate, a valid
    write reaches the stub, and a requester the model writes into the arguments is ignored."""
    clean.setattr(server, "WRITES_ENABLED", True)
    name, args = WRITE_CASES[domain]
    seen = ask(clean, domain)
    r = seen["run"](name, {**args, "requested_by": "ceo@acme.example"})
    assert r["status"] == "not_implemented", r
    assert REQUESTER in json.dumps(r) and "ceo@acme.example" not in json.dumps(r)
    r = seen["run"](name, {})
    assert r["status"] in ("invalid_input", "refused"), r


def test_requester_without_email_is_the_actor(clean):
    w = fake_writes(clean, "edr")
    seen = ask(clean, "edr", email="")
    seen["run"]("edr_initiate_scan", {"endpoint": "H"})
    assert w.calls[0][2] == WRITER


def test_same_action_once_and_cap(clean):
    w = fake_writes(clean, "edr")
    seen = ask(clean, "edr")
    r = seen["run"]
    assert r("edr_initiate_scan", {"endpoint": "H1"})["status"] == "ok"
    again = r("edr_initiate_scan", {"endpoint": "H1"})
    assert again["status"] == "refused" and "already sent" in again["message"]
    for i in range(2, 2 + server.MAX_WRITES_PER_RUN - 1):
        assert r("edr_initiate_scan", {"endpoint": f"H{i}"})["status"] == "ok"
    assert "cap" in r("edr_initiate_scan", {"endpoint": "H99"})["message"]
    assert len(w.calls) == server.MAX_WRITES_PER_RUN
    # A new request starts a new budget.
    assert ask(clean, "edr")["run"]("edr_initiate_scan", {"endpoint": "H1"})["status"] == "ok"


def test_once_per_request_counts_refused_input_too(clean):
    """A write the adapter rejects still spends the action: the model can't loop on it."""
    clean.setattr(server, "WRITES_ENABLED", True)
    r = ask(clean, "edr")["run"]
    assert r("edr_initiate_scan", {"endpoint": "*"})["status"] == "invalid_input"
    assert r("edr_initiate_scan", {"endpoint": "*"})["status"] == "refused"


def test_kill_switch(clean):
    w = fake_writes(clean, "idp")
    clean.setattr(server, "WRITES_ENABLED", False)
    seen = ask(clean, "idp")
    assert not WRITE_NAMES["idp"] & seen["names"]
    assert seen["run"]("idp_set_user_suspension", {"user": "z"})["status"] == "refused"
    assert not server._can_write("idp", WRITER) and w.calls == []


def test_unconfigured_writer_adds_nothing(clean):
    clean.setattr(server, "WRITES_ENABLED", True)
    clean.setitem(server.DOMAIN_WRITES, "productivity_suite",
                  dataclasses.replace(server.DOMAIN_WRITES["productivity_suite"], writer=None))
    seen = ask(clean, "productivity_suite")
    assert not (WRITE_NAMES["productivity_suite"] | {"suite_list_tokens"}) & seen["names"]
    assert not server._can_write("productivity_suite", WRITER)
    assert seen["run"]("suite_revoke_token", {})["status"] == "error"  # not a tool here: the read router says so


def test_domain_without_a_write_module(clean):
    clean.setattr(server, "WRITES_ENABLED", True)
    clean.delitem(server.DOMAIN_WRITES, "idp")
    seen = ask(clean, "idp")
    assert seen["names"] == set(server.ADAPTERS["idp"].read.TOOL_NAMES) and not server._can_write("idp", WRITER)


def test_list_tools_reach_everyone_but_writes_dont(clean):
    w = fake_writes(clean, "productivity_suite")
    seen = ask(clean, "productivity_suite", actor=READER, email="a@acme.example")
    assert "suite_list_tokens" in seen["names"] and not WRITE_NAMES["productivity_suite"] & seen["names"]
    assert seen["run"]("suite_list_tokens", {"user": "a@acme.example"})["status"] == "ok"
    assert w.calls[0][2] == f"a@acme.example ({READER})"
    seen = ask(clean, "productivity_suite", actor=BOT, email="")
    assert "suite_list_tokens" in seen["names"]
    seen["run"]("suite_list_tokens", {"user": "a@acme.example"})
    assert w.calls[-1][2] == BOT


def test_list_tools_through_the_example_writer(clean):
    seen = ask(clean, "productivity_suite", actor=READER, email="a@acme.example")
    assert seen["run"]("suite_list_tokens", {"user": "a@acme.example"})["status"] == "not_implemented"


def test_alert_bot_never_gets_manual_writes(clean):
    clean.setattr(server, "WRITE_AUTHORIZED", server.WRITE_AUTHORIZED | {BOT})  # even if misconfigured
    for domain in WRITE_CASES:
        w = fake_writes(clean, domain)
        seen = ask(clean, domain, actor=BOT, email="")
        assert not WRITE_NAMES[domain] & seen["names"], domain
        name, args = WRITE_CASES[domain]
        assert seen["run"](name, args)["status"] == "refused"
        assert "recommend only" in seen["note"] and w.calls == []


def test_write_adapter_that_raises_or_returns_junk_is_contained(clean):
    clean.setattr(server, "WRITES_ENABLED", True)

    def boom(*a):
        raise RuntimeError("adapter bug")

    for i, bad in enumerate((boom, lambda *a: None, lambda *a: {"no": "status"})):
        clean.setitem(server.DOMAIN_WRITES, "edr", dataclasses.replace(server.DOMAIN_WRITES["edr"], run=bad))
        r = ask(clean, "edr")["run"]("edr_initiate_scan", {"endpoint": f"H{i}"})
        assert r["status"] == "error" and r["outcome_unknown"] is True


def test_writes_are_audited(clean, caplog):
    fake_writes(clean, "edr")
    with caplog.at_level(logging.INFO, logger="jarvis_tools"):
        r = ask(clean, "edr")["run"]
        r("edr_initiate_scan", {"endpoint": "H1"})
        r("edr_initiate_scan", {"endpoint": "H1"})
    lines = [json.loads(m) for m in (x.getMessage() for x in caplog.records) if m.startswith("{")]
    calls = [x for x in lines if x["jarvis_tools"] == "write_call"]
    assert [(x["tool"], x["status"], x["actor"], x["domain"]) for x in calls] == [
        ("edr_initiate_scan", "ok", WRITER, "edr"), ("edr_initiate_scan", "refused", WRITER, "edr")]
    assert len([x for x in lines if x["jarvis_tools"] == "write_call_start"]) == 1


# --- automatic actions on alert-bot posts -------------------------------------------------------------------------

T1, T2, T3 = "2614239137407374345", "2614239235159852289", "2614200000000000001"
EDR_CONSOLE = os.environ["EDR_CONSOLE_URL"]
EDR_BASE = os.environ["EDR_BASE_URL"]
BRAND_CONSOLE = os.environ["BRAND_PROTECTION_CONSOLE_URL"]
BRAND_BASE = os.environ["BRAND_PROTECTION_BASE_URL"]
IRM_CONSOLE = os.environ["INSIDER_RISK_CONSOLE_URL"]
EMAIL_CONSOLE = os.environ["EMAIL_SECURITY_CONSOLE_URL"]
EMAIL_BASE = os.environ["EMAIL_SECURITY_BASE_URL"]


def edr_post(*ids, origin=EDR_CONSOLE):
    return "New threat\n" + "\n".join(f"<{origin}/alerts/{i}|view alert>" for i in ids)


@pytest.fixture
def auto(clean):
    clean.setattr(server, "AUTO_ENABLED", True)
    return clean


def test_auto_ids_only_from_console_links_for_the_alert_bot(auto):
    fake_writes(auto, "edr")
    post = (edr_post(T2, T1, T1) + f"\nthreat {T3} mentioned without a link\n{edr_post(T3, origin=EDR_BASE)}"
            f"\nhttps://elsewhere.example.test/alerts/{T3} /alerts/{T3}")
    assert server._auto_ids("edr", BOT, post) == [T1, T2]
    assert server._auto_ids("edr", WRITER, post) == []
    assert server._auto_ids("idp", BOT, post) == []  # no automatic actions in that domain
    auto.setattr(server, "AUTO_ENABLED", False)
    assert server._auto_ids("edr", BOT, post) == []
    auto.setattr(server, "AUTO_ENABLED", True)
    auto.setitem(server.DOMAIN_WRITES, "edr", dataclasses.replace(server.DOMAIN_WRITES["edr"], writer=None))
    assert server._auto_ids("edr", BOT, post) == []


def test_auto_ids_follow_each_domains_console(auto):
    for d in ("edr", "brand_protection", "email_security", "insider_risk"):
        fake_writes(auto, d)
    post = (f"{EDR_CONSOLE}/alerts/{T1} {BRAND_CONSOLE}/domains/ABC-37157 {EMAIL_CONSOLE}/messages/{MID} "
            f"{IRM_CONSOLE}/app/#/alerts/review-alerts/{SID}")
    assert server._auto_ids("edr", BOT, post) == [T1]
    assert server._auto_ids("brand_protection", BOT, post) == ["ABC-37157"]
    assert server._auto_ids("email_security", BOT, post) == [MID]
    assert server._auto_ids("insider_risk", BOT, post) == [SID]
    # The tenant API host is not the console: nothing there counts.
    assert server._auto_ids("brand_protection", BOT, f"{BRAND_BASE}/domains/ABC-37157") == []
    assert server._auto_ids("email_security", BOT, f"{EMAIL_BASE}/messages/{MID} {MID}") == []


def test_auto_ids_capped(auto):
    fake_writes(auto, "edr")
    ids = [str(2614200000000000100 + i) for i in range(40)]
    assert len(server._auto_ids("edr", BOT, edr_post(*ids))) == server.MAX_AUTO_IDS


def test_auto_ids_shape_and_multi_group_pattern(auto):
    w = fake_writes(auto, "edr")
    mod = type("M", (), {"AUTO_ID_PATTERN": re.compile(r"(id)=(\w+)"), "AUTO_ID_SHAPE": re.compile(r"\w+"),
                         "AUTO_NOTE": "n", "auto_tools": staticmethod(lambda: []),
                         "auto_requester": staticmethod(lambda a: a),
                         "auto_check": staticmethod(lambda *a: (None, "no"))})
    auto.setitem(server.DOMAIN_WRITES, "edr", dataclasses.replace(server.DOMAIN_WRITES["edr"], module=mod, writer=w))
    assert server._auto_ids("edr", BOT, "id=5 id=6") == ["id"]  # group 1
    mod.AUTO_ID_PATTERN = re.compile(r"\S+")  # no group: the whole match, still shape-checked
    mod.AUTO_ID_SHAPE = re.compile(r"[a-z]{3}")
    assert server._auto_ids("edr", BOT, "abc abcd x-y def") == ["abc", "def"]


def test_edr_auto_close_fp_only_listed_ids_once(auto):
    w = fake_writes(auto, "edr")
    seen = ask(auto, "edr", actor=BOT, email="", alert_post=edr_post(T1, T2))
    assert T1 in seen["note"] and T2 in seen["note"] and "never allowlist" in seen["note"]
    assert {t["name"] for t in server.DOMAIN_WRITES["edr"].module.auto_tools()} <= seen["names"]
    assert not (WRITE_NAMES["edr"] - {"edr_close_alert"}) & seen["names"]
    assert seen["tools"]["edr_close_alert"]["description"].startswith("WRITE, AUTOMATIC CLOSE ONLY")
    r = seen["run"]
    note = {"note": NOTE}
    assert r("edr_close_alert", {"alert_ids": [T1], "verdict": "true_positive", **note})["status"] == "refused"
    assert r("edr_close_alert", {"alert_ids": [T3], "verdict": "false_positive", **note})["status"] == "refused"
    assert r("edr_close_alert", {"alert_ids": [T1, T3], "verdict": "false_positive", **note})["status"] == "refused"
    assert r("edr_add_hash_exclusion", {"hashes": "a" * 40})["status"] == "refused"
    assert r("edr_network_contain", {"endpoint": "H1"})["status"] == "refused"
    assert w.calls == []
    assert r("edr_close_alert", {"alert_ids": [T1], "verdict": "False_Positive", **note})["status"] == "ok"
    assert w.calls[0][2] == f"{BOT} (alert bot, automatic close)"
    assert r("edr_close_alert", {"alert_ids": [T1], "verdict": "false_positive", **note})["status"] == "refused"
    rerun = ask(auto, "edr", actor=BOT, email="", alert_post=edr_post(T1, T2))["run"]  # later request, same post
    out = rerun("edr_close_alert", {"alert_ids": [T1], "verdict": "false_positive", **note})
    assert out["status"] == "refused" and "already took" in out["message"]
    assert len(w.calls) == 1


def test_auto_ids_come_only_from_the_signed_post(auto):
    """An ID the model varies (or copies from elsewhere) is refused even though the post carried a close relative."""
    w = fake_writes(auto, "edr")
    seen = ask(auto, "edr", actor=BOT, email="", alert_post=edr_post(T1))
    near = T1[:-1] + ("0" if T1[-1] != "0" else "1")
    r = seen["run"]("edr_close_alert", {"alert_ids": [near], "verdict": "false_positive", "note": NOTE})
    assert r["status"] == "refused" and w.calls == []
    # An ID in the post but not in a console link is not eligible either.
    seen = ask(auto, "edr", actor=BOT, email="", alert_post="no links here " + T1 + " " + edr_post(T1, origin=EDR_BASE))
    assert "recommend only" in seen["note"] and "edr_close_alert" not in seen["names"]
    assert seen["run"]("edr_close_alert", {"alert_ids": [T1], "verdict": "false_positive", "note": NOTE})[
        "status"] == "refused"
    # A post swapped after signing never gets that far.
    auth = signed("ask_edr_specialist", actor=BOT, email="", alert_post="nothing")
    auth["alert_post"] = edr_post(T1)
    out = json.loads(run(server._run_specialist, "ask_edr_specialist", server.SPECIALISTS["edr"], "q", "", auth))
    assert out["status"] == "refused" and w.calls == []


def test_edr_auto_close_through_the_example_writer(auto):
    """auto_payload normalises the arguments, and the automatic requester passes the real writer's gate."""
    seen = ask(auto, "edr", actor=BOT, email="", alert_post=edr_post(T1))
    out = seen["run"]("edr_close_alert", {"alert_ids": [T1, T1], "verdict": "FALSE_POSITIVE", "note": NOTE,
                                          "requested_by": "ceo@acme.example"})
    assert out["status"] == "not_implemented", out
    assert out["requested_by"] == f"{BOT} (alert bot, automatic close)"
    assert out["validated"]["alert_ids"] == [T1] and out["validated"]["verdict"] == "false_positive"
    assert "ceo@acme.example" not in json.dumps(out)


def test_auto_payload_is_what_the_writer_gets(auto):
    w = fake_writes(auto, "edr")
    r = ask(auto, "edr", actor=BOT, email="", alert_post=edr_post(T1))["run"]
    assert r("edr_close_alert", {"alert_ids": [T1, T1], "verdict": "False_Positive", "note": NOTE,
                                 "extra": "dropped"})["status"] == "ok"
    assert w.calls[0][1] == {"alert_ids": [T1], "verdict": "false_positive", "note": NOTE}


def test_auto_payload_missing_is_identity(auto):
    w = fake_writes(auto, "edr")
    real = server.DOMAIN_WRITES["edr"].module
    mod = type("M", (), {h: getattr(real, h) for h in server.AUTO_HOOKS})  # no auto_payload
    auto.setitem(server.DOMAIN_WRITES, "edr", dataclasses.replace(server.DOMAIN_WRITES["edr"], module=mod))
    r = ask(auto, "edr", actor=BOT, email="", alert_post=edr_post(T1))["run"]
    args = {"alert_ids": [T1], "verdict": "false_positive", "note": NOTE, "extra": 1}
    assert r("edr_close_alert", args)["status"] == "ok" and w.calls[0][1] == args


def test_broken_auto_policy_refuses(auto):
    w = fake_writes(auto, "edr")
    real = server.DOMAIN_WRITES["edr"].module

    def boom(*a):
        raise RuntimeError("policy bug")

    for check in (boom, lambda *a: ("edr|close|x", None), lambda *a: ([], None), lambda *a: ([None], None),
                  lambda *a: (None, None)):
        mod = type("M", (), {**{h: getattr(real, h) for h in server.AUTO_HOOKS}, "auto_check": staticmethod(check)})
        auto.setitem(server.DOMAIN_WRITES, "edr", dataclasses.replace(server.DOMAIN_WRITES["edr"], module=mod))
        r = ask(auto, "edr", actor=BOT, email="", alert_post=edr_post(T1))["run"]
        out = r("edr_close_alert", {"alert_ids": [T1], "verdict": "false_positive", "note": NOTE})
        assert out["status"] == "refused" and out["message"]
    assert w.calls == [] and server._auto_done == {}


def test_broken_auto_payload_sends_nothing(auto):
    w = fake_writes(auto, "edr")
    real = server.DOMAIN_WRITES["edr"].module

    def boom(*a):
        raise RuntimeError("payload bug")

    mod = type("M", (), {**{h: getattr(real, h) for h in server.AUTO_HOOKS}, "auto_payload": staticmethod(boom)})
    auto.setitem(server.DOMAIN_WRITES, "edr", dataclasses.replace(server.DOMAIN_WRITES["edr"], module=mod))
    out = ask(auto, "edr", actor=BOT, email="", alert_post=edr_post(T1))["run"](
        "edr_close_alert", {"alert_ids": [T1], "verdict": "false_positive", "note": NOTE})
    assert out["status"] == "error" and w.calls == []


def test_auto_hourly_cap_per_domain(auto):
    auto.setattr(server, "MAX_AUTO_ACTIONS_PER_HOUR", 2)
    fake_writes(auto, "edr")
    ids = [str(2614200000000000100 + i) for i in range(3)]
    r = ask(auto, "edr", actor=BOT, email="", alert_post=edr_post(*ids))["run"]
    fp = {"verdict": "false_positive", "note": NOTE}
    assert r("edr_close_alert", {"alert_ids": ids[:2], **fp})["status"] == "ok"
    out = r("edr_close_alert", {"alert_ids": ids[2:], **fp})
    assert out["status"] == "refused" and "cap" in out["message"]
    # Another domain has its own cap.
    fake_writes(auto, "brand_protection")
    b = ask(auto, "brand_protection", actor=BOT, email="", alert_post=f"{BRAND_CONSOLE}/alerts/ABC-1")["run"]
    assert b("brand_update_alert", {"alert_id": "ABC-1", "state": "archived", "mode": "auto",
                                    "verdict": "false_positive", "confidence": 99, "note": NOTE})["status"] == "ok"
    # An hour later the cap has room again.
    server._auto_done.update({k: (d, t - 3600) for k, (d, t) in server._auto_done.items()})
    assert r("edr_close_alert", {"alert_ids": ids[2:], **fp})["status"] == "ok"


def test_auto_batch_over_the_cap_is_refused_whole(auto):
    auto.setattr(server, "MAX_AUTO_ACTIONS_PER_HOUR", 2)
    w = fake_writes(auto, "edr")
    ids = [str(2614200000000000100 + i) for i in range(3)]
    r = ask(auto, "edr", actor=BOT, email="", alert_post=edr_post(*ids))["run"]
    assert r("edr_close_alert", {"alert_ids": ids, "verdict": "false_positive", "note": NOTE})["status"] == "refused"
    assert w.calls == [] and server._auto_done == {}


def test_brand_auto_archive_only_signed_ids_and_policy(auto):
    w = fake_writes(auto, "brand_protection")
    seen = ask(auto, "brand_protection", actor=BOT, email="",
               alert_post=f"New alert {BRAND_CONSOLE}/domains/ABC-37157 (lookalike)")
    assert "brand_update_alert" in seen["names"] and "ABC-37157" in seen["note"]
    assert seen["tools"]["brand_update_alert"]["description"].startswith("AUTOMATIC ARCHIVE ONLY")
    r = seen["run"]
    ok = {"alert_id": f"{BRAND_CONSOLE}/domains/ABC-37157", "state": "archived", "mode": "auto",
          "verdict": "false_positive", "confidence": 98, "note": "Acme Juice Bar staff login, unrelated company."}
    for bad in ({**ok, "confidence": 95}, {**ok, "mode": "analyst_requested"}, {**ok, "state": "taken_down"},
                {**ok, "alert_id": "ABC-1"}, {**ok, "alert_id": "ABC-37158"}, {**ok, "verdict": "true_positive"},
                {**ok, "alert_id": f"{BRAND_BASE}/domains/ABC-37158"}):
        assert r("brand_update_alert", bad)["status"] == "refused"
    assert r("brand_update_alert", ok)["status"] == "ok"
    assert w.calls == [("brand_update_alert", ok, f"{BOT} (alert bot, automatic)")]
    assert r("brand_update_alert", ok)["status"] == "refused"  # once per alert
    assert len(w.calls) == 1


def test_brand_auto_archive_through_the_example_writer(auto):
    r = ask(auto, "brand_protection", actor=BOT, email="", alert_post=f"{BRAND_CONSOLE}/domains/ABC-37157")["run"]
    out = r("brand_update_alert", {"alert_id": "ABC-37157", "state": "archived", "mode": "auto",
                                   "verdict": "false_positive", "confidence": 99, "note": NOTE})
    assert out["status"] == "not_implemented" and out["requested_by"] == f"{BOT} (alert bot, automatic)"
    assert "99% confidence" in out["comment"]


def test_email_auto_actions_policy(auto):
    w = fake_writes(auto, "email_security")
    seen = ask(auto, "email_security", actor=BOT, email="", alert_post=f"Flagged: {EMAIL_CONSOLE}/messages/{MID}")
    assert {"email_action_message", "email_block_sender"} <= seen["names"] and MID in seen["note"]
    assert "confidence" in seen["tools"]["email_block_sender"]["input_schema"]["properties"]
    r = seen["run"]
    q = {"message_id": MID, "action": "quarantine", "verdict": "malicious", "confidence": 99, "reason": JUST}
    assert r("email_action_message", {**q, "confidence": 98})["status"] == "refused"
    assert r("email_action_message", {**q, "action": "trash"})["status"] == "refused"
    assert r("email_action_message", {**q, "action": "restore"})["status"] == "refused"
    assert r("email_action_message", {**q, "message_id": MID2})["status"] == "refused"
    assert r("email_action_message", q)["status"] == "ok"
    block = {"sender_email": "a@evil-sender.net", "reason": JUST, "message_id": MID}
    assert r("email_block_sender", {**block, "confidence": 97})["status"] == "refused"
    assert r("email_block_sender", {**block, "confidence": 100})["status"] == "ok"
    assert [c[2] for c in w.calls] == ["", ""]  # agent-initiated gates in the writer
    assert "confidence" in w.calls[0][1]          # quarantine keeps it (part of its schema)
    assert w.calls[1][1] == block                  # auto_payload strips the automatic-only confidence


def test_email_bare_message_ids_are_not_eligible(auto):
    fake_writes(auto, "email_security")
    seen = ask(auto, "email_security", actor=BOT, email="", alert_post=f"Flagged message: {MID}")
    assert "recommend only" in seen["note"] and not WRITE_NAMES["email_security"] & seen["names"]


def test_email_auto_through_the_example_writer(auto):
    r = ask(auto, "email_security", actor=BOT, email="", alert_post=f"{EMAIL_CONSOLE}/messages/{MID}")["run"]
    out = r("email_action_message", {"message_id": MID, "action": "quarantine", "verdict": "malicious",
                                     "confidence": 99, "reason": JUST})
    assert out["status"] == "not_implemented" and out["audit"]["route"] == "agent_initiated", out
    assert out["audit"]["requested_by"] is None


def test_email_banner_for_suspicious_and_cap(auto):
    fake_writes(auto, "email_security")
    auto.setattr(server, "MAX_AUTO_ACTIONS_PER_HOUR", 1)
    seen = ask(auto, "email_security", actor=BOT, email="",
               alert_post=f"{EMAIL_CONSOLE}/messages/{MID} {EMAIL_CONSOLE}/messages/{MID2}")
    r = seen["run"]
    banner = {"action": "warning_banner", "verdict": "suspicious", "reason": JUST}
    assert r("email_action_message", {"message_id": MID, **banner})["status"] == "ok"
    out = r("email_action_message", {"message_id": MID2, **banner})
    assert out["status"] == "refused" and "cap" in out["message"]


def test_irm_auto_close_only_signed_ids_and_policy(auto):
    w = fake_writes(auto, "insider_risk")
    link = f"{IRM_CONSOLE}/app/#/alerts/review-alerts/{SID}"
    seen = ask(auto, "insider_risk", actor=BOT, email="", alert_post=f"Alert {link}")
    assert "irm_close_alert" in seen["names"] and SID in seen["note"]
    assert seen["tools"]["irm_close_alert"]["description"].startswith("AUTOMATIC CLOSE ONLY")
    r = seen["run"]
    ok = {"session_id": link, "disposition": "false_positive", "mode": "auto", "confidence": 98,
          "note": "Likely benign / false positive, 98% confidence. " + NOTE}
    for bad in ({**ok, "confidence": 97}, {**ok, "mode": "analyst_requested"}, {**ok, "disposition": "true_positive"},
                {**ok, "disposition": "closed"}, {**ok, "session_id": "1789055499205_0"}):
        assert r("irm_close_alert", bad)["status"] == "refused"
    assert r("irm_close_alert", ok)["status"] == "ok"
    assert w.calls[0][2] == f"{BOT} (alert bot, automatic)"
    assert r("irm_close_alert", {**ok, "disposition": "benign_true_positive"})["status"] == "refused"  # once
    assert len(w.calls) == 1


def test_irm_writes_for_writers_and_entitlement(clean):
    w = fake_writes(clean, "insider_risk")
    fake_reads(clean, "insider_risk")
    seen = ask(clean, "insider_risk")
    assert {"irm_search_alerts", "irm_get_alert", "irm_search_events", "irm_check_ai_entitlement", "irm_close_alert",
            "search_tickets", "enterprise_search", "web_search"} <= seen["names"]
    assert seen["run"]("enterprise_search", {"query": "x"})["act_as"] == EMAIL
    ok = {"session_id": SID, "disposition": "false_positive", "note": NOTE}
    assert seen["run"]("irm_close_alert", ok)["status"] == "ok"
    assert w.calls[0][2] == REQUESTER


def test_no_auto_actions_when_switched_off_or_for_people(auto):
    w = fake_writes(auto, "brand_protection")
    post = f"{BRAND_CONSOLE}/domains/ABC-37157"
    archive = {"alert_id": "ABC-37157", "state": "archived", "mode": "auto", "verdict": "false_positive",
               "confidence": 99, "note": NOTE}
    auto.setattr(server, "AUTO_ENABLED", False)
    seen = ask(auto, "brand_protection", actor=BOT, email="", alert_post=post)
    assert "brand_update_alert" not in seen["names"] and "recommend only" in seen["note"]
    assert seen["run"]("brand_update_alert", archive)["status"] == "refused"
    auto.setattr(server, "AUTO_ENABLED", True)
    seen = ask(auto, "brand_protection", actor=READER, email="a@acme.example", alert_post=post)
    assert seen["note"] == "" and "brand_update_alert" not in seen["names"]
    assert seen["run"]("brand_update_alert", archive)["status"] == "refused"
    # A writer posting a console link gets the analyst route (writes switched on by fake_writes), not automatic.
    seen = ask(auto, "brand_protection", actor=WRITER, alert_post=post)
    assert seen["note"] == "" and seen["tools"]["brand_update_alert"]["description"] == next(
        t for t in server.DOMAIN_WRITES["brand_protection"].tools)["description"]
    assert w.calls == []


def test_auto_actions_are_audited(auto, caplog):
    fake_writes(auto, "edr")
    with caplog.at_level(logging.INFO, logger="jarvis_tools"):
        r = ask(auto, "edr", actor=BOT, email="", alert_post=edr_post(T1))["run"]
        r("edr_close_alert", {"alert_ids": [T1], "verdict": "false_positive", "note": NOTE})
        r("edr_close_alert", {"alert_ids": [T1], "verdict": "true_positive", "note": NOTE})
    lines = [json.loads(m) for m in (x.getMessage() for x in caplog.records) if m.startswith("{")]
    assert [(x["status"], x["actor"]) for x in lines if x["jarvis_tools"] == "auto_action"] == [
        ("ok", BOT), ("refused", BOT)]
    assert len([x for x in lines if x["jarvis_tools"] == "auto_action_start"]) == 1


def test_alert_bot_note():
    assert server._alert_bot_note(WRITER, [T1], "edr") == ""
    note = server._alert_bot_note(BOT, [T1], "edr")
    assert T1 in note and note.startswith(f"This request was started by the {server.org.ALERT_BOT_NAME}")
    assert note.endswith(server.DOMAIN_WRITES["edr"].module.AUTO_NOTE + T1 + ".")
    assert "recommend only" in server._alert_bot_note(BOT, [], "edr")
    assert "recommend only" in server._alert_bot_note(BOT, [T1], "idp")
