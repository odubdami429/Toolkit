"""The jarvis_guard patch that keeps Slack user IDs in mentions. Hermes's gateway modules are stubbed."""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import sys
import types
from pathlib import Path

PLUGIN = Path(__file__).resolve().parents[1] / "plugins" / "jarvis_guard"


def _load_guard():
    gw = types.ModuleType("gateway")
    sc = types.ModuleType("gateway.session_context")
    sc._UNSET = object()
    sc._bound_session_value = lambda name: sc._UNSET
    sc.bound_session_key = lambda: ""
    gw.session_context = sc
    sys.modules.update({"gateway": gw, "gateway.session_context": sc})
    spec = importlib.util.spec_from_file_location("jarvis_guard_under_test", PLUGIN / "__init__.py",
                                                  submodule_search_locations=[str(PLUGIN)])
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class SlackAdapter:
    async def _resolve_user_name(self, uid, chat_id="", team_id=""):
        return {"U00000000P1": "Pat Lee"}.get(uid, uid)

    async def _humanize_user_mentions(self, text, chat_id="", team_id=""):
        return "ORIGINAL"


def test_mentions_keep_ids_once_adapter_loads():
    jg = _load_guard()
    sys.modules.pop(jg._SLACK_ADAPTER_MODULE, None)
    assert jg._patch_mentions() is False
    sys.modules[jg._SLACK_ADAPTER_MODULE] = types.SimpleNamespace(SlackAdapter=SlackAdapter, other=1)
    try:
        assert jg._patch_mentions() is True
        a = SlackAdapter()
        out = asyncio.run(a._humanize_user_mentions("about <@U00000000P1|Pat Lee> and <@U0UNKNOWN1>?"))
        assert out == "about @Pat Lee (U00000000P1) and @U0UNKNOWN1?"
        assert asyncio.run(a._humanize_user_mentions("plain")) == "plain"
    finally:
        sys.modules.pop(jg._SLACK_ADAPTER_MODULE, None)


def test_sign_covers_requester_email(monkeypatch):
    import hashlib
    import hmac

    jg = _load_guard()
    monkeypatch.setenv("JARVIS_GUARD_HMAC_KEY", "k")
    monkeypatch.setattr(jg, "_actor_email", lambda actor: "pat.lee@example.com")
    b = {"actor_id": "U00000000A1", "session_key": "agent:main:slack:dm:T00000000:D1", "chat_id": "D1",
         "thread_id": ""}
    auth = jg._sign("enterprise_search", b, "call-1")
    msg = "|".join(["enterprise_search", "U00000000A1", b["session_key"], "call-1", str(auth["ts"]),
                    "pat.lee@example.com", hashlib.sha256(b"").hexdigest()]).encode()
    assert auth["actor_email"] == "pat.lee@example.com"
    assert auth["sig"] == hmac.new(b"k", msg, hashlib.sha256).hexdigest()


def test_actor_email_lookup_is_cached_and_fails_closed(monkeypatch):
    jg = _load_guard()
    calls = []

    class FakeSlack:
        def call(self, method, **params):
            calls.append(params["user"])
            if params["user"] == "U00000000Z5":
                return {"ok": True, "user": {"is_bot": True, "profile": {"email": "bot@example.com"}}}
            if params["user"] == "U00000000Z6":
                return {"ok": False, "error": "user_not_found"}
            return {"ok": True, "user": {"profile": {"email": "Pat.Lee@Example.com"}}}

    monkeypatch.setattr(jg, "_slack_client", lambda: FakeSlack())
    assert jg._actor_email("U00000000A1") == "pat.lee@example.com"
    assert jg._actor_email("U00000000A1") == "pat.lee@example.com"
    assert calls == ["U00000000A1"]
    assert jg._actor_email("U00000000Z5") == "" and jg._actor_email("U00000000Z6") == ""


# --- bot triggers and the requester check ---------------------------------------------------------------------------

BOT, ALERTS, TEAM = "U00000000B1", "C00000000C1", "T00000000"


def _bot_env(monkeypatch, cap="20"):
    monkeypatch.setenv("JARVIS_SLACK_TEAM_ID", TEAM)
    monkeypatch.setenv("SLACK_ALLOWED_USERS", f"U00000000A1,U00000000A2,{BOT}")
    monkeypatch.setenv("JARVIS_TRIGGER_BOTS", BOT)
    monkeypatch.setenv("JARVIS_BOT_CHANNELS", ALERTS)
    monkeypatch.setenv("JARVIS_BOT_TRIGGERS_PER_HOUR", cap)


def _source(**kw):
    base = {"platform": types.SimpleNamespace(value="slack"), "is_bot": True, "user_id": BOT, "chat_id": ALERTS,
            "chat_type": "group", "scope_id": TEAM, "thread_id": "1.2", "message_id": "1.2"}
    base.update(kw)
    return types.SimpleNamespace(**base)


def test_bot_trigger_gate(monkeypatch):
    jg = _load_guard()
    _bot_env(monkeypatch)
    assert jg._bot_skip_reason(_source()) is None
    assert jg._bot_skip_reason(_source(is_bot=False, user_id="U00000000Z3")) is None  # people: Hermes's allowlist
    assert jg._bot_skip_reason(_source(user_id="U00000000B9")) == "bot is not a trigger bot"
    assert jg._bot_skip_reason(_source(user_id="")) == "bot is not a trigger bot"  # Workflow Builder: user=None
    assert jg._bot_skip_reason(_source(chat_id="C0ENGCHAN01")) == "bot trigger outside the bot channels"
    assert jg._bot_skip_reason(_source(chat_type="dm", chat_id="D0BOTDM001")) == "bot trigger outside the bot channels"
    assert jg._bot_skip_reason(_source(scope_id="T0OTHER001")) == "not the pinned Slack workspace"
    assert jg._bot_skip_reason(_source(platform=types.SimpleNamespace(value="telegram"))) is None
    monkeypatch.delenv("JARVIS_TRIGGER_BOTS")
    assert jg._bot_skip_reason(_source()) == "bot is not a trigger bot"


def test_bot_trigger_hourly_cap(monkeypatch):
    jg = _load_guard()
    _bot_env(monkeypatch, cap="2")
    assert [jg._bot_skip_reason(_source()) for _ in range(3)] == [None, None, "hourly bot trigger cap reached"]
    jg._bot_triggers[:] = [t - jg._BOT_TRIGGER_WINDOW_S for t in jg._bot_triggers]
    assert jg._bot_skip_reason(_source()) is None
    monkeypatch.setenv("JARVIS_BOT_TRIGGERS_PER_HOUR", "not-a-number")
    assert jg._bot_skip_reason(_source()) == "hourly bot trigger cap reached"


def test_pre_gateway_dispatch_skips_other_bots(monkeypatch):
    jg = _load_guard()
    _bot_env(monkeypatch)
    ev = lambda **kw: types.SimpleNamespace(source=_source(**kw))  # noqa: E731
    assert jg._on_pre_gateway_dispatch(event=ev()) is None
    assert jg._on_pre_gateway_dispatch(event=ev(is_bot=False, user_id="U00000000A1")) is None
    out = jg._on_pre_gateway_dispatch(event=ev(user_id="U00000000B9"), gateway=None, session_store=None)
    assert out == {"action": "skip", "reason": "jarvis_guard: bot is not a trigger bot"}
    assert jg._on_pre_gateway_dispatch(event=None) is None


def _b(actor, chat, chat_type="group"):
    return {"env_planted": [], "session_key": f"agent:main:slack:{chat_type}:{TEAM}:{chat}", "platform": "slack",
            "actor_id": actor, "chat_id": chat}


def test_tool_calls_need_an_allowlisted_requester(monkeypatch):
    jg = _load_guard()
    _bot_env(monkeypatch)
    assert jg._deny_reason("x", _b("U00000000A1", "C0ANYWHERE1")) is None
    assert jg._deny_reason("x", _b(BOT, ALERTS)) is None
    assert jg._deny_reason("x", _b(BOT, "C0ENGCHAN01")) == "requester is not allowlisted here"  # listed, not a person
    assert jg._deny_reason("x", _b(BOT, "D0BOTDM001", "dm")) == "requester is not allowlisted here"
    assert jg._deny_reason("x", _b(BOT, "")) == "requester is not allowlisted here"
    assert jg._deny_reason("x", _b("U00000000B9", ALERTS)) == "requester is not allowlisted here"
    assert jg._deny_reason("x", _b("U00000000Z7", "D0DM000001", "dm")) == "requester is not allowlisted here"
    monkeypatch.setenv("SLACK_ALLOWED_USERS", "")
    assert jg._deny_reason("x", _b("U00000000A1", "C0ANYWHERE1")) == "requester is not allowlisted here"


# --- alert-bot posts: the bot's own thread root, signed whole as alert_post ------------------------------------------

POST_TEXT = ("*EDR alert* <https://edr.example.com/incidents/threats/2614239137407374345/overview|view>\n"
             "<https://edr.example.com/incidents/threats/2614239235159852289/overview|view> <@U00000000J1>")
POST = {"ok": True, "messages": [{"ts": "1794870947.393139", "user": BOT, "text": POST_TEXT}]}


class _Slack:
    def __init__(self, reply):
        self.reply, self.calls = reply, 0

    def call(self, method, **params):
        self.calls += 1
        assert method == "conversations.replies" and params["limit"] == 1
        return self.reply


def _bb(actor=BOT, chat=ALERTS, thread="1794870947.393139"):
    return {**_b(actor, chat), "thread_id": thread}


def _expected_sig(tool, b, auth, key=b"k"):
    import hashlib
    import hmac
    msg = "|".join([tool, b["actor_id"], b["session_key"], auth["tool_call_id"], str(auth["ts"]), auth["actor_email"],
                    hashlib.sha256(auth["alert_post"].encode()).hexdigest()]).encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def test_alert_root_is_the_bots_post(monkeypatch):
    jg = _load_guard()
    _bot_env(monkeypatch)
    fake = _Slack(POST)
    monkeypatch.setattr(jg, "_slack_client", lambda: fake)
    blob = jg._alert_root(_bb())
    assert json.loads(blob) == {"text": POST_TEXT, "blocks": None, "attachments": None}
    assert jg._alert_root(_bb()) == blob and fake.calls == 1  # cached
    assert jg._alert_root(_bb(actor="U00000000A1")) == ""  # a person: no alert post
    assert jg._alert_root(_bb(chat="C0ENGCHAN01")) == ""
    assert jg._alert_root(_bb(thread="")) == ""


def test_alert_root_needs_the_bots_own_unedited_root(monkeypatch):
    jg = _load_guard()
    _bot_env(monkeypatch)
    for msg in ({**POST["messages"][0], "user": "U00000000Z3"}, {**POST["messages"][0], "ts": "1.0"},
                {**POST["messages"][0], "edited": {"user": BOT}}):
        jg._alert_roots.clear()
        monkeypatch.setattr(jg, "_slack_client", lambda m=msg: _Slack({"ok": True, "messages": [m]}))
        assert jg._alert_root(_bb()) == ""
    jg._alert_roots.clear()
    monkeypatch.setattr(jg, "_slack_client", lambda: _Slack({"ok": False, "error": "not_in_channel"}))
    assert jg._alert_root(_bb()) == ""


def test_alert_root_is_truncated(monkeypatch):
    jg = _load_guard()
    _bot_env(monkeypatch)
    long = {"ok": True, "messages": [{**POST["messages"][0], "text": "x" * 50000}]}
    monkeypatch.setattr(jg, "_slack_client", lambda: _Slack(long))
    assert len(jg._alert_root(_bb())) == jg._ALERT_POST_MAX == 20000


def test_alert_root_audit_line_has_no_content(monkeypatch):
    jg = _load_guard()
    _bot_env(monkeypatch)
    lines = []
    monkeypatch.setattr(jg._log, "info", lines.append)
    monkeypatch.setattr(jg, "_slack_client", lambda: _Slack(POST))
    blob = jg._alert_root(_bb())
    rec = json.loads(lines[-1])
    assert rec["jarvis_guard"] == "alert_root" and rec["length"] == len(blob) and rec["usable"] is True
    assert rec["sha256"] == hashlib.sha256(blob.encode()).hexdigest()[:16]
    assert "2614239137407374345" not in lines[-1]


def test_sign_carries_the_alert_post_for_any_jarvis_tools_tool(monkeypatch):
    jg = _load_guard()
    _bot_env(monkeypatch)
    monkeypatch.setenv("JARVIS_GUARD_HMAC_KEY", "k")
    monkeypatch.setattr(jg, "_actor_email", lambda actor: "")
    monkeypatch.setattr(jg, "_slack_client", lambda: _Slack(POST))
    blob = jg._alert_root(_bb())
    for tool in ("ask_edr_specialist", "ask_email_security_specialist", "search_tickets", "anything_new"):
        auth = jg._sign(tool, _bb(), "c1")
        assert set(auth) == {"actor", "actor_email", "alert_post", "session_key", "tool_call_id", "ts", "sig"}
        assert auth["alert_post"] == blob and "auto_close_ids" not in auth
        assert auth["sig"] == _expected_sig(tool, _bb(), auth)


def test_signature_covers_the_alert_post(monkeypatch):
    jg = _load_guard()
    _bot_env(monkeypatch)
    monkeypatch.setenv("JARVIS_GUARD_HMAC_KEY", "k")
    monkeypatch.setattr(jg, "_actor_email", lambda actor: "")
    monkeypatch.setattr(jg, "_slack_client", lambda: _Slack(POST))
    auth = jg._sign("ask_edr_specialist", _bb(), "c1")
    assert auth["sig"] == _expected_sig("ask_edr_specialist", _bb(), auth)
    tampered = {**auth, "alert_post": auth["alert_post"].replace("2614239137407374345", "2614239137407374346")}
    assert tampered["alert_post"] != auth["alert_post"]
    assert _expected_sig("ask_edr_specialist", _bb(), tampered) != auth["sig"]
    assert _expected_sig("ask_edr_specialist", _bb(), {**auth, "alert_post": ""}) != auth["sig"]


def test_a_persons_call_gets_an_empty_alert_post(monkeypatch):
    jg = _load_guard()
    _bot_env(monkeypatch)
    monkeypatch.setenv("JARVIS_GUARD_HMAC_KEY", "k")
    monkeypatch.setattr(jg, "_actor_email", lambda actor: "pat.lee@example.com")
    fake = _Slack(POST)
    monkeypatch.setattr(jg, "_slack_client", lambda: fake)
    b = _bb(actor="U00000000A1")  # a person replying in the alert's thread
    auth = jg._sign("ask_edr_specialist", b, "c1")
    assert auth["alert_post"] == "" and fake.calls == 0
    assert auth["sig"] == _expected_sig("ask_edr_specialist", b, auth)


def test_pre_tool_call_injects_jarvis_auth(monkeypatch):
    jg = _load_guard()
    _bot_env(monkeypatch)
    monkeypatch.setenv("JARVIS_GUARD_HMAC_KEY", "k")
    monkeypatch.setattr(jg, "_actor_email", lambda actor: "")
    monkeypatch.setattr(jg, "_slack_client", lambda: _Slack(POST))
    b = {**_bb(), "user_id": BOT, "actor_name": "", "thread_id": "1794870947.393139"}
    monkeypatch.setattr(jg, "_binding", lambda: b)
    monkeypatch.setattr(jg, "_jarvis_tools_name", lambda name: name.removeprefix("mcp_jarvis_tools_"))
    out = jg._on_pre_tool_call(tool_name="mcp_jarvis_tools_ask_brand_protection_specialist", tool_call_id="t1")
    auth = out["args"]["jarvis_auth"]
    assert out["action"] == "modify" and auth["alert_post"] and auth["tool_call_id"] == "t1"
    assert auth["sig"] == _expected_sig("ask_brand_protection_specialist", b, auth)


# --- Slack write tools: who may call them, caps, off switch ---------------------------------------------------------

def _w(actor, session="agent:main:slack:dm:T00000000:D0DM000001"):
    return {"actor_id": actor, "session_key": session, "chat_id": "D0DM000001"}


def test_slack_write_refusals(monkeypatch):
    jg = _load_guard()
    _bot_env(monkeypatch)
    monkeypatch.setenv("SLACK_ALLOWED_USERS", f"U00000000A1,U00000000A2,U00000000A4,{BOT}")
    monkeypatch.setenv("JARVIS_WRITERS", "U00000000A1,U00000000A2")
    assert jg._slack_write_refusal("create_slack_channel", _w("U00000000A1")) is None
    assert "authorized writers" in jg._slack_write_refusal("create_slack_channel", _w("U00000000A4"))  # not a writer
    assert jg._slack_write_refusal("join_slack_channel", _w("U00000000A4")) is None
    assert "allowlist" in jg._slack_write_refusal("join_slack_channel", _w(BOT))  # alert bot: never
    assert "allowlist" in jg._slack_write_refusal("create_slack_channel", _w(BOT))
    assert "allowlist" in jg._slack_write_refusal("join_slack_channel", _w("U00000000Z7"))
    monkeypatch.setenv("JARVIS_SLACK_WRITES_ENABLED", "false")
    assert "switched off" in jg._slack_write_refusal("join_slack_channel", _w("U00000000A2"))


def test_slack_write_caps_per_thread(monkeypatch):
    jg = _load_guard()
    _bot_env(monkeypatch)
    monkeypatch.setenv("JARVIS_WRITERS", "U00000000A1")
    assert jg._slack_write_refusal("create_slack_channel", _w("U00000000A1")) is None
    assert "already ran" in jg._slack_write_refusal("create_slack_channel", _w("U00000000A1"))
    assert jg._slack_write_refusal("create_slack_channel", _w("U00000000A1", "other-thread")) is None
    assert [jg._slack_write_refusal("join_slack_channel", _w("U00000000A1")) is None for _ in range(3)] == \
        [True, True, False]


def test_transform_hook_holds_the_stream_and_keeps_labels_bold():
    jg = _load_guard()
    hooks = {}

    class Ctx:
        def register_hook(self, name, cb, hold_stream=False):
            hooks[name] = (cb, hold_stream)

        def register_tool(self, **kw):
            return None  # registration_rejected path: stops before the mention patch and the loaded line

    jg.register(Ctx())
    cb, held = hooks["transform_llm_output"]
    assert held is True
    assert cb(response_text="*Verdict:* Escalate", session_id="s", platform="slack") == "**Verdict:** Escalate"
    assert cb(response_text="nothing to change") is None
    assert cb(response_text=None) is None
