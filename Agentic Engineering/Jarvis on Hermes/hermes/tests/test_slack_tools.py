"""Tests for the jarvis_guard Slack read tools. A fake transport stands in for Slack; nothing touches the network.

    python -m pytest -q hermes/tests
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "slack_tools", Path(__file__).resolve().parents[1] / "plugins" / "jarvis_guard" / "slack_tools.py")
st = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(st)

REQ = "U00000000A1"
TOKEN = "xoxb-fake-token-value"


class FakeSlack:
    def __init__(self, responses: dict):
        self.responses = responses
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, method: str, params: dict) -> dict:
        self.calls.append((method, params))
        r = self.responses.get(method, {"ok": False, "error": "unexpected"})
        return r(params) if callable(r) else r


def client(responses: dict) -> tuple[st.Slack, FakeSlack]:
    fake = FakeSlack({"auth.test": {"ok": True, "user_id": "UBOT00001", "bot_id": "BBOT00001"}, **responses})
    return st.Slack(TOKEN, transport=fake), fake


def methods(fake: FakeSlack) -> list[str]:
    return [m for m, _ in fake.calls]


# --- client -------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("method", ["chat.postMessage", "conversations.join", "conversations.create", "users.list"])
def test_only_read_methods(method):
    s, fake = client({})
    with pytest.raises(PermissionError):
        s.call(method)
    assert fake.calls == []


def test_repr_hides_token():
    assert TOKEN not in repr(st.Slack(TOKEN))


# --- lookup_slack_user --------------------------------------------------------------------------------------------

USER = {"ok": True, "user": {"id": REQ, "real_name": "Pat Lee", "tz": "America/New_York",
                             "profile": {"display_name": "Pat", "email": "pat.lee@example.com", "title": "Engineer",
                                         "phone": "555-0100"}}}


@pytest.mark.parametrize("raw", [REQ, f"<@{REQ}>", f"<@{REQ}|pat>", f"@{REQ}", f" {REQ} "])
def test_lookup_by_id_forms(raw):
    s, fake = client({"users.info": USER})
    out = st.lookup_slack_user(s, {"user": raw})
    assert out["status"] == "ok" and out["email"] == "pat.lee@example.com" and out["account_type"] == "member"
    assert fake.calls == [("users.info", {"user": REQ})]
    assert "phone" not in json.dumps(out) and "555-0100" not in json.dumps(out)


@pytest.mark.parametrize("raw", ["pat.lee@example.com", "<mailto:pat.lee@example.com|pat.lee@example.com>"])
def test_lookup_by_email(raw):
    s, fake = client({"users.lookupByEmail": USER})
    out = st.lookup_slack_user(s, {"user": raw})
    assert out["status"] == "ok" and fake.calls == [("users.lookupByEmail", {"email": "pat.lee@example.com"})]


@pytest.mark.parametrize("raw", ["", "@Pat", "Pat Lee", "C0123456789", None])
def test_lookup_rejects(raw):
    s, fake = client({})
    assert st.lookup_slack_user(s, {"user": raw})["status"] == "error" and fake.calls == []


@pytest.mark.parametrize("user,expected", [
    ({"is_restricted": True}, "multi_channel_guest"),
    ({"is_restricted": True, "is_ultra_restricted": True}, "single_channel_guest"),
    ({"is_bot": True}, "bot"),
    ({"is_bot": True, "id": "UBOT00001"}, "this_system"),
])
def test_account_types(user, expected):
    u = {"id": "U00000000Z1", "profile": {}, **user}
    s, _ = client({"users.info": {"ok": True, "user": u}})
    assert st.lookup_slack_user(s, {"user": u["id"]})["account_type"] == expected


def test_lookup_slack_error():
    s, _ = client({"users.info": {"ok": False, "error": "user_not_found"}})
    out = st.lookup_slack_user(s, {"user": "U00000000Z2"})
    assert out["status"] == "error" and out["slack_error"] == "user_not_found"


# --- parse_link ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("https://example.slack.com/archives/C00000000C2/p1789650398817579",
     ("C00000000C2", "1789650398.817579", "1789650398.817579")),
    ("<https://example.slack.com/archives/C00000000C2/p1789650398817579|link>",
     ("C00000000C2", "1789650398.817579", "1789650398.817579")),
    ("https://example.slack.com/archives/C00000000C2/p1789650400000001?thread_ts=1789650398.817579&cid=C00000000C2",
     ("C00000000C2", "1789650400.000001", "1789650398.817579")),
    ("https://app.slack.com/archives/G0PRIVATE01/p1789650398817579",
     ("G0PRIVATE01", "1789650398.817579", "1789650398.817579")),
])
def test_parse_link(raw, expected):
    assert st.parse_link(raw) == expected


@pytest.mark.parametrize("raw,needle", [
    ("https://evil.example/archives/C00000000C2/p1789650398817579", "isn't a Slack link"),
    ("https://example.slack.com.evil.example/archives/C00000000C2/p1789650398817579", "isn't a Slack link"),
    ("http://example.slack.com/archives/C00000000C2/p1789650398817579", "isn't a Slack link"),
    ("https://example.slack.com/archives/C00000000C2", "channel, not"),
    ("https://example.slack.com/team/U00000000A1", "isn't a Slack message link"),
])
def test_parse_link_rejects(raw, needle):
    with pytest.raises(ValueError, match=needle):
        st.parse_link(raw)


# --- resolve_slack_link -------------------------------------------------------------------------------------------

LINK = "https://example.slack.com/archives/C00000000C2/p1789650398817579"
THREAD = {"ok": True, "has_more": False, "messages": [
    {"ts": "1789650398.817579", "bot_id": "B1", "bot_profile": {"name": "mdr_handoff"}, "text": "",
     "attachments": [{"fallback": "dup", "title": "Phish hand-off",
                      "text": "Sender drvega[@]minsa.gob[.]pa linked hxxps://aspeniareinc[.]com/login",
                      "fields": [{"title": "Hash", "value": "d41d8cd98f00b204e9800998ecf8427e"}]}]},
    {"ts": "1789650500.000100", "user": REQ, "text": "<@UXYZ12345> see <https://portal.example.net/x|Portal> "
                                                       "and 203.0.113.7"},
]}


def members(*ids, cursor=""):
    return {"ok": True, "members": list(ids), "response_metadata": {"next_cursor": cursor}}


def public_info():
    return {"ok": True, "channel": {"id": "C00000000C2", "is_private": False}}


def test_resolve_happy_path_and_indicators(monkeypatch):
    monkeypatch.setenv("ORG_EXTRA_DOMAINS", "example.net")  # the organisation's own domains aren't indicators
    s, fake = client({"conversations.members": members(REQ), "conversations.info": public_info(),
                      "conversations.replies": THREAD})
    out = st.resolve_slack_link(s, {"url": LINK}, requester=REQ, current_chat="C0SOMEWHERE")
    assert out["status"] == "ok" and out["message_count"] == 2 and out["channel_mention"] == "<#C00000000C2>"
    assert methods(fake) == ["conversations.members", "conversations.info", "conversations.replies"]
    assert out["target"]["author"] == "mdr_handoff" and "Phish hand-off" in out["target"]["text"]
    assert "dup" not in out["transcript"]
    assert "@UXYZ12345" in out["transcript"] and "Portal (https://portal.example.net/x)" in out["transcript"]
    ind = out["indicators"]
    assert ind["defanged_in_source"] is True
    assert "aspeniareinc.com/login" in " ".join(ind["marked_iocs"]) and "drvega@minsa.gob.pa" in ind["marked_iocs"]
    assert "aspeniareinc.com" in ind["domains"] and "portal.example.net" not in ind["domains"]
    assert "portal.example.net" in ind["domains_all"]
    assert ind["ips"] == ["203.0.113.7"] and ind["hashes"] == ["d41d8cd98f00b204e9800998ecf8427e"]


def test_indicator_noise_comes_from_org_env(monkeypatch):
    text = "see https://login.example.com/x, mail.example.org, evil-example.com and app.slack.com"
    monkeypatch.delenv("ORG_EMAIL_DOMAINS", raising=False)
    monkeypatch.delenv("ORG_EXTRA_DOMAINS", raising=False)
    assert st.indicators(text)["domains"] == ["evil-example.com", "login.example.com", "mail.example.org"]
    monkeypatch.setenv("ORG_EMAIL_DOMAINS", "Example.com, @example.org")
    assert st.indicators(text)["domains"] == ["evil-example.com"]
    assert "app.slack.com" in st.indicators(text)["domains_all"]


def test_indicator_noise_includes_configured_provider_hosts(monkeypatch):
    text = "see https://edr.example.net/incidents/1, sub.edr.example.net, other.example.net and evil-example.com"
    for k in ("ORG_EMAIL_DOMAINS", "ORG_EXTRA_DOMAINS", *st._PROVIDER_URL_VARS):
        monkeypatch.delenv(k, raising=False)
    assert "edr.example.net" in st.indicators(text)["domains"]
    monkeypatch.setenv("EDR_BASE_URL", "https://edr.example.net")
    monkeypatch.setenv("TICKETING_BASE_URL", "not a url")
    assert st.indicators(text)["domains"] == ["evil-example.com", "other.example.net"]


def test_guest_note_uses_org_name(monkeypatch):
    monkeypatch.setenv("ORG_NAME", "Example Corp")
    u = {"id": "U00000000Z1", "profile": {}, "is_restricted": True}
    s, _ = client({"users.info": {"ok": True, "user": u}})
    assert "Guest account: not a full Example Corp member." in st.lookup_slack_user(s, {"user": u["id"]})["notes"]


def test_reply_link_targets_the_reply():
    link = "https://example.slack.com/archives/C00000000C2/p1789650500000100?thread_ts=1789650398.817579"
    s, fake = client({"conversations.members": members(REQ), "conversations.info": public_info(),
                      "conversations.replies": THREAD})
    out = st.resolve_slack_link(s, {"url": link}, requester=REQ, current_chat="C0SOMEWHERE")
    assert out["target"]["author"] == REQ
    assert fake.calls[-1][1]["ts"] == "1789650398.817579"


def test_requester_not_member_is_refused_before_reading():
    s, fake = client({"conversations.members": members("U00000000Z3")})
    out = st.resolve_slack_link(s, {"url": LINK}, requester=REQ, current_chat="C0SOMEWHERE")
    assert out["status"] == "refused" and "not a member" in out["message"]
    assert "conversations.replies" not in methods(fake)


def test_membership_paginates():
    pages = iter([members("U00000000Z4", cursor="next"), members(REQ)])
    s, fake = client({"conversations.members": lambda p: next(pages), "conversations.info": public_info(),
                      "conversations.replies": THREAD})
    assert st.resolve_slack_link(s, {"url": LINK}, requester=REQ, current_chat="C1")["status"] == "ok"
    assert [p.get("cursor") for m, p in fake.calls if m == "conversations.members"] == [None, "next"]


def test_private_channel_content_stays_out_of_other_channels():
    link = "https://example.slack.com/archives/G0PRIVATE01/p1789650398817579"
    info = {"ok": True, "channel": {"id": "G0PRIVATE01", "is_private": True}}
    s, fake = client({"conversations.members": members(REQ), "conversations.info": info,
                      "conversations.replies": THREAD})
    out = st.resolve_slack_link(s, {"url": link}, requester=REQ, current_chat="C0PUBLIC001")
    assert out["status"] == "refused" and "private" in out["message"]
    assert "conversations.replies" not in methods(fake)
    assert st.resolve_slack_link(s, {"url": link}, requester=REQ, current_chat="D0MYDM0001")["status"] == "ok"
    assert st.resolve_slack_link(s, {"url": link}, requester=REQ, current_chat="G0PRIVATE01")["status"] == "ok"


def test_bot_turns_read_only_the_current_channel():
    link = "https://example.slack.com/archives/C0PUBLIC001/p1789650398817579"
    info = {"ok": True, "channel": {"id": "C0PUBLIC001", "is_private": False}}
    s, fake = client({"conversations.members": members(REQ), "conversations.info": info,
                      "conversations.replies": THREAD})
    out = st.resolve_slack_link(s, {"url": link}, requester=REQ, current_chat="C0ALERTS001", same_channel_only=True)
    assert out["status"] == "refused" and "alert bot" in out["message"]
    assert fake.calls == []
    assert st.resolve_slack_link(s, {"url": link}, requester=REQ, current_chat="C0PUBLIC001",
                                 same_channel_only=True)["status"] == "ok"


def test_dm_links_only_from_the_same_dm():
    link = "https://example.slack.com/archives/D0OTHERDM1/p1789650398817579"
    s, fake = client({"conversations.replies": THREAD})
    assert st.resolve_slack_link(s, {"url": link}, requester=REQ, current_chat="D0MYDM0001")["status"] == "refused"
    assert fake.calls == []
    assert st.resolve_slack_link(s, {"url": link}, requester=REQ, current_chat="D0OTHERDM1")["status"] == "ok"


def test_no_requester_refused():
    s, fake = client({})
    assert st.resolve_slack_link(s, {"url": LINK}, requester="", current_chat="C1")["status"] == "refused"
    assert fake.calls == []


@pytest.mark.parametrize("error", ["not_in_channel", "channel_not_found"])
def test_bot_not_in_channel(error):
    s, _ = client({"conversations.members": {"ok": False, "error": error}})
    out = st.resolve_slack_link(s, {"url": LINK}, requester=REQ, current_chat="C1")
    assert out["status"] == "error" and out["slack_error"] == error and "/invite @jarvis" in out["message"]


def test_thread_not_found():
    s, _ = client({"conversations.members": members(REQ), "conversations.info": public_info(),
                   "conversations.replies": {"ok": True, "messages": []}})
    assert st.resolve_slack_link(s, {"url": LINK}, requester=REQ, current_chat="C1")["slack_error"] == "thread_not_found"


def test_bad_link_makes_no_calls():
    s, fake = client({})
    out = st.resolve_slack_link(s, {"url": "https://example.com/x"}, requester=REQ, current_chat="C1")
    assert out["status"] == "error" and fake.calls == []


def test_limits_and_truncation_keep_the_root():
    many = {"ok": True, "messages": [{"ts": "1789650398.817579", "user": REQ, "text": "ROOT"}] +
            [{"ts": f"17896504{i:02d}.000000", "user": REQ, "text": f"reply {i} " + "x" * 200} for i in range(60)]}
    s, fake = client({"conversations.members": members(REQ), "conversations.info": public_info(),
                      "conversations.replies": many})
    out = st.resolve_slack_link(s, {"url": LINK, "max_replies": 500, "max_chars": 10}, requester=REQ,
                                current_chat="C1")
    assert fake.calls[-1][1]["limit"] == "200"
    assert out["truncated"] is True and out["transcript"].splitlines()[0].endswith("ROOT")
    assert len(out["transcript"]) <= st.MIN_CHARS + 2
    assert "reply 59" in out["transcript"]


def test_blocks_rendered_without_duplicates():
    msg = {"text": "Alert fired", "blocks": [
        {"type": "section", "text": {"type": "mrkdwn", "text": "Alert fired"}},
        {"type": "rich_text", "elements": [{"type": "rich_text_section", "elements": [
            {"type": "text", "text": "Host "}, {"type": "link", "url": "https://c.example", "text": "console"}]}]},
    ], "files": [{"name": "shot.png", "mimetype": "image/png"}]}
    text = st.message_text(msg)
    assert text.count("Alert fired") == 1 and "console (https://c.example)" in text and "[file: shot.png" in text


def test_tool_specs():
    assert set(st.TOOLS) == {"lookup_slack_user", "resolve_slack_link", "read_slack_channel"}
    for name, spec in st.TOOLS.items():
        assert "Read-only" in spec["description"]
        assert spec["parameters"]["required"] or name == "read_slack_channel"


# --- read_slack_channel -------------------------------------------------------------------------------------------

CH = "C0ABCDEF12"
DM = "D0ABCDEF12"
PUBLIC = {"ok": True, "channel": {"id": CH, "name": "ir-2026-11", "is_private": False}}
PRIVATE = {"ok": True, "channel": {"id": CH, "name": "ir-secret", "is_private": True}}
MEMBERS = {"ok": True, "members": [REQ, "U00000000Z1"]}
NOW = 1_795_000_000.0


def _msg(ts: float, text: str, user: str = REQ, **kw) -> dict:
    return {"ts": f"{ts:.6f}", "user": user, "text": text, **kw}


def history(*msgs: dict, has_more: bool = False, cursor: str = "") -> dict:
    # Slack returns newest first
    return {"ok": True, "messages": sorted(msgs, key=lambda m: -float(m["ts"])), "has_more": has_more,
            "response_metadata": {"next_cursor": cursor}}


def channel_client(**over) -> tuple[st.Slack, FakeSlack]:
    responses = {"conversations.members": MEMBERS, "conversations.info": PUBLIC,
                 "conversations.history": history(_msg(NOW - 100, "second"), _msg(NOW - 200, "first")),
                 "users.info": lambda p: {"ok": True, "user": {"id": p["user"], "real_name": "Name " + p["user"][-3:],
                                                                "profile": {"display_name": ""}}}}
    responses.update(over)
    return client(responses)


def read(s, args=None, **kw):
    kw.setdefault("requester", REQ)
    kw.setdefault("current_chat", CH)
    return st.read_slack_channel(s, args or {}, **kw)


def test_channel_read_only_method_added():
    assert "conversations.history" in st.READ_METHODS
    assert not any(m.startswith(("chat.", "conversations.join", "conversations.create")) for m in st.READ_METHODS)


@pytest.mark.parametrize("raw,expected", [
    ("", CH), ("this channel", CH), (CH, CH), (f"<#{CH}>", CH), (f"<#{CH}|ir-2026-11>", CH), (f"#{CH}", CH),
    (f"https://example.slack.com/archives/{CH}", CH),
    (f"https://example.slack.com/archives/{CH}/p1795017104393169?thread_ts=1795016789.253099", CH),
    (f"<https://example.slack.com/archives/{CH}>", CH),
])
def test_parse_channel(raw, expected):
    assert st.parse_channel(raw, CH) == expected


@pytest.mark.parametrize("raw", ["#ir-2026-11", "ir-2026-11", "https://evil.example.com/archives/C0ABCDEF12",
                                 "http://example.slack.com/archives/C0ABCDEF12"])
def test_parse_channel_rejects(raw):
    with pytest.raises(ValueError):
        st.parse_channel(raw, CH)


def test_reads_oldest_first_with_names():
    s, fake = channel_client()
    out = read(s)
    assert out["status"] == "ok" and out["message_count"] == 2 and out["channel_name"] == "ir-2026-11"
    t = out["transcript"]
    assert t.index("first") < t.index("second")
    assert f"Name {REQ[-3:]} ({REQ})" in t
    assert methods(fake)[:2] == ["conversations.members", "conversations.info"]
    hist = [p for m, p in fake.calls if m == "conversations.history"][0]
    assert float(hist["latest"]) - float(hist["oldest"]) == pytest.approx(7 * 86400, abs=5)


def test_since_until_and_days():
    s, fake = channel_client()
    read(s, {"since": "2026-11-01", "until": "2026-11-02T00:00:00Z"})
    hist = [p for m, p in fake.calls if m == "conversations.history"][0]
    assert hist["oldest"].startswith("1793491200") and hist["latest"].startswith("1793577600")
    s, fake = channel_client()
    read(s, {"days": 2})
    hist = [p for m, p in fake.calls if m == "conversations.history"][0]
    assert float(hist["latest"]) - float(hist["oldest"]) == pytest.approx(2 * 86400, abs=5)


@pytest.mark.parametrize("args,needle", [
    ({"since": "last tuesday"}, "`since`"), ({"days": "lots"}, "numbers"),
    ({"since": "2026-11-02", "until": "2026-11-01"}, "before"),
    ({"since": "2026-01-01", "until": "2026-11-01"}, "at most 90 days"),
    ({"channel": "#general"}, "channel"),
])
def test_bad_args(args, needle):
    s, fake = channel_client()
    out = read(s, args)
    assert out["status"] == "error" and needle in out["message"]
    assert "conversations.history" not in methods(fake)


def test_requester_must_be_member():
    s, fake = channel_client(**{"conversations.members": {"ok": True, "members": ["U00000000Z1"]}})
    out = read(s)
    assert out["status"] == "refused" and "not a member" in out["message"]
    assert "conversations.history" not in methods(fake)


def test_no_requester_refused():
    s, fake = channel_client()
    assert read(s, requester="")["status"] == "refused" and fake.calls == []


def test_private_only_in_that_channel_or_dm():
    s, fake = channel_client(**{"conversations.info": PRIVATE})
    out = read(s, {"channel": CH}, current_chat="C0ELSEWHERE")
    assert out["status"] == "refused" and "private" in out["message"]
    assert "conversations.history" not in methods(fake)
    s, _ = channel_client(**{"conversations.info": PRIVATE})
    assert read(s, {"channel": CH}, current_chat=CH)["status"] == "ok"
    s, _ = channel_client(**{"conversations.info": PRIVATE})
    assert read(s, {"channel": CH}, current_chat=DM)["is_private"] is True


def test_dm_only_from_inside_it():
    s, fake = channel_client()
    assert read(s, {"channel": DM}, current_chat=CH)["status"] == "refused" and fake.calls == []
    s, fake = channel_client()
    out = read(s, {}, current_chat=DM)
    assert out["status"] == "ok" and "conversations.members" not in methods(fake)


def test_alert_bot_only_current_channel():
    s, fake = channel_client()
    out = read(s, {"channel": "C0OTHER0001"}, same_channel_only=True)
    assert out["status"] == "refused" and "alert bot" in out["message"] and fake.calls == []
    s, _ = channel_client()
    assert read(s, {}, same_channel_only=True)["status"] == "ok"


def test_not_in_channel_points_at_join():
    s, _ = channel_client(**{"conversations.history": {"ok": False, "error": "not_in_channel"}})
    out = read(s)
    assert out["slack_error"] == "not_in_channel" and out["channel"] == CH and "join_slack_channel" in out["next_step"]
    s, _ = channel_client(**{"conversations.info": PRIVATE,
                             "conversations.history": {"ok": False, "error": "not_in_channel"}})
    out = read(s)
    assert out["status"] == "error" and "next_step" in out and "join_slack_channel" not in out["next_step"]


def test_threads_inlined_and_counted():
    parent = _msg(NOW - 300, "incident started", reply_count=3)
    replies = {"ok": True, "messages": [parent, _msg(NOW - 290, "looking", user="U00000000Z1"),
                                        _msg(NOW - 280, "contained")]}
    s, fake = channel_client(**{"conversations.history": history(parent, _msg(NOW - 100, "all clear")),
                                "conversations.replies": replies})
    out = read(s)
    t = out["transcript"]
    assert t.index("incident started") < t.index("↳") < t.index("contained") < t.index("all clear")
    assert "(1 more replies not read)" in t
    assert out["thread_count"] == 1 and out["threads_read"] == 1
    s, fake = channel_client(**{"conversations.history": history(parent), "conversations.replies": replies})
    read(s, {"include_threads": False})
    assert "conversations.replies" not in methods(fake)


def test_pagination_and_cap():
    pages = iter([history(*[_msg(NOW - i, f"m{i}") for i in range(1, 4)], has_more=True, cursor="c2"),
                  history(*[_msg(NOW - i, f"m{i}") for i in range(4, 7)], has_more=True, cursor="c3")])
    s, fake = channel_client(**{"conversations.history": lambda p: next(pages)})
    out = read(s, {"max_messages": 5})
    hist = [p for m, p in fake.calls if m == "conversations.history"]
    assert len(hist) == 2 and hist[1]["cursor"] == "c2" and hist[1]["limit"] == "2"
    assert out["message_count"] == 5 and out["older_messages_not_read"] is True


def test_truncation_keeps_newest():
    msgs = [_msg(NOW - i * 10, f"msg{i:03d} " + "x" * 200) for i in range(1, 30)]
    s, _ = channel_client(**{"conversations.history": history(*msgs)})
    out = read(s, {"max_chars": 1000})
    assert out["truncated"] and len(out["transcript"]) <= 1002
    assert "msg001" in out["transcript"] and "msg029" not in out["transcript"]
    assert out["last_message_at"] is not None


def test_joins_dropped_and_indicators():
    s, _ = channel_client(**{"conversations.history": history(
        _msg(NOW - 50, "joined", subtype="channel_join"), _msg(NOW - 40, "bad host evil[.]example"))})
    out = read(s)
    assert out["message_count"] == 1 and "joined" not in out["transcript"]
    assert "evil.example" in out["indicators"]["marked_iocs"]


def test_tool_schema_registered():
    spec = st.TOOLS["read_slack_channel"]
    assert spec["parameters"]["required"] == [] and "channel" in spec["parameters"]["properties"]
