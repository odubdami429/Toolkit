"""Tests for the jarvis_guard Slack write tools. A fake transport stands in for Slack; nothing touches the network.

    python -m pytest -q hermes/tests
"""

from __future__ import annotations

import importlib.util
from datetime import datetime, timezone
from pathlib import Path

import pytest

_DIR = Path(__file__).resolve().parents[1] / "plugins" / "jarvis_guard"


def _load(name):
    spec = importlib.util.spec_from_file_location(name, _DIR / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


st = _load("slack_tools")
sw = _load("slack_write_tools")

REQ, BOT, AUDIT, TEAM = "U00000000A1", "U00000000J1", "C00000000C1", "T00000000"
NOW = datetime(2026, 11, 17, 3, 0, tzinfo=timezone.utc)
GROUP = ["U00000000A2", "U00000000A1", "U00000000A3", BOT]


GROUP_ID = "S00000000G1"
FALLBACK_IDS = ["U00000000A2", "U00000000A1", BOT]


@pytest.fixture(autouse=True)
def _org_env(monkeypatch):
    monkeypatch.setenv("JARVIS_SECURITY_GROUP", GROUP_ID)
    monkeypatch.setenv("JARVIS_SECURITY_GROUP_FALLBACK", ",".join(FALLBACK_IDS))
    monkeypatch.setenv("ORG_SECURITY_TEAM", "Security")


class FakeSlack:
    def __init__(self, responses: dict):
        self.responses = responses
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, method: str, params: dict) -> dict:
        self.calls.append((method, params))
        r = self.responses.get(method, {"ok": False, "error": "unexpected"})
        return r(params) if callable(r) else r


def client(responses: dict):
    base = {"auth.test": {"ok": True, "user_id": BOT}, "chat.postMessage": {"ok": True},
            "users.info": lambda p: {"ok": True, "user": {"real_name": f"Name {p['user']}"}}}
    fake = FakeSlack({**base, **responses})
    return st.Slack("xoxb-fake", transport=fake, methods=sw.WRITE_CLIENT_METHODS), fake


def methods(fake):
    return [m for m, _ in fake.calls]


def posts(fake):
    return [(p["channel"], p["text"]) for m, p in fake.calls if m == "chat.postMessage"]


CREATED = {"ok": True, "channel": {"id": "C0NEWCHAN01", "name": "2026-11-17-jane-doe-plist-alert"}}
REASON = "Coordinate response to the EDR plist alert on LAPTOP-0042 <!channel>"


def create(responses, **args):
    s, fake = client(responses)
    a = {"topic": "jane.doe plist alert", "reason": REASON, **args}
    return sw.create_slack_channel(s, a, requester=REQ, team_id=TEAM, audit_channel=AUDIT, now=NOW), fake


# --- client ---------------------------------------------------------------------------------------------------------

def test_read_client_still_refuses_writes():
    s = st.Slack("xoxb-fake", transport=FakeSlack({}))
    for m in ("conversations.create", "conversations.join", "chat.postMessage"):
        with pytest.raises(PermissionError):
            s.call(m)


def test_write_client_allows_only_its_methods():
    s, fake = client({})
    for m in ("conversations.archive", "conversations.kick", "chat.delete", "usergroups.update", "admin.users.list"):
        with pytest.raises(PermissionError):
            s.call(m)
    assert fake.calls == []


# --- channel name ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("topic,expected", [
    ("jane.doe plist alert", "2026-11-17-jane-doe-plist-alert"),
    ("#ir-2026-11-10-ABC-29117 phish", "2026-11-17-abc-29117-phish"),
    ("2026-11-10-idp sign-ins", "2026-11-17-idp-sign-ins"),
    ("IR phishing domain", "2026-11-17-ir-phishing-domain"),
    ("Café   malware!!", "2026-11-17-cafe-malware"),
    ("testing", "2026-11-17-testing"),
    ("a very long topic about the launcher malware popups on many macs",
     "2026-11-17-a-very-long-topic-about-the-launcher"),
])
def test_channel_name(topic, expected):
    assert sw.channel_name(topic, NOW) == (expected, "")


@pytest.mark.parametrize("topic", ["", "  ", "!!", "2026-11-10"])
def test_channel_name_rejects_empty(topic):
    assert sw.channel_name(topic, NOW)[0] is None


# --- create_slack_channel ----------------------------------------------------------------------------------------------

def test_create_happy_path():
    out, fake = create({"usergroups.users.list": {"ok": True, "users": GROUP},
                        "conversations.create": CREATED, "conversations.invite": {"ok": True}})
    assert out["status"] == "ok" and out["invite_source"] == "group" and out["channel"] == "C0NEWCHAN01"
    assert dict(fake.calls)["usergroups.users.list"]["usergroup"] == GROUP_ID
    create_params = dict(fake.calls)["conversations.create"]
    assert create_params == {"name": "2026-11-17-jane-doe-plist-alert", "is_private": "true", "team_id": TEAM}
    invite = dict(fake.calls)["conversations.invite"]
    assert invite["users"] == "U00000000A2,U00000000A1,U00000000A3"  # the bot itself is never invited
    (c1, kickoff), (c2, audit) = posts(fake)
    assert c1 == "C0NEWCHAN01" and c2 == AUDIT
    assert f"<@{REQ}>" in kickoff and "&lt;!channel&gt;" in kickoff and "<!channel>" not in kickoff + audit
    assert out["kickoff_posted"] and out["audit_posted"]


def test_create_fallback_when_group_unreadable():
    out, fake = create({"usergroups.users.list": {"ok": False, "error": "missing_scope"},
                        "conversations.create": CREATED, "conversations.invite": {"ok": True}})
    assert out["invite_source"] == "fallback" and "usergroups:read" in out["fallback_reason"]
    # JARVIS_SECURITY_GROUP_FALLBACK, in order, without the bot itself
    assert dict(fake.calls)["conversations.invite"]["users"] == "U00000000A2,U00000000A1"
    assert out["invited"] == ["Name U00000000A2", "Name U00000000A1"]
    assert "fallback" in posts(fake)[1][1] and GROUP_ID in posts(fake)[1][1]


def test_fallback_ids_from_env(monkeypatch):
    monkeypatch.setenv("JARVIS_SECURITY_GROUP_FALLBACK", " u00000000a1, U00000000A2,,not-an-id,U00000000A1 ")
    assert sw.fallback_ids() == ["U00000000A1", "U00000000A2"]
    monkeypatch.delenv("JARVIS_SECURITY_GROUP_FALLBACK")
    assert sw.fallback_ids() == []


def test_create_refuses_when_group_unreadable_and_no_fallback(monkeypatch):
    monkeypatch.setenv("JARVIS_SECURITY_GROUP_FALLBACK", "")
    out, fake = create({"usergroups.users.list": {"ok": False, "error": "missing_scope"}})
    assert out["status"] == "refused" and "JARVIS_SECURITY_GROUP_FALLBACK" in out["message"]
    assert "conversations.create" not in methods(fake) and posts(fake) == []


@pytest.mark.parametrize("value", [None, "", "   "])
def test_create_refuses_when_group_not_configured(monkeypatch, value):
    if value is None:
        monkeypatch.delenv("JARVIS_SECURITY_GROUP")
    else:
        monkeypatch.setenv("JARVIS_SECURITY_GROUP", value)
    out, fake = create({})
    assert out["status"] == "refused" and "JARVIS_SECURITY_GROUP" in out["message"]
    assert "Escalate to the Security team" in out["message"] and fake.calls == []


def test_escalation_names_the_configured_team(monkeypatch):
    monkeypatch.setenv("ORG_SECURITY_TEAM", "Detection & Response")
    out, _ = create({"usergroups.users.list": {"ok": True, "users": GROUP},
                     "conversations.create": {"ok": False, "error": "invalid_auth"}})
    assert out["status"] == "error" and "Escalate to the Detection & Response team" in out["message"]
    assert "{escalate}" not in out["message"]


def test_create_refuses_a_huge_group_before_creating():
    users = [f"U0MEMBER{i:03d}" for i in range(sw.MAX_GROUP + 1)]
    out, fake = create({"usergroups.users.list": {"ok": True, "users": users}})
    assert out["status"] == "refused" and "conversations.create" not in methods(fake)


def test_create_name_taken_is_not_retried():
    out, fake = create({"usergroups.users.list": {"ok": True, "users": GROUP},
                        "conversations.create": {"ok": False, "error": "name_taken"}})
    assert out["status"] == "name_taken" and methods(fake).count("conversations.create") == 1
    assert "conversations.invite" not in methods(fake) and posts(fake) == []


def test_create_partial_invite():
    inv = {"ok": False, "error": "failed_for_some_users",
           "errors": [{"user": "U00000000A3", "error": "user_disabled"}, {"user": REQ, "error": "already_in_channel"}]}
    out, _ = create({"usergroups.users.list": {"ok": True, "users": GROUP},
                     "conversations.create": CREATED, "conversations.invite": inv})
    assert out["status"] == "partial"
    assert out["not_invited"] == [{"name": "Name U00000000A3", "user_id": "U00000000A3", "slack_error": "user_disabled"}]


def test_create_invite_refused_entirely():
    out, _ = create({"usergroups.users.list": {"ok": True, "users": GROUP},
                     "conversations.create": CREATED, "conversations.invite": {"ok": False, "error": "missing_scope"}})
    assert out["status"] == "created_no_members" and out["created"] is True


@pytest.mark.parametrize("args,why", [
    ({"topic": ""}, "topic"),
    ({"reason": "too short"}, "reason"),
    ({"reason": "testing the tool please"}, "placeholder"),
])
def test_create_input_checks_before_any_call(args, why):
    out, fake = create({}, **args)
    assert out["status"] == "invalid_input" and why in out["message"] and fake.calls == []


def test_create_long_reason_starting_with_test_is_fine():
    out, _ = create({"usergroups.users.list": {"ok": True, "users": GROUP}, "conversations.create": CREATED,
                     "conversations.invite": {"ok": True}},
                    reason="Testing the incident-channel tool end to end, requested in Slack by Pat")
    assert out["status"] == "ok"


def test_create_slack_error_mapped():
    out, _ = create({"usergroups.users.list": {"ok": True, "users": GROUP},
                     "conversations.create": {"ok": False, "error": "restricted_action"}})
    assert out["status"] == "error" and "Workspace policy" in out["message"]


# --- join_slack_channel ---------------------------------------------------------------------------------------------

PUBLIC = {"ok": True, "channel": {"id": "C0PUBLIC001", "name": "eng-alerts", "num_members": 40}}
JOIN_REASON = "Reading the phishing hand-off Pat linked in this thread"


def join(responses, channel="C0PUBLIC001", reason=JOIN_REASON, requester=REQ):
    s, fake = client(responses)
    return sw.join_slack_channel(s, {"channel": channel, "reason": reason}, requester=requester,
                                 audit_channel=AUDIT), fake


def members(*ids):
    return {"ok": True, "members": list(ids), "response_metadata": {"next_cursor": ""}}


def test_join_happy_path_and_audit():
    out, fake = join({"conversations.info": PUBLIC, "conversations.members": members(REQ),
                      "conversations.join": {"ok": True}})
    assert out["status"] == "ok" and out["joined"] is True
    assert posts(fake) == [(AUDIT, f":inbox_tray: Jarvis joined #eng-alerts (C0PUBLIC001) at the request of <@{REQ}>."
                                   f"\n> {JOIN_REASON}\n_Joined so it could read a message linked there. Remove it "
                                   "via #eng-alerts > channel name > Integrations > Apps to undo._")]


@pytest.mark.parametrize("channel", ["<#C0PUBLIC001|eng-alerts>",
                                     "https://example.slack.com/archives/C0PUBLIC001/p1789650398817579"])
def test_join_accepts_mentions_and_links(channel):
    out, fake = join({"conversations.info": PUBLIC, "conversations.members": members(REQ),
                      "conversations.join": {"ok": True}}, channel=channel)
    assert out["status"] == "ok" and dict(fake.calls)["conversations.join"] == {"channel": "C0PUBLIC001"}


def test_join_requires_requester_membership():
    out, fake = join({"conversations.info": PUBLIC, "conversations.members": members("U00000000Z3")})
    assert out["status"] == "refused" and "not a member" in out["message"]
    assert "conversations.join" not in methods(fake) and posts(fake) == []


@pytest.mark.parametrize("ch,why", [
    ({"is_private": True}, "private"), ({"is_archived": True}, "archived"), ({"is_mpim": True}, "DM"),
])
def test_join_refuses_non_public(ch, why):
    info = {"ok": True, "channel": {**PUBLIC["channel"], **ch}}
    out, fake = join({"conversations.info": info, "conversations.members": members(REQ)})
    assert out["status"] == "refused" and why in out["message"] and "conversations.join" not in methods(fake)


def test_join_already_member_is_a_no_op():
    info = {"ok": True, "channel": {**PUBLIC["channel"], "is_member": True}}
    out, fake = join({"conversations.info": info})
    assert out["already_member"] is True and "conversations.join" not in methods(fake) and posts(fake) == []


@pytest.mark.parametrize("channel,reason,status", [
    ("D0SOMEDM01", JOIN_REASON, "refused"), ("#general", JOIN_REASON, "invalid_input"),
    ("C0PUBLIC001", "short", "invalid_input"), ("C0PUBLIC001", "testing a join for the analyst here", "invalid_input"),
])
def test_join_input_checks_before_any_call(channel, reason, status):
    out, fake = join({}, channel=channel, reason=reason)
    assert out["status"] == status and fake.calls == []


def test_join_slack_error_mapped():
    out, _ = join({"conversations.info": PUBLIC, "conversations.members": members(REQ),
                   "conversations.join": {"ok": False, "error": "missing_scope"}})
    assert out["status"] == "error" and "channels:join" in out["message"]


# --- resolve_slack_link hands off to the join -------------------------------------------------------------------------

def test_resolve_not_in_channel_points_at_the_join():
    link = "https://example.slack.com/archives/C0PUBLIC001/p1789650398817579"
    fake = FakeSlack({"conversations.members": members(REQ), "conversations.info": PUBLIC,
                      "conversations.replies": {"ok": False, "error": "not_in_channel"}})
    out = st.resolve_slack_link(st.Slack("xoxb-fake", transport=fake), {"url": link}, requester=REQ,
                                current_chat="C0ELSEWHERE")
    assert out["slack_error"] == "not_in_channel" and out["channel"] == "C0PUBLIC001"
    assert "join_slack_channel" in out["next_step"]
