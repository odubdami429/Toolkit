"""Tests for the vendor-neutral AI-tool entitlement check. A fake IdP adapter module implements user_groups."""

from __future__ import annotations

import json
from types import SimpleNamespace

from providers.insider_risk import ai_entitlement as ae

EMAIL = "jane.doe@acme.example"
SECRET = "fake-idp-secret-token"


class FakeClient:
    def _secrets_for_scrub(self):
        return [SECRET]


def fake_idp(answer=None, raises=None):
    calls = []

    def user_groups(client, email):
        calls.append(email)
        if raises:
            raise raises
        base = {"status": "ok", "email": email, "user_status": "ACTIVE", "groups": [], "truncated": False}
        return {**base, **(answer or {})}

    return SimpleNamespace(user_groups=user_groups), calls


def _run(answer=None, email=EMAIL, raises=None):
    idp, calls = fake_idp(answer, raises)
    return ae.run_tool(idp, FakeClient(), "irm_check_ai_entitlement", {"email": email}), calls


def test_tool_surface():
    assert ae.TOOL_NAMES == {"irm_check_ai_entitlement"}
    assert [t["name"] for t in ae.TOOLS] == ["irm_check_ai_entitlement"]
    assert "sanctioned AI tool" in ae.TOOL["description"]


def test_member_matches_exact_group_names_only():
    out, calls = _run({"groups": ["Everyone", "ai-platform-users", "AI-Assistant-Users", "ai-assistant-users-old"]})
    assert out["status"] == "ok" and out["result"] == "member" and out["matched_groups"] == ["ai-platform-users"]
    assert out["account_status"] == "ACTIVE" and calls == [EMAIL]
    assert "Everyone" not in json.dumps(out)


def test_not_member():
    out, _ = _run({"groups": ["Everyone", "other-ai-users"]})
    assert out["status"] == "ok" and out["result"] == "not_member" and out["matched_groups"] == []


def test_unknown_cases():
    out, _ = _run({"status": "not_found", "user_status": None})
    assert out["result"] == "unknown" and "No identity provider user" in out["reason"]
    out, _ = _run({"user_status": "SUSPENDED", "groups": ["ai-platform-users"]})
    assert out["result"] == "unknown" and out["account_status"] == "SUSPENDED"
    out, _ = _run({"status": "ambiguous", "message": "2 users match."})
    assert out["result"] == "unknown" and "ambiguous" in out["reason"]


def test_truncated_group_list_is_unknown_unless_matched():
    out, _ = _run({"groups": [f"g-{i}" for i in range(200)], "truncated": True})
    assert out["result"] == "unknown" and "cut off" in out["reason"]
    out, _ = _run({"groups": ["g-1", "ai-assistant-users"], "truncated": True})
    assert out["result"] == "member"


def test_bad_email_and_errors_are_unknown_never_member():
    for bad in ("", "jane", "jane@personal-mail.net", "jane@acme.example.evil.example"):
        out, calls = _run(email=bad)
        assert out["status"] == "error" and out["result"] == "unknown" and not calls
    out, _ = _run({"status": "error", "message": "HTTP 500"})
    assert out["status"] == "error" and out["result"] == "unknown" and out["next_step"] and "HTTP 500" in out["reason"]
    out, _ = _run(raises=RuntimeError("boom"))
    assert out["status"] == "error" and out["result"] == "unknown"
    assert ae.run_tool(None, None, "irm_check_ai_entitlement", {"email": EMAIL})["result"] == "unknown"
    idp, _ = fake_idp()
    assert ae.run_tool(idp, None, "irm_check_ai_entitlement", {"email": EMAIL})["result"] == "unknown"
    assert ae.run_tool(idp, FakeClient(), "other", {})["status"] == "error"


def test_mailto_form_and_secret_never_in_output():
    out, calls = _run({"groups": ["ai-assistant-users"]}, email="<mailto:Jane.Doe@acme.example>")
    assert out["result"] == "member" and out["email"] == EMAIL and calls == [EMAIL]
    out, _ = _run({"status": "error", "message": f"token {SECRET} rejected"})
    assert SECRET not in json.dumps(out)


def test_sanctioned_groups_come_from_env():
    assert ae.SANCTIONED_GROUPS == ("ai-assistant-users", "ai-platform-users")
    assert ae.ORG_DOMAIN == "@acme.example"
    assert "ai-assistant-users, ai-platform-users" in ae.TOOL["description"]
    assert "Sanctioned AI tools here: Example AI Assistant (assistant.example.net)" in ae.TOOL["description"]


def test_no_sanctioned_groups_configured_is_unknown(monkeypatch):
    monkeypatch.setattr(ae, "SANCTIONED_GROUPS", ())
    out, calls = _run({"groups": ["ai-assistant-users"]})
    assert out["result"] == "unknown" and "SANCTIONED_AI_GROUPS" in out["reason"] and not calls
