"""Slack write tools for Jarvis: `create_slack_channel` and `join_slack_channel`.

They live in the Hermes plugin, next to the read tools, because they need the Slack bot token, which only Hermes
holds. Each takes a Slack client limited to WRITE_CLIENT_METHODS (the read tools keep their read-only client) and the
requester from the guard's binding, never from tool input.

- `create_slack_channel`: one private investigation or incident channel named YYYY-MM-DD-<topic> (date from the server
  clock; no "ir-" prefix, since not every channel is incident response), with the live members of the security user
  group (JARVIS_SECURITY_GROUP) invited (the JARVIS_SECURITY_GROUP_FALLBACK list if the group can't be read, refused
  if the group is implausibly large or not configured), a kickoff post in the channel and an audit post in the audit
  channel. The model picks only the topic and the reason, so text in an alert can't get anyone else invited.
  `name_taken` is refused, never auto-suffixed: it usually means this investigation already has a channel.
- `join_slack_channel`: adds Jarvis to one public, unarchived channel the requester is a member of, so it can read a
  message linked there, and announces the join in the audit channel.

Who may call them (JARVIS_WRITERS only for create; any allowlisted person for join; never an alert bot), the per-thread
caps and the off switch are enforced by the guard before these run. Settings are read from the environment at call
time. Standard library only.
"""

from __future__ import annotations

import os
import re
import unicodedata
from datetime import datetime, timezone
from typing import Any, Optional

WRITE_CLIENT_METHODS = frozenset({
    "auth.test", "users.info", "usergroups.users.list", "conversations.info", "conversations.members",
    "conversations.create", "conversations.invite", "conversations.join", "chat.postMessage",
})

MAX_GROUP = 15  # a group this big is the wrong group or a misconfiguration, not an IR team
SLUG_MAX = 40  # YYYY-MM-DD- is 11 characters; Slack allows 80, shorter reads better
MIN_REASON = 20
MAX_MEMBER_PAGES = 10

_USER_ID = re.compile(r"[UW][A-Z0-9]{6,}")
_CHANNEL_ID = re.compile(r"#?([CGD][A-Z0-9]{7,})", re.IGNORECASE)
_ARCHIVES = re.compile(r"/archives/([A-Z0-9]+)", re.IGNORECASE)
_CREATE_PLACEHOLDER = re.compile(r"^(test|testing|asdf|because|reason|n/?a|incident|ir channel)\b", re.IGNORECASE)
_JOIN_PLACEHOLDER = re.compile(r"^(test|testing|asdf|because|reason|n/?a)\b", re.IGNORECASE)


def security_team() -> str:
    """The team that owns Jarvis, for messages (ORG_SECURITY_TEAM, org.env)."""
    return os.environ.get("ORG_SECURITY_TEAM", "").strip() or "Security"


def security_group() -> str:
    """The Slack user group (S...) whose live members create_slack_channel invites (JARVIS_SECURITY_GROUP), or ""."""
    return os.environ.get("JARVIS_SECURITY_GROUP", "").strip()


def fallback_ids() -> list[str]:
    """Invitees used only when the group can't be read (JARVIS_SECURITY_GROUP_FALLBACK), in order, de-duplicated."""
    out: list[str] = []
    for u in os.environ.get("JARVIS_SECURITY_GROUP_FALLBACK", "").split(","):
        u = u.strip().upper()
        if _USER_ID.fullmatch(u) and u not in out:
            out.append(u)
    return out


def _escalate() -> str:
    return f"Escalate to the {security_team()} team"


def _group_label(group: str) -> str:
    return f"the {security_team()} user group ({group})"


# "{escalate}" is filled at call time from ORG_SECURITY_TEAM.
CREATE_ERRORS = {
    "missing_scope": "The Jarvis Slack app is missing the `groups:write` scope, so it can't create private channels. "
                     "{escalate}; don't retry.",
    "restricted_action": "Workspace policy stops Jarvis from creating private channels. A Slack admin has to allow "
                         "it. Don't retry.",
    "invalid_name": "Slack rejected the channel name. Call again with a plainer `topic`.",
    "invalid_name_specials": "Slack rejected the channel name. Call again with a plainer `topic`.",
    "invalid_name_maxlength": "The channel name is too long for Slack. Call again with a shorter `topic`.",
    "invalid_name_required": "The channel name came out empty. Call again with a real `topic`.",
    "no_channel": "Slack wouldn't create the channel. Call again with a different `topic`.",
    "missing_argument": "Slack says an argument is missing (probably team_id). {escalate}; don't retry.",
    "invalid_team_id": "Slack rejected the team ID. {escalate}; don't retry.",
    "team_access_not_granted": "Jarvis isn't granted access to create channels in this workspace. "
                               "{escalate}; don't retry.",
    "ratelimited": "Slack is rate limiting Jarvis. Wait a minute and ask again.",
    "invalid_auth": "The Jarvis Slack token was rejected. {escalate}; don't retry.",
}
INVITE_HINTS = {
    "missing_scope": "Jarvis needs `groups:write`",
    "user_is_restricted": "guest accounts can't be added",
    "user_not_found": "no such user",
    "user_disabled": "account deactivated",
    "ratelimited": "Slack rate-limited the invite",
}
JOIN_ERRORS = {
    "missing_scope": "The Jarvis Slack app is missing the `channels:join` scope. A member of the channel has to add "
                     "Jarvis (/invite @jarvis). Don't retry.",
    "is_archived": "That channel is archived and can't be joined.",
    "method_not_supported_for_channel_type": "That isn't a public channel, so Jarvis can't add itself. A member has "
                                             "to /invite @jarvis.",
    "channel_not_found": "Jarvis can't see that channel.",
    "ratelimited": "Slack is rate limiting Jarvis. Wait a minute and ask again.",
}


def _esc(text: str) -> str:
    """Model-written text goes into Slack posts: it must not ping a channel or fake a link."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _refused(message: str) -> dict:
    return {"status": "refused", "message": message, "next_step": "Relay the message as written. Don't retry."}


def _invalid(message: str) -> dict:
    return {"status": "invalid_input", "message": message,
            "next_step": "Fix the input and call once more, or tell the analyst what's missing."}


def _reason(raw: Any, placeholder: re.Pattern, *, short_placeholder_only: bool) -> tuple[Optional[str], str]:
    reason = " ".join(str(raw or "").split())
    if len(reason) < MIN_REASON:
        return None, (f"`reason` is required and must be at least {MIN_REASON} characters: say what it's for and "
                      "which alert, ticket or thread it relates to. It's posted in the audit channel.")
    if placeholder.match(reason) and (len(reason) < 40 or not short_placeholder_only):
        return None, f"`reason` looks like a placeholder (\"{reason[:40]}\"). Give the real one."
    return reason[:500], ""


def channel_name(topic: Any, now: Optional[datetime] = None) -> tuple[Optional[str], str]:
    """YYYY-MM-DD-<slug> from the topic and the server clock (UTC), or (None, why)."""
    raw = str(topic or "").strip()
    if not raw:
        return None, ("`topic` is required: a few words naming the investigation, e.g. \"jane.doe plist alert\". "
                      "It becomes the channel name YYYY-MM-DD-<topic>.")
    slug = unicodedata.normalize("NFKD", raw).encode("ascii", "ignore").decode().lower()
    slug = re.sub(r"^#", "", slug)
    slug = re.sub(r"^(?:ir[-_ ]?)?\d{4}-?\d{2}-?\d{2}[-_ ]?", "", slug)  # a full channel name passed back
    slug = re.sub(r"[^a-z0-9]+", "-", slug).strip("-")
    if len(slug) > SLUG_MAX:
        cut = slug[:SLUG_MAX]
        slug = re.sub(r"-[^-]*$", "", cut) or cut
    slug = slug.rstrip("-")
    if len(slug) < 3:
        return None, (f"`topic` \"{raw[:60]}\" leaves too little for a channel name once punctuation is removed. "
                      "Use a few plain words naming the investigation.")
    day = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%d")
    return f"{day}-{slug}", ""


def _bot_user(slack) -> str:
    r = slack.call("auth.test")
    return str(r.get("user_id") or "") if r.get("ok") else ""


def _invitees(slack, bot_user: str, group: str) -> tuple[Optional[list[str]], str, Optional[str], Optional[dict]]:
    """(ids, source, fallback_reason, refusal). source is "group" or "fallback"."""
    label = _group_label(group)
    r = slack.call("usergroups.users.list", usergroup=group, include_disabled="false")
    if r.get("ok") and isinstance(r.get("users"), list):
        ids: list[str] = []
        for u in r["users"]:
            u = str(u or "").upper()
            if _USER_ID.fullmatch(u) and u != bot_user and u not in ids:
                ids.append(u)
        if len(ids) > MAX_GROUP:
            return None, "group", None, _refused(
                f"{label} has {len(ids)} members, more than the {MAX_GROUP} this tool invites. That looks "
                f"like the wrong group or a misconfigured one. Nothing was created. {_escalate()}.")
        if ids:
            return ids, "group", None, None
        why = f"{label} has no active members"
    else:
        code = str(r.get("error") or "no_response")
        why = {"missing_scope": "Jarvis is missing the `usergroups:read` scope",
               "no_such_subteam": f"user group {group} doesn't exist",
               "subteam_not_found": f"user group {group} doesn't exist"}.get(code, f"the group lookup failed ({code})")
    fallback = [u for u in fallback_ids() if u != bot_user]
    if not fallback:
        return None, "fallback", why, _refused(
            f"Couldn't read {label} ({why}) and no fallback list is configured (JARVIS_SECURITY_GROUP_FALLBACK), so "
            f"nobody could be invited. Nothing was created. {_escalate()}.")
    return fallback, "fallback", why, None


def _name(slack, uid: str) -> str:
    r = slack.call("users.info", user=uid)
    u = (r.get("user") or {}) if r.get("ok") else {}
    return str(u.get("real_name") or (u.get("profile") or {}).get("real_name") or uid)


def _post(slack, channel: str, text: str) -> bool:
    return bool(slack.call("chat.postMessage", channel=channel, text=text, unfurl_links="false",
                           unfurl_media="false").get("ok"))


# --- create_slack_channel ----------------------------------------------------------------------------------------------

def create_slack_channel(slack, args: dict, *, requester: str, team_id: str, audit_channel: str,
                      now: Optional[datetime] = None) -> dict:
    args = args or {}
    group = security_group()
    if not group:
        return _refused("Channel creation isn't configured: JARVIS_SECURITY_GROUP (the Slack user group to invite) is "
                        f"not set. Nothing was created. {_escalate()}.")
    name, why = channel_name(args.get("topic"), now)
    if not name:
        return _invalid(why)
    reason, why = _reason(args.get("reason"), _CREATE_PLACEHOLDER, short_placeholder_only=True)
    if not reason:
        return _invalid(why)
    reason_safe = _esc(reason)
    bot_user = _bot_user(slack)
    ids, source, fallback_reason, refusal = _invitees(slack, bot_user, group)
    if refusal:
        return refusal

    r = slack.call("conversations.create", name=name, is_private="true", team_id=team_id or None)
    channel = (r.get("channel") or {}) if r.get("ok") else {}
    if not channel.get("id"):
        code = str(r.get("error") or "unknown_error")
        if code == "name_taken":
            return {"status": "name_taken", "channel_name": f"#{name}",
                    "message": f"A channel called #{name} already exists, probably for this same investigation.",
                    "next_step": "Ask the analyst whether to use that one. Only create another if they confirm it's "
                                 "a different one, with a more specific topic."}
        return {"status": "error", "slack_error": code,
                "message": CREATE_ERRORS.get(code, f"Slack wouldn't create #{name}: {code}.").replace(
                    "{escalate}", _escalate()),
                "next_step": "Relay the message. Nothing was created."}
    cid, cname = str(channel["id"]), str(channel.get("name") or name)

    inv = slack.call("conversations.invite", channel=cid, users=",".join(ids), force="true")
    bad: dict[str, str] = {}
    if inv.get("ok") is False and not isinstance(inv.get("errors"), list):
        bad = {u: str(inv.get("error") or "unknown_error") for u in ids}
    else:
        for e in inv.get("errors") or []:
            if isinstance(e, dict) and e.get("user") and e.get("error") != "already_in_channel":
                bad[str(e["user"])] = str(e.get("error") or "error")
    invited = [u for u in ids if u not in bad]
    names = {u: _name(slack, u) for u in ids}
    miss = ("Not invited: " + ", ".join(f"{names[u]} ({INVITE_HINTS.get(e, e)})" for u, e in bad.items())
            + ". Add them by hand: channel name > Members > Add people.") if bad else ""
    source_note = (f"Invited the fallback list because {fallback_reason}: check the members against {_group_label(group)}."
                   if source == "fallback" else "")
    by = f" at the request of <@{requester}>" if requester else ""

    kickoff = (f":mag: *Channel opened*{by}.\n> {reason_safe}\n"
               f"Members: {' '.join(f'<@{u}>' for u in invited) or '_nobody, see below_'}"
               + (f"\n:warning: {miss}" if miss else "") + (f"\n:information_source: {source_note}" if source_note else "")
               + "\n_Created by Jarvis. @-mention Jarvis here to pull in alerts, users or devices._")
    audit = (f":lock: Jarvis created private channel *#{cname}* ({cid}){by}.\n> {reason_safe}\n"
             f"Invited: {', '.join(names[u] for u in invited) or 'nobody'}"
             + (f"\n:warning: {miss}" if miss else "") + (f"\n:information_source: {source_note}" if source_note else "")
             + "\n_Archive it from the channel settings when the work is done._")
    kickoff_posted = _post(slack, cid, kickoff)
    audit_posted = _post(slack, audit_channel, audit) if audit_channel else False

    status = "ok" if not bad else ("partial" if invited else "created_no_members")
    mention = f"<#{cid}>"
    return {
        "status": status, "created": True, "channel": cid, "channel_name": f"#{cname}", "channel_mention": mention,
        "invited": [names[u] for u in invited], "invite_source": source, "fallback_reason": fallback_reason,
        "not_invited": [{"name": names[u], "user_id": u, "slack_error": e} for u, e in bad.items()],
        "reason": reason, "kickoff_posted": kickoff_posted, "audit_posted": audit_posted,
        "message": (f"Created {mention} and invited {', '.join(names[u] for u in invited)}." if status == "ok"
                    else f"Created {mention}, but {miss}"),
        "next_step": ((f"Tell the analyst the channel is ready and link it as {mention}."
                       + (f" Also tell them: {source_note}" if source_note else "")) if status == "ok"
                      else f"Tell the analyst the channel exists ({mention}) and who still needs adding.")
                     + " Don't call create_slack_channel again for this request.",
    }


# --- join_slack_channel ---------------------------------------------------------------------------------------------

def _channel_from(raw: Any) -> Optional[str]:
    cleaned = str(raw or "").strip().lstrip("<").rstrip(">").split("|")[0].strip()
    m = _CHANNEL_ID.fullmatch(cleaned)
    if m:
        return m.group(1).upper()
    if "slack.com/" in cleaned.lower():
        m = _ARCHIVES.search(cleaned)
        return m.group(1).upper() if m else None
    return None


def _is_member(slack, channel: str, user: str) -> tuple[Optional[bool], str]:
    cursor = ""
    for _ in range(MAX_MEMBER_PAGES):
        r = slack.call("conversations.members", channel=channel, limit=1000, cursor=cursor or None)
        if not r.get("ok"):
            return None, str(r.get("error") or "unknown_error")
        if user in (r.get("members") or []):
            return True, ""
        cursor = str((r.get("response_metadata") or {}).get("next_cursor") or "")
        if not cursor:
            return False, ""
    return None, "too_many_members"


def join_slack_channel(slack, args: dict, *, requester: str, audit_channel: str) -> dict:
    args = args or {}
    channel = _channel_from(args.get("channel"))
    if not channel:
        return _invalid("`channel` is required: the channel ID (C…) or the Slack link it came from. "
                        "resolve_slack_link returns it in `channel`. A #name isn't enough.")
    if channel.startswith("D"):
        return _refused("That's a direct message. Jarvis can't join DMs.")
    reason, why = _reason(args.get("reason"), _JOIN_PLACEHOLDER, short_placeholder_only=False)
    if not reason:
        return _invalid(why)
    if not requester:
        return _refused("No single requester is bound to this turn, so the join can't be checked.")

    info = slack.call("conversations.info", channel=channel)
    if not info.get("ok"):
        code = str(info.get("error") or "unknown_error")
        if code == "channel_not_found":
            return _refused(f"<#{channel}> doesn't exist, or it's a private channel Jarvis can't see. A member has "
                            "to /invite @jarvis.")
        return {"status": "error", "slack_error": code, "message": f"Slack refused the channel lookup: {code}.",
                "next_step": "Relay the message. Don't retry."}
    ch = info.get("channel") or {}
    cname = f"#{ch.get('name') or ch.get('name_normalized') or channel}"
    if ch.get("is_im") or ch.get("is_mpim"):
        return _refused("That's a DM or group DM, not a channel. Jarvis can't join it.")
    if ch.get("is_private") or ch.get("is_group"):
        return _refused(f"{cname} is private. Jarvis can only join public channels: a member has to /invite "
                        "@jarvis, or paste the message into this thread.")
    if ch.get("is_archived"):
        return _refused(f"{cname} is archived, so Jarvis can't join it. Ask for the message to be pasted instead.")
    if ch.get("is_member"):
        return {"status": "ok", "joined": False, "already_member": True, "channel": channel, "channel_name": cname,
                "message": f"Jarvis is already in {cname}. Nothing to do.",
                "next_step": "Call resolve_slack_link again with the original link."}

    member, err = _is_member(slack, channel, requester)
    if member is None:
        return _refused(f"Couldn't check whether you're in {cname} ({err}), so Jarvis won't join it.")
    if not member:
        return _refused(f"You're not a member of {cname}, so Jarvis won't join it for you.")

    r = slack.call("conversations.join", channel=channel)
    if not r.get("ok"):
        code = str(r.get("error") or "unknown_error")
        return {"status": "error", "slack_error": code, "channel": channel, "channel_name": cname,
                "message": JOIN_ERRORS.get(code, f"Slack refused the join: {code}."),
                "next_step": "Relay the message. Don't retry."}
    by = f" at the request of <@{requester}>" if requester else ""
    audit = (f":inbox_tray: Jarvis joined {cname} ({channel}){by}.\n> {_esc(reason)}\n"
             f"_Joined so it could read a message linked there. Remove it via {cname} > channel name > Integrations "
             "> Apps to undo._")
    audit_posted = _post(slack, audit_channel, audit) if audit_channel else False
    return {"status": "ok", "joined": True, "already_member": False, "channel": channel, "channel_name": cname,
            "member_count": ch.get("num_members"), "reason": reason, "audit_posted": audit_posted,
            "message": f"Joined {cname}.", "next_step": "Call resolve_slack_link again with the original link."}


TOOLS = {
    "create_slack_channel": {
        "description": (
            "Creates ONE private Slack channel for an investigation or incident, named YYYY-MM-DD-<topic>, invites "
            "the members of "
            "the configured security user group, posts the reason in it and logs it in the audit channel. Only "
            "authorized writers can ask; call it only when the analyst explicitly asks for a channel, at most once per "
            "request. You choose only the topic and reason. On name_taken, ask whether to use the existing channel."),
        "parameters": {
            "type": "object",
            "properties": {
                "topic": {"type": "string", "description": (
                    "2-6 plain words naming the investigation from the request or the alert (user, host, alert "
                    "type, ticket key), e.g. \"jane.doe plist alert\". No date: the tool adds YYYY-MM-DD-.")},
                "reason": {"type": "string", "description": (
                    "At least 20 characters: what the channel is for and which alert, ticket or thread it relates "
                    "to. Posted in the new channel and the audit channel. Start with what was asked.")},
            },
            "required": ["topic", "reason"],
        },
    },
    "join_slack_channel": {
        "description": (
            "Adds Jarvis to ONE public Slack channel so it can read a message the analyst linked there, and "
            "announces the join in the audit channel. Use only after resolve_slack_link returned not_in_channel "
            "for a link the analyst asked about, never speculatively, at most once per channel and twice per "
            "request. The analyst must be a member of the channel. Private, archived and DM targets are refused."),
        "parameters": {
            "type": "object",
            "properties": {
                "channel": {"type": "string", "description": (
                    "The channel ID (C…) from resolve_slack_link's `channel`, or the Slack link.")},
                "reason": {"type": "string", "description": (
                    "At least 20 characters naming this request, e.g. \"reading the phishing hand-off Pat linked "
                    "in #security\". Posted in the audit channel.")},
            },
            "required": ["channel", "reason"],
        },
    },
}
