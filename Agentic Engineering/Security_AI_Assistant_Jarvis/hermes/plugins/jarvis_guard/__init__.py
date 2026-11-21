"""Jarvis guard: requester binding and gating for every tool call, bot-trigger filtering, jarvis-tools call signing,
the Slack tools, and the `jarvis_whoami` actor-binding probe.

Every call to a jarvis-tools MCP tool gets a `jarvis_auth` argument injected via `modify`: the bound requester, their
work email, session key, tool-call ID, timestamp, the alert bot's thread-root post (alert-bot calls only) and an HMAC
over them (per-boot key shared only with jarvis-tools). jarvis-tools refuses calls without a valid one, so the
specialists fail closed if this guard is missing or bypassed.

Alert bots: SLACK_ALLOW_BOTS=mentions makes Hermes let ANY bot that @-mentions Jarvis skip SLACK_ALLOWED_USERS, but
the Slack adapter's early sender check doesn't apply that bypass, so a trigger bot must also be in
SLACK_ALLOWED_USERS. The pre_gateway_dispatch hook drops every bot message except a trigger bot (JARVIS_TRIGGER_BOTS)
in a bot channel (JARVIS_BOT_CHANNELS), under an hourly cap, before Hermes's own auth runs. That hook fails open
(Hermes logs a hook exception and dispatches anyway), so pre_tool_call re-checks the requester and fails closed, and
never treats a trigger bot as a person even though it is in SLACK_ALLOWED_USERS.

Not here: per-request budgets (jarvis-tools caps its own tools; the provider write gate is in jarvis-tools, keyed on the
signed requester and JARVIS_WRITERS). register() stays free of network calls (10 s load timeout). Every
decision is one JSON line on the container init's stderr, which docker sends to journald under the jarvis-hermes
tag, outside HERMES_HOME.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import sys
import threading
import time
from typing import Any, Optional

from gateway import session_context as _sc
from gateway.session_context import bound_session_key

from . import slack_format, slack_tools, slack_write_tools

# Private names, pinned to v0.23.1 (sha256:276d4468…). get_session_env() falls back to os.environ when a ContextVar
# was never bound in this context, so read the ContextVars directly and treat "never bound" as empty.
_bound_session_value = _sc._bound_session_value
_UNSET = _sc._UNSET

# Hermes redirects its own stderr into $HERMES_HOME/logs/gateway-stdio.log, which Hermes can rewrite. Write to the
# container init's stderr instead (docker --init: PID 1 is docker-init, running as the same UID), which docker sends
# to journald outside the container. Shipping them off the host is left to the deployment.
def _audit_stream():
    try:
        return open("/proc/1/fd/2", "w", buffering=1, encoding="utf-8")
    except OSError:
        return sys.stderr


_log = logging.getLogger("jarvis_guard")
if not _log.handlers:
    _handler = logging.StreamHandler(_audit_stream())
    _handler.setFormatter(logging.Formatter("%(message)s"))
    _log.addHandler(_handler)
    _log.setLevel(logging.INFO)
    _log.propagate = False

PLUGIN_VERSION = "1.1.0"  # keep in step with plugin.yaml
BLOCKED_TOOLS = frozenset({"skill_manage", "clarify"})
_ACTOR_VARS = ("HERMES_SESSION_PLATFORM", "HERMES_SESSION_ACTOR_ID", "HERMES_SESSION_ACTOR_NAME",
               "HERMES_SESSION_USER_ID", "HERMES_SESSION_CHAT_ID", "HERMES_SESSION_THREAD_ID")


def _bound(name: str) -> str:
    value = _bound_session_value(name)
    return "" if value is _UNSET or value is None else str(value)


def _binding() -> dict[str, Any]:
    """What this turn is bound to, from ContextVars only. Identity values in the process env are a tripwire:
    Hermes never puts them there (it does write HERMES_SESSION_ID, which isn't identity), so their presence
    means someone planted them."""
    planted = sorted(k for k in (*_ACTOR_VARS, "HERMES_SESSION_KEY") if k in os.environ)
    return {
        "session_key": bound_session_key(),
        "env_planted": planted,
        **{name.removeprefix("HERMES_SESSION_").lower(): _bound(name) for name in _ACTOR_VARS},
    }


def _pinned_team() -> str:
    """The one Slack workspace Jarvis serves (managed .env, checked by jarvis-preflight). Read per call, not at
    import, so it doesn't depend on when Hermes applies the .env."""
    return os.environ.get("JARVIS_SLACK_TEAM_ID", "").strip()


def _slack_team(session_key: str) -> str:
    """The Slack team ID in a session key (<ns>:slack:<chat_type>:<team>:...), or "" if it has none. Hermes puts
    the team (scope_id) right after the chat type, so a bot token from another workspace fails closed."""
    parts = session_key.split(":")
    try:
        team = parts[parts.index("slack") + 2]
    except (ValueError, IndexError):
        return ""
    return team if team.startswith(("T", "E")) else ""


def _id_set(name: str) -> frozenset[str]:
    """A comma-separated ID list from the environment (managed .env or org.env), read per call like the pinned
    team."""
    return frozenset(v.strip() for v in os.environ.get(name, "").split(",") if v.strip())


def _is_trigger_bot(actor_id: str) -> bool:
    return bool(actor_id) and actor_id in _id_set("JARVIS_TRIGGER_BOTS")


def _requester_allowed(actor_id: str, chat_id: str) -> bool:
    """An allowlisted person anywhere Hermes admits them, or a trigger bot in one of its bot channels. Trigger bots
    are in SLACK_ALLOWED_USERS only to get past the adapter's early check, so they never count as people here."""
    if _is_trigger_bot(actor_id):
        return bool(chat_id) and chat_id in _id_set("JARVIS_BOT_CHANNELS")
    return bool(actor_id) and actor_id in _id_set("SLACK_ALLOWED_USERS")


def _deny_reason(tool_name: str, b: dict[str, Any]) -> Optional[str]:
    if tool_name in BLOCKED_TOOLS:
        return f"{tool_name} is disabled for Jarvis"
    if b["env_planted"]:
        return "session identity found in the process environment"
    if not b["session_key"]:
        return "no session bound to this turn"
    if b["platform"] != "slack":
        return "not a Slack turn"
    pinned = _pinned_team()
    if not pinned or _slack_team(b["session_key"]) != pinned:
        return "not the pinned Slack workspace"
    if not b["actor_id"]:
        return "no single requester for this turn (merged input or unbound actor)"
    if not _requester_allowed(b["actor_id"], b["chat_id"]):
        return "requester is not allowlisted here"
    return None


# Bot triggers allowed in the last hour, across all trigger bots and channels: an alert storm or a looping workflow
# stops here, before any model spend. In memory, so a restart resets it.
_BOT_TRIGGER_WINDOW_S = 3600
_bot_triggers: list[float] = []
_bot_lock = threading.Lock()


def _bot_triggers_per_hour() -> int:
    try:
        return max(0, int(os.environ.get("JARVIS_BOT_TRIGGERS_PER_HOUR", "20")))
    except ValueError:
        return 0


def _bot_skip_reason(source: Any) -> Optional[str]:
    """Why a bot-authored Slack message must not start a turn, or None to let Hermes handle it."""
    platform = getattr(getattr(source, "platform", None), "value", getattr(source, "platform", ""))
    if str(platform) != "slack" or getattr(source, "is_bot", False) is not True:
        return None
    user_id = str(getattr(source, "user_id", "") or "")
    chat_id = str(getattr(source, "chat_id", "") or "")
    if not _is_trigger_bot(user_id):
        return "bot is not a trigger bot"
    if getattr(source, "chat_type", "") != "group" or chat_id not in _id_set("JARVIS_BOT_CHANNELS"):
        return "bot trigger outside the bot channels"
    pinned = _pinned_team()
    if not pinned or str(getattr(source, "scope_id", "") or "") != pinned:
        return "not the pinned Slack workspace"
    now = time.monotonic()
    with _bot_lock:
        _bot_triggers[:] = [t for t in _bot_triggers if now - t < _BOT_TRIGGER_WINDOW_S]
        if len(_bot_triggers) >= _bot_triggers_per_hour():
            return "hourly bot trigger cap reached"
        _bot_triggers.append(now)
    return None


def _on_pre_gateway_dispatch(event: Any = None, **_: Any) -> Optional[dict[str, Any]]:
    source = getattr(event, "source", None)
    if getattr(source, "is_bot", False) is not True:
        return None
    reason = _bot_skip_reason(source)
    _log.info(json.dumps({
        "jarvis_guard": "bot_trigger", "decision": "skip" if reason else "allow", "reason": reason,
        "user_id": getattr(source, "user_id", None), "chat_id": getattr(source, "chat_id", None),
        "thread_id": getattr(source, "thread_id", None), "message_id": getattr(source, "message_id", None),
    }, sort_keys=True))
    if reason:
        return {"action": "skip", "reason": f"jarvis_guard: {reason}"}
    return None


JARVIS_TOOLS_TOOLSET = "mcp-jarvis_tools"
# How Hermes may prefix an MCP tool's registry name; jarvis-tools signs and verifies its own (unprefixed) name.
_MCP_NAME_PREFIXES = ("mcp__jarvis_tools__", "mcp_jarvis_tools_", "mcp-jarvis_tools-", "jarvis_tools__", "jarvis_tools_")


def _jarvis_tools_name(tool_name: str) -> Optional[str]:
    """The jarvis-tools tool name if this call goes to the jarvis_tools MCP server, else None."""
    try:
        from tools.registry import registry
        toolset = registry.get_toolset_for_tool(tool_name)
    except Exception:
        toolset = None
    if toolset != JARVIS_TOOLS_TOOLSET:
        return None
    for prefix in _MCP_NAME_PREFIXES:
        if tool_name.startswith(prefix):
            return tool_name[len(prefix):]
    return tool_name


# Requester work emails, from the requester's Slack ID (users.info), so jarvis-tools can act as the requester (e.g.
# enterprise search permissions) from a value the model can't supply. Cached an hour; "" when Slack doesn't give one.
_EMAIL_TTL_S = 3600
_emails: dict[str, tuple[str, float]] = {}


def _actor_email(actor_id: str) -> str:
    hit = _emails.get(actor_id)
    if hit and time.time() - hit[1] < _EMAIL_TTL_S:
        return hit[0]
    try:
        r = _slack_client().call("users.info", user=actor_id)
        user = (r.get("user") or {}) if r.get("ok") else {}
        email = "" if user.get("is_bot") or user.get("deleted") else str((user.get("profile") or {}).get("email") or "")
    except Exception:  # noqa: BLE001 - no email means act-as tools refuse; others are unaffected
        email = ""
    _emails[actor_id] = (email.lower(), time.time())
    return email.lower()


# Alert-bot calls: the trigger bot's own unedited thread-root post, read from Slack here so neither the model nor a
# later edit can change it, is signed whole as `alert_post`. jarvis-tools' provider adapter for the specialist's
# domain extracts the alert IDs it may act on automatically from that post; this guard knows nothing about vendors or
# ID formats. Any other requester gets alert_post "".
_ALERT_POST_MAX = 20000
_ALERT_ROOT_TTL_S = 600
_alert_roots: dict[tuple[str, str], tuple[str, float]] = {}  # (chat, thread) -> (root post blob, when read)


def _alert_root(b: dict[str, Any]) -> str:
    """The trigger bot's own unedited thread-root post (text, blocks, attachments) as one string, or "" (not a trigger
    bot in a bot channel, not the bot's own unedited root post, or any Slack error)."""
    actor, chat, thread = b["actor_id"], b["chat_id"], b["thread_id"]
    if not (thread and _requester_allowed(actor, chat) and _is_trigger_bot(actor)):
        return ""
    cached = _alert_roots.get((chat, thread))
    if cached and time.monotonic() - cached[1] < _ALERT_ROOT_TTL_S:
        return cached[0]
    try:
        r = _slack_client().call("conversations.replies", channel=chat, ts=thread, limit=1, inclusive="true")
    except Exception:  # noqa: BLE001 - no post is the safe answer
        r = {}
    msgs = (r.get("messages") or []) if r.get("ok") else []
    root = msgs[0] if msgs and isinstance(msgs[0], dict) else {}
    blob = ""
    if root.get("ts") == thread and root.get("user") == actor and not root.get("edited"):
        blob = json.dumps({k: root.get(k) for k in ("text", "blocks", "attachments")})[:_ALERT_POST_MAX]
    _alert_roots[(chat, thread)] = (blob, time.monotonic())
    _log.info(json.dumps({"jarvis_guard": "alert_root", "chat_id": chat, "thread_id": thread, "actor_id": actor,
                          "slack_ok": bool(r.get("ok")), "usable": bool(blob), "length": len(blob),
                          "sha256": hashlib.sha256(blob.encode()).hexdigest()[:16] if blob else None},
                         sort_keys=True))
    return blob


def _sign(server_tool: str, b: dict[str, Any], tool_call_id: str) -> Optional[dict[str, Any]]:
    """jarvis_auth for one jarvis-tools call. sig = HMAC-SHA256(key, "|".join([tool, actor, session_key,
    tool_call_id, ts, actor_email, sha256_hex(alert_post)]))."""
    key = os.environ.get("JARVIS_GUARD_HMAC_KEY", "").encode()
    if not key:
        return None
    ts = int(time.time())
    email = _actor_email(b["actor_id"])
    alert_post = _alert_root(b)
    message = "|".join([server_tool, b["actor_id"], b["session_key"], tool_call_id, str(ts), email,
                        hashlib.sha256(alert_post.encode()).hexdigest()]).encode()
    return {"actor": b["actor_id"], "actor_email": email, "alert_post": alert_post,
            "session_key": b["session_key"], "tool_call_id": tool_call_id, "ts": ts,
            "sig": hmac.new(key, message, hashlib.sha256).hexdigest()}


def _on_pre_tool_call(tool_name: str = "", args: Any = None, session_id: str = "", turn_id: str = "",
                      tool_call_id: str = "", **_: Any) -> Optional[dict[str, Any]]:
    _patch_mentions()  # no-op once done; covers an adapter that loaded after register()
    b = _binding()
    reason = _deny_reason(tool_name, b)
    server_tool = None if reason else _jarvis_tools_name(tool_name)
    auth = None
    if server_tool:
        auth = _sign(server_tool, b, tool_call_id or os.urandom(8).hex())
        if auth is None:
            reason = "jarvis-tools signing key missing"
    _log.info(json.dumps({
        "jarvis_guard": "pre_tool_call", "decision": "block" if reason else "allow", "reason": reason,
        "tool": tool_name, "session_id": session_id, "turn_id": turn_id, "tool_call_id": tool_call_id,
        "signed_for": server_tool if auth else None, **b,
    }, sort_keys=True))
    if reason:
        return {"action": "block", "message": f"Blocked by jarvis_guard: {reason}."}
    if auth:
        # Shallow-merged into the args before dispatch, so the model can't supply or override it.
        return {"action": "modify", "args": {"jarvis_auth": auth}}
    return None


def _whoami(*_args: Any, **_kwargs: Any) -> str:
    """Diagnostic probe: the binding as a plugin tool handler sees it (no secrets, read-only)."""
    b = _binding()
    _log.info(json.dumps({"jarvis_guard": "jarvis_whoami", **b}, sort_keys=True))
    return json.dumps(b)


# Hermes v0.23.1 rewrites every inbound <@UID> to "@DisplayName" (SlackAdapter._humanize_user_mentions), so Jarvis
# never sees the ID of someone the analyst mentions and can't look them up. Keep the ID next to the name. Pinned to
# v0.23.1 internals like the session ContextVars above; patched once, as soon as the Slack adapter module is loaded.
_SLACK_ADAPTER_MODULE = "hermes_plugins.platforms__slack.adapter"
_mentions_patched = False


async def _humanize_keep_ids(self, text: str, chat_id: str = "", team_id: str = "") -> str:
    if not text or "<@" not in text:
        return text
    for uid in set(re.findall(r"<@([A-Z0-9]+)(?:\|[^>]*)?>", text)):
        name = await self._resolve_user_name(uid, chat_id=chat_id, team_id=team_id)
        display = (name or uid).strip() or uid
        label = f"@{display} ({uid})" if display != uid else f"@{uid}"
        text = re.sub(rf"<@{uid}(?:\|[^>]*)?>", lambda _m, _label=label: _label, text)
    return text


def _patch_mentions() -> bool:
    global _mentions_patched
    if _mentions_patched:
        return True
    mod = sys.modules.get(_SLACK_ADAPTER_MODULE)
    if mod is None:
        return False
    for obj in vars(mod).values():
        if isinstance(obj, type) and callable(getattr(obj, "_humanize_user_mentions", None)) \
                and callable(getattr(obj, "_resolve_user_name", None)):
            obj._humanize_user_mentions = _humanize_keep_ids
            _mentions_patched = True
            _log.info(json.dumps({"jarvis_guard": "mention_ids_patched", "class": obj.__name__}, sort_keys=True))
    return _mentions_patched


def _patch_mentions_when_loaded(timeout_s: float = 120.0) -> None:
    """Hermes imports the Slack adapter after plugins register but before Slack connects: poll until it's there."""
    deadline = time.monotonic() + timeout_s
    while not _patch_mentions() and time.monotonic() < deadline:
        time.sleep(0.1)
    if not _mentions_patched:
        _log.info(json.dumps({"jarvis_guard": "mention_ids_not_patched"}, sort_keys=True))


_slack: Optional[slack_tools.Slack] = None


def _slack_client() -> slack_tools.Slack:
    global _slack
    if _slack is None:
        _slack = slack_tools.Slack(os.environ.get("SLACK_BOT_TOKEN", ""))
    return _slack


def _slack_handler(name: str):
    """Handler for a Slack read tool. The pre_tool_call hook has already checked the workspace and requester."""
    def handler(args: Any = None, **_kwargs: Any) -> str:
        b = _binding()
        args = args if isinstance(args, dict) else {}
        try:
            if name == "lookup_slack_user":
                result = slack_tools.lookup_slack_user(_slack_client(), args)
            else:
                read = slack_tools.read_slack_channel if name == "read_slack_channel" else slack_tools.resolve_slack_link
                result = read(_slack_client(), args, requester=b["actor_id"], current_chat=b["chat_id"],
                              same_channel_only=_is_trigger_bot(b["actor_id"]))
        except Exception as e:  # noqa: BLE001 - a tool error must not take down the turn
            result = {"status": "error", "message": f"{name} failed ({type(e).__name__})."}
        _log.info(json.dumps({"jarvis_guard": "slack_tool", "tool": name, "actor_id": b["actor_id"],
                              "chat_id": b["chat_id"], "session_key": b["session_key"],
                              "status": result.get("status"), "slack_error": result.get("slack_error"),
                              "target": result.get("channel") or result.get("user_id")}, sort_keys=True))
        return json.dumps(result)
    return handler


# Slack write tools (create_slack_channel, join_slack_channel). Their own client, limited to the methods they need, so
# the read tools stay read-only. create_slack_channel: writers only (JARVIS_WRITERS, org.env). join_slack_channel:
# any allowlisted person. Never an alert bot. Per-thread caps over 10 minutes; JARVIS_SLACK_WRITES_ENABLED=false
# (secret key jarvis_slack_writes_enabled) turns both off.
_SLACK_WRITE_CAPS = {"create_slack_channel": 1, "join_slack_channel": 2}
_SLACK_WRITE_WINDOW_S = 600
_slack_write_calls: dict[tuple[str, str], list[float]] = {}
_slack_writer: Optional[slack_tools.Slack] = None


def _slack_write_client() -> slack_tools.Slack:
    global _slack_writer
    if _slack_writer is None:
        _slack_writer = slack_tools.Slack(os.environ.get("SLACK_BOT_TOKEN", ""),
                                          methods=slack_write_tools.WRITE_CLIENT_METHODS)
    return _slack_writer


def _slack_write_refusal(name: str, b: dict[str, Any]) -> Optional[str]:
    """Why this requester can't run this Slack write now, or None. Counts the call when allowed."""
    actor = b["actor_id"]
    if os.environ.get("JARVIS_SLACK_WRITES_ENABLED", "true").strip().lower() == "false":
        return "Jarvis's Slack actions (creating and joining channels) are switched off right now."
    if not actor or _is_trigger_bot(actor) or actor not in _id_set("SLACK_ALLOWED_USERS"):
        return "Only a person on Jarvis's allowlist can ask it to create or join channels."
    if name == "create_slack_channel" and actor not in _id_set("JARVIS_WRITERS"):
        return "Creating channels is limited to Jarvis's authorized writers. Ask one of them."
    key, now = (name, b["session_key"]), time.monotonic()
    with _bot_lock:
        recent = [t for t in _slack_write_calls.get(key, []) if now - t < _SLACK_WRITE_WINDOW_S]
        if len(recent) >= _SLACK_WRITE_CAPS[name]:
            _slack_write_calls[key] = recent
            return (f"{name} already ran {len(recent)} time(s) in this thread in the last 10 minutes, the most "
                    "allowed. Report the earlier result instead.")
        _slack_write_calls[key] = recent + [now]
    return None


def _slack_write_handler(name: str):
    def handler(args: Any = None, **_kwargs: Any) -> str:
        b = _binding()
        args = args if isinstance(args, dict) else {}
        refusal = _slack_write_refusal(name, b)
        if refusal:
            result = {"status": "refused", "message": refusal, "next_step": "Relay the message. Nothing was changed."}
        else:
            try:
                if name == "create_slack_channel":
                    result = slack_write_tools.create_slack_channel(
                        _slack_write_client(), args, requester=b["actor_id"], team_id=_pinned_team(),
                        audit_channel=os.environ.get("JARVIS_AUDIT_CHANNEL", "").strip())
                else:
                    result = slack_write_tools.join_slack_channel(
                        _slack_write_client(), args, requester=b["actor_id"],
                        audit_channel=os.environ.get("JARVIS_AUDIT_CHANNEL", "").strip())
            except Exception as e:  # noqa: BLE001 - a tool error must not take down the turn
                result = {"status": "error", "outcome_unknown": True,
                          "message": f"{name} failed partway ({type(e).__name__}). Check Slack before asking again.",
                          "next_step": "Tell the analyst it may or may not have happened; don't retry."}
        _log.info(json.dumps({"jarvis_guard": "slack_write", "tool": name, "actor_id": b["actor_id"],
                              "chat_id": b["chat_id"], "session_key": b["session_key"],
                              "status": result.get("status"), "slack_error": result.get("slack_error"),
                              "channel": result.get("channel"), "channel_name": result.get("channel_name"),
                              "invite_source": result.get("invite_source"),
                              "args": {k: str(v)[:300] for k, v in args.items()}}, sort_keys=True))
        return json.dumps(result)
    return handler


def _on_transform_llm_output(response_text: Any = "", **_: Any) -> Optional[str]:
    """Bold labels written Slack-style (`*x*`) would otherwise post as italics (see slack_format). Never raises:
    the stream is held for this hook, so an exception would withhold the reply; None keeps the original."""
    try:
        if not isinstance(response_text, str):
            return None
        out = slack_format.slack_to_markdown(response_text)
        return out if out and out != response_text else None
    except Exception:  # pragma: no cover - the formatter is regex-only
        return None


_WHOAMI_DESCRIPTION = ("Report which Slack user, channel and thread this turn is bound to. Diagnostic only; "
                       "use it when asked who you think is talking to you.")


def register(ctx) -> None:
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
    ctx.register_hook("pre_gateway_dispatch", _on_pre_gateway_dispatch)
    # hold_stream: the rewrite must land before Slack sees the reply, so replies aren't streamed.
    ctx.register_hook("transform_llm_output", _on_transform_llm_output, hold_stream=True)
    handle = ctx.register_tool(
        name="jarvis_whoami", toolset="jarvis_guard", handler=_whoami, description=_WHOAMI_DESCRIPTION,
        schema={"name": "jarvis_whoami", "description": _WHOAMI_DESCRIPTION,
                "parameters": {"type": "object", "properties": {}}},
    )
    # Load canary: Hermes skips a plugin that fails to load, and ignores the registrations of one that overran the
    # load timeout, then keeps running. jarvis-guard-canary (ExecStartPost) stops the unit unless this line, with
    # this start's nonce, reaches journald before Slack connects. Only claim "loaded" if Hermes took the tool.
    handles = [handle]
    for name, spec in slack_tools.TOOLS.items():
        handles.append(ctx.register_tool(
            name=name, toolset="jarvis_guard", handler=_slack_handler(name), description=spec["description"],
            schema={"name": name, **spec}))
    for name, spec in slack_write_tools.TOOLS.items():
        handles.append(ctx.register_tool(
            name=name, toolset="jarvis_guard", handler=_slack_write_handler(name), description=spec["description"],
            schema={"name": name, **spec}))
    if any(h is None for h in handles):
        _log.info(json.dumps({"jarvis_guard": "registration_rejected"}, sort_keys=True))
        return
    if not _patch_mentions():
        threading.Thread(target=_patch_mentions_when_loaded, name="jarvis_guard_mentions", daemon=True).start()
    _log.info(json.dumps({"jarvis_guard": "loaded", "version": PLUGIN_VERSION, "slack_team": _pinned_team(),
                          "writers": len(_id_set("JARVIS_WRITERS")),
                          "trigger_bots": sorted(_id_set("JARVIS_TRIGGER_BOTS")),
                          "bot_channels": sorted(_id_set("JARVIS_BOT_CHANNELS")),
                          "boot_nonce": os.environ.get("JARVIS_GUARD_BOOT_NONCE", "")}, sort_keys=True))
