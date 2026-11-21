"""jarvis-tools: the MCP server Hermes calls for Jarvis's specialist agents.

Every tool call must carry `jarvis_auth`, which Hermes's jarvis_guard plugin injects in pre_tool_call: the Slack
requester bound to the turn, the session and tool-call IDs, a timestamp, the requester's email, the alert bot's own
post (alert-bot requests only) and an HMAC over them with a per-boot key. The server refuses calls without a valid,
fresh, unused one, so a missing or bypassed guard fails closed here. That's a channel check between the two
containers, not authorization: a compromised Hermes holds the key too.

Specialists are named by security domain (EDR, identity provider, ...). Which vendor implements a domain is a
deployment choice (`<PREFIX>_PROVIDER` in org.env, see providers/__init__.py); this module only knows the domain
interface, never a vendor.
"""

from __future__ import annotations

import dataclasses
import functools
import hashlib
import hmac
import json
import logging
import os
import sys
import threading
import time
import uuid
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

import anyio
import uvicorn
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

import org
import providers
import web_tools
from providers.insider_risk import ai_entitlement
from specialist import Specialist, run_specialist

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(message)s")
# httpx logs every request URL at INFO, query values (emails, hashes) included, duplicating our own request lines.
logging.getLogger("httpx").setLevel(logging.WARNING)
log = logging.getLogger("jarvis_tools")

TOOLS_TOKEN = os.environ["JARVIS_TOOLS_TOKEN"]
HMAC_KEY = os.environ["JARVIS_GUARD_HMAC_KEY"].encode()
MAX_SKEW_S = 300
HERE = Path(__file__).resolve().parent

_seen_calls: dict[str, float] = {}
_seen_lock = threading.Lock()


def _audit(event: str, **fields) -> None:
    log.info(json.dumps({"jarvis_tools": event, **fields}, sort_keys=True, default=str))


def verify_auth(tool: str, auth: dict | None) -> tuple[str, str | None]:
    """Return (actor, None) for a valid jarvis_auth, else ("", reason)."""
    if not isinstance(auth, dict):
        return "", "missing jarvis_auth (the Hermes guard didn't sign this call)"
    actor = str(auth.get("actor", ""))
    session_key = str(auth.get("session_key", ""))
    call_id = str(auth.get("tool_call_id", ""))
    ts = auth.get("ts")
    sig = str(auth.get("sig", ""))
    if not (actor and session_key and call_id and isinstance(ts, int) and sig):
        return "", "incomplete jarvis_auth"
    # actor_email is signed too: it's who enterprise search acts as, so it must come from the guard, never the model.
    # So is alert_post (as its SHA-256): the alert bot's own post, the only source of IDs an automatic action may touch.
    post_hash = hashlib.sha256(str(auth.get("alert_post", "")).encode()).hexdigest()
    message = "|".join([tool, actor, session_key, call_id, str(ts), str(auth.get("actor_email", "")),
                        post_hash]).encode()
    expected = hmac.new(HMAC_KEY, message, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return "", "bad jarvis_auth signature"
    if abs(time.time() - ts) > MAX_SKEW_S:
        return "", "stale jarvis_auth"
    now = time.time()
    with _seen_lock:
        for k, t in list(_seen_calls.items()):
            if now - t > 2 * MAX_SKEW_S:
                del _seen_calls[k]
        if call_id in _seen_calls:
            return "", "replayed jarvis_auth"
        _seen_calls[call_id] = now
    return actor, None


# --- Adapters, clients and writers ----------------------------------------------------------------------------------
# One adapter per domain (None when the domain is disabled in org.env). A domain is available when its adapter and
# its client (tenant + credential) both exist.

WEB = "web_research"
TICKETING = "ticketing"
ENTERPRISE_SEARCH = "enterprise_search"
SPECIALIST_DOMAINS = ("edr", "idp", "productivity_suite", "email_security", "brand_protection", "insider_risk")

ADAPTERS: dict[str, providers.Adapter | None] = {k: providers.load(k) for k in providers.DOMAINS}


def _title(domain: str) -> str:
    return "Web research" if domain == WEB else providers.DOMAINS[domain].title


def _new_client(domain: str) -> Any:
    ad = ADAPTERS.get(domain)
    if ad is None:
        return None
    try:
        return ad.read.client_from_env(os.environ)
    except Exception as e:  # noqa: BLE001 - a bad credential must not stop the server
        log.warning("%s client unavailable: %s", domain, type(e).__name__)
        return None


def _new_writer(domain: str, client: Any) -> Any:
    ad = ADAPTERS.get(domain)
    if ad is None or ad.write is None or client is None:
        return None
    try:
        return ad.write.writer_from_env(os.environ, client)
    except Exception as e:  # noqa: BLE001 - a bad credential must not stop the server
        log.warning("%s writer unavailable: %s", domain, type(e).__name__)
        return None


CLIENTS: dict[str, Any] = {k: _new_client(k) for k in providers.DOMAINS}


def _available(domain: str) -> bool:
    return domain == WEB or (ADAPTERS.get(domain) is not None and CLIENTS.get(domain) is not None)


def _not_configured(domain: str, what: str = "specialist") -> dict:
    title = _title(domain)
    return {"status": "error", "error": f"{title} is not configured on this host",
            "next_step": f"Say the {title} {what} is unavailable; never invent results."}


def _tools(domain: str) -> list[dict]:
    ad = ADAPTERS.get(domain)
    return list(ad.read.TOOLS) if ad is not None else []


def _names(tools: list[dict]) -> frozenset[str]:
    return frozenset(t["name"] for t in tools)


TICKETING_TOOLS = _tools(TICKETING)
ENTERPRISE_SEARCH_TOOLS = _tools(ENTERPRISE_SEARCH)
ENTERPRISE_SEARCH_TOOL_NAMES = _names(ENTERPRISE_SEARCH_TOOLS)
INTERNAL_TOOL_NAMES = _names(TICKETING_TOOLS) | ENTERPRISE_SEARCH_TOOL_NAMES
AI_ENTITLEMENT_TOOL_NAMES = ai_entitlement.TOOL_NAMES


# The request context a domain's read interface takes (see its contract), passed as a keyword to run_tool: enterprise
# search acts as the requester's signed email; email security records who asked in its access-justification log.
# Every other domain gets none.
READ_CONTEXT = {ENTERPRISE_SEARCH: "act_as", "email_security": "requester"}

NO_ACT_AS = {"status": "refused",
             "message": (f"Enterprise search acts as the requester and needs their {org.ORG_NAME} email "
                         f"(@{org.ORG_EMAIL_DOMAIN}); none was verified for this request. Nothing was sent."),
             "next_step": "Say enterprise search is unavailable for this request; never invent internal context."}


def may_act_as(email: str) -> bool:
    """True only for an exact, lowercase name@<primary org email domain>: the one identity enterprise search may act
    as. Checked here as well as in the adapter, so an adapter that forgets the rule still never runs as nobody."""
    return isinstance(email, str) and email == email.strip().lower() and org.is_org_email(email)


def _domain_read(domain: str, name: str, args: dict, *, act_as: str = "", requester: str = "") -> dict:
    """One read through the domain's adapter, with only the context its interface takes (READ_CONTEXT)."""
    ad, client = ADAPTERS.get(domain), CLIENTS.get(domain)
    if ad is None or client is None:
        return _not_configured(domain, "lookup" if domain in (TICKETING, ENTERPRISE_SEARCH) else "specialist")
    if domain == ENTERPRISE_SEARCH and not may_act_as(act_as):
        return dict(NO_ACT_AS)
    ctx = {"act_as": act_as, "requester": requester}
    kw = {READ_CONTEXT[domain]: ctx[READ_CONTEXT[domain]]} if domain in READ_CONTEXT else {}
    try:
        result = ad.read.run_tool(client, name, args, **kw)
    except Exception as e:  # noqa: BLE001 - the interface says never raises; a broken adapter must not kill the loop
        log.warning("%s tool %s raised %s", domain, name, type(e).__name__)
        result = None
    if not isinstance(result, dict) or "status" not in result:
        return {"status": "error", "message": f"The {_title(domain)} adapter returned no usable result.",
                "next_step": "Say this lookup failed; never invent results."}
    return result


def _specialist_read(domain: str, name: str, args: dict, *, act_as: str = "", requester: str = "") -> dict:
    """A specialist's reads: its own domain, plus the internal-context tools (ticketing, enterprise search) and the
    AI-tool entitlement check (answered by the identity provider) where the specialist has them."""
    if name in INTERNAL_TOOL_NAMES:
        return _domain_read(TICKETING if name not in ENTERPRISE_SEARCH_TOOL_NAMES else ENTERPRISE_SEARCH, name, args,
                            act_as=act_as)
    if domain == "insider_risk" and name in AI_ENTITLEMENT_TOOL_NAMES:
        idp = ADAPTERS.get("idp")
        return ai_entitlement.run_tool(idp.read if idp is not None else None, CLIENTS.get("idp"), name, args)
    if domain == WEB:
        return {"status": "error", "error": f"unknown tool {name}"}
    return _domain_read(domain, name, args, act_as=act_as, requester=requester)


# --- Writes ---------------------------------------------------------------------------------------------------------
# Every domain with a write adapter is gated the same way. Only the Slack users in JARVIS_WRITERS (org.env) get the
# write tools, decided here from the signed requester: the specialist doesn't even get them for anyone else. Each
# distinct action once per request, MAX_WRITES_PER_RUN in total, every call audited. JARVIS_WRITES_ENABLED is the kill
# switch (jarvis-secrets writes it; anything but "true" turns writes off). LIST_TOOLS are reads that need the writer's
# credential, offered to every requester.

WRITE_AUTHORIZED = org.WRITERS
WRITES_ENABLED = os.environ.get("JARVIS_WRITES_ENABLED", "").strip().lower() == "true"
MAX_WRITES_PER_RUN = 6

# Automatic actions on alerts the alert bot posts in a bot channel: each domain's write adapter defines what may run
# automatically and on which IDs (found in the bot's own signed post). Each action once per alert for the process
# lifetime, at most MAX_AUTO_ACTIONS_PER_HOUR per domain. JARVIS_AUTO_CLOSE_ENABLED is its own switch, separate from
# JARVIS_WRITES_ENABLED.
AUTO_ACTORS = org.TRIGGER_BOTS  # JARVIS_TRIGGER_BOTS (org.env): the alert pipeline's Slack bot(s)
AUTO_ENABLED = os.environ.get("JARVIS_AUTO_CLOSE_ENABLED", "").strip().lower() == "true"
MAX_AUTO_ACTIONS_PER_HOUR = 10
MAX_AUTO_IDS = 25
#: What a write module must define for automatic actions (see providers/__init__.py); a module with only some of them
#: gets none.
AUTO_HOOKS = ("AUTO_ID_PATTERN", "AUTO_ID_SHAPE", "AUTO_NOTE", "auto_tools", "auto_check", "auto_requester")
_auto_done: dict[str, tuple[str, float]] = {}  # dedupe key -> (domain, when)
_auto_lock = threading.Lock()


@dataclasses.dataclass(frozen=True)
class DomainWrites:
    domain: str
    module: ModuleType
    writer: Any
    tools: list[dict]
    list_tools: list[dict]
    run: Callable[..., dict]  # run_write_tool(writer, name, args, requester) -> dict, never raises

    @property
    def write_names(self) -> frozenset[str]:
        return _names(self.tools)

    @property
    def list_names(self) -> frozenset[str]:
        return _names(self.list_tools)

    @property
    def can_auto_act(self) -> bool:
        return all(hasattr(self.module, h) for h in AUTO_HOOKS)

    def call(self, name: str, args: dict, requester: str) -> dict:
        """run_write_tool, held to its interface: a dict with "status", never an exception."""
        try:
            result = self.run(self.writer, name, args, requester)
        except Exception as e:  # noqa: BLE001 - the interface says never raises
            log.warning("%s write tool %s raised %s", self.domain, name, type(e).__name__)
            result = None
        if not isinstance(result, dict) or "status" not in result:
            return {"status": "error", "outcome_unknown": True,
                    "message": f"The {_title(self.domain)} write adapter returned no usable result.",
                    "next_step": "It isn't known whether anything changed. Verify with a read; do not call again."}
        return result


def _domain_writes(domain: str) -> DomainWrites | None:
    ad = ADAPTERS.get(domain)
    if ad is None or ad.write is None:
        return None
    w = ad.write
    return DomainWrites(domain, w, _new_writer(domain, CLIENTS.get(domain)), list(w.WRITE_TOOLS),
                        list(getattr(w, "LIST_TOOLS", [])), w.run_write_tool)


DOMAIN_WRITES: dict[str, DomainWrites] = {
    k: dw for k in SPECIALIST_DOMAINS if (dw := _domain_writes(k)) is not None}


def _can_write(domain: str, actor: str) -> bool:
    dw = DOMAIN_WRITES.get(domain)
    return (dw is not None and dw.writer is not None and WRITES_ENABLED and actor in WRITE_AUTHORIZED
            and actor not in AUTO_ACTORS)


def _requester(actor: str, act_as: str) -> str:
    return f"{act_as} ({actor})" if act_as else actor


def _auto_ids(domain: str, actor: str, alert_post: str) -> list[str]:
    """Alert IDs this (already verified) request may act on automatically: none unless automatic actions are on, the
    domain's writer supports them and is configured, and the requester is the alert bot. The IDs come only from the
    alert bot's own post, signed in jarvis_auth."""
    dw = DOMAIN_WRITES.get(domain)
    if not (AUTO_ENABLED and actor in AUTO_ACTORS and dw is not None and dw.writer is not None and dw.can_auto_act):
        return []
    found = set()
    for m in dw.module.AUTO_ID_PATTERN.finditer(alert_post or ""):
        i = m.group(1) if m.re.groups else m.group(0)
        if i and dw.module.AUTO_ID_SHAPE.fullmatch(i):
            found.add(i)
    return sorted(found)[:MAX_AUTO_IDS]


def _write_runner(domain: str, base_run: Callable[[str, dict], dict], actor: str, requester: str,
                  request_id: str) -> Callable[[str, dict], dict]:
    """A specialist's run_tool for one request: its reads as before, list reads through the writer, and writes for
    authorized actors only, each distinct action at most once per request and at most MAX_WRITES_PER_RUN in total."""
    dw = DOMAIN_WRITES[domain]
    sent: set[str] = set()

    def run(name: str, args: dict) -> dict:
        if name in dw.list_names:
            if dw.writer is None:
                return {"status": "error", "error": f"{name} is not configured on this host",
                        "next_step": "Say this lookup is unavailable; never invent results."}
            return dw.call(name, args, requester)
        if name not in dw.write_names:
            return base_run(name, args)
        key = json.dumps([name, args], sort_keys=True, default=str)
        if not _can_write(domain, actor):
            result = {"status": "refused", "message": "Actions through Jarvis are limited to authorized writers, or "
                      "writes are switched off.", "next_step": "Recommend the action instead; nothing was changed."}
        elif key in sent:
            result = {"status": "refused", "message": "This exact action was already sent in this request.",
                      "next_step": "Don't send it again. Report the earlier result; verify with a read if unsure."}
        elif len(sent) >= MAX_WRITES_PER_RUN:
            result = {"status": "refused", "message": f"Write cap reached ({MAX_WRITES_PER_RUN} per request).",
                      "next_step": "Report what was done and ask the analyst to send the rest as a new request."}
        else:
            sent.add(key)
            _audit("write_call_start", request_id=request_id, actor=actor, domain=domain, tool=name, args=key[:1500])
            result = dw.call(name, args, requester)
        _audit("write_call", request_id=request_id, actor=actor, domain=domain, tool=name, status=result.get("status"),
               outcome_unknown=bool(result.get("outcome_unknown")), args=key[:1500])
        return result

    return run


def _auto_runner(domain: str, base_run: Callable[[str, dict], dict], actor: str, eligible: list[str],
                 request_id: str) -> Callable[[str, dict], dict]:
    """A specialist's run_tool for an alert-bot request: reads as before, plus the domain's automatic actions on the
    signed alert IDs only, each action once per alert, under the hourly cap."""
    dw = DOMAIN_WRITES[domain]
    mod = dw.module
    allowed = frozenset(eligible)
    requester = mod.auto_requester(actor)
    payload_for = getattr(mod, "auto_payload", None) or (lambda name, args: args)

    def run(name: str, args: dict) -> dict:
        if name in dw.list_names:
            return dw.call(name, args, actor)
        if name not in dw.write_names:
            return base_run(name, args)
        args = args if isinstance(args, dict) else {}
        logged = json.dumps([name, args], sort_keys=True, default=str)[:1500]
        try:
            keys, why = mod.auto_check(name, args, allowed)
        except Exception as e:  # noqa: BLE001 - a broken policy check refuses, never acts
            log.warning("%s auto_check raised %s", domain, type(e).__name__)
            keys, why = None, None
        if keys is not None and not (isinstance(keys, list) and keys and all(isinstance(k, str) and k for k in keys)):
            keys = None  # a policy answer that isn't a non-empty list of dedupe keys is a refusal
        result = None
        if not keys:
            result = {"status": "refused", "message": why or "This action can't run automatically.",
                      "next_step": "Recommend the action instead; nothing was changed."}
        else:
            now = time.time()
            with _auto_lock:
                recent = sum(1 for d, t in _auto_done.values() if d == domain and now - t < 3600)
                if any(k in _auto_done for k in keys):
                    result = {"status": "refused", "message": "Jarvis already took this automatic action.",
                              "next_step": "Don't send it again; verify the current state with a read."}
                elif recent + len(keys) > MAX_AUTO_ACTIONS_PER_HOUR:
                    result = {"status": "refused",
                              "message": f"Automatic action cap reached ({MAX_AUTO_ACTIONS_PER_HOUR} an hour).",
                              "next_step": "Recommend the action instead; an analyst can do it."}
                else:
                    _auto_done.update({k: (domain, now) for k in keys})
            if result is None:
                _audit("auto_action_start", request_id=request_id, actor=actor, domain=domain, tool=name, args=logged)
                try:
                    payload = payload_for(name, args)
                except Exception as e:  # noqa: BLE001 - the key is spent, but nothing is sent
                    log.warning("%s auto_payload raised %s", domain, type(e).__name__)
                    payload = None
                result = dw.call(name, payload, requester) if isinstance(payload, dict) else {
                    "status": "error", "message": "The automatic action could not be built; nothing was sent.",
                    "next_step": "Recommend the action instead; an analyst can do it."}
        _audit("auto_action", request_id=request_id, actor=actor, domain=domain, tool=name,
               status=result.get("status"), outcome_unknown=bool(result.get("outcome_unknown")), args=logged)
        return result

    return run


NO_ENTERPRISE_SEARCH_NOTE = ("Enterprise search is not available on this request (it acts as the requester, and there "
                             "is no person to act as): run the no-enterprise-search internal-context check.")


def _alert_bot_note(actor: str, eligible: list[str], domain: str) -> str:
    """Extra brief line for alert-bot requests (none for people)."""
    if actor not in AUTO_ACTORS:
        return ""
    note = f"This request was started by the {org.ALERT_BOT_NAME} from an alert post; no analyst is present."
    dw = DOMAIN_WRITES.get(domain)
    if eligible and dw is not None and dw.can_auto_act:
        return note + " " + dw.module.AUTO_NOTE + ", ".join(eligible) + "."
    return note + " Automatic actions are off for this request: recommend only."


# --- Specialists ----------------------------------------------------------------------------------------------------

MAX_ITERATIONS = {"edr": 50, "idp": 30, "productivity_suite": 30, "email_security": 30, "brand_protection": 40,
                  "insider_risk": 40, WEB: 10}
# Specialists that also get the internal-context tools (ticketing, enterprise search as the requester) and web tools.
WITH_INTERNAL_CONTEXT = ("edr", "brand_protection", "insider_risk")


def _prompt(domain: str) -> str:
    """The domain prompt plus the configured provider's addendum (if any), with their {{ORG_*}} placeholders filled
    (an unknown placeholder fails at startup)."""
    base = HERE / "specialists" / domain
    text = org.render((base / "prompt.md").read_text(encoding="utf-8"))
    ad = ADAPTERS.get(domain) if domain in providers.DOMAINS else None
    addendum = base / "providers" / f"{ad.provider}.md" if ad is not None else None
    if addendum is not None and addendum.is_file():
        text += "\n\n" + org.render(addendum.read_text(encoding="utf-8"))
    return text


def _specialist(domain: str) -> Specialist:
    if domain == WEB:
        tools: list[dict] = list(web_tools.WEB_TOOLS)
    else:
        tools = _tools(domain)
        if domain == "insider_risk":
            tools += ai_entitlement.TOOLS
        if domain in WITH_INTERNAL_CONTEXT:
            tools += TICKETING_TOOLS + ENTERPRISE_SEARCH_TOOLS + web_tools.WEB_TOOLS
    internal = domain in WITH_INTERNAL_CONTEXT
    return Specialist(
        key=domain,
        title=_title(domain),
        prompt=_prompt(domain),
        tools=tools,
        run_tool=functools.partial(_specialist_read, domain),
        max_iterations=MAX_ITERATIONS[domain],
        acts_as_requester=internal,
        internal_tools=INTERNAL_TOOL_NAMES if internal else frozenset(),
    )


SPECIALISTS: dict[str, Specialist] = {d: _specialist(d) for d in SPECIALIST_DOMAINS + (WEB,)}


def _prepare(spec: Specialist, actor: str, auth: dict, request_id: str) -> tuple[Specialist, str]:
    """The specialist as offered to this requester (tools and run_tool), and the server-written brief note."""
    domain = spec.key
    act_as = str(auth.get("actor_email", ""))
    requester = _requester(actor, act_as)
    eligible = _auto_ids(domain, actor, str(auth.get("alert_post", "")))
    tools = list(spec.tools)
    # Enterprise search acts as the requester, so with no requester email (the alert bot) it can only refuse. Leave
    # it out and say so in the brief; the prompts swap in the domain's own alert history on these requests.
    no_search = not act_as and any(t["name"] in ENTERPRISE_SEARCH_TOOL_NAMES for t in tools)
    if no_search:
        tools = [t for t in tools if t["name"] not in ENTERPRISE_SEARCH_TOOL_NAMES]
    run: Callable[[str, dict], dict] = functools.partial(spec.run_tool, act_as=act_as, requester=requester)
    dw = DOMAIN_WRITES.get(domain)
    if dw is not None and dw.writer is not None:
        if eligible:
            tools += dw.list_tools + dw.module.auto_tools()
            run = _auto_runner(domain, run, actor, eligible, request_id)
        else:
            tools += dw.list_tools + (dw.tools if _can_write(domain, actor) else [])
            run = _write_runner(domain, run, actor, requester, request_id)
    note = _alert_bot_note(actor, eligible, domain)
    if no_search:
        note = (note + " " if note else "") + NO_ENTERPRISE_SEARCH_NOTE
    return dataclasses.replace(spec, tools=tools, run_tool=run), note


async def _run_specialist(tool: str, spec: Specialist, question: str, context: str, jarvis_auth: dict | None) -> str:
    request_id = uuid.uuid4().hex[:12]
    actor, reason = verify_auth(tool, jarvis_auth)
    if reason:
        _audit("refused", tool=tool, request_id=request_id, reason=reason)
        return json.dumps({"status": "refused", "reason": reason,
                           "next_step": f"Tell the analyst the {spec.title} specialist is unavailable right now."})
    if not _available(spec.key):
        _audit("not_configured", tool=tool, request_id=request_id, actor=actor, domain=spec.key)
        return json.dumps(_not_configured(spec.key))
    _audit("specialist_start", specialist=spec.key, request_id=request_id, actor=actor,
           tool_call_id=jarvis_auth.get("tool_call_id"), question_chars=len(question), context_chars=len(context))
    spec, note = _prepare(spec, actor, jarvis_auth, request_id)
    return await anyio.to_thread.run_sync(
        functools.partial(run_specialist, spec, question, context, actor, request_id, note=note))


mcp = MCPServer(
    name="jarvis-tools",
    instructions=("Specialist agents for Jarvis, one per security domain (each ask_* tool runs a specialist and "
                  "returns its final answer), plus read-only ticket, wiki and enterprise search lookups."),
)

_ACT_NOTE = "put the analyst's instruction in `question` verbatim."
_RELAY = "It runs its own investigation and returns a finished answer; relay it, don't re-investigate."

SPECIALIST_TOOLS: dict[str, tuple[str, str]] = {
    "ask_edr_specialist": ("edr", (
        "EDR specialist: triage an EDR alert/threat, answer backlog questions (how many open alerts, oldest, top "
        "hosts), look up an endpoint/agent, or hunt in endpoint telemetry with the EDR query language. Give it the "
        "analyst's question plus every identifier you have (alert/threat ID, console URL, hash, host, user, time "
        "window) and any pasted alert JSON in `context`. " + _RELAY + " For authorized writers it can also act "
        "(close an alert, allowlist or block a hash, allowlist a path, network-contain a host, start a full disk "
        "scan): " + _ACT_NOTE)),
    "ask_idp_specialist": ("idp", (
        "Identity provider specialist: look up a person's account (status, MFA factors, groups, apps), a group's "
        "members and app assignments, an app's configuration and assigned users, or search the identity provider's "
        "system log (sign-ins, MFA, admin and OAuth activity, IPs) over a time window. For authorized writers it can "
        "also suspend or unsuspend an account and clear a user's sessions: " + _ACT_NOTE + " Give it the analyst's "
        "question plus every identifier you have (email, user/group/app ID or name, IP, time window, event types) "
        "in `context`. " + _RELAY)),
    "ask_suite_specialist": ("productivity_suite", (
        "Productivity suite specialist (email, documents and accounts): look up a person's account (suspended, "
        "admin, last login, org unit, manager, recovery details), or search the suite's audit logs over a time "
        "window: sign-ins and IPs, OAuth app grants and revocations, file sharing and downloads, mail metadata "
        "(senders, recipients, subjects), account security changes (2-step verification, recovery, forwarding) and "
        "admin console changes, for one user or org-wide, and the apps a user has authorised right now. "
        "Investigates one employee for exfiltration or account compromise. For authorized writers it can also "
        "revoke an app's access or sign someone out: " + _ACT_NOTE + " Give it the analyst's question plus every "
        "identifier you have (email, name, IP, app name or client id, file name, time window) in `context`. "
        + _RELAY)),
    "ask_email_security_specialist": ("email_security", (
        "Email security specialist: is this email phishing/malicious (verdict with evidence: SPF/DKIM/DMARC, links, "
        "attachments, sender), what mail did we get from a sender or domain or about a subject, who received, read, "
        "clicked or reported a campaign, what the email security platform and its automated analysis concluded, "
        "and whether a quarantine or other action finished. For authorized writers it can also quarantine, trash, "
        "banner or restore a message group and block a sender: " + _ACT_NOTE + " Give it the analyst's question "
        "plus every identifier you have (message or group id, sender, subject, recipient, Message-ID header, "
        "attachment hash, time window) and any pasted alert in `context`. " + _RELAY)),
    "ask_brand_protection_specialist": ("brand_protection", (
        "Brand protection specialist: review a brand-protection alert or any lookalike domain, phishing site, fake "
        "job posting, social or executive impersonation, or brand misuse (verdict, risk, category, takedown "
        "recommendation, with web and internal-context evidence); look up an alert (ABC-1234) or search alerts by "
        "domain, handle or queue state (how many need confirmation, newest high severity); or scan a URL with the "
        "platform's scanner on request. For authorized writers it can also archive an alert or mark it taken down: "
        + _ACT_NOTE + " Give it the analyst's question plus every identifier you have (alert id or console link, "
        "domain, URL, handle, pasted alert) in `context`. " + _RELAY)),
    "ask_insider_risk_specialist": ("insider_risk", (
        "Insider risk (DLP) specialist: triage an insider-risk alert (session) with a verdict and confidence, or "
        "answer questions about a person's file movement (uploads, syncs, pastes, email, removable media, GenAI "
        "tools), their alert history and how earlier alerts were closed, and whether they are in a sanctioned "
        "AI-tool group in the identity provider. Give it the analyst's question plus every identifier you have "
        "(console link or session ID, the person's email, file name or hash, destination, time window, pasted "
        "alert) in `context`. " + _RELAY + " For authorized writers it can also close an alert with a note: "
        + _ACT_NOTE)),
    "ask_web_research": (WEB, (
        "Web research specialist: public threat intel on a hash, domain, IP or file; CVEs and vendor security "
        "advisories; what a product, app or browser extension is and who makes it; vendor docs. Read-only. Put "
        "the question in `question` and only public indicators in `context` (never employee names, emails, "
        f"internal hostnames or other internal details: its searches leave {org.ORG_NAME}). Returns a sourced "
        "answer.")),
}


def _register_specialist_tool(tool_name: str, domain: str, description: str) -> Callable:
    async def ask(question: str, context: str = "", jarvis_auth: dict | None = None) -> str:
        """question: the analyst's ask in plain words. context: identifiers, pasted alert, prior findings."""
        return await _run_specialist(tool_name, SPECIALISTS[domain], question, context, jarvis_auth)

    ask.__name__ = ask.__qualname__ = tool_name
    mcp.tool(name=tool_name, description=description)(ask)
    return ask


for _tool_name, (_domain, _description) in SPECIALIST_TOOLS.items():
    globals()[_tool_name] = _register_specialist_tool(_tool_name, _domain, _description)


# Ticket, wiki and enterprise search reads Jarvis makes itself (lookups; the EDR, brand protection and insider risk
# specialists have their own access). Per-thread caps over a rolling window back up the per-request budget in SOUL.md.
DIRECT_WINDOW_S = 600
DIRECT_CAPS = {"search_tickets": 6, "get_ticket_details": 6, "search_wiki": 4, "get_wiki_page_details": 6,
               "enterprise_search": 4, "enterprise_chat": 2, "enterprise_read_document": 3}
DIRECT_DOMAINS = {"search_tickets": TICKETING, "get_ticket_details": TICKETING, "search_wiki": TICKETING,
                  "get_wiki_page_details": TICKETING, "enterprise_search": ENTERPRISE_SEARCH,
                  "enterprise_chat": ENTERPRISE_SEARCH, "enterprise_read_document": ENTERPRISE_SEARCH}
_direct_calls: dict[tuple[str, str], list[float]] = {}
_direct_lock = threading.Lock()


def _direct_budget_ok(session_key: str, tool: str) -> bool:
    now = time.time()
    with _direct_lock:
        for k in [k for k, ts in _direct_calls.items() if not ts or now - ts[-1] > DIRECT_WINDOW_S]:
            del _direct_calls[k]
        ts = [t for t in _direct_calls.get((session_key, tool), []) if now - t <= DIRECT_WINDOW_S]
        if len(ts) >= DIRECT_CAPS[tool]:
            _direct_calls[(session_key, tool)] = ts
            return False
        _direct_calls[(session_key, tool)] = ts + [now]
        return True


async def _run_direct(tool: str, args: dict, jarvis_auth: dict | None) -> str:
    request_id = uuid.uuid4().hex[:12]
    actor, reason = verify_auth(tool, jarvis_auth)
    if reason:
        _audit("refused", tool=tool, request_id=request_id, reason=reason)
        return json.dumps({"status": "refused", "reason": reason,
                           "next_step": "Tell the analyst this lookup is unavailable right now."})
    domain = DIRECT_DOMAINS[tool]
    if not _available(domain):
        _audit("direct_call", tool=tool, request_id=request_id, actor=actor, status="not_configured")
        return json.dumps(_not_configured(domain, "lookup"))
    if not _direct_budget_ok(str(jarvis_auth.get("session_key")), tool):
        _audit("direct_call", tool=tool, request_id=request_id, actor=actor, status="budget_exceeded")
        return json.dumps({"status": "budget_exceeded",
                           "message": f"{tool} cap reached for this thread ({DIRECT_CAPS[tool]} per 10 minutes).",
                           "next_step": "Answer from what you already have, or ask the analyst to narrow the request."})
    started = time.monotonic()
    run = functools.partial(_domain_read, domain, tool, args, act_as=str(jarvis_auth.get("actor_email", "")))
    result = await anyio.to_thread.run_sync(run)
    _audit("direct_call", tool=tool, request_id=request_id, actor=actor, status=result.get("status"),
           query=str(next(iter(args.values()), ""))[:300], duration_ms=int((time.monotonic() - started) * 1000))
    return json.dumps(result)


# Descriptions come from the configured adapter (it knows its query syntax); these are used when a domain is off.
_DIRECT_FALLBACK = {
    "search_tickets": "Search tickets (read-only). Returns up to 10 tickets: key, link, summary, status, dates.",
    "get_ticket_details": "Read one ticket in full (read-only). Input: the ticket key, e.g. SEC-123.",
    "search_wiki": "Search wiki pages (read-only). Returns up to 10 pages: ID, title, space, link, snippet.",
    "get_wiki_page_details": "Read one wiki page as plain text (read-only). Input: the page ID.",
    "enterprise_search": (f"Search {org.ORG_NAME}'s internal knowledge with enterprise search as the requester, so "
                          "only what they can see."),
    "enterprise_chat": "Ask the enterprise-search assistant a question as the requester; returns a cited answer.",
    "enterprise_read_document": "Read the full text of one document enterprise search found, as the requester.",
}


def _direct_description(tool: str) -> str:
    for t in TICKETING_TOOLS + ENTERPRISE_SEARCH_TOOLS:
        if t["name"] == tool:
            return "Read-only. " + t["description"]
    return _DIRECT_FALLBACK[tool]


@mcp.tool(name="search_tickets", description=_direct_description("search_tickets"))
async def search_tickets(query: str, jarvis_auth: dict | None = None) -> str:
    """query: a ticket search query."""
    return await _run_direct("search_tickets", {"query": query}, jarvis_auth)


@mcp.tool(name="get_ticket_details", description=_direct_description("get_ticket_details"))
async def get_ticket_details(ticket_key: str, jarvis_auth: dict | None = None) -> str:
    """ticket_key: a ticket key like SEC-123."""
    return await _run_direct("get_ticket_details", {"ticket_key": ticket_key}, jarvis_auth)


@mcp.tool(name="search_wiki", description=_direct_description("search_wiki"))
async def search_wiki(query: str, jarvis_auth: dict | None = None) -> str:
    """query: a wiki search query."""
    return await _run_direct("search_wiki", {"query": query}, jarvis_auth)


@mcp.tool(name="get_wiki_page_details", description=_direct_description("get_wiki_page_details"))
async def get_wiki_page_details(page_id: str, jarvis_auth: dict | None = None) -> str:
    """page_id: the numeric page ID."""
    return await _run_direct("get_wiki_page_details", {"page_id": page_id}, jarvis_auth)


@mcp.tool(name="enterprise_search", description=_direct_description("enterprise_search"))
async def enterprise_search(query: str, jarvis_auth: dict | None = None) -> str:
    """query: a short keyword query."""
    return await _run_direct("enterprise_search", {"query": query}, jarvis_auth)


@mcp.tool(name="enterprise_chat", description=_direct_description("enterprise_chat"))
async def enterprise_chat(message: str, jarvis_auth: dict | None = None) -> str:
    """message: the question for the enterprise-search assistant."""
    return await _run_direct("enterprise_chat", {"message": message}, jarvis_auth)


@mcp.tool(name="enterprise_read_document", description=_direct_description("enterprise_read_document"))
async def enterprise_read_document(url: str = "", id: str = "", jarvis_auth: dict | None = None) -> str:  # noqa: A002
    """url: the document link from a search result. id: a document id (if no url)."""
    return await _run_direct("enterprise_read_document", {"url": url, "id": id}, jarvis_auth)


class BearerAuth:
    """Pure ASGI middleware: every HTTP request needs `Authorization: Bearer <JARVIS_TOOLS_TOKEN>`."""

    def __init__(self, app):
        self.app = app
        self.expected = f"Bearer {TOOLS_TOKEN}".encode()

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            got = dict(scope.get("headers") or []).get(b"authorization", b"")
            if not hmac.compare_digest(got, self.expected):
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-type", b"text/plain")]})
                await send({"type": "http.response.body", "body": b"unauthorized"})
                return
        await self.app(scope, receive, send)


def main() -> None:
    # SSE responses, not JSON: Hermes's HTTP client has a fixed 300 s read timeout (separate from the 540 s tool
    # timeout), and a JSON response sends nothing until the specialist finishes. SSE pings every 15 s.
    app = mcp.streamable_http_app(
        stateless_http=True,
        json_response=False,
        host="0.0.0.0",
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=["jarvis-tools:8080", "jarvis-tools"],
            allowed_origins=[],
        ),
    )
    _audit("startup", providers=providers.describe(),
           configured={k: _available(k) for k in providers.DOMAINS},
           writers={k: v.writer is not None for k, v in DOMAIN_WRITES.items()},
           writes_enabled=WRITES_ENABLED, write_authorized=len(WRITE_AUTHORIZED),
           auto_enabled=AUTO_ENABLED, auto_actors=len(AUTO_ACTORS),
           auto_domains=sorted(k for k, v in DOMAIN_WRITES.items() if v.can_auto_act and v.writer is not None),
           specialists=sorted(SPECIALIST_TOOLS), direct_tools=sorted(DIRECT_CAPS))
    uvicorn.run(BearerAuth(app), host="0.0.0.0", port=8080, log_level="warning", access_log=False)


if __name__ == "__main__":
    main()
