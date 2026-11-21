"""Generic contract tests: every adapter registered in providers.DOMAINS must pass these.

Nothing here names a domain's tools or a provider: the tests iterate the registry, so a new adapter registered in
``providers/__init__.py`` is tested automatically. Domain-specific behaviour (validation details, the automatic-action
accept matrix) lives in ``tests/test_contract_<domain>.py``.

What an adapter must guarantee:
* tool names start with the domain's prefix (ticketing: exactly its four fixed names), match the contract's names,
  and are unique across all domains (and distinct from the specialists' web tools);
* every schema is ``{"name", "description", "input_schema": {"type": "object", "properties": {...}}}`` with
  ``required`` a subset of ``properties``, and no vendor names anywhere in it;
* ``client_from_env`` returns None without configuration (and never raises on a bad one);
* ``run_tool`` / ``run_write_tool`` return a JSON-serialisable dict with ``status`` for every tool, for empty and for
  garbage input, with or without a client, and never raise; results never carry the credential;
* write tools refuse without a verified requester (and ignore a requester the model writes into the arguments);
* automatic-action hooks, where present, are complete and safe (see the ``auto`` tests).
"""

from __future__ import annotations

import codecs
import copy
import importlib
import json
import os
import re
from dataclasses import dataclass
from types import ModuleType
from typing import Any

import pytest

import providers
import web_tools

# --- the registry ------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Impl:
    domain: str
    provider: str
    contract: ModuleType
    read: ModuleType
    write: ModuleType | None

    @property
    def d(self) -> providers.Domain:
        return providers.DOMAINS[self.domain]

    @property
    def prefix(self) -> str:
        return self.d.env_prefix

    def read_tools(self) -> list[dict]:
        return list(self.read.TOOLS)

    def list_tools(self) -> list[dict]:
        return list(getattr(self.write, "LIST_TOOLS", []) or []) if self.write else []

    def write_tools(self) -> list[dict]:
        return list(self.write.WRITE_TOOLS) if self.write else []

    def auto_tools(self) -> list[dict]:
        return list(self.write.auto_tools()) if has_auto(self) else []

    def extra_tools(self) -> list[dict]:
        """Tools a domain owns besides its adapter's (the insider risk AI-entitlement check)."""
        if self.domain == "insider_risk":
            from providers.insider_risk import ai_entitlement
            return list(ai_entitlement.TOOLS)
        return []

    def all_tools(self) -> list[dict]:
        return self.read_tools() + self.list_tools() + self.write_tools() + self.auto_tools()


def _load(domain: str, provider: str) -> Impl:
    read_mod, write_mod = providers.DOMAINS[domain].providers[provider]
    return Impl(domain, provider, importlib.import_module(f"providers.{domain}.contract"),
                importlib.import_module(read_mod), importlib.import_module(write_mod) if write_mod else None)


IMPLS = [_load(d, p) for d in providers.DOMAINS for p in providers.DOMAINS[d].providers]
IDS = [f"{i.domain}:{i.provider}" for i in IMPLS]
AUTO_HOOKS = ("AUTO_ID_PATTERN", "AUTO_ID_SHAPE", "AUTO_NOTE", "auto_tools", "auto_check", "auto_requester")
TICKETING_NAMES = {"search_tickets", "get_ticket_details", "search_wiki", "get_wiki_page_details"}


def has_auto(i: Impl) -> bool:
    return i.write is not None and hasattr(i.write, "auto_check")


def tool_cases(kind: str) -> list[tuple[Impl, str]]:
    out = []
    for i in IMPLS:
        tools = {"read": i.read_tools, "list": i.list_tools, "write": i.write_tools}[kind]()
        out += [(i, t["name"]) for t in tools]
    return out


def _case_ids(cases: list[tuple[Impl, str]]) -> list[str]:
    return [f"{i.domain}:{i.provider}:{n}" for i, n in cases]


READ_CASES, LIST_CASES, WRITE_CASES = tool_cases("read"), tool_cases("list"), tool_cases("write")
AUTO_IMPLS = [i for i in IMPLS if has_auto(i)]

# Vendor names that must never appear in a tool surface. rot13, so this file stays free of them too. Short ones are
# matched as whole words, the rest as substrings (so a product suffix is caught as well).
_WORDS = [codecs.decode(w, "rot13") for w in (
    "fragvary", "bxgn", "tbbtyr", "fhoyvzr", "qbccry", "pbqr42", "vaplqe", "ngynffvna", "wven", "pbasyhrapr",
    "cbjredhrel", "qrrc ivfvovyvgl", "fgbelyvar", "ergbby", "pebjqfgevxr", "qrsraqre", "pneoba oynpx", "cebbscbvag",
    "zvzrpnfg", "fcyhax", "freivprabj", "mfpnyre", "argfxbcr")]
_SHORT = [codecs.decode(w, "rot13") for w in ("tjf", "wdy", "pdy", "fqy", "zdy", "f1", "nfn", "tyrna")]
BANNED = re.compile("|".join([re.escape(w) for w in _WORDS] + [r"\b" + re.escape(w) + r"\b" for w in _SHORT]),
                    re.IGNORECASE)

# Model input an adapter must survive: wrong types, huge, nested, control characters, injection-looking text.
GARBAGE_VALUES: list[Any] = [None, True, -1, 0, 10**30, 1.5e308, "", " ", "\x00\x01\x7f", "x" * 20_000, "…",
                             "../../etc/passwd", "'; DROP TABLE x;--", "${jndi:ldap://x}", "*", ["a"] * 500, [],
                             [None, {"a": []}], {"nested": {"deeper": [1, 2, 3]}}, "https://evil.example/a?b=c",
                             "requested by someone else"]
NON_DICT_ARGS: list[Any] = [None, "string", 5, ["list"], True]
REQUESTER = "pat.writer@acme.example (U00000000A1)"


def garbage_args(tool: dict) -> list[dict]:
    props = list(tool["input_schema"].get("properties", {})) or ["x"]
    out = [{p: v for p in props} for v in GARBAGE_VALUES]
    out += [{"unexpected": "value"}, {p.upper(): "x" for p in props}, {"requested_by": REQUESTER}]
    return out


def secrets() -> list[str]:
    """Credential values the test environment configures (they must never appear in a result)."""
    keys = ("API_TOKEN", "CLIENT_SECRET", "PRIVATE_KEY_B64")
    return [os.environ[f"{d.env_prefix}_{k}"] for d in providers.DOMAINS.values() for k in keys
            if len(os.environ.get(f"{d.env_prefix}_{k}", "")) >= 6]


def check_result(r: Any, where: str) -> None:
    assert isinstance(r, dict), where
    assert isinstance(r.get("status"), str) and r["status"], where
    body = json.dumps(r)  # JSON-serialisable (raises otherwise)
    assert not [s for s in secrets() if s in body], where


def client_for(i: Impl) -> Any:
    try:
        return i.read.client_from_env(os.environ)
    except Exception:  # noqa: BLE001 - asserted separately
        return None


def writer_for(i: Impl) -> Any:
    try:
        return i.write.writer_from_env(os.environ, client_for(i)) if i.write else None
    except Exception:  # noqa: BLE001 - asserted separately
        return None


def schema_by_name(i: Impl, name: str) -> dict:
    return next(t for t in i.read_tools() + i.list_tools() + i.write_tools() if t["name"] == name)


# --- registry ------------------------------------------------------------------------------------------------------

def test_registry_is_not_empty_and_every_domain_has_a_provider():
    assert IMPLS
    assert all(d.providers for d in providers.DOMAINS.values())


@pytest.mark.parametrize("i", IMPLS, ids=IDS)
def test_registry_matches_the_contract(i):
    assert i.d.key == i.domain
    assert i.contract.PREFIX == i.d.env_prefix and i.contract.TOOL_PREFIX == i.d.tool_prefix
    assert re.fullmatch(r"[A-Z][A-Z0-9_]*", i.d.env_prefix) and i.d.title.strip()
    assert re.fullmatch(r"[a-z0-9_]+", i.provider)
    assert callable(i.read.client_from_env) and callable(i.read.run_tool)
    if i.write is not None:
        assert callable(i.write.writer_from_env) and callable(i.write.run_write_tool)


@pytest.mark.parametrize("i", IMPLS, ids=IDS)
def test_provider_loads_from_env(i):
    env = {f"{i.prefix}_PROVIDER": i.provider.upper()}
    ad = providers.load(i.domain, env)
    assert ad is not None and ad.read is i.read and ad.write is i.write and ad.provider == i.provider
    assert providers.load(i.domain, {f"{i.prefix}_PROVIDER": ""}) is None
    with pytest.raises(ValueError):
        providers.load(i.domain, {f"{i.prefix}_PROVIDER": "no_such_provider"})


# --- tool names ----------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("i", IMPLS, ids=IDS)
def test_tool_names_prefixed_and_as_the_contract_says(i):
    reads, lists, writes = ([t["name"] for t in f()] for f in (i.read_tools, i.list_tools, i.write_tools))
    names = reads + lists + writes
    assert reads and len(names) == len(set(names))
    for n in names:
        assert re.fullmatch(r"[a-z][a-z0-9_]{2,63}", n), n
        assert n.startswith(i.d.tool_prefix), n
    if i.domain == "ticketing":
        assert set(names) == TICKETING_NAMES
    elif not i.d.tool_prefix:
        pytest.fail(f"{i.domain} has no tool prefix")
    # The adapter implements the contract's tools exactly: no renames, no extras, none missing.
    assert set(reads) == set(i.contract.TOOL_NAMES) == set(i.read.TOOL_NAMES)
    assert set(lists) == set(getattr(i.contract, "LIST_TOOL_NAMES", frozenset()))
    assert set(writes) == set(getattr(i.contract, "WRITE_TOOL_NAMES", frozenset()))
    if i.write is not None and hasattr(i.write, "WRITE_TOOL_NAMES"):
        assert set(i.write.WRITE_TOOL_NAMES) == set(writes)


def test_tool_names_unique_across_domains():
    owner: dict[str, str] = {t["name"]: "web" for t in web_tools.WEB_TOOLS}
    for d in providers.DOMAINS:
        names = set()
        for i in (x for x in IMPLS if x.domain == d):
            names |= {t["name"] for t in i.read_tools() + i.list_tools() + i.write_tools() + i.extra_tools()}
        for n in names:
            assert n not in owner, f"{n} is defined by both {owner[n]} and {d}"
            owner[n] = d


# --- schemas ---------------------------------------------------------------------------------------------------------

def _check_schema(t: dict) -> None:
    assert isinstance(t, dict) and set(t) == {"name", "description", "input_schema"}, t.get("name")
    name = t["name"]
    assert isinstance(t["description"], str) and len(t["description"].strip()) >= 20, name
    s = t["input_schema"]
    assert isinstance(s, dict) and s.get("type") == "object", name
    assert isinstance(s.get("properties"), dict), name
    for p, spec in s["properties"].items():
        assert re.fullmatch(r"[a-z][a-z0-9_]*", p), (name, p)
        assert isinstance(spec, dict) and ({"type", "enum", "anyOf", "oneOf"} & set(spec)), (name, p)
        if "enum" in spec:
            assert isinstance(spec["enum"], list) and spec["enum"], (name, p)
    req = s.get("required", [])
    assert isinstance(req, list) and all(isinstance(r, str) for r in req) and len(req) == len(set(req)), name
    assert set(req) <= set(s["properties"]), name
    json.dumps(t)


@pytest.mark.parametrize("i", IMPLS, ids=IDS)
def test_schemas_are_valid_objects(i):
    for t in i.all_tools() + i.extra_tools():
        _check_schema(t)


@pytest.mark.parametrize("i", IMPLS, ids=IDS)
def test_no_vendor_names_in_the_tool_surface(i):
    for t in i.all_tools() + i.extra_tools():
        hit = BANNED.search(json.dumps(t))
        assert hit is None, (t["name"], hit and hit.group(0))
    if has_auto(i):
        assert BANNED.search(i.write.AUTO_NOTE) is None


def test_banned_word_screen_works():
    assert BANNED.search("Run a " + codecs.decode("cbjredhrel", "rot13").upper() + " query")
    assert BANNED.search(codecs.decode("wdy", "rot13") + " syntax")
    assert not BANNED.search("sdlc s10 asap jquery")


# --- configuration -------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("i", IMPLS, ids=IDS)
def test_client_from_env_needs_configuration(i):
    p = i.prefix
    assert i.read.client_from_env({}) is None
    assert i.read.client_from_env({f"{p}_PROVIDER": i.provider}) is None
    assert i.read.client_from_env({f"{p}_API_TOKEN": "x" * 20}) is None  # credentials but no tenant
    assert i.read.client_from_env({f"{p}_BASE_URL": f"https://{i.domain}.example.test"}) is None  # no credentials
    for bad in ("http://plain.example.test", "https://x.example.test/path?q=1", "not a url", "https://user:pw@x.test"):
        assert i.read.client_from_env({f"{p}_BASE_URL": bad, f"{p}_API_TOKEN": "x" * 20}) is None, bad
    if i.write is not None:
        assert i.write.writer_from_env({}, None) is None


@pytest.mark.parametrize("i", IMPLS, ids=IDS)
def test_client_repr_never_shows_the_credential(i):
    for obj in (client_for(i), writer_for(i)):
        if obj is not None:
            assert not [s for s in secrets() if s in repr(obj) or s in str(obj)]


# --- reads never raise -----------------------------------------------------------------------------------------------

READ_CTX = [{}, {"act_as": "pat.writer@acme.example", "requester": REQUESTER}, {"act_as": "", "requester": ""}]


@pytest.mark.parametrize("i,name", READ_CASES, ids=_case_ids(READ_CASES))
def test_run_tool_always_returns_a_status(i, name):
    t = schema_by_name(i, name)
    for client in (client_for(i), None):
        for ctx in READ_CTX:
            for args in [{}] + garbage_args(t):
                check_result(i.read.run_tool(client, name, copy.deepcopy(args), **ctx), f"{name} {ctx} {args!r:.80}")
            for args in NON_DICT_ARGS:
                check_result(i.read.run_tool(client, name, args, **ctx), f"{name} {args!r}")


@pytest.mark.parametrize("i", IMPLS, ids=IDS)
def test_run_tool_unknown_tool_is_an_error(i):
    for name in ("no_such_tool", "", None, 5, i.d.tool_prefix + "nope"):
        r = i.read.run_tool(client_for(i), name, {})
        check_result(r, repr(name))
        assert r["status"] not in ("ok", "found", "not_implemented"), name


@pytest.mark.parametrize("i,name", READ_CASES, ids=_case_ids(READ_CASES))
def test_unconfigured_client_never_returns_a_result(i, name):
    """Without a client an adapter can't have looked anything up: whatever it says, it isn't a result."""
    t = schema_by_name(i, name)
    args = {p: "value" for p in t["input_schema"]["properties"]}
    r = i.read.run_tool(None, name, args, act_as="pat.writer@acme.example", requester=REQUESTER)
    check_result(r, name)
    assert r["status"] not in ("ok", "found", "no_results", "not_found"), r


@pytest.mark.parametrize("i", [x for x in IMPLS if hasattr(x.contract, "may_act_as")],
                         ids=[f"{x.domain}:{x.provider}" for x in IMPLS if hasattr(x.contract, "may_act_as")])
def test_act_as_domains_refuse_without_an_org_requester(i):
    """Domains that act as the requester refuse, sending nothing, without exactly one org-domain email."""
    for t in i.read_tools():
        args = {p: "https://docs.example.test/d/1" if p == "url" else "quarterly report"
                for p in t["input_schema"]["properties"]}
        for who in ("", "  ", "pat@evil.example", "pat@sub.acme.example", "pat@acme-mail.example",
                    "Pat.Writer@acme.example", " pat@acme.example", "pat@acme.example,ceo@acme.example", None):
            r = i.read.run_tool(client_for(i), t["name"], dict(args), act_as=who)
            check_result(r, f"{t['name']} {who!r}")
            assert r["status"] == "refused", (t["name"], who, r)
        assert i.contract.may_act_as("pat.writer@acme.example")


@pytest.mark.parametrize("i", [x for x in IMPLS if hasattr(x.contract, "USER_GROUPS_STATUSES")],
                         ids=[f"{x.domain}:{x.provider}" for x in IMPLS if hasattr(x.contract, "USER_GROUPS_STATUSES")])
def test_user_groups_interface(i):
    """The identity-provider hook the AI-entitlement check uses: always the documented envelope, never raises."""
    assert callable(getattr(i.read, "user_groups", None))
    for client in (client_for(i), None):
        for email in ("pat@acme.example", "", None, "not an email", "a@b", ["x"], "x" * 5000):
            r = i.read.user_groups(client, email)
            check_result(r, repr(email))
            assert r["status"] in i.contract.USER_GROUPS_STATUSES, r
            assert {"email", "user_status", "groups", "truncated"} <= set(r), r
            assert isinstance(r["groups"], list) and isinstance(r["truncated"], bool)


# --- writes ----------------------------------------------------------------------------------------------------------

def _empty_requester_is_automatic(i: Impl) -> bool:
    """A domain whose automatic route is the empty requester (its writer then applies agent-initiated gates)."""
    return has_auto(i) and i.write.auto_requester("U00000000B1") == ""


@pytest.mark.parametrize("i,name", WRITE_CASES + LIST_CASES, ids=_case_ids(WRITE_CASES + LIST_CASES))
def test_run_write_tool_always_returns_a_status(i, name):
    t = schema_by_name(i, name)
    for writer in (writer_for(i), None):
        for requester in ("", REQUESTER, None, "x" * 5000):
            for args in [{}] + garbage_args(t):
                check_result(i.write.run_write_tool(writer, name, copy.deepcopy(args), requester),
                             f"{name} {requester!r:.40} {args!r:.80}")
            for args in NON_DICT_ARGS:
                check_result(i.write.run_write_tool(writer, name, args, requester), f"{name} {args!r}")


@pytest.mark.parametrize("i", [x for x in IMPLS if x.write], ids=[f"{x.domain}:{x.provider}" for x in IMPLS if x.write])
def test_run_write_tool_unknown_tool_is_an_error(i):
    for name in ("no_such_tool", "", None, i.d.tool_prefix + "delete_everything"):
        r = i.write.run_write_tool(writer_for(i), name, {}, REQUESTER)
        check_result(r, repr(name))
        assert r["status"] not in ("ok", "accepted", "not_implemented"), name


@pytest.mark.parametrize("i,name", WRITE_CASES, ids=_case_ids(WRITE_CASES))
def test_write_tools_refuse_without_a_requester(i, name):
    """No verified requester, no write. A requester the model writes into the arguments never counts."""
    t = schema_by_name(i, name)
    model_claims = {"requested_by": REQUESTER, "requestedBy": REQUESTER, "requester": REQUESTER}
    for writer in (writer_for(i), None):
        for requester in ("", "  ", None):
            for args in ({}, model_claims, {**{p: "value" for p in t["input_schema"]["properties"]}, **model_claims}):
                r = i.write.run_write_tool(writer, name, dict(args), requester)
                check_result(r, f"{name} {requester!r}")
                if _empty_requester_is_automatic(i):
                    # The empty requester is this domain's automatic route: it may not refuse outright, but input
                    # like this never gets through its agent-initiated gates.
                    assert r["status"] in ("refused", "invalid_input", "error"), (name, r)
                else:
                    assert r["status"] == "refused", (name, requester, args, r)
                assert r.get("written") in (None, False), r


# --- automatic actions ------------------------------------------------------------------------------------------------

# Candidate console-link shapes and IDs, used to show that a domain's pattern finds IDs in its console's links and
# nowhere else. Only the IDs the domain's AUTO_ID_SHAPE accepts are used.
_SAMPLE_IDS = ("ABCDE12345", "ABC-37157", "01a19cdd-ebcd-7cdd-b7e6-4c3790e8b98c", "1063501912683821806_1789484488969_0")
_SAMPLE_PATHS = ("alerts/{id}", "domains/{id}", "messages/{id}", "app/#/alerts/review-alerts/{id}")


def _sample_links(i: Impl, origin: str) -> list[tuple[str, str]]:
    shape = i.write.AUTO_ID_SHAPE
    return [(origin.rstrip("/") + "/" + p.format(id=x), x) for x in _SAMPLE_IDS if shape.fullmatch(x)
            for p in _SAMPLE_PATHS]


def _ids(pattern: re.Pattern, text: str) -> list[str]:
    return [m.group(1) if m.re.groups else m.group(0) for m in pattern.finditer(text)]


def _make_pattern(i: Impl):
    return getattr(i.write, "make_auto_id_pattern", None) or i.contract.make_auto_id_pattern


AUTO_IDS = [f"{x.domain}:{x.provider}" for x in AUTO_IMPLS]


@pytest.mark.parametrize("i", AUTO_IMPLS, ids=AUTO_IDS)
def test_auto_hooks_are_complete(i):
    missing = [h for h in AUTO_HOOKS if not hasattr(i.write, h)]
    assert not missing, missing
    assert isinstance(i.write.AUTO_ID_PATTERN, re.Pattern) and isinstance(i.write.AUTO_ID_SHAPE, re.Pattern)
    assert isinstance(i.write.AUTO_NOTE, str) and i.write.AUTO_NOTE.strip()
    assert isinstance(i.write.auto_requester("U00000000B1"), str)
    assert callable(_make_pattern(i))


@pytest.mark.parametrize("i", AUTO_IMPLS, ids=AUTO_IDS)
def test_auto_tools_are_a_subset_of_the_write_tools(i):
    auto = i.write.auto_tools()
    names = [t["name"] for t in auto]
    assert auto and len(names) == len(set(names))
    assert set(names) <= {t["name"] for t in i.write_tools()}
    for t in auto:
        _check_schema(t)
    auto[0]["description"] = "mutated"  # each call returns fresh copies
    auto[0]["input_schema"]["properties"]["mutated"] = {"type": "string"}
    assert i.write.auto_tools()[0]["description"] != "mutated"
    assert "mutated" not in i.write.auto_tools()[0]["input_schema"]["properties"]
    assert "mutated" not in schema_by_name(i, names[0])["input_schema"]["properties"]


@pytest.mark.parametrize("console", [None, "", "   ", "not a url", "https://", "ftp://console.example.test"])
@pytest.mark.parametrize("i", AUTO_IMPLS, ids=AUTO_IDS)
def test_make_auto_id_pattern_without_a_console_never_matches(i, console):
    p = _make_pattern(i)(console)
    assert isinstance(p, re.Pattern)
    origins = [os.environ.get(f"{i.prefix}_CONSOLE_URL", ""), os.environ.get(f"{i.prefix}_BASE_URL", ""),
               "https://anything.example.test", "http://x"]
    text = "\n".join(link for o in origins if o for link, _ in _sample_links(i, o)) + " " + " ".join(_SAMPLE_IDS)
    assert p.search(text) is None


@pytest.mark.parametrize("i", AUTO_IMPLS, ids=AUTO_IDS)
def test_auto_id_pattern_takes_ids_only_from_console_links(i):
    console = os.environ.get(f"{i.prefix}_CONSOLE_URL", "")
    if not console:
        pytest.skip(f"{i.prefix}_CONSOLE_URL is not set in the test environment")
    links = _sample_links(i, console)
    assert links, "none of the sample IDs fits AUTO_ID_SHAPE; extend _SAMPLE_IDS"
    for p in (_make_pattern(i)(console), i.write.AUTO_ID_PATTERN):
        found = {x for link, x in links if x in _ids(p, link)}
        assert found, "no console link shape yields an ID; extend _SAMPLE_PATHS"
        for got in _ids(p, "\n".join(link for link, _ in links)):
            assert i.write.AUTO_ID_SHAPE.fullmatch(got), got
        others = [os.environ.get(f"{i.prefix}_BASE_URL", ""), "https://elsewhere.example.test",
                  console.replace("https://", "https://x"), console + ".evil.example",
                  "https://evil.example/?u=" + console.replace("https://", "")]
        for o in [o for o in others if o]:
            assert _ids(p, "\n".join(link for link, _ in _sample_links(i, o))) == [], o
        assert _ids(p, " ".join(_SAMPLE_IDS)) == []  # bare IDs are never taken


@pytest.mark.parametrize("i", AUTO_IMPLS, ids=AUTO_IDS)
def test_auto_check_refuses_unknown_tools_and_empty_input(i):
    any_ids = frozenset(_SAMPLE_IDS)
    for name in ("no_such_tool", "", i.d.tool_prefix + "delete_everything"):
        keys, why = i.write.auto_check(name, {}, any_ids)
        assert keys is None and isinstance(why, str) and why, name
    for t in i.write_tools():
        for allowed in (frozenset(), any_ids):
            keys, why = i.write.auto_check(t["name"], {}, allowed)
            assert keys is None and why, t["name"]


@pytest.mark.parametrize("i", AUTO_IMPLS, ids=AUTO_IDS)
def test_auto_check_and_payload_never_raise(i):
    for t in i.write_tools():
        for args in garbage_args(t) + NON_DICT_ARGS:
            keys, why = i.write.auto_check(t["name"], copy.deepcopy(args), frozenset(_SAMPLE_IDS))
            assert keys is None or (isinstance(keys, list) and keys and all(isinstance(k, str) for k in keys))
            assert keys is not None or why
            if hasattr(i.write, "auto_payload"):
                assert isinstance(i.write.auto_payload(t["name"], copy.deepcopy(args)), dict)


@pytest.mark.parametrize("i", AUTO_IMPLS, ids=AUTO_IDS)
def test_auto_check_needs_the_id_in_the_allowed_set(i):
    """Whatever arguments carry an ID, nothing passes with an empty allowed set (IDs only come from the post)."""
    for t in i.write_tools():
        props = t["input_schema"]["properties"]
        for x in _SAMPLE_IDS:
            args = {p: ([x] if props[p].get("type") == "array" else x) for p in props}
            assert i.write.auto_check(t["name"], args, frozenset())[0] is None, (t["name"], x)
