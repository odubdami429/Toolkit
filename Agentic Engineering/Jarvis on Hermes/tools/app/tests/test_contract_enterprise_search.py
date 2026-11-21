"""Enterprise search domain: contract shape, the act-as-the-requester rule, and the example adapter's validation."""

import codecs
import json
import os
import re

import pytest

from providers import DOMAINS
from providers.enterprise_search import contract
from providers.enterprise_search import example as ex

BANNED = [codecs.decode(w, "rot13") for w in (
    "fragvarybar", "fragvary", "bxgn", "tbbtyr", "tjf", "fhoyvzr", "qbccry", "pbqr42", "vaplqe", "ngynffvna", "wven",
    "wdy", "pbasyhrapr", "pdy", "tyrna", "cbjredhrel", "qrrc ivfvovyvgl", "fqy", "fgbelyvar", "zdy", "ergbby",
    "pebjqfgevxr", "qrsraqre", "f1")]
ME = "jane.doe@acme.example"


@pytest.fixture(scope="module")
def client():
    c = ex.client_from_env(os.environ)
    assert c is not None
    return c


def run(name, args, act_as=ME):
    return ex.run_tool(ex.client_from_env(os.environ), name, args, act_as)


def test_registry_read_only():
    d = DOMAINS["enterprise_search"]
    assert d.providers["example"] == ("providers.enterprise_search.example", None)
    assert d.env_prefix == contract.PREFIX and d.tool_prefix == contract.TOOL_PREFIX
    assert contract.WRITE_TOOLS == [] and contract.LIST_TOOLS == []


def test_names_schemas_and_parameters():
    names = [t["name"] for t in ex.TOOLS]
    assert names == ["enterprise_search", "enterprise_chat", "enterprise_read_document"]
    assert all(n.startswith("enterprise_") for n in names) and len(set(names)) == 3
    params = {}
    for t in ex.TOOLS:
        s = t["input_schema"]
        assert s["type"] == "object" and set(s.get("required", [])) <= set(s["properties"])
        params[t["name"]] = (set(s["properties"]), set(s.get("required", [])))
    assert params == {"enterprise_search": ({"query"}, {"query"}), "enterprise_chat": ({"message"}, {"message"}),
                      "enterprise_read_document": ({"url", "id"}, set())}


def test_no_vendor_names_and_says_it_acts_as_the_requester():
    blob = json.dumps(ex.TOOLS).lower() + (contract.__doc__ + ex.__doc__).lower()
    assert not [x for x in BANNED if re.search(r"\b" + re.escape(x) + r"\b", blob)]
    assert all("requester" in t["description"] for t in ex.TOOLS)
    assert "Acme Corp" in contract.tool("enterprise_search")["description"]


def test_client_from_env():
    assert ex.client_from_env({}) is None
    assert ex.client_from_env({"ENTERPRISE_SEARCH_BASE_URL": "https://search.example.test"}) is None
    c = ex.client_from_env({"ENTERPRISE_SEARCH_BASE_URL": "https://search.example.test",
                            "ENTERPRISE_SEARCH_API_TOKEN": "tok-abc"})
    assert c is not None and "tok-abc" not in repr(c)


@pytest.mark.parametrize("who", ["", None, 5, "jane.doe", "jane.doe@acme-mail.example", "jane.doe@sub.acme.example",
                                 "jane.doe@acme.example.evil.example", "jane.doe@personal-mail.net", " jane.doe@acme.example",
                                 "Jane.Doe@ACME.example", "jane doe@acme.example", "a@acme.example,b@acme.example",
                                 "jane.doe@acme.example\n"])
def test_refuses_without_an_org_domain_requester(who):
    for name, args in (("enterprise_search", {"query": "hash"}), ("enterprise_chat", {"message": "hi"}),
                       ("enterprise_read_document", {"id": "doc-1"})):
        r = run(name, args, who)
        assert r["status"] == "refused" and "validated" not in r, (name, who)


def test_act_as_is_never_taken_from_tool_input():
    r = run("enterprise_search", {"query": "hash", "act_as": ME, "email": ME}, "")
    assert r["status"] == "refused"
    r = run("enterprise_search", {"query": "hash", "act_as": "someone@acme.example"})
    assert r["acted_as"] == ME


def test_contract_may_act_as():
    assert contract.may_act_as(ME)
    assert not contract.may_act_as("me@acme-mail.example")  # only the primary domain
    assert not contract.may_act_as(None)


def test_run_tool_never_raises(client):
    for name in list(ex.TOOL_NAMES) + ["enterprise_nope", None]:
        for args in (None, "x", [], {}, {"query": None}, {"message": ["a"]}, {"url": 5, "id": {}}, {"query": "q"}):
            for who in (ME, ""):
                for c in (client, None):
                    r = ex.run_tool(c, name, args, who)
                    assert isinstance(r, dict) and isinstance(r.get("status"), str), (name, args)
                    json.dumps(r)
    assert ex.run_tool(None, "enterprise_search", {"query": "q"}, ME)["status"] == "error"
    assert ex.run_tool(client, "enterprise_search", {"query": "q"})["status"] == "refused"  # act_as defaults to ""


def test_input_validation():
    for name, key, cap in (("enterprise_search", "query", contract.MAX_QUERY_CHARS),
                           ("enterprise_chat", "message", contract.MAX_CHAT_CHARS)):
        assert run(name, {})["status"] == "invalid_input"
        assert run(name, {key: "  "})["status"] == "invalid_input"
        assert run(name, {key: "x" * (cap + 1)})["status"] == "invalid_input"
        r = run(name, {key: " abc "})
        assert r["status"] == "not_implemented" and r["validated"] == {key: "abc"} and r["acted_as"] == ME
        assert r["next_step"] == "Say this lookup isn't implemented in this deployment; never invent results."
    for bad in ({}, {"url": "http://docs.example.test/a"}, {"url": "ftp://x"}, {"id": "  "},
                {"url": "https://x/" + "a" * contract.MAX_URL_CHARS}, {"id": "x" * (contract.MAX_ID_CHARS + 1)}):
        assert run("enterprise_read_document", bad)["status"] == "invalid_input", bad
    assert run("enterprise_read_document", {"url": "https://docs.example.test/d/1", "id": "x"})["validated"] == {
        "url": "https://docs.example.test/d/1"}
    assert run("enterprise_read_document", {"url": "not a url", "id": "doc-1"})["validated"] == {"id": "doc-1"}
