"""Ticketing and wiki domain: contract shape, primers, and the example adapter's validation."""

import codecs
import json
import os
import re

import pytest

from providers import DOMAINS
from providers.ticketing import contract
from providers.ticketing import example as ex

BANNED = [codecs.decode(w, "rot13") for w in (
    "fragvarybar", "fragvary", "bxgn", "tbbtyr", "tjf", "fhoyvzr", "qbccry", "pbqr42", "vaplqe", "ngynffvna", "wven",
    "wdy", "pbasyhrapr", "pdy", "tyrna", "cbjredhrel", "qrrc ivfvovyvgl", "fqy", "fgbelyvar", "zdy", "ergbby",
    "pebjqfgevxr", "qrsraqre", "f1")]


@pytest.fixture(scope="module")
def client():
    c = ex.client_from_env(os.environ)
    assert c is not None
    return c


def run(name, args):
    return ex.run_tool(ex.client_from_env(os.environ), name, args)


def test_registry_read_only():
    d = DOMAINS["ticketing"]
    assert d.providers["example"] == ("providers.ticketing.example", None)
    assert d.env_prefix == contract.PREFIX and d.tool_prefix == "" == contract.TOOL_PREFIX
    assert contract.WRITE_TOOLS == [] and contract.LIST_TOOLS == []


def test_names_schemas_and_parameters():
    names = [t["name"] for t in ex.TOOLS]
    assert names == ["search_tickets", "get_ticket_details", "search_wiki", "get_wiki_page_details"]
    assert ex.TOOL_NAMES == frozenset(names)
    params = {}
    for t in ex.TOOLS:
        s = t["input_schema"]
        assert s["type"] == "object" and set(s["required"]) <= set(s["properties"])
        params[t["name"]] = set(s["properties"])
    assert params == {"search_tickets": {"query"}, "get_ticket_details": {"ticket_key"}, "search_wiki": {"query"},
                      "get_wiki_page_details": {"page_id"}}


def test_no_vendor_names():
    blob = json.dumps(contract.TOOLS + ex.TOOLS).lower() + (contract.__doc__ + ex.__doc__).lower()
    assert not [x for x in BANNED if re.search(r"\b" + re.escape(x) + r"\b", blob)]


def test_query_language_primers():
    for name in ("search_tickets", "search_wiki"):
        c = contract.tool(name)["description"]
        assert contract.PRIMER_SLOT in c and "query language" in c
        a = next(t for t in ex.TOOLS if t["name"] == name)["description"]
        assert contract.PRIMER_SLOT not in a and "(document your query syntax here)" in a
    assert contract.with_primer(contract.TOOLS, "search_tickets", "P")[0]["description"].endswith("Query syntax: P")
    with pytest.raises(KeyError):
        contract.with_primer(contract.TOOLS, "nope", "P")


def test_client_from_env():
    assert ex.client_from_env({}) is None
    assert ex.client_from_env({"TICKETING_BASE_URL": "https://tickets.example.test"}) is None
    c = ex.client_from_env({"TICKETING_BASE_URL": "https://tickets.example.test", "TICKETING_API_TOKEN": "tok-123",
                            "TICKETING_USERNAME": "bot@acme.example"})
    assert c is not None and "tok-123" not in repr(c) and c.console_url == "https://tickets.example.test"


GARBAGE = [None, "x", 1, [], {}, {"query": None}, {"query": ["a"]}, {"ticket_key": {"a": 1}}, {"page_id": True},
           {"page_id": 1.5}, {"query": "\x00" * 2000}]


def test_run_tool_never_raises(client):
    for name in list(ex.TOOL_NAMES) + ["nope", None]:
        for args in GARBAGE:
            for c in (client, None):
                r = ex.run_tool(c, name, args)
                assert isinstance(r, dict) and isinstance(r.get("status"), str), (name, args)
                json.dumps(r)
    assert ex.run_tool(None, "search_tickets", {"query": "x"})["status"] == "error"


def test_search_validation():
    for name in ("search_tickets", "search_wiki"):
        for bad in ({}, {"query": ""}, {"query": "   "}, {"query": 5},
                    {"query": "x" * (contract.MAX_QUERY_CHARS + 1)}):
            assert run(name, bad)["status"] == "invalid_input", (name, bad)
        r = run(name, {"query": '  text ~ "abc"  '})
        assert r["status"] == "not_implemented" and r["validated"] == {"query": 'text ~ "abc"'}
        assert r["next_step"] == "Say this lookup isn't implemented in this deployment; never invent results."


@pytest.mark.parametrize("raw,key", [("SEC-123", "SEC-123"), ("sec-123", "SEC-123"), (" [SEC-9] ", "SEC-9"),
                                     ("https://console.tickets.example.test/browse/SEC-77", "SEC-77"),
                                     ("https://console.tickets.example.test/x?ticket=OPS-5", "OPS-5"),
                                     ("4567", "4567"), (4567, "4567")])
def test_ticket_key_accepted(raw, key):
    r = run("get_ticket_details", {"ticket_key": raw})
    assert r["status"] == "not_implemented" and r["validated"] == {"ticket_key": key}


@pytest.mark.parametrize("raw", [None, "", "SEC", "SEC-0", "SEC 123", "S-1-2", "../SEC-1", "https://x/y", "-1",
                                 "1" * 13, True])
def test_ticket_key_refused(raw):
    assert run("get_ticket_details", {"ticket_key": raw})["status"] == "invalid_input"


def test_page_id():
    assert run("get_wiki_page_details", {"page_id": "123456"})["validated"] == {"page_id": "123456"}
    assert run("get_wiki_page_details", {"page_id": 123456})["validated"] == {"page_id": "123456"}
    for bad in (None, "", "../etc", "a b", "x" * 65, "https://wiki.example.test/pages/123", True):
        assert run("get_wiki_page_details", {"page_id": bad})["status"] == "invalid_input", bad
