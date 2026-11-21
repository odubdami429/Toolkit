"""EDR domain: contract shape, the example adapter's validation, and the automatic-action policy."""

import codecs
import json
import re

import pytest

from providers import DOMAINS
from providers.edr import contract
from providers.edr import example as ex
from providers.edr import example_write as exw

# Vendor names that must never appear in the contract (rot13 so this file stays free of them too).
BANNED = [codecs.decode(w, "rot13") for w in (
    "fragvarybar", "fragvary", "bxgn", "tbbtyr", "tjf", "fhoyvzr", "qbccry", "pbqr42", "vaplqe", "ngynffvna", "wven",
    "wdy", "pbasyhrapr", "pdy", "tyrna", "cbjredhrel", "qrrc ivfvovyvgl", "fqy", "fgbelyvar", "zdy", "ergbby",
    "pebjqfgevxr", "qrsraqre", "f1")]
CONSOLE = "https://console.edr.example.test"
REQ = "a@acme.example (U00000000A1)"
JUST = "Signed vendor updater, verified by hash reputation; ticket SEC-1."
NOTE = "Benign: signed test file, 99% confidence."
SHA1 = "3395856ce81f2b7382dee72602f798b642f14140"
SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


@pytest.fixture(scope="module")
def client():
    c = ex.client_from_env(__import__("os").environ)
    assert c is not None
    return c


@pytest.fixture(scope="module")
def writer(client):
    w = exw.writer_from_env(__import__("os").environ, client)
    assert w is not None
    return w


def all_tools():
    return ex.TOOLS + exw.LIST_TOOLS + exw.WRITE_TOOLS + contract.auto_tools()


def text_of(tool: dict) -> str:
    return json.dumps(tool).lower()


# --- contract shape ------------------------------------------------------------------------------------------------

def test_registry_points_at_the_example_modules():
    assert DOMAINS["edr"].providers["example"] == ("providers.edr.example", "providers.edr.example_write")
    assert DOMAINS["edr"].env_prefix == contract.PREFIX and DOMAINS["edr"].tool_prefix == contract.TOOL_PREFIX


def test_tool_names_prefixed_unique_and_as_specified():
    names = [t["name"] for t in ex.TOOLS + exw.LIST_TOOLS + exw.WRITE_TOOLS]
    assert len(names) == len(set(names))
    assert all(n.startswith("edr_") for n in names)
    assert {t["name"] for t in ex.TOOLS} == {"edr_get_alert", "edr_list_open_alerts", "edr_lookup_device",
                                             "edr_query"}
    assert {t["name"] for t in exw.WRITE_TOOLS} == {"edr_close_alert", "edr_add_hash_exclusion",
                                                     "edr_add_hash_blocklist", "edr_add_path_exclusion",
                                                     "edr_network_contain", "edr_initiate_scan"}
    assert exw.LIST_TOOLS == []
    assert ex.TOOL_NAMES == contract.TOOL_NAMES and exw.WRITE_TOOL_NAMES == contract.WRITE_TOOL_NAMES


def test_schemas_are_valid_objects_with_declared_required_params():
    for t in all_tools():
        s = t["input_schema"]
        assert s["type"] == "object" and isinstance(s["properties"], dict), t["name"]
        assert set(s.get("required", [])) <= set(s["properties"]), t["name"]
        assert t["description"].strip(), t["name"]
        for p in s["properties"].values():
            assert "type" in p or "anyOf" in p


def test_parameter_names():
    params = {t["name"]: set(t["input_schema"]["properties"]) for t in ex.TOOLS + exw.WRITE_TOOLS}
    assert params["edr_get_alert"] == {"threat_id", "endpoint_name", "file_hash", "threat_name", "lookback_hours",
                                       "limit", "include_resolved", "verbose"}
    assert params["edr_list_open_alerts"] == {"list_limit", "order"}
    assert params["edr_lookup_device"] == {"query", "search_by", "include_decommissioned", "limit"}
    assert params["edr_query"] == {"query", "lookback_hours", "start_datetime", "end_datetime", "max_rows",
                                   "result_type"}
    assert params["edr_close_alert"] == {"alert_ids", "verdict", "note"}
    assert params["edr_add_hash_exclusion"] == params["edr_add_hash_blocklist"] == {"hashes", "os_type",
                                                                                    "justification"}
    assert params["edr_add_path_exclusion"] == {"paths", "os_type", "path_exclusion_type", "justification"}
    assert params["edr_network_contain"] == {"endpoint", "justification", "confirm_server"}
    assert params["edr_initiate_scan"] == {"endpoint", "justification"}


def test_no_vendor_names_anywhere_in_the_contract():
    for t in all_tools():
        low = text_of(t)
        for w in BANNED:
            assert not re.search(r"\b" + re.escape(w) + r"\b", low), (t["name"], w)
    doc = (contract.__doc__ + ex.__doc__ + exw.__doc__).lower()
    assert not [w for w in BANNED if re.search(r"\b" + re.escape(w) + r"\b", doc)]


def test_primer_is_filled_in_by_the_adapter():
    q = next(t for t in contract.TOOLS if t["name"] == "edr_query")
    assert contract.PRIMER_SLOT in q["description"]
    filled = next(t for t in ex.TOOLS if t["name"] == "edr_query")
    assert contract.PRIMER_SLOT not in filled["description"]
    assert filled["description"].endswith(ex.QUERY_PRIMER)
    assert contract.PRIMER_SLOT in q["description"]  # the contract's copy is untouched
    other = contract.with_primer([{"name": "x", "description": "Base."}], "x", "Syntax: a=b")
    assert other[0]["description"] == "Base. Syntax: a=b"
    with pytest.raises(KeyError):
        contract.with_primer(contract.TOOLS, "edr_nope", "p")


def test_write_descriptions_say_write_and_recorded_requester():
    for t in exw.WRITE_TOOLS:
        assert t["description"].startswith("WRITE."), t["name"]
        assert "requester" in t["description"]
    contain = contract.tool("edr_network_contain")["description"]
    assert "ALARM" in contain and "ONE" in contain and "confirm_server" in contain


# --- client construction -------------------------------------------------------------------------------------------

def test_client_from_env_needs_base_url_and_credentials():
    assert ex.client_from_env({}) is None
    assert ex.client_from_env({"EDR_BASE_URL": "https://edr.example.test"}) is None
    assert ex.client_from_env({"EDR_API_TOKEN": "t"}) is None
    assert ex.client_from_env({"EDR_BASE_URL": "https://edr.example.test", "EDR_CLIENT_ID": "id"}) is None
    assert ex.client_from_env({"EDR_BASE_URL": "http://edr.example.test", "EDR_API_TOKEN": "t"}) is None
    c = ex.client_from_env({"EDR_BASE_URL": "https://edr.example.test", "EDR_CLIENT_ID": "id",
                            "EDR_CLIENT_SECRET": "sekret-value"})
    assert c is not None and "sekret-value" not in repr(c)
    assert exw.writer_from_env({}, None) is None
    assert exw.writer_from_env({}, object()) is None


# --- never raises --------------------------------------------------------------------------------------------------

GARBAGE = [None, "x", 5, [], {}, {"query": None}, {"query": ["a", "b"]}, {"threat_id": {"a": 1}},
           {"limit": "lots"}, {"lookback_hours": float("nan")}, {"alert_ids": [None, 5]}, {"hashes": 12},
           {"endpoint": {"x": 1}}, {"paths": ["\x00"]}, {"os_type": ["windows"]}]


def test_run_tool_always_returns_a_status(client):
    for t in ex.TOOLS + [{"name": "edr_nope"}]:
        for args in GARBAGE:
            for c in (client, None):
                r = ex.run_tool(c, t["name"], args)
                assert isinstance(r, dict) and isinstance(r.get("status"), str), (t["name"], args)
                json.dumps(r)
    assert ex.run_tool(client, None, {})["status"] == "error"


def test_run_write_tool_always_returns_a_status(writer):
    for t in exw.WRITE_TOOLS + [{"name": "edr_nope"}]:
        for args in GARBAGE:
            for w in (writer, None):
                for req in (REQ, "", None, 5):
                    r = exw.run_write_tool(w, t["name"], args, req)
                    assert isinstance(r, dict) and isinstance(r.get("status"), str), (t["name"], args, req)
                    json.dumps(r)


# --- read validation -----------------------------------------------------------------------------------------------

def run(name, args, client=None):
    return ex.run_tool(client or ex.client_from_env(__import__("os").environ), name, args)


def test_get_alert_validation():
    assert run("edr_get_alert", {})["status"] == "invalid_input"
    assert run("edr_get_alert", {"file_hash": "xyz"})["status"] == "invalid_input"
    assert run("edr_get_alert", {"threat_id": "a b!"})["status"] == "invalid_input"
    assert run("edr_get_alert", {"threat_id": "https://elsewhere.example.test/alerts/ABCDE12345"})["status"] == \
        "invalid_input"
    r = run("edr_get_alert", {"threat_id": f"{CONSOLE}/alerts/ABCDE12345/overview, 1234567890",
                              "limit": 500, "include_resolved": "true"})
    assert r["status"] == "not_implemented" and r["tool"] == "edr_get_alert"
    assert r["next_step"] == "Say this lookup isn't implemented in this deployment; never invent results."
    v = r["validated"]
    assert v["alert_ids"] == ["ABCDE12345", "1234567890"] and v["by_id"] and v["lookback_hours"] is None
    assert v["limit"] == contract.MAX_ALERT_LIMIT and v["include_resolved"] is True
    v = run("edr_get_alert", {"file_hash": SHA1.upper(), "lookback_hours": 10 ** 9})["validated"]
    assert v["file_hash"] == SHA1 and v["lookback_hours"] == contract.MAX_ALERT_LOOKBACK_H
    assert run("edr_get_alert", {"endpoint_name": "HOST-1"})["validated"]["lookback_hours"] == \
        contract.DEFAULT_ALERT_LOOKBACK_H
    assert run("edr_get_alert", {"endpoint_name": "H", "limit": "many"})["status"] == "invalid_input"


def test_list_open_alerts_validation():
    assert run("edr_list_open_alerts", {"order": "random"})["status"] == "invalid_input"
    v = run("edr_list_open_alerts", {})["validated"]
    assert v == {"list_limit": contract.DEFAULT_OPEN_LIST, "order": "attention"}
    assert run("edr_list_open_alerts", {"list_limit": 99, "order": "Newest"})["validated"] == {
        "list_limit": contract.MAX_OPEN_LIST, "order": "newest"}
    assert run("edr_list_open_alerts", {"list_limit": -5})["validated"]["list_limit"] == 0


def test_lookup_device_one_value_per_call():
    for bad in ({}, {"query": ""}, {"query": ["a", "b"]}, {"query": "host1, host2"}, {"query": "host*"},
                {"query": "LAPTOP-12..."}, {"query": "ab"}, {"query": "x" * 101}, {"query": "host\x01"},
                {"query": "host1", "search_by": "mac"}, {"query": "not-an-ip", "search_by": "ip"},
                {"query": "abc", "search_by": "uuid"}):
        assert run("edr_lookup_device", bad)["status"] == "invalid_input", bad
    v = run("edr_lookup_device", {"query": ["LAPTOP-12"], "limit": 1000})["validated"]
    assert v == {"query": "LAPTOP-12", "search_by": "auto", "include_decommissioned": False,
                 "limit": contract.MAX_DEVICE_LIMIT}
    assert run("edr_lookup_device", {"query": "10.0.0.5", "search_by": "ip"})["status"] == "not_implemented"


def test_query_validation():
    for bad in ({}, {"query": "  "}, {"query": 5}, {"query": "x" * (contract.MAX_QUERY_CHARS + 1)},
                {"query": "q", "result_type": "chart"},
                {"query": "q", "start_datetime": "2026-01-01T00:00:00"},
                {"query": "q", "start_datetime": "yesterday Z"},
                {"query": "q", "start_datetime": "2026-01-02T00:00:00Z", "end_datetime": "2026-01-01T00:00:00Z"}):
        assert run("edr_query", bad)["status"] == "invalid_input", bad
    v = run("edr_query", {"query": " event.type = 'x' ", "lookback_hours": 99999, "max_rows": 0})["validated"]
    assert v["query"] == "event.type = 'x'" and v["lookback_hours"] == contract.MAX_QUERY_LOOKBACK_H
    assert v["max_rows"] == 1 and v["result_type"] == "table"
    assert run("edr_query", {"query": "q", "lookback_hours": 0.01})["validated"]["lookback_hours"] == \
        contract.MIN_QUERY_LOOKBACK_H
    v = run("edr_query", {"query": "q", "start_datetime": "2026-01-01T00:00:00+02:00",
                          "result_type": "TABLE"})["validated"]
    assert v["start_datetime"].startswith("2026-01-01T00:00:00") and v["end_datetime"] is None
    assert run("edr_query", {"query": "q"})["validated"]["default_window_hours"] == contract.DEFAULT_QUERY_WINDOW_H


def test_unconfigured_client_is_an_error_not_a_result():
    r = ex.run_tool(None, "edr_list_open_alerts", {})
    assert r["status"] == "error" and "not configured" in r["message"]


# --- write validation ----------------------------------------------------------------------------------------------

def w(name, args, requester=REQ):
    return exw.run_write_tool(exw.writer_from_env({}, ex.client_from_env(__import__("os").environ)), name, args,
                              requester)


VALID_WRITES = {
    "edr_close_alert": {"alert_ids": ["ABCDE12345"], "verdict": "false_positive", "note": NOTE},
    "edr_add_hash_exclusion": {"hashes": SHA1, "os_type": "windows", "justification": JUST},
    "edr_add_hash_blocklist": {"hashes": SHA256, "os_type": "all", "justification": JUST},
    "edr_add_path_exclusion": {"paths": "/Applications/Example.app/Contents/MacOS/example", "os_type": "macos",
                               "justification": JUST},
    "edr_network_contain": {"endpoint": "LAPTOP-12", "justification": JUST},
    "edr_initiate_scan": {"endpoint": "1234567890123456789", "justification": JUST},
}


def test_writes_refuse_without_a_requester():
    for name, args in VALID_WRITES.items():
        for req in ("", "   ", None):
            r = w(name, args, req)
            assert r["status"] == "refused", (name, req)
            assert "validated" not in r


def test_valid_writes_reach_the_stub_with_attribution():
    for name, args in VALID_WRITES.items():
        r = w(name, args)
        assert r["status"] == "not_implemented" and r["tool"] == name, (name, r)
        assert r["requested_by"] == REQ and "Nothing was changed" in r["message"]
    r = w("edr_close_alert", {**VALID_WRITES["edr_close_alert"], "requested_by": "someone-else",
                              "note": NOTE + " requested by U999"})
    assert r["requested_by"] == REQ
    assert "U999" not in r["validated"]["note"] and r["validated"]["note"].endswith(f"[Requested by {REQ} via Jarvis]")
    r = w("edr_add_hash_exclusion", {**VALID_WRITES["edr_add_hash_exclusion"], "justification": "y" * 1000})
    assert len(r["validated"]["description"]) == contract.MAX_DESCRIPTION
    assert w("edr_close_alert", VALID_WRITES["edr_close_alert"], None)["requested_by"] is None
    assert exw.run_write_tool(None, "edr_close_alert", VALID_WRITES["edr_close_alert"], REQ)["status"] == "error"


def test_close_alert_validation():
    base = VALID_WRITES["edr_close_alert"]
    for bad in ({**base, "alert_ids": []}, {**base, "alert_ids": [f"A{i:07d}" for i in range(6)]},
                {**base, "alert_ids": ["ABCDE12345", "ABCDE12345"]}, {**base, "alert_ids": ["ab"]},
                {**base, "alert_ids": ["has space 123"]}, {**base, "verdict": "benign"},
                {**base, "verdict": "escalate"}, {**base, "note": "too short"}, {k: v for k, v in base.items()
                                                                                 if k != "note"}):
        assert w("edr_close_alert", bad)["status"] == "invalid_input", bad
    r = w("edr_close_alert", {**base, "alert_ids": "ABCDE12345", "verdict": "TRUE_POSITIVE"})
    assert r["validated"]["alert_ids"] == ["ABCDE12345"] and r["validated"]["verdict"] == "true_positive"


def test_hash_exclusion_validation():
    base = VALID_WRITES["edr_add_hash_exclusion"]
    for bad in ({**base, "hashes": ""}, {**base, "hashes": "d41d8cd98f00b204e9800998ecf8427e"},
                {**base, "hashes": "z" * 40}, {**base, "hashes": "a" * 40},
                {**base, "hashes": ",".join(f"{i:039x}1" for i in range(1, 12))},
                {**base, "os_type": ""}, {**base, "os_type": "all"}, {**base, "os_type": "solaris"},
                {**base, "justification": "short"}, {**base, "justification": "test " + "x" * 40}):
        assert w("edr_add_hash_exclusion", bad)["status"] == "invalid_input", bad
    r = w("edr_add_hash_exclusion", {**base, "hashes": f"{SHA1.upper()}, {SHA1}\n{SHA256}"})
    assert r["validated"]["hashes"] == [SHA1, SHA256] and r["validated"]["duplicates_collapsed"] == [SHA1]


def test_hash_blocklist_validation():
    base = VALID_WRITES["edr_add_hash_blocklist"]
    v = w("edr_add_hash_blocklist", base)["validated"]
    assert v["os_types"] == list(contract.BLOCKLIST_ALL_OS)
    hashes = ",".join(f"{i + 1:064x}" for i in range(10))
    assert w("edr_add_hash_blocklist", {**base, "hashes": hashes, "os_type": "windows,macos,linux"})["status"] == \
        "not_implemented"
    assert w("edr_add_hash_blocklist", {**base, "hashes": hashes + f",{11:064x}"})["status"] == "invalid_input"
    for bad in ({**base, "os_type": ""}, {**base, "os_type": "windows,beos"},
                {**base, "hashes": "d41d8cd98f00b204e9800998ecf8427e"}, {**base, "hashes": "0" * 64}):
        assert w("edr_add_hash_blocklist", bad)["status"] == "invalid_input", bad


@pytest.mark.parametrize("path,os_type,kind", [
    ("/tmp/payload", "macos", "file"),
    ("/Users/alice/Downloads/tool", "macos", "file"),
    ("/usr/local/bin/*", "linux", "file"),
    ("~/bin/tool", "linux", "file"),
    ("$HOME/bin/tool", "linux", "file"),
    ("/opt/app/../bin/tool", "linux", "file"),
    ("relative/path/tool", "linux", "file"),
    ("/opt/app/tool...", "linux", "file"),
    ("/opt/app/", "linux", "file"),
    ("/tool", "linux", "file"),
    ("/Applications", "macos", "folder"),
    ("/Users/alice", "macos", "subfolders"),
    ("C:\\Users\\Public\\x.exe", "windows", "file"),
    ("C:\\Windows\\Temp\\x.exe", "windows", "file"),
    ("\\\\share\\x.exe", "windows", "file"),
    ("%APPDATA%\\x.exe", "windows", "file"),
    ("C:\\Program Files", "windows", "folder"),
    ("/opt/app/tool", "windows", "file"),
])
def test_path_exclusion_refusals_are_final(path, os_type, kind):
    r = w("edr_add_path_exclusion", {"paths": path, "os_type": os_type, "path_exclusion_type": kind,
                                     "justification": JUST})
    assert r["status"] == "invalid_input", r


def test_path_exclusion_accepts_and_dedupes_exact_paths():
    r = w("edr_add_path_exclusion", {"paths": "/Applications/Example.app/Contents/MacOS/example\n"
                                              "/applications/example.app/contents/macos/EXAMPLE",
                                     "os_type": "macos", "justification": JUST})
    assert r["validated"]["paths"] == ["/Applications/Example.app/Contents/MacOS/example"]
    r = w("edr_add_path_exclusion", {"paths": "C:/Program Files/Example/app.exe", "os_type": "windows",
                                     "justification": JUST})
    assert r["validated"]["paths"] == ["C:\\Program Files\\Example\\app.exe"]
    r = w("edr_add_path_exclusion", {"paths": "/opt/example/app", "os_type": "linux",
                                     "path_exclusion_type": "folder", "justification": JUST})
    assert r["validated"]["paths"] == ["/opt/example/app/"] and r["validated"]["mode"] == "suppress"
    assert w("edr_add_path_exclusion", {"paths": "/opt/example/app", "os_type": "linux", "mode": "interoperability",
                                        "justification": JUST})["status"] == "invalid_input"
    six = "\n".join(f"/opt/example/app{i}" for i in range(6))
    assert w("edr_add_path_exclusion", {"paths": six, "os_type": "linux", "justification": JUST})["status"] == \
        "invalid_input"


@pytest.mark.parametrize("name", ["edr_network_contain", "edr_initiate_scan"])
def test_exactly_one_endpoint(name):
    for bad in ("", ["a-host", "b-host"], "a-host,b-host", "a-host; b-host", "LAPTOP-*", "LAPTOP-1...",
                "LAPTOP-1\u2026", "ab", "x" * 101, "host\x00x", "a-host|b-host"):
        r = w(name, {"endpoint": bad, "justification": JUST})
        assert r["status"] == "invalid_input", (name, bad)
    assert w(name, {"endpoint": "LAPTOP-12", "justification": "short"})["status"] == "invalid_input"
    assert w(name, {"endpoint": "LAPTOP-12", "justification": "n/a " + "x" * 40})["status"] == "invalid_input"
    r = w(name, {"endpoint": ["LAPTOP-12"], "justification": JUST})
    assert r["status"] == "not_implemented" and r["validated"]["endpoint"] == "LAPTOP-12"
    assert r["validated"]["justification"].endswith(f"[Requested by {REQ} via Jarvis]")


def test_contain_passes_confirm_server_through():
    r = w("edr_network_contain", {"endpoint": "SRV-DB-01", "justification": JUST, "confirm_server": True})
    assert r["validated"]["confirm_server"] is True
    r = w("edr_network_contain", {"endpoint": "SRV-DB-01", "justification": JUST})
    assert r["validated"]["confirm_server"] is False


# --- automatic actions ---------------------------------------------------------------------------------------------

ALLOWED = frozenset({"ABCDE12345", "2614239137407374345"})


@pytest.mark.parametrize("name,args,keys", [
    ("edr_close_alert", {"alert_ids": ["ABCDE12345"], "verdict": "false_positive", "note": NOTE},
     ["edr|close|ABCDE12345"]),
    ("edr_close_alert", {"alert_ids": ["ABCDE12345", "2614239137407374345", "ABCDE12345"],
                         "verdict": "False_Positive", "note": NOTE},
     ["edr|close|ABCDE12345", "edr|close|2614239137407374345"]),
    ("edr_close_alert", {"alert_ids": "ABCDE12345", "verdict": " false_positive "}, ["edr|close|ABCDE12345"]),
    ("edr_close_alert", {"alert_ids": ["ABCDE12345"], "verdict": "true_positive"}, None),
    ("edr_close_alert", {"alert_ids": ["ABCDE12345"]}, None),
    ("edr_close_alert", {"alert_ids": ["ZZZZZ99999"], "verdict": "false_positive"}, None),
    ("edr_close_alert", {"alert_ids": ["ABCDE12345", "ZZZZZ99999"], "verdict": "false_positive"}, None),
    ("edr_close_alert", {"alert_ids": [], "verdict": "false_positive"}, None),
    ("edr_close_alert", {"verdict": "false_positive"}, None),
    ("edr_close_alert", "garbage", None),
    ("edr_add_hash_exclusion", {"hashes": SHA1, "verdict": "false_positive", "alert_ids": ["ABCDE12345"]}, None),
    ("edr_network_contain", {"endpoint": "LAPTOP-12", "alert_ids": ["ABCDE12345"],
                             "verdict": "false_positive"}, None),
    ("edr_initiate_scan", {"endpoint": "LAPTOP-12"}, None),
    ("edr_add_hash_blocklist", {}, None),
    ("edr_add_path_exclusion", {}, None),
])
def test_auto_check_matrix(name, args, keys):
    got, why = exw.auto_check(name, args, ALLOWED)
    assert got == keys
    assert (why is None) == (keys is not None)


def test_auto_check_refuses_badly_shaped_ids_even_if_allowed():
    assert exw.auto_check("edr_close_alert", {"alert_ids": ["ab"], "verdict": "false_positive"},
                          frozenset({"ab"}))[0] is None
    assert exw.auto_check("edr_close_alert", {"alert_ids": ["a/b/c/d/e"], "verdict": "false_positive"},
                          frozenset({"a/b/c/d/e"}))[0] is None


def test_auto_hooks():
    assert exw.AUTO_ID_SHAPE is contract.AUTO_ID_SHAPE
    assert exw.AUTO_ID_SHAPE.fullmatch("ABCDE12345") and exw.AUTO_ID_SHAPE.fullmatch("a_b-c1")
    assert not exw.AUTO_ID_SHAPE.fullmatch("abcd") and not exw.AUTO_ID_SHAPE.fullmatch("x" * 65)
    assert "never allowlist" in exw.AUTO_NOTE
    assert exw.auto_requester("U00000000B1") == "U00000000B1 (alert bot, automatic close)"
    tools = exw.auto_tools()
    assert [t["name"] for t in tools] == ["edr_close_alert"]
    assert tools[0]["description"].startswith("WRITE, AUTOMATIC CLOSE ONLY")
    assert tools[0]["input_schema"] == contract.tool("edr_close_alert")["input_schema"]
    tools[0]["description"] = "mutated"
    assert exw.auto_tools()[0]["description"].startswith("WRITE, AUTOMATIC CLOSE ONLY")
    assert exw.auto_payload("edr_close_alert", {"alert_ids": ["ABCDE12345", "ABCDE12345"], "verdict": "FALSE_POSITIVE",
                                                "note": NOTE, "requested_by": "x"}) == {
        "alert_ids": ["ABCDE12345"], "verdict": "false_positive", "note": NOTE}


def test_auto_requester_passes_the_example_writer():
    r = w("edr_close_alert", VALID_WRITES["edr_close_alert"], exw.auto_requester("U00000000B1"))
    assert r["status"] == "not_implemented" and r["requested_by"] == "U00000000B1 (alert bot, automatic close)"


def test_make_auto_id_pattern_extracts_ids_from_console_links():
    p = contract.make_auto_id_pattern(CONSOLE)
    post = (f"New alert {CONSOLE}/alerts/ABCDE12345/overview and <{CONSOLE}/app/incidents/2614239137407374345|view>"
            f"\n{CONSOLE.upper()}/ALERTS/XYZ987654?tab=1 {CONSOLE}/threats/abc_def-12")
    assert [m.group(1) for m in p.finditer(post)] == ["ABCDE12345", "2614239137407374345", "XYZ987654", "abc_def-12"]
    assert exw.AUTO_ID_PATTERN.pattern == p.pattern


@pytest.mark.parametrize("post", [
    "https://edr.example.test/alerts/ABCDE12345",
    "https://elsewhere.example.test/alerts/ABCDE12345",
    "https://console.edr.example.test.evil.example/alerts/ABCDE12345",
    "https://xconsole.edr.example.test/alerts/ABCDE12345",
    "http://console.edr.example.test/alerts/ABCDE12345",
    "https://evil.example/?u=console.edr.example.test/alerts/ABCDE12345",
    "alert ABCDE12345 mentioned without a link",
    "https://console.edr.example.test/settings/ABCDE12345",
    "https://console.edr.example.test/alerts/abcd",
    "https://console.edr.example.test/alerts/" + "x" * 65,
])
def test_make_auto_id_pattern_ignores_other_hosts_and_shapes(post):
    assert contract.make_auto_id_pattern(CONSOLE).search(post) is None


@pytest.mark.parametrize("console", [None, "", "   ", "console.edr.example.test", "http://console.edr.example.test",
                                     "https://", "not a url"])
def test_make_auto_id_pattern_never_matches_without_a_console(console):
    p = contract.make_auto_id_pattern(console)
    assert p.search(f"{CONSOLE}/alerts/ABCDE12345") is None
    assert p.search("https://anything/alerts/ABCDE12345 ABCDE12345") is None


def test_make_auto_id_pattern_trailing_slash_and_case():
    p = contract.make_auto_id_pattern(CONSOLE.upper() + "/")
    assert p.search(f"{CONSOLE}/alerts/ABCDE12345").group(1) == "ABCDE12345"


def test_auto_id_pattern_skips_segment_words():
    from providers.edr import contract as c
    rx = c.make_auto_id_pattern("https://console.edr.example.test")
    post = "see https://console.edr.example.test/incidents/threats/2614239137407374345/overview"
    assert [m.group(1) for m in rx.finditer(post)] == ["2614239137407374345"]
