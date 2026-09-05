# -*- coding: utf-8 -*-
"""MCP server (stdio JSON-RPC) over the shared haap tool surface."""
import io
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from haap.mcp_server import MCPServer, PROTOCOL_VERSION, mcp_tool_list, run_stdio
from haap.tools import HaapRuntime, merge_config, tool_schemas


@pytest.fixture()
def server(tmp_path):
    rt = HaapRuntime(merge_config({"haap_dir": str(tmp_path / "haap"), "serve": False,
                                   "auto_register": False}))
    yield MCPServer(rt)
    rt.stop()


def _req(method, req_id=1, **params):
    return {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}


def test_initialize_and_ping(server):
    res = server.handle(_req("initialize", protocolVersion=PROTOCOL_VERSION,
                             capabilities={}, clientInfo={"name": "t", "version": "0"}))
    assert res["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert res["result"]["serverInfo"]["name"] == "haap"
    assert "tools" in res["result"]["capabilities"]
    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert server.initialized is True
    assert server.handle(_req("ping", 2))["result"] == {}


def test_tools_list_matches_shared_surface(server):
    res = server.handle(_req("tools/list"))
    tools = res["result"]["tools"]
    assert {t["name"] for t in tools} == set(tool_schemas())
    assert all("inputSchema" in t and "description" in t for t in tools)
    assert mcp_tool_list() == tools


def test_tools_call_whoami(server):
    res = server.handle(_req("tools/call", name="haap_whoami", arguments={}))
    assert res["result"]["isError"] is False
    payload = json.loads(res["result"]["content"][0]["text"])
    assert payload["success"] and payload["fingerprint"].startswith("HF-")


def test_tool_failure_is_isError_not_protocol_error(server):
    res = server.handle(_req("tools/call", name="haap_registry_register", arguments={}))
    assert "error" not in res
    assert res["result"]["isError"] is True
    assert "endpoint" in json.loads(res["result"]["content"][0]["text"])["error"]


def test_unknown_tool_and_method(server):
    assert server.handle(_req("tools/call", name="nope", arguments={}))["error"]["code"] == -32602
    assert server.handle(_req("no/such"))["error"]["code"] == -32601
    assert server.handle({"foo": "bar"})["error"]["code"] == -32600


def test_stdio_roundtrip(tmp_path):
    rt = HaapRuntime(merge_config({"haap_dir": str(tmp_path / "haap"), "serve": False,
                                   "auto_register": False}))
    lines = [
        json.dumps(_req("initialize", 1, protocolVersion=PROTOCOL_VERSION)),
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        "not json",
        json.dumps(_req("tools/list", 2)),
        json.dumps(_req("tools/call", 3, name="haap_whoami", arguments={})),
    ]
    out = io.StringIO()
    rc = run_stdio(rt, stdin=io.StringIO("\n".join(lines) + "\n"), stdout=out)
    assert rc == 0
    responses = [json.loads(l) for l in out.getvalue().splitlines()]
    ids = [r.get("id") for r in responses]
    assert ids == [1, None, 2, 3]            # notification produced no output
    assert responses[1]["error"]["code"] == -32700
    assert len(responses[2]["result"]["tools"]) == len(tool_schemas())
    assert json.loads(responses[3]["result"]["content"][0]["text"])["success"] is True
