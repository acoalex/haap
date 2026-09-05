# -*- coding: utf-8 -*-
"""HAAP as an MCP server (Model Context Protocol, stdio transport).

Exposes the shared ``haap_*`` tool surface (``haap.tools``) to any MCP host:
Hermes Agent (``mcp_servers`` in ``~/.hermes/config.yaml``), Claude Code,
Cursor, etc. Dependency-free: newline-delimited JSON-RPC 2.0 over stdin/stdout.

    haap mcp                   # tools only (client side of HAAP)
    haap mcp --serve --port 8443 --endpoint https://me.example/haap/messages
                               # also run the HAAP messaging server in-process

Implements the MCP methods a tool server needs: ``initialize``, ``ping``,
``tools/list``, ``tools/call`` (plus ignoring ``notifications/*``). Errors use
JSON-RPC codes; tool failures come back as ``isError`` results, never as
protocol errors, so the host model can read them.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Callable, Optional, TextIO

from . import __version__
from .tools import HaapRuntime, build_handlers, tool_schemas

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "haap", "version": __version__}

# JSON-RPC error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602


def mcp_tool_list() -> list[dict]:
    """Tools in MCP shape: ``{name, description, inputSchema}``."""
    return [
        {"name": name, "description": spec["description"], "inputSchema": spec["parameters"]}
        for name, spec in tool_schemas().items()
    ]


def _result(req_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


class MCPServer:
    """Pure request handler + stdio loop over a ``HaapRuntime``."""

    def __init__(self, runtime: HaapRuntime, handlers: Optional[dict[str, Callable]] = None):
        self.runtime = runtime
        self.handlers = handlers or build_handlers(runtime)
        self.initialized = False

    # -- dispatch -------------------------------------------------------------
    def handle(self, message: Any) -> Optional[dict]:
        """Handle one JSON-RPC message; ``None`` means no response (notification)."""
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return _error(message.get("id") if isinstance(message, dict) else None,
                          INVALID_REQUEST, "invalid JSON-RPC 2.0 request")
        method = message.get("method")
        req_id = message.get("id")
        params = message.get("params") or {}

        if isinstance(method, str) and method.startswith("notifications/"):
            if method == "notifications/initialized":
                self.initialized = True
            return None
        if req_id is None:
            return None  # unknown notification: ignore

        if method == "initialize":
            requested = str(params.get("protocolVersion") or PROTOCOL_VERSION)
            return _result(req_id, {
                "protocolVersion": requested if requested == PROTOCOL_VERSION else PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO,
                "instructions": (
                    "HAAP tools: discover agents in the public directory, make friends, "
                    "delegate tasks and book marketplace services. The directory is a phone "
                    "book, not a notary — trust signals are data for you to weigh."
                ),
            })
        if method == "ping":
            return _result(req_id, {})
        if method == "tools/list":
            return _result(req_id, {"tools": mcp_tool_list()})
        if method == "tools/call":
            name = params.get("name")
            handler = self.handlers.get(name) if isinstance(name, str) else None
            if handler is None:
                return _error(req_id, INVALID_PARAMS, f"unknown tool '{name}'")
            arguments = params.get("arguments") or {}
            if not isinstance(arguments, dict):
                return _error(req_id, INVALID_PARAMS, "arguments must be an object")
            text = handler(arguments)
            try:
                is_error = not json.loads(text).get("success", True)
            except (ValueError, AttributeError):
                is_error = False
            return _result(req_id, {"content": [{"type": "text", "text": text}],
                                    "isError": is_error})
        return _error(req_id, METHOD_NOT_FOUND, f"method not found: {method}")

    # -- stdio loop -----------------------------------------------------------
    def serve(self, stdin: TextIO = None, stdout: TextIO = None) -> int:
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except ValueError:
                response = _error(None, PARSE_ERROR, "parse error")
            else:
                if isinstance(message, list):  # batch
                    responses = [r for r in (self.handle(m) for m in message) if r is not None]
                    response = responses or None
                else:
                    response = self.handle(message)
            if response is not None:
                stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
                stdout.flush()
        return 0


def run_stdio(runtime: HaapRuntime, stdin: TextIO = None, stdout: TextIO = None) -> int:
    """Start the runtime (server/registration if configured) and serve MCP."""
    runtime.start()
    try:
        return MCPServer(runtime).serve(stdin, stdout)
    finally:
        runtime.stop()
