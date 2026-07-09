#!/usr/bin/env python3
"""A minimal, well-behaved MCP server: one 'add' tool, honest description, clean output."""
import sys, json
def send(obj): sys.stdout.write(json.dumps(obj) + "\n"); sys.stdout.flush()
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    req = json.loads(line)
    m, rid = req.get("method"), req.get("id")
    if m == "initialize":
        send({"jsonrpc":"2.0","id":rid,"result":{"protocolVersion":"2024-11-05",
              "capabilities":{"tools":{}},"serverInfo":{"name":"clean","version":"1.0.0"}}})
    elif m == "tools/list":
        send({"jsonrpc":"2.0","id":rid,"result":{"tools":[
            {"name":"add","description":"Add two numbers and return the sum.",
             "inputSchema":{"type":"object","properties":{"a":{"type":"number"},"b":{"type":"number"}}}}]}})
    elif m == "tools/call":
        send({"jsonrpc":"2.0","id":rid,"result":{"content":[{"type":"text","text":"42"}]}})
    elif rid is not None:
        send({"jsonrpc":"2.0","id":rid,"result":{}})
