#!/usr/bin/env python3
"""
smoke.py - verify mcp-guard runs against a real MCP server.

Why this exists: mcp-guard is an inline *proxy*, not a driver. On its own it
launches a server and waits for a client to speak MCP to it -- so running
mcp_guard.py bare against a server inspects nothing, because no messages flow.
This script plays the client: it performs the MCP handshake
(initialize -> initialized -> tools/list) so a real tools/list flows through
the proxy, letting you watch it record a trust-on-first-use baseline and scan
the server's tool descriptions and schemas.

It uses a throwaway baseline dir, so every run shows the full "baseline
recorded" output on a clean server. Expected result on a clean server: 0 flags.
To watch mcp-guard *catch* a malicious server instead, run:

    python3 demo/run_demo.py

Usage:
    python3 smoke.py                                            # default: server-everything
    python3 smoke.py -- npx -y @modelcontextprotocol/server-memory
    python3 smoke.py -- npx -y @modelcontextprotocol/server-filesystem /tmp
    python3 smoke.py -- <any stdio MCP server command>
"""
import subprocess, json, sys, os, time, tempfile, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
GUARD = os.path.join(HERE, "mcp_guard.py")
DEFAULT_SERVER = ["npx", "-y", "@modelcontextprotocol/server-everything"]
TIMEOUT_S = 120


def server_cmd_from_argv(argv):
    if "--" in argv:
        cmd = argv[argv.index("--") + 1:]
    else:
        cmd = argv
    return cmd or DEFAULT_SERVER


def main():
    server_cmd = server_cmd_from_argv(sys.argv[1:])
    baseline_dir = tempfile.mkdtemp(prefix="mcpg-smoke-")
    audit_log = os.path.join(baseline_dir, "audit.jsonl")

    print(f"[smoke] guarding: {' '.join(server_cmd)}")
    print("[smoke] watch the [mcp-guard] lines below "
          "(expect 'baseline recorded' and 0 flags on a clean server)\n")

    proc = subprocess.Popen(
        ["python3", GUARD, "--id", "smoke",
         "--baseline-dir", baseline_dir, "--log", audit_log, "--"] + server_cmd,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr, bufsize=0,
    )

    def send(obj):
        proc.stdin.write((json.dumps(obj) + "\n").encode())
        proc.stdin.flush()

    send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
          "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                     "clientInfo": {"name": "smoke", "version": "0"}}})

    tools = None
    deadline = time.time() + TIMEOUT_S
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            break
        try:
            obj = json.loads(line.strip())
        except (json.JSONDecodeError, ValueError):
            continue
        if obj.get("id") == 1 and "result" in obj:
            send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        elif obj.get("id") == 2 and "result" in obj:
            tools = obj["result"].get("tools", [])
            break

    try:
        proc.stdin.close()
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        proc.kill()

    n_flags = 0
    if os.path.exists(audit_log):
        with open(audit_log) as f:
            n_flags = sum(1 for ln in f if '"type": "flag"' in ln)
    shutil.rmtree(baseline_dir, ignore_errors=True)

    print()
    if tools is None:
        print("[smoke] FAILED: no tools/list response. Is the server command correct, "
              "and does it speak MCP over stdio?")
        sys.exit(1)

    print(f"[smoke] OK: {len(tools)} tools listed, {n_flags} flag(s) on a clean server.")
    print(f"[smoke] tools: {[t.get('name') for t in tools]}")
    print("[smoke] to watch mcp-guard catch a malicious server: python3 demo/run_demo.py")


if __name__ == "__main__":
    main()
