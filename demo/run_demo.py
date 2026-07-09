#!/usr/bin/env python3
"""Drives a full MCP exchange (initialize, tools/list, tools/call) through mcp-guard."""
import sys, os, json, subprocess, threading, time

def echo_stderr(proc):
    for raw in iter(proc.stderr.readline, b""):
        sys.stdout.write("        " + raw.decode(errors="replace"))
        sys.stdout.flush()

def run_through_proxy(label, server_script, server_id):
    print(f"\n{'='*70}\n{label}\n{'='*70}")
    here = os.path.dirname(os.path.abspath(__file__))
    guard = os.path.join(here, "..", "mcp_guard.py")
    cmd = [sys.executable, guard, "--id", server_id,
           "--baseline-dir", "/tmp/mcpg_baselines", "--log", "/tmp/mcpg_audit.jsonl",
           "--", sys.executable, os.path.join(here, server_script)]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    threading.Thread(target=echo_stderr, args=(proc,), daemon=True).start()

    def rpc(obj, expect_reply=True):
        proc.stdin.write((json.dumps(obj) + "\n").encode()); proc.stdin.flush()
        if not expect_reply: return None
        raw = proc.stdout.readline()
        return json.loads(raw) if raw.strip() else None

    rpc({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}})
    rpc({"jsonrpc":"2.0","method":"notifications/initialized"}, expect_reply=False)
    tl = rpc({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
    tc = rpc({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"add","arguments":{"a":40,"b":2}}})
    time.sleep(0.2)
    proc.stdin.close(); proc.wait()
    time.sleep(0.2)
    print(f"\n    client saw tool result: {tc['result']['content'][0]['text'][:50]!r}")

# 1) clean server first -> records the trust-on-first-use baseline, no flags
run_through_proxy("RUN 1: clean server (establishes baseline)", "mock_clean.py", "demo-server")
# 2) 'next version' is the malicious fixture, same id -> drift + poison flags fire
run_through_proxy("RUN 2: same server, compromised 'update' (should raise flags)", "mock_evil.py", "demo-server")
print("\n" + "="*70 + "\nDemo complete.\n" + "="*70)
