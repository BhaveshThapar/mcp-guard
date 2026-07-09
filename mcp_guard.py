#!/usr/bin/env python3
"""
mcp-guard - an inline security proxy for MCP servers.

It sits between an MCP client (the agent) and an MCP server. Every JSON-RPC
message passes through unchanged, but on the way through it inspects:

  1. Tool schemas (from tools/list) for:
       - injection language hidden in tool *descriptions* (tool poisoning)
       - drift vs a trust-on-first-use baseline (a trusted server that later
         adds a tool or changes a description = the rug-pull case)
  2. Tool outputs (from tools/call results) for:
       - injection language in returned content (crafted output that tries to
         steer the agent)
       - leaked credential patterns

Scope (deliberately honest): this covers the SUPPLY-CHAIN surface (is the
server itself malicious / did it change) and TOOL-OUTPUT INSPECTION (is the
content it returns trying to manipulate the agent). It does NOT fully solve
confused-deputy: it cannot see what the agent ultimately *does* with content
it trusts. That is a separate agent-side layer, on the roadmap.

Usage:
    python mcp_guard.py [--id NAME] [--baseline-dir DIR] [--log FILE] -- <server command>

Example:
    python mcp_guard.py --id postmark -- npx -y some-mcp-server
"""

import sys, os, json, re, threading, subprocess, hashlib, time

# ----- human-readable output goes to STDERR so it never corrupts the -----
# ----- JSON-RPC protocol stream flowing over stdout to the client.   -----

def log(msg, level="info"):
    colors = {"flag": "\033[91m", "info": "\033[90m", "warn": "\033[93m", "ok": "\033[92m"}
    reset = "\033[0m"
    c = colors.get(level, "")
    sys.stderr.write(f"{c}[mcp-guard] {msg}{reset}\n")
    sys.stderr.flush()

# ---------------------------------------------------------------------------
# Detection rules (v0 heuristics). A light-LLM verifier for the ambiguous
# cases is the intended next tier; these deterministic rules are the cheap
# first pass that runs on every message.
# ---------------------------------------------------------------------------

INJECTION_RULES = [
    ("prompt-injection",   re.compile(r"ignore\s+(all\s+|your\s+|the\s+)?previous\s+instructions", re.I)),
    ("prompt-injection",   re.compile(r"disregard\s+(the\s+|all\s+)?(above|previous|prior)", re.I)),
    ("prompt-injection",   re.compile(r"new\s+instructions\s*:", re.I)),
    ("system-override",    re.compile(r"<\s*important\s*>|<\s*system\s*>", re.I)),
    ("system-override",    re.compile(r"you\s+are\s+now\s+", re.I)),
    ("exfil-instruction",  re.compile(r"(send|forward|email|post|upload)\b.{0,40}\b(to|bcc)\b.{0,40}@", re.I)),
    ("exfil-instruction",  re.compile(r"(bcc|blind\s*copy)\b.{0,40}@", re.I)),
    ("tool-steering",      re.compile(r"(also|then|first)\s+call\s+the\s+\w+\s+tool", re.I)),
]

CREDENTIAL_RULES = [
    ("aws-key",     re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private-key", re.compile(r"-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----")),
    ("ssh-key",     re.compile(r"ssh-(rsa|ed25519)\s+AAAA")),
    ("bearer",      re.compile(r"\b(sk|pk|ghp|xox[bap])[-_][A-Za-z0-9]{16,}")),
]

def scan(text):
    """Return list of (rule_name, matched_snippet) for any rule that fires."""
    if not text:
        return []
    hits = []
    for name, rx in INJECTION_RULES + CREDENTIAL_RULES:
        m = rx.search(text)
        if m:
            snippet = text[max(0, m.start()-15): m.end()+25].replace("\n", " ")
            hits.append((name, snippet.strip()))
    return hits

# ---------------------------------------------------------------------------
# Baseline (trust-on-first-use). First time we see a server's tools we record
# them; every later run diffs against that snapshot.
# ---------------------------------------------------------------------------

def baseline_path(baseline_dir, server_id):
    os.makedirs(baseline_dir, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", server_id)
    return os.path.join(baseline_dir, f"{safe}.json")

def load_baseline(baseline_dir, server_id):
    p = baseline_path(baseline_dir, server_id)
    if os.path.exists(p):
        with open(p) as f:
            return json.load(f)
    return None

def save_baseline(baseline_dir, server_id, tools):
    with open(baseline_path(baseline_dir, server_id), "w") as f:
        json.dump(tools, f, indent=2)

# ---------------------------------------------------------------------------
# Inspection of specific message types
# ---------------------------------------------------------------------------

class Guard:
    def __init__(self, server_id, baseline_dir, audit_log):
        self.server_id = server_id
        self.baseline_dir = baseline_dir
        self.audit_log = audit_log
        self.pending = {}          # request id -> method
        self.lock = threading.Lock()
        self.flag_count = 0

    def audit(self, record):
        record["ts"] = time.time()
        with open(self.audit_log, "a") as f:
            f.write(json.dumps(record) + "\n")

    def flag(self, rule, detail, snippet=None):
        self.flag_count += 1
        msg = f"FLAG [{rule}] {detail}"
        if snippet:
            msg += f"  ->  \"{snippet}\""
        log(msg, "flag")
        self.audit({"type": "flag", "rule": rule, "detail": detail, "snippet": snippet})

    def on_client_message(self, obj):
        # client -> server. Record request ids so we can correlate responses.
        if isinstance(obj, dict) and "id" in obj and "method" in obj:
            with self.lock:
                self.pending[obj["id"]] = obj["method"]
            if obj["method"] == "tools/call":
                params = obj.get("params", {})
                self.audit({"type": "tool_call", "tool": params.get("name"),
                            "arguments": params.get("arguments")})
                log(f"tool call: {params.get('name')}", "info")

    def on_server_message(self, obj):
        # server -> client. Correlate to the request and inspect.
        if not isinstance(obj, dict):
            return
        rid = obj.get("id")
        method = None
        if rid is not None:
            with self.lock:
                method = self.pending.pop(rid, None)

        if method == "tools/list":
            self._inspect_tools_list(obj.get("result", {}))
        elif method == "tools/call":
            self._inspect_tool_result(obj.get("result", {}))

    def _inspect_tools_list(self, result):
        tools = result.get("tools", []) or []
        current = {}
        for t in tools:
            name = t.get("name", "?")
            desc = t.get("description", "") or ""
            schema = json.dumps(t.get("inputSchema", {}), sort_keys=True)
            current[name] = {"description": desc,
                             "schema_hash": hashlib.sha256(schema.encode()).hexdigest()[:16]}
            # 1) scan the description itself for injection (tool poisoning)
            for rule, snip in scan(desc):
                self.flag(rule, f"in description of tool '{name}'", snip)

        # 2) diff against the trust-on-first-use baseline (drift / rug pull)
        base = load_baseline(self.baseline_dir, self.server_id)
        if base is None:
            save_baseline(self.baseline_dir, self.server_id, current)
            log(f"baseline recorded for '{self.server_id}' ({len(current)} tools, trust-on-first-use)", "ok")
        else:
            for name, meta in current.items():
                if name not in base:
                    self.flag("new-tool-added", f"tool '{name}' not present in baseline")
                elif base[name]["description"] != meta["description"]:
                    self.flag("tool-description-changed",
                              f"tool '{name}' description changed since baseline")
                elif base[name]["schema_hash"] != meta["schema_hash"]:
                    self.flag("tool-schema-changed", f"tool '{name}' input schema changed since baseline")
            for name in base:
                if name not in current:
                    log(f"tool '{name}' removed since baseline", "warn")

    def _inspect_tool_result(self, result):
        # concatenate the text content the agent would actually read
        parts = []
        for item in (result.get("content", []) or []):
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(item.get("text", ""))
        text = "\n".join(parts)
        for rule, snip in scan(text):
            self.flag(rule, "in returned tool output", snip)


# ---------------------------------------------------------------------------
# The proxy: pump bytes both directions, parse each line as JSON-RPC, inspect.
# MCP stdio framing is newline-delimited JSON.
# ---------------------------------------------------------------------------

def pump(src, dst, on_message):
    for raw in iter(src.readline, b""):
        line = raw.rstrip(b"\n")
        if line.strip():
            try:
                obj = json.loads(line)
                on_message(obj)
            except json.JSONDecodeError:
                # Not protocol JSON (some servers wrongly print logs to stdout).
                # Pass it through untouched, but note it.
                log("non-JSON line on stream (passing through)", "warn")
        dst.write(raw)
        dst.flush()
    try:
        dst.close()
    except Exception:
        pass

def main():
    argv = sys.argv[1:]
    if "--" in argv:
        i = argv.index("--")
        opts, server_cmd = argv[:i], argv[i+1:]
    else:
        opts, server_cmd = [], argv

    if not server_cmd:
        sys.stderr.write(__doc__)
        sys.exit(1)

    # tiny manual option parse
    server_id = None
    baseline_dir = os.path.expanduser("~/.mcp-guard/baselines")
    audit_log = os.path.expanduser("~/.mcp-guard/audit.jsonl")
    it = iter(range(len(opts)))
    j = 0
    while j < len(opts):
        if opts[j] == "--id":            server_id = opts[j+1]; j += 2
        elif opts[j] == "--baseline-dir": baseline_dir = opts[j+1]; j += 2
        elif opts[j] == "--log":          audit_log = opts[j+1]; j += 2
        else: j += 1

    if server_id is None:
        server_id = re.sub(r"[^A-Za-z0-9._-]", "_", server_cmd[-1])
    os.makedirs(os.path.dirname(audit_log), exist_ok=True)

    log(f"guarding '{server_id}'  ->  {' '.join(server_cmd)}", "ok")
    guard = Guard(server_id, baseline_dir, audit_log)

    proc = subprocess.Popen(server_cmd, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=sys.stderr)

    t1 = threading.Thread(target=pump, args=(sys.stdin.buffer, proc.stdin, guard.on_client_message), daemon=True)
    t2 = threading.Thread(target=pump, args=(proc.stdout, sys.stdout.buffer, guard.on_server_message), daemon=True)
    t1.start(); t2.start()

    proc.wait()
    t2.join(timeout=1)
    log(f"session ended - {guard.flag_count} flag(s) raised. audit log: {audit_log}",
        "flag" if guard.flag_count else "ok")

if __name__ == "__main__":
    main()
