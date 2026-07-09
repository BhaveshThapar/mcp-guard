# mcp-guard

An inline security proxy for MCP servers. It sits between your MCP client (the
agent) and an MCP server; every message passes through unchanged, but on the way
through, `mcp-guard` inspects it and flags anything suspicious.

This grew out of [mcp-audit](https://github.com/BhaveshThapar/mcp-audit) — a
behavioral audit of 70 MCP servers. That project showed what servers *do* at
startup. The gap it surfaced: the dangerous behavior isn't at startup, it's in
what a server returns during tool calls, and in what changes after you've already
trusted it. `mcp-guard` watches that, live.

## What it catches

As an inline proxy, it inspects two surfaces:

**Supply-chain drift (the rug-pull case).** On the first run it records a
trust-on-first-use baseline of the server's tools. On every later run it diffs
against that baseline and flags a server that quietly **adds a tool** or **changes
a tool's description or schema** — i.e. a server that was clean when you adopted
it and changed later. This is the exact failure static scans and namespace auth
miss: a trusted author (or a compromised one) going rogue in a later version.

**Tool-output & tool-description inspection.** It scans tool *descriptions* (for
tool-poisoning — injection instructions hidden in the schema the agent reads) and
tool *outputs* (for crafted content that tries to steer the agent, and for leaked
credential patterns).

## What it does NOT catch (honest scope)

`mcp-guard` covers the **supply-chain surface** ("is this server malicious or did
it change?") and **content inspection** ("is the content it returns trying to
manipulate the agent?").

It does **not** fully solve **confused-deputy** attacks. A server can be 100%
clean by every metric here and still hand back poisoned content that manipulates
the agent into misusing permissions it legitimately has — because the exploit is
in the *data*, not the server's *behavior*, and the damage happens in what the
*agent does next*, which a server-side proxy cannot see. Catching that requires a
separate **agent-side layer** that has visibility into the agent's actions. That
is deliberately **out of scope for v0 and on the roadmap** — see below. If a tool
claims to make confused-deputy go away by watching the server, be skeptical.

## How it works

MCP stdio transport is newline-delimited JSON-RPC. `mcp-guard` launches the real
server as a subprocess and pumps bytes in both directions, parsing each message:

```
  client  <-->  mcp-guard  <-->  server
                   |
              inspect: schema drift, description/output injection, credential leaks
                   |
              baseline (trust-on-first-use)  +  audit log (JSONL)
```

Detection today is a set of cheap deterministic rules (the first tier). The
intended second tier is a light LLM verifier for the ambiguous
"is-this-output-steering-the-agent" cases — escalated to only when the cheap
rules are inconclusive, to keep inline latency low.

## Try it

```bash
# runs a clean server (0 flags, baseline recorded), then the same server
# "updated" to a compromised version (drift + poison flags fire)
python3 demo/run_demo.py
```

Against a real server:

```bash
python3 mcp_guard.py --id my-server -- npx -y <some-mcp-server>
```

The proxy speaks MCP itself, so you can also point a real MCP client at
`mcp_guard.py -- <server command>` in place of the server command.

## Roadmap

- **Agent-side layer** for confused-deputy: intent visibility into what the agent
  does with tool results (the gap named above). Different, harder build.
- **Light-LLM verifier** as the second detection tier for ambiguous content.
- **Diff-then-deep-run at scale**: cheap inline check on everything, expensive
  deep inspection only on servers whose behavior changed.
- **Policy enforcement**: move from flag-and-log to block-suspicious, with
  per-org or per-server learned baselines.

## Design notes

Positioning as a *proxy* rather than a scanner is deliberate: it's the one
deployable surface that covers supply-chain defense and content inspection from a
single point you control, without distributing anything into every client. Threat
models are layered, not competing — this is the first layer; the agent-side layer
is the last line of defense. Neither substitutes for the other.

---

*Built by [YOUR NAME] · [contact / GitHub]. Grew out of the
[mcp-audit](https://github.com/BhaveshThapar/mcp-audit) 70-server study.*
