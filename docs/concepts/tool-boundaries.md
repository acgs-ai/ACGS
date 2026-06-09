# Tool boundaries

A tool boundary is the point where an agent proposal becomes a real side effect.

## Common boundaries

- shell commands;
- file reads and writes;
- code edits;
- network calls;
- MCP tool calls;
- deployment commands;
- database mutations;
- secret or credential access.

## Boundary contract

At a governed boundary, the host must:

1. normalize the proposed tool call;
2. ask ACGS for a decision before execution;
3. block deny, escalate, malformed, and verification-failure outcomes;
4. write audit evidence;
5. execute only the action covered by the receipt.

## Bypass risk

If a tool can be called through another path that avoids the gate, the boundary is advisory rather than authoritative. Document bypasses and progressively move high-risk tools behind enforceable gates.
