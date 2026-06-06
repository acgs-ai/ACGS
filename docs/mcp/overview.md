# MCP overview

MCP is an important tool boundary because it standardizes how agents discover and call external capabilities. ACGS should treat MCP tool calls as proposed side effects that require pre-execution authorization when they affect files, networks, credentials, deployments, databases, or other protected resources.

## Current scope

The current `gove-zone` integration code supports MCP-style payload normalization. That is not the same as claiming a complete governed MCP gateway is production-deployed.

## Governance goal

Every MCP tool call should be evaluated through the same core contract:

1. normalize tool name and arguments;
2. evaluate authority and policy;
3. emit decision receipt;
4. block unsafe or unverifiable calls before execution;
5. retain audit evidence for replay.
