# MCP quickstart

This quickstart uses MCP-style payloads with the local gate. It does not require claiming that a full MCP server gateway is deployed.

## Evaluate a payload

```bash
cat > /tmp/acgs-mcp-call.json <<'JSON'
{
  "method": "tools/call",
  "params": {
    "name": "filesystem.read_file",
    "arguments": {
      "path": "README.md"
    }
  }
}
JSON

uv run --package gove-zone gove-zone gate --actor mcp-quickstart < /tmp/acgs-mcp-call.json
```

## Add coverage for a new MCP tool

1. Capture the tool's exact JSON-RPC shape.
2. Add normalization tests for the shape.
3. Add allow and deny policy fixtures.
4. Prove the host routes the tool through the gate before execution.
5. Record audit output in the evidence packet.
