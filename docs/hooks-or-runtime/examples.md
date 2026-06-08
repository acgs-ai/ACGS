# Hook or runtime examples

## Single tool call

```json
{
  "tool_name": "Edit",
  "tool_input": {
    "file_path": "README.md",
    "new_string": "demo"
  }
}
```

Evaluate it locally:

```bash
printf '{"tool_name":"Edit","tool_input":{"file_path":"README.md","new_string":"demo"}}' \
  | uv run --package gove-zone gove-zone gate --actor example
```

## MCP-style call shape

```json
{
  "method": "tools/call",
  "params": {
    "name": "filesystem.write_file",
    "arguments": {
      "path": "README.md",
      "content": "demo"
    }
  }
}
```

The adapter should normalize this into the same governed tool-call contract before evaluation.

## Malformed batch behavior

Recognized multi-call containers that include unparseable child calls should fail closed. Do not silently ignore malformed children or fall back to an allow decision for the parent batch.
