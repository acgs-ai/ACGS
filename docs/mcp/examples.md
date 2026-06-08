# MCP examples

## Filesystem write

```json
{
  "method": "tools/call",
  "params": {
    "name": "filesystem.write_file",
    "arguments": {
      "path": "docs/example.md",
      "content": "example"
    }
  }
}
```

Expected governance posture: require authorization before writing and preserve the receipt.

## Deployment action

```json
{
  "method": "tools/call",
  "params": {
    "name": "cloud.run.deploy",
    "arguments": {
      "service": "acgi-ai-console",
      "region": "us-central1"
    }
  }
}
```

Expected governance posture: require privileged authority, deployment policy context, and post-deploy evidence before making production claims.

## Secret access

```json
{
  "method": "tools/call",
  "params": {
    "name": "secrets.read",
    "arguments": {
      "name": "CONSOLE_AUTH_UPSTREAM"
    }
  }
}
```

Expected governance posture: deny or escalate unless actor identity, purpose, and audit requirements are satisfied.
