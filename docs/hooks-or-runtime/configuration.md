# Hook or runtime configuration

The current local runtime surface is `gove-zone`.

## Generate configuration guidance

```bash
uv run --package gove-zone gove-zone setup --format json
```

Use the generated output as host-specific guidance. Keep user-local credentials and private MCP configuration outside the repository.

## Check installation health

```bash
uv run --package gove-zone gove-zone doctor
```

## Gate mode rollout

Use a staged rollout:

1. report-only receipt emission;
2. audit-chain verification;
3. deny-path and malformed-input tests;
4. enforce mode for selected tools;
5. broader enforcement after bypass review.

## Repository example

This checkout wires a Claude-style pre-tool hook through `.claude/settings.json` and `.claude/hooks/acgs-emit-receipt.py`. Treat that as an example host adapter, not the only possible runtime integration.
