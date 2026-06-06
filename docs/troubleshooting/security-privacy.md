# Security and privacy troubleshooting

## Secrets

Do not commit secrets, private MCP credentials, cloud tokens, or user-local config. Keep private host configuration in user-local files or managed secret stores.

## Sensitive prompts and data

Treat prompts, tool arguments, and audit logs as potentially sensitive. Redact or minimize content before sharing outside the authorized review boundary.

## Deny by default for privileged actions

Secret access, deployment, database mutation, and cross-tenant data access should deny or escalate unless identity, policy, and audit evidence are complete.

## Audit handling

Audit evidence is security material. Preserve integrity, restrict access, and avoid editing JSONL audit files by hand.

## Claim safety

Do not claim regulatory compliance, production certification, or complete security coverage without independent evidence for that exact claim.
