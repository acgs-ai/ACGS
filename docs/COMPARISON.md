# Honest comparison

> **Core invariant: No valid Decision Receipt, no side effect.**

ACGS / gove-zone is an **alpha, local receipt-gated kernel**, not a deployed
managed service. Its current differentiator is a self-contained Decision Receipt
with exact actor, action, canonical-argument, policy, and audit bindings that a
local governed executor can verify. Signing requires configured trust material;
single-use enforcement is optional. Cross-host portability validators remain
roadmap work.

This is not a claim that other systems only log after execution. Several current
systems enforce policy before a tool call.

| System or category | Evidenced strength | ACGS's narrower emphasis | Composition posture |
|---|---|---|---|
| AWS AgentCore Policy | Deterministic pre-tool-call authorization and policy-decision logs. | Self-contained, locally executor-verifiable receipts with exact bindings. | Preserve an authenticated upstream decision as federated provenance. |
| Microsoft Agent Control Specification / Agent Governance Toolkit | Fail-closed runtime intervention, evidence fields, broad framework support, and audit integrity/inclusion proofs. | A sealed per-decision artifact verified by the local executor before the side effect, with optional local consumption. | Preserve the original decision and adapter provenance as a federated attestation. |
| Galileo Agent Control | Centralized runtime policy control and an open-source integration surface. | Offline receipt verification and exact execution-boundary bindings. | Adapter candidate; no shipped production adapter is claimed. |
| OPA / Cedar | Mature deterministic policy evaluation. | Connects a verdict to executor validation, receipt evidence, audit, and replay. | Use as a decision source rather than forcing replacement. |
| NVIDIA NeMo Guardrails and security guardrails | Pre/post tool-call and model-interaction controls, with scope varying by product. | Authorization evidence for consequential side effects, not general moderation. | Complementary controls. |
| MCP and agent frameworks | Tool connectivity and orchestration. | A gate at the executor boundary. | Route the real side effect through the governed executor. |
| IAM, sandboxing, and SIEM | Identity, containment, and operational evidence. | Exact per-action authorization evidence. | Required complements, not replaced by ACGS. |

## Assurance classes

Different sources must not be rendered as the same trust state:

1. **Native receipt** — signed before execution and directly verified by the
   ACGS executor. This repository provides local primitives; a managed native
   transaction spine is not shipped.
2. **Federated attestation** — derived from an authenticated upstream policy
   decision, countersigned by a trusted adapter, with original provenance
   retained. Adapter profiles are planned.
3. **Observed evidence** — derived from logs or traces after execution. It is
   never represented as pre-execution authorization proof.

The local proof pack and verifier demonstrate repository-local conformance.
They do not prove managed ingestion, independently witnessed anchoring,
production deployment, certification, customer use, or revenue.

## Sources

- AWS AgentCore Policy: <https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html>
- Microsoft Agent Governance Toolkit: <https://github.com/microsoft/agent-governance-toolkit>
- Galileo Agent Control: <https://github.com/Agent-Control-Plane/agent-control-plane>
- Open Policy Agent: <https://www.openpolicyagent.org/docs/latest/>
- Cedar: <https://docs.cedarpolicy.com/>
- NVIDIA NeMo Guardrails: <https://docs.nvidia.com/nemo/guardrails/latest/>
