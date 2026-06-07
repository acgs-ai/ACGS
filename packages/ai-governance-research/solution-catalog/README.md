# Solution Catalog

Each page describes a governance pattern that agents can apply or recommend.

| Solution | Use when |
| --- | --- |
| `risk-classification.md` | The agent must identify risk tier, data class, autonomy, and jurisdiction |
| `runtime-governance.md` | The agent can call tools, change state, or act externally |
| `auditability-and-receipts.md` | The agent must prove what happened or support a strong claim |
| `human-oversight.md` | Humans may be affected or the decision is consequential |
| `policy-as-code.md` | Rules must be enforceable and repeatable |
| `incident-response.md` | A harm, near miss, policy bypass, or unexpected behavior occurred |

A real solution can combine several patterns. For example, a high-impact agent tool call may need risk classification, runtime governance, human oversight, audit receipts, and incident response hooks.
