# Thread: Guardrails vs Receipts (Tuned X/Twitter format)

Source: [docs/blog/2026-06-receipts-vs-guardrails-positioning.md](file:///home/martin/Documents/ACGS/docs/blog/2026-06-receipts-vs-guardrails-positioning.md)
Every claim verified via the gove-zone proof path, 2026-06-07.

---

### Tweet 1 (Hook)
AI agent "governance" got crowded fast (Microsoft, Galileo, CSA all naming a "control layer"). But most tools govern the *perimeter*: what an agent attempts.

The harder question: when an action runs, was it legitimate—with proof you can verify afterward? 🧵

*Length: 260 / 280 characters*

---

### Tweet 2 (Distinction 1: Guardrails)
1/ Distinction 1: Guardrails moderate the message. Receipts gate the action.

A guardrail filters text or tool requests. But by the time a tool call leaves a model, the real question is: may THIS actor run THIS action with THESE args under THIS policy evidence?

*Length: 261 / 280 characters*

---

### Tweet 3 (Worked Example)
2/ E.g., a receipt issued for `{"path":"/tmp/safe.txt"}` won't authorize `{"path":"/etc/shadow"}`.

Same action, different args → blocked as an argument mismatch BEFORE any side effect. A text guardrail has no equivalent move, as args can mutate before the system call.

*Length: 254 / 280 characters*

---

### Tweet 4 (Distinction 2: Logs vs Receipts)
3/ Distinction 2: An audit log is a narrative. A Decision Receipt is a gate.

A log is a story told after the fact—it can't stop anything, and if mutable, can't prove what happened.

The receipt IS the gate: the same object both enforces the decision and records it.

*Length: 263 / 280 characters*

---

### Tweet 5 (Tamper Evidence)
4/ Inside gove-zone, local decisions are hash-linked in a tamper-evident audit chain. Tamper with one entry, and verification fails.

For higher assurance, opt-in Ed25519 signing makes authority cryptographically attributable rather than merely recorded. Fails closed.

*Length: 263 / 280 characters*

---

### Tweet 6 (Where it sits)
5/ gove-zone runs below the agent framework, binding actor + action + args + policy + validator + authority + receipt + audit into one decision.

It doesn't replace sandboxing or IAM. It acts as the execution membrane underneath them, failing closed on any validation gap.

*Length: 263 / 280 characters*

---

### Tweet 7 (Limitations & Link)
6/ Honest boundary: gove-zone is alpha (0.1.0.dev0). Real, locally reproducible proof—not compliance or regulator certification.

Run the 1-minute proof path to see it gate actions & fail closed when tampered:
github.com/dislovelhl/ACGS

*Length: 241 / 280 characters (counting the GitHub link as 23 characters)*
