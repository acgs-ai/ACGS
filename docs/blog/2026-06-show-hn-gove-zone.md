# Show HN submission — gove-zone (paste-ready)

Claim-safe per docs/CLAIMS.md. All capability lines verified via the proof path (smoke + receipt-gated demo + tamper demo), 2026-06-07.
HN formatting note: comments render only blank-line paragraphs, *italics*, and 2-space-indented code — no #headers, no ```fences, no **bold**, no tables.

---

## Title

Show HN: gove-zone – receipt-gated execution for AI agents (fail-closed, alpha)

## URL

https://github.com/dislovelhl/ACGS

---

## First comment (paste verbatim into HN)

AI-agent governance got crowded fast. Some of it sits at the perimeter — content guardrails that watch prompts and score LLM outputs. But the strongest entrants already enforce at the execution boundary: Microsoft's open-source Agent Governance Toolkit is runtime policy-enforcement middleware (pre/post tool-call policy via Cedar/OPA, fail-closed, Merkle-chained audit). gove-zone sits at that same tool-call boundary; its narrower bet is the artifact, not the layer. The whole thing reduces to one invariant: no valid Decision Receipt, no side effect — a sealed, signed-before-execution receipt a relying party can verify on its own, rather than a forensic audit trail reconstructed after the fact.

Guardrails vs receipts. A prompt-level guardrail moderates what an agent *says*. But once a tools/call leaves the model, intent stops being the question — the question is whether *this* actor may run *this* action with *these exact arguments* under *this* policy. Text guardrails sit on the wrong side of that line: a safe-looking argument can be mutated by middleware or the runtime caller before it reaches the OS (a path flips from /tmp/safe.txt to /etc/shadow). gove-zone evaluates policy at the executor and binds the action name, the exact serialized arguments, the actor, and the policy context into one verifiable object — the Decision Receipt. Without a receipt matching those exact parameters, the executor fails closed.

Logs vs receipts. Post-hoc logging (e.g. the EU AI Act's Article 12) is a narrative written after the fact — it can't stop a destructive action, and if it's mutable it can't even prove what happened. gove-zone makes the receipt the gate: evaluated and stored before the side effect runs. Audit events are hash-chained locally, so modifying one entry breaks chain verification. Decisions can be replayed where the raw call context was retained. For higher-assurance setups, receipt signing is opt-in Ed25519 — a forged or recomputed receipt with no valid signature is rejected.

Try it in about a minute:

  tmp=$(mktemp -d) && uv run --package gove-zone gove-zone smoke --audit "$tmp/audit.jsonl"
  uv run --package gove-zone python packages/gove-zone/examples/receipt-gated-execution/demo.py
  uv run --package gove-zone python examples/tamper_demo/demo.py

A safe write is allowed; an id_rsa write is denied before any side effect; both decisions verify as a hash-linked chain; tampering with the evidence makes verification fail.

What this is not — it's alpha (0.1.0.dev0), a local kernel, not a managed service:

- Not production-, compliance-, or regulator-certified. The EU AI Act deadline is a reason to build this layer now, not a certificate we ship.
- Not a sandbox. You still need gVisor/Firecracker/Docker to contain untrusted execution; gove-zone is the logical permission membrane, not containment.
- Signing is opt-in and assumes you run your own keys/PKI.

It's open source — please try to bypass the fail-closed gates and tell us where it breaks.

Repo: https://github.com/dislovelhl/ACGS
Docs: https://acgs.ai/docs
