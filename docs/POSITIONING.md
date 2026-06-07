# Positioning: why a neutral governance layer is a category, not a feature

> **Core invariant: No valid Decision Receipt, no side effect.**

A fair objection: *"Agent governance is becoming a built-in feature of every agent platform. Why is this a separate thing?"*

The answer is not that ACGS does more than a platform's built-in governance — those controls can be excellent. It is *independence*: a team running agents on several platforms often wants governance evidence that lives outside any one platform, in a format it controls. This note states the case from the buyer's needs and from evidence, and names no competitor.

## The independence argument

When each platform governs only its own agents, a team running on several platforms ends up with governance evidence fragmented across vendors, in vendor-shaped formats, and stored inside the platforms whose agents it describes. A team that wants one consistent record of what every agent — anywhere — was authorized to do, in a format it owns and can take with it, needs a layer that sits outside any single platform. That independence removes the fragmentation, and it is a different job from any one platform's built-in controls.

ACGS is the layer a team reaches for when it would rather not depend on any one platform to govern the agents it runs on three others. That is why independence and neutrality are the product, not a feature checkbox.

## What makes the neutrality real (and what does not yet)

Neutrality is only credible if it is visible in the artifacts. What is shipped today:

- **The gate sits below the runtime.** Policy is evaluated at the executor boundary, not inside any one framework. The payload parser (`integration.py`) is documented runtime-neutral and treats hook, MCP, function-call, and generic shapes alike — no privileged default. Evidence: `docs/CLAIMS.md`, `INTEGRATION_MATRIX.md`.
- **The Decision Receipt is a vendor-neutral format.** Its fields carry no framework- or model-specific shape (`receipt.py`), so the audit record a buyer keeps does not belong to any vendor. Evidence: `DECISION_RECEIPT_SPEC.md`.
- **The audit chain and replay are local and inspectable.** Evidence over assertion: run the proof path in the README.

What is **not** yet true, stated plainly so the neutrality claim stays honest:

- Cross-host **portability validators** (the same receipt verified across independent agent hosts) are on the [roadmap](ROADMAP.md), not shipped.
- Per-runtime coverage is **tiered**, not uniform — shipped/tested for some surfaces, illustrative patterns for others, roadmap for the rest. The [integration matrix](INTEGRATION_MATRIX.md) shows exactly which is which.
- ACGS is alpha and not production-, compliance-, or regulator-certified. See [`CLAIMS.md`](CLAIMS.md).

## The one-line version

Built-in platform governance answers "are my agents on *this* platform behaving?" ACGS answers "can I prove, in one vendor-neutral format I own, that an agent — on any platform I wire the gate into — was authorized before it acted?" The second question is the one a neutral layer is positioned to answer across platforms. (Verifying that record across *independent* hosts is the cross-host portability work still on the [roadmap](ROADMAP.md).)

## What this note is not

This is not a claim that ACGS replaces platform controls, IAM, sandboxing, or content moderation — it complements them (see [`COMPARISON.md`](COMPARISON.md)). And it is not a claim that any platform's own governance is deficient. It is a claim about *position*: a team that wants platform-independent governance evidence needs it to live somewhere no single platform owns.
