# Positioning: why a neutral governance layer is a category, not a feature

> **Core invariant: No valid Decision Receipt, no side effect.**

A fair objection: *"Agent governance is becoming a built-in feature of every agent platform. Why is this a separate thing?"*

The answer is not that ACGS does more than a platform's built-in governance — those controls can be excellent. It is that ACGS occupies a position a single platform is **not structurally placed to offer**: even-handed neutrality *across the platforms themselves*. This note states the case from evidence, and names no competitor.

## The structural argument

A vendor that ships agents and also governs those agents has a built-in conflict of interest: the governor and the governed are the same party. That says nothing about the quality of its engineering — only about its position. And the moment a team runs agents on more than one platform, "let each platform govern its own agents" fragments the governance evidence across vendors, in vendor-shaped formats, held by the parties being audited. A neutral layer outside the platforms is what removes both the conflict and the fragmentation.

ACGS is the layer a team reaches for *precisely because* it does not want to hand any one platform the authority to govern the agents it runs on three other platforms. That is a different job from any single platform's built-in controls, and it is why neutrality is the product, not a feature checkbox.

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

Built-in platform governance answers "are my agents on *this* platform behaving?" ACGS answers "can I prove, in one portable format I own, that *any* agent — on any platform — was authorized before it acted?" The second question is the one a neutral layer is positioned to answer across platforms.

## What this note is not

This is not a claim that ACGS replaces platform controls, IAM, sandboxing, or content moderation — it complements them (see [`COMPARISON.md`](COMPARISON.md)). And it is not a claim that any named competitor is deficient. It is a claim about *position*: even-handedness is a job that only a party outside the platforms can hold.
