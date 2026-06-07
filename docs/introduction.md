# Introduction

> **Core invariant: No valid Decision Receipt, no side effect.**

ACGS is not a coding agent, and it is not tied to one vendor's stack. It is the vendor-neutral, fail-closed governance boundary that decides whether any agent is authorized to act, records the decision in a portable receipt, and makes the result replayable — the same way no matter which framework, model, or protocol issued the call.

Modern agent stacks increasingly expose local customization surfaces: skills, hooks, memory, MCP servers, CLI workflows, and runtime tool adapters. Those surfaces are useful, but they do not by themselves prove legitimate authority before a side effect happens. ACGS positions the governance decision below the agent and above the side-effectful tool.

## What ACGS governs

ACGS governs proposed actions, not model text in isolation. A runtime, hook host, MCP bridge, workflow engine, CI job, or custom executor proposes a tool call. ACGS evaluates the call against authority, policy, boundary, and evidence requirements before the caller performs the side effect.

The expected result is a verifiable decision receipt and audit event that can be replayed later against the captured policy context.

## What ACGS is not

ACGS is not:

- a replacement coding agent;
- a prompt pack that merely advises an agent;
- a best-effort local guardrail that can silently fail open;
- a compliance certification claim;
- proof of production deployment without live deploy evidence.

The current repository is an alpha, production-shaped foundation. Use local verification output and receipt evidence when making readiness claims.

## Core thesis

Agent customization is becoming normal, and it is spreading across many runtimes at once. The missing layer is a framework-neutral governance plane that can sit under any of those agents and enforce legitimate action before tools execute — recording each decision in one evidence format a team keeps regardless of which framework or model it later switches to. A platform that also ships the agents it governs carries an inherent conflict of interest and keeps that evidence in its own format; a plane outside the platforms avoids both. ACGS is built to occupy that position and privileges no runtime. Which runtimes are supported, and at what proof depth, is documented honestly in [`INTEGRATION_MATRIX.md`](INTEGRATION_MATRIX.md).
