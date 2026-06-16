# Human evaluator guide

Audience: developers, funders, buyers, reviewers, contributors, and security evaluators.

## Why agent side effects need governance

Agent systems increasingly connect model reasoning to tools that change the world: files, APIs, databases, infrastructure, payment systems, email, queues, CI/CD, and MCP servers. A model can propose an action, but proposal is not authority. Without a separate execution gate, teams often discover unauthorized or poorly-evidenced tool calls only after the side effect has already happened.

ACGS / gove-zone moves the governance decision before execution and makes the decision inspectable afterward.

## What ACGS is

ACGS / gove-zone is a receipt-gated execution membrane. It evaluates a proposed side effect against policy, authority, identity, action, arguments, tenant, boundary, and evidence requirements. It emits a Decision Receipt and an audit event. The executor runs only when the receipt verifies.

Core invariant:

> **No valid Decision Receipt, no side effect.**

## How ACGS differs from guardrails

Guardrails often moderate text, model outputs, prompt content, or structured responses. ACGS governs execution legitimacy: whether a concrete side effect may run. A guardrail might say "do not reveal secrets"; ACGS can block `write_file(path="~/.ssh/id_rsa")` before the tool runs and record the denial.

Use both: guardrails for content and behavior constraints, ACGS for side-effect authorization.

## How ACGS differs from MCP

MCP connects models and tools through a protocol. MCP answers "how does an agent call this tool?" ACGS answers "may this specific actor run this specific tool call with these arguments under this policy?"

MCP can be the transport. ACGS is the gate before `tools/call` reaches the side-effectful implementation.

## How ACGS differs from orchestration frameworks

LangGraph, OpenAI Agents-style runtimes, CrewAI-like systems, and custom planners orchestrate work. They schedule, route, retry, or compose tools. ACGS does not orchestrate; it authorizes side effects. Put the receipt gate at the framework's tool boundary, node boundary, or executor adapter.

## Where it fits in an agent stack

```text
model / planner / agent framework
        │ proposes action
        ▼
ACGS governance check
        │ emits Decision Receipt + audit evidence
        ▼
executor receipt gate
        │ verifies actor/action/args/policy/audit/signature/expiry
        ▼
side-effectful tool or fail-closed denial
```

The model may request an action. The executor must enforce the receipt gate.

## Why receipt-gated execution matters

A Decision Receipt turns "the agent thought it was okay" into a narrow, verifiable contract:

- who proposed the action;
- which action was proposed;
- which arguments were authorized;
- which policy bundle/hash governed the decision;
- which validator/authority issued the decision;
- when it expires;
- which audit event anchors it;
- whether a signature is required and verified.

That receipt can be checked before execution and reviewed after incidents.

## Current maturity

`gove-zone` is alpha (`0.1.0.dev0`). Implemented local capabilities include:

- policy-before-execution kernel;
- Decision Receipt schema and validation;
- receipt-gated executor;
- actor/action/argument/policy/tenant/boundary/expiry binding;
- tamper-evident JSONL audit chain;
- replay helpers and optional raw-argument side store;
- opt-in Ed25519 signing mode;
- local proof pack and demos;
- adapter parsing for hook/MCP/function-call payload shapes.

## Current limitations

- Local JSONL audit storage is not WORM/off-host durability.
- Signing is opt-in; unsigned local mode is not a production signing claim.
- No PKI, certificate chain, revocation, or managed key custody.
- No complete IAM/RBAC system.
- No compliance certification or regulator approval.
- Integration examples are local reference patterns, not certified framework adapters.
- Production deployment requires external credentials, deployment evidence, monitoring, incident response, and review beyond this local proof path.

## How to evaluate the repo quickly

Run:

```bash
tmp=$(mktemp -d) && uv run --package gove-zone gove-zone smoke --audit "$tmp/acgs-gove-zone-smoke-audit.jsonl"
uv run --extra crypto --package gove-zone python packages/gove-zone/examples/receipt-gated-execution/demo.py
uv run --package gove-zone python examples/tamper_demo/demo.py
uv run python -m pytest tests/docs --import-mode=importlib -q
```

Then inspect `docs/CLAIMS.md`. If a claim is not linked to source, tests, demo output, receipt evidence, replay verification, or roadmap, downgrade it.
