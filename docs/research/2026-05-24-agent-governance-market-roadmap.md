# Agent Governance Market + Research Roadmap for `govern-zone`

Generated: 2026-05-24T19:31:39-04:00
Repository: `/home/martin/finished work/govern-zone`

## 0. Executive thesis

`govern-zone` should be positioned as runtime governance infrastructure for AI agents, not as another agent framework. The real problem is that agent autonomy is moving faster than enterprise-grade authorization, evidence, audit, and replay. Prompt policies, static role checks, and post-hoc logs do not form a trustworthy execution boundary when an agent can call tools, write files, send network requests, or trigger business workflows.

The product thesis is:

```text
Agent reasoning may remain flexible and model-native.
External side effects must cross a deterministic, fail-closed governance boundary.
Every action must produce evidence that can be replayed, inspected, exported, and trusted.
```

The architecture path should combine three research threads:

1. Policies on Paths: govern the tuple `(agent identity, partial path, proposed action, organizational state)` at runtime.
2. Tool calls as syscalls: treat MCP, file, shell, database, browser, and API calls like privileged host functions.
3. Evidence-first governance: emit tamper-evident receipts before or at the point of authorization, then cross-link them to traces, console views, and domain-specific review workflows.

The market timing is strong but unforgiving. Gartner predicts over 40% of agentic AI projects will be cancelled by end-2027 because of escalating costs, unclear business value, or inadequate risk controls. AI governance market forecasts show high growth, but buyers will not reward vague “responsible AI” claims; they need operational proof that a specific agent action was allowed, denied, transformed, or escalated under a specific policy version.

## 1. Real-world problem to solve

### 1.1 Core problem

Enterprises want AI agents to perform real work, but real work creates side effects:

- file writes and deletions;
- shell commands;
- network/API calls;
- database changes;
- emails, calendar actions, payments, contract redlines, Terraform applies;
- multi-agent handoffs and peer decisions;
- regulated-domain outputs in legal, healthcare, finance, infrastructure, and government settings.

Current controls are often inadequate because they sit in the wrong layer:

| Common control | Why it is insufficient alone |
|---|---|
| System prompts | Shape behavior but do not evaluate every execution path. A prompt is advisory, not an enforcement boundary. |
| Static access control | Blocks some tools/resources, but ignores path-dependent risk: the same action may be safe or unsafe depending on what happened before. |
| In-process guardrail libraries | Can be skipped, monkey-patched, or bypassed if the agent controls the same runtime/privilege domain. |
| Post-hoc logging | Records damage after execution; does not prove the action was authorized before the side effect. |
| Human review only | Does not scale to high-frequency tool calls and often lacks machine-verifiable evidence. |

The concrete buyer pain is not “we need ethics.” It is:

```text
Can we prove, for this agent action, who/what proposed it, what policy version evaluated it, why it was allowed or denied, whether the action executed, and whether that evidence was tampered with?
```

### 1.2 Why now

Research and market signals converge:

- Agent security research shows tool-using agents are vulnerable to indirect prompt injection, tool misuse, and privacy/security failures.
- Enterprise analysts warn that many agentic projects will stall because risk controls and ROI are immature.
- Regulation is moving from principles to operational obligations: EU AI Act, NIST AI RMF, NIST GenAI profile, OWASP GenAI/Agentic guidance.
- Agent tool protocols such as MCP increase interoperability but also create a common privileged execution surface.
- Buyers in legal, healthcare, financial services, infrastructure, and public sector need evidence, not screenshots.

## 2. Final goal

The final goal is a governed agent runtime platform with a small, auditable kernel and domain/product layers around it.

### 2.1 Product-level goal

Deliver an evidence-ready governance boundary for autonomous AI execution:

```text
Goal -> Proposed action -> Runtime governance decision -> Execution or denial -> Receipt -> Audit chain -> Replay/export/console review
```

Every external action should satisfy:

```text
authority_check AND policy_check AND path_context_check AND audit_commit
```

If any required gate cannot evaluate or cannot commit evidence, the system denies or escalates by default.

### 2.2 Platform-level goal

Build `govern-zone` as a layered system:

1. Kernel: `gove-zone` as minimal fail-closed dispatcher, decision model, receipt, audit, replay.
2. Library: `acgs-lite` as public PyPI legitimacy/governance library with integrations and broader policy surface.
3. Multi-agent layer: `constitutional-swarm` for peer validation, signed votes, settlement, bounded trust dynamics.
4. Evaluation layer: `acgs_governance_eval_mvp` plus benchmark adapters for AgentDojo/InjecAgent/ToolEmu-style tests.
5. Observability/evidence layer: `agent-bus-analyzer` plus Phoenix/OpenTelemetry cross-links.
6. Buyer interface: `acgi-ai` privileged console and public trust surface.
7. Domain packs: CFT infrastructure, Canadian legal skills, ClinicalGuard, LegalGuard, future healthcare/legal/finance packs.

### 2.3 Non-goals

- Do not claim compliance certification by default.
- Do not position ACGS as replacing LangGraph, CrewAI, OpenAI Agents SDK, Claude Code, Codex, or MCP.
- Do not rely on prompt-only compliance.
- Do not make Phoenix/OTel the authoritative evidence store; traces are adjuncts, hash-chained ACGS evidence is authoritative.
- Do not break `acgs-lite` public API or its Python `>=3.10` floor.

## 3. Research screen: relevant papers and what they imply

Screening criteria: papers were included if they directly affect runtime AI-agent governance, tool-use safety, policy-to-rule enforcement, multi-agent governance, or operational security/evidence.

### 3.1 Core architecture papers

| Paper/source | Key finding | Implication for `govern-zone` |
|---|---|---|
| Runtime Governance for AI Agents: Policies on Paths, arXiv:2603.16586 | Formalizes governance as runtime evaluation of agent identity, partial path, proposed next action, and organizational state. Prompt-level instructions and static access controls are special cases, not sufficient general solutions. | Make “path-aware policy evaluation” the north-star abstraction. `gove-zone` should not just classify a tool name; it should evaluate a decision request with actor, path, action, state, and policy version. |
| ProbeLogits: Kernel-Level LLM Inference Primitives for AI-Native Operating Systems, arXiv:2604.11943 | Proposes a zero-parameter, single-forward-pass logit probe as a low-latency semantic classification primitive below the agent layer. | Spike a sidecar/classifier path for semantic risk scores before tool execution. Keep it optional and calibrated; deterministic policy remains authoritative. |
| Governed MCP: Kernel-Level Tool Governance for AI Agents via Logit-Based Safety Primitives, arXiv:2604.16870 | Treats MCP tool calls as agent syscalls and places schema, trust, rate, adversarial, semantic, constitutional, and audit checks below the agent privilege boundary. | Build an MCP gateway prototype around `gove-zone`: schema validation, actor/trust tier, policy check, optional ProbeLogits, chain-hash audit. |
| Governance-as-a-Service, arXiv:2508.18765 | Frames governance as a modular runtime service that intercepts agent actions/outputs, applies declarative policy, updates trust, and allows/warns/blocks/escalates. | Keep `gove-zone` embeddable and black-box-agent compatible. Do not require model weights or framework lock-in. |

### 3.2 Agent threat/evaluation papers

| Paper/source | Key finding | Implication for `govern-zone` |
|---|---|---|
| AgentDojo, arXiv:2406.13352 | 97 realistic tasks, 629 security test cases; evaluates prompt-injection attacks/defenses for agents using tools over untrusted data. | Add AgentDojo adapter to the eval MVP; report attack success reduction, utility retention, and false-positive rate. |
| ToolEmu, arXiv:2309.15817 | LM-emulated sandbox for 36 high-stakes tools and 144 test cases; 68.8% of ToolEmu-identified failures were valid real-world failures; even the safest tested agent had failures 23.9% of the time. | Add synthetic tool-risk scenarios to acceptance tests. Use ToolEmu-style emulation to find long-tail unsafe tool paths before real deployment. |
| InjecAgent, arXiv:2403.02691 | 1,054 test cases, 17 user tools, 62 attacker tools; ReAct-prompted GPT-4 vulnerable 24% of the time, nearly doubled under reinforced attacker prompts. | Add indirect-prompt-injection suites for file/email/web/tool content. Gate must inspect external-content provenance and path context. |
| The Emerged Security and Privacy of LLM Agent, arXiv:2407.19354 | Surveys LLM-agent security/privacy threats, impacts on humans/environments/agents, and defensive strategies. | Use as taxonomy input for risk classes: prompt injection, tool misuse, privacy leakage, cross-agent compromise, operational environment harm. |

### 3.3 Policy-to-enforcement papers

| Paper/source | Key finding | Implication for `govern-zone` |
|---|---|---|
| Executable Governance for AI: Policy to Tests, arXiv:2512.04408 | Converts natural-language policy documents into normalized, executable JSON rules with provenance, hazard, scope, conditions, exceptions, and evidence signals. | Build a policy compiler spike: EU AI Act/NIST/domain policy prose -> `gove-zone` policy bundle + tests + evidence requirements. |
| Policy-as-Prompt, arXiv:2509.23994 | Extracts policy/security constraints from PRDs/TDDs/source artifacts into source-linked runtime guardrails, with default-deny model. | Use design docs and package READMEs as source artifacts for initial project-specific policies. But treat prompt classifiers as advisory unless anchored by deterministic checks. |
| NIST AI RMF + NIST GenAI Profile | Provides voluntary risk-management framework and GenAI-specific profile for lifecycle trustworthiness. | Map ACGS controls to RMF functions: Govern, Map, Measure, Manage. Use as buyer-facing evidence taxonomy. |
| OWASP Top 10 for Agentic Applications 2026 + OWASP LLM Top 10 | Identifies critical risks for autonomous/agentic AI; LLM Top 10 includes prompt injection and insecure output handling. | Use OWASP risk IDs in threat model, test labels, and console incident taxonomy. |

## 4. Market, regulatory, and buyer data

### 4.1 Market signals

| Source | Data point | Product implication |
|---|---:|---|
| Gartner, 2025-06-25 | Over 40% of agentic AI projects predicted to be cancelled by end-2027 due to escalating costs, unclear business value, or inadequate risk controls. Gartner poll: 19% significant investment, 42% conservative investment, 31% wait-and-see/unsure. By 2028, Gartner predicts at least 15% of day-to-day work decisions autonomous via agentic AI and 33% of enterprise software apps with agentic AI. | Sell “reduce cancellation risk by making agent risk controls and ROI evidence explicit.” Avoid hype; prove one decision end-to-end. |
| MarketsandMarkets AI Governance Market, Jan 2025 | Forecasts AI governance from USD 0.89B in 2024 to USD 5.78B in 2029, 45.3% CAGR. Risk management and compliance functionality forecast at 49.2% CAGR; BFSI largest end-user segment at 18.0% in 2024. | Initial GTM should focus on risk/compliance functions and regulated sectors, not general AI productivity. |
| Grand View Research AI Governance Market, May 2026 | Estimates USD 308.3M in 2025 to USD 3.59B in 2033, 36.0% CAGR; large enterprises dominate; healthcare/life sciences fastest-growing vertical at 39.9% CAGR. | Domain packs for healthcare/legal/finance/infrastructure are credible expansion paths. |

### 4.2 Regulatory signals

| Source | Key requirement/signal | Product implication |
|---|---|---|
| EU AI Act official EC page | AI Act entered into force 2024-08-01 and is fully applicable 2026-08-02 with exceptions; risk-based framework with unacceptable, high, transparency, and minimal/no-risk categories. | Console and receipts should map decisions to risk categories, human oversight, logging, documentation, and post-market monitoring themes. |
| NIST AI RMF 1.0 | Voluntary framework for managing risks to individuals, organizations, and society; released 2023-01-26. | Use NIST as non-legal buyer language for trustworthiness and lifecycle risk. |
| NIST GenAI Profile, NIST.AI.600-1 | Cross-sectoral companion profile for GenAI risks, published 2024-07-26. | Use as test/evidence taxonomy for GenAI-specific risks in eval MVP and console reporting. |
| OWASP GenAI Security Project | Community security guidance for LLM and agentic applications; Agentic Top 10 2026 published 2025-12-09. | Map ACGS controls to OWASP risks; add security-team-friendly labels to receipts and incidents. |

### 4.3 Buyer wedge

Best initial buyer profile:

```text
Regulated-AI procurement officer, AI platform lead, security/GRC lead, or legal/healthcare/financial-services operator who already has or is piloting LLM-touching agents and must prove action-level control before production.
```

Best proof journey:

```text
Buyer selects one high-risk tool action -> sees pre-execution decision -> sees reason/policy/actor/path -> exports signed/hash-anchored receipt -> auditor/security reviewer can verify chain and replay context.
```

Message to avoid:

```text
“We make agents ethical.”
```

Message to use:

```text
“We provide fail-closed, replayable governance evidence for agent actions before side effects occur.”
```

## 5. Project/subproject map

### 5.1 System map

| Layer | Subproject | Role |
|---|---|---|
| Workspace control | root `pyproject.toml`, `MONOREPO.md`, `Makefile`, workflows | Coordinates uv workspace, package gates, CI, registry, parent docs. |
| Kernel | `packages/gove-zone/` | Minimal fail-closed governed runtime for tool calls, receipts, audit chain, replay, hooks. |
| Public library | `packages/acgs-lite/` | Published PyPI legitimacy/governance library with policy engine, integrations, compliance examples, audit, MACI. |
| Multi-agent governance | `packages/Acgs-Swarm/` | AgentDNA, DAG/swarm execution, peer validation, signed votes, settlements, trust dynamics. |
| Evaluation | `acgs_governance_eval_mvp/` | Pre-execution gates, policy recall, governance recall, FastAPI, OTel, tests. |
| Infrastructure domain pack | `acgs-cft-governance-pack/` | Terraform plan governance and evidence for Google Cloud CFT. |
| Observability/evidence | `packages/agent-bus-analyzer/`, `hermes_acgs_bundle/phoenix/` | Observer-only bus trace analysis, OpenAPI types, Phoenix/OTel cross-linking. |
| Buyer/operator interface | `acgi-ai/` | React/Vite public + privileged console, evidence review, receipt export, trust/security pages. |
| Enterprise admin | `acgs-enterprise-ai-manager/frontend/` | Vue admin/CRUD surface; candidate legacy/admin lane, not core runtime. |
| Legal vertical | `ca-legal-agent-skills/` | 38 Canadian legal skills plus governed FastAPI runtime, matter gates, citation/release audit. |
| Clinical vertical | `clinicalguard-privacy-hardening/` and private `packages/clinicalguard` lane when initialized | Healthcare/privacy governance pack; PHI/clinical safety review candidate. |
| Automation/docs | `automation/`, `docs/` | Policies, proposals, roadmap, design records, workflow examples. |

### 5.2 Mapping matrix

| Subproject | Real-world problem | Final goal | Breakthrough to pursue | Current/new tech stack | Prototype to try next |
|---|---|---|---|---|---|
| Root workspace | Governance code is spread across libraries, frontend, evals, bundles, and domain packs; developers need a single source of truth. | Keep the parent repo as an honest registry and verification fan-out, not a confused mega-package. | Dependency/CI routing as governance: every package has a declared gate and evidence owner. | uv workspace, Python 3.11 local floor, pnpm 9.15/Node 24 for frontend, path-filtered GitHub Actions, Makefile fan-out. | Add a `docs/governance-stack-index.md` that links each package to its policy/evidence contract and gate. |
| `packages/gove-zone/` | Agents can execute side-effectful tool calls before governance/audit happens. | Minimal runtime kernel under ~2.5k LOC that denies when policy/audit/receipt fails. | Implement Policies-on-Paths in the kernel decision request; treat tool dispatch as syscall mediation. | Python 3.11, stdlib, optional Pydantic, SHA-256 JSONL chain, `fcntl.flock`, CLI hooks, future Rust/WASM sidecar. | `PathPolicyDecision` schema: actor + path digest + tool call + org state + policy hash -> ALLOW/DENY/TRANSFORM/ESCALATE; dispatcher-level tests prove no tool runs before audit append. |
| `packages/acgs-lite/` | Developers need embeddable governance with a stable public API and broad framework integrations. | Stable PyPI legitimacy layer that emits governed decisions, boundaries, MACI separation, compliance mappings, and replayable receipts. | Combine action legitimacy taxonomy with path-aware kernel adapter; optional Rust/PyO3 hot path for canonical hashing/policy eval. | Python >=3.10, Pydantic, Click, optional FastAPI/OTel/OpenAI/Anthropic/LangChain/MCP/etc., future Rust kernel modules under existing `rust/` lane. | `acgs-lite[gove-zone]` adapter that can route `GovernedCallable` through `gove-zone` for pre-execution tool-call receipts without breaking existing APIs. |
| `packages/Acgs-Swarm/` | Multi-agent systems lack durable settlement evidence: who validated, what quorum, what trust update, what final decision. | Orchestrator-free governance runtime for societies of agents with signed votes, settlements, replayable receipts, and bounded trust. | Use governance receipts as the settlement primitive across LangGraph/handoff/swarm flows. | Python >=3.11, `acgs-lite`, Braintrust, cryptography, numpy, optional websockets, torch/transformers, sentence-transformers, LangGraph 1.1-1.2, Anthropic Vertex/Gemini extras. | AgentDojo-style multi-agent benchmark: compromised worker proposes unsafe tool call; mesh peer validation must catch/escalate and settle with signed evidence. |
| `packages/agent-bus-analyzer/` | Even when a gate exists, operators cannot see dispatch/response/event drift and tampering across the bus. | Observer-only analysis API that never authorizes but detects wiring defects, gaps, tampering, and stale evidence. | Evidence graph: chain-hashed bus events + OpenAPI projection + console trace lens. | Python 3.11, FastAPI, Pydantic, anyio, uvicorn, JSON schema, mypy/ruff. | “One action trace” endpoint: given `receipt_id`, return bus events, audit hash, Phoenix trace IDs, and console-ready evidence summary. |
| `acgi-ai/` | Buyers and auditors cannot trust invisible backend claims; they need a polished, privilege-aware evidence console. | Buyer-demoable public/trust pages plus privileged console where one policy enforcement decision can be verified and exported. | Turn receipts into buyer-facing artifacts: policy version, actor, reason, hash, trace, replay status, export. | React 19, Vite, TypeScript 6, Tailwind 4, TanStack Router/Query, Biome, MSW, OpenAPI types, Cloud Run console, Vercel marketing, strict CSP. | `/console/audit/:receiptId` proof journey: load one receipt, verify hash chain, show policy/path/action, export signed evidence packet. |
| `acgs_governance_eval_mvp/` | Governance claims need benchmarks; otherwise “safe agent” is just marketing copy. | Evaluation harness for authority, policy recall, governance recall, audit, replay, API, and OTel metrics. | Convert AgentDojo/InjecAgent/ToolEmu into regression gates and market-facing metrics. | Python 3.11, FastAPI optional, OTel optional, JSONL chain, pytest. | Add `benchmarks/agentdojo_adapter.py` and `benchmarks/injecagent_adapter.py`; report attack success rate, utility retention, fail-closed rate, p95 gate latency. |
| `acgs-cft-governance-pack/` | Infrastructure teams need pre-apply evidence for Terraform plans, not just after-the-fact cloud audit logs. | Governance pack for CFT plans: validate project/network/GKE/IAM controls before apply and emit evidence. | Treat Terraform plan changes as proposed agent/tool actions; use same receipt vocabulary as runtime governance. | Python 3.11, Terraform plan JSON, gcloud terraform vet, OPA/Rego-compatible posture, JSONL Merkle evidence, GitHub Actions. | GitHub Actions evidence gate: upload `terraform-plan.evidence.jsonl`, fail apply on deny, link result to `acgi-ai` trust/evidence console. |
| `hermes_acgs_bundle/` | Hermes/Codex/Claude-style agents can self-orchestrate procedures, but side effects need an external gate and traceability. | Middleware and observability bundle that gates/observes tool calls and cross-links ACGS evidence to Phoenix traces. | In-context procedure execution + external runtime governance: reasoning remains in model, authorization stays outside. | Python middleware, JSONL evidence writer, Phoenix 15.x, OTLP HTTP `:6006/v1/traces`, gRPC `:4317`, OpenTelemetry/OpenInference. | PreToolUse/Pre-command hook demo: fail-closed mode denies protected writes, emits ACGS event hash, attaches `acgs.event_hash` to Phoenix span. |
| `ca-legal-agent-skills/` / LegalGuard | Canadian legal AI outputs require citation discipline, privilege protection, matter isolation, confidence labels, and lawyer-review escalation. | Domain vertical with 38 deployable skills plus governed runtime for non-technical Canadian lawyers. | Domain-specific release gate: output is not released unless citation audit, matter isolation, and audit hash commit pass. | FastAPI runtime, Next.js web, matter gate, ACGS precheck, output auditor, hash-chained per-matter JSONL, optional CanLII metadata, multiple execution backends. | Connect legal runtime to `gove-zone` decision receipts; every matter run exports a legal-specific receipt with citation status and lawyer-review triggers. |
| ClinicalGuard / healthcare vertical | Clinical/healthcare agents touch PHI, safety-critical advice, and regulated professional boundaries. | Healthcare/privacy domain pack with PHI controls, clinical safety escalation, and auditable professional-review boundaries. | PHI-aware path policy: who accessed what patient-context data, why, and under which review obligation. | Python skills/runtime when initialized, privacy-hardening docs, future HIPAA/PHIPA/PIPEDA policy packs, ACGS receipts. | Clinical PHI redaction + release gate benchmark: deny cross-patient leakage, require clinician review for diagnosis/treatment recommendations. |
| `acgs-enterprise-ai-manager/frontend/` | Enterprises need admin CRUD surfaces, but generic admin UI is not the unique wedge. | Decide whether this remains legacy/admin adjunct or becomes internal ops console. | If retained, make it consume the same evidence API instead of building a parallel truth. | Vue 3, Vite, Vue Router, Pinia, Axios, JWT/localStorage currently. | Triage: either archive as non-core or refactor to read from agent-bus/evidence APIs; do not let it compete with `acgi-ai` buyer console. |

## 6. Breakthrough bets

### 6.1 Policies on Paths as the central abstraction

Target decision request:

```json
{
  "actor": {"id": "agent-legal-1", "role": "LegalOps", "tenant": "default"},
  "path": {
    "run_id": "...",
    "step_index": 12,
    "previous_event_hash": "sha256:...",
    "summary_hash": "sha256:..."
  },
  "action": {
    "tool": "contract.redline",
    "resource": "contracts/supplier-123",
    "argument_hash": "sha256:..."
  },
  "state": {
    "policy_version": "sha256:...",
    "risk_domain": "legal",
    "matter_id": "MATTER-123",
    "org_controls": ["human_review_required_for_settlement"]
  }
}
```

Decision output:

```json
{
  "decision": "ALLOW | DENY | TRANSFORM | ESCALATE",
  "reason_codes": ["POLICY-ID"],
  "policy_version": "sha256:...",
  "audit_hash": "sha256:...",
  "receipt_id": "..."
}
```

### 6.2 Tool calls as syscalls

Treat every external tool as a privileged operation:

```text
agent proposes -> host normalizes -> governance gate decides -> audit commits -> host executes or denies
```

The agent should not be able to call the side-effectful host function without passing through the gate. In pure Python/Hermes prototypes this is a hook discipline; in future Rust/WASM/MCP prototypes it should become an actual privilege boundary.

### 6.3 ProbeLogits / semantic safety sidecar

Use ProbeLogits as an experimental semantic risk score, not as the sole authority:

```text
schema check -> static policy -> path policy -> semantic risk score -> final deterministic decision -> audit
```

Acceptance metrics:

- latency overhead under an explicit p95 budget;
- attack success reduction on AgentDojo/InjecAgent/ToolEmu scenarios;
- false-positive rate on benign workflows;
- calibrated confidence buckets, not ungrounded “safe/unsafe” claims.

### 6.4 Evidence graph

Unify receipts, bus events, and traces:

```text
receipt_id
  -> audit event hash
  -> previous event hash / Merkle root
  -> bus dispatch/response events
  -> Phoenix trace_id/span_id
  -> console evidence packet
```

Phoenix traces can expire; ACGS chain evidence must remain authoritative.

### 6.5 Policy-to-tests compiler

Use P2T-style extraction to convert policy prose into:

- canonical rules;
- test fixtures;
- evidence requirements;
- human-review triggers;
- console explanation copy.

Start with high-value corpora:

1. `acgi-ai/DESIGN.md` and `DEPLOY.md` for frontend privilege/CSP/bus honesty rules.
2. `docs/PLAN-GOVE-ZONE-KERNEL.md` for kernel invariants.
3. EU AI Act / NIST / OWASP excerpts for external buyer taxonomy.
4. Canadian legal skill guardrails for vertical release gates.

## 7. Prototype roadmap

### P0: one-action proof path

Goal: one side-effectful action is governed end-to-end.

Build:

1. `gove-zone` receives a normalized hook/tool event.
2. Policy evaluates actor/path/action/state.
3. Audit append commits before execution.
4. Decision denies or allows.
5. Receipt is emitted.
6. `agent-bus-analyzer` can read the receipt and project a console model.
7. `acgi-ai` displays and exports the receipt.

Success metric:

```text
Given one attempted protected write, the system denies it, produces a hash-linked receipt, and the console can verify/export that receipt.
```

### P0: benchmark adapter spike

Goal: convert research into regression gates.

Build:

- AgentDojo/InjecAgent scenario adapter skeletons;
- ToolEmu-style synthetic high-stakes tool list;
- metrics JSON: `attack_success_rate`, `utility_success_rate`, `false_positive_rate`, `fail_closed_rate`, `p95_latency_ms`.

Success metric:

```text
A governance change cannot claim improvement without before/after benchmark output.
```

### P1: MCP syscall gateway

Goal: prove `gove-zone` can wrap MCP-style tool calls.

Build:

- JSON-RPC/MCP schema validation;
- trust tier and rate limit stubs;
- policy decision through `gove-zone`;
- optional semantic sidecar;
- chain-hash audit.

Success metric:

```text
All MCP tool calls route through one mediated path; direct bypass is detectable in tests.
```

### P1: ProbeLogits sidecar

Goal: assess if semantic token-logit classification improves action gating.

Build:

- local small-model prototype that reads class-token logits for `Safe`, `Risky`, `Forbidden`, `Escalate`;
- no generated text in the hot path;
- calibration dataset from AgentDojo/InjecAgent/ToolEmu fixtures;
- compare against LLM-judge and regex/static policy baselines.

Success metric:

```text
Semantic layer improves detection without unacceptable latency or false-positive rate; otherwise keep it as research-only.
```

### P1: CFT evidence gate

Goal: domain proof for infrastructure buyers.

Build:

- GitHub Actions example around Terraform plan JSON;
- ACGS evidence artifact upload;
- console import path for Terraform evidence.

Success metric:

```text
A denied public-ingress or broad-IAM plan exits non-zero and produces an auditor-readable evidence bundle.
```

### P2: vertical legal/clinical release gates

Goal: prove domain value beyond generic runtime governance.

Build:

- Legal: matter isolation + citation verification + lawyer-review triggers as receipt fields.
- Clinical: PHI redaction + patient-context isolation + clinician-review triggers.

Success metric:

```text
A domain-specific output cannot reach RELEASED without committed audit hash and domain release gate success.
```

## 8. Target stack

### Runtime/governance

- Python 3.11+ for new workspace packages.
- Preserve `acgs-lite` Python `>=3.10` public floor.
- Pydantic v2 for schemas where useful; stdlib-only hot path where possible.
- SHA-256 canonical JSON hashes for portable receipts; consider BLAKE3 for performance only if cross-language compatibility is planned.
- JSONL append-only audit for MVP; SQLite/Postgres event store for multi-tenant service layer.
- Optional Rust/PyO3 or Rust/WASM sidecar for canonical hashing, policy eval, and future privilege-boundary experiments.

### Agent/tool interfaces

- MCP / JSON-RPC as first-class tool-call surface.
- Hermes/Codex/Claude Code hooks as practical early host integrations.
- LangGraph adapter through `Acgs-Swarm`, not in the kernel.
- OpenTelemetry/OpenInference spans as adjunct observability.

### Frontend/product

- `acgi-ai`: Node 24, pnpm 9.15, React 19, Vite, Tailwind 4, TanStack Router/Query, Biome, strict CSP.
- Console origin must remain privileged: no third-party scripts/fonts, no public-only shortcuts, fail-closed bus behavior in production.
- OpenAPI-generated types from `agent-bus-analyzer`/bus contracts.

### Policy/evaluation

- P2T-style JSON policy DSL for extracted obligations.
- OPA/Rego and/or Cedar are worth testing for infrastructure/IAM policies; keep kernel policy interface engine-agnostic.
- AgentDojo, InjecAgent, ToolEmu-inspired fixtures for safety regression.
- NIST/EU/OWASP crosswalk for reporting labels, not as unsupported compliance certification.

## 9. Measurement plan

| Metric | Why it matters |
|---|---|
| Evidence coverage | Percent of side-effectful tool calls with committed receipt before execution. Target: 100%. |
| Fail-closed rate | Percent of policy/audit/eval exceptions that deny/escalate instead of allow. Target: 100%. |
| Replay determinism | Percent of stored receipts that replay to the same decision under same policy version. Target: 100%. |
| Attack success rate | Benchmark-specific attack success before/after ACGS. Target: material reduction without hiding utility loss. |
| Utility success rate | Governance must not block all useful work. Track benign task completion. |
| False-positive rate | Buyer trust dies if safe actions are blocked unpredictably. |
| p95 gate latency | Governance must fit interactive/tool-loop workflows. |
| Evidence export time | Buyer proof journey should complete quickly: find receipt -> verify -> export. |
| Console bus honesty | Production must not silently render fixtures when upstream is absent. |

## 10. Key risks and mitigations

| Risk | Mitigation |
|---|---|
| Prompt-only governance sneaks back in | Require dispatcher-level tests proving tool calls cannot execute without gate/audit path. |
| User-space hook bypass | Treat hooks as MVP only; MCP gateway/Rust-WASM sidecar should progressively harden boundary. |
| Overclaiming compliance | Use “maps to” and “evidence supports,” not “certifies.” Legal review for public claims. |
| Audit contains secrets/PHI | Store hashes/fingerprints, not raw tool inputs; domain-specific redaction policies. |
| Semantic classifier uncalibrated | Keep ProbeLogits optional until benchmarked; deterministic policy remains final authority. |
| Utility collapse | Always report utility success alongside attack reduction. |
| Submodule/public API breakage | Respect submodule boundaries; do not break `acgs-lite` PyPI API or Python `>=3.10` floor. |
| Console evidence becomes theater | Console must verify hash chain and policy version; no unsupported fixture claims in production. |

## 11. Recommended execution order

1. Finish `gove-zone` one-action proof path and dispatcher-level fail-closed tests.
2. Add benchmark adapter skeletons to `acgs_governance_eval_mvp`.
3. Wire `agent-bus-analyzer` receipt projection and `acgi-ai` receipt proof page.
4. Build MCP syscall gateway spike.
5. Add ProbeLogits semantic sidecar only after baseline eval metrics exist.
6. Convert CFT pack into first infrastructure domain proof.
7. Integrate LegalGuard/ClinicalGuard release gates as vertical proof packs.
8. Produce buyer-facing claim matrix: every public claim must link to a source event, policy version, receipt, or explicitly stubbed artifact.

## 12. Source appendix

### Research

- Runtime Governance for AI Agents: Policies on Paths, arXiv:2603.16586 — https://arxiv.org/abs/2603.16586
- ProbeLogits: Kernel-Level LLM Inference Primitives for AI-Native Operating Systems, arXiv:2604.11943 — https://arxiv.org/html/2604.11943
- Governed MCP: Kernel-Level Tool Governance for AI Agents via Logit-Based Safety Primitives, arXiv:2604.16870 — https://arxiv.org/html/2604.16870v1
- AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents, arXiv:2406.13352 — https://arxiv.org/abs/2406.13352
- Identifying the Risks of LM Agents with an LM-Emulated Sandbox / ToolEmu, arXiv:2309.15817 — https://arxiv.org/abs/2309.15817
- InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated LLM Agents, arXiv:2403.02691 — https://arxiv.org/abs/2403.02691
- The Emerged Security and Privacy of LLM Agent: A Survey with Case Studies, arXiv:2407.19354 — https://arxiv.org/abs/2407.19354
- Executable Governance for AI: Translating Policies into Rules Using LLMs, arXiv:2512.04408 — https://arxiv.org/html/2512.04408v1
- Policy-as-Prompt: Turning AI Governance Rules into Guardrails for AI Agents, arXiv:2509.23994 — https://arxiv.org/html/2509.23994v2
- Governance-as-a-Service: A Multi-Agent Framework for AI System Compliance and Policy Enforcement, arXiv:2508.18765 — https://arxiv.org/html/2508.18765v2

### Market/regulatory/security

- Gartner: Over 40% of Agentic AI Projects Will Be Canceled by End of 2027 — https://www.gartner.com/en/newsroom/press-releases/2025-06-25-gartner-predicts-over-40-percent-of-agentic-ai-projects-will-be-canceled-by-end-of-2027
- MarketsandMarkets AI Governance Market Report 2024-2029 — https://www.marketsandmarkets.com/Market-Reports/ai-governance-market-176187291.html
- Grand View Research AI Governance Market — https://www.grandviewresearch.com/industry-analysis/ai-governance-market-report
- NIST AI Risk Management Framework — https://www.nist.gov/itl/ai-risk-management-framework
- NIST AI RMF Generative AI Profile, NIST.AI.600-1 — https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence
- EU AI Act official European Commission page — https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai
- OWASP Top 10 for Agentic Applications 2026 — https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- OWASP Top 10 for Large Language Model Applications / GenAI Security Project — https://owasp.org/www-project-top-10-for-large-language-model-applications/

### Local repository sources inspected

- `MONOREPO.md`
- `pyproject.toml`
- `docs/PLAN-GOVE-ZONE-KERNEL.md`
- `docs/design/acgs-governed-hermes-in-context-runtime-governance.md`
- `packages/gove-zone/README.md`
- `packages/gove-zone/pyproject.toml`
- `packages/acgs-lite/README.md`
- `packages/acgs-lite/pyproject.toml`
- `packages/Acgs-Swarm/README.md`
- `packages/Acgs-Swarm/pyproject.toml`
- `packages/agent-bus-analyzer/README.md`
- `packages/agent-bus-analyzer/pyproject.toml`
- `acgi-ai/PLAN.md`
- `acgi-ai/package.json`
- `acgs_governance_eval_mvp/README.md`
- `acgs-cft-governance-pack/README.md`
- `hermes_acgs_bundle/phoenix/README.md`
- `ca-legal-agent-skills/README.md`
- `acgs-enterprise-ai-manager/frontend/README.md`
