# Platform UI/UX research — visualized workbench

Date: 2026-05-25
Status: research-backed product blueprint, not deployment proof or certification.

## Source-backed capabilities a leading AI-governance platform should expose

1. **Governance workflow, not a claims page.** NIST AI RMF frames AI risk management as an operating loop: govern, map, measure, and manage. Its 2026 critical-infrastructure profile concept note also reinforces that operators need practical risk-management practices for AI-enabled capabilities. The product UI should turn that loop into visible work: intake, risk context, measurement/evaluation, mitigation, and evidence export.
2. **Agent security controls in the operator path.** OWASP GenAI guidance names prompt injection, sensitive disclosure, excessive agency, overreliance, and related LLM risks. The platform should show least-agency scope, guardrail state, refusal reason, and human-review requirements before an action proceeds.
3. **Trace-first observability.** OpenAI Agents SDK, LangSmith, and Phoenix all treat traces/spans as core objects for inspecting LLM calls, tool calls, handoffs, guardrails, retrieval, and custom logic. The UI should visualize a run path rather than bury execution inside raw logs.
4. **Evaluation and monitoring beside the trace.** LangSmith, Phoenix, and Humanloop document evaluation workflows, online monitoring, offline regression tests, code/AI/human evaluators, annotations, dashboards, and alerts. A leading platform should let teams compare versions and investigate failures without leaving the governed case.
5. **Human release with enough context to reject.** Human-in-the-loop should not be a signature checkbox. The reviewer needs source context, trace evidence, eval deltas, policy citations, and authority status in one release view.
6. **Exportable evidence and claim boundaries.** GovernZone should keep its differentiator: receipts, hashes, replay references, policy/model/prompt snapshots, and explicit claim boundaries that can leave the product without overstating live assurance.
7. **Operator quick-start path.** The interface should not force new users to infer the operating model from dense tables. It should expose three plain actions in the same visual workbench: Start here, Hold release, and Export proof.
8. **Operator decision rail.** A first-time reviewer should not have to decide from a full dashboard. The workbench should present a short plain-language rail: Pick the case, Inspect the path, and Decide and export. Each step needs a visible proof label so the visual path is still useful without color.
9. **Launch proof ladder.** Deployment readiness should be visible as a plain path: Local readiness, Live verifier, and Assurance packet. Operators should not have to read a generated manifest to know which proof is still local and which external blocker remains.
10. **Simple service path.** GOV.UK service-design guidance emphasizes user needs, simple first-time success, and a clear outcome. GovernZone should therefore make the next safe action visible before dense evidence tables, and should keep blocked/pending states actionable rather than decorative.
11. **Accessible visual proof.** WCAG 2.2 keeps keyboard focus, input assistance, and accessible authentication in the product-quality frame. Visualized governance work must not rely on color alone; every status, proof step, and blocked action needs text labels that survive keyboard and assistive-technology review.

## UI/UX direction for this repo

- Use the existing editorial constitutional UI: warm paper, black rules, mono labels, rust only for emphasis and controlled path markers.
- Add a public workbench blueprint to the marketing surface so buyers see how work becomes inspectable.
- Keep the console direction simple: one queue, one visual trace, one evaluation panel, one release gate, one evidence room.
- Add a same-style quick-start checklist so a first-time operator can choose the next safe action, know when to hold release, and export bounded proof without leaving the workbench.
- Add an operator decision rail in the same UI so the first scan answers: Pick the case, Inspect the path, and Decide and export.
- Add a launch proof ladder in the same workbench so local readiness, live deployment verification, and external assurance blockers are visible without changing UI systems.
- Make visual work text-first and keyboard-reviewable: every workbench stage, proof ladder rung, and hold/release decision needs a readable label before any color, icon, or layout cue.
- Avoid new dependencies, icon systems, dashboard colors, heavy animation, or generic SaaS gradients.
- Phrase everything as a target product blueprint until live deployment proof, legal review, SOC 2 evidence, WCAG manual evidence, and penetration-test evidence are attached.

## Sources reviewed

- NIST AI Risk Management Framework: https://www.nist.gov/itl/ai-risk-management-framework
- OWASP Top 10 for Large Language Model Applications / GenAI Security Project: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- OpenAI Agents SDK tracing: https://openai.github.io/openai-agents-python/tracing/
- OpenAI Agents SDK guardrails: https://openai.github.io/openai-agents-js/guides/guardrails/
- LangSmith observability: https://docs.langchain.com/langsmith/observability
- Arize Phoenix overview: https://arize.com/docs/phoenix
- Humanloop evaluators: https://humanloop.com/docs/evaluation/overview
- GOV.UK Service Manual — user needs and simple services: https://www.gov.uk/service-manual/user-centred-design/user-needs/ and https://www.gov.uk/service-manual/service-standard/point-4-make-the-service-simple-to-use
- W3C WAI — WCAG 2.2 updates: https://www.w3.org/WAI/standards-guidelines/wcag/new-in-22/
