# Platform UI/UX research — visualized workbench

Date: 2026-05-25
Status: research-backed product blueprint, not deployment proof or certification.

## Source-backed capabilities a leading AI-governance platform should expose

1. **Governance workflow, not a claims page.** NIST AI RMF frames AI risk management as an operating loop: govern, map, measure, and manage. ISO/IEC 42001 adds the management-system shape: ownership, objectives, controls, monitoring, review, and continual improvement. The product UI should turn that loop into visible work: intake, risk context, measurement/evaluation, mitigation, and evidence export.
2. **Agent security controls in the operator path.** OWASP GenAI guidance names prompt injection, sensitive disclosure, excessive agency, overreliance, and related LLM risks. The platform should show least-agency scope, guardrail state, refusal reason, and human-review requirements before an action proceeds.
3. **Trace-first observability.** OpenTelemetry documents vendor-neutral traces, metrics, and logs, plus generative-AI semantic conventions. OpenAI Agents SDK, LangSmith, and Phoenix all treat traces/spans as core objects for inspecting LLM calls, tool calls, handoffs, guardrails, retrieval, and custom logic. The UI should visualize a run path rather than bury execution inside raw logs.
4. **Evaluation and monitoring beside the trace.** LangSmith, Phoenix, and Humanloop document evaluation workflows, online monitoring, offline regression tests, code/AI/human evaluators, annotations, dashboards, and alerts. A leading platform should let teams compare versions and investigate failures without leaving the governed case.
5. **Human release with enough context to reject.** Human-in-the-loop should not be a signature checkbox. The EU AI Act orientation material highlights risk management, data quality, documentation/traceability, transparency, human oversight, accuracy, cybersecurity, and robustness for high-risk systems. The reviewer needs source context, trace evidence, eval deltas, policy citations, authority status, and current blocker state in one release view.
6. **Exportable evidence and claim boundaries.** GovernZone should keep its differentiator: receipts, hashes, replay references, policy/model/prompt snapshots, and explicit claim boundaries that can leave the product without overstating live assurance.
7. **Operator quick-start path.** The interface should not force new users to infer the operating model from dense tables. It should expose three plain actions in the same visual workbench: Start here, Hold release, and Export proof.
8. **Operator decision rail.** A first-time reviewer should not have to decide from a full dashboard. The workbench should present a short plain-language rail: Pick the case, Inspect the path, and Decide and export. Each step needs a visible proof label so the visual path is still useful without color.
9. **Guided review path.** The first minute of use should be visible before dense tables: Choose the case, Follow the path, Check the hold, and Export bounded proof. This makes the product easy to use without hiding the trace, evidence, authority, or claim boundary.
10. **Launch proof ladder.** Deployment readiness should be visible as a plain path: Local readiness, Live verifier, and Assurance packet. Operators should not have to read a generated manifest to know which proof is still local and which external blocker remains.
11. **Simple service path.** GOV.UK service-design guidance emphasizes user needs, simple first-time success, and a clear outcome. GovernZone should therefore make the next safe action visible before dense evidence tables, and should keep blocked/pending states actionable rather than decorative.
12. **Accessible visual proof.** WCAG 2.2 keeps keyboard focus, input assistance, and accessible authentication in the product-quality frame. Visualized governance work must not rely on color alone; every status, proof step, and blocked action needs text labels that survive keyboard and assistive-technology review.
13. **Platform requirements rail.** The workbench should translate research into six plain visual lanes: Govern, Regulate, Secure, Observe, Measure, and Use. Each lane needs a framework cue, a control question, a proof label, and a same-console route so research is actionable instead of a static memo.
14. **Framework integration rail.** Agent-framework adoption should be visible before developers wire side effects. The UI should show OpenAI Responses, OpenAI Chat, LangChain-style, MCP-style, and Claude/Codex-style payloads entering a Normalize → Gate → Receipt → Adopt path, including malformed batch denial, while keeping local adapter proof separate from live third-party framework deployment proof.
15. **Current saved cutover state.** Production blockers should be visible in the same workbench instead of hidden in generated JSON. The UI should show Marketing origin, Console origin, Storybook proof, and Evidence validation lanes with the saved verifier state, proof names, next route, and `safeToClaimProduction=false` boundary.
16. **Live verifier blocker map.** Failed live checks should be visible as work, not just terminal output. The UI should show live-console-dns, live-storybook-dns, live-console-healthz, live-console-security-headers, live-storybook-https, and live-storybook-manifest blocker ids with the proof check and next operator route.
17. **Release blocker queue.** External blockers should look like work items, not a paragraph in a preflight report. The UI should show production-deployment, frontend-production-auth, legal-review-of-claim-matrix, third-party-penetration-test, full-wcag-manual-screen-reader-evidence, and hosted-storybook-buyer-evidence with owner, artifact, and unblock-command labels.
18. **Production command rail.** Deploy operators should not have to reconstruct proof commands from docs. The UI should show make production-blocker-evidence, verify:production-live, validate:production-evidence, and validate:hosted-storybook-proof with the artifact each command produces.
19. **Assurance proof intake.** External proof should have an operator-facing intake map before launch. The UI should show Production authority, Legal claim review, Security assessment, Manual accessibility, and Hosted buyer evidence lanes with the required template or assurance field and an explicit reminder that placeholders are not proof.
20. **Agent framework starter kits.** Developer adoption should begin with a visible payload shape and a local proof command, not a vague SDK promise. The UI should show OpenAI Responses starter, LangChain tool-call starter, MCP / Claude / Codex hook starter, and Benchmark fixture starter cards with `gove-zone gate`, `gove-zone setup`, or `gove-zone eval` commands, proof labels, and next routes while keeping the boundary clear that local adapter proof is not live framework deployment proof.
21. **Hosted Storybook runway.** Hosted buyer-evidence should have a visible publish sequence before anyone removes the blocker. The UI should show Build local gallery, Enable Pages deploy, Verify live Storybook, and Attach hosted proof with the `storybook:build`, `STORYBOOK_PAGES_ENABLED=true`, `storybook-manifest-live`, and `copyIntoProductionEvidence.hostedStorybook` labels while keeping the boundary clear that local runway guidance is not hosted proof.

## UI/UX direction for this repo

- Use the existing editorial constitutional UI: warm paper, black rules, mono labels, rust only for emphasis and controlled path markers.
- Add a public workbench blueprint to the marketing surface so buyers see how work becomes inspectable.
- Keep the console direction simple: one queue, one visual trace, one evaluation panel, one release gate, one evidence room.
- Add a same-style quick-start checklist so a first-time operator can choose the next safe action, know when to hold release, and export bounded proof without leaving the workbench.
- Add a platform requirements rail in the same UI so users can scan: **Govern → Regulate → Secure → Observe → Measure → Use** before entering dense evidence. Each card should answer "what must this platform make easy?" with a text proof label.
- Add a framework integration rail in the same UI so agent-framework adoption is visible as **Normalize → Gate → Receipt → Adopt** before a tool side effect runs. The rail should name OpenAI Responses, OpenAI Chat, LangChain-style, MCP-style, and Claude/Codex-style payloads without claiming live framework deployment proof.
- Add agent framework starter kits in the same UI so developer adoption is visible as **Pick payload → run gate → attach receipt**. The cards should cover OpenAI Responses starter, LangChain tool-call starter, MCP / Claude / Codex hook starter, and Benchmark fixture starter without claiming live framework deployment proof.
- Add a guided review path in the same UI so a first-time operator can follow: Choose the case, Follow the path, Check the hold, and Export bounded proof.
- Add an operator decision rail in the same UI so the first scan answers: Pick the case, Inspect the path, and Decide and export.
- Add a launch proof ladder in the same workbench so local readiness, live deployment verification, and external assurance blockers are visible without changing UI systems.
- Add a current saved cutover state panel under the launch proof ladder so marketing `already-live`, console `dns-or-service-blocked`, Storybook `dns-or-pages-blocked`, and evidence `waiting-for-live-checks` states are actionable without opening a manifest.
- Add a release blocker queue under the launch proof ladder so `production-deployment`, `frontend-production-auth`, `legal-review-of-claim-matrix`, `third-party-penetration-test`, `full-wcag-manual-screen-reader-evidence`, and `hosted-storybook-buyer-evidence` are visible with owner, artifact, and unblock-command labels before anyone claims launch readiness.
- Add a live verifier blocker map under the same launch proof ladder so `live-console-dns`, `live-storybook-dns`, `live-console-healthz`, `live-console-security-headers`, `live-storybook-https`, and `live-storybook-manifest` are visible as deploy actions before anyone claims launch readiness.
- Add a production command rail under the same launch proof ladder so `make production-blocker-evidence`, `verify:production-live`, `validate:production-evidence`, and `validate:hosted-storybook-proof` are visible with their output artifacts before operators attach external proof.
- Add a hosted Storybook runway under the same launch proof ladder so the buyer-evidence path is visible as **Build local gallery → Enable Pages deploy → Verify live Storybook → Attach hosted proof** before `hosted-storybook-buyer-evidence` can be cleared.
- Add an assurance proof intake panel under the same launch proof ladder so Production authority, Legal claim review, Security assessment, Manual accessibility, and Hosted buyer evidence blockers have visible proof fields before anyone claims launch readiness.
- Make visual work text-first and keyboard-reviewable: every workbench stage, proof ladder rung, and hold/release decision needs a readable label before any color, icon, or layout cue.
- Avoid new dependencies, icon systems, dashboard colors, heavy animation, or generic SaaS gradients.
- Phrase everything as a target product blueprint until live deployment proof, legal review, SOC 2 evidence, WCAG manual evidence, and penetration-test evidence are attached.

## Sources reviewed

- NIST AI Risk Management Framework: https://www.nist.gov/itl/ai-risk-management-framework
- ISO/IEC 42001 AI management systems: https://www.iso.org/standard/42001
- European Commission — Navigating the AI Act: https://digital-strategy.ec.europa.eu/en/faqs/navigating-ai-act
- OWASP Top 10 for Large Language Model Applications / GenAI Security Project: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- OpenTelemetry documentation and generative AI semantic conventions: https://opentelemetry.io/docs/ and https://opentelemetry.io/docs/specs/semconv/gen-ai/
- OpenAI Agents SDK tracing: https://openai.github.io/openai-agents-python/tracing/
- OpenAI Agents SDK guardrails: https://openai.github.io/openai-agents-js/guides/guardrails/
- LangSmith observability: https://docs.langchain.com/langsmith/observability
- Arize Phoenix overview: https://arize.com/docs/phoenix
- Humanloop evaluators: https://humanloop.com/docs/evaluation/overview
- GOV.UK Service Manual — user needs and simple services: https://www.gov.uk/service-manual/user-centred-design/user-needs/ and https://www.gov.uk/service-manual/service-standard/point-4-make-the-service-simple-to-use
- Nielsen Norman Group — 10 usability heuristics / visibility of system status: https://www.nngroup.com/articles/ten-usability-heuristics/
- W3C WAI — WCAG 2.2 overview and updates: https://www.w3.org/WAI/standards-guidelines/wcag/ and https://www.w3.org/WAI/standards-guidelines/wcag/new-in-22/
- Storybook visual testing: https://storybook.js.org/docs/writing-tests/visual-testing/
