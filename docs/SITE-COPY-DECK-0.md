# ACGS origin copy deck v0 (acgs.ai)

Date: 2026-09-01 (Asia/Shanghai)
Author: 幕僚长
Status: internal copy deck for a designer. Not a live site change. Not a quote. Not a SKU change. Not a release. Not a certification.
Checked live: 2026-09-01. Public origin is https://acgs.ai/. Do not use acgs.dev or gove-zone.vercel.app as public copy.

This deck is bilingual. English and Chinese on a given page must make the same claim. If one language would be stronger, cut it from both.

Nav (keep short): Home · How it works · What it is not · Evidence · Status · Docs
Every page: a visible link Claims & Evidence → /evidence.

Out of scope (do not add): blog, pricing, logos, demo video, newsletter.

## 0. What is actually live today (so the rewrite does not invent a before)

| Surface | Observed 2026-09-01 | Implication |
|---|---|---|
| https://acgs.ai/ | Self-governance prompt for agents. Not an SDK page. Not a console. | Hero today does not say 1.1M RPS / nine frameworks / production-ready. |
| https://acgs.ai/governance-framework.txt | Protocol + five mapping domains (GDPR, HIPAA/PHIPA, SOC 2, PCI DSS, EU AI Act), each labeled obligations to consider, not legal advice, not attestation. | Keep this honesty. Do not upgrade it to "covers." |
| https://acgs.ai/docs | 404 | Docs page must say the docs site is not deployed. Deep-link GitHub trees. |
| https://acgs.dev/ | 402 DEPLOYMENT_DISABLED | Not a public origin. Do not link. |
| PyPI gove-zone | 1.0.0rc2 (2026-08-23), classifier Beta, Apache-2.0. https://pypi.org/project/gove-zone/ | Public kernel contract is rc2 Beta, not rc3. |
| GitHub acgs-ai/gove-zone | README invariant matches this deck. Source metadata may mention untagged rc3. | Site must pin published version, not source metadata. |
| PyPI acgs-lite | 2.12.0 (2026-08-15). README: "No independently confirmed production users yet." https://pypi.org/project/acgs-lite/ | Membrane, not the kernel gate. |
| Zenodo record titled ACGS-2: A Production-Ready Constitutional AI Governance System | Search snippet: >1,250 RPS, 847 constitutional test cases, P99 3.2 ms, 99.99% uptime. https://doi.org/10.5281/zenodo.16416793 | Do not republish. Mapping ≠ attestation. |
| dislovelhl/governance-mcp README | 6,471 RPS; 18,582 tests; 18 frameworks. https://github.com/dislovelhl/governance-mcp | Do not republish on acgs.ai without a public harness + hardware + raw output. |
| Phrase "1.1M RPS" | Not found on live acgs.ai or in current team notes. | Treat as not publicly reported. Do not restore. |

The trust liability is not only the homepage. It is the family of older artifacts (Zenodo title, MCP README, lite README "20 frameworks" + dead /docs links) sitting next to a kernel that disclaims certification.

## 1. Home

### Status strip (above the fold, always visible)

EN: Published kernel: gove-zone 1.0.0rc2 Beta. Membrane: acgs-lite 2.12.0. Console and control plane are not offered as a gate. See Status.

ZH: 已上架内核：gove-zone 1.0.0rc2 Beta。膜：acgs-lite 2.12.0。控制台与控制面不作为闸提供。见 Status.

### Hero

Typesetting source of truth (matches §9): ship line (2) as the hero; put line (1) immediately under it as the proof line; use line (3) as the diagram caption, not a second hero.

EN hero: No valid decision receipt, no side effect — on wired gove-zone paths only.

Proof line EN: On a path wired through gove-zone (the receipt-gated kernel: a library that decides, records, and checks a receipt before a tool runs), a tool call does not run unless a Decision Receipt (a machine-checkable record bound to this actor, this action, and these argument values) verifies. Check: from the kernel repo, `uv run python examples/receipt-gated-execution/demo.py` exits 0.

The governed executor fails closed without a valid receipt. It is not a sandbox, not an identity system, and not a certificate.

ZH hero: 没有有效判定收据，就没有副作用 — 仅限已接线的 gove-zone 路径。

Proof line ZH: 在已接到 gove-zone（收据闸内核：在工具跑之前做判定、留证、核收据的库）的路径上，除非 Decision Receipt（绑住本次行动者、本次动作、这组参数值的、可机器核对的记录）核验通过，工具调用不得执行。核对：内核仓根 `uv run python examples/receipt-gated-execution/demo.py` 退出码 0。

受治执行器在没有有效收据时失败即关。不是沙箱，不是身份系统，也不是证书。

### CTA (same in both languages, two links only)

- Prove it locally → GitHub README Prove the invariant locally (https://github.com/acgs-ai/gove-zone#readme)
- Claims & Evidence → /evidence

Do not add "Get started on acgs.ai/docs". That URL is 404.

### One diagram (designer: three boxes, one arrow of trust)

```text
gove-zone (kernel / 闸)
  receipt before tool
        ↑ optional bridge, experimental
acgs-lite (membrane / 膜)
  constitution check; not the kernel gate
        ↑ not a gate
console / control plane
  not offered as a gate on this site
```

Caption EN: ACGS is a family: a receipt-gated kernel, a constitutional membrane, and other layers we do not sell as gates. Only the kernel box is a gate, and only on paths you wire.
Caption ZH: ACGS 是一个家族：收据闸内核、宪法膜，以及我们不作为闸出售的其它层。只有内核箱是闸，且只在你接线的路径上。

Three lines under the diagram (not features):

- EN: The model may compute a call. The call remains a candidate until a receipt says it may run. / ZH: 模型可以算出一次调用。在收据说可以跑之前，那次调用仍是候选。
- EN: Fail closed (if the kernel cannot decide or cannot record evidence, the tool does not run). / ZH: 失败即关（内核无法判定或无法留证时，工具不得跑）。
- EN: Neighbors (content filters, authorization systems, hook contracts) are different scope. They are not this gate. / ZH: 邻居（内容过滤、授权系统、hook 契约）是不同范围。它们不是这道闸。

No RPS. No framework count. No "production-ready."

## 2. How it works

Title EN: How a side effect is gated
Title ZH: 副作用怎么被闸住

Intro EN: Four moments. The fourth is a stop, not a fourth kind of permission.
Intro ZH: 四个时刻。第四个是停下，不是第四种放行。

### Step 1 — Propose (提议)

EN: An agent (or a person) proposes a tool call: a name plus argument values. That proposal is not permission.
ZH: 智能体（或人）提出一次工具调用：名字加参数值。提议不是许可。

Example: `email.send` to alice@example.com, subject Q3, body hash ….

### Step 2 — Decide (判定)

EN: A policy (rules the kernel evaluates; not a human queue) returns one of four kernel verdicts. Only ALLOW and TRANSFORM can authorize a side effect:

- ALLOW — this call may run as proposed
- DENY — this call must not run
- TRANSFORM — a rewritten argument set may run; the original must not
- ESCALATE — a kernel verdict that does not authorize a side effect; the tool does not run

ZH: 策略（内核评估的规则；不是人工队列）给出四种内核判定之一。只有 ALLOW 和 TRANSFORM 能授权副作用：

- ALLOW — 可按所提参数执行
- DENY — 不得执行
- TRANSFORM — 只可执行改写后的参数；原文不得执行
- ESCALATE — 内核判定，但不授权副作用；工具不得跑

The kernel records the decision and issues a Decision Receipt. A missing, expired, mismatched, or unverifiable receipt is treated as DENY. For ESCALATE, the decision is recorded and execution is refused; its receipt is non-executable.

### Step 3 — Execute only with the receipt (有收据才执行)

EN: A governed executor (the code that is allowed to call the tool) checks the receipt against the call it is about to make. If they do not match, the tool does not run.
ZH: 受治执行器（被允许去调工具的那段代码）用即将发出的调用核对收据。对不上，工具不得跑。

Worked examples (same in both languages; labels only translated):

| Verdict | Call | What the executor does |
|---|---|---|
| ALLOW | crm.update_record Opportunity 006xx, amount 12000, currency USD | Runs the CRM write with those fields |
| DENY | payments.create_charge amount 50000 when policy max is 10000 | Does not call the payment API |
| TRANSFORM | email.send with an extra Bcc stripped by policy | Sends only the approved to / subject / body_hash |
| ESCALATE | Policy returns ESCALATE, or a human must decide | Fail closed. No tool call. Receipt and audit event exist; they do not authorize execution. |
| (stop) | Policy cannot decide, or audit write fails | Fail closed. No tool call. A human may be asked outside the kernel. That ask is not a receipt. |

### Step 4 — ESCALATE does not authorize a side effect (升级不授权副作用)

EN: ESCALATE is a kernel verdict. It is not a fourth kind of permission. The kernel records it and the executor refuses the tool (fail closed); any receipt for that decision is non-executable. A later human decision must arrive through a provider-authenticated, single-use approval event and trigger a fresh proposal, policy evaluation, and executable receipt. The ESCALATE receipt is never upgraded or reused — this library does not pretend to be an approval UI.

ZH: ESCALATE 是一种内核判定。它不是第四种放行。内核记录它，执行器拒绝工具（失败即关）；该判定的任何收据均不可执行。之后的人工作业必须通过提供方认证且仅可消费一次的批准事件，并触发新的提议、策略评估和可执行收据。ESCALATE 收据不得升级或复用；本库不假装成人审界面。

## 3. What it is not

Title EN: What this is not
Title ZH: 这不是什么

Intro EN: This page is the product. If you needed one of the things below, gove-zone is the wrong layer.
Intro ZH: 这一页就是产品。若你要的是下面其中一项，gove-zone 不是那一层。

| Not | Why (EN) | Why (ZH) |
|---|---|---|
| Not a sandbox | It does not contain a compromised host. | 它不把失陷宿主关进笼子。 |
| Not IAM / FGA | It does not answer "may this principal use this tool." It answers "may this call, with these arguments, run now." | 它不问「这个主体能不能用这工具」。它问「这一次调用、这组参数、现在能不能跑」。 |
| Not a content filter | It does not score whether text is toxic or on-brand. Guardrails are a different layer. | 它不给文本打毒性或品牌分。护栏是另一层。 |
| Not a compliance certificate | No SOC 2, HIPAA, GDPR, PCI, or EU AI Act attestation is claimed. Mapping documents and acgs assess reports are not certificates. | 不声称 SOC 2、HIPAA、GDPR、PCI 或欧盟 AI 法案获证。映射文档和 acgs assess 报告不是证书。 |
| Not a human-approval UI | There is no queue, no "click Allow," no console product on this origin. | 没有审批队列，没有「点允许」，本源站没有控制台产品。 |
| Not a Cursor / host lock | Unwired host tools are unwired. That is a boundary, not a failure. | 未接线的宿主工具就是未接线。这是边界，不是无能。 |
| Not OPA, not an MCP gateway, not Agent Hooks | Different scope: policy engine, identity front door, cooperative hook. None of those is a parameter-bound receipt on the execute path. | 不同范围：策略引擎、身份门口、合作 hook。都不是执行路径上绑参数的收据。 |

Footer EN: HTTP 202 from a bus is not approval. A green membrane check is not the kernel gate. A GitHub star count is not a user count.
Footer ZH: 总线上的 HTTP 202 不是批准。膜检查变绿不是内核闸。GitHub 星标不是用户数。

## 4. Evidence (Claims & Evidence)

Title EN: Claims & Evidence
Title ZH: 声称与证据

Intro EN: Every public sentence we are willing to keep. If a row's evidence is "none," the claim does not ship.
Intro ZH: 我们愿意保留的每一句公开话。若证据是「无」，这句不上线。

Link this page from every nav. This is the anti-hype contract.

| # | Claim (EN = ZH) | Evidence | Residual |
|---|---|---|---|
| C1 | No valid decision receipt, no side effect — on a path wired through gove-zone. / 没有有效判定收据，就没有副作用 — 仅限已接到 gove-zone 的路径。 | https://github.com/acgs-ai/gove-zone/blob/main/README.md ; https://github.com/acgs-ai/gove-zone/tree/main/examples/receipt-gated-execution | Unwired tools are not gated. Direct `DecisionReceipt.verify()` is not a complete execute boundary (in-repo security contract). |
| C2 | Public kernel package is gove-zone==1.0.0rc2, Beta, Apache-2.0, uploaded 2026-08-23. / 公开内核包是 gove-zone==1.0.0rc2，Beta，Apache-2.0，上传于 2026-08-23。 | https://pypi.org/project/gove-zone/ | Not a stable 1.0.0. Source trees may show other version strings; those are not the published contract. |
| C3 | The published kernel disclaims planning, HITL UI, full IAM/PKI, host containment, WORM storage, and regulatory certification. / 已上架内核声明不做规划、HITL UI、完整 IAM/PKI、宿主遏制、WORM、监管认证。 | https://pypi.org/project/gove-zone/ ; https://github.com/acgs-ai/gove-zone/blob/main/README.md | Disclaimers are not substitutes for independent audit. |
| C4 | acgs-lite 2.12.0 is a constitutional membrane (YAML + wrappers). It is not the kernel gate. / acgs-lite 2.12.0 是宪法膜（YAML + 包装）。不是内核闸。 | https://pypi.org/project/acgs-lite/ ; in-repo bridge marked Experimental | Membrane green ≠ Gate-2. |
| C5 | No independently confirmed production users are claimed. / 不声称已有独立证实的生产用户。 | https://github.com/acgs-ai/acgs-lite/blob/main/README.md | Absence of a claim is not evidence of absence of private use. We still do not state a customer count. |
| C6 | PyPI download counts exist and are not customer counts. Print day/week/month figures only after a fresh pypistats or pepy fetch. / PyPI 下载次数存在，且不是客户数。仅在重新从 pypistats 或 pepy 拉取后才打印日/周/月数字。 | pypistats.org or pepy.tech API (not PyPI project pages — PyPI JSON returns -1 for downloads) | Last observed 2026-09-01, **not re-verified** this session (pypistats timed out): gove-zone 0 / 24 / 152 ; acgs-lite 48 / 184 / 3926. Mirrors, CI, and retries inflate counts. Do not ship these numbers until re-fetched. Do not call them users. |
| C7 | GitHub star counts are not publicly used as a product claim. / GitHub 星标不作产品声称。 | none as marketing evidence | If asked: look at the repo page that day. Do not cache a number in copy. |
| C8 | Throughput numbers (1.1M RPS, 6,471 RPS, 1,250 RPS, P99 3.2 ms, 99.99% uptime) are not publicly reported on this origin. / 吞吐数字（1.1M RPS、6,471 RPS、1,250 RPS、P99 3.2 ms、99.99% 可用性）在本源站未公开报告。 | none on acgs.ai | Older Zenodo / MCP README figures stay off this site until a public harness, hardware description, and raw output exist. |
| C9 | Regulatory coverage: none certified. Live origin file lists five domains as obligations to consider (GDPR, HIPAA/PHIPA, SOC 2, PCI DSS, EU AI Act). lite acgs assess is a mapping CLI marked Beta in-repo, not an attestation. / 监管覆盖：无一获证。现源站文件列出五个域作为须考虑的义务（GDPR、HIPAA/PHIPA、SOC 2、PCI DSS、欧盟 AI 法案）。lite 的 acgs assess 是仓内标为 Beta 的映射 CLI，不是获证。 | https://acgs.ai/governance-framework.txt ; acgs-lite Component Stability (acgs assess Beta) | Mapping ≠ implemented control ≠ certificate. Do not say "covers nine" or "covers twenty." |
| C10 | Public docs site is not deployed (/docs = 404 as of 2026-09-01). / 公开文档站未部署。 | Fetch of https://acgs.ai/docs | Until it exists, Docs page links only GitHub paths. |
| C11 | Eval/embed of the kernel is discussable. A production SKU, SaaS seats, and air-gap delivery are targets, not facts. / 内核可谈评测/嵌入。生产 SKU、SaaS 席位、断网交付是目标，不是事实。 | internal planning only; nothing on origin today sells seats | Do not put pricing or a buy button on this pass. |

Rows C8 and C9 are the ones that used to leak trust. They stay as explicit non-claims.

## 5. Status

Title EN: Component status
Title ZH: 组件状态

Intro EN: Pins a buyer can check before integrating. Dates are upload or last public observation, not "production since."
Intro ZH: 买家接入前可核对的钉死信息。日期是上传或上次公开观察，不是「投产始于」。

| Component | Public pin | Maturity word we will print | Is it a gate? | Notes |
|---|---|---|---|---|
| gove-zone | PyPI 1.0.0rc2 2026-08-23, Beta | rc / Beta | Yes, on wired paths only | Untagged source labels (e.g. rc3 in a tree) are not the public pin. |
| acgs-lite | PyPI 2.12.0 2026-08-15 | published library | No | Membrane. In-repo table calls some adapters Stable; we still do not call the membrane a gate. |
| acgs_lite.gove bridge | extra gove, in-repo Experimental | experimental | No (adapter) | Distinct receipt format from lite legitimacy receipts. |
| MCP adapter (lite) | in-repo Beta | Beta | No | Transport hardening is the operator's. |
| LangGraph / LangChain wrapper (lite) | in-repo "Stable" for the thin wrapper | pattern / wrapper | No | Wrapper stability ≠ kernel gate. |
| Console (acgi-ai) | no public origin, no public repo | pattern-only | No | Not offered. |
| Control plane | no public sellable origin | not offered | No | Do not describe as ready. |
| Agent bus / swarm | family pieces | not offered as a gate | No | HTTP 202 ≠ approval. |

The word production does not appear in this table except as "not offered" / "no independently confirmed production users."

Footer: Last reviewed 2026-09-01. Replace this table from a status.json once that asset exists.

## 6. Docs entry

Title EN: Documentation
Title ZH: 文档

EN: The documentation site at /docs is not deployed (HTTP 404, checked 2026-09-01). Until it is, use the source trees. These are not marketing paraphrases.

ZH: /docs 文档站未部署（HTTP 404，2026-09-01 核对）。在部署之前，请用源码树。以下不是营销转写。

| Want | Link |
|---|---|
| Kernel invariant + local proof | https://github.com/acgs-ai/gove-zone/blob/main/README.md |
| Kernel architecture | https://github.com/acgs-ai/gove-zone/blob/main/ARCHITECTURE.md |
| Governed execution | https://github.com/acgs-ai/gove-zone/blob/main/docs/governed-execution.md |
| Decision receipts | https://github.com/acgs-ai/gove-zone/blob/main/docs/decision-receipts.md |
| Threat model | https://github.com/acgs-ai/gove-zone/blob/main/docs/threat-model.md |
| Membrane README | https://github.com/acgs-ai/acgs-lite/blob/main/README.md |
| Origin self-governance protocol | https://acgs.ai/governance-framework.txt |

Do not list https://acgs.ai/docs/quickstart (or any /docs/... child) until it returns 200.

## 7. Before / after (hero and top three claims)

### Hero

| | Before (do not ship) | After |
|---|---|---|
| EN | AI governance platform / production-ready constitutional system (Zenodo title and similar). Live homepage is actually an agent self-prompt, which is also not the kernel invariant. | No valid decision receipt, no side effect — on wired gove-zone paths only. |
| ZH | 「AI 治理平台 / 生产就绪」类句（Zenodo 标题及同类表述）。现首页实际是智能体自治理提示，也不是内核不变量。 | 没有有效判定收据，就没有副作用 — 仅限已接线的 gove-zone 路径。 |
| Removed | platform, future of compliance, production-ready | — |
| Replaced with | scoped invariant + proof link | — |

### Claim A — throughput

| | Before | After |
|---|---|---|
| Text | "1.1M RPS" (not on live origin; nearby artifacts: 1,250 RPS, 6,471 RPS) | Not publicly reported on this origin. |
| Removed | every RPS / P99 / uptime figure without a harness | — |
| Replaced with | Evidence row C8; Status does not show a speed number | — |

### Claim B — frameworks

| | Before | After |
|---|---|---|
| Text | "covers nine regulatory frameworks" (live file lists five mapping domains; lite README says 20 mapped via acgs assess) | None certified. Five domains listed as obligations to consider. Mapping CLI ≠ certificate. |
| Removed | covers, nine, twenty as a capability count | — |
| Replaced with | named list + "obligations to consider" + "none certified" in one unburied line | — |

### Claim C — production-ready

| | Before | After |
|---|---|---|
| Text | "production-ready" (Zenodo title; kernel README forbids it; lite: no independently confirmed production users) | Component matrix: kernel rc / Beta; membrane published library; console pattern-only. |
| Removed | production-ready, production-scale, enterprise-ready | — |
| Replaced with | version pins and maturity words that match PyPI classifiers | — |

## 8. Assets the project must produce

| Asset | Why the new copy needs it | Status |
|---|---|---|
| This copy deck | Designer input | exists (this file) |
| Claims & Evidence as /evidence HTML | Non-negotiable #3 | needs creation (no site rebuild in this pass) |
| status.json (component, version, date, maturity, gate: yes/no) | Status page without hand-editing | needs creation |
| Public docs site at /docs | Docs entry currently honest-404 | needs creation (and must not 404-link from badges) |
| Kernel smoke + receipt demo (in-repo) | Falsifiable hero | exists in acgs-ai/gove-zone |
| Signed proof-pack example | Evidence for C1 beyond smoke | exists in-repo (gove-zone-proofpack / examples); needs a public, version-pinned walkthrough once /docs exists |
| Public benchmark harness + hardware + raw JSON | Only way to ever print RPS | needs creation. Until then, do not print RPS. |
| Framework inventory JSON (name, artifact type: template / mapping / checklist / none, certified: no) | Replaces "covers N" | needs creation; seed from governance-framework.txt (five domains, certified: no) |
| Remove or relabel Zenodo "Production-Ready" title / MCP README RPS | Stops the contradiction leaking from off-origin pages | needs external service (Zenodo / GitHub README edits; not this deck) |
| Fix acgs-lite README links to acgs.ai/docs | Dead docs links re-create hype | needs creation (repo edit; out of this pass) |
| Stripe / seat / pricing page | — | not in this pass |
| Customer logos, download counts as users | — | do not create |

## 9. Three hero lines, ranked by falsifiability

1. **Most falsifiable.** EN: On a path wired through gove-zone, a tool call does not run unless a Decision Receipt bound to this actor, this action, and these argument values verifies. Check: from the kernel repo, `uv run python examples/receipt-gated-execution/demo.py` exits 0. / ZH: 在已接到 gove-zone 的路径上，除非绑住本次行动者、本次动作、这组参数的判定收据核验通过，工具调用不得执行。核对：内核仓根 `uv run python examples/receipt-gated-execution/demo.py` 退出码 0。
   Why first: a stranger can run the command. If the demo fails, the hero is false. Smoke (`uv run gove-zone smoke`) is a shorter allow/deny/audit check; it does not by itself prove argument binding.

2. **Invariant, scoped.** EN: No valid decision receipt, no side effect — on wired gove-zone paths only. / ZH: 没有有效判定收据，就没有副作用 — 仅限已接线的 gove-zone 路径。
   Why second: one sentence, still scoped. Less immediately runnable than (1).

3. **Family, still honest.** EN: ACGS is a family: a receipt-gated kernel, a constitutional membrane, and other layers we do not sell as gates. / ZH: ACGS 是一个家族：收据闸内核、宪法膜，以及我们不作为闸出售的其它层。
   Why third: true, but a skeptic cannot falsify it with one command. Use as a subhead, not the hero.

Ship (2) in the hero. Put (1) immediately under it as the proof line. Keep (3) for the diagram caption.

## 10. Designer notes (not copy)

- Type: quiet. No gradient orbs, no shield icons that look like a certificate.
- Claims & Evidence is a first-class nav item, not a footer footnote.
- Do not render a live RPS counter, a framework pie, or a "trusted by" row.
- If a CMS field is empty, print "not publicly reported" rather than hiding the row.
- Do not bind this copy to acgs.dev. Origin is acgs.ai.
- Shipping this copy onto the live origin is a separate change (site deploy). This file is not that change.

---

## Verification 2026-09-01 (read-only audit)

Auditor: Cursor agent (plan execution). Method: PyPI JSON API, live fetches of acgs.ai, grep of monorepo and gove-zone standalone repo, Zenodo record page.

### Per-claim results

| Row | Verdict | Notes |
|---|---|---|
| C1 | **Verified** | Stable README invariant and `examples/receipt-gated-execution/demo.py` symbols/paths match. Smoke is a shorter allow/deny/audit check and was not re-run this session. |
| C2 | **Verified** | PyPI JSON: version 1.0.0rc2, upload 2026-08-23, Beta classifier. Monorepo nested `packages/gove-zone/pyproject.toml` shows 0.1.0.dev0 Alpha — confirms "pin PyPI not source." |
| C3 | **Verified** | PyPI README "It does not provide" list matches deck. |
| C4 | **Verified** | acgs-lite 2.12.0 on PyPI; gove bridge marked Experimental in published README. |
| C5 | **Verified** | acgs-lite README "No independently confirmed production users yet." |
| C6 | **Partial — do not ship numbers** | Attribution is pypistats/pepy, not PyPI pages. Specific counts remain in Residual only until re-fetched. |
| C7 | **Verified** | No star-count claim in deck copy. |
| C8 | **Verified** | acgs.ai has no RPS figures. Zenodo record fetched successfully (title "Production-Ready", >1,250 RPS, P99 3.2 ms, 99.99% uptime, 847 tests). governance-mcp README not fetched (timeout). |
| C9 | **Verified** | governance-framework.txt lists five domains with "obligations to consider" and explicit claim boundary. acgs-lite Component Stability marks `acgs assess` as Beta. |
| C10 | **Verified** | https://acgs.ai/docs returns 404. |
| C11 | **Caveat** | "SKU-0 (internal)" not found in monorepo grep. Deck row updated to "internal planning only." |

### New findings (outside original deck)

| ID | Finding | Action for site/copy |
|---|---|---|
| N1 | Published acgs-lite 2.12.0 README still says gove-zone "not yet published to PyPI" | Fix in acgs-lite nested repo (separate PR). Do not echo on acgs.ai. |
| N2 | dislovelhl/governance-mcp README RPS / test / framework counts were not re-fetched this session (timeout) | Keep off acgs.ai until a public harness + hardware + raw output exist. |
| N3 | Published gove-zone README has broken sentence "The project website is." and "while this repository remains private" | Fix in gove-zone repo README (separate PR). |
| N4 | acgs-lite README footer links commercial licenses to acgs.ai (no commercial page on origin) | Remove or relabel in lite README. |
| N5 | Monorepo nested acgs-lite submodule at 2.11.0; PyPI at 2.12.0 | Status page must pin PyPI; monorepo pointer drift is expected. |

### Codex work location (resolved)

- Standalone repo: `/home/martin/Documents/gove-zone`
- Branch: `feat/embed-l2c-slices` @ `e74e32ddf1e6685118d279d8bb2727760f251f6e` (parent `31e989ca`; `codex/rc3-source-candidate` was the pre-demo tip)
- `origin/main` @ `448a079e`
- Five-tool stub demo: `examples/l2c-embed-slices/demo.py` — `uv run python examples/l2c-embed-slices/demo.py` exit 0 verified this pass. Not pushed. Not merged.
