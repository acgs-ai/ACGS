> **Internal engineering document.** Not part of the public release artifact.

# Governance Hub — CTA Verification Report

> **Two scopes in this report.** The main body tests the **live URL** the CTA points agents at (`https://acgs.ai`). **Addendum A** (appended at the end) re-tests **C2–C5 against the source on branch `feat/marketing-governance-hub` @ `5129fab`**, where the interview is actually implemented. The combined bottom line is at the very end.

**Target (HUB_URL):** `https://acgs.ai`
**POST_CLAIM under test (verbatim):**
> "Point your agent at the URL — there's a guided interview that maps your current work to a governance setup. It works best with your agent's memory turned on."

**Verifier stance:** Independent, skeptical, fail-closed. Every verdict defaults to NOT PROVEN; only exercised evidence moves it. "The hub claims X" is kept separate from "I verified X."

**Date exercised:** 2026-06-05

---

## 1. Interaction model (Step 0 finding)

The live URL does **not currently serve a governance hub**. Every entry point I probed at the apex returned **HTTP 404**, while only a Cloudflare-managed `robots.txt` responded with 200.

| Probe | Result |
|---|---|
| `GET https://acgs.ai/` | **HTTP 404 Not Found** |
| `GET https://www.acgs.ai/` | **HTTP 404 Not Found** |
| `GET https://acgs.ai/interview` | **HTTP 404 Not Found** |
| `GET https://acgs.ai/governance` | **HTTP 404 Not Found** |
| `GET https://acgs.ai/agent` | **HTTP 404 Not Found** |
| `GET https://acgs.ai/llms.txt` | **HTTP 404 Not Found** |
| `GET https://acgs.ai/.well-known/llms.txt` | **HTTP 404 Not Found** |
| `GET https://acgs.ai/robots.txt` | **HTTP 200** (Cloudflare-managed default) |
| WebSearch `acgs.ai governance hub agent interview` | No result references acgs.ai; only generic third-party governance articles |

**What this means.** A 404 is an HTTP status, not a JS-rendering artifact. A single-page app serves its shell with **200** + HTML; a 404 means nothing was deployed/routed at that path. So the "maybe it's an SPA my fetcher can't render" hypothesis is ruled out by the status code itself — there is no 200 shell to render.

**Ruling out edge bot-blocking (the one alternative that would flip this).** Because the served robots.txt does `Disallow: /` for ClaudeBot, a 404 to WebFetch *could* in principle be an agent-specific Cloudflare block disguised as 404 rather than a genuine empty origin. I tested this directly with a neutral-UA `curl` (ignores robots, is not ClaudeBot):

```
HTTP/2 404
content-length: 0
server: cloudflare
cf-ray: a06e11cf8904b2eb-YYZ
```

`/interview` returned the identical empty 404. A neutral fetcher gets the same **404 with an empty body and no origin headers** — a WAF/bot block would return 403 or a challenge page *with* a body, not an empty 404. So this is "nothing deployed behind the apex," not edge-blocking of my agent. That earns the **FAIL-not-UNABLE** distinction without relying on robots.txt reachability (robots.txt is exempt from robots blocking, so its 200 proves nothing about `/`).

**Corroborating repo evidence (authoritative).** This workspace contains the hub's own source (`acgi-ai/`):
- `acgi-ai/CLAUDE.md:175` — *"Production URL: `https://acgs.ai` (**pending DNS** — staging URL is the Vercel preview from `vercel ls --prod`)."* The apex is the **intended** production domain but DNS is **not yet pointed at the deployment**. This exactly explains apex 404 + Cloudflare-served robots.txt (proxy on, no origin behind `/`).
- `acgi-ai/src/routes/` on the checked-out tree contains: `Marketing.tsx`, `console/`, `Login.tsx`, `Trust.tsx`, `Security.tsx`, `Privacy.tsx`, `ProductSurfaces.tsx`, `NotFound.tsx`, `workbench-content.ts`. A grep for `interview | governance.*brief | llms.txt | agent.*instruction` returned **zero files**. The "guided interview / brief generator / agent-readable instructions" pages described in the marketing copy live on a **different feature branch** (`feat/marketing-governance-hub`), not on the live site and not on the current checkout.

**robots.txt is itself relevant to the claim.** The served `robots.txt` issues `Disallow: /` to `ClaudeBot`, `GPTBot`, `CCBot`, `Google-Extended`, `meta-externalagent`, and `CloudflareBrowserRenderingCrawler`, plus `Content-Signal: ai-train=no`. A compliant AI agent "pointed at the URL" is told **not to crawl it at all**.

**Scope honesty.** I exercised the live URL over HTTP via two independent fetchers (WebFetch and neutral-UA curl), plus the agent-readable paths, search presence, and a cross-check against the hub's own source. I did **not** additionally drive a JS-rendering browser: the repo-mandated `/browse` (gstack) skill is not installed in this session, and direct `claude-in-chrome` tools are forbidden by repo policy. That cross-check is **not-run** — but a JS browser only matters for distinguishing a 200 SPA shell from rendered content; here both fetchers return an empty **404**, so there is no shell to render and the browser check is non-load-bearing.

---

## 2. Verdicts table

| Claim | Verdict | Evidence (one-line) |
|---|---|---|
| C1 — Agent can find & start the interview | **FAIL** | Entry point exercised: `https://acgs.ai/` and 6 other paths all return HTTP 404; robots.txt also `Disallow: /` for ClaudeBot. There is nothing to start. |
| C2 — Interview is genuinely guided | **UNABLE-TO-TEST** | No reachable interview surface at the live URL to engage (404). Interview route is absent from the current source tree; lives on another branch. |
| C3 — Output maps to the specific work | **UNABLE-TO-TEST** | Cannot run PRIMARY vs CONTRAST contexts against a non-existent endpoint. |
| C4 — Memory-on improves the result | **UNABLE-TO-TEST** | Cannot compare cold vs memory-loaded runs against a 404. |
| C5 — Governance produced is substantive | **UNABLE-TO-TEST** | No artifact is produced at the live URL to audit. |
| Safety — no risk in pointing an agent at it | **PASS** | Pointing an agent at acgs.ai returns 404 + a passive robots.txt. No access grant, code execution, install, or privileged action is requested. (Note: nothing useful happens either.) |

Verdict scale: PASS = exercised and demonstrated · PARTIAL = held weakly · FAIL = exercised and did not hold · UNABLE-TO-TEST = interaction model blocked it.

---

## 3. Evidence detail

**C1 — FAIL (not UNABLE).** I distinguish these deliberately. UNABLE would mean the interaction model blocked the test. It didn't: a neutral-UA `curl` (not ClaudeBot, ignores robots) received `HTTP/2 404` with `content-length: 0`, `server: cloudflare`, and no origin headers — at the apex and at `/interview`. That is a definitive empty 404 from the edge with nothing deployed behind it, not an agent-specific block (which would be 403/challenge with a body). So the entry point was genuinely exercised and genuinely answered "nothing here." Two independent reasons an arriving agent cannot start: (a) the path 404s, so there is no interview to begin; and (b) the served robots.txt issues `Disallow: /` to ClaudeBot/GPTBot, so a compliant agent is told not to fetch it at all. The claim's load-bearing precondition — "there's a guided interview at the URL" — is false at the URL given. Hence FAIL, exercised.

**C2/C3/C4/C5 — UNABLE-TO-TEST.** These all presuppose C1. With no reachable interview, there is no interaction to characterize, no adaptivity to compare, no memory delta to measure, and no governance artifact to audit. I refuse to round any of these up to PASS or FAIL on the basis of the marketing copy or off-branch source — that would be asserting, not verifying. (If the goal is to test the *implementation* rather than the *live CTA*, that requires a different target: a running build of the `feat/marketing-governance-hub` branch, which was not the URL supplied.)

**Safety — PASS.** The only thing an agent receives today is a 404 body and a `robots.txt` that asks it not to crawl. No prompt to grant filesystem/tool access, no code to run, nothing to install, no privileged endpoint. The residual is reputational, not security: the CTA sends agents to a dead URL.

---

## 4. Substance audit (Step 5 scorecard)

**Not assessable at the live URL** — no governance setup is produced to audit. Marking each dimension UNABLE rather than inferring from copy:

| Dimension | Status | Note |
|---|---|---|
| 1. Authority (auth required *before* action) | UNABLE | No artifact produced at live URL. |
| 2. Default (fail closed) | UNABLE | — |
| 3. Record (audit trail defined) | UNABLE | — |
| 4. Least privilege (bounded + enforced, e.g. $500 cap) | UNABLE | — |
| 5. Escalation / human-in-the-loop | UNABLE | — |
| 6. Failure handling (tool/model error, violation) | UNABLE | — |
| 7. Domain specificity (GDPR / PHIPA / SOC 2 mapped) | UNABLE | — |

To make this section real, re-run against a reachable deployment that actually emits a governance brief.

---

## 5. Failure modes & gaps found

1. **Dead CTA (critical).** The published instruction "Point your agent at the URL" resolves to HTTP 404 at `https://acgs.ai`. The promise and the reality diverge at step one.
2. **DNS / deploy not live.** Per the hub's own `acgi-ai/CLAUDE.md:175`, acgs.ai is "Production URL (pending DNS)." The CTA was written/published as if the site were live; it is not.
3. **robots.txt actively excludes the intended audience.** The Cloudflare-managed `robots.txt` sends `Disallow: /` to ClaudeBot/GPTBot/CCBot/Google-Extended/meta-externalagent and `ai-train=no`. A claim whose whole point is "point your *agent* at the URL" is undercut by a robots policy that tells those exact agents not to fetch. Even after DNS is live, a compliant agent may decline to crawl.
4. **No agent-readable entry.** No `llms.txt`, `/.well-known/llms.txt`, `/agent`, or machine-readable interview entry responded. There is no non-browser path for an agent to "begin and conduct" the interview as the claim implies.
5. **Claim/branch mismatch.** The interview/brief-generator pages exist only on `feat/marketing-governance-hub`, not on the live site or the current tree — so the experience the CTA describes is not yet shipped to the URL it names.
6. **Not discoverable.** No search presence ties acgs.ai to this hub; an agent that "searches" rather than direct-loads finds generic third-party material instead.

---

## 6. Fix-before-publishing list (prioritized)

1. **Make the CTA resolve.** Complete DNS cutover so `https://acgs.ai/` serves the hub (200, real content) before any post tells agents to point at it. Verify with an out-of-network fetch, not just an internal preview.
2. **Ship the interview to the live host.** Merge/deploy the `feat/marketing-governance-hub` interview + brief-generator + agent-instructions routes to the production build that acgs.ai serves. Confirm the specific paths (`/interview` or whatever the canonical entry is) return 200.
3. **Reconcile robots.txt with the thesis.** If the product *wants* AI agents to fetch and conduct the interview, stop serving a `Disallow: /` for ClaudeBot/GPTBot etc. (replace the Cloudflare-managed default with an intentional policy), or expose an explicitly-allowed agent path / `llms.txt`. Today the policy contradicts the pitch.
4. **Add an agent-readable entry point.** Publish `llms.txt` (and/or `/.well-known/`) describing how an agent begins the interview, so the claim "point your agent at the URL" has a real non-browser on-ramp.
5. **Only then re-run C2–C5 and the substance audit** against the live deployment, including the adaptivity probe (fintech vs hospital/PHI) and the memory-on vs cold comparison.
6. **Soften the post until live.** Until 1–4 land, the CTA overclaims a working experience that returns 404. Either gate the post on go-live or reword to a waitlist/preview.

---

## 7. Transcript appendix (interactions actually had)

```
# WebFetch (Anthropic fetcher)
GET https://acgs.ai/                       -> HTTP 404 Not Found
GET https://acgs.ai/llms.txt               -> HTTP 404 Not Found
GET https://acgs.ai/robots.txt             -> HTTP 200
    User-agent: *  Content-Signal: search=yes,ai-train=no  Allow: /
    User-agent: ClaudeBot      Disallow: /
    User-agent: GPTBot         Disallow: /
    User-agent: CCBot          Disallow: /
    User-agent: Google-Extended Disallow: /
    User-agent: meta-externalagent Disallow: /
    User-agent: CloudflareBrowserRenderingCrawler Disallow: /
    (+ Amazonbot, Applebot-Extended, Bytespider disallowed)
GET https://www.acgs.ai/                   -> HTTP 404 Not Found
GET https://acgs.ai/interview              -> HTTP 404 Not Found
GET https://acgs.ai/governance             -> HTTP 404 Not Found
GET https://acgs.ai/agent                  -> HTTP 404 Not Found
GET https://acgs.ai/.well-known/llms.txt   -> HTTP 404 Not Found
WebSearch "acgs.ai governance hub agent interview" -> no acgs.ai references; generic 3rd-party governance articles only

# curl (neutral UA, ignores robots) — discriminator: deployed-empty vs edge-blocked
curl -i https://acgs.ai/          -> HTTP/2 404  content-length: 0  server: cloudflare  (no origin headers)
curl -i https://acgs.ai/interview -> HTTP/2 404  content-length: 0  server: cloudflare  (no origin headers)
  => empty 404 from a neutral fetcher = nothing deployed behind apex, NOT an agent-specific WAF block.

Repo cross-check (acgi-ai/, current checkout feat/add-research-packages):
  acgi-ai/CLAUDE.md:175  -> "Production URL: https://acgs.ai (pending DNS — staging URL is the Vercel preview)"
  acgi-ai/src/routes/    -> Marketing, console, Login, Trust, Security, Privacy, ProductSurfaces, NotFound, workbench-content
  grep interview|governance-brief|llms.txt|agent-instruction in acgi-ai/src -> 0 files (those pages are on feat/marketing-governance-hub)

Not run: JS-rendering browser load (gstack /browse skill unavailable this session;
         direct claude-in-chrome forbidden by repo policy). 404 status codes make
         this cross-check non-load-bearing for the verdict.
```

---

**Substantiation verdict:** POST_CLAIM is **NOT currently substantiated — high confidence.** The single load-bearing precondition fails at the entry point: `https://acgs.ai` returns an empty HTTP 404 — confirmed by two independent fetchers including a neutral-UA `curl` that gets `404 content-length: 0 server: cloudflare` with no origin behind it, which rules out agent-specific edge-blocking and makes this a *tested* FAIL rather than an untestable one. Corroborating, but not load-bearing: the hub's own source documents the domain as "pending DNS," the interview route is absent from the live host, and the served robots.txt tells the very agents the claim targets not to crawl. Nothing about "a guided interview that maps your work to a governance setup" can be exercised at the URL given. Re-test after a real go-live.

---

# Addendum A — C2–C5 retest against the branch build

**Scope:** branch `feat/marketing-governance-hub` @ commit `5129fab` ("feat(marketing): launch AI agent governance hub"), checked out in an isolated git worktree. This is where the interview the CTA promises is actually implemented. C1 and Safety are unchanged from the live test; this addendum re-opens C2–C5 now that there is real source to exercise.

**Method & its limit (honesty first).** I assessed the interview by reading its full, deterministic implementation (`acgi-ai/src/routes/Marketing.tsx`) plus the served entry shell (`acgi-ai/index.html`) and the agent-asset directory (`public/`). I did **not** drive the rendered React form in a live browser — the repo-mandated `/browse` skill is unavailable and direct browser tools are forbidden. This is acceptable here because the "interview" is a **pure, fully-readable function of its inputs** (no backend, no LLM, no network): reading the logic tells you exactly what every input combination produces. Where a verdict depends on browser-only behavior, I say so.

### What the interview actually is

A single-screen, client-side React form `GovernanceInterview()` (`Marketing.tsx:990`) that deterministically scores risk and renders a "Governance brief" live. Inputs: free-text `task` + `affected`, `requestedRole` (advise/draft/simulate/execute), `reversible`, `approval`, and 14 checkbox **risk signals** with fixed weights (`riskSignals`, `Marketing.tsx:114-208`). Output: `score = Σ weights` → `level` (blocked/high≥10/medium≥5/low) → `mode` via `modeFor()` (`:534`), plus per-signal `boundaries`, `humanChecks`, `logging`, a **fixed** `doNotAllow` list, a **fixed** `stopConditions` list, and `nextStep`. There is no server call and no model call — it is a calculator.

### Revised verdicts (branch build)

| Claim | Verdict | Evidence (one-line) |
|---|---|---|
| C2 — Interview is genuinely guided | **PARTIAL** | In a browser the brief recomputes live from inputs (`aria-live`, `Marketing.tsx:1170`) — reactive, not a static dump. But it is one form, not an adaptive/branching interview, and for the *agent* the CTA addresses the page is a JS-only SPA shell (`index.html:10-11`) — fetching the URL yields `<div id="root">` + a bundle, not a conductible interview. |
| C3 — Output maps to the specific work | **FAIL** | The interview's inputs and scoring (`riskSignals` `:114-208`, `GovernanceInterview` `:990`, `modeFor` `:534`) contain **no domain/jurisdiction dimension** — they import no compliance data and reference no framework. `privateData` (weight 3) covers PII and PHI identically. Same signal selections → identical brief for the fintech-GDPR and hospital-PHIPA personas; `task`/`affected` text is echoed verbatim, never analyzed (`:1072-1075`). The $500 cap cannot be represented (no numeric limits). **Sharper still:** the rest of the site clearly *knows* these frameworks — `ProductSurfaces.tsx:281` names "EU AI Act, GDPR, NIST AI RMF, SOC 2, HIPAA, ISO 42001, CCPA, FDA SaMD"; `Console.tsx`/`mocks` carry GDPR Art. 22 + HIPAA §164.502(b) posture — yet **none of it is wired into the interview**. Domain-blindness here is a wiring gap, not ignorance. Templates with the nouns swapped. |
| C4 — Memory-on improves the result | **FAIL** | The brief is a pure function of form inputs; agent memory state is never read, so memory-on cannot change output. Worse, the hub's own substance prescribes the **opposite**: "Memory off by default for sensitive work" (pattern `:473-478`; signal boundary `:193`) and lists "Memory contamination" as a failure mode (`:240-247`). The CTA contradicts the product for exactly the sensitive PII/PHI scenarios under test. |
| C5 — Governance produced is substantive | **PASS (with caveats)** | The governance vocabulary is real, not vibes: authority-before-action ("No named authority, no tool call," `:219`), fail-closed default (`modeFor`→`fail-closed`, `:535`), decision-receipt logging (`:1054`), explicit stop conditions (`:1014-1020`), least-privilege per-signal boundaries (`:114-208`), human-in-the-loop + two-person review (`:1046-1048`, pattern `:460-462`), simulation-before-execution and credential isolation (patterns `:480-501`). Caveats: it is **advisory, not enforced** (a marketing page, no runtime gate, no numeric caps), and **domain-blind** (dim 7 below). |

### Substance audit (now assessable) — Step 5 scorecard

| Dimension | Status | Proof |
|---|---|---|
| 1. Authority before action | **Present** | `doNotAllow`: "Do not assume available tools equal permission to act" (`:1023`); rule "No named authority, no tool call" (`:219`); humanChecks require approval "fresh, explicit, and tied to the exact action" (`:1048`). |
| 2. Default (fail closed) | **Present** | `blocked` → `mode = fail-closed` → nextStep "Stop execution" (`:535`, `:1058`); triggers when execute + blocking signal + approval≠yes (`:1002-1004`). |
| 3. Record (audit trail) | **Present** | Non-low logging captures "task, authority, selected mode, tool calls, evidence, approval, refusal reasons, stop events … as a decision receipt" (`:1054`); pattern "Audit log required" with Timestamp/Actor/Action/Evidence/Decision (`:464-471`). |
| 4. Least privilege (bounded **+ enforced**) | **Partial** | Per-signal boundaries + sandboxed/draft-only modes are described, but nothing is enforced — it is rendered guidance, and there is no representation of a hard cap like "$500." |
| 5. Escalation / human-in-the-loop | **Present** | approval-required mode (`:536`); "A separate reviewer should inspect high-risk output" (`:1047`); blocked → "obtain explicit human authority with a rollback plan" (`:1058`). |
| 6. Failure handling | **Present (generic)** | stopConditions cover tool-result conflict, failed/unrunnable verification, and an action becoming irreversible/financial/production "without fresh approval" (`:1016-1019`). |
| 7. Domain specificity (GDPR/PHIPA/SOC 2) | **Absent** | No regulatory mapping anywhere; only generic `legal` signal "escalate to qualified review" (`:155-161`). |

Net: **5 present, 1 partial, 1 absent.** This is genuine governance scaffolding on the generic axis — not "be careful + add logging" filler — but it is neither personalized to the deployment nor enforced.

### What this changes vs. the live-URL test

- The interview **is real** and the governance model behind it is **substantive** (C5 PASS) — that is the part the live 404 hid. Credit where due.
- But the two specific promises in the CTA still do **not** hold even with the implementation in hand: it does **not** "map to your *current work*" in any domain/regulatory sense (C3 FAIL — generic signals only), and "works best with memory **on**" is **contradicted by the hub's own thesis** (C4 FAIL — it preaches memory *off* for sensitive work).
- Agent-consumption gap persists: "Agent-readable by design" (`hubPillars`, `:83-84`) is aspirational — the good `agentReadableRules` (`:504-512`) are rendered client-side, not exposed at a stable machine-readable endpoint (no `llms.txt`; `public/AGENTS.md` is just a generated folder-doc).

### Additional fix-before-publishing items (branch)

7. **Add a real domain axis** so C3 can pass: a regulated-context input (GDPR / HIPAA-PHIPA / SOC 2 / PCI) that changes obligations, plus numeric limits (e.g., the $500 cap) the brief can echo and gate on.
8. **Reconcile the memory message.** Either drop "works best with memory on" from the CTA, or scope it precisely (e.g., "load your *deployment context*, keep *cross-task* memory off") so it stops contradicting the hub's own "memory off for sensitive work" pattern.
9. **Expose an agent-readable endpoint.** Serve `agentReadableRules` + `briefFormat` as `llms.txt` / a static JSON or markdown brief so an agent "pointed at the URL" can actually consume the interview without executing the SPA.
10. **Pre-render or SSR the hub content** so a fetch of `/` returns the governance text, not an empty `#root` shell — required for the "a human *or an AI agent* can inspect the URL" claim (`:84`) to be literally true.

---

## Combined bottom line

**POST_CLAIM is NOT substantiated.** Two independent reasons, at two scopes:

1. **Live (high confidence):** the CTA's URL `https://acgs.ai` returns an empty 404 for everyone (neutral-UA curl confirmed), and the served robots.txt tells AI agents not to crawl — so there is nothing to point an agent at today.
2. **Branch build (high confidence):** even with the interview implemented, its two specific promises fail — it does not map to the user's *domain/regulatory* work (no GDPR/PHIPA/SOC 2 dimension; identical briefs across personas), and "memory on" is contradicted by the hub's own "memory off for sensitive work" guidance. The underlying governance model is genuinely substantive (C5 PASS), so the fix is reachable — but as worded, the claim overstates what the hub does.
