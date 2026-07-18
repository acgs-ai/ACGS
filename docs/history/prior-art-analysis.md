# ACGS — Prior-Art & Priority Record

**Document type:** Defensive-publication / prior-art record
**Status:** Public
**Maintainer:** Honglin Lyu (`dislovelhl`)
**Last updated:** 2026-07-18 (git-history items in §1/§6 independently re-verified against the live GitHub commit graph on this date; the Zenodo deposit rests on the public DOI and maintainer attestation — automated re-fetch from the landing environment was blocked, see §7 Verification provenance)

-----

## 0. Purpose and scope

This document records the public, timestamped disclosures underlying ACGS and states, with claim discipline, what ACGS asserts as an original contribution versus what it builds on from established prior art.

It is a **defensive-publication record**, *not* an assertion of patentable priority. Its function is to (a) establish a public prior-art date so the disclosed mechanisms remain freely usable and cannot be enclosed by others, and (b) separate the defensible original synthesis from techniques that are already well known. Where a mechanism is standard practice, this document says so explicitly — disclaiming novelty where none exists is what makes the remaining claims credible.

> **Patent posture (time-sensitive; not legal advice).** A public enabling disclosure starts the clock: in the US the inventor’s grace period is 12 months from first disclosure — for the 2025-07-29 deposit that window runs until **~2026-07-29**, i.e. **still open as of this record’s 2026-07-18 update date, but only briefly**; in absolute-novelty jurisdictions (EPO, CN, and most others) the July 2025 disclosure was an immediate bar. This record adopts a **defensive-publication** posture (§0): it treats the disclosure as **published prior art**, which prevents others from enclosing the disclosed mechanisms. Note two things precisely: publishing as prior art is **not** the same as a public-domain dedication (it does not by itself waive the author’s rights), and whether to *also* preserve the still-open US filing option is a **time-sensitive decision for patent counsel**, not one settled by this document.

-----

## 1. Priority anchors (evidence, in order of strength)

**Primary — independent third-party timestamp.**
Zenodo deposit, DOI `10.5281/zenodo.16417581` — *“ACGS-2: A Production-Ready Constitutional AI Governance System”* — record created 2025-07-28, published 2025-07-29; creator: Lyu, Honglin. Dates and metadata here are per the maintainer’s Zenodo deposit; the DOI is public and independently resolvable. (Automated re-fetch of the record from the environment that landed this file was blocked on 2026-07-18 — `doi.org`, `zenodo.org`, and the Zenodo records API all returned HTTP 403 to the tooling, and a web search did not surface the record — so this specific line is **maintainer-attested, not re-verified in that pass**; see §6 and §7.) Zenodo assigns the timestamp independently of the author, which is what makes this the load-bearing evidence in this record. Indexed via Zenodo / OpenAIRE.

**Secondary — source history (corroborating context, not primary date proof).**
Two repositories, in sequence:

- `github.com/ACGSpgp/acgs2` — the July-2025-era ACGS-2 implementation. Initial commit `32816c04854a4f3d23eb1b21ef3d736f290debdd` is stated to live **in that repository** (and is verified **absent** from `dislovelhl/ACGS`; see §6 — its positive presence in `ACGSpgp/acgs2` is asserted, not verified in the landing pass).
- `github.com/dislovelhl/ACGS` — the current canonical repository. History begins **2026-05-04** (root commit `35ebf7d`, “initial: acgi-ai marketing + console + deployment scaffold”; confirmed parentless — i.e. the true first commit — via the GitHub API on 2026-07-18). The total commit count and signing breakdown live in §6; see the note there on reconciling the reported totals.

First appearance of the narrow-claim elements in the canonical repository (re-verified from the live commit graph, 2026-07-18):

- **MACI role separation — three lanes at the root.** A MACI console ships in the root commit `35ebf7d` (2026-05-04), but the root implementation (`acgi-ai/src/routes/console/Maci.tsx`) renders **three** lanes only — **Proposer, Validator, Executor** — and states verbatim “Three lanes, no overlap.” So the root commit establishes the decision/enforcement **role separation**, *not* the full four-role decomposition of §2: the **Observer** role is **not** present at the root, and its first appearance in the canonical history is **not pinned in this pass** (see §6). Do not read the root commit as evidence of the four-role claim.
- **`docs/DECISION_RECEIPT_SPEC.md`** — created in `6399a0a` (2026-06-06, “docs: add receipt-gated governance proof path”; the file is added in that commit, 197 lines — confirmed via the GitHub API on 2026-07-18).

**Continuity note (stated plainly):** there is a ~9-month interval between the July 2025 Zenodo disclosure and the start of the canonical repository’s history. The bridge for that interval is the `ACGSpgp/acgs2` repository; anyone auditing this chain should examine that repository’s history directly. This record does not claim the canonical repo’s history reaches back to the disclosure date.

> **On git as evidence:** commit-embedded author/commit timestamps are settable at commit time and are **not**, by themselves, proof of date. The defensible time evidence is the independent Zenodo deposit above; repository history is corroborating context. To harden it, see the verification checklist in §6 (commit signing, push-history integrity, repository ownership).

-----

## 2. The priority claim, stated narrowly

ACGS does **not** claim priority over “constitutional AI governance” as a category. That term has many concurrent 2025 claimants; the broad claim is not defensible and this record does not make it.

The defensible, narrow contribution disclosed in July 2025 is a specific **synthesis and application**:

> A runtime **reference monitor for autonomous agents** that
> (i) separates policy *decision* from *enforcement* across explicit roles — **MACI**: Proposer, Validator, Executor, Observer;
> (ii) gates every externally-effecting tool call behind an **out-of-band, signed governance-decision receipt**; and
> (iii) enforces **fail-closed** semantics — *no valid receipt, no side effect* — with the receipt retained as audit evidence.

Every underlying mechanism has prior art (see §3). The claimed originality is their **integration and application to LLM-agent tool execution**, publicly disclosed July 2025. (The four-role form of this claim is anchored to the July 2025 Zenodo disclosure, not to the canonical repo’s May-2026 root commit — see the first-appearance note in §1.)

-----

## 3. Claims register

**Legend** — **PRIOR ART**: established technique, not claimed as novel. **SYNTHESIS**: original integration/application; the components are prior art. **CANDIDATE-NOVEL**: plausibly first in this specific form — defensible, but not adjudicated.

|#|Element                                                                  |Status                                    |Prior-art lineage relied upon                                                                          |What ACGS actually asserts                                                                             |
|-|-------------------------------------------------------------------------|------------------------------------------|-------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------|
|1|Runtime enforcement of policy at execution time                          |PRIOR ART                                 |Reference monitor (Anderson, 1972); complete-mediation & tamper-resistance properties                  |Application to autonomous-agent tool calls — not a new enforcement concept                             |
|2|Decision/enforcement separation across roles (MACI)                      |SYNTHESIS                                 |Reference-monitor decision-vs-enforcement split; Clark–Wilson integrity (1987); object-capability model|The specific four-role decomposition (Proposer/Validator/Executor/Observer) for LLM agents             |
|3|Out-of-band signed decision receipt as a precondition for any side effect|CANDIDATE-NOVEL (as application)          |Object-capability tokens; macaroons (Birgisson et al., 2014); signed-capability / JWT patterns         |A governance receipt that must be present out-of-band for an agent’s tool call to take effect          |
|4|Fail-closed gate (“no receipt, no side effect”)                          |SYNTHESIS                                 |Fail-safe defaults & least privilege (Saltzer & Schroeder, 1975)                                       |Applied as the terminal execution gate for agent actions                                               |
|5|Cryptographic integrity of the governing policy (“constitutional hash”)  |PRIOR ART                                 |Content-addressed integrity; signed configuration; TUF / Sigstore-style transparency                   |Naming and framing only; the integrity mechanism itself is standard                                    |
|6|Policy-as-code + formal validation + AI-assisted policy synthesis        |PRIOR ART (each) / SYNTHESIS (combination)|OPA/Rego & policy-as-code; formal policy verification; policy/program synthesis research               |Integration of the three into one validation path                                                      |
|7|Auditable decision evidence / receipts log                               |PRIOR ART                                 |Tamper-evident & transparency logs (Certificate Transparency lineage)                                  |Application to agent-governance decisions                                                              |
|8|Distributed service architecture (“26 services”)                         |NOT A NOVELTY CLAIM                       |Microservices                                                                                          |Deployment topology; service count is **not** asserted as a contribution                               |
|9|Runtime governance layer for the Constitutional-AI paradigm              |SYNTHESIS / framing                       |Constitutional AI (Bai et al., 2022) — a *training-time* method                                        |Positioning CAI-style constraints at **runtime**, complementing (not replacing) training-time alignment|

-----

## 4. Scope and maturity of the July 2025 disclosure

Stated precisely, to keep this record accurate and to foreclose the obvious challenge:

- The July 2025 disclosure documented **architecture and mechanism design**, validated on **synthetic data**. It should be read as a **research disclosure of a working prototype**, not as evidence of a production deployment in a regulated workload.
- Design elements that were **roadmap at time of disclosure** — notably shipped formal-verification artifacts and third-party-signed conformance evidence — are tracked as subsequent gates in the ACGS goal documentation and are **not** claimed as demonstrated in the July 2025 record.
- “Verifiable,” in the disclosure, denotes the **design property** (deterministic validators, signed receipts). Cryptographically-substantiated, independently-checkable verification is a later gate, not asserted complete as of July 2025.

> Any external summary of maturity should quote this section, **not** the deposit title. The deposit title is a fixed historical artifact; this section is the accurate maturity statement.

-----

## 5. Prior art expressly relied upon (credits)

ACGS is built on, and does not claim to originate:

- the **reference-monitor** concept (Anderson) and its complete-mediation / tamper-resistance / verifiability properties;
- the **Clark–Wilson** integrity model;
- the **object-capability** security model;
- **fail-safe defaults** and **least privilege** (Saltzer & Schroeder);
- **policy-as-code** engines (OPA / Rego);
- **capability tokens** and **macaroons**;
- software-signing and transparency-log infrastructure (**Sigstore**, **TUF**, Certificate Transparency lineage);
- **Constitutional AI** (Anthropic) as the training-time paradigm ACGS complements at runtime.

Explicit credit here is not a weakness of the claim — it is what makes a prior-art analysis credible and what keeps §2 defensible.

-----

## 6. Verification checklist (pin before external use)

To be confirmed by the maintainer before this record is relied on in diligence, grant, or freedom-to-operate contexts. Checked boxes were re-verified in the 2026-07-18 landing pass by the method named; unchecked boxes remain open.

- [ ] **Deposit verification** — DOI `10.5281/zenodo.16417581` is the anchor of record. Title, dates (created 2025-07-28, published 2025-07-29), and creator (Lyu, Honglin) are **maintainer-attested**; automated re-fetch from the landing environment **failed on 2026-07-18** (`doi.org` / `zenodo.org` / Zenodo records API → HTTP 403; a web search did not surface the record). Maintainer to confirm directly against the Zenodo records API from an unblocked network and record the result here.
- [x] **First-appearance dates (canonical repo)** — a MACI console with **three** lanes (Proposer / Validator / Executor; **no Observer**) is present from root commit `35ebf7d` (2026-05-04); `docs/DECISION_RECEIPT_SPEC.md` added in `6399a0a` (2026-06-06, 197 lines). Both independently re-verified against the live GitHub commit graph on 2026-07-18.
- [ ] **Four-role (Observer-inclusive) first appearance** — **not pinned.** The root commit contains three lanes only; the first canonical-repo artifact that adds the **Observer** role must be located and dated before §2’s four-role decomposition is cited to repository history (it remains anchored to the July 2025 Zenodo disclosure).
- [x] **Legacy-commit location** — `32816c04…` confirmed **absent** from `dislovelhl/ACGS` (GitHub API returned 422 “No commit found” on 2026-07-18). Its attribution to `ACGSpgp/acgs2` is asserted, **not** verified in this pass — that org is outside the verifying environment’s scope; see the audit item below.
- [ ] **Commit integrity** — signing is reported mixed (maintainer count: 292 of 763 commits signed, 471 unsigned; root commit `35ebf7d` unsigned). These figures were **not re-verified in the landing pass**, and an earlier draft of this record carried an inconsistent “393+” total — before external use, run `git rev-list --count HEAD` (true total) and a `git log --show-signature` tally (signed count) and record both here. Recommendation: enforce signed commits going forward (branch protection) and record this cut-over date. **The commits that landed this very record are unsigned (see §7) — signing them is the first instance of this item.**
- [ ] **`ACGSpgp/acgs2` audit** — confirm ownership/control of the `ACGSpgp` org, that the July-2025 history is intact (no rewrites), and archive a bundle (`git bundle`) of it alongside this record — it is the sole bridge for the disclosure→canonical-repo interval.
- [ ] **Maturity wording** — ensure every external summary uses §4 language (not the deposit title) as the maturity claim.
- [ ] **Deposit archival** — archive a copy of the deposit PDF alongside this record.

-----

## 7. Verification provenance (2026-07-18 landing pass)

This file was committed to the repository by an automated assistant acting for the maintainer. To keep the audit trail honest, here is exactly what was and was not independently re-verified in that pass, and by what method.

**Independently re-verified — GitHub commit-graph API (`dislovelhl/ACGS`):**

- `35ebf7d78f59ea92f1e66d2b807b8701d8b9da2e` is the **parentless root commit**, authored `2026-05-04T07:03:08Z`, “initial: acgi-ai marketing + console + deployment scaffold”. Its `acgi-ai/src/routes/console/Maci.tsx` renders a MACI console with **three** lanes — Proposer, Validator, Executor (“Three lanes, no overlap”); it does **not** contain the Observer role.
- `6399a0a9416cd24e71ec3649d67ecc1715a082e4`, authored `2026-06-06T19:09:51Z`, **adds** `docs/DECISION_RECEIPT_SPEC.md` (197 lines, status “added”).
- `32816c04…` **does not resolve** in `dislovelhl/ACGS` (API `422 No commit found`), corroborating its exclusion from the canonical history.

**Not re-verified in this pass (asserted / maintainer-attested / out of scope):**

- The Zenodo deposit (DOI, title, 2025-07-28 / 2025-07-29 dates, creator) — `doi.org`, `zenodo.org`, the Zenodo records API, and a web search all failed to return the record from the landing environment (HTTP 403 / no index hit). This is an access limitation of that environment, **not** evidence about the record itself; it must be confirmed from an unblocked network.
- Presence of `32816c04…` in `ACGSpgp/acgs2` — that repository is outside the verifying environment’s scope.
- Commit signing counts and total commit count (§6) — not tallied in this pass; the reported figures are unreconciled.

**Signature status of this record’s own commits.** They were created via the GitHub contents API and are **unsigned** (committer `MartinLyu <mt@acgs.ai>`; no GPG `gpgsig` header, no web-flow signing key — `git log --format=%G?` reports `N`). Stated plainly so the record does not fail its own integrity test: the provenance of *this* file currently rests on GitHub’s push/audit trail, **not** on a commit signature. Signing these commits is the first concrete instance of the §6 commit-integrity recommendation.

-----

*This record intentionally disclaims novelty for standard techniques (§3) and states maturity precisely (§4). That discipline is exactly what makes the narrow claim in §2 defensible.*
