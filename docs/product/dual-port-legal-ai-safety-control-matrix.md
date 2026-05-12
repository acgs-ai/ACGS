# Dual-Port Legal AI — Legal Safety and Source-Control Matrix

Status: integration-ready PRD content
Scope: Ontario and Federal Canadian legal information workflows
Date: 2026-05-11

## Purpose

This matrix defines the minimum legal-safety controls for the Dual-Port Legal AI product requirements package. It separates lawyer/staff workbench use from client-facing education and intake, keeps outputs source-backed, and prevents the product from implying unsupervised legal advice or unverified court-facing content.

## Output boundary rules

| Output type | Permitted audience | Required source posture | Mandatory human step | Must not do |
|---|---|---|---|---|
| Legal information summary | Lawyer/staff and client interface | Cite approved public legal sources when specific legal propositions are stated. | Lawyer review before client-specific reliance. | Present a personalized legal opinion or predict case outcome as certain. |
| Risk summary / triage note | Lawyer/staff; client interface only as plain-language escalation guidance | Tie risks to user-provided facts and identified source gaps. | Escalate to lawyer when facts suggest rights, deadlines, filings, settlement, admissibility, or litigation strategy. | Tell the client what they should file, plead, admit, settle, or sign without lawyer review. |
| Opinion-draft support | Internal legal workbench only | Every legal proposition must link to an approved source or be marked as needing authority. | Lawyer signs off before delivery, filing, or use in legal advice. | Deliver directly to clients, courts, opposing counsel, tribunals, or public records. |
| Court-facing draft / litigation material | Internal legal workbench only | Use verified source citations and flag AI assistance for disclosure review. | Lawyer verifies authorities, record references, procedural rules, and disclosure requirements before export. | Export as final or filing-ready without review and disclosure assessment. |

## Source allowlist and evidence controls

| Control area | Requirement | Launch acceptance standard | Blocked-launch condition |
|---|---|---|---|
| Approved legal sources | Initial approved sources should include official court websites, CanLII, Ontario e-Laws for Ontario statutes/regulations, and other firm-approved legal-source repositories. | Product UI and reviewer guidance distinguish official/legal sources from general web content. | The system cannot identify whether a cited authority came from an approved source. |
| Claim-source compatibility | A legal claim about statute, regulation, case law, procedure, deadline, or filing requirement must cite a compatible source type. | Reviewer can trace each legal claim to a source or see an explicit `authority needed` marker. | The system presents uncited legal propositions as verified law. |
| Source freshness | Time-sensitive claims must show retrieval or review date where practical. | PRD requires review of dates for statutes, procedural rules, and court guidance. | The product hides or omits the review status for time-sensitive legal content. |
| Insufficient evidence | If approved sources do not support an answer, the output must say the evidence is insufficient and route to human review. | Client-facing language uses plain terms such as `I do not have enough verified information to answer that safely.` | The product fabricates, guesses, or fills legal authority gaps with unsupported assertions. |

## Legal-safety control matrix

| Risk | Required product control | Internal workbench behavior | Client-interface behavior | Evidence to retain |
|---|---|---|---|---|
| Hallucinated authority | Require source-backed claims, authority-needed markers, and reviewer-visible citation checks. | Show source links, missing-authority flags, and confidence limits to lawyer/staff users. | Avoid detailed legal conclusions when authority is missing; offer escalation. | Prompt/input snapshot, cited sources, missing-authority flags, reviewer decision. |
| Unsupervised legal advice | Separate legal information from opinion drafting and require lawyer review for client-specific recommendations. | Permit drafts and analysis only as lawyer-assistive work product. | Provide education, intake, risk flags, and escalation; do not recommend a final legal action. | Output type, review status, escalation reason, final approver where applicable. |
| Confidentiality leakage | Minimize input collection, restrict vendor/model routing, and require privacy/security review before any external processing. | Warn users before adding sensitive facts; support redaction and matter-based access controls. | Collect only necessary intake facts and show confidentiality boundaries. | Data category, access log, retention class, redaction status. |
| Misuse of court-facing content | Gate exports for pleadings, affidavits, factums, motion records, and other litigation materials. | Require lawyer verification of authorities, record references, procedural rules, and AI disclosure needs. | Do not expose court-facing draft generation directly to clients. | Export request, reviewer checklist, disclosure decision, cited authorities. |
| Overbroad risk scoring | Tie risk summaries to facts and source gaps instead of deterministic predictions. | Show why a risk was flagged and what facts are missing. | Use plain-language triage and recommend lawyer contact for high-risk situations. | Facts used, missing facts, risk category, escalation threshold triggered. |
| Retention/privacy mismatch | Define retention limits, audit purpose, and deletion procedures before launch. | Store only required evidence for audit/replay and matter accountability. | Explain retention at intake where applicable. | Retention class, deletion eligibility, access/audit log. |

## Human review triggers

The product must route to a lawyer or authorized legal reviewer when any of the following occurs:

1. The user asks what they should do in their specific matter.
2. The answer depends on a limitation period, filing deadline, procedural rule, settlement choice, rights waiver, admissibility issue, or litigation strategy.
3. The output is intended for a client, court, tribunal, regulator, opposing counsel, or public filing.
4. A cited source is missing, incompatible, stale, or contradicted by another source.
5. The matter includes confidential, privileged, personal, child/family, immigration, criminal, employment termination, housing eviction, or other high-impact facts.
6. The system cannot safely classify the requested output as legal information rather than legal advice.

## Audit and replay requirements

For every reviewed output, the product should retain enough evidence for internal accountability without over-collecting personal information:

- user role and port used (`internal workbench` or `client interface`);
- output type requested and output type delivered;
- prompt/input snapshot or approved redacted equivalent;
- source list, retrieval/review dates where available, and missing-authority markers;
- model/vendor route if applicable, without approving new vendors by default;
- human reviewer, decision, edits, and escalation outcome;
- export/disclosure decision for court-facing or litigation material.

## Blocked-launch checklist

Launch should be blocked if any item below is true:

- Client-facing flows can generate personalized legal advice without lawyer review.
- Court-facing drafts can be exported without authority verification and disclosure review.
- Legal claims appear without approved-source citations or explicit insufficient-evidence language.
- The product cannot separate legal information, risk summary, opinion-draft support, and court-facing content.
- Confidential or personal information can be routed to an unapproved service, vendor, model, log, or analytics sink.
- Retention, audit, and access-control responsibilities are not assigned.
- Reviewers cannot reconstruct what sources and facts supported an output.
- The implementation requires a new dependency that has not passed privacy, security, legal, and rollback review.

## Dependency posture

This safety matrix is documentation-only and does not require a new package, SDK, service, model provider, or runtime dependency. Any future dependency proposal must follow the companion dependency-impact note before implementation.
