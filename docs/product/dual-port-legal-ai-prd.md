# Dual-Port Legal AI PRD

Status: stakeholder review draft
Audience: lawyers, legal operations, compliance reviewers, firm leadership, product, design, and client-intake teams
Jurisdictional scope for this draft: Ontario and Federal Canadian legal workflows only
Source context: `.omx/context/legal-ai-prd-20260511T000000Z.md`

## 1. Executive Summary

Dual-Port Legal AI is a controlled legal AI workflow system. It helps lawyers, legal staff, and clients get faster, source-backed legal information while reducing the risk of unsupervised legal advice, hallucinated legal authority, confidentiality leakage, and misuse of AI-generated court-facing content.

The product has two clearly separated ports:

1. **Internal Legal Workbench** - for lawyers and authorized staff working under firm supervision.
2. **External Client Interface** - for client education, intake, status collection, risk triage, and escalation to a lawyer or staff member.

The system is not an autonomous lawyer, compliance certification engine, or self-serve legal-advice product. It must keep final legal judgment, client advice, and litigation-use decisions under human lawyer control.

## 2. Product Goals

### Goals

- Provide plain-language, source-backed legal information for Ontario and Federal Canadian workflows.
- Help lawyers and legal staff draft, summarize, compare, and review materials faster.
- Give clients a safe intake and education interface without allowing unsupervised legal advice.
- Make source grounding, human review, disclosure, privacy, and audit expectations visible in the workflow.
- Block or escalate outputs when sources are missing, evidence is weak, confidentiality risk is high, or court-facing use is proposed.

### Non-Goals

- No unsupervised legal advice to clients.
- No automatic filing, serving, or submission of AI-generated material.
- No representation that the system is certified compliant with LSO, Federal Court, OPC, or any regulator.
- No use outside Ontario or Federal Canadian workflows until separately reviewed and approved.
- No final determinations on privilege, admissibility, litigation strategy, settlement position, or client rights without lawyer review.

## 3. Users and Ports

| Port | Primary Users | Allowed Purpose | Hard Boundary |
| --- | --- | --- | --- |
| Internal Legal Workbench | Lawyers, articling students, paralegals, legal assistants, legal operations | Research assistance, drafting support, source-backed summaries, internal risk flags, review checklists, matter-specific work under supervision | Output remains draft or internal work product until reviewed and approved by an authorized lawyer or delegated reviewer. |
| External Client Interface | Existing or prospective clients, intake staff, client-service teams | Education, intake collection, document upload guidance, risk-summary triage, escalation routing | Must not provide personalized legal advice, final legal conclusions, litigation instructions, or court-ready documents without human review. |

## 4. Allowed Output Labels

Every AI response must carry one visible output label. The label controls wording, evidence requirements, and human review gates.

| Label | Meaning | Allowed Port(s) | Required Guardrails |
| --- | --- | --- | --- |
| **Legal Information** | General explanation of legal concepts, process steps, official-source excerpts, or source-backed summaries. | Internal and external | Must cite or link approved sources where legal claims are made. Must include plain-language limits and escalation path for client-specific questions. |
| **Risk Summary** | Issue spotting, uncertainty notes, or triage flags based on user-provided facts. | Internal and external | Must avoid final legal conclusions. Must explain uncertainty, missing facts, and when lawyer review is needed. |
| **Opinion Draft** | Draft legal reasoning, advice memo, negotiation position, or strategy support prepared for lawyer review. | Internal only | Must be marked draft. Must require lawyer approval before client delivery or reliance. |
| **Court-Facing Draft** | Draft material that may be filed, served, quoted, or relied on in litigation or tribunal/court processes. | Internal only | Must require source verification, hallucination checks, human approval, and disclosure review before any external use. |
| **Blocked / Escalate** | The system cannot safely answer or continue. | Internal and external | Must explain the safe reason at a high level and route to an authorized human reviewer. |

## 5. Source-Grounding Rules

### Approved source classes for this draft

- Official Federal Court and court/tribunal websites for relevant procedural requirements and notices.
- CanLII for Canadian cases, statutes, regulations, and legal commentary where appropriate.
- Ontario e-Laws for Ontario statutes and regulations.
- Official federal or provincial government sources for legislation, regulations, forms, and public guidance.
- Firm-approved internal knowledge sources after confidentiality and currency review.

### Claim-source compatibility

| Claim Type | Minimum Source Expectation | If Source Is Missing or Weak |
| --- | --- | --- |
| Statute or regulation text | Official source preferred, such as Ontario e-Laws for Ontario law or official federal sources for federal law. | Do not state as settled. Ask for permission to search approved sources or escalate. |
| Case law proposition | CanLII or official court source, plus pinpoint or clear case identification where available. | Mark as unverified and require lawyer review. |
| Court procedure or AI disclosure expectation | Official court website, practice direction, notice, or current procedural source. | Do not generate court-facing guidance as final. Escalate to internal review. |
| General legal education | Approved public legal information sources or official sources. | Present as general information only and include limits. |
| Matter-specific recommendation | Matter file plus approved legal authority, reviewed by lawyer. | Block external advice and route to lawyer. |

The product must not fabricate citations, imply a source says more than it does, or hide uncertainty. If the system cannot connect an answer to approved evidence, it must say so plainly.

## 6. Human Review Gates

Human review is mandatory before:

- Sending legal advice, opinion drafts, or strategy recommendations to a client.
- Using AI-generated content in court, tribunal, or litigation materials.
- Relying on a citation, quote, or legal proposition not verified against approved sources.
- Handling unclear privilege, confidentiality, conflict, limitation-period, urgent injunction, settlement, or rights-impacting issues.
- Providing any client-specific conclusion through the external client interface.
- Reusing client or matter information for training, evaluation, or product improvement beyond the approved retention and privacy policy.

Human review may be performed by an authorized lawyer or an approved delegate only where professional obligations and firm policy permit delegation.

## 7. Privacy and Confidentiality Controls

The product must support privacy-aware and confidentiality-preserving use of client and matter information.

Minimum controls:

- Collect only information needed for the stated legal workflow.
- Separate external client intake content from internal workbench materials by role and matter access.
- Show users when they are about to include personal information, sensitive documents, or privileged material.
- Prevent client data from being used for model training unless separately approved by policy and consent where required.
- Apply retention limits, deletion paths, and matter-level access controls.
- Maintain safeguards for personal information consistent with legal authority, necessity, proportionality, retention limits, and security expectations.
- Escalate when the system detects possible confidentiality, privilege, or conflict concerns.

## 8. Audit, Replay, and Evidence Requirements

For every material output, the system should preserve enough evidence for later review without over-collecting personal information.

Required audit fields:

- Matter or session identifier.
- User role and port used.
- Output label.
- Prompt or request summary.
- Sources retrieved, cited, or rejected.
- Version of source set or retrieval configuration.
- Model or workflow version.
- Human reviewer, approval status, and timestamp where review is required.
- Block/escalation reason when the system refuses or escalates.

Replay must allow an authorized reviewer to understand why an output was produced, which sources supported it, what uncertainty was disclosed, and whether required human review occurred.

## 9. Legal Safety and Control Matrix

| Risk | Control | User Experience Requirement | Launch Gate |
| --- | --- | --- | --- |
| Hallucinated legal authority | Source allowlist, citation verification, insufficient-evidence fallback | Show cited sources and uncertainty; never invent citations | Must pass citation accuracy checks on sampled outputs. |
| Unsupervised legal advice | Port separation, output labels, external advice block | External users receive education, triage, and escalation, not final advice | External interface must block matter-specific advice conclusions. |
| Court-facing misuse | Court-facing draft label, disclosure reminder, lawyer approval gate | Warn that litigation material needs human verification and disclosure review where applicable | No export path without approval and verification state. |
| Confidentiality leakage | Role-based access, intake segregation, warning on sensitive uploads | Make privacy/confidentiality handling visible before submission | Access controls and retention settings must be configured. |
| Out-of-scope jurisdiction | Ontario/Federal scope labels and jurisdiction checks | Ask user to confirm jurisdiction or escalate if outside scope | Out-of-scope answers must be blocked or marked unsupported. |
| Stale or weak source | Source freshness indicators and source-class ranking | Explain when a source may not be current or sufficient | Approved source list and freshness policy must be accepted. |
| Over-reliance by staff or clients | Human review gates and draft labels | Prominent labels and next-step prompts | Reviewer workflow must be tested end to end. |

## 10. MVP Workflow

1. User enters the correct port.
2. System confirms role, matter context, jurisdiction, and intended output label.
3. System checks whether the request is allowed for that port.
4. System retrieves or references approved sources.
5. System produces a labeled answer, risk summary, draft, or escalation.
6. System records audit evidence.
7. Human review is required for advice, opinion drafts, court-facing materials, and high-risk outputs.
8. Approved outputs may be shared, exported, or used according to firm policy.

## 11. Launch Acceptance Criteria

Launch may proceed only when all of the following are true:

- Stakeholders can identify which port they are using and what the port permits.
- Output labels are visible and consistently applied.
- External client interface blocks unsupervised legal advice and routes to human review.
- Internal workbench marks opinion and court-facing content as drafts until reviewed.
- Approved source classes are documented and tested against sample Ontario and Federal Canadian questions.
- Insufficient-evidence behavior is tested and produces safe escalation instead of confident unsupported answers.
- Human review gates are tested for advice, litigation/court-facing material, and sensitive client information.
- Audit/replay records show source grounding, model/workflow version, reviewer status, and block reasons.
- Privacy/confidentiality controls are documented, visible in the workflow, and reviewed by the appropriate internal owner.
- Stakeholder review confirms the artifact does not imply compliance certification, regulator approval, or autonomous legal practice.

## 12. Blocked-Launch Criteria

Launch must be blocked if any of the following remain unresolved:

- The external interface can produce client-specific legal advice without human review.
- The system can fabricate or present unverified legal citations as reliable authority.
- Court-facing drafts can be exported without source verification, disclosure review, and human approval state.
- Approved source classes, freshness expectations, or insufficient-evidence behavior are undefined.
- Privacy, confidentiality, retention, or access-control ownership is unresolved.
- Audit/replay evidence is insufficient to reconstruct material outputs and review decisions.
- Ontario/Federal scope limits are unclear or the product suggests broader jurisdictional coverage without review.
- Disclaimers, escalation paths, or reviewer responsibilities are missing.

## 13. Phased Delivery

### Phase 1: Controlled Documentation and Prototype

- Finalize this PRD with legal, operations, product, and privacy reviewers.
- Define approved source list, output labels, disclaimers, retention rules, and reviewer roles.
- Prototype internal-only workflows using non-production or approved test matters.

### Phase 2: Internal Workbench Pilot

- Pilot source-backed summaries, risk summaries, and opinion drafts with lawyer review.
- Test audit/replay evidence and reviewer approval records.
- Measure citation accuracy, escalation quality, and user understanding of labels.

### Phase 3: External Client Interface Pilot

- Enable client education and intake flows only after external advice blocks are verified.
- Validate escalation routing, confidentiality warnings, and role/matter access separation.
- Review client-facing language with legal, privacy, and operations owners.

### Phase 4: Limited Production Release

- Release only for approved Ontario and Federal Canadian workflows.
- Monitor blocked requests, source failures, reviewer overrides, and user confusion.
- Expand scope only after separate legal, privacy, and operational review.

## 14. Open Decisions Before Production

- MVP practice areas and excluded practice areas.
- Final approved source list and source freshness policy.
- Final disclaimer and client-facing escalation wording.
- Vendor/model approval policy.
- Retention and deletion schedule.
- Human-review thresholds, reviewer roles, and escalation ownership.
- Testing set for Ontario and Federal Canadian legal workflows.
