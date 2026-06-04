# Claim Validation

`claim-matrix.json` is the engineering control for public trust, security,
privacy, accessibility, and compliance wording in `acgi-ai`.

Current status: `engineering_draft_pending_legal`. The matrix is not legal
approval, production proof, third-party certification, WCAG conformance, or
SOC 2 attestation. Every claim remains `publicDeployAllowed=false` until the
named reviewer signs off the exact wording and evidence state.

## Local Gate

Run:

```bash
pnpm -F acgi-ai run test:claim-matrix
```

For the trust-center surface, also run:

```bash
pnpm -F acgi-ai run audit:eval
```

The claim-matrix gate fails closed when:

- public copy uses blocked overclaim phrases before signoff
- required claim IDs are missing
- claim wording uses compliance, certification, guarantee, or production-ready
  language
- an evidence file or source file is missing
- an evidence anchor is empty or is not an exact substring of the cited file
- owner, reviewer, next review date, or `publicDeployAllowed=false` is missing
- package script wiring drops `test:claim-matrix` from `test:all`
- this validation document stops covering the required claim IDs

## Evidence Rules

Evidence anchors must quote an exact, durable substring from the cited file.
Do not use conceptual labels such as "production auth proof" unless that exact
text appears in the file. Prefer anchors from primary local contracts, scripts,
config, generated manifests, or signed external evidence.

Use evidence states conservatively:

- `config`: local config or static verifier evidence exists
- `stubbed`: local scaffolding exists, but live proof is absent
- `manual_required`: manual reviewer evidence is required before stronger copy
- `external_required`: legal, production, third-party, or live environment proof
  is still outside the local codebase
- `live`: only use when deployed live evidence is present and cited

Previous knowledge is preserved by updating the matrix entry with a new anchor,
state, reviewer, and review date rather than silently replacing the claim with
stronger wording.

## Required Claims

| Claim ID | Evidence boundary |
| --- | --- |
| `subprocessor-boundary` | Marketing/console hosting split, RSS draft status, and legal review gate |
| `console-privilege-boundary` | Surface bundle split, console-only sentinels, and privileged console origin |
| `audit-retention` | Audit-retention target plus external storage/legal proof gap |
| `regulatory-positioning` | Mapping and evidence workflow wording only, no regulatory satisfaction claim |
| `production-auth-boundary` | Demo-session production block plus external auth provider requirement |
| `console-csp-and-headers` | Caddy CSP/header config plus live postdeploy proof requirement |
| `font-provenance` | Self-hosted font references and committed SHA-256 manifest |
| `bus-proxy-boundary` | Same-origin `/api/*` bus proxy, schema-version header, and fail-closed upstream |
| `wcag-manual-evidence` | Local accessibility foundation plus required manual screen-reader evidence |
| `soc2-roadmap` | Roadmap/control-mapping wording only, no attestation or certification claim |

## Launch Thesis Claim

| Claim ID | Evidence boundary |
| --- | --- |
| `gove-zone-runtime-governance-plane` | Alpha receipt-gated runtime governance claim, backed by package architecture/security docs and proof-pack command source; local runtime evidence only, with production, assurance, signing, MACI, and sandboxing caveats attached |

## Update Procedure

1. Edit public copy with conservative wording first.
2. Add or update the claim matrix entry with source files, exact evidence
   anchors, owner, reviewer, evidence state, and review date.
3. Keep `publicDeployAllowed=false` unless legal review has explicitly signed
   off and the evidence is live or otherwise independently verified.
4. Run `pnpm -F acgi-ai run test:claim-matrix`.
5. Run `pnpm -F acgi-ai run audit:eval` when trust, security, SOC 2, DPA,
   subprocessors, or security-contact copy changed.
