export const meta = {
  name: 'tier2-live-probe-gate',
  description:
    'Tier-2 live verification for the governance-hub claim: fan out read-only probes against the deployed site (agent-readable surface, hero copy, robots/ai-train stance, privileged console-origin redirect), then aggregate FAIL-CLOSED — publish stays blocked unless every required probe passes against live behavior.',
  whenToUse:
    "Run AFTER W4 ops lands (DNS cutover + Cloudflare). Until then it WILL fail — that is correct fail-closed behavior, and the report tells you exactly which live preconditions are still missing. Override target with args:{domain:'acgs.ai'}; tune robots expectation with args:{aiTrainExpectation:'disallow'|'allow'|'either'}.",
  phases: [{ title: 'Probe' }, { title: 'Aggregate' }],
}

// ── args normalization ───────────────────────────────────────────────────────
const input =
  typeof args === 'string'
    ? (() => {
        try {
          return JSON.parse(args)
        } catch {
          return { domain: args }
        }
      })()
    : args

// ── Shell/prompt-safety for values embedded in probe URLs & prompt snippets ──
// Each probe sub-agent is handed a PROMPT that interpolates these arg-derived
// values (the target URL, the console origin, the robots expectation) directly
// into instruction text it then acts on with WebFetch. Taken raw they enable two
// failure modes:
//   1. SHELL injection — a value with a quote / ; / $() / backtick could break
//      out of any command a sub-agent is told to run (this gate is read-only, but
//      defense in depth still applies wherever a value reaches a command).
//   2. PROMPT injection — a value with a newline can inject new instructions into
//      the sub-agent's prompt, or repoint the URL it fetches. Shell-quoting does
//      NOT stop this.
// So: VALIDATE first (fail closed — refuse to run on anything outside a narrow
// allowlist, which also rejects control chars / newlines), shell-quote second
// (defense in depth) wherever a value is embedded in a command. These values flow
// into prompt/URL text only (no shell command), so they are validated, not shq'd.
const shq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`
function assertShellSafe(value, label, allowed) {
  const s = String(value)
  if (!allowed.test(s)) {
    throw new Error(
      `tier2-live-probe-gate: refusing to run — \`${label}\` = ${JSON.stringify(s)} ` +
        `contains characters unsafe to embed in a probe command/prompt (allowed: ${allowed}). ` +
        `This gate fails closed rather than emit a command a sub-agent could be tricked into ` +
        `mis-running, or a prompt it could be tricked into mis-reading.`
    )
  }
}

// A bare hostname (default 'acgs.ai') never legitimately needs a quote/space/;/$/
// backtick/newline. The filesystem-path allowlist admits domain chars and rejects
// every shell metachar and control char.
const DOMAIN = input?.domain ?? 'acgs.ai'
assertShellSafe(DOMAIN, 'domain', /^[A-Za-z0-9._/-]+$/)
const ORIGIN = `https://${DOMAIN}`
// Where /console must 308 to (privileged origin stays isolated even live).
// A full URL (default 'https://console.acgs.ai') needs ':' and '/' — the pathspec
// allowlist admits both while still rejecting quotes/space/;/$/backtick/newline.
const CONSOLE_ORIGIN = input?.consoleOrigin ?? 'https://console.acgs.ai'
assertShellSafe(CONSOLE_ORIGIN, 'consoleOrigin', /^[A-Za-z0-9._/:*!()-]+$/)
// Open product decision #4: what robots/ai-train stance do we EXPECT?
//   'disallow' = expect AI crawlers blocked · 'allow' = expect allowed · 'either' = report only.
// A short slug — the slug allowlist fits the three legitimate values exactly.
const AI_TRAIN_EXPECTATION = input?.aiTrainExpectation ?? 'either'
assertShellSafe(AI_TRAIN_EXPECTATION, 'aiTrainExpectation', /^[A-Za-z0-9._-]+$/)

// ── The probe set ─────────────────────────────────────────────────────────────
// required:true probes gate publishing. A required probe that fails (or cannot be
// evaluated) blocks the gate. 'advisory' probes are reported, not gating.
const PROBES = [
  {
    key: 'llms-txt',
    required: true,
    url: `${ORIGIN}/llms.txt`,
    assert:
      'HTTP 200; Content-Type is text/plain (NOT text/html); body is the agent-readable governance framework (plain text), not the SPA HTML shell (must not start with "<!doctype html>"). ok=true only if all hold.',
  },
  {
    key: 'governance-framework-txt',
    required: true,
    url: `${ORIGIN}/governance-framework.txt`,
    assert:
      'HTTP 200; Content-Type text/plain; body is the framework rules in plain text, not HTML. ok=true only if all hold.',
  },
  {
    key: 'hero-page',
    required: true,
    url: `${ORIGIN}/`,
    assert:
      'HTTP 200; Content-Type text/html; the served HTML contains the sibling governance block (id="agent-governance") AND a pointer to /llms.txt. ok=true only if the page loads and the agent-discoverable block is present.',
  },
  {
    key: 'console-redirect',
    required: true,
    url: `${ORIGIN}/console`,
    assert: `A 308 (or 30x) redirect whose Location targets the privileged console origin (${CONSOLE_ORIGIN}). The marketing origin must NOT itself serve console content. ok=true only if it redirects to the console origin; ok=false if it 200s with console markup (privileged-origin leak) or does not redirect.`,
  },
  {
    key: 'robots-ai-train',
    required: false,
    url: `${ORIGIN}/robots.txt`,
    assert: `Report the robots.txt directives, specifically any AI-crawler / ai-train / GPTBot / training rules. Expectation = "${AI_TRAIN_EXPECTATION}": if 'disallow', ok=true when AI crawlers are blocked; if 'allow', ok=true when permitted; if 'either', ok=true as long as robots.txt is served (stance is reported, not gated).`,
  },
  {
    key: 'internal-docs-404',
    required: true,
    url: `${ORIGIN}/CLAUDE.md`,
    assert:
      'Internal instruction docs must NOT be publicly served. Expect HTTP 404 (or 30x to a 404). ok=true only if CLAUDE.md is not retrievable as content; ok=false if it returns 200 with the file body (information leak).',
  },
]

// ── structured-output contract ────────────────────────────────────────────────
const PROBE_RESULT = {
  type: 'object',
  required: ['key', 'ok', 'httpStatus'],
  properties: {
    key: { type: 'string' },
    // ok = the live behavior matched the assertion. Default to false on any doubt.
    ok: { type: 'boolean' },
    httpStatus: { type: 'integer' }, // 0 if the request could not be made at all
    contentType: { type: 'string' },
    // The single most relevant observed fact (redirect target, first bytes, a directive).
    evidence: { type: 'string' },
    // Why it failed / what is still missing, if ok=false.
    finding: { type: 'string' },
  },
}

// ── Probe prompt ──────────────────────────────────────────────────────────────
const probePrompt = (p) => `You are running ONE read-only liveness probe against a deployed website to verify a published governance claim holds in production.

STRICT BOUNDARIES:
- Use an HTTP GET (or HEAD) ONLY via the WebFetch tool. NO POST/PUT/DELETE, no form submission, no authentication, no side effects. You are observing, not changing anything.
- Probe ONLY this one URL:  ${p.url}

ASSERTION TO EVALUATE:
${p.assert}

PROCEDURE:
1. Fetch ${p.url}. Record the HTTP status (use 0 if the request could not be completed at all — DNS failure, connection refused, timeout). Record the Content-Type header if available.
2. Inspect the body/headers ONLY as far as needed to evaluate the assertion above. Capture the single most relevant piece of evidence (e.g. the redirect Location, the first ~80 bytes of the body, the matched/missing marker, the robots directive).
3. Decide ok: true ONLY if the live response genuinely satisfies the assertion. Default ok=false whenever you are uncertain, the host is unreachable, or the evidence is ambiguous — this is a fail-CLOSED gate.
4. If ok=false, put the concrete reason / what is still missing in the "finding" field.

Set key="${p.key}". Report ONLY what the live response actually showed — never assume the deploy is up. If DNS/connection failed, that is httpStatus=0, ok=false, finding="host unreachable (W4 ops not yet live?)".`

// ── Orchestration: fan-out probes → fail-closed aggregate ─────────────────────
// Probes are independent → run them all in parallel. The aggregate genuinely needs
// EVERY probe result at once to decide publish-allowed, so the barrier is correct.
log(`tier2-live-probe-gate: ${PROBES.length} probes against ${ORIGIN} (ai-train expectation: ${AI_TRAIN_EXPECTATION})`)

phase('Probe')
// Inherit the session model (do NOT drop to haiku): a small model unreliably calls
// the forced StructuredOutput tool and silently returns null. A dropped probe is
// counted as a failed REQUIRED probe below (fail-closed — safe direction), but a
// tooling drop would surface as a false BLOCK and be misread as "deploy not live".
// The aggregate distinguishes a dropped probe (evaluated=false) from a genuine
// assertion failure, but paying for a reliable schema avoids the ambiguity at the
// source. Each probe is one WebFetch GET — requires the workflow subagent to carry
// the WebFetch tool; if it does not, every probe fails-closed (see `evaluated`).
const results = (
  await parallel(
    PROBES.map((p) => () =>
      agent(probePrompt(p), {
        label: `probe:${p.key}`,
        phase: 'Probe',
        schema: PROBE_RESULT,
      }).then((r) => (r ? { ...r, key: r.key || p.key, required: p.required, url: p.url } : null)),
    ),
  )
).filter(Boolean)

phase('Aggregate')
// Index by probe key so a dropped/skipped agent is treated as a FAILED required
// probe, never silently as a pass.
const byKey = new Map(results.map((r) => [r.key, r]))

const required = PROBES.filter((p) => p.required)
const advisory = PROBES.filter((p) => !p.required)

const requiredStatus = required.map((p) => {
  const r = byKey.get(p.key)
  return {
    key: p.key,
    url: p.url,
    // No result at all = not verified = fail-closed.
    ok: !!r && r.ok === true,
    evaluated: !!r,
    httpStatus: r?.httpStatus ?? 0,
    evidence: r?.evidence ?? '',
    finding: r ? r.finding || '' : 'probe produced no result (agent skipped/crashed) — treated as failed',
  }
})

const advisoryStatus = advisory.map((p) => {
  const r = byKey.get(p.key)
  return {
    key: p.key,
    url: p.url,
    ok: !!r && r.ok === true,
    evaluated: !!r,
    httpStatus: r?.httpStatus ?? 0,
    evidence: r?.evidence ?? '',
    finding: r?.finding ?? '',
  }
})

// FAIL-CLOSED: publish is allowed ONLY when every required probe was evaluated AND passed.
const requiredPassed = requiredStatus.filter((r) => r.ok).length
const publishAllowed = requiredStatus.every((r) => r.ok)

const blocking = requiredStatus
  .filter((r) => !r.ok)
  .map((r) => ({ key: r.key, url: r.url, httpStatus: r.httpStatus, reason: r.finding || 'assertion not satisfied' }))

log(
  `tier2-live-gate: required ${requiredPassed}/${requiredStatus.length} passed · ` +
    `advisory ${advisoryStatus.filter((a) => a.ok).length}/${advisoryStatus.length} · → publish ${
      publishAllowed ? 'ALLOWED (live preconditions met)' : 'BLOCKED (fail-closed)'
    }`,
)

return {
  // The gate verdict. Note: until W4 ops (DNS + Cloudflare) lands this is expected
  // to be false — the blocking[] list then enumerates the missing live preconditions.
  publishAllowed,
  origin: ORIGIN,
  consoleOrigin: CONSOLE_ORIGIN,
  aiTrainExpectation: AI_TRAIN_EXPECTATION,
  summary: {
    requiredTotal: requiredStatus.length,
    requiredPassed,
    advisoryTotal: advisoryStatus.length,
    advisoryPassed: advisoryStatus.filter((a) => a.ok).length,
    droppedProbes: PROBES.length - results.length,
  },
  blocking,
  required: requiredStatus,
  advisory: advisoryStatus,
  note:
    'Tier-2 is one of three publish preconditions. Even publishAllowed=true here does NOT clear the claim: claim-matrix.json still requires legal signoff (publicDeployAllowed:false) and Tier-1 (claim-verify-pipeline) must be green.',
}
