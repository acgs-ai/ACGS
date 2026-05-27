#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const repoRoot = resolve(root, '..')
const DEFAULT_BUYER_MANIFEST = 'dist-buyer-evidence/manifest.json'
const DEFAULT_LIVE_OUTPUT = '../dist-release-evidence/production-live-verification.json'
const DEFAULT_OUT = '../dist-release-evidence/hosted-storybook-handoff.json'
const STORYBOOK_TARGET = 'https://storybook.acgs.ai'
const STORYBOOK_MANIFEST_URL = 'https://storybook.acgs.ai/manifest.json'
const COMMAND_TEMPLATE =
  'pnpm -F acgi-ai run build:hosted-storybook-handoff -- --buyer-evidence-manifest <dist-buyer-evidence/manifest.json> --live-output <verify-production-live.json> --out <hosted-storybook-handoff.json>'
const CLAIM_BOUNDARY =
  'Hosted Storybook handoff is generated from local files only; it does not deploy, mutate DNS, fetch live origins, install the official Storybook runtime, validate legal/SOC2/WCAG/pentest/regulatory claims, or create hosted Storybook proof; it is not live production proof.'
const STORYBOOK_BLOCKER_IDS = new Set([
  'live-storybook-dns',
  'live-storybook-https',
  'live-storybook-manifest',
])

function usage() {
  return `Usage: node scripts/build-hosted-storybook-handoff.mjs [options]

Builds a local hosted-storybook-handoff artifact from the buyer-evidence manifest,
Storybook Pages workflow, and optional verify:production-live JSON. This command
performs local file I/O only: it does not deploy, mutate DNS, fetch live origins,
install Storybook, or create hosted Storybook proof.

Options:
  --buyer-evidence-manifest <path>  Local buyer evidence manifest (default: ${DEFAULT_BUYER_MANIFEST})
  --live-output <path>              Optional verify:production-live JSON (default: ${DEFAULT_LIVE_OUTPUT} when present)
  --out <path>                      Write handoff JSON to this path (default: ${DEFAULT_OUT})
  --json                            Print machine-readable JSON to stdout
  --require-live-clear              Exit non-zero when Storybook live blockers remain or live output is absent
  --help                            Show this help
`
}

function parseArgs(argv) {
  const options = {
    buyerManifestPath: DEFAULT_BUYER_MANIFEST,
    liveOutputPath: DEFAULT_LIVE_OUTPUT,
    outPath: DEFAULT_OUT,
    json: false,
    requireLiveClear: false,
    help: false,
  }

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]
    const next = () => {
      index += 1
      if (index >= argv.length) throw new Error(`${arg} requires a value`)
      return argv[index]
    }

    if (arg === '--') continue
    else if (arg === '--buyer-evidence-manifest') options.buyerManifestPath = next()
    else if (arg === '--live-output') options.liveOutputPath = next()
    else if (arg === '--out') options.outPath = next()
    else if (arg === '--json') options.json = true
    else if (arg === '--require-live-clear') options.requireLiveClear = true
    else if (arg === '--help' || arg === '-h') options.help = true
    else throw new Error(`Unknown option: ${arg}`)
  }
  return options
}

function readText(path, label, { optional = false, fromRepoRoot = false } = {}) {
  const base = fromRepoRoot ? repoRoot : root
  try {
    return readFileSync(resolve(base, path), 'utf8')
  } catch (error) {
    if (optional && error.code === 'ENOENT') return null
    throw new Error(`Could not read ${label} ${path}: ${error.message}`)
  }
}

function readJson(path, label, options = {}) {
  const text = readText(path, label, options)
  if (text === null) return null
  try {
    return JSON.parse(text)
  } catch (error) {
    throw new Error(`Could not parse ${label} JSON ${path}: ${error.message}`)
  }
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0
}

function compactStory(story) {
  return {
    id: story.id,
    title: story.title,
    route: story.route,
    localGates: Array.isArray(story.localGates) ? story.localGates : [],
    sourceFiles: Array.isArray(story.sourceFiles) ? story.sourceFiles : [],
  }
}

function compactBlocker(blocker) {
  return {
    blockerId: blocker.blockerId,
    checkId: blocker.checkId ?? null,
    status: blocker.status ?? 'fail',
    area: blocker.area ?? 'Hosted Storybook buyer evidence',
    requiredAction:
      blocker.requiredAction ??
      'Resolve the hosted Storybook live verifier failure and rerun verify:production-live.',
    error: blocker.error ?? null,
    evidence: blocker.evidence && typeof blocker.evidence === 'object' ? blocker.evidence : {},
  }
}

function storybookBlockers(liveOutput) {
  const blockers = Array.isArray(liveOutput?.blockers) ? liveOutput.blockers : []
  return blockers
    .filter((blocker) => blocker && STORYBOOK_BLOCKER_IDS.has(blocker.blockerId))
    .map(compactBlocker)
}

function storybookCheckStatuses(liveOutput) {
  const checks = Array.isArray(liveOutput?.checks) ? liveOutput.checks : []
  return checks
    .filter((check) => String(check?.id ?? '').startsWith('storybook-'))
    .map((check) => ({ id: check.id, status: check.status, error: check.error ?? null }))
}

function workflowHasPublicationContract(workflow) {
  return [
    'name: buyer-evidence-storybook',
    'ACGI_EVIDENCE_CNAME: storybook.acgs.ai',
    'actions/upload-pages-artifact@v3',
    'actions/deploy-pages@v4',
    "vars.STORYBOOK_PAGES_ENABLED == 'true'",
    'url: https://storybook.acgs.ai',
  ].every((needle) => workflow.includes(needle))
}

function buildHandoff({ buyerManifest, liveOutput, workflow, options }) {
  if (buyerManifest?.artifactKind !== 'local-buyer-evidence-gallery') {
    throw new Error('buyer evidence manifest artifactKind must be local-buyer-evidence-gallery')
  }
  if (liveOutput && liveOutput.artifactKind !== 'production-live-verification') {
    throw new Error('live output artifactKind must be production-live-verification')
  }

  const workflowReady = workflowHasPublicationContract(workflow)
  const publishTargetReady = buyerManifest.publishTarget === STORYBOOK_TARGET
  const stories = Array.isArray(buyerManifest.stories) ? buyerManifest.stories.map(compactStory) : []
  const storyIds = stories.map((story) => story.id).filter(isNonEmptyString)
  const blockers = storybookBlockers(liveOutput)
  const checkStatuses = storybookCheckStatuses(liveOutput)
  const liveStatus = liveOutput?.status ?? null
  const status =
    liveStatus === 'pass' && blockers.length === 0 && publishTargetReady && workflowReady
      ? 'live-verifier-clear'
      : publishTargetReady && workflowReady
        ? 'blocked'
        : 'operator-preflight'

  return {
    schemaVersion: 1,
    artifactKind: 'hosted-storybook-handoff',
    generatedAt: new Date().toISOString(),
    status,
    claimBoundary: CLAIM_BOUNDARY,
    command: COMMAND_TEMPLATE,
    target: {
      url: STORYBOOK_TARGET,
      manifestUrl: STORYBOOK_MANIFEST_URL,
      requiredRepoVariable: 'STORYBOOK_PAGES_ENABLED=true',
      requiredWorkflow: '.github/workflows/storybook.yml',
      requiredArtifactName: 'buyer-evidence-storybook',
      dns: {
        host: 'storybook.acgs.ai',
        type: 'CNAME',
        target: 'GitHub Pages custom domain target for this repository',
      },
    },
    localPublication: {
      manifestPath: options.buyerManifestPath,
      artifactKind: buyerManifest.artifactKind,
      publishTarget: buyerManifest.publishTarget,
      publishTargetReady,
      storyIds,
      stories,
      claimBoundary: buyerManifest.claimBoundary,
    },
    workflow: {
      path: '.github/workflows/storybook.yml',
      ready: workflowReady,
      pagesDeployGatedBy: 'vars.STORYBOOK_PAGES_ENABLED == true',
      claimBoundary:
        'Workflow presence is local configuration evidence only; hosted proof requires a successful external Pages deploy and live verifier pass.',
    },
    liveVerification: {
      liveOutputPath: options.liveOutputPath,
      productionLiveStatus: liveStatus,
      storybookCheckStatuses: checkStatuses,
      storybookBlockers: blockers,
      blockedUntil:
        blockers.length > 0 || liveStatus !== 'pass'
          ? 'Publish the Pages artifact, configure storybook.acgs.ai DNS/HTTPS, then rerun verify:production-live until storybook-dns-live, storybook-https-live, and storybook-manifest-live pass.'
          : null,
    },
    copyIntoProductionEvidence: {
      hostedStorybook: {
        url: STORYBOOK_TARGET,
        manifestUrl: STORYBOOK_MANIFEST_URL,
        status: status === 'live-verifier-clear' ? 'verified' : 'pending',
        proofRef:
          status === 'live-verifier-clear'
            ? '<successful Storybook Pages deploy URL plus passing verify:production-live JSON>'
            : 'pending-external:storybook-pages-proof',
        claimBoundary:
          status === 'live-verifier-clear'
            ? 'verified only by attached live Storybook proof and passing live verifier JSON.'
            : 'pending means this file does not prove hosted Storybook buyer evidence.',
      },
      remainingBlocker: status === 'live-verifier-clear' ? null : 'hosted-storybook-buyer-evidence',
    },
    operatorNextSteps: [
      'Build the buyer evidence artifact with ACGI_EVIDENCE_CNAME=storybook.acgs.ai so manifest publishTarget is https://storybook.acgs.ai and CNAME is present.',
      'Enable STORYBOOK_PAGES_ENABLED=true only for the intended repository/environment and confirm GitHub Pages custom-domain settings.',
      'Configure storybook.acgs.ai DNS for the GitHub Pages custom-domain target.',
      'Run the buyer-evidence-storybook workflow on master and attach the Pages deploy URL plus buyer-evidence-storybook artifact.',
      'Rerun pnpm -F acgi-ai run verify:production-live -- --json and require storybook-dns-live, storybook-https-live, and storybook-manifest-live to pass before claiming hosted Storybook proof.',
    ],
  }
}

function printHuman(handoff, outPath) {
  console.log(`Hosted Storybook handoff: ${handoff.status}`)
  console.log(CLAIM_BOUNDARY)
  if (outPath) console.log(`Wrote ${outPath}`)
  console.log(`Target: ${handoff.target.url}`)
  console.log(`Story ids: ${handoff.localPublication.storyIds.join(', ')}`)
  const blockers = handoff.liveVerification.storybookBlockers.map((blocker) => blocker.blockerId)
  console.log(`Storybook blockers: ${blockers.join(', ') || 'none'}`)
}

function main() {
  let options
  try {
    options = parseArgs(process.argv.slice(2))
    if (options.help) {
      console.log(usage())
      return
    }
    const buyerManifest = readJson(options.buyerManifestPath, 'buyer evidence manifest')
    const liveOutput = readJson(options.liveOutputPath, 'live output', { optional: true })
    const workflow = readText('.github/workflows/storybook.yml', 'Storybook workflow', {
      fromRepoRoot: true,
    })
    const handoff = buildHandoff({ buyerManifest, liveOutput, workflow, options })
    const encoded = `${JSON.stringify(handoff, null, 2)}\n`
    if (options.outPath) writeFileSync(resolve(root, options.outPath), encoded)
    if (options.json || !options.outPath) process.stdout.write(encoded)
    else printHuman(handoff, options.outPath)
    if (options.requireLiveClear && handoff.status !== 'live-verifier-clear') process.exit(1)
  } catch (error) {
    if (options?.json) {
      process.stdout.write(
        `${JSON.stringify(
          {
            schemaVersion: 1,
            artifactKind: 'hosted-storybook-handoff-error',
            status: 'fail',
            error: error.message,
            claimBoundary: CLAIM_BOUNDARY,
          },
          null,
          2,
        )}\n`,
      )
    } else {
      console.error(error.message)
      console.error(usage())
    }
    process.exit(1)
  }
}

main()
