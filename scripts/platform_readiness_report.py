#!/usr/bin/env python3
"""Local platform-readiness audit for the governed AI platform goal.

This report is intentionally conservative. It proves repo-local readiness
surfaces and records external blockers, but it does not treat local green
checks as production deployment proof.

Usage:
    python scripts/platform_readiness_report.py
    python scripts/platform_readiness_report.py --json
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class ReadinessItem:
    item_id: str
    title: str
    status: str  # "pass" | "fail" | "pending"
    evidence: str
    command: str

    @property
    def icon(self) -> str:
        return {"pass": "✅", "fail": "❌", "pending": "⏳"}.get(self.status, "?")


def _read(repo_root: Path, relative_path: str) -> str:
    return (repo_root / relative_path).read_text()


def _maybe_read(repo_root: Path, relative_path: str) -> str:
    path = repo_root / relative_path
    return path.read_text() if path.is_file() else ""


def _load_json(repo_root: Path, relative_path: str) -> dict[str, Any]:
    return json.loads(_read(repo_root, relative_path))


def _all_files_exist(repo_root: Path, paths: list[str]) -> tuple[bool, list[str]]:
    missing = [path for path in paths if not (repo_root / path).is_file()]
    return not missing, missing


def _contains_all(source: str, needles: list[str]) -> tuple[bool, list[str]]:
    missing = [needle for needle in needles if needle not in source]
    return not missing, missing


def _item(
    item_id: str,
    title: str,
    ok: bool,
    evidence: str,
    command: str,
    *,
    pending: bool = False,
) -> ReadinessItem:
    status = "pending" if pending else "pass" if ok else "fail"
    return ReadinessItem(item_id, title, status, evidence, command)


def build_items(repo_root: Path = REPO_ROOT) -> list[ReadinessItem]:
    """Build the local readiness checklist from current repo state."""

    items: list[ReadinessItem] = []

    core_docs = [
        "README.md",
        "MONOREPO.md",
        "docs/governance-stack-index.md",
        "docs/integration-readiness-task-map.md",
    ]
    docs_exist, missing_docs = _all_files_exist(repo_root, core_docs)
    readme = _maybe_read(repo_root, "README.md")
    docs_linked, missing_links = _contains_all(
        readme,
        ["MONOREPO.md", "docs/governance-stack-index.md", "make verify"],
    )
    items.append(
        _item(
            "local-evidence-spine",
            "Root evidence spine and onboarding map exist",
            docs_exist and docs_linked,
            (
                "core docs present and README routes to registry/index/gates"
                if docs_exist and docs_linked
                else f"missing_files={missing_docs}, missing_readme_links={missing_links}"
            ),
            "make lint-docs",
        )
    )

    makefile = _maybe_read(repo_root, "Makefile")
    package_json = _load_json(repo_root, "acgi-ai/package.json")
    openapi_block = ""
    if "openapi:" in makefile:
        openapi_block = makefile.split("openapi:", 1)[1].split("\nclean:", 1)[0]
    openapi_ok, openapi_missing = _contains_all(
        openapi_block,
        [
            "agent-bus-analyzer export-openapi --output acgi-ai/contracts/bus.openapi.json",
            "biome format --write contracts/bus.openapi.json",
            "cp acgi-ai/contracts/bus.openapi.json acgi-ai/src/api/openapi.json",
            "$(PNPM) -F acgi-ai run gen:api",
        ],
    )
    expected_gen_api = (
        "openapi-typescript contracts/bus.openapi.json -o src/api/bus.generated.ts "
        "&& biome format --write src/api/bus.generated.ts"
    )
    gen_api_ok = package_json.get("scripts", {}).get("gen:api") == expected_gen_api
    schema_files_ok, schema_missing = _all_files_exist(
        repo_root,
        [
            "acgi-ai/contracts/bus.openapi.json",
            "acgi-ai/src/api/openapi.json",
            "acgi-ai/src/api/bus.generated.ts",
            "acgi-ai/scripts/check-bus-schema-contract.mjs",
        ],
    )
    items.append(
        _item(
            "bus-contract-regeneration",
            "Bus OpenAPI source of truth regenerates contract, mirror, and types",
            openapi_ok and gen_api_ok and schema_files_ok,
            (
                "make openapi exports contract, refreshes mirror, and runs gen:api"
                if openapi_ok and gen_api_ok and schema_files_ok
                else (
                    f"missing_make_parts={openapi_missing}, gen_api_ok={gen_api_ok}, "
                    f"missing_files={schema_missing}"
                )
            ),
            "make openapi && pnpm -F acgi-ai run test:bus-schema",
        )
    )

    deploy_files = [
        "acgi-ai/infra/Caddyfile",
        "acgi-ai/infra/Dockerfile.console",
        "acgi-ai/infra/cloudrun/service.preview.yaml",
        "acgi-ai/infra/cloudrun/service.staging.yaml",
        "acgi-ai/infra/cloudrun/service.production.yaml",
        "acgi-ai/scripts/postdeploy-verify.sh",
    ]
    deploy_files_ok, deploy_missing = _all_files_exist(repo_root, deploy_files)
    deploy_scripts = package_json.get("scripts", {})
    deploy_scripts_ok = all(
        key in deploy_scripts
        for key in [
            "verify:postdeploy",
            "test:cloudrun-templates",
            "test:cloudrun-renderer",
            "test:container-pins",
            "test:postdeploy-live-assets",
        ]
    )
    items.append(
        _item(
            "deploy-contracts-local",
            "Local deploy contract files and post-deploy checks are present",
            deploy_files_ok and deploy_scripts_ok,
            (
                "Cloud Run/Caddy/container/postdeploy proof surfaces are wired"
                if deploy_files_ok and deploy_scripts_ok
                else f"missing_files={deploy_missing}, deploy_scripts_ok={deploy_scripts_ok}"
            ),
            "pnpm -F acgi-ai run test:cloudrun-templates && "
            "pnpm -F acgi-ai run test:cloudrun-renderer && "
            "pnpm -F acgi-ai run test:container-pins && "
            "pnpm -F acgi-ai run test:postdeploy-live-assets",
        )
    )

    cloudrun_renderer_files_ok, cloudrun_renderer_missing = _all_files_exist(
        repo_root,
        [
            "acgi-ai/scripts/render-cloudrun-service.mjs",
            "acgi-ai/scripts/check-cloudrun-renderer.mjs",
            ".github/workflows/console.yml",
        ],
    )
    cloudrun_renderer_ok, cloudrun_renderer_missing_parts = _contains_all(
        "\n".join(
            [
                _maybe_read(repo_root, "acgi-ai/scripts/render-cloudrun-service.mjs"),
                _maybe_read(repo_root, "acgi-ai/scripts/check-cloudrun-renderer.mjs"),
                _maybe_read(repo_root, ".github/workflows/console.yml"),
                _maybe_read(repo_root, "docs/integration-readiness-task-map.md"),
                _maybe_read(repo_root, "acgi-ai/DEPLOY.md"),
            ]
        ),
        [
            "replaceExactlyOnce",
            "rendered service.yaml still contains REPLACE_* placeholders",
            "must start with http:// or https://",
            "node scripts/render-cloudrun-service.mjs",
            "test:cloudrun-renderer",
            "Shared Cloud Run renderer",
        ],
    )
    cloudrun_renderer_scripts_ok = (
        deploy_scripts.get("render:cloudrun") == "node scripts/render-cloudrun-service.mjs"
        and deploy_scripts.get("test:cloudrun-renderer")
        == "node scripts/check-cloudrun-renderer.mjs"
        and "pnpm run test:cloudrun-renderer" in deploy_scripts.get("test:contract", "")
        and "pnpm run test:cloudrun-renderer" in deploy_scripts.get("test:all", "")
    )
    items.append(
        _item(
            "cloudrun-renderer-local",
            "Cloud Run service rendering is deterministic and fail-closed",
            cloudrun_renderer_files_ok and cloudrun_renderer_ok and cloudrun_renderer_scripts_ok,
            (
                "shared renderer proves image/build/auth/bus substitution before deploy"
                if cloudrun_renderer_files_ok
                and cloudrun_renderer_ok
                and cloudrun_renderer_scripts_ok
                else (
                    f"missing_files={cloudrun_renderer_missing}, "
                    f"missing_parts={cloudrun_renderer_missing_parts}, "
                    f"scripts_ok={cloudrun_renderer_scripts_ok}"
                )
            ),
            "pnpm -F acgi-ai run test:cloudrun-renderer",
        )
    )

    production_deploy_files_ok, production_deploy_missing = _all_files_exist(
        repo_root,
        [
            ".github/workflows/marketing.yml",
            ".github/workflows/console.yml",
            "acgi-ai/scripts/check-production-deploy-contract.mjs",
        ],
    )
    production_deploy_ok, production_deploy_missing_parts = _contains_all(
        "\n".join(
            [
                _maybe_read(repo_root, ".github/workflows/marketing.yml"),
                _maybe_read(repo_root, ".github/workflows/console.yml"),
                _maybe_read(
                    repo_root,
                    "acgi-ai/scripts/check-production-deploy-contract.mjs",
                ),
                _maybe_read(repo_root, "docs/integration-readiness-task-map.md"),
                _maybe_read(repo_root, "acgi-ai/DEPLOY.md"),
            ]
        ),
        [
            "::error::Vercel production deploy blocked",
            "exit 1",
            "VERCEL_TOKEN",
            "VERCEL_ORG_ID",
            "VERCEL_PROJECT_ID",
            "CONSOLE_AUTH_UPSTREAM",
            "CONSOLE_BUS_UPSTREAM",
            "test:production-deploy-contract",
            "production deploy fail-closed",
        ],
    )
    production_deploy_scripts_ok = (
        deploy_scripts.get("test:production-deploy-contract")
        == "node scripts/check-production-deploy-contract.mjs"
        and "pnpm run test:production-deploy-contract" in deploy_scripts.get("test:all", "")
        and "pnpm run test:production-deploy-contract" in deploy_scripts.get("test:contract", "")
    )
    items.append(
        _item(
            "production-deploy-fail-closed-local",
            "Production deploy workflows fail closed when credentials are absent",
            production_deploy_files_ok and production_deploy_ok and production_deploy_scripts_ok,
            (
                "marketing push deploy errors on missing Vercel secrets; "
                "console deploy remains WIF/renderer/postdeploy gated"
                if production_deploy_files_ok
                and production_deploy_ok
                and production_deploy_scripts_ok
                else (
                    f"missing_files={production_deploy_missing}, "
                    f"missing_parts={production_deploy_missing_parts}, "
                    f"scripts_ok={production_deploy_scripts_ok}"
                )
            ),
            "pnpm -F acgi-ai run test:production-deploy-contract",
        )
    )

    production_launch_files_ok, production_launch_missing = _all_files_exist(
        repo_root,
        [
            "acgi-ai/PRODUCTION-LAUNCH.md",
            "acgi-ai/scripts/check-production-launch-handoff.mjs",
            ".github/workflows/console.yml",
            ".github/workflows/marketing.yml",
        ],
    )
    production_launch_ok, production_launch_missing_parts = _contains_all(
        "\n".join(
            [
                _maybe_read(repo_root, "acgi-ai/PRODUCTION-LAUNCH.md"),
                _maybe_read(
                    repo_root,
                    "acgi-ai/scripts/check-production-launch-handoff.mjs",
                ),
                _maybe_read(repo_root, "docs/integration-readiness-task-map.md"),
                _maybe_read(repo_root, "acgi-ai/DEPLOY.md"),
                _maybe_read(repo_root, "scripts/build_release_evidence.py"),
            ]
        ),
        [
            "Local readiness is not production deployment proof",
            "No stronger claims until live proof is attached",
            "VERCEL_TOKEN",
            "GCP_WORKLOAD_IDENTITY_PROVIDER",
            "GCP_ARTIFACT_REGISTRY",
            "CONSOLE_AUTH_UPSTREAM",
            "CONSOLE_BUS_UPSTREAM",
            "make verify-js-node24",
            "make platform-readiness",
            "make release-evidence",
            "verify:postdeploy -- https://console.acgs.ai",
            "dist-release-evidence/manifest.json",
            "buyer-evidence-gallery",
            "console-dist",
            "Cloud Run revision URL",
            "test:production-launch-handoff",
            "production launch handoff",
        ],
    )
    production_launch_scripts_ok = (
        deploy_scripts.get("test:production-launch-handoff")
        == "node scripts/check-production-launch-handoff.mjs"
        and "pnpm run test:production-launch-handoff" in deploy_scripts.get("test:all", "")
    )
    items.append(
        _item(
            "production-launch-handoff-local",
            "Production launch handoff is explicit and machine-verifiable",
            production_launch_files_ok and production_launch_ok and production_launch_scripts_ok,
            (
                "operator handoff lists secrets, preflights, live proof artifacts, "
                "rollback triggers, and claim boundaries"
                if production_launch_files_ok
                and production_launch_ok
                and production_launch_scripts_ok
                else (
                    f"missing_files={production_launch_missing}, "
                    f"missing_parts={production_launch_missing_parts}, "
                    f"scripts_ok={production_launch_scripts_ok}"
                )
            ),
            "pnpm -F acgi-ai run test:production-launch-handoff",
        )
    )

    production_authority_files_ok, production_authority_missing = _all_files_exist(
        repo_root,
        [
            "acgi-ai/production-authority.example.json",
            "acgi-ai/scripts/check-production-authority-packet.mjs",
            "acgi-ai/PRODUCTION-LAUNCH.md",
            "acgi-ai/DEPLOY.md",
        ],
    )
    production_authority_packet = _maybe_read(
        repo_root,
        "acgi-ai/production-authority.example.json",
    )
    production_authority_json_ok = False
    if production_authority_packet:
        try:
            authority_payload = json.loads(production_authority_packet)
        except json.JSONDecodeError:
            authority_payload = {}
        production_authority_json_ok = (
            authority_payload.get("artifactKind") == "production-authority-packet"
            and authority_payload.get("status") == "pending-external-authority"
            and "pending-external:deploy-owner-approval" in production_authority_packet
            and "not production deployment proof" in str(authority_payload.get("claimBoundary", ""))
        )
    production_authority_ok, production_authority_missing_parts = _contains_all(
        "\n".join(
            [
                production_authority_packet,
                _maybe_read(repo_root, "acgi-ai/scripts/check-production-authority-packet.mjs"),
                _maybe_read(repo_root, "acgi-ai/PRODUCTION-LAUNCH.md"),
                _maybe_read(repo_root, "acgi-ai/DEPLOY.md"),
                _maybe_read(repo_root, "docs/integration-readiness-task-map.md"),
                _maybe_read(repo_root, "scripts/build_release_evidence.py"),
            ]
        ),
        [
            "production-authority.example.json",
            "test:production-authority-packet",
            "pending-external:deploy-owner-approval",
            "deploy-owner-approval",
            "dns-owner-approval",
            "auth-owner-approval",
            "claims-owner-approval",
            "not production deployment proof",
        ],
    )
    production_authority_scripts_ok = (
        deploy_scripts.get("test:production-authority-packet")
        == "node scripts/check-production-authority-packet.mjs"
        and "pnpm run test:production-authority-packet" in deploy_scripts.get("test:all", "")
    )
    items.append(
        _item(
            "production-authority-packet-local",
            "Production deployment authority packet is explicit and claim-safe",
            production_authority_files_ok
            and production_authority_json_ok
            and production_authority_ok
            and production_authority_scripts_ok,
            (
                "production-authority.example.json keeps deploy/DNS/auth/claim "
                "approvals pending-external so local readiness cannot be confused "
                "with authority to mutate production"
                if production_authority_files_ok
                and production_authority_json_ok
                and production_authority_ok
                and production_authority_scripts_ok
                else (
                    f"missing_files={production_authority_missing}, "
                    f"json_ok={production_authority_json_ok}, "
                    f"missing_parts={production_authority_missing_parts}, "
                    f"scripts_ok={production_authority_scripts_ok}"
                )
            ),
            "pnpm -F acgi-ai run test:production-authority-packet",
        )
    )

    production_evidence_files_ok, production_evidence_missing = _all_files_exist(
        repo_root,
        [
            "acgi-ai/production-evidence.example.json",
            "acgi-ai/scripts/check-production-evidence-template.mjs",
            "acgi-ai/PRODUCTION-LAUNCH.md",
            "acgi-ai/DEPLOY.md",
            ".github/workflows/console.yml",
        ],
    )
    production_evidence_template = _maybe_read(
        repo_root,
        "acgi-ai/production-evidence.example.json",
    )
    production_evidence_json_ok = False
    if production_evidence_template:
        try:
            template_payload = json.loads(production_evidence_template)
        except json.JSONDecodeError:
            template_payload = {}
        production_evidence_json_ok = (
            template_payload.get("artifactKind") == "production-evidence-template"
            and template_payload.get("status") == "template-only"
            and "not live production proof" in template_payload.get("claimBoundary", "")
            and template_payload.get("hostedStorybook", {}).get("status") == "pending"
            and template_payload.get("assurance", {}).get("legalClaimMatrix", {}).get("status")
            == "pending-external"
            and template_payload.get("assurance", {})
            .get("legalClaimMatrix", {})
            .get("claimMatrixRef")
            == "REPLACE_WITH_LEGAL_REVIEWED_CLAIM_MATRIX_ARTIFACT_OR_HASH"
            and template_payload.get("assurance", {}).get("pentest", {}).get("criticalFindingsOpen")
            == "REPLACE_WITH_ZERO_OPEN_CRITICAL_FINDINGS_COUNT"
            and "REPLACE_WITH_NVDA_EVIDENCE"
            in template_payload.get("assurance", {}).get("wcagManual", {}).get("assistiveTech", [])
            and template_payload.get("assurance", {}).get("browserScreenshots", {}).get("bundleRef")
            == "REPLACE_WITH_BROWSER_SCREENSHOT_OR_VISUAL_DIFF_BUNDLE_ARTIFACT_OR_HASH"
            and template_payload.get("verification", {}).get("postdeployCommand")
            == "pnpm -F acgi-ai run verify:postdeploy -- https://console.acgs.ai"
            and template_payload.get("verification", {}).get("productionLiveCommand")
            == "pnpm -F acgi-ai run verify:production-live -- --json"
            and template_payload.get("artifacts", {}).get("verifyProductionLiveOutput")
            == "REPLACE_WITH_VERIFY_PRODUCTION_LIVE_JSON_ARTIFACT_OR_HASH"
            and template_payload.get("verification", {}).get("productionLiveStatus")
            == "REPLACE_WITH_PASS_OR_FAIL_FROM_VERIFY_PRODUCTION_LIVE"
            and template_payload.get("verification", {}).get("productionLiveBlockers")
            == ["REPLACE_WITH_BLOCKER_IDS_FROM_VERIFY_PRODUCTION_LIVE_OR_EMPTY_ARRAY"]
            and "validate:production-evidence"
            in template_payload.get("verification", {}).get(
                "productionEvidenceValidationCommand", ""
            )
            and template_payload.get("artifacts", {}).get("validatedProductionEvidence")
            == "REPLACE_WITH_VALIDATE_PRODUCTION_EVIDENCE_JSON_ARTIFACT_OR_HASH"
        )
    production_evidence_ok, production_evidence_missing_parts = _contains_all(
        "\n".join(
            [
                production_evidence_template,
                _maybe_read(
                    repo_root,
                    "acgi-ai/scripts/check-production-evidence-template.mjs",
                ),
                _maybe_read(repo_root, "acgi-ai/PRODUCTION-LAUNCH.md"),
                _maybe_read(repo_root, "acgi-ai/DEPLOY.md"),
                _maybe_read(repo_root, "docs/integration-readiness-task-map.md"),
                _maybe_read(repo_root, "scripts/build_release_evidence.py"),
                _maybe_read(repo_root, "acgi-ai/scripts/check-production-live-verifier.mjs"),
                _maybe_read(repo_root, ".github/workflows/console.yml"),
            ]
        ),
        [
            "production-evidence.example.json",
            "test:production-evidence-template",
            "test:production-live-verifier",
            "test:production-evidence-validator",
            "verify:production-live",
            "validate:production-evidence",
            "not live production proof",
            "pending-external",
            "https://console.acgs.ai/healthz",
            "REPLACE_WITH_POSTDEPLOY_OUTPUT_ARTIFACT_OR_HASH",
            "REPLACE_WITH_VERIFY_PRODUCTION_LIVE_JSON_ARTIFACT_OR_HASH",
            "REPLACE_WITH_BLOCKER_IDS_FROM_VERIFY_PRODUCTION_LIVE_OR_EMPTY_ARRAY",
            "REPLACE_WITH_VALIDATE_PRODUCTION_EVIDENCE_JSON_ARTIFACT_OR_HASH",
            "productionLiveBlockers",
            "productionEvidenceValidationCommand",
            "validatedProductionEvidence",
            "acgi-ai/production-evidence.example.json",
        ],
    )
    production_evidence_scripts_ok = (
        deploy_scripts.get("test:production-evidence-template")
        == "node scripts/check-production-evidence-template.mjs"
        and "pnpm run test:production-evidence-template" in deploy_scripts.get("test:all", "")
        and "pnpm run test:production-live-verifier" in deploy_scripts.get("test:all", "")
        and "pnpm run test:production-evidence-validator" in deploy_scripts.get("test:all", "")
        and "pnpm run validate:production-evidence" not in deploy_scripts.get("test:all", "")
    )
    items.append(
        _item(
            "production-evidence-template-local",
            "Production evidence intake template is machine-verifiable",
            production_evidence_files_ok
            and production_evidence_json_ok
            and production_evidence_ok
            and production_evidence_scripts_ok,
            (
                "template captures live deploy proof placeholders and pending-external "
                "assurance boundaries plus verified assurance detail fields without "
                "claiming production proof"
                if production_evidence_files_ok
                and production_evidence_json_ok
                and production_evidence_ok
                and production_evidence_scripts_ok
                else (
                    f"missing_files={production_evidence_missing}, "
                    f"json_ok={production_evidence_json_ok}, "
                    f"missing_parts={production_evidence_missing_parts}, "
                    f"scripts_ok={production_evidence_scripts_ok}"
                )
            ),
            "pnpm -F acgi-ai run test:production-evidence-template",
        )
    )

    production_live_files_ok, production_live_missing = _all_files_exist(
        repo_root,
        [
            "acgi-ai/scripts/verify-production-live.mjs",
            "acgi-ai/scripts/check-production-live-verifier.mjs",
            "acgi-ai/production-evidence.example.json",
            "acgi-ai/PRODUCTION-LAUNCH.md",
            "acgi-ai/DEPLOY.md",
        ],
    )
    production_live_ok, production_live_missing_parts = _contains_all(
        "\n".join(
            [
                _maybe_read(repo_root, "acgi-ai/scripts/verify-production-live.mjs"),
                _maybe_read(repo_root, "acgi-ai/scripts/check-production-live-verifier.mjs"),
                production_evidence_template,
                _maybe_read(repo_root, "acgi-ai/PRODUCTION-LAUNCH.md"),
                _maybe_read(repo_root, "acgi-ai/DEPLOY.md"),
                _maybe_read(repo_root, "docs/integration-readiness-task-map.md"),
                _maybe_read(repo_root, "scripts/build_release_evidence.py"),
            ]
        ),
        [
            "verify:production-live",
            "test:production-live-verifier",
            "not live production proof",
            "pending-external",
            "https://console.acgs.ai",
            "https://storybook.acgs.ai",
            "https://storybook.acgs.ai/manifest.json",
            "storybook-manifest-live",
            "EXPECTED_SERVED_HASH",
            "EXPECTED_BUILD_ID",
            "REPLACE_WITH_VERIFY_PRODUCTION_LIVE_JSON_ARTIFACT_OR_HASH",
            "REPLACE_WITH_BLOCKER_IDS_FROM_VERIFY_PRODUCTION_LIVE_OR_EMPTY_ARRAY",
            "blockedUntil",
            "blockers",
        ],
    )
    production_live_scripts_ok = (
        deploy_scripts.get("verify:production-live") == "node scripts/verify-production-live.mjs"
        and deploy_scripts.get("test:production-live-verifier")
        == "node scripts/check-production-live-verifier.mjs"
        and "pnpm run test:production-live-verifier" in deploy_scripts.get("test:all", "")
        and "pnpm run verify:production-live" not in deploy_scripts.get("test:all", "")
    )
    items.append(
        _item(
            "production-live-verifier-local",
            "Production live verifier command is locally wired without auto-running network checks",
            production_live_files_ok and production_live_ok and production_live_scripts_ok,
            (
                "verify:production-live captures DNS, HTTPS, healthz, header, "
                "Storybook manifest proof, and blocker ids after deploy while "
                "local test:all only checks wiring"
                if production_live_files_ok and production_live_ok and production_live_scripts_ok
                else (
                    f"missing_files={production_live_missing}, "
                    f"missing_parts={production_live_missing_parts}, "
                    f"scripts_ok={production_live_scripts_ok}"
                )
            ),
            "pnpm -F acgi-ai run test:production-live-verifier",
        )
    )

    production_blocker_report_files_ok, production_blocker_report_missing = _all_files_exist(
        repo_root,
        [
            "acgi-ai/scripts/build-production-blocker-report.mjs",
            "acgi-ai/scripts/check-production-blocker-report.mjs",
            "acgi-ai/scripts/verify-production-live.mjs",
            "acgi-ai/PRODUCTION-LAUNCH.md",
            "acgi-ai/DEPLOY.md",
        ],
    )
    production_blocker_report_ok, production_blocker_report_missing_parts = _contains_all(
        "\n".join(
            [
                _maybe_read(repo_root, "acgi-ai/scripts/build-production-blocker-report.mjs"),
                _maybe_read(repo_root, "acgi-ai/scripts/check-production-blocker-report.mjs"),
                _maybe_read(repo_root, "acgi-ai/scripts/check-production-live-verifier.mjs"),
                _maybe_read(
                    repo_root,
                    "acgi-ai/scripts/check-production-evidence-validator.mjs",
                ),
                _maybe_read(repo_root, "acgi-ai/PRODUCTION-LAUNCH.md"),
                _maybe_read(repo_root, "acgi-ai/DEPLOY.md"),
                _maybe_read(repo_root, "docs/integration-readiness-task-map.md"),
                _maybe_read(repo_root, "scripts/build_release_evidence.py"),
            ]
        ),
        [
            "build:production-blocker-report",
            "test:production-blocker-report",
            "production-blocker-report",
            "--live-output",
            "--require-clear",
            "copyIntoProductionEvidence",
            "productionLiveBlockers",
            "not live production proof",
            "does not deploy",
        ],
    )
    production_blocker_report_scripts_ok = (
        deploy_scripts.get("build:production-blocker-report")
        == "node scripts/build-production-blocker-report.mjs"
        and deploy_scripts.get("test:production-blocker-report")
        == "node scripts/check-production-blocker-report.mjs"
        and "pnpm run test:production-blocker-report" in deploy_scripts.get("test:all", "")
        and "pnpm run build:production-blocker-report" not in deploy_scripts.get("test:all", "")
    )
    items.append(
        _item(
            "production-blocker-report-local",
            "Production live blockers can be packaged into an operator handoff report",
            production_blocker_report_files_ok
            and production_blocker_report_ok
            and production_blocker_report_scripts_ok,
            (
                "build:production-blocker-report converts verify:production-live JSON "
                "into a production-blocker-report with copyIntoProductionEvidence "
                "fields while preserving the not live production proof boundary"
                if production_blocker_report_files_ok
                and production_blocker_report_ok
                and production_blocker_report_scripts_ok
                else (
                    f"missing_files={production_blocker_report_missing}, "
                    f"missing_parts={production_blocker_report_missing_parts}, "
                    f"scripts_ok={production_blocker_report_scripts_ok}"
                )
            ),
            "pnpm -F acgi-ai run test:production-blocker-report",
        )
    )

    production_evidence_validator_files_ok, production_evidence_validator_missing = (
        _all_files_exist(
            repo_root,
            [
                "acgi-ai/scripts/validate-production-evidence.mjs",
                "acgi-ai/scripts/check-production-evidence-validator.mjs",
                "acgi-ai/production-evidence.example.json",
                "acgi-ai/PRODUCTION-LAUNCH.md",
                "acgi-ai/DEPLOY.md",
            ],
        )
    )
    production_evidence_validator_ok, production_evidence_validator_missing_parts = _contains_all(
        "\n".join(
            [
                _maybe_read(
                    repo_root,
                    "acgi-ai/scripts/validate-production-evidence.mjs",
                ),
                _maybe_read(
                    repo_root,
                    "acgi-ai/scripts/check-production-evidence-validator.mjs",
                ),
                production_evidence_template,
                _maybe_read(repo_root, "acgi-ai/PRODUCTION-LAUNCH.md"),
                _maybe_read(repo_root, "acgi-ai/DEPLOY.md"),
                _maybe_read(repo_root, "docs/integration-readiness-task-map.md"),
                _maybe_read(repo_root, "scripts/build_release_evidence.py"),
                _maybe_read(
                    repo_root,
                    "acgi-ai/scripts/check-production-evidence-template.mjs",
                ),
                _maybe_read(repo_root, "acgi-ai/scripts/check-security-invariants.mjs"),
                _maybe_read(
                    repo_root,
                    "acgi-ai/scripts/check-ci-readiness-gates.mjs",
                ),
            ]
        ),
        [
            "validate:production-evidence",
            "test:production-evidence-validator",
            "production-evidence-validation",
            "productionLiveStatus",
            "productionLiveBlockers",
            "deployment-blocked-live-blockers-match",
            "productionEvidenceValidationCommand",
            "productionEvidenceValidationOutputRef",
            "validatedProductionEvidence",
            "--manifest",
            "--live-output",
            "--require-pass",
            "require-pass-assurance-legalClaimMatrix-verified",
            "criticalFindingsOpen",
            "assistiveTech",
            "deployment-blocked",
            "live-verified",
            "not live production proof",
            "pending-external",
        ],
    )
    production_evidence_validator_scripts_ok = (
        deploy_scripts.get("validate:production-evidence")
        == "node scripts/validate-production-evidence.mjs"
        and deploy_scripts.get("test:production-evidence-validator")
        == "node scripts/check-production-evidence-validator.mjs"
        and "pnpm run test:production-evidence-validator" in deploy_scripts.get("test:all", "")
        and "pnpm run validate:production-evidence" not in deploy_scripts.get("test:all", "")
    )
    items.append(
        _item(
            "production-evidence-validator-local",
            "Completed production evidence validator is locally wired "
            "without auto-running operator proof",
            production_evidence_validator_files_ok
            and production_evidence_validator_ok
            and production_evidence_validator_scripts_ok,
            (
                "validate:production-evidence checks completed live-verified or "
                "deployment-blocked manifests and blocker ids against attached "
                "live verifier JSON, and rejects require-pass output until verified "
                "legal, pentest, manual WCAG, and browser assurance details replace "
                "pending-external refs"
                if production_evidence_validator_files_ok
                and production_evidence_validator_ok
                and production_evidence_validator_scripts_ok
                else (
                    f"missing_files={production_evidence_validator_missing}, "
                    f"missing_parts={production_evidence_validator_missing_parts}, "
                    f"scripts_ok={production_evidence_validator_scripts_ok}"
                )
            ),
            "pnpm -F acgi-ai run test:production-evidence-validator",
        )
    )

    production_cutover_plan_files_ok, production_cutover_plan_missing = _all_files_exist(
        repo_root,
        [
            "acgi-ai/scripts/build-production-cutover-plan.mjs",
            "acgi-ai/scripts/check-production-cutover-plan.mjs",
            "acgi-ai/scripts/verify-production-live.mjs",
            "acgi-ai/scripts/build-production-blocker-report.mjs",
            "acgi-ai/PRODUCTION-LAUNCH.md",
            "acgi-ai/DEPLOY.md",
        ],
    )
    production_cutover_plan_ok, production_cutover_plan_missing_parts = _contains_all(
        "\n".join(
            [
                _maybe_read(repo_root, "acgi-ai/scripts/build-production-cutover-plan.mjs"),
                _maybe_read(repo_root, "acgi-ai/scripts/check-production-cutover-plan.mjs"),
                _maybe_read(repo_root, "acgi-ai/scripts/check-production-blocker-report.mjs"),
                _maybe_read(repo_root, "acgi-ai/scripts/check-production-launch-handoff.mjs"),
                _maybe_read(repo_root, "acgi-ai/PRODUCTION-LAUNCH.md"),
                _maybe_read(repo_root, "acgi-ai/DEPLOY.md"),
                _maybe_read(repo_root, "docs/integration-readiness-task-map.md"),
                _maybe_read(repo_root, "scripts/build_release_evidence.py"),
            ]
        ),
        [
            "build:production-cutover-plan",
            "test:production-cutover-plan",
            "production-cutover-plan",
            "--blocker-report",
            "dnsCutover",
            "requiredGitHubSecrets",
            "productionLiveBlockers",
            "copyIntoProductionEvidence",
            "not live production proof",
            "does not deploy",
            "mutate DNS",
        ],
    )
    production_cutover_plan_scripts_ok = (
        deploy_scripts.get("build:production-cutover-plan")
        == "node scripts/build-production-cutover-plan.mjs"
        and deploy_scripts.get("test:production-cutover-plan")
        == "node scripts/check-production-cutover-plan.mjs"
        and "pnpm run test:production-cutover-plan" in deploy_scripts.get("test:all", "")
        and "pnpm run build:production-cutover-plan" not in deploy_scripts.get("test:all", "")
    )
    items.append(
        _item(
            "production-cutover-plan-local",
            "Production DNS/deploy cutover plan can be generated from saved live blockers",
            production_cutover_plan_files_ok
            and production_cutover_plan_ok
            and production_cutover_plan_scripts_ok,
            (
                "build:production-cutover-plan packages required secrets, DNS cutover "
                "records, live blockers, and copyIntoProductionEvidence fields while "
                "preserving the not live production proof boundary"
                if production_cutover_plan_files_ok
                and production_cutover_plan_ok
                and production_cutover_plan_scripts_ok
                else (
                    f"missing_files={production_cutover_plan_missing}, "
                    f"missing_parts={production_cutover_plan_missing_parts}, "
                    f"scripts_ok={production_cutover_plan_scripts_ok}"
                )
            ),
            "pnpm -F acgi-ai run test:production-cutover-plan",
        )
    )

    production_evidence_draft_files_ok, production_evidence_draft_missing = _all_files_exist(
        repo_root,
        [
            "acgi-ai/scripts/build-production-evidence-draft.mjs",
            "acgi-ai/scripts/check-production-evidence-draft.mjs",
            "acgi-ai/scripts/validate-production-evidence.mjs",
            "acgi-ai/scripts/build-production-blocker-report.mjs",
            "acgi-ai/scripts/build-production-cutover-plan.mjs",
            "acgi-ai/PRODUCTION-LAUNCH.md",
            "acgi-ai/DEPLOY.md",
        ],
    )
    production_evidence_draft_ok, production_evidence_draft_missing_parts = _contains_all(
        "\n".join(
            [
                _maybe_read(repo_root, "acgi-ai/scripts/build-production-evidence-draft.mjs"),
                _maybe_read(repo_root, "acgi-ai/scripts/check-production-evidence-draft.mjs"),
                _maybe_read(repo_root, "acgi-ai/scripts/validate-production-evidence.mjs"),
                _maybe_read(repo_root, "acgi-ai/scripts/check-production-evidence-validator.mjs"),
                _maybe_read(repo_root, "acgi-ai/scripts/check-production-launch-handoff.mjs"),
                _maybe_read(repo_root, "acgi-ai/PRODUCTION-LAUNCH.md"),
                _maybe_read(repo_root, "acgi-ai/DEPLOY.md"),
                _maybe_read(repo_root, "docs/integration-readiness-task-map.md"),
                _maybe_read(repo_root, "scripts/build_release_evidence.py"),
                _maybe_read(repo_root, "acgi-ai/scripts/check-security-invariants.mjs"),
                _maybe_read(repo_root, "acgi-ai/scripts/check-ci-readiness-gates.mjs"),
            ]
        ),
        [
            "build:production-evidence-draft",
            "test:production-evidence-draft",
            "production-evidence-draft",
            "production-evidence.deployment-blocked.json",
            "deployment-blocked",
            "pending-external",
            "productionBlockerReport",
            "productionCutoverPlan",
            "productionLiveBlockers",
            "productionEvidenceValidationCommand",
            "not live production proof",
            "does not deploy",
        ],
    )
    production_evidence_draft_scripts_ok = (
        deploy_scripts.get("build:production-evidence-draft")
        == "node scripts/build-production-evidence-draft.mjs"
        and deploy_scripts.get("test:production-evidence-draft")
        == "node scripts/check-production-evidence-draft.mjs"
        and "pnpm run test:production-evidence-draft" in deploy_scripts.get("test:all", "")
        and "pnpm run build:production-evidence-draft" not in deploy_scripts.get("test:all", "")
    )
    items.append(
        _item(
            "production-evidence-draft-local",
            (
                "Deployment-blocked production evidence draft can be generated "
                "from saved local artifacts"
            ),
            production_evidence_draft_files_ok
            and production_evidence_draft_ok
            and production_evidence_draft_scripts_ok,
            (
                "build:production-evidence-draft combines saved live verifier, "
                "production-blocker-report, and production-cutover-plan JSON into "
                "a validator-ready deployment-blocked manifest while preserving "
                "pending-external proof refs and the not live production proof boundary"
                if production_evidence_draft_files_ok
                and production_evidence_draft_ok
                and production_evidence_draft_scripts_ok
                else (
                    f"missing_files={production_evidence_draft_missing}, "
                    f"missing_parts={production_evidence_draft_missing_parts}, "
                    f"scripts_ok={production_evidence_draft_scripts_ok}"
                )
            ),
            "pnpm -F acgi-ai run test:production-evidence-draft",
        )
    )

    production_evidence_chain_files_ok, production_evidence_chain_missing = _all_files_exist(
        repo_root,
        [
            "scripts/build_release_evidence.py",
            "tests/test_release_evidence_bundle.py",
            "docs/integration-readiness-task-map.md",
            "acgi-ai/DEPLOY.md",
            "acgi-ai/PRODUCTION-LAUNCH.md",
        ],
    )
    production_evidence_chain_ok, production_evidence_chain_missing_parts = _contains_all(
        "\n".join(
            [
                _maybe_read(repo_root, "scripts/build_release_evidence.py"),
                _maybe_read(repo_root, "tests/test_release_evidence_bundle.py"),
                _maybe_read(repo_root, "docs/integration-readiness-task-map.md"),
                _maybe_read(repo_root, "acgi-ai/DEPLOY.md"),
                _maybe_read(repo_root, "acgi-ai/PRODUCTION-LAUNCH.md"),
            ]
        ),
        [
            "production_evidence_chain_snapshot",
            "productionEvidenceChain",
            "production-evidence-validation.deployment-blocked.json",
            "productionLiveBlockers",
            "hostedStorybookHandoff",
            "not live production proof",
        ],
    )
    items.append(
        _item(
            "production-evidence-chain-local",
            "Saved production evidence handoff artifacts are compared for drift",
            production_evidence_chain_files_ok and production_evidence_chain_ok,
            (
                "release evidence now compares saved live verifier, blocker report, "
                "cutover plan, deployment-blocked draft, validator output, and hosted "
                "Storybook handoff snapshots for blocker drift; not live production proof"
                if production_evidence_chain_files_ok and production_evidence_chain_ok
                else (
                    f"missing_files={production_evidence_chain_missing}, "
                    f"missing_parts={production_evidence_chain_missing_parts}"
                )
            ),
            "make release-evidence && uv run python -m pytest "
            "tests/test_release_evidence_bundle.py --import-mode=importlib -q",
        )
    )

    production_blocker_evidence_files_ok, production_blocker_evidence_missing = _all_files_exist(
        repo_root,
        [
            "scripts/build_production_blocker_evidence.py",
            "tests/test_production_blocker_evidence.py",
            "scripts/run_acgi_node24_gate.sh",
            "scripts/build_release_evidence.py",
            "scripts/production_launch_preflight.py",
            "Makefile",
            "docs/integration-readiness-task-map.md",
            "acgi-ai/DEPLOY.md",
            "acgi-ai/PRODUCTION-LAUNCH.md",
        ],
    )
    production_blocker_evidence_ok, production_blocker_evidence_missing_parts = _contains_all(
        "\n".join(
            [
                _maybe_read(repo_root, "scripts/build_production_blocker_evidence.py"),
                _maybe_read(repo_root, "tests/test_production_blocker_evidence.py"),
                _maybe_read(repo_root, "scripts/build_release_evidence.py"),
                _maybe_read(repo_root, "scripts/production_launch_preflight.py"),
                _maybe_read(repo_root, "Makefile"),
                _maybe_read(repo_root, "docs/integration-readiness-task-map.md"),
                _maybe_read(repo_root, "acgi-ai/DEPLOY.md"),
                _maybe_read(repo_root, "acgi-ai/PRODUCTION-LAUNCH.md"),
            ]
        ),
        [
            "build_production_blocker_evidence.py",
            "test_production_blocker_evidence.py",
            "production-blocker-evidence:",
            "productionBlockerEvidenceRunbook",
            "--dry-run --json",
            "run_acgi_node24_gate.sh",
            "exact Node 24",
            "FORBIDDEN_MUTATING_INVOCATIONS",
            "copy-supplied-live-output",
            "continueOnNonzeroWithOutput",
            "wrapper-captured transcript",
            "production-live-verification.json",
            "production-blocker-report.json",
            "production-cutover-plan.json",
            "hosted-storybook-handoff.json",
            "production-evidence.deployment-blocked.json",
            "production-evidence-validation.deployment-blocked.json",
            "production-launch-preflight.json",
            "not live production proof",
            "does not deploy",
            "mutate DNS",
        ],
    )
    items.append(
        _item(
            "production-blocker-evidence-runbook-local",
            (
                "Deployment-blocked production evidence packet can be refreshed "
                "by one operator command"
            ),
            production_blocker_evidence_files_ok and production_blocker_evidence_ok,
            (
                "make production-blocker-evidence orchestrates live verifier JSON, "
                "blocker report, cutover plan, hosted Storybook handoff, deployment-blocked "
                "evidence draft, validator output, optional hosted Storybook proof "
                "validation, release evidence, and preflight JSON; "
                "acgi-ai commands run through the exact Node 24 gate; unit tests lock "
                "copy-live-output transcript canonicalization and the non-deploying "
                "dry-run plan without claiming live production proof"
                if production_blocker_evidence_files_ok and production_blocker_evidence_ok
                else (
                    f"missing_files={production_blocker_evidence_missing}, "
                    f"missing_parts={production_blocker_evidence_missing_parts}"
                )
            ),
            "uv run python scripts/build_production_blocker_evidence.py --dry-run --json "
            "&& uv run python -m pytest tests/test_production_blocker_evidence.py "
            "--import-mode=importlib -q",
        )
    )

    production_launch_preflight_files_ok, production_launch_preflight_missing = _all_files_exist(
        repo_root,
        [
            "scripts/production_launch_preflight.py",
            "tests/test_production_launch_preflight.py",
            "scripts/build_release_evidence.py",
            "Makefile",
            "docs/integration-readiness-task-map.md",
            "acgi-ai/DEPLOY.md",
            "acgi-ai/PRODUCTION-LAUNCH.md",
        ],
    )
    production_launch_preflight_ok, production_launch_preflight_missing_parts = _contains_all(
        "\n".join(
            [
                _maybe_read(repo_root, "scripts/production_launch_preflight.py"),
                _maybe_read(repo_root, "tests/test_production_launch_preflight.py"),
                _maybe_read(repo_root, "scripts/build_release_evidence.py"),
                _maybe_read(repo_root, "Makefile"),
                _maybe_read(repo_root, "docs/integration-readiness-task-map.md"),
                _maybe_read(repo_root, "acgi-ai/DEPLOY.md"),
                _maybe_read(repo_root, "acgi-ai/PRODUCTION-LAUNCH.md"),
            ]
        ),
        [
            "production-launch-preflight",
            "production_launch_preflight.py",
            "productionLaunchPreflight",
            "ready",
            "blocked",
            "requiredActions",
            "refresh-release-evidence-clean-commit",
            "externalBlockerIds",
            "externalBlockers",
            "proofIntakeArtifacts",
            "productionAuthorityPacket",
            "hostedStorybookProofTemplate",
            "repository",
            "not production deployment proof",
            "does not deploy",
            "mutate DNS",
            "--require-ready",
        ],
    )
    items.append(
        _item(
            "production-launch-preflight-local",
            "Release evidence has a conservative production launch ready/blocked gate",
            production_launch_preflight_files_ok and production_launch_preflight_ok,
            (
                "production launch preflight converts the release-evidence manifest "
                "into a ready/blocked decision with requiredActions, live verifier, "
                "evidence-chain, clean commit freshness, externalBlockerIds, "
                "external blocker details, and proof-intake artifacts while "
                "preserving the not production deployment proof boundary"
                if production_launch_preflight_files_ok and production_launch_preflight_ok
                else (
                    f"missing_files={production_launch_preflight_missing}, "
                    f"missing_parts={production_launch_preflight_missing_parts}"
                )
            ),
            "make production-launch-preflight && uv run python -m pytest "
            "tests/test_production_launch_preflight.py --import-mode=importlib -q",
        )
    )

    fixture_fallback_files_ok, fixture_fallback_missing = _all_files_exist(
        repo_root,
        [
            "acgi-ai/src/api/hooks.ts",
            "acgi-ai/scripts/check-security-invariants.mjs",
            "acgi-ai/scripts/check-gove-zone-mvp.mjs",
            "acgi-ai/DEPLOY.md",
            "docs/integration-readiness-task-map.md",
        ],
    )
    fixture_fallback_ok, fixture_fallback_missing_parts = _contains_all(
        "\n".join(
            [
                _maybe_read(repo_root, "acgi-ai/src/api/hooks.ts"),
                _maybe_read(repo_root, "acgi-ai/scripts/check-security-invariants.mjs"),
                _maybe_read(repo_root, "acgi-ai/scripts/check-gove-zone-mvp.mjs"),
                _maybe_read(repo_root, "acgi-ai/DEPLOY.md"),
                _maybe_read(repo_root, "docs/integration-readiness-task-map.md"),
            ]
        ),
        [
            "canUseFixtureFallback",
            "import.meta.env.PROD",
            "return false",
            "isNetworkUnavailable",
            "error instanceof TypeError",
            "error instanceof ApiError",
            "failed to fetch",
            "!isNetworkUnavailable(error)",
            "production dist bundle must not contain console fixture data sentinels",
            "test:mvp",
            "test:security",
        ],
    )
    fixture_fallback_scripts_ok = "pnpm run test:mvp" in deploy_scripts.get(
        "test:all", ""
    ) and "pnpm run test:security" in deploy_scripts.get("test:all", "")
    items.append(
        _item(
            "fixture-fallback-fail-closed-local",
            "Fixture fallback is production-disabled and network-only in mock mode",
            fixture_fallback_files_ok and fixture_fallback_ok and fixture_fallback_scripts_ok,
            (
                "withFixtureFallback is disabled in production, rethrows ApiError "
                "and non-network errors, and only falls back for network-unavailable "
                "TypeError cases in explicit mock mode"
                if fixture_fallback_files_ok and fixture_fallback_ok and fixture_fallback_scripts_ok
                else (
                    f"missing_files={fixture_fallback_missing}, "
                    f"missing_parts={fixture_fallback_missing_parts}, "
                    f"scripts_ok={fixture_fallback_scripts_ok}"
                )
            ),
            "pnpm -F acgi-ai run test:security && pnpm -F acgi-ai run test:mvp",
        )
    )

    auth_gate_files_ok, auth_gate_missing = _all_files_exist(
        repo_root,
        [
            "acgi-ai/infra/Caddyfile",
            "acgi-ai/src/lib/session.ts",
            "acgi-ai/src/surfaces/console/App.tsx",
            "acgi-ai/scripts/check-auth-boundary.mjs",
            "acgi-ai/infra/cloudrun/service.preview.yaml",
            "acgi-ai/infra/cloudrun/service.staging.yaml",
            "acgi-ai/infra/cloudrun/service.production.yaml",
        ],
    )
    auth_gate_ok, auth_gate_missing_parts = _contains_all(
        "\n".join(
            [
                _maybe_read(repo_root, "acgi-ai/infra/Caddyfile"),
                _maybe_read(repo_root, "acgi-ai/src/lib/session.ts"),
                _maybe_read(repo_root, "acgi-ai/src/surfaces/console/App.tsx"),
                _maybe_read(repo_root, "acgi-ai/scripts/check-auth-boundary.mjs"),
                _maybe_read(repo_root, "acgi-ai/scripts/render-cloudrun-service.mjs"),
                _maybe_read(repo_root, ".github/workflows/console.yml"),
                _maybe_read(repo_root, "docs/integration-readiness-task-map.md"),
                _maybe_read(repo_root, "acgi-ai/DEPLOY.md"),
            ]
        ),
        [
            "@console_routes path /console /console/*",
            "/auth/status",
            "hasProductionSession",
            "forward-auth-status-bridge",
            "forward_auth {$AUTH_UPSTREAM:127.0.0.1:65535}",
            "REPLACE_AUTH_UPSTREAM_AT_DEPLOY_TIME",
            "CONSOLE_AUTH_UPSTREAM",
            "'AUTH_UPSTREAM'",
            "is required",
            "Console auth forward gate",
        ],
    )
    auth_gate_scripts_ok = (
        deploy_scripts.get("test:auth-boundary") == "node scripts/check-auth-boundary.mjs"
        and "pnpm run test:auth-boundary" in deploy_scripts.get("test:all", "")
    )
    items.append(
        _item(
            "console-auth-forward-gate",
            "Console deep links fail closed behind a deploy-time auth upstream",
            auth_gate_files_ok and auth_gate_ok and auth_gate_scripts_ok,
            (
                "/console* and /auth/status are forward-auth gated, the SPA awaits "
                "hasProductionSession, Cloud Run templates carry AUTH_UPSTREAM, and "
                "CI refuses deploy without CONSOLE_AUTH_UPSTREAM"
                if auth_gate_files_ok and auth_gate_ok and auth_gate_scripts_ok
                else (
                    f"missing_files={auth_gate_missing}, "
                    f"missing_parts={auth_gate_missing_parts}, "
                    f"auth_gate_scripts_ok={auth_gate_scripts_ok}"
                )
            ),
            "pnpm -F acgi-ai run test:auth-boundary && pnpm -F acgi-ai run test:cloudrun-renderer",
        )
    )

    claim_files_ok, claim_missing = _all_files_exist(
        repo_root,
        [
            "acgi-ai/claim-matrix.json",
            "acgi-ai/src/routes/Trust.tsx",
            "acgi-ai/src/routes/Security.tsx",
            "acgi-ai/public/.well-known/security.txt",
            "acgi-ai/public/subprocessors.xml",
        ],
    )
    claim_scripts_ok = all(
        key in deploy_scripts for key in ["test:claim-matrix", "test:trust-surface", "audit:eval"]
    )
    readiness = _maybe_read(repo_root, "docs/integration-readiness-task-map.md")
    conservative_source = "\n".join(
        [
            readiness,
            readme,
            _maybe_read(repo_root, "docs/governance-stack-index.md"),
        ]
    )
    conservative_copy_ok, conservative_missing = _contains_all(
        conservative_source,
        ["Do not claim production deployment", "Legal review of claim matrix"],
    )
    items.append(
        _item(
            "claim-safety",
            "Public trust claims are evidence-mapped and overclaim-guarded",
            claim_files_ok and claim_scripts_ok and conservative_copy_ok,
            (
                "claim matrix, trust/security surfaces, and conservative caveats are wired"
                if claim_files_ok and claim_scripts_ok and conservative_copy_ok
                else (
                    f"missing_files={claim_missing}, claim_scripts_ok={claim_scripts_ok}, "
                    f"missing_caveats={conservative_missing}"
                )
            ),
            "pnpm -F acgi-ai run audit:eval",
        )
    )

    platform_blueprint_files_ok, platform_blueprint_missing = _all_files_exist(
        repo_root,
        [
            "docs/platform-ui-ux-research.md",
            "acgi-ai/DESIGN.md",
            "acgi-ai/src/routes/Marketing.tsx",
            "acgi-ai/src/routes/Console.tsx",
            "acgi-ai/src/routes/console/Workbench.tsx",
            "acgi-ai/src/routes/console/wire-decisions.ts",
            "acgi-ai/src/App.css",
            "acgi-ai/scripts/check-platform-blueprint.mjs",
        ],
    )
    platform_blueprint_source = "\n".join(
        [
            _maybe_read(repo_root, "docs/platform-ui-ux-research.md"),
            _maybe_read(repo_root, "acgi-ai/DESIGN.md"),
            _maybe_read(repo_root, "acgi-ai/src/routes/Marketing.tsx"),
            _maybe_read(repo_root, "acgi-ai/src/routes/Console.tsx"),
            _maybe_read(repo_root, "acgi-ai/src/routes/console/Workbench.tsx"),
            _maybe_read(repo_root, "acgi-ai/src/routes/console/wire-decisions.ts"),
            _maybe_read(repo_root, "acgi-ai/src/App.css"),
            _maybe_read(repo_root, "acgi-ai/scripts/check-platform-blueprint.mjs"),
        ]
    )
    platform_blueprint_ok, platform_blueprint_missing_parts = _contains_all(
        platform_blueprint_source,
        [
            "Status: research-backed product blueprint",
            "NIST AI Risk Management Framework",
            "OWASP Top 10 for Large Language Model Applications",
            "OpenAI Agents SDK tracing",
            "LangSmith observability",
            "Arize Phoenix overview",
            "Humanloop evaluators",
            "## Platform UX blueprint",
            "work queue → trace graph → evaluation panel → human release gate → evidence room",
            'id="workbench"',
            "Visualized <em>work</em>",
            "Work queue",
            "Trace graph",
            "Evaluation panel",
            "Human release gate",
            "Evidence room",
            "m-workbench",
            "m-workbench-checklist",
            "Operator quick start",
            "Start here",
            "Hold release",
            "Export proof",
            "Launch proof ladder",
            "Local readiness",
            "Live verifier",
            "Assurance packet",
            "product blueprint, not certification or live assurance",
            "/console/workbench",
            "workbench-console-map",
            "workbench-board",
            "workbench-checklist",
            "workbench-proof-ladder",
            "Local UX blueprint only",
            "not production assurance",
        ],
    )
    platform_blueprint_scripts_ok = (
        deploy_scripts.get("test:platform-blueprint")
        == "node scripts/check-platform-blueprint.mjs"
        and "pnpm run test:platform-blueprint" in deploy_scripts.get("test:all", "")
        and "pnpm run test:platform-blueprint" in deploy_scripts.get("audit:eval", "")
    )
    items.append(
        _item(
            "platform-blueprint-ui-local",
            "Research-backed visual workbench blueprint is locally guarded",
            platform_blueprint_files_ok
            and platform_blueprint_ok
            and platform_blueprint_scripts_ok,
            (
                "platform UI/UX research, DESIGN.md, same-style marketing workbench "
                "and console workbench, launch proof ladder, and "
                "test:platform-blueprint keep the visual easy-use roadmap "
                "inspectable without claiming production assurance"
                if platform_blueprint_files_ok
                and platform_blueprint_ok
                and platform_blueprint_scripts_ok
                else (
                    f"missing_files={platform_blueprint_missing}, "
                    f"missing_parts={platform_blueprint_missing_parts}, "
                    f"scripts_ok={platform_blueprint_scripts_ok}"
                )
            ),
            "pnpm -F acgi-ai run test:platform-blueprint",
        )
    )

    local_gate_ok, local_gate_missing = _contains_all(
        makefile,
        [
            "verify: lint typecheck test",
            "lint: lint-js lint-py lint-docs",
            "platform-readiness:",
            "grep -q '^\\[tool\\.mypy\\]'",
            "grep -q '^files = '",
            "$(UV) run mypy) || exit $$?",
            "$(UV) run mypy src tests) || exit $$?",
            "mypy skipped — not configured",
        ],
    )
    local_scripts_ok = (
        deploy_scripts.get("test") == "pnpm run test:all"
        and "test:all" in deploy_scripts
        and "test:contract" in deploy_scripts
    )
    items.append(
        _item(
            "local-verification-fanout",
            "Local verification fan-out has one root and one frontend entry point",
            local_gate_ok and local_scripts_ok,
            (
                "make verify, make platform-readiness, pnpm test:all, test:contract, "
                "and configured pyproject mypy fan-out are wired"
                if local_gate_ok and local_scripts_ok
                else f"missing_make_parts={local_gate_missing}, local_scripts_ok={local_scripts_ok}"
            ),
            "make verify",
        )
    )

    node24_files_ok, node24_missing = _all_files_exist(
        repo_root,
        [
            "scripts/run_acgi_node24_gate.sh",
            "acgi-ai/.node-version",
            "acgi-ai/package.json",
        ],
    )
    node24_ok, node24_missing_parts = _contains_all(
        "\n".join(
            [
                makefile,
                _maybe_read(repo_root, "scripts/run_acgi_node24_gate.sh"),
                readme,
                _maybe_read(repo_root, "acgi-ai/GETTING_STARTED.md"),
                _maybe_read(repo_root, "docs/integration-readiness-task-map.md"),
            ]
        ),
        [
            "verify-js-node24:",
            "fnm use",
            "process.versions.node",
            "packageManager.split('@')",
            "make verify-js-node24",
        ],
    )
    package_node_ok = (
        _maybe_read(repo_root, "acgi-ai/.node-version").strip() == "24"
        and package_json.get("engines", {}).get("node") == ">=24 <25"
        and package_json.get("packageManager") == "pnpm@9.15.4"
    )
    items.append(
        _item(
            "node24-local-toolchain",
            "Local frontend verification can run on the exact Node 24 toolchain",
            node24_files_ok and node24_ok and package_node_ok,
            (
                "make verify-js-node24 activates fnm Node 24, checks pnpm, "
                "and runs acgi-ai test:all"
                if node24_files_ok and node24_ok and package_node_ok
                else (
                    f"missing_files={node24_missing}, "
                    f"missing_parts={node24_missing_parts}, "
                    f"package_node_ok={package_node_ok}"
                )
            ),
            "make verify-js-node24",
        )
    )

    release_evidence_files_ok, release_evidence_missing = _all_files_exist(
        repo_root,
        [
            "scripts/build_release_evidence.py",
            "tests/test_release_evidence_bundle.py",
        ],
    )
    release_evidence_ok, release_evidence_missing_make = _contains_all(
        makefile,
        [
            "release-evidence:",
            "$(UV) run python scripts/build_release_evidence.py",
        ],
    )
    release_docs_ok, release_docs_missing = _contains_all(
        "\n".join(
            [
                readme,
                _maybe_read(repo_root, "docs/integration-readiness-task-map.md"),
                _maybe_read(repo_root, "acgi-ai/DEPLOY.md"),
            ]
        ),
        ["release-evidence", "local release-readiness evidence bundle"],
    )
    items.append(
        _item(
            "release-evidence-bundle",
            "Local release-readiness evidence bundle is buildable",
            release_evidence_files_ok and release_evidence_ok and release_docs_ok,
            (
                "release evidence bundle packages readiness, buyer artifact, and blockers"
                if release_evidence_files_ok and release_evidence_ok and release_docs_ok
                else (
                    f"missing_files={release_evidence_missing}, "
                    f"missing_make_parts={release_evidence_missing_make}, "
                    f"missing_docs={release_docs_missing}"
                )
            ),
            "make release-evidence",
        )
    )

    proof_journey_ok, proof_journey_missing = _all_files_exist(
        repo_root,
        [
            "acgi-ai/src/routes/console/AuditProof.tsx",
            "packages/agent-bus-analyzer/tests/test_gove_zone_audit_tail.py",
            "packages/agent-bus-analyzer/tests/test_evidence_signing.py",
        ],
    )
    proof_docs_ok, proof_docs_missing = _contains_all(
        readiness,
        [
            "Console receipt proof journey",
            "Live bus receipt proof lookup",
            "Deployment-managed evidence signing",
            "Analyzer Phoenix trace cross-links",
        ],
    )
    items.append(
        _item(
            "buyer-proof-journey",
            "Buyer proof journey is represented from receipt to signed evidence packet",
            proof_journey_ok and proof_docs_ok,
            (
                "receipt proof UI, bus lookup, audit-tail import, signing, "
                "and Phoenix links are tracked"
                if proof_journey_ok and proof_docs_ok
                else (
                    f"missing_files={proof_journey_missing}, "
                    f"missing_readiness_rows={proof_docs_missing}"
                )
            ),
            "pnpm -F acgi-ai run test:mvp && "
            "cd packages/agent-bus-analyzer && "
            "PYTHONPATH=src python -m pytest "
            "tests/test_gove_zone_audit_tail.py tests/test_evidence_signing.py -q",
        )
    )

    runtime_bridge_files_ok, runtime_bridge_missing = _all_files_exist(
        repo_root,
        [
            "packages/gove-zone/src/gove_zone/integration.py",
            "packages/gove-zone/tests/test_integration_hook.py",
            "packages/gove-zone/tests/test_setup.py",
            "packages/gove-zone/README.md",
            "acgi-ai/src/routes/ProductSurfaces.tsx",
        ],
    )
    runtime_bridge_ok, runtime_bridge_missing_parts = _contains_all(
        "\n".join(
            [
                _maybe_read(repo_root, "packages/gove-zone/src/gove_zone/integration.py"),
                _maybe_read(repo_root, "packages/gove-zone/tests/test_integration_hook.py"),
                _maybe_read(repo_root, "packages/gove-zone/tests/test_setup.py"),
                _maybe_read(repo_root, "packages/gove-zone/README.md"),
                _maybe_read(repo_root, "acgi-ai/src/routes/ProductSurfaces.tsx"),
            ]
        ),
        [
            "tool_call_from_hook_payload",
            "tool_calls_from_hook_payload",
            'method": "tools/call"',
            "function_call",
            "output",
            "OpenAI Responses",
            "tool_calls",
            "OpenAI Chat",
            "LangChain-style",
            "Claude/Codex-style",
            "MCP-style",
            "receipt_count",
            "runtime.malformed_batch",
            "slug: 'gove-zone'",
            "Governance before every",
            "uv run --package gove-zone gove-zone smoke",
        ],
    )
    items.append(
        _item(
            "runtime-framework-bridge-local",
            "Runtime hook adapter normalizes common agent-framework tool-call shapes",
            runtime_bridge_files_ok and runtime_bridge_ok,
            (
                "gove-zone bridge normalizes Claude/Codex, MCP, function-call, "
                "OpenAI Responses output function_call items, OpenAI Chat tool_calls, "
                "LangChain-style tool_calls, generic payloads, and batched tool-call "
                "events without letting one denied child or malformed recognized batch "
                "hide inside a batch; the routeable /products/gove-zone surface exposes "
                "the adoption path"
                if runtime_bridge_files_ok and runtime_bridge_ok
                else (
                    f"missing_files={runtime_bridge_missing}, "
                    f"missing_parts={runtime_bridge_missing_parts}"
                )
            ),
            "uv run --package gove-zone python -m pytest "
            "packages/gove-zone/tests/test_integration_hook.py "
            "packages/gove-zone/tests/test_setup.py --import-mode=importlib -q",
        )
    )

    runtime_policy_gate_ok, runtime_policy_gate_missing_parts = _contains_all(
        "\n".join(
            [
                _maybe_read(repo_root, "packages/gove-zone/src/gove_zone/cli.py"),
                _maybe_read(repo_root, "packages/gove-zone/tests/test_setup.py"),
                _maybe_read(repo_root, "packages/gove-zone/README.md"),
                readiness,
            ]
        ),
        [
            "--policy-bundle",
            "RuleSetPolicy.load",
            "DENY and ESCALATE decisions exit non-zero",
            "blocked",
            "Runtime policy gate",
            "OpenAI Responses-style",
            "OpenAI Chat-style",
            "LangChain-style",
            "receipt_count",
            "malformed_batch",
        ],
    )
    items.append(
        _item(
            "runtime-policy-gate-local",
            "Runtime gate can enforce reviewed policy bundles before side effects",
            runtime_policy_gate_ok,
            (
                "gove-zone gate loads RuleSetPolicy bundles, covers OpenAI Responses, "
                "OpenAI Chat, and LangChain tool-call payloads, and exits non-zero "
                "on deny/escalate, including one denied child or malformed recognized "
                "batch inside a batched event"
                if runtime_policy_gate_ok
                else f"missing_parts={runtime_policy_gate_missing_parts}"
            ),
            "uv run --package gove-zone python -m pytest "
            "packages/gove-zone/tests/test_setup.py --import-mode=importlib -q",
        )
    )

    gove_zone_smoke_files_ok, gove_zone_smoke_missing = _all_files_exist(
        repo_root,
        [
            "packages/gove-zone/src/gove_zone/smoke.py",
            "packages/gove-zone/src/gove_zone/cli.py",
            "packages/gove-zone/tests/test_setup.py",
        ],
    )
    gove_zone_smoke_ok, gove_zone_smoke_missing_parts = _contains_all(
        "\n".join(
            [
                _maybe_read(repo_root, "packages/gove-zone/src/gove_zone/smoke.py"),
                _maybe_read(repo_root, "packages/gove-zone/src/gove_zone/cli.py"),
                _maybe_read(repo_root, "packages/gove-zone/tests/test_setup.py"),
                _maybe_read(repo_root, "packages/gove-zone/README.md"),
                readme,
                readiness,
            ]
        ),
        [
            "gove-zone-smoke-report",
            "allow-before-side-effect",
            "deny-before-side-effect",
            "audit-chain-verifies",
            "gove-zone smoke",
            "not production deployment proof",
        ],
    )
    items.append(
        _item(
            "gove-zone-smoke-local",
            "Gove Zone runtime has a one-command local allow/deny/audit smoke proof",
            gove_zone_smoke_files_ok and gove_zone_smoke_ok,
            (
                "gove-zone smoke proves allow/deny/audit-chain behavior without "
                "agent-host, network, or production credentials"
                if gove_zone_smoke_files_ok and gove_zone_smoke_ok
                else (
                    f"missing_files={gove_zone_smoke_missing}, "
                    f"missing_parts={gove_zone_smoke_missing_parts}"
                )
            ),
            "uv run --package gove-zone gove-zone smoke && "
            "uv run --package gove-zone python -m pytest "
            "packages/gove-zone/tests/test_setup.py --import-mode=importlib -q",
        )
    )

    blocker_needles = [
        "Production deployment",
        "Frontend production auth",
        "Legal review of claim matrix",
        "Third-party penetration test",
        "Full WCAG/manual screen reader evidence",
        "Hosted Storybook buyer evidence",
    ]
    blockers_ok, missing_blockers = _contains_all(readiness, blocker_needles)
    items.append(
        _item(
            "external-blockers-documented",
            "External production blockers are explicit instead of hidden",
            blockers_ok,
            (
                "production deploy, auth, legal, pentest, WCAG/manual, "
                "and hosted Storybook caveats documented"
                if blockers_ok
                else f"missing_blockers={missing_blockers}"
            ),
            "sed -n '/Valid deferrals/,/Hosted Storybook/p' docs/integration-readiness-task-map.md",
        )
    )

    buyer_evidence_files_ok, buyer_evidence_missing = _all_files_exist(
        repo_root,
        [
            "acgi-ai/scripts/build-buyer-evidence.mjs",
            "acgi-ai/scripts/check-buyer-evidence-artifact.mjs",
        ],
    )
    buyer_evidence_scripts_ok = (
        deploy_scripts.get("evidence:build") == "node scripts/build-buyer-evidence.mjs"
        and deploy_scripts.get("test:buyer-evidence")
        == "node scripts/check-buyer-evidence-artifact.mjs"
        and deploy_scripts.get("storybook:build") == "pnpm run evidence:build"
        and "pnpm run test:buyer-evidence" in deploy_scripts.get("test:all", "")
    )
    buyer_evidence_docs_ok, buyer_evidence_docs_missing = _contains_all(
        "\n".join(
            [
                readiness,
                _maybe_read(repo_root, "acgi-ai/ARCHITECTURE.md"),
                _maybe_read(repo_root, "acgi-ai/DEPLOY.md"),
                _maybe_read(repo_root, "acgi-ai/GETTING_STARTED.md"),
                readme,
            ]
        ),
        [
            "local buyer-evidence",
            "evidence:build",
            "test:buyer-evidence",
            "visual governance workbench",
            ".nojekyll",
            "hostedProofRequirements",
        ],
    )
    items.append(
        _item(
            "buyer-evidence-gallery-local",
            "Local buyer-evidence gallery artifact is buildable and claim-safe",
            buyer_evidence_files_ok and buyer_evidence_scripts_ok and buyer_evidence_docs_ok,
            (
                "dependency-free local buyer-evidence gallery builder, visual "
                "workbench story, and verifier are wired"
                if buyer_evidence_files_ok and buyer_evidence_scripts_ok and buyer_evidence_docs_ok
                else (
                    f"missing_files={buyer_evidence_missing}, "
                    f"scripts_ok={buyer_evidence_scripts_ok}, "
                    f"missing_docs={buyer_evidence_docs_missing}"
                )
            ),
            "pnpm -F acgi-ai run evidence:build && pnpm -F acgi-ai run test:buyer-evidence",
        )
    )

    console_workflow = _maybe_read(repo_root, ".github/workflows/console.yml")
    buyer_evidence_ci_ok, buyer_evidence_ci_missing = _contains_all(
        console_workflow,
        [
            "Build buyer evidence gallery artifact",
            "pnpm evidence:build",
            "Upload buyer evidence gallery artifact",
            "buyer-evidence-gallery",
            "acgi-ai/dist-buyer-evidence",
            "if-no-files-found: error",
        ],
    )
    items.append(
        _item(
            "buyer-evidence-ci-artifact",
            "Buyer-evidence gallery is built and retained as a CI artifact",
            buyer_evidence_ci_ok,
            (
                "console workflow uploads the buyer-evidence gallery before deploy auth"
                if buyer_evidence_ci_ok
                else f"missing_workflow_parts={buyer_evidence_ci_missing}"
            ),
            "pnpm -F acgi-ai run test:ci-gates && pnpm -F acgi-ai run evidence:build",
        )
    )

    storybook_runtime_plan = _maybe_read(repo_root, "acgi-ai/storybook-runtime.plan.json")
    storybook_runtime_plan_check = _maybe_read(
        repo_root, "acgi-ai/scripts/check-storybook-runtime-plan.mjs"
    )
    storybook_runtime_files_ok, storybook_runtime_missing = _all_files_exist(
        repo_root,
        [
            "acgi-ai/storybook-runtime.plan.json",
            "acgi-ai/scripts/check-storybook-runtime-plan.mjs",
            "acgi-ai/DEPLOY.md",
            "acgi-ai/PRODUCTION-LAUNCH.md",
            "docs/integration-readiness-task-map.md",
        ],
    )
    storybook_runtime_ok, storybook_runtime_missing_parts = _contains_all(
        "\n".join(
            [
                storybook_runtime_plan,
                storybook_runtime_plan_check,
                _maybe_read(repo_root, "acgi-ai/DEPLOY.md"),
                _maybe_read(repo_root, "acgi-ai/PRODUCTION-LAUNCH.md"),
                readiness,
                _maybe_read(repo_root, "scripts/build_release_evidence.py"),
            ]
        ),
        [
            "storybook-runtime.plan.json",
            "test:storybook-runtime-plan",
            "pending-external:dependency-owner-approval",
            "not official Storybook runtime proof",
            "not hosted Storybook proof",
            "not production deployment proof",
            "no dependencies are installed by this plan",
            "npx storybook@latest init",
            "@storybook/react-vite",
        ],
    )
    storybook_runtime_scripts_ok = (
        deploy_scripts.get("test:storybook-runtime-plan")
        == "node scripts/check-storybook-runtime-plan.mjs"
        and "pnpm run test:storybook-runtime-plan" in deploy_scripts.get("test:all", "")
        and deploy_scripts.get("storybook:build") == "pnpm run evidence:build"
    )
    items.append(
        _item(
            "storybook-runtime-plan-local",
            "Official Storybook runtime dependency plan is explicit and claim-safe",
            storybook_runtime_files_ok and storybook_runtime_ok and storybook_runtime_scripts_ok,
            (
                "storybook-runtime.plan.json keeps official Storybook dependency/runtime "
                "work behind pending-external dependency approval while preserving the "
                "dependency-free buyer-evidence publication shim"
                if storybook_runtime_files_ok
                and storybook_runtime_ok
                and storybook_runtime_scripts_ok
                else (
                    f"missing_files={storybook_runtime_missing}, "
                    f"missing_parts={storybook_runtime_missing_parts}, "
                    f"scripts_ok={storybook_runtime_scripts_ok}"
                )
            ),
            "pnpm -F acgi-ai run test:storybook-runtime-plan",
        )
    )

    storybook_workflow = _maybe_read(repo_root, ".github/workflows/storybook.yml")
    storybook_publication_files_ok, storybook_publication_missing = _all_files_exist(
        repo_root,
        [
            ".github/workflows/storybook.yml",
            "acgi-ai/scripts/check-storybook-publication.mjs",
        ],
    )
    storybook_publication_ok, storybook_publication_missing_parts = _contains_all(
        "\n".join(
            [
                storybook_workflow,
                _maybe_read(repo_root, "acgi-ai/scripts/build-buyer-evidence.mjs"),
                _maybe_read(repo_root, "acgi-ai/scripts/check-storybook-publication.mjs"),
                readiness,
                _maybe_read(repo_root, "acgi-ai/DEPLOY.md"),
            ]
        ),
        [
            "name: buyer-evidence-storybook",
            "ACGI_EVIDENCE_CNAME: storybook.acgs.ai",
            ".nojekyll",
            "hostedProofRequirements",
            "actions/upload-pages-artifact@v3",
            "actions/deploy-pages@v4",
            "vars.STORYBOOK_PAGES_ENABLED == 'true'",
            "test:storybook-publication",
            "test:hosted-storybook-handoff",
            "test:hosted-storybook-proof-template",
            "storybook.acgs.ai",
        ],
    )
    storybook_publication_scripts_ok = (
        deploy_scripts.get("test:storybook-publication")
        == "node scripts/check-storybook-publication.mjs"
        and "pnpm run test:storybook-publication" in deploy_scripts.get("test:all", "")
    )
    items.append(
        _item(
            "storybook-publication-workflow-local",
            "Buyer-evidence Storybook publication workflow is locally verifiable",
            storybook_publication_files_ok
            and storybook_publication_ok
            and storybook_publication_scripts_ok,
            (
                "storybook.acgs.ai Pages workflow scaffold builds claim-safe buyer "
                "evidence and runs hosted handoff/proof-template checks before deploy"
                if storybook_publication_files_ok
                and storybook_publication_ok
                and storybook_publication_scripts_ok
                else (
                    f"missing_files={storybook_publication_missing}, "
                    f"missing_parts={storybook_publication_missing_parts}, "
                    f"scripts_ok={storybook_publication_scripts_ok}"
                )
            ),
            "pnpm -F acgi-ai run test:storybook-publication",
        )
    )

    hosted_storybook_handoff_files_ok, hosted_storybook_handoff_missing = _all_files_exist(
        repo_root,
        [
            "acgi-ai/scripts/build-hosted-storybook-handoff.mjs",
            "acgi-ai/scripts/check-hosted-storybook-handoff.mjs",
            "acgi-ai/scripts/check-storybook-publication.mjs",
            "acgi-ai/scripts/check-production-live-verifier.mjs",
            "acgi-ai/PRODUCTION-LAUNCH.md",
            "acgi-ai/DEPLOY.md",
        ],
    )
    hosted_storybook_handoff_ok, hosted_storybook_handoff_missing_parts = _contains_all(
        "\n".join(
            [
                _maybe_read(repo_root, "acgi-ai/scripts/build-hosted-storybook-handoff.mjs"),
                _maybe_read(repo_root, "acgi-ai/scripts/check-hosted-storybook-handoff.mjs"),
                _maybe_read(repo_root, "acgi-ai/scripts/check-storybook-publication.mjs"),
                _maybe_read(repo_root, "acgi-ai/scripts/check-production-live-verifier.mjs"),
                _maybe_read(repo_root, "acgi-ai/PRODUCTION-LAUNCH.md"),
                _maybe_read(repo_root, "acgi-ai/DEPLOY.md"),
                readiness,
                _maybe_read(repo_root, "scripts/build_release_evidence.py"),
            ]
        ),
        [
            "build:hosted-storybook-handoff",
            "test:hosted-storybook-handoff",
            "hosted-storybook-handoff",
            "hosted-storybook-handoff.json",
            "--buyer-evidence-manifest",
            "--live-output",
            "storybook-manifest-live",
            "pending-external:storybook-pages-proof",
            "copyIntoProductionEvidence",
            "not live production proof",
            "does not deploy",
        ],
    )
    hosted_storybook_handoff_scripts_ok = (
        deploy_scripts.get("build:hosted-storybook-handoff")
        == "node scripts/build-hosted-storybook-handoff.mjs"
        and deploy_scripts.get("test:hosted-storybook-handoff")
        == "node scripts/check-hosted-storybook-handoff.mjs"
        and "pnpm run test:hosted-storybook-handoff" in deploy_scripts.get("test:all", "")
        and "pnpm run build:hosted-storybook-handoff" not in deploy_scripts.get("test:all", "")
    )
    items.append(
        _item(
            "hosted-storybook-handoff-local",
            "Hosted Storybook handoff can be generated from local publication and live evidence",
            hosted_storybook_handoff_files_ok
            and hosted_storybook_handoff_ok
            and hosted_storybook_handoff_scripts_ok,
            (
                "build:hosted-storybook-handoff packages the Pages-ready buyer evidence "
                "manifest, storybook-manifest-live blockers, pending-external Storybook "
                "proof refs, and copyIntoProductionEvidence.hostedStorybook without "
                "claiming live production proof"
                if hosted_storybook_handoff_files_ok
                and hosted_storybook_handoff_ok
                and hosted_storybook_handoff_scripts_ok
                else (
                    f"missing_files={hosted_storybook_handoff_missing}, "
                    f"missing_parts={hosted_storybook_handoff_missing_parts}, "
                    f"scripts_ok={hosted_storybook_handoff_scripts_ok}"
                )
            ),
            "pnpm -F acgi-ai run test:hosted-storybook-handoff",
        )
    )

    hosted_storybook_proof_files_ok, hosted_storybook_proof_missing = _all_files_exist(
        repo_root,
        [
            "acgi-ai/hosted-storybook-proof.example.json",
            "acgi-ai/scripts/check-hosted-storybook-proof-template.mjs",
            "acgi-ai/scripts/validate-hosted-storybook-proof.mjs",
            "acgi-ai/scripts/build-hosted-storybook-handoff.mjs",
            "acgi-ai/scripts/verify-production-live.mjs",
            ".github/workflows/storybook.yml",
            ".github/workflows/console.yml",
            "acgi-ai/PRODUCTION-LAUNCH.md",
            "acgi-ai/DEPLOY.md",
            "docs/integration-readiness-task-map.md",
        ],
    )
    hosted_storybook_proof_ok, hosted_storybook_proof_missing_parts = _contains_all(
        "\n".join(
            [
                _maybe_read(repo_root, "acgi-ai/hosted-storybook-proof.example.json"),
                _maybe_read(repo_root, "acgi-ai/scripts/check-hosted-storybook-proof-template.mjs"),
                _maybe_read(repo_root, "acgi-ai/scripts/validate-hosted-storybook-proof.mjs"),
                _maybe_read(repo_root, "acgi-ai/scripts/build-hosted-storybook-handoff.mjs"),
                _maybe_read(repo_root, "acgi-ai/scripts/verify-production-live.mjs"),
                _maybe_read(repo_root, ".github/workflows/storybook.yml"),
                _maybe_read(repo_root, ".github/workflows/console.yml"),
                _maybe_read(repo_root, "acgi-ai/PRODUCTION-LAUNCH.md"),
                _maybe_read(repo_root, "acgi-ai/DEPLOY.md"),
                readiness,
                _maybe_read(repo_root, "scripts/build_release_evidence.py"),
            ]
        ),
        [
            "hosted-storybook-proof.example.json",
            "test:hosted-storybook-proof-template",
            "validate:hosted-storybook-proof",
            "hosted-storybook-proof-validation",
            "hosted-storybook-proof-template",
            "storybook-manifest-live",
            "pending-external:storybook-pages-proof",
            "live-storybook-dns",
            "live-storybook-https",
            "live-storybook-manifest",
            "browserEvidence",
            "automatedA11yReportRefs",
            "visualDiffRefs",
            "not WCAG conformance proof",
            "copyIntoProductionEvidence.hostedStorybook",
            "remainingBlockerToRemove",
            "not hosted Storybook proof",
            "not production deployment proof",
        ],
    )
    hosted_storybook_proof_scripts_ok = (
        deploy_scripts.get("test:hosted-storybook-proof-template")
        == "node scripts/check-hosted-storybook-proof-template.mjs"
        and deploy_scripts.get("validate:hosted-storybook-proof")
        == "node scripts/validate-hosted-storybook-proof.mjs"
        and "pnpm run test:hosted-storybook-proof-template" in deploy_scripts.get("test:all", "")
        and "pnpm run validate:hosted-storybook-proof" not in deploy_scripts.get("test:all", "")
        and "pnpm run verify:production-live" not in deploy_scripts.get("test:all", "")
        and "pnpm run build:hosted-storybook-handoff" not in deploy_scripts.get("test:all", "")
    )
    items.append(
        _item(
            "hosted-storybook-proof-intake-local",
            "Hosted Storybook proof intake is machine-verifiable before claim",
            hosted_storybook_proof_files_ok
            and hosted_storybook_proof_ok
            and hosted_storybook_proof_scripts_ok,
            (
                "hosted-storybook-proof.example.json requires Pages run, DNS, "
                "hosted manifest, passing storybook-manifest-live, absent "
                "live-storybook blockers, hosted browser screenshot, automated "
                "accessibility, and visual-diff evidence, "
                "copyIntoProductionEvidence.hostedStorybook, "
                "and validate:hosted-storybook-proof completed-proof checks saved as "
                "dist-release-evidence/hosted-storybook-proof-validation.json before "
                "hosted-storybook-buyer-evidence can be removed"
                if hosted_storybook_proof_files_ok
                and hosted_storybook_proof_ok
                and hosted_storybook_proof_scripts_ok
                else (
                    f"missing_files={hosted_storybook_proof_missing}, "
                    f"missing_parts={hosted_storybook_proof_missing_parts}, "
                    f"scripts_ok={hosted_storybook_proof_scripts_ok}"
                )
            ),
            (
                "pnpm -F acgi-ai run test:hosted-storybook-proof-template "
                "&& pnpm -F acgi-ai run validate:hosted-storybook-proof -- --proof "
                "<hosted-storybook-proof.json> --live-output <verify-production-live.json> "
                "--out ../dist-release-evidence/hosted-storybook-proof-validation.json "
                "--require-pass"
            ),
        )
    )

    frontend_deps = {
        **package_json.get("dependencies", {}),
        **package_json.get("devDependencies", {}),
    }
    official_storybook_dependency_present = any(
        name == "storybook" or name.startswith("@storybook/") for name in frontend_deps
    )
    storybook_plan_present = "Storybook" in _maybe_read(repo_root, "acgi-ai/PLAN.md")
    hosted_storybook_present = (
        official_storybook_dependency_present and "storybook.acgs.ai" in storybook_workflow
    )
    items.append(
        _item(
            "hosted-storybook-buyer-evidence",
            "Hosted Storybook buyer-evidence publication is either live or visibly pending",
            hosted_storybook_present,
            (
                "official Storybook dependency and hosted publish workflow are present"
                if hosted_storybook_present
                else (
                    "storybook.acgs.ai publication workflow exists; official Storybook "
                    "runtime dependency and live storybook-manifest-live proof remain pending"
                )
            ),
            "add official Storybook runtime and verify live storybook.acgs.ai",
            pending=storybook_plan_present and not hosted_storybook_present,
        )
    )

    return items


def summarize(items: list[ReadinessItem]) -> dict[str, int]:
    return {
        "pass": sum(1 for item in items if item.status == "pass"),
        "fail": sum(1 for item in items if item.status == "fail"),
        "pending": sum(1 for item in items if item.status == "pending"),
        "total": len(items),
    }


def render_markdown(items: list[ReadinessItem]) -> str:
    summary = summarize(items)
    lines = [
        "# Platform readiness report",
        "",
        (
            f"**Result:** {summary['pass']}/{summary['total']} pass · "
            f"{summary['fail']} fail · {summary['pending']} pending"
        ),
        "",
        "This report is local readiness evidence only. Production deployment remains unproven",
        "until credentialed deploy workflows, live post-deploy checks, and "
        "browser/API evidence run.",
        "",
        "| ID | Status | Readiness item | Evidence | Proof command |",
        "|---|---|---|---|---|",
    ]
    for item in items:
        lines.append(
            f"| `{item.item_id}` | {item.icon} {item.status} | {item.title} | "
            f"`{item.evidence}` | `{item.command}` |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown.")
    args = parser.parse_args()

    items = build_items(REPO_ROOT)
    if args.json:
        payload = {"summary": summarize(items), "items": [asdict(item) for item in items]}
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    else:
        sys.stdout.write(render_markdown(items))

    return 1 if any(item.status == "fail" for item in items) else 0


if __name__ == "__main__":
    sys.exit(main())
