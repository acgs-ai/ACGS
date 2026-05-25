#!/usr/bin/env python3
"""Summarize whether the current release evidence is ready for production launch.

The preflight is intentionally conservative. It reads the local release-evidence
manifest and returns `blocked` until local readiness has zero failures/pending
items, saved live-verifier output passes, the production evidence chain is
consistent, validation output passes, and external blocker rows have been
replaced by attached proof. It does not deploy, mutate DNS, fetch live origins,
or grant authority to launch.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = REPO_ROOT / "dist-release-evidence" / "manifest.json"
CLAIM_BOUNDARY = (
    "Production launch preflight over local release evidence only; not production "
    "deployment proof, not deploy approval, not DNS proof, not hosted Storybook "
    "proof, and not legal/SOC2/WCAG/pentest/regulatory assurance."
)


def _strings(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return [str(value) for value in values if isinstance(value, str) and value.strip()]


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _blocker(action_id: str, title: str, evidence: Any) -> dict[str, Any]:
    return {"id": action_id, "title": title, "evidence": evidence}


def _compact_artifact(artifact: dict[str, Any], keys: list[str]) -> dict[str, Any]:
    return {key: artifact[key] for key in keys if key in artifact and artifact[key] is not None}


def _proof_intake_artifacts(artifacts: dict[str, Any]) -> dict[str, Any]:
    """Return the local templates/operators that can replace external blockers."""

    return {
        "productionLaunchHandoff": _compact_artifact(
            _dict(artifacts.get("productionLaunchHandoff")),
            ["handoff", "proofCommand", "claimBoundary"],
        ),
        "productionAuthorityPacket": _compact_artifact(
            _dict(artifacts.get("productionAuthorityPacket")),
            [
                "templatePath",
                "proofCommand",
                "templateStatus",
                "requiredApprovalIds",
                "claimBoundary",
            ],
        ),
        "productionEvidenceTemplate": _compact_artifact(
            _dict(artifacts.get("productionEvidenceTemplate")),
            ["templatePath", "proofCommand", "templateStatus", "claimBoundary"],
        ),
        "productionLiveVerifier": _compact_artifact(
            _dict(artifacts.get("productionLiveVerifier")),
            ["liveProofCommand", "savedOutputCommand", "targets", "claimBoundary"],
        ),
        "hostedStorybookProofTemplate": _compact_artifact(
            _dict(artifacts.get("hostedStorybookProofTemplate")),
            [
                "templatePath",
                "proofCommand",
                "templateStatus",
                "requiredPassingCheckIds",
                "requiredAbsentBlockerIds",
                "claimBoundary",
            ],
        ),
    }


def _proof_intake_ids_for_blocker(blocker_id: str) -> list[str]:
    mapping = {
        "production-deployment": [
            "productionLaunchHandoff",
            "productionAuthorityPacket",
            "productionEvidenceTemplate",
            "productionLiveVerifier",
        ],
        "frontend-production-auth": [
            "productionAuthorityPacket",
            "productionEvidenceTemplate",
            "productionLiveVerifier",
        ],
        "legal-review-of-claim-matrix": ["productionEvidenceTemplate"],
        "third-party-penetration-test": ["productionEvidenceTemplate"],
        "full-wcag-manual-screen-reader-evidence": ["productionEvidenceTemplate"],
        "hosted-storybook-buyer-evidence": [
            "hostedStorybookProofTemplate",
            "productionEvidenceTemplate",
            "productionLiveVerifier",
        ],
    }
    return mapping.get(blocker_id, ["productionEvidenceTemplate"])


def _git(args: list[str], repo_root: Path = REPO_ROOT) -> str | None:
    try:
        return subprocess.check_output(
            ["git", *args],
            cwd=repo_root,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None


def _current_repository_snapshot(repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    status_lines = (_git(["status", "--short"], repo_root) or "").splitlines()
    return {
        "path": str(repo_root),
        "branch": _git(["branch", "--show-current"], repo_root),
        "commit": _git(["rev-parse", "HEAD"], repo_root),
        "dirty": bool(status_lines),
        "dirtyEntryCount": len(status_lines),
    }


def _repository_freshness_issues(
    manifest_repository: dict[str, Any],
    current_repository: dict[str, Any],
) -> list[str]:
    issues: list[str] = []
    manifest_commit = manifest_repository.get("commit")
    current_commit = current_repository.get("commit")
    if not manifest_commit:
        issues.append("manifest-commit-missing")
    if manifest_repository.get("dirty") or manifest_repository.get("dirtyEntryCount", 0):
        issues.append("manifest-dirty")
    if current_repository.get("dirty") or current_repository.get("dirtyEntryCount", 0):
        issues.append("current-worktree-dirty")
    if manifest_commit and current_commit and manifest_commit != current_commit:
        issues.append("manifest-commit-does-not-match-current-head")
    return issues


def build_preflight(
    manifest: dict[str, Any],
    *,
    manifest_path: Path | str = DEFAULT_MANIFEST,
    current_repository: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a conservative production launch preflight decision."""

    manifest_repository = _dict(manifest.get("repository"))
    current_repository = (
        _current_repository_snapshot() if current_repository is None else _dict(current_repository)
    )
    repository_issues = _repository_freshness_issues(
        manifest_repository,
        current_repository,
    )

    readiness = _dict(manifest.get("readiness"))
    summary = _dict(readiness.get("summary"))
    pending_item_ids = _strings(readiness.get("pendingItemIds"))
    failing_item_ids = _strings(readiness.get("failingItemIds"))

    artifacts = _dict(manifest.get("evidenceArtifacts"))
    live_snapshot = _dict(
        _dict(artifacts.get("productionLiveVerifier")).get("latestOutputSnapshot")
    )
    chain_snapshot = _dict(
        _dict(artifacts.get("productionEvidenceChain")).get("latestChainSnapshot")
    )
    validation_snapshot = _dict(
        _dict(artifacts.get("productionEvidenceValidation")).get("latestValidationSnapshot")
    )

    proof_intake_artifacts = _proof_intake_artifacts(artifacts)
    external_blockers = []
    for blocker in manifest.get("externalBlockers", []):
        if not isinstance(blocker, dict) or not blocker.get("blockerId"):
            continue
        blocker_id = str(blocker["blockerId"])
        external_blockers.append(
            {
                **blocker,
                "blockerId": blocker_id,
                "proofIntakeArtifactIds": _proof_intake_ids_for_blocker(blocker_id),
            }
        )
    external_blocker_ids = [str(blocker["blockerId"]) for blocker in external_blockers]
    live_blockers = _strings(live_snapshot.get("blockers"))
    chain_issues = _strings(chain_snapshot.get("issues"))
    validation_failures = _strings(validation_snapshot.get("failingCheckIds"))

    required_actions: list[dict[str, Any]] = []
    if repository_issues:
        required_actions.append(
            _blocker(
                "refresh-release-evidence-clean-commit",
                "Regenerate release evidence from the current clean commit before launch.",
                {
                    "issues": repository_issues,
                    "manifestRepository": manifest_repository,
                    "currentRepository": current_repository,
                },
            )
        )
    if summary.get("fail", 0) or failing_item_ids:
        required_actions.append(
            _blocker(
                "resolve-local-readiness-failures",
                "Fix failing local readiness items before launch.",
                {"failCount": summary.get("fail"), "failingItemIds": failing_item_ids},
            )
        )
    if summary.get("pending", 0) or pending_item_ids:
        required_actions.append(
            _blocker(
                "clear-local-readiness-pending-items",
                "Clear or replace pending local readiness items with attached proof.",
                {"pendingCount": summary.get("pending"), "pendingItemIds": pending_item_ids},
            )
        )
    if live_snapshot.get("present") is not True:
        required_actions.append(
            _blocker(
                "attach-production-live-verifier-output",
                "Attach saved verify:production-live JSON before launch.",
                {"path": live_snapshot.get("path")},
            )
        )
    elif live_snapshot.get("status") != "pass" or live_blockers:
        required_actions.append(
            _blocker(
                "attach-passing-production-live-verifier-output",
                "Run live production checks after deploy and attach a passing verifier output.",
                {"status": live_snapshot.get("status"), "blockers": live_blockers},
            )
        )
    if chain_snapshot.get("status") != "consistent" or chain_issues:
        required_actions.append(
            _blocker(
                "refresh-production-evidence-chain",
                "Regenerate release evidence until saved handoff artifacts agree.",
                {"status": chain_snapshot.get("status"), "issues": chain_issues},
            )
        )
    if validation_snapshot.get("present") is not True:
        required_actions.append(
            _blocker(
                "attach-production-evidence-validation",
                "Attach production evidence validator output before launch.",
                {"path": validation_snapshot.get("path")},
            )
        )
    elif validation_snapshot.get("status") != "pass" or validation_failures:
        required_actions.append(
            _blocker(
                "pass-production-evidence-validation",
                "Fix production evidence validation failures before launch.",
                {"status": validation_snapshot.get("status"), "failures": validation_failures},
            )
        )
    if external_blocker_ids:
        required_actions.append(
            _blocker(
                "replace-external-blockers-with-proof",
                "Attach external deployment, authority, assurance, and hosted proof before launch.",
                {
                    "externalBlockerIds": external_blocker_ids,
                    "externalBlockers": external_blockers,
                    "proofIntakeArtifacts": proof_intake_artifacts,
                },
            )
        )

    status = "ready" if not required_actions else "blocked"
    return {
        "schemaVersion": 1,
        "artifactKind": "production-launch-preflight",
        "generatedAt": dt.datetime.now(dt.UTC).isoformat(),
        "status": status,
        "manifestPath": str(manifest_path),
        "claimBoundary": CLAIM_BOUNDARY,
        "repository": {
            "manifest": manifest_repository,
            "current": current_repository,
            "issues": repository_issues,
        },
        "readinessSummary": summary,
        "pendingItemIds": pending_item_ids,
        "failingItemIds": failing_item_ids,
        "productionLive": {
            "path": live_snapshot.get("path"),
            "present": live_snapshot.get("present"),
            "status": live_snapshot.get("status"),
            "blockers": live_blockers,
            "generatedAt": live_snapshot.get("generatedAt"),
        },
        "productionEvidenceChain": {
            "status": chain_snapshot.get("status"),
            "issues": chain_issues,
            "validation": chain_snapshot.get("validation"),
        },
        "productionEvidenceValidation": {
            "path": validation_snapshot.get("path"),
            "present": validation_snapshot.get("present"),
            "status": validation_snapshot.get("status"),
            "failingCheckIds": validation_failures,
        },
        "externalBlockerIds": external_blocker_ids,
        "externalBlockers": external_blockers,
        "proofIntakeArtifacts": proof_intake_artifacts,
        "requiredActions": required_actions,
    }


def render_markdown(preflight: dict[str, Any]) -> str:
    actions = (
        preflight.get("requiredActions")
        if isinstance(preflight.get("requiredActions"), list)
        else []
    )
    action_lines = (
        "\n".join(
            f"- `{action['id']}` — {action['title']}"
            for action in actions
            if isinstance(action, dict) and action.get("id")
        )
        or "- None. Verify live launch authority before deployment."
    )
    blockers = ", ".join(preflight.get("externalBlockerIds", [])) or "none"
    proof_intakes = _dict(preflight.get("proofIntakeArtifacts"))
    proof_intake_refs = ", ".join(
        str(meta.get("templatePath") or meta.get("handoff") or meta.get("liveProofCommand"))
        for meta in proof_intakes.values()
        if isinstance(meta, dict)
        and (meta.get("templatePath") or meta.get("handoff") or meta.get("liveProofCommand"))
    )
    proof_intake_refs = proof_intake_refs or "none"
    return f"""# Production launch preflight

Status: `{preflight["status"]}`

{preflight["claimBoundary"]}

- Manifest: `{preflight["manifestPath"]}`
- Repository freshness: `{preflight["repository"].get("issues") or "current clean commit"}`
- Readiness: `{preflight["readinessSummary"]}`
- Pending items: `{", ".join(preflight["pendingItemIds"]) or "none"}`
- Live verifier status: `{preflight["productionLive"].get("status")}`
- Production evidence chain: `{preflight["productionEvidenceChain"].get("status")}`
- External blockers: `{blockers}`
- Proof intake artifacts: `{proof_intake_refs}`

## Required actions

{action_lines}
"""


def load_manifest(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--out", help="Optional path to write the preflight JSON artifact.")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of markdown.")
    parser.add_argument(
        "--require-ready",
        action="store_true",
        help="Exit non-zero when the preflight status is not ready.",
    )
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    if not manifest_path.is_file():
        print(f"Release evidence manifest not found: {manifest_path}")
        print("Run `make release-evidence` first.")
        return 2

    preflight = build_preflight(load_manifest(manifest_path), manifest_path=manifest_path)
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(preflight, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    if args.json:
        print(json.dumps(preflight, indent=2, sort_keys=True))
    else:
        print(render_markdown(preflight))

    if args.require_ready and preflight["status"] != "ready":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
