#!/usr/bin/env python3
"""Build a local deployment-blocked production evidence packet.

This is an operator convenience wrapper around the existing acgi-ai evidence
builders. It may run the live verifier when no --live-output is supplied, but it
never deploys, mutates DNS, approves release authority, installs dependencies,
or creates live production proof. Failing live verification is expected before
external production DNS/deploy/Storybook proof exists; the command preserves that
failure as blocker evidence and generates the local handoff artifacts that the
release evidence bundle can compare for drift.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
ACGI_ROOT = REPO_ROOT / "acgi-ai"
EVIDENCE_DIR = REPO_ROOT / "dist-release-evidence"
NODE24_GATE = REPO_ROOT / "scripts" / "run_acgi_node24_gate.sh"

CLAIM_BOUNDARY = (
    "Local production-blocker evidence orchestration only; may run the live "
    "verifier when requested/defaulted, but does not deploy, mutate DNS, approve "
    "release authority, install dependencies, create hosted Storybook proof, or "
    "create live production proof; it is not live production proof."
)

OUTPUTS = {
    "live": EVIDENCE_DIR / "production-live-verification.json",
    "blockerReport": EVIDENCE_DIR / "production-blocker-report.json",
    "cutoverPlan": EVIDENCE_DIR / "production-cutover-plan.json",
    "hostedStorybookHandoff": EVIDENCE_DIR / "hosted-storybook-handoff.json",
    "evidenceDraft": EVIDENCE_DIR / "production-evidence.deployment-blocked.json",
    "evidenceValidation": EVIDENCE_DIR / "production-evidence-validation.deployment-blocked.json",
    "releaseManifest": EVIDENCE_DIR / "manifest.json",
    "preflight": EVIDENCE_DIR / "production-launch-preflight.json",
}


def _rel_for_acgi(path: Path) -> str:
    return os.path.relpath(path.resolve(), ACGI_ROOT).replace(os.sep, "/")


def _rel_for_repo(path: Path) -> str:
    return os.path.relpath(path.resolve(), REPO_ROOT).replace(os.sep, "/")


def _command_entry(
    command_id: str,
    cmd: list[str],
    *,
    env: dict[str, str] | None = None,
    continue_on_nonzero_with_output: Path | None = None,
) -> dict[str, Any]:
    return {
        "id": command_id,
        "cmd": cmd,
        "cwd": str(REPO_ROOT),
        "env": env or {},
        "continueOnNonzeroWithOutput": (
            _rel_for_repo(continue_on_nonzero_with_output)
            if continue_on_nonzero_with_output
            else None
        ),
    }


def _acgi_command(*args: str) -> list[str]:
    """Return an acgi-ai pnpm command guarded by the exact Node 24 wrapper."""

    return ["bash", _rel_for_repo(NODE24_GATE), "pnpm", "-F", "acgi-ai", *args]


def build_plan(args: argparse.Namespace) -> list[dict[str, Any]]:
    live_output = Path(args.live_output).resolve() if args.live_output else OUTPUTS["live"]
    live_out_for_acgi = _rel_for_acgi(OUTPUTS["live"])
    blocker_report_for_acgi = _rel_for_acgi(OUTPUTS["blockerReport"])
    cutover_plan_for_acgi = _rel_for_acgi(OUTPUTS["cutoverPlan"])
    hosted_handoff_for_acgi = _rel_for_acgi(OUTPUTS["hostedStorybookHandoff"])
    evidence_draft_for_acgi = _rel_for_acgi(OUTPUTS["evidenceDraft"])
    validation_for_repo = _rel_for_repo(OUTPUTS["evidenceValidation"])

    commands: list[dict[str, Any]] = [
        _command_entry(
            "build-buyer-evidence-gallery",
            _acgi_command("run", "evidence:build"),
            env={"ACGI_EVIDENCE_CNAME": "storybook.acgs.ai"},
        )
    ]

    if args.live_output:
        commands.append(
            _command_entry(
                "copy-supplied-live-output",
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--internal-copy-live-output",
                    str(live_output),
                    str(OUTPUTS["live"]),
                ],
            )
        )
    else:
        commands.append(
            _command_entry(
                "run-production-live-verifier",
                _acgi_command(
                    "run",
                    "verify:production-live",
                    "--",
                    "--json",
                    "--out",
                    live_out_for_acgi,
                    "--timeout-ms",
                    str(args.timeout_ms),
                ),
                continue_on_nonzero_with_output=OUTPUTS["live"],
            )
        )

    commands.extend(
        [
            _command_entry(
                "build-production-blocker-report",
                _acgi_command(
                    "run",
                    "build:production-blocker-report",
                    "--",
                    "--live-output",
                    live_out_for_acgi,
                    "--out",
                    blocker_report_for_acgi,
                ),
            ),
            _command_entry(
                "build-production-cutover-plan",
                _acgi_command(
                    "run",
                    "build:production-cutover-plan",
                    "--",
                    "--live-output",
                    live_out_for_acgi,
                    "--blocker-report",
                    blocker_report_for_acgi,
                    "--out",
                    cutover_plan_for_acgi,
                ),
            ),
            _command_entry(
                "build-hosted-storybook-handoff",
                _acgi_command(
                    "run",
                    "build:hosted-storybook-handoff",
                    "--",
                    "--buyer-evidence-manifest",
                    "dist-buyer-evidence/manifest.json",
                    "--live-output",
                    live_out_for_acgi,
                    "--out",
                    hosted_handoff_for_acgi,
                ),
            ),
        ]
    )

    if not args.dry_run:
        live = _read_json(OUTPUTS["live"], "live verifier output")
        blockers = live.get("blockers") if isinstance(live.get("blockers"), list) else []
        if live.get("status") == "fail" and blockers:
            commands.extend(
                [
                    _command_entry(
                        "build-production-evidence-draft",
                        _acgi_command(
                            "run",
                            "build:production-evidence-draft",
                            "--",
                            "--live-output",
                            live_out_for_acgi,
                            "--blocker-report",
                            blocker_report_for_acgi,
                            "--cutover-plan",
                            cutover_plan_for_acgi,
                            "--out",
                            evidence_draft_for_acgi,
                            "--validation-output-ref",
                            validation_for_repo,
                        ),
                    ),
                    _command_entry(
                        "validate-deployment-blocked-production-evidence",
                        _acgi_command(
                            "run",
                            "validate:production-evidence",
                            "--",
                            "--manifest",
                            evidence_draft_for_acgi,
                            "--live-output",
                            live_out_for_acgi,
                            "--out",
                            _rel_for_acgi(OUTPUTS["evidenceValidation"]),
                        ),
                    ),
                ]
            )
    else:
        commands.extend(
            [
                _command_entry(
                    "build-production-evidence-draft-when-live-fails",
                    _acgi_command(
                        "run",
                        "build:production-evidence-draft",
                        "--",
                        "--live-output",
                        live_out_for_acgi,
                        "--blocker-report",
                        blocker_report_for_acgi,
                        "--cutover-plan",
                        cutover_plan_for_acgi,
                        "--out",
                        evidence_draft_for_acgi,
                        "--validation-output-ref",
                        validation_for_repo,
                    ),
                ),
                _command_entry(
                    "validate-deployment-blocked-production-evidence-when-live-fails",
                    _acgi_command(
                        "run",
                        "validate:production-evidence",
                        "--",
                        "--manifest",
                        evidence_draft_for_acgi,
                        "--live-output",
                        live_out_for_acgi,
                        "--out",
                        _rel_for_acgi(OUTPUTS["evidenceValidation"]),
                    ),
                ),
            ]
        )

    commands.extend(
        [
            _command_entry(
                "refresh-release-evidence-bundle",
                ["uv", "run", "python", "scripts/build_release_evidence.py"],
            ),
            _command_entry(
                "write-production-launch-preflight-json",
                [
                    "uv",
                    "run",
                    "python",
                    "scripts/production_launch_preflight.py",
                    "--manifest",
                    _rel_for_repo(OUTPUTS["releaseManifest"]),
                    "--out",
                    _rel_for_repo(OUTPUTS["preflight"]),
                    "--json",
                ],
            ),
        ]
    )
    return commands


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError(f"Missing {label}: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid {label} JSON at {path}: {exc}") from exc


def _extract_single_json_artifact(
    text: str,
    *,
    label: str,
    artifact_kind: str,
) -> dict[str, Any]:
    """Extract exactly one artifact JSON object from a wrapper-captured transcript.

    Operators should prefer verifier ``--out`` files because they are clean JSON,
    but package-manager wrappers can print engine warnings before/after stdout
    when an operator captures ``pnpm ... --json`` output directly. Accept only a
    single object with the expected ``artifactKind`` so noisy transcripts can be
    canonicalized without treating arbitrary logs as valid proof.
    """
    decoder = json.JSONDecoder()
    matches: list[dict[str, Any]] = []
    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            parsed, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and parsed.get("artifactKind") == artifact_kind:
            matches.append(parsed)

    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise RuntimeError(
            f"Invalid {label} JSON transcript: found {len(matches)} "
            f"{artifact_kind} artifacts; attach one verifier output"
        )
    raise RuntimeError(f"Invalid {label} JSON transcript: no {artifact_kind} artifact found")


def _read_json_artifact(path: Path, label: str, artifact_kind: str) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise RuntimeError(f"Missing {label}: {path}") from exc

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return _extract_single_json_artifact(
            text,
            label=label,
            artifact_kind=artifact_kind,
        )

    if not isinstance(payload, dict):
        raise RuntimeError(f"Invalid {label} JSON at {path}: expected object")
    return payload


def _copy_live_output(source: Path, destination: Path) -> int:
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = _read_json_artifact(
        source,
        "supplied live verifier output",
        "production-live-verification",
    )
    if payload.get("artifactKind") != "production-live-verification":
        print(
            "supplied live output artifactKind must be production-live-verification",
            file=sys.stderr,
        )
        return 2
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Copied live output {source} -> {destination}")
    return 0


def run_command(entry: dict[str, Any]) -> None:
    env = os.environ.copy()
    env.update({str(k): str(v) for k, v in entry.get("env", {}).items()})
    print(f"==> {entry['id']}: {' '.join(entry['cmd'])}")
    result = subprocess.run(
        entry["cmd"],
        cwd=entry["cwd"],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    if result.returncode == 0:
        return

    output = entry.get("continueOnNonzeroWithOutput")
    if output:
        output_path = REPO_ROOT / output
        if output_path.is_file():
            print(
                f"Continuing after expected non-zero {entry['id']} because {output} was written.",
                file=sys.stderr,
            )
            return
    raise RuntimeError(f"{entry['id']} failed with exit code {result.returncode}")


def summarize() -> dict[str, Any]:
    live = _read_json(OUTPUTS["live"], "live verifier output")
    preflight = _read_json(OUTPUTS["preflight"], "production launch preflight")
    manifest = _read_json(OUTPUTS["releaseManifest"], "release evidence manifest")
    output_statuses: dict[str, Any] = {}
    for key, path in OUTPUTS.items():
        output_statuses[key] = {"path": _rel_for_repo(path), "present": path.is_file()}
        if path.is_file() and path.suffix == ".json":
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                output_statuses[key].update(
                    {
                        "artifactKind": payload.get("artifactKind"),
                        "status": payload.get("status"),
                    }
                )
            except json.JSONDecodeError:
                output_statuses[key]["status"] = "invalid-json"

    blockers = [
        blocker.get("blockerId")
        for blocker in live.get("blockers", [])
        if isinstance(blocker, dict) and blocker.get("blockerId")
    ]
    return {
        "schemaVersion": 1,
        "artifactKind": "production-blocker-evidence-run",
        "status": "blocked" if blockers or preflight.get("status") != "ready" else "ready",
        "claimBoundary": CLAIM_BOUNDARY,
        "productionLiveStatus": live.get("status"),
        "productionLiveBlockers": blockers,
        "preflightStatus": preflight.get("status"),
        "readinessSummary": manifest.get("readiness", {}).get("summary"),
        "externalBlockerIds": preflight.get("externalBlockerIds", []),
        "outputs": output_statuses,
        "operatorNextSteps": preflight.get("requiredActions", []),
    }


def render_human(payload: dict[str, Any]) -> str:
    blockers = ", ".join(payload.get("productionLiveBlockers", [])) or "none"
    outputs = payload.get("outputs", {})
    output_lines = "\n".join(
        (
            f"- {name}: {meta['path']} "
            f"({'present' if meta.get('present') else 'missing'}, {meta.get('status')})"
        )
        for name, meta in outputs.items()
    )
    return f"""Production blocker evidence run: {payload["status"]}
{payload["claimBoundary"]}

Production live status: {payload.get("productionLiveStatus")}
Production live blockers: {blockers}
Preflight status: {payload.get("preflightStatus")}

Outputs:
{output_lines}
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--live-output",
        help=(
            "Existing production-live-verification JSON to copy into "
            "dist-release-evidence before building handoff artifacts. If omitted, "
            "the live verifier is run and may exit non-zero while still saving JSON."
        ),
    )
    parser.add_argument("--timeout-ms", type=int, default=10_000)
    parser.add_argument("--dry-run", action="store_true", help="Print the planned commands only.")
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    parser.add_argument(
        "--internal-copy-live-output",
        nargs=2,
        metavar=("SOURCE", "DESTINATION"),
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args(argv)

    if args.internal_copy_live_output:
        source, destination = args.internal_copy_live_output
        return _copy_live_output(Path(source), Path(destination))

    if args.timeout_ms < 1:
        parser.error("--timeout-ms must be positive")

    if args.dry_run:
        plan = build_plan(args)
        payload = {
            "schemaVersion": 1,
            "artifactKind": "production-blocker-evidence-plan",
            "status": "dry-run",
            "claimBoundary": CLAIM_BOUNDARY,
            "commands": plan,
            "outputs": {key: _rel_for_repo(path) for key, path in OUTPUTS.items()},
        }
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(f"Production blocker evidence dry run ({len(plan)} commands)")
            print(CLAIM_BOUNDARY)
            for entry in plan:
                print(f"- {entry['id']}: {' '.join(entry['cmd'])}")
        return 0

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    initial_plan = build_plan(argparse.Namespace(**{**vars(args), "dry_run": True}))
    # Run through hosted handoff first; draft/validation are conditional on the fresh live JSON.
    for entry in initial_plan[:5]:
        run_command(entry)
    live = _read_json(OUTPUTS["live"], "live verifier output")
    if live.get("artifactKind") != "production-live-verification":
        raise RuntimeError("production-live-verification artifactKind is required")

    for entry in build_plan(args)[5:]:
        run_command(entry)

    payload = summarize()
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render_human(payload))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
