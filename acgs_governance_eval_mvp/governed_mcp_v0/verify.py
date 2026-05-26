"""Audit-chain replay verification for governed MCP v0.

Walks the audit JSONL hash chain, re-derives every event hash from its
recorded receipt, and re-checks that each "allow" decision left the
expected fixture-tree side effect (file content, outbox row, deploy
state, github mutation).

Pure read-only — never mutates the audit chain or the fixture tree.
"""
from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Any

from ._io import (
    _contains,
    _read_json,
    _resolve_fixture_path,
    sha256_json,
)
from .constants import GENESIS_HASH
from .models import ReplayResult, RuntimeTargets


def _iter_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            value = json.loads(line)
            if isinstance(value, dict):
                rows.append(value)
    return rows


def _verify_allowed_effect(
    targets: RuntimeTargets,
    receipt: dict[str, Any],
    line_number: int,
    failures: list[str],
) -> None:
    if receipt.get("decision") != "allow":
        return
    action_id = receipt.get("action_id")
    args = receipt.get("normalized_args")
    if not isinstance(args, dict):
        failures.append(f"audit line {line_number}: missing_normalized_args")
        return

    if action_id == "filesystem.write_file":
        raw_path = args.get("path")
        content_hash = args.get("content_hash")
        if not isinstance(raw_path, str) or not isinstance(content_hash, str):
            failures.append(f"audit line {line_number}: filesystem_effect_args_invalid")
            return
        try:
            target = _resolve_fixture_path(targets.fs_dir, raw_path)
        except ValueError:
            failures.append(f"audit line {line_number}: filesystem_effect_path_escape")
            return
        if not target.exists():
            failures.append(f"audit line {line_number}: filesystem_effect_missing")
        elif sha256(target.read_bytes()).hexdigest() != content_hash:
            failures.append(f"audit line {line_number}: filesystem_effect_hash_mismatch")
        return

    if action_id == "email.send":
        try:
            outbox_rows = _iter_jsonl(targets.outbox_path)
        except Exception:
            failures.append(f"audit line {line_number}: email_effect_malformed")
            return
        expected_to = args.get("to")
        expected_subject = args.get("subject")
        expected_body_hash = args.get("body_hash")
        matched = any(
            row.get("to") == expected_to
            and row.get("subject") == expected_subject
            and isinstance(row.get("body"), str)
            and sha256(str(row.get("body")).encode("utf-8")).hexdigest() == expected_body_hash
            for row in outbox_rows
        )
        if not matched:
            failures.append(f"audit line {line_number}: email_effect_missing_or_mismatched")
        return

    if action_id == "deploy.restart_service":
        try:
            state = (
                _read_json(targets.deploy_state_path)
                if targets.deploy_state_path.exists()
                else {}
            )
        except Exception:
            failures.append(f"audit line {line_number}: deploy_effect_malformed")
            return
        if state != {
            "service": args.get("service"),
            "environment": args.get("environment"),
            "status": "restarted",
        }:
            failures.append(f"audit line {line_number}: deploy_effect_mismatch")
        return

    if action_id == "github.mutate_repo":
        try:
            state = (
                _read_json(targets.github_state_path)
                if targets.github_state_path.exists()
                else {}
            )
        except Exception:
            failures.append(f"audit line {line_number}: github_effect_malformed")
            return
        mutations = state.get("mutations", [])
        matched = any(
            isinstance(row, dict)
            and row.get("repo") == args.get("repo")
            and row.get("mutation") == args.get("mutation")
            and sha256_json(row.get("payload")) == args.get("payload_hash")
            for row in mutations
        )
        if not matched:
            failures.append(f"audit line {line_number}: github_effect_missing_or_mismatched")


def verify_replay_bundle(targets: RuntimeTargets) -> ReplayResult:
    failures: list[str] = []
    previous_hash = GENESIS_HASH
    checked = 0
    if not targets.audit_path.exists():
        return ReplayResult(valid=False, checked_events=0, failures=["missing audit.jsonl"])
    with targets.audit_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            checked += 1
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                failures.append(f"audit line {line_number}: malformed json")
                continue
            if event.get("previous_hash") != previous_hash:
                failures.append(f"audit line {line_number}: previous_hash_mismatch")
            claimed_hash = event.get("event_hash")
            event_core = dict(event)
            event_core.pop("event_hash", None)
            recomputed_hash = sha256_json(event_core)
            if claimed_hash != recomputed_hash:
                failures.append(f"audit line {line_number}: event_hash_mismatch")
            receipt_ref = event.get("receipt_path")
            if not isinstance(receipt_ref, str):
                failures.append(f"audit line {line_number}: missing receipt_path")
                previous_hash = str(claimed_hash)
                continue
            receipt_path = (targets.evidence_dir / receipt_ref).resolve()
            if not _contains(targets.evidence_dir, receipt_path):
                failures.append(f"audit line {line_number}: receipt_path_escape")
            elif not receipt_path.exists():
                failures.append(f"audit line {line_number}: missing_receipt")
            else:
                receipt = _read_json(receipt_path)
                required = {
                    "action_id",
                    "tool_name",
                    "normalized_args_hash",
                    "normalized_args",
                    "policy_ids",
                    "decision",
                    "reason",
                    "timestamp",
                    "constitution_hash",
                    "event_hash",
                }
                missing = sorted(required.difference(receipt))
                if missing:
                    failures.append(
                        f"audit line {line_number}: receipt_missing_fields={','.join(missing)}"
                    )
                receipt_core = dict(receipt)
                receipt_event_hash = receipt_core.pop("event_hash", None)
                if sha256_json(receipt_core) != event.get("receipt_hash"):
                    failures.append(f"audit line {line_number}: receipt_hash_mismatch")
                if receipt_event_hash != claimed_hash:
                    failures.append(f"audit line {line_number}: receipt_event_hash_mismatch")
                _verify_allowed_effect(targets, receipt, line_number, failures)
            previous_hash = str(claimed_hash)
    return ReplayResult(
        valid=not failures and checked > 0,
        checked_events=checked,
        failures=failures,
    )
