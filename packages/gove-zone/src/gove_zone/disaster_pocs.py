"""Deterministic orchestration for the three local disaster proof fixtures.

This module deliberately delegates proof generation, verification, and replay to
the product-native P0, P1, and P2 implementations.  It only normalizes their
already-verified evidence into one path-neutral report.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from gove_zone.path_capability import AttestedDirectory, PathCapabilityIdentityError
from gove_zone.proof_pack import PinnedOutputRoot

DISASTER_POCS_REPORT_SCHEMA: Final = "gove-zone.disaster-pocs-report/v1"
DISASTER_POCS_CLAIM_BOUNDARY: Final = "local-fixture-only-no-real-side-effects"
DISASTER_POCS_SCENARIOS: Final = (
    "release-artifact-tamper",
    "mcp-prompt-injection",
    "spend-loop",
)


class DisasterPoCError(ValueError, RuntimeError):
    """Raised when an umbrella proof cannot be generated fail-closed."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


_DIRECTORY_FLAGS: Final = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_OUTPUT_PATH_INVALID: Final = "DISASTER_POCS_OUTPUT_PATH_INVALID"
_OUTPUT_ANCESTOR_UNSAFE: Final = "DISASTER_POCS_OUTPUT_ANCESTOR_UNSAFE"
_OUTPUT_ENTRY_UNSAFE: Final = "DISASTER_POCS_OUTPUT_ENTRY_UNSAFE"
_OUTPUT_NOT_OWNED: Final = "DISASTER_POCS_OUTPUT_NOT_OWNED"
_OUTPUT_NOT_PRIVATE: Final = "DISASTER_POCS_OUTPUT_NOT_PRIVATE"
_OUTPUT_NOT_EMPTY: Final = "DISASTER_POCS_OUTPUT_NOT_EMPTY"
_OUTPUT_IDENTITY_CHANGED: Final = "DISASTER_POCS_OUTPUT_IDENTITY_CHANGED"


@dataclass(frozen=True)
class _OutputGuard:
    path: Path
    parent_identity: tuple[int, int]
    output_identity: tuple[int, int]


def _canonical_digest(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _lexical_absolute(output: str | Path) -> Path:
    raw = os.fspath(output)
    if not raw or "\0" in raw:
        raise DisasterPoCError(_OUTPUT_PATH_INVALID)
    normalized = Path(os.path.abspath(raw))
    if not normalized.is_absolute() or not normalized.name:
        raise DisasterPoCError(_OUTPUT_PATH_INVALID)
    return normalized


def _open_directory_chain(path: Path) -> tuple[int, os.stat_result]:
    """Open an absolute directory one no-follow component at a time."""

    descriptor = -1
    try:
        descriptor = os.open(path.anchor, _DIRECTORY_FLAGS)
        current = os.fstat(descriptor)
        for component in path.parts[1:]:
            before = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                raise DisasterPoCError(_OUTPUT_ANCESTOR_UNSAFE)
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            after = os.fstat(child)
            if _identity(before) != _identity(after) or not stat.S_ISDIR(after.st_mode):
                os.close(child)
                raise DisasterPoCError(_OUTPUT_IDENTITY_CHANGED)
            os.close(descriptor)
            descriptor = child
            current = after
        return descriptor, current
    except DisasterPoCError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except (FileNotFoundError, NotADirectoryError, PermissionError, OSError) as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise DisasterPoCError(_OUTPUT_ANCESTOR_UNSAFE) from exc


def _entry_stat(parent_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise DisasterPoCError(_OUTPUT_ENTRY_UNSAFE) from exc


def _validate_output_entry(
    parent_fd: int,
    name: str,
    *,
    expected_identity: tuple[int, int] | None = None,
    require_empty: bool,
) -> tuple[int, int]:
    before = _entry_stat(parent_fd, name)
    if before is None or not stat.S_ISDIR(before.st_mode):
        raise DisasterPoCError(_OUTPUT_ENTRY_UNSAFE)
    if before.st_uid != os.geteuid():
        raise DisasterPoCError(_OUTPUT_NOT_OWNED)
    if stat.S_IMODE(before.st_mode) != 0o700:
        raise DisasterPoCError(_OUTPUT_NOT_PRIVATE)
    if before.st_nlink < 2:
        raise DisasterPoCError(_OUTPUT_ENTRY_UNSAFE)
    if expected_identity is not None and _identity(before) != expected_identity:
        raise DisasterPoCError(_OUTPUT_IDENTITY_CHANGED)

    descriptor = -1
    try:
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        opened = os.fstat(descriptor)
        if _identity(before) != _identity(opened) or not stat.S_ISDIR(opened.st_mode):
            raise DisasterPoCError(_OUTPUT_IDENTITY_CHANGED)
        if opened.st_uid != os.geteuid() or stat.S_IMODE(opened.st_mode) != 0o700:
            raise DisasterPoCError(_OUTPUT_IDENTITY_CHANGED)
        if require_empty and os.listdir(descriptor):
            raise DisasterPoCError(_OUTPUT_NOT_EMPTY)
        after = _entry_stat(parent_fd, name)
        if after is None or _identity(after) != _identity(opened):
            raise DisasterPoCError(_OUTPUT_IDENTITY_CHANGED)
        if after.st_nlink != opened.st_nlink:
            raise DisasterPoCError(_OUTPUT_IDENTITY_CHANGED)
        return _identity(opened)
    except DisasterPoCError:
        raise
    except OSError as exc:
        raise DisasterPoCError(_OUTPUT_ENTRY_UNSAFE) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _revalidate_output(guard: _OutputGuard, *, require_empty: bool) -> None:
    parent_fd, parent_info = _open_directory_chain(guard.path.parent)
    try:
        if _identity(parent_info) != guard.parent_identity:
            raise DisasterPoCError(_OUTPUT_IDENTITY_CHANGED)
        _validate_output_entry(
            parent_fd,
            guard.path.name,
            expected_identity=guard.output_identity,
            require_empty=require_empty,
        )
    finally:
        os.close(parent_fd)


def _prepare_output(output: str | Path) -> _OutputGuard:
    root = _lexical_absolute(output)
    parent_fd, initial_parent = _open_directory_chain(root.parent)
    try:
        existing = _entry_stat(parent_fd, root.name)
        if existing is not None:
            output_identity = _validate_output_entry(
                parent_fd,
                root.name,
                require_empty=True,
            )
            parent_identity = _identity(initial_parent)
        else:
            os.close(parent_fd)
            parent_fd = -1
            parent_fd, current_parent = _open_directory_chain(root.parent)
            if _identity(current_parent) != _identity(initial_parent):
                raise DisasterPoCError(_OUTPUT_IDENTITY_CHANGED)
            if _entry_stat(parent_fd, root.name) is not None:
                raise DisasterPoCError(_OUTPUT_IDENTITY_CHANGED)
            try:
                os.mkdir(root.name, mode=0o700, dir_fd=parent_fd)
            except OSError as exc:
                raise DisasterPoCError(_OUTPUT_ENTRY_UNSAFE) from exc
            output_identity = _validate_output_entry(
                parent_fd,
                root.name,
                require_empty=True,
            )
            os.close(parent_fd)
            parent_fd = -1
            parent_fd, post_create_parent = _open_directory_chain(root.parent)
            if _identity(post_create_parent) != _identity(current_parent):
                raise DisasterPoCError(_OUTPUT_IDENTITY_CHANGED)
            parent_identity = _identity(post_create_parent)
            _validate_output_entry(
                parent_fd,
                root.name,
                expected_identity=output_identity,
                require_empty=True,
            )
        guard = _OutputGuard(root, parent_identity, output_identity)
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)
    _revalidate_output(guard, require_empty=True)
    return guard


def _read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DisasterPoCError(f"invalid native evidence file: {path.name}") from exc
    if not isinstance(value, dict):
        raise DisasterPoCError(f"native evidence must be an object: {path.name}")
    return value


def _read_rows(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        rows = [json.loads(line) for line in lines if line.strip()]
    except (OSError, json.JSONDecodeError) as exc:
        raise DisasterPoCError(f"invalid native evidence file: {path.name}") from exc
    if not rows or not all(isinstance(row, dict) for row in rows):
        raise DisasterPoCError(f"native evidence must contain object rows: {path.name}")
    return rows


def _read_pinned_object(pinned: PinnedOutputRoot, relative: str) -> dict[str, Any]:
    try:
        value = json.loads(pinned.read_bytes(relative, label=relative))
    except (OSError, json.JSONDecodeError) as exc:
        raise DisasterPoCError("DISASTER_POCS_EVIDENCE_INVALID") from exc
    if not isinstance(value, dict):
        raise DisasterPoCError("DISASTER_POCS_EVIDENCE_INVALID")
    return value


def _read_pinned_rows(pinned: PinnedOutputRoot, relative: str) -> list[dict[str, Any]]:
    try:
        lines = pinned.read_bytes(relative, label=relative).decode("utf-8").splitlines()
        rows = [json.loads(line) for line in lines if line.strip()]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DisasterPoCError("DISASTER_POCS_EVIDENCE_INVALID") from exc
    if not rows or not all(isinstance(row, dict) for row in rows):
        raise DisasterPoCError("DISASTER_POCS_EVIDENCE_INVALID")
    return rows


def _phase_checkpoint(
    pinned: PinnedOutputRoot,
    phase: str,
    phase_hook: Callable[[str, PinnedOutputRoot], None] | None,
) -> None:
    if phase_hook is not None:
        phase_hook(phase, pinned)
    pinned.checkpoint()


def _strings(values: Sequence[object], *, field: str) -> list[str]:
    if not all(isinstance(value, str) and value for value in values):
        raise DisasterPoCError(f"native evidence contains an invalid {field}")
    return [str(value) for value in values]


def _relative_command(*parts: str) -> list[str]:
    if any(Path(part).is_absolute() for part in parts):
        raise DisasterPoCError("public verification commands must be path-relative")
    return list(parts)


def _run_release(
    pinned: PinnedOutputRoot,
    phase_hook: Callable[[str, PinnedOutputRoot], None] | None,
    output_capability: AttestedDirectory,
) -> dict[str, Any]:
    from gove_zone.release_gate import ReleaseProofSinkError
    from gove_zone.release_proof import (
        generate_release_artifact_tamper_demo,
        replay_release_proof_pack,
        verify_release_proof_pack,
    )

    scenario_name = "release-artifact-tamper"
    pinned.mkdir(scenario_name)
    scenario_capability = output_capability.subdirectory(scenario_name)
    scenario_root = scenario_capability.display_path

    def commit_guard(phase: str) -> None:
        try:
            _phase_checkpoint(pinned, f"release:{phase}", phase_hook)
        except DisasterPoCError as exc:
            if exc.reason_code in {
                "pinned output parent identity changed",
                "pinned output root identity changed",
            }:
                raise PathCapabilityIdentityError(PathCapabilityIdentityError.reason_code) from exc
            raise

    _phase_checkpoint(pinned, "release:before-native-hook", phase_hook)
    try:
        native = generate_release_artifact_tamper_demo(
            scenario_root,
            commit_guard=commit_guard,
            path_capability=scenario_capability,
        )
    except PathCapabilityIdentityError as exc:
        raise DisasterPoCError(_OUTPUT_IDENTITY_CHANGED) from exc
    except ReleaseProofSinkError as exc:
        cause: BaseException | None = exc
        seen: set[int] = set()
        while cause is not None and id(cause) not in seen:
            seen.add(id(cause))
            if type(cause) is PathCapabilityIdentityError and cause.args == (
                PathCapabilityIdentityError.reason_code,
            ):
                break
            cause = cause.__cause__
        else:
            raise
        if cause is not None:
            # The local fixture adapter may already have confirmed execution.
            # Keep the concrete non-retryable wrapper in the cause chain while
            # exposing the umbrella's stable identity-change reason code.
            raise DisasterPoCError(_OUTPUT_IDENTITY_CHANGED) from exc
    _phase_checkpoint(pinned, "release:after-native-hook", phase_hook)
    pack = scenario_root / "proof-pack"
    receipt_key = scenario_root / "external-keys" / "receipt-ed25519.pub"
    checkpoint_key = scenario_root / "external-keys" / "checkpoint-ed25519.pub"
    consumption_key = scenario_root / "external-keys" / "consumption-ed25519.pub"
    lifecycle_key = scenario_root / "external-keys" / "lifecycle-ed25519.pub"
    digest = str(native["pack_digest"])
    verified = verify_release_proof_pack(
        pack,
        receipt_public_key=receipt_key,
        checkpoint_public_key=checkpoint_key,
        consumption_public_key=consumption_key,
        lifecycle_public_key=lifecycle_key,
        expected_pack_digest=digest,
        path_capability=scenario_capability,
    )
    replayed = replay_release_proof_pack(
        directory=pack,
        receipt_public_key=receipt_key,
        checkpoint_public_key=checkpoint_key,
        consumption_public_key=consumption_key,
        lifecycle_public_key=lifecycle_key,
        expected_pack_digest=digest,
        path_capability=scenario_capability,
    )
    if not verified.valid or not replayed.valid:
        raise DisasterPoCError("native release verification or replay failed")

    _phase_checkpoint(pinned, "release:before-evidence-read", phase_hook)
    evidence = _read_pinned_object(pinned, f"{scenario_name}/proof-pack/scenario.json")
    approved = evidence["approved_arguments"]
    attempted = evidence["attempted_arguments"]
    if not isinstance(approved, dict) or not isinstance(attempted, dict):
        raise DisasterPoCError("release arguments are malformed")

    verify_command = _relative_command(
        "gove-zone",
        "release",
        "verify-proof-pack",
        "--pack",
        f"{scenario_name}/proof-pack",
        "--receipt-public-key",
        f"{scenario_name}/external-keys/receipt-ed25519.pub",
        "--checkpoint-public-key",
        f"{scenario_name}/external-keys/checkpoint-ed25519.pub",
        "--consumption-public-key",
        f"{scenario_name}/external-keys/consumption-ed25519.pub",
        "--lifecycle-public-key",
        f"{scenario_name}/external-keys/lifecycle-ed25519.pub",
        "--expected-pack-digest",
        digest,
    )
    replay_command = verify_command.copy()
    replay_command[2] = "replay-proof-pack"
    return {
        "scenario": scenario_name,
        "claim_boundary": str(native["claim_boundary"]),
        "decision": str(native["decision"]),
        "unsafe_baseline_mode": "private-local-fixture-no-fallback",
        "baseline": {
            "arguments": attempted,
            "side_effect_calls": int(native["baseline_side_effect_calls"]),
        },
        "governed": {
            "approved_arguments": approved,
            "attempted_arguments": attempted,
            "side_effect_calls": int(native["governed_side_effect_calls"]),
        },
        "companion_allow_side_effect_calls": int(native["companion_allow_side_effect_calls"]),
        "reason_codes": _strings(list(native["reason_codes"]), field="reason code"),
        "receipt_ids": [str(native["approved_receipt_id"])],
        "refusal_ids": [str(native["refusal_id"])],
        "audit_event_ids": _strings(list(native["audit_event_ids"]), field="audit event id"),
        "proof_pack": f"{scenario_name}/proof-pack",
        "pack_digest": digest,
        "verify_command": verify_command,
        "replay_command": replay_command,
    }


def _run_mcp(
    pinned: PinnedOutputRoot,
    phase_hook: Callable[[str, PinnedOutputRoot], None] | None,
    output_capability: AttestedDirectory,
) -> dict[str, Any]:
    import anyio

    from gove_zone.mcp_proof_export import (
        MCPGenuineProofLease,
        export_prompt_injection_disaster_proof,
    )

    scenario_name = "mcp-prompt-injection"
    pinned.mkdir(scenario_name)
    scenario_capability = output_capability.subdirectory(scenario_name)
    scenario_root = scenario_capability.display_path
    pack = scenario_root / "proof-pack"
    envelope = scenario_root / "verification-envelope"
    runtime_capability = output_capability.subdirectory(".disaster-runtime").subdirectory(
        "mcp", create=True
    )

    def commit_guard(phase: str) -> None:
        _phase_checkpoint(pinned, f"mcp:{phase}", phase_hook)

    async def generate() -> Any:
        return await export_prompt_injection_disaster_proof(
            pack,
            envelope,
            runtime_root=runtime_capability.display_path,
            commit_guard=commit_guard,
            pre_codec_barrier=commit_guard,
            output_capability=scenario_capability,
            runtime_capability=runtime_capability,
        )

    _phase_checkpoint(pinned, "mcp:before-native-hook", phase_hook)
    native = anyio.run(generate)
    if not isinstance(native, MCPGenuineProofLease):
        raise DisasterPoCError("capability MCP export did not return an owned lease")
    with native:
        _phase_checkpoint(pinned, "mcp:after-native-hook", phase_hook)
        digest = native.envelope_digest
        verified = native.verify()
        replayed = native.replay()
        if verified != native.pack_digest or replayed != native.pack_digest:
            raise DisasterPoCError("native MCP verification or replay failed")

        _phase_checkpoint(pinned, "mcp:before-evidence-read", phase_hook)
        summary = native.proof_summary
        attack = summary["scenario"].get("attack")
        if not isinstance(attack, dict) or not isinstance(attack.get("arguments"), dict):
            raise DisasterPoCError("MCP attack evidence is malformed")
        protocol = summary["protocol_results"]
        refusal = summary["refusals"]
        receipt_ids = _strings(
            [row["evidence_id"] for row in protocol if row.get("evidence_kind") == "receipt"],
            field="receipt id",
        )
        refusal_ids = _strings([row["evidence_id"] for row in refusal], field="refusal id")
        audit_ids = _strings([row["event_id"] for row in protocol], field="audit event id")
        attack_arguments = {
            "tool_name": attack["tool_name"],
            "arguments": attack["arguments"],
            "untrusted_prompt": attack["untrusted_prompt"],
            "poisoned_tool_description": attack["poisoned_tool_description"],
        }
        verify_command = _relative_command(
            "gove-zone",
            "mcp",
            "verify-proof-pack",
            "--pack",
            f"{scenario_name}/proof-pack",
            "--verification",
            f"{scenario_name}/verification-envelope",
            "--expected-envelope-digest",
            digest,
        )
        replay_command = verify_command.copy()
        replay_command[2] = "replay-proof-pack"
        return {
            "scenario": scenario_name,
            "claim_boundary": "local-fixture-only-no-real-mcp-server",
            "decision": "DENY",
            "unsafe_baseline_mode": str(attack["unsafe_baseline_mode"]),
            "baseline": {
                "arguments": attack_arguments,
                "side_effect_calls": int(attack["baseline_side_effect_calls"]),
            },
            "governed": {
                "arguments": attack_arguments,
                "side_effect_calls": int(attack["governed_downstream_calls"]),
                "prompt_used_as_policy_input": bool(attack["prompt_used_as_policy_input"]),
            },
            "reason_codes": [str(attack["expected_refusal_reason"])],
            "receipt_ids": receipt_ids,
            "refusal_ids": refusal_ids,
            "audit_event_ids": audit_ids,
            "proof_pack": f"{scenario_name}/proof-pack",
            "verification_envelope": f"{scenario_name}/verification-envelope",
            "pack_digest": native.pack_digest,
            "envelope_digest": digest,
            "verify_command": verify_command,
            "replay_command": replay_command,
            "semantic_verified": True,
            "replay_complete": True,
        }


def _run_spend(
    pinned: PinnedOutputRoot,
    phase_hook: Callable[[str, PinnedOutputRoot], None] | None,
    output_capability: AttestedDirectory,
) -> dict[str, Any]:
    from gove_zone.spend_proof_export import (
        export_spend_loop_disaster_proof,
        replay_exported_spend_proof,
        verify_exported_spend_proof,
    )

    scenario_name = "spend-loop"
    pinned.mkdir(scenario_name)
    scenario_capability = output_capability.subdirectory(scenario_name)
    runtime_parent = output_capability.subdirectory(".disaster-runtime")
    runtime_capability = runtime_parent.subdirectory("spend", create=True)
    scenario_root = scenario_capability.display_path
    pack = scenario_root / "proof-pack"
    envelope = scenario_root / "verification-envelope"

    def commit_guard(phase: str) -> None:
        _phase_checkpoint(pinned, f"spend:{phase}", phase_hook)

    _phase_checkpoint(pinned, "spend:before-native-hook", phase_hook)
    try:
        native = export_spend_loop_disaster_proof(
            pack,
            envelope,
            runtime_root=runtime_capability.display_path,
            commit_guard=commit_guard,
            output_capability=scenario_capability,
            runtime_capability=runtime_capability,
        )
    except PathCapabilityIdentityError as exc:
        raise DisasterPoCError(_OUTPUT_IDENTITY_CHANGED) from exc
    _phase_checkpoint(pinned, "spend:after-native-hook", phase_hook)
    digest = str(native.envelope_digest)
    verified = verify_exported_spend_proof(
        pack,
        envelope,
        expected_envelope_digest=digest,
        output_capability=scenario_capability,
    )
    replayed = replay_exported_spend_proof(
        pack,
        envelope,
        expected_envelope_digest=digest,
        output_capability=scenario_capability,
    )
    if verified != native.pack_digest or replayed != native.pack_digest:
        raise DisasterPoCError("native spend verification or replay failed")

    _phase_checkpoint(pinned, "spend:before-evidence-read", phase_hook)
    evidence = _read_pinned_object(pinned, f"{scenario_name}/proof-pack/scenario.json")
    loop = evidence.get("loop")
    if not isinstance(loop, dict):
        raise DisasterPoCError("spend loop evidence is malformed")
    requests = _read_pinned_rows(pinned, f"{scenario_name}/proof-pack/requests.jsonl")
    protocol = _read_pinned_rows(
        pinned,
        f"{scenario_name}/proof-pack/protocol-results.jsonl",
    )
    refusals = _read_pinned_rows(pinned, f"{scenario_name}/proof-pack/refusals.jsonl")
    payments: list[Mapping[str, Any]] = []
    for row in requests:
        arguments = row.get("arguments")
        if not isinstance(arguments, dict) or not isinstance(arguments.get("payment"), dict):
            raise DisasterPoCError("spend request evidence is malformed")
        payments.append(arguments["payment"])
    request_count = int(loop["request_count"])
    if len(payments) != request_count:
        raise DisasterPoCError("spend request evidence count is inconsistent")
    baseline_payments = [
        {
            "provider": "stripe-test",
            "recipient": "vendor-known",
            "amount": "10.00",
            "amount_minor": 1000,
            "currency": "USD",
            "reference": f"unsafe-loop-order-{index:02d}",
        }
        for index in range(1, request_count + 1)
    ]
    receipt_ids = _strings(
        [row["receipt_id"] for row in protocol if row.get("receipt_id") is not None],
        field="receipt id",
    )
    refusal_ids = _strings([row["audit_event_id"] for row in refusals], field="refusal id")
    audit_ids = _strings([row["audit_event_id"] for row in protocol], field="audit event id")
    reason_codes = sorted(
        {
            str(reason)
            for row in refusals
            for reason in row.get("reason_codes", [])
            if isinstance(reason, str)
        }
    )
    verify_command = _relative_command(
        "gove-zone",
        "spend",
        "verify-proof-pack",
        "--pack",
        f"{scenario_name}/proof-pack",
        "--verification",
        f"{scenario_name}/verification-envelope",
        "--expected-envelope-digest",
        digest,
    )
    replay_command = verify_command.copy()
    replay_command[2] = "replay-proof-pack"
    return {
        "scenario": scenario_name,
        "claim_boundary": "local-fixture-only-no-real-payment",
        "decision": "DENY",
        "unsafe_baseline_mode": str(loop["unsafe_baseline_mode"]),
        "baseline": {
            "arguments": baseline_payments,
            "side_effect_calls": int(loop["baseline_effect_count"]),
            "total_minor": int(loop["baseline_total_minor"]),
        },
        "governed": {
            "arguments": payments,
            "side_effect_calls": int(loop["governed_effect_count"]),
            "succeeded_count": int(loop["governed_succeeded_count"]),
            "denied_count": int(loop["governed_denied_count"]),
            "total_minor": int(loop["governed_total_minor"]),
        },
        "request_count": request_count,
        "amount_minor": int(loop["amount_minor"]),
        "currency": str(loop["currency"]),
        "budget_limit_minor": int(loop["budget_limit_minor"]),
        "reason_codes": reason_codes,
        "receipt_ids": receipt_ids,
        "refusal_ids": refusal_ids,
        "audit_event_ids": audit_ids,
        "proof_pack": f"{scenario_name}/proof-pack",
        "verification_envelope": f"{scenario_name}/verification-envelope",
        "pack_digest": str(native.pack_digest),
        "envelope_digest": digest,
        "verify_command": verify_command,
        "replay_command": replay_command,
    }


def _semantic_view(report: Mapping[str, Any]) -> dict[str, Any]:
    stable_fields = (
        "scenario",
        "claim_boundary",
        "decision",
        "unsafe_baseline_mode",
        "baseline",
        "governed",
        "companion_allow_side_effect_calls",
        "request_count",
        "amount_minor",
        "currency",
        "budget_limit_minor",
        "reason_codes",
    )
    return {field: report[field] for field in stable_fields if field in report}


def run_disaster_pocs(
    output: str | Path,
    scenario: str = "all",
    *,
    _phase_hook: Callable[[str, PinnedOutputRoot], None] | None = None,
) -> dict[str, Any]:
    """Generate and independently verify one or all local disaster proof fixtures."""

    if scenario != "all" and scenario not in DISASTER_POCS_SCENARIOS:
        raise DisasterPoCError("DISASTER_POCS_SCENARIO_INVALID")
    guard = _prepare_output(output)
    selected = DISASTER_POCS_SCENARIOS if scenario == "all" else (scenario,)
    reports: list[dict[str, Any]] = []

    try:
        with (
            PinnedOutputRoot.create(
                guard.path,
                error_type=DisasterPoCError,
            ) as pinned,
            pinned.attest() as output_capability,
        ):
            runtime_created = False
            try:
                pinned.mkdir(".disaster-runtime")
                runtime_created = True
                for name in selected:
                    _phase_checkpoint(pinned, f"{name}:before-dispatch", _phase_hook)
                    if name == "release-artifact-tamper":
                        reports.append(_run_release(pinned, _phase_hook, output_capability))
                    elif name == "mcp-prompt-injection":
                        reports.append(_run_mcp(pinned, _phase_hook, output_capability))
                    else:
                        reports.append(_run_spend(pinned, _phase_hook, output_capability))
                _phase_checkpoint(pinned, "before-report", _phase_hook)
            finally:
                if runtime_created:
                    pinned.cleanup(".disaster-runtime")
    except DisasterPoCError as error:
        if error.reason_code.startswith("DISASTER_POCS_"):
            raise
        raise DisasterPoCError("DISASTER_POCS_OUTPUT_IDENTITY_CHANGED") from error

    semantic_evidence = {
        "schema": DISASTER_POCS_REPORT_SCHEMA,
        "claim_boundary": DISASTER_POCS_CLAIM_BOUNDARY,
        "scenario_selection": scenario,
        "scenarios": [_semantic_view(report) for report in reports],
    }
    return {
        "schema": DISASTER_POCS_REPORT_SCHEMA,
        "claim_boundary": DISASTER_POCS_CLAIM_BOUNDARY,
        "scenario_selection": scenario,
        "scenario_digest": _canonical_digest(semantic_evidence),
        "scenario_digest_scope": (
            "semantic-evidence-excludes-paths-random-identifiers-and-proof-digests"
        ),
        "scenarios": reports,
        "valid": True,
    }


__all__ = [
    "DISASTER_POCS_CLAIM_BOUNDARY",
    "DISASTER_POCS_REPORT_SCHEMA",
    "DISASTER_POCS_SCENARIOS",
    "DisasterPoCError",
    "run_disaster_pocs",
]
