"""Genuine P1-C3 MCP proof exporter integration and fail-closed tests."""

from __future__ import annotations

import dataclasses
import json
import os
import shutil
from contextlib import asynccontextmanager
from pathlib import Path

import anyio
import pytest
from mcp import ClientSession

import gove_zone.mcp_proof_export as proof_export_module
from gove_zone.authorization import strict_json_hash
from gove_zone.decision import canonical_json
from gove_zone.mcp_proof import (
    MCP_ACTION_PROOF_CODEC,
    MCP_ACTION_PROOF_PAYLOAD_FILES,
    MCPActionProofError,
)
from gove_zone.mcp_proof_export import (
    MCP_PROOF_ENVELOPE_CODEC,
    MCPGenuineProofExportError,
    export_genuine_mcp_proof,
    verify_exported_mcp_proof,
)


def _reseal_pack(pack: Path) -> str:
    payloads = {name: (pack / name).read_bytes() for name in MCP_ACTION_PROOF_PAYLOAD_FILES}
    entries = MCP_ACTION_PROOF_CODEC.manifest_entries(payloads)
    unsigned = MCP_ACTION_PROOF_CODEC.manifest_payload(entries)
    digest = MCP_ACTION_PROOF_CODEC.pack_digest(unsigned)
    (pack / "manifest.json").write_bytes(
        MCP_ACTION_PROOF_CODEC.json_bytes({**unsigned, "pack_digest": digest})
    )
    return digest


def _reseal_envelope(envelope: Path, pack_digest: str) -> str:
    expected = json.loads((envelope / "expected-pack-digest.json").read_text(encoding="utf-8"))
    expected["pack_digest"] = pack_digest
    (envelope / "expected-pack-digest.json").write_bytes(
        MCP_PROOF_ENVELOPE_CODEC.json_bytes(expected)
    )
    payloads = {
        name: (envelope / name).read_bytes()
        for name in ("expected-pack-digest.json", "trust-bundle.json")
    }
    entries = MCP_PROOF_ENVELOPE_CODEC.manifest_entries(payloads)
    unsigned = MCP_PROOF_ENVELOPE_CODEC.manifest_payload(entries)
    digest = MCP_PROOF_ENVELOPE_CODEC.pack_digest(unsigned)
    (envelope / "manifest.json").write_bytes(
        MCP_PROOF_ENVELOPE_CODEC.json_bytes({**unsigned, "pack_digest": digest})
    )
    return digest


def _refresh_fixture_integrity(fixture: dict[str, object]) -> None:
    before = fixture["ledger_before"]
    after = fixture["ledger_after"]
    call_log = fixture["call_log"]
    assert isinstance(before, list)
    assert isinstance(after, list)
    assert isinstance(call_log, list)
    before_count = len(before)
    after_count = len(after)
    delta = after_count - before_count
    fixture["ledger_before_count"] = before_count
    fixture["ledger_after_count"] = after_count
    fixture["write_delta"] = delta
    fixture["call_count"] = len(call_log)
    fixture["ledger_before_digest"] = strict_json_hash(before)
    fixture["ledger_after_digest"] = strict_json_hash(after)
    fixture["write_delta_digest"] = strict_json_hash(
        {"before": before_count, "after": after_count, "delta": delta}
    )
    fixture["call_log_digest"] = strict_json_hash(call_log)


def _process_is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def test_genuine_normal_and_poison_export_verifies_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = {"list_tools": 0, "call_tool": 0}
    outer_sessions: list[ClientSession] = []
    original_in_process_session = proof_export_module._in_process_client_session
    original_list_tools = ClientSession.list_tools
    original_call_tool = ClientSession.call_tool

    @asynccontextmanager
    async def tracked_in_process_session(server: object) -> object:
        async with original_in_process_session(server) as session:  # type: ignore[arg-type]
            outer_sessions.append(session)
            yield session

    async def tracked_list_tools(self: ClientSession, *args: object, **kwargs: object) -> object:
        if any(self is session for session in outer_sessions):
            calls["list_tools"] += 1
        return await original_list_tools(self, *args, **kwargs)  # type: ignore[arg-type]

    async def tracked_call_tool(self: ClientSession, *args: object, **kwargs: object) -> object:
        if any(self is session for session in outer_sessions):
            calls["call_tool"] += 1
        return await original_call_tool(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        proof_export_module, "_in_process_client_session", tracked_in_process_session
    )
    monkeypatch.setattr(ClientSession, "list_tools", tracked_list_tools)
    monkeypatch.setattr(ClientSession, "call_tool", tracked_call_tool)
    commit_phases: list[str] = []
    barrier_phases: list[str] = []

    async def run() -> None:
        result = await export_genuine_mcp_proof(
            tmp_path / "pack",
            tmp_path / "envelope",
            runtime_root=tmp_path / "private-runtime",
            commit_guard=commit_phases.append,
            pre_codec_barrier=barrier_phases.append,
        )
        verification = verify_exported_mcp_proof(
            result.pack_directory,
            result.envelope_directory,
            expected_envelope_digest=result.envelope_digest,
        )
        assert type(verification) is str
        assert verification == result.pack_digest
        assert len(outer_sessions) == 2
        assert calls == {"list_tools": 1, "call_tool": 2}
        assert commit_phases == [
            "before-pack",
            "after-pack",
            "before-envelope",
            "after-envelope",
        ]
        assert barrier_phases == ["pack", "envelope"]
        assert {path.name for path in result.pack_directory.iterdir()} == {
            *MCP_ACTION_PROOF_PAYLOAD_FILES,
            "manifest.json",
        }

        protocol = [
            json.loads(line)
            for line in (result.pack_directory / "protocol-results.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        ]
        normal, poison = protocol
        for row in protocol:
            assert row["governed_operation"] == "tools/call"
            assert row["authority"] == "mcp.tools.call"
            assert row["downstream_tool"] == "fixture.write_once"
            assert row["signature_purpose"] == "gateway-exchange"
            assert row["signature_algorithm"] == "ed25519"
            assert len(row["signature"]) == 128
        assert normal["downstream_call_count"] == normal["side_effect_write_count"] == 1
        assert normal["downstream_call_digest"]
        assert poison["downstream_call_count"] == poison["side_effect_write_count"] == 0
        assert poison["downstream_call_digest"] == ""

        normal_fixture = json.loads(
            (result.pack_directory / "normal-fixture-state.json").read_text(encoding="utf-8")
        )
        poison_fixture = json.loads(
            (result.pack_directory / "poison-fixture-state.json").read_text(encoding="utf-8")
        )
        assert normal_fixture["ledger_before"] == []
        assert normal_fixture["ledger_after"] == [{"record": "genuine-normal-proof"}]
        assert normal_fixture["call_log"] == [{"tool": "fixture.write_once"}]
        assert normal_fixture["write_delta"] == normal_fixture["call_count"] == 1
        assert poison_fixture["ledger_before"] == poison_fixture["ledger_after"] == []
        assert poison_fixture["call_log"] == []
        assert poison_fixture["write_delta"] == poison_fixture["call_count"] == 0
        poison_consumption = json.loads(
            (result.pack_directory / "poison-consumption-snapshot.json").read_text(encoding="utf-8")
        )
        assert poison_consumption["generation"] == 0
        assert poison_consumption["records"] == []

        public_bytes = b"".join(
            path.read_bytes()
            for root in (result.pack_directory, result.envelope_directory)
            for path in root.iterdir()
        )
        assert str(tmp_path).encode() not in public_bytes
        for forbidden in (
            b"fixture-token",
            b"fixture-downstream-secret",
            b"proof-normal-nonce",
            b"proof-normal-idempotency",
        ):
            assert forbidden not in public_bytes

        for lane in ("normal", "poison"):
            state = tmp_path / "private-runtime" / lane
            fixture_pid = int((state / "fixture.pid").read_text(encoding="utf-8"))
            assert not _process_is_alive(fixture_pid)

    anyio.run(run)


def test_envelope_no_replace_preserves_already_committed_pack(tmp_path: Path) -> None:
    (tmp_path / "envelope").mkdir()

    async def run() -> None:
        with pytest.raises(MCPGenuineProofExportError) as captured:
            await export_genuine_mcp_proof(
                tmp_path / "pack",
                tmp_path / "envelope",
                runtime_root=tmp_path / "private-runtime",
            )
        error = captured.value
        assert error.pack_committed is True
        assert error.envelope_committed is False
        assert error.durability == "pack-committed"
        assert error.retry_safe is False
        assert (tmp_path / "pack" / "manifest.json").is_file()
        assert list((tmp_path / "envelope").iterdir()) == []

    anyio.run(run)


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("governed_operation", "authority"),
        ("governed_operation", "downstream_tool"),
        ("authority", "downstream_tool"),
    ],
)
def test_offline_verifier_rejects_resealed_identity_swap(
    tmp_path: Path, left: str, right: str
) -> None:
    async def run() -> None:
        result = await export_genuine_mcp_proof(
            tmp_path / "pack",
            tmp_path / "envelope",
            runtime_root=tmp_path / "private-runtime",
        )
        mutated = tmp_path / "mutated"
        shutil.copytree(result.pack_directory, mutated)
        protocol_bytes = (mutated / "protocol-results.jsonl").read_text(encoding="utf-8")
        rows = [json.loads(line) for line in protocol_bytes.splitlines()]
        rows[0][left], rows[0][right] = rows[0][right], rows[0][left]
        (mutated / "protocol-results.jsonl").write_text(
            "".join(canonical_json(row) + "\n" for row in rows), encoding="utf-8"
        )
        # Re-seal the public manifests; the signed exchange and semantic links
        # still make the three identity classes non-interchangeable.
        digest = _reseal_pack(mutated)
        envelope_digest = _reseal_envelope(result.envelope_directory, digest)
        with pytest.raises(MCPActionProofError, match="identity/signature"):
            verify_exported_mcp_proof(
                mutated,
                result.envelope_directory,
                expected_envelope_digest=envelope_digest,
            )

    anyio.run(run)


@pytest.mark.parametrize(
    "mutation",
    ["preexisting-normal-ledger", "nonempty-poison-ledger", "normal-args-mismatch"],
)
def test_resealed_fixture_ledger_semantic_substitutions_fail_closed(
    tmp_path: Path, mutation: str
) -> None:
    async def run() -> None:
        result = await export_genuine_mcp_proof(
            tmp_path / "pack",
            tmp_path / "envelope",
            runtime_root=tmp_path / "private-runtime",
        )
        mutated_pack = tmp_path / "mutated-pack"
        mutated_envelope = tmp_path / "mutated-envelope"
        shutil.copytree(result.pack_directory, mutated_pack)
        shutil.copytree(result.envelope_directory, mutated_envelope)
        lane = "poison" if mutation == "nonempty-poison-ledger" else "normal"
        fixture_path = mutated_pack / f"{lane}-fixture-state.json"
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        if mutation == "preexisting-normal-ledger":
            prior = {"record": "preexisting"}
            fixture["ledger_before"] = [prior]
            fixture["ledger_after"] = [prior, {"record": "genuine-normal-proof"}]
        elif mutation == "nonempty-poison-ledger":
            prior = {"record": "preexisting"}
            fixture["ledger_before"] = [prior]
            fixture["ledger_after"] = [prior]
        else:
            fixture["ledger_before"] = []
            fixture["ledger_after"] = [{"record": "different-from-replay"}]
        _refresh_fixture_integrity(fixture)
        fixture_path.write_bytes(MCP_ACTION_PROOF_CODEC.json_bytes(fixture))
        digest = _reseal_pack(mutated_pack)
        envelope_digest = _reseal_envelope(mutated_envelope, digest)
        with pytest.raises(MCPActionProofError, match="fixture .*ledger"):
            verify_exported_mcp_proof(
                mutated_pack,
                mutated_envelope,
                expected_envelope_digest=envelope_digest,
            )

    anyio.run(run)


def test_envelope_verification_uses_one_frozen_trust_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def run() -> None:
        result = await export_genuine_mcp_proof(
            tmp_path / "pack",
            tmp_path / "envelope",
            runtime_root=tmp_path / "private-runtime",
        )
        codec_type = type(MCP_PROOF_ENVELOPE_CODEC)
        original_read = codec_type.read_exact_pack

        def capture_then_swap(self: object, directory: Path) -> dict[str, bytes]:
            snapshot = original_read(self, directory)  # type: ignore[arg-type]
            if self is MCP_PROOF_ENVELOPE_CODEC:
                (directory / "trust-bundle.json").write_bytes(b"{}\n")
            return snapshot

        monkeypatch.setattr(codec_type, "read_exact_pack", capture_then_swap)
        verification = verify_exported_mcp_proof(
            result.pack_directory,
            result.envelope_directory,
            expected_envelope_digest=result.envelope_digest,
        )
        assert verification == result.pack_digest

    anyio.run(run)


def test_post_pack_digest_guard_reports_committed_artifact_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_export = proof_export_module.export_mcp_proof_pack

    def export_with_wrong_returned_digest(*args: object, **kwargs: object) -> object:
        pack = original_export(*args, **kwargs)
        return dataclasses.replace(pack, pack_digest="0" * 64)

    monkeypatch.setattr(
        proof_export_module, "export_mcp_proof_pack", export_with_wrong_returned_digest
    )

    async def run() -> None:
        with pytest.raises(MCPGenuineProofExportError) as captured:
            await export_genuine_mcp_proof(
                tmp_path / "pack",
                tmp_path / "envelope",
                runtime_root=tmp_path / "private-runtime",
            )
        error = captured.value
        assert error.pack_committed is True
        assert error.envelope_committed is False
        assert error.phase == "post-pack-digest-guard"
        assert error.durability == "pack-committed"
        assert error.retry_safe is False
        assert (tmp_path / "pack" / "manifest.json").is_file()
        assert not (tmp_path / "envelope").exists()

    anyio.run(run)


@pytest.mark.parametrize(
    ("failing_phase", "envelope_committed", "durability"),
    [
        ("after-pack", False, "pack-committed"),
        ("before-envelope", False, "pack-committed"),
        ("after-envelope", True, "pack-and-envelope-committed"),
    ],
)
def test_output_root_commit_guard_failure_preserves_committed_artifacts(
    tmp_path: Path,
    failing_phase: str,
    envelope_committed: bool,
    durability: str,
) -> None:
    phases: list[str] = []

    def guard(phase: str) -> None:
        phases.append(phase)
        if phase == failing_phase:
            raise RuntimeError("injected output-root identity failure")

    async def run() -> None:
        with pytest.raises(MCPGenuineProofExportError) as captured:
            await export_genuine_mcp_proof(
                tmp_path / "pack",
                tmp_path / "envelope",
                runtime_root=tmp_path / "private-runtime",
                commit_guard=guard,
            )
        error = captured.value
        assert error.pack_committed is True
        assert error.envelope_committed is envelope_committed
        assert error.phase == f"output-root:{failing_phase}"
        assert error.durability == durability
        assert error.retry_safe is False
        assert (tmp_path / "pack" / "manifest.json").is_file()
        assert (tmp_path / "envelope" / "manifest.json").is_file() is envelope_committed
        assert phases[-1] == failing_phase

    anyio.run(run)


def test_post_envelope_verification_failure_reports_both_commits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_offline_verification(*args: object, **kwargs: object) -> object:
        raise MCPActionProofError("injected offline verification failure")

    monkeypatch.setattr(proof_export_module, "verify_exported_mcp_proof", fail_offline_verification)

    async def run() -> None:
        with pytest.raises(MCPGenuineProofExportError) as captured:
            await export_genuine_mcp_proof(
                tmp_path / "pack",
                tmp_path / "envelope",
                runtime_root=tmp_path / "private-runtime",
            )
        error = captured.value
        assert error.pack_committed is True
        assert error.envelope_committed is True
        assert error.phase == "post-envelope-offline-verify"
        assert error.durability == "pack-and-envelope-committed"
        assert error.retry_safe is False
        assert (tmp_path / "pack" / "manifest.json").is_file()
        assert (tmp_path / "envelope" / "manifest.json").is_file()

    anyio.run(run)


def test_genuine_export_carries_exact_runtime_policy_attestation(tmp_path: Path) -> None:
    async def run() -> None:
        result = await export_genuine_mcp_proof(
            tmp_path / "pack",
            tmp_path / "envelope",
            runtime_root=tmp_path / "private-runtime",
        )
        policy = json.loads((result.pack_directory / "policy.json").read_text(encoding="utf-8"))
        trust = json.loads(
            (result.envelope_directory / "trust-bundle.json").read_text(encoding="utf-8")
        )
        for lane in ("normal", "poison"):
            policy_lane = policy["lanes"][lane]
            trust_lane = trust["lanes"][lane]
            attestation = policy_lane["policy_attestation"]
            assert attestation == trust_lane["policy_attestation"]
            assert attestation == {
                "tenant_id": policy_lane["tenant_id"],
                "artifact_id": "mcp-reference-policy",
                "policy_version": policy_lane["policy_version"],
                "digest": strict_json_hash(policy_lane["artifact"]),
                "resolver_id": "mcp-reference-policy-resolver",
            }

    anyio.run(run)


def test_replacing_pack_and_envelope_fails_original_external_digest(tmp_path: Path) -> None:
    async def run() -> None:
        original = await export_genuine_mcp_proof(
            tmp_path / "original-pack",
            tmp_path / "original-envelope",
            runtime_root=tmp_path / "original-runtime",
        )
        replacement = await export_genuine_mcp_proof(
            tmp_path / "replacement-pack",
            tmp_path / "replacement-envelope",
            runtime_root=tmp_path / "replacement-runtime",
        )
        assert replacement.envelope_digest != original.envelope_digest
        with pytest.raises(MCPActionProofError, match="external expected envelope digest"):
            verify_exported_mcp_proof(
                replacement.pack_directory,
                replacement.envelope_directory,
                expected_envelope_digest=original.envelope_digest,
            )

    anyio.run(run)


@pytest.mark.parametrize("boundary", ["outer", "expected-member"])
def test_v1_envelope_boundaries_are_rejected(tmp_path: Path, boundary: str) -> None:
    async def run() -> None:
        result = await export_genuine_mcp_proof(
            tmp_path / "pack",
            tmp_path / "envelope",
            runtime_root=tmp_path / "private-runtime",
        )
        if boundary == "outer":
            manifest_path = result.envelope_directory / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["schema"] = "gove-zone.mcp-action-proof-envelope/v1"
            manifest_path.write_bytes(MCP_PROOF_ENVELOPE_CODEC.json_bytes(manifest))
            external_digest = result.envelope_digest
        else:
            expected_path = result.envelope_directory / "expected-pack-digest.json"
            expected = json.loads(expected_path.read_text(encoding="utf-8"))
            expected["schema"] = "gove-zone.mcp-action-expected-pack-digest/v1"
            expected_path.write_bytes(MCP_PROOF_ENVELOPE_CODEC.json_bytes(expected))
            external_digest = _reseal_envelope(result.envelope_directory, result.pack_digest)
        with pytest.raises(MCPActionProofError, match="schema|manifest|digest"):
            verify_exported_mcp_proof(
                result.pack_directory,
                result.envelope_directory,
                expected_envelope_digest=external_digest,
            )

    anyio.run(run)


def test_prompt_injection_disaster_export_is_exact_and_offline_verified(tmp_path: Path) -> None:
    from gove_zone.mcp_proof import (
        MCP_POISONED_TOOL_DESCRIPTION,
        MCP_PROMPT_INJECTION_SCENARIO_SCHEMA,
        MCP_PROMPT_INJECTION_TEXT,
    )
    from gove_zone.mcp_proof_export import export_prompt_injection_disaster_proof

    async def run() -> None:
        result = await export_prompt_injection_disaster_proof(
            tmp_path / "pack",
            tmp_path / "envelope",
            runtime_root=tmp_path / "runtime",
        )
        assert (
            verify_exported_mcp_proof(
                result.pack_directory,
                result.envelope_directory,
                expected_envelope_digest=result.envelope_digest,
            )
            == result.pack_digest
        )
        scenario = json.loads((result.pack_directory / "scenario.json").read_text("utf-8"))
        attack = scenario["attack"]
        assert scenario["schema"] == MCP_PROMPT_INJECTION_SCENARIO_SCHEMA
        assert attack["untrusted_prompt"] == MCP_PROMPT_INJECTION_TEXT
        assert attack["poisoned_tool_description"] == MCP_POISONED_TOOL_DESCRIPTION
        assert attack["tool_name"] == "fixture.write_once"
        assert attack["arguments"] == {"record": "genuine-poison-proof"}
        assert attack["baseline_side_effect_calls"] == 1
        assert attack["governed_downstream_calls"] == 0
        assert attack["prompt_used_as_policy_input"] is False

    anyio.run(run)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("untrusted_prompt", "mutated prompt"),
        ("poisoned_tool_description", "mutated description"),
        ("tool_name", "fixture.read_ledger"),
        ("arguments", {"record": "mutated"}),
        ("governed_downstream_calls", 1),
    ],
)
def test_resealed_prompt_injection_attack_mutation_fails_closed(
    tmp_path: Path,
    field: str,
    replacement: object,
) -> None:
    from gove_zone.mcp_proof import MCPActionProofError
    from gove_zone.mcp_proof_export import export_prompt_injection_disaster_proof

    async def run() -> None:
        result = await export_prompt_injection_disaster_proof(
            tmp_path / "pack",
            tmp_path / "envelope",
            runtime_root=tmp_path / "runtime",
        )
        scenario_path = result.pack_directory / "scenario.json"
        scenario = json.loads(scenario_path.read_text("utf-8"))
        scenario["attack"][field] = replacement
        scenario_path.write_bytes(MCP_ACTION_PROOF_CODEC.json_bytes(scenario))
        mutated_pack_digest = _reseal_pack(result.pack_directory)
        envelope_digest = _reseal_envelope(result.envelope_directory, mutated_pack_digest)
        with pytest.raises(MCPActionProofError, match="prompt injection"):
            verify_exported_mcp_proof(
                result.pack_directory,
                result.envelope_directory,
                expected_envelope_digest=envelope_digest,
            )

    anyio.run(run)


def test_capability_proof_export_and_verify_are_descriptor_bound(tmp_path: Path) -> None:
    import anyio

    from gove_zone.mcp_proof_export import MCPGenuineProofLease, export_genuine_mcp_proof
    from gove_zone.proof_pack import PinnedOutputRoot

    async def exercise() -> None:
        output = tmp_path / "cap-proof"
        runtime_root = tmp_path / "cap-runtime"
        with (
            PinnedOutputRoot.create(output) as output_pin,
            output_pin.attest() as output_capability,
            PinnedOutputRoot.create(runtime_root) as runtime_pin,
            runtime_pin.attest() as runtime_capability,
        ):
            exported = await export_genuine_mcp_proof(
                output / "proof-pack",
                output / "verification-envelope",
                runtime_root=runtime_root,
                output_capability=output_capability,
                runtime_capability=runtime_capability,
            )
            assert isinstance(exported, MCPGenuineProofLease)
            with exported:
                assert exported.verify() == exported.pack_digest
                assert exported.replay() == exported.pack_digest

    anyio.run(exercise)


@pytest.mark.parametrize("phase", ["before-runtime", "before-spawn"])
def test_capability_proof_export_rename_swap_fails_closed(tmp_path: Path, phase: str) -> None:
    import anyio

    from gove_zone.mcp_proof_export import export_genuine_mcp_proof
    from gove_zone.path_capability import PathCapabilityIdentityError
    from gove_zone.proof_pack import PinnedOutputRoot

    async def exercise() -> None:
        output = tmp_path / f"rename-proof-{phase}"
        runtime_root = tmp_path / f"rename-runtime-{phase}"
        with (
            PinnedOutputRoot.create(output) as output_pin,
            output_pin.attest() as output_capability,
            PinnedOutputRoot.create(runtime_root) as runtime_pin,
            runtime_pin.attest() as runtime_capability,
        ):
            swapped = False

            def guard(current: str) -> None:
                nonlocal swapped
                if current == phase and not swapped:
                    swapped = True
                    target = runtime_root
                    target.rename(target.with_name(target.name + "-moved"))
                    target.mkdir(mode=0o700)

            with pytest.raises(PathCapabilityIdentityError) as captured:
                await export_genuine_mcp_proof(
                    output / "proof-pack",
                    output / "verification-envelope",
                    runtime_root=runtime_root,
                    commit_guard=guard,
                    output_capability=output_capability,
                    runtime_capability=runtime_capability,
                )
            assert swapped
            assert captured.value is not None

    anyio.run(exercise)


def test_capability_export_terminal_rename_returns_inode_bound_lease(tmp_path: Path) -> None:
    """A replacement pathname cannot redirect a returned capability lease."""
    import asyncio

    from gove_zone.mcp_proof_export import (
        MCPGenuineProofLease,
        export_genuine_mcp_proof,
    )
    from gove_zone.proof_pack import PinnedOutputRoot

    output = tmp_path / "output"
    detached = tmp_path / "detached-output"
    runtime = tmp_path / "runtime"

    async def run() -> None:
        with (
            PinnedOutputRoot.create(output) as output_root,
            output_root.attest() as output_capability,
            PinnedOutputRoot.create(runtime) as runtime_root,
            runtime_root.attest() as runtime_capability,
        ):

            def rename_at_terminal_boundary(phase: str) -> None:
                if phase == "verified":
                    output.rename(detached)
                    output.mkdir(mode=0o700)

            lease = await export_genuine_mcp_proof(
                output / "proof-pack",
                output / "verification-envelope",
                runtime_root=runtime_capability.display_path,
                commit_guard=rename_at_terminal_boundary,
                output_capability=output_capability,
                runtime_capability=runtime_capability,
            )
            assert isinstance(lease, MCPGenuineProofLease)
            with lease:
                assert lease.verify() == lease.pack_digest
                assert lease.replay() == lease.pack_digest
                assert not hasattr(lease, "pack_directory")
                assert not hasattr(lease, "envelope_directory")
                assert not hasattr(lease, "root_fd")
            with pytest.raises(RuntimeError, match="closed"):
                lease.verify()

        assert list(output.iterdir()) == []
        assert (detached / "proof-pack").is_dir()
        assert (detached / "verification-envelope").is_dir()

    asyncio.run(run())


def test_capability_export_verified_hook_error_closes_lease_fds(tmp_path: Path) -> None:
    """An exception after lease construction must not retain child descriptors."""
    import asyncio
    import os

    from gove_zone.mcp_proof_export import export_genuine_mcp_proof
    from gove_zone.proof_pack import PinnedOutputRoot

    output = tmp_path / "output"
    runtime = tmp_path / "runtime"

    def descriptor_count() -> int:
        return len(os.listdir("/proc/self/fd"))

    async def run() -> None:
        with (
            PinnedOutputRoot.create(output) as output_root,
            output_root.attest() as output_capability,
            PinnedOutputRoot.create(runtime) as runtime_root,
            runtime_root.attest() as runtime_capability,
        ):
            before = descriptor_count()

            def fail_after_lease_construction(phase: str) -> None:
                if phase == "verified":
                    raise RuntimeError("terminal hook failure")

            with pytest.raises(RuntimeError, match="terminal hook failure"):
                await export_genuine_mcp_proof(
                    output / "proof-pack",
                    output / "verification-envelope",
                    runtime_root=runtime_capability.display_path,
                    commit_guard=fail_after_lease_construction,
                    output_capability=output_capability,
                    runtime_capability=runtime_capability,
                )
            assert descriptor_count() == before

    asyncio.run(run())


def test_capability_export_repeated_normal_and_error_lifecycles_restore_fd_baseline(
    tmp_path: Path,
) -> None:
    import asyncio
    import os

    from gove_zone.mcp_proof_export import MCPGenuineProofLease, export_genuine_mcp_proof
    from gove_zone.proof_pack import PinnedOutputRoot

    def descriptor_count() -> int:
        return len(os.listdir("/proc/self/fd"))

    async def run() -> None:
        baseline = descriptor_count()
        for index in range(3):
            output = tmp_path / f"normal-output-{index}"
            runtime = tmp_path / f"normal-runtime-{index}"
            with (
                PinnedOutputRoot.create(output) as output_root,
                output_root.attest() as output_capability,
                PinnedOutputRoot.create(runtime) as runtime_root,
                runtime_root.attest() as runtime_capability,
            ):
                lease = await export_genuine_mcp_proof(
                    output / "proof-pack",
                    output / "verification-envelope",
                    runtime_root=runtime_capability.display_path,
                    output_capability=output_capability,
                    runtime_capability=runtime_capability,
                )
                assert isinstance(lease, MCPGenuineProofLease)
                with lease:
                    assert lease.verify() == lease.pack_digest
            assert descriptor_count() == baseline

        for index in range(3):
            output = tmp_path / f"error-output-{index}"
            runtime = tmp_path / f"error-runtime-{index}"
            with (
                PinnedOutputRoot.create(output) as output_root,
                output_root.attest() as output_capability,
                PinnedOutputRoot.create(runtime) as runtime_root,
                runtime_root.attest() as runtime_capability,
            ):

                def fail_terminal_hook(phase: str) -> None:
                    if phase == "verified":
                        raise RuntimeError("terminal hook failure")

                with pytest.raises(RuntimeError, match="terminal hook failure"):
                    await export_genuine_mcp_proof(
                        output / "proof-pack",
                        output / "verification-envelope",
                        runtime_root=runtime_capability.display_path,
                        commit_guard=fail_terminal_hook,
                        output_capability=output_capability,
                        runtime_capability=runtime_capability,
                    )
            assert descriptor_count() == baseline

    asyncio.run(run())


def test_forgotten_lease_gc_restores_fd_baseline_while_parent_is_live(tmp_path: Path) -> None:
    import asyncio
    import gc
    import os
    import weakref

    from gove_zone.mcp_proof_export import export_genuine_mcp_proof
    from gove_zone.proof_pack import PinnedOutputRoot

    async def run() -> None:
        output = tmp_path / "output"
        runtime = tmp_path / "runtime"
        with (
            PinnedOutputRoot.create(output) as output_root,
            output_root.attest() as output_capability,
            PinnedOutputRoot.create(runtime) as runtime_root,
            runtime_root.attest() as runtime_capability,
        ):
            # Collect first so the baseline is quiescent: the gc.collect() below
            # would otherwise reap descriptor-owning garbage left by earlier
            # tests in this process and push the count *below* the baseline.
            gc.collect()
            baseline = len(os.listdir("/proc/self/fd"))
            lease = await export_genuine_mcp_proof(
                output / "proof-pack",
                output / "verification-envelope",
                runtime_root=runtime_capability.display_path,
                output_capability=output_capability,
                runtime_capability=runtime_capability,
            )
            lease_ref = weakref.ref(lease)
            unreachable_cycle: list[object] = [lease]
            unreachable_cycle.append(unreachable_cycle)
            del lease, unreachable_cycle
            gc.collect()
            assert lease_ref() is None
            assert len(os.listdir("/proc/self/fd")) == baseline
            output_capability.checkpoint()

    asyncio.run(run())


def test_detached_lease_handles_do_not_share_parent_or_invalidation(tmp_path: Path) -> None:
    import asyncio

    import gove_zone.mcp_proof_export as proof_export
    from gove_zone.proof_pack import PinnedOutputRoot

    async def run() -> None:
        output = tmp_path / "output"
        runtime = tmp_path / "runtime"
        with (
            PinnedOutputRoot.create(output) as output_root,
            PinnedOutputRoot.create(runtime) as runtime_root,
            runtime_root.attest() as runtime_capability,
        ):
            output_capability = output_root.attest()
            first = await proof_export.export_genuine_mcp_proof(
                output / "proof-pack",
                output / "verification-envelope",
                runtime_root=runtime_capability.display_path,
                output_capability=output_capability,
                runtime_capability=runtime_capability,
            )
            pack = output_capability.detach_subdirectory("proof-pack")
            envelope = output_capability.detach_subdirectory("verification-envelope")
            second = proof_export._mint_mcp_genuine_proof_lease(pack, envelope)
            with pytest.raises(RuntimeError, match="already claimed"):
                proof_export._mint_mcp_genuine_proof_lease(pack, envelope)
            output_capability.close()
            assert first.verify() == first.pack_digest
            assert second.verify() == second.pack_digest
            first.close()
            assert second.verify() == second.pack_digest
            second.close()

    asyncio.run(run())


def test_lease_forge_copy_pickle_and_failed_mint_close_resources(tmp_path: Path) -> None:
    import asyncio
    import copy
    import pickle

    import gove_zone.mcp_proof_export as proof_export
    from gove_zone.mcp_proof import MCP_ACTION_PROOF_CODEC
    from gove_zone.proof_pack import PinnedOutputRoot

    async def run() -> None:
        output = tmp_path / "output"
        runtime = tmp_path / "runtime"
        with (
            PinnedOutputRoot.create(output) as output_root,
            output_root.attest() as output_capability,
            PinnedOutputRoot.create(runtime) as runtime_root,
            runtime_root.attest() as runtime_capability,
        ):
            lease = await proof_export.export_genuine_mcp_proof(
                output / "proof-pack",
                output / "verification-envelope",
                runtime_root=runtime_capability.display_path,
                output_capability=output_capability,
                runtime_capability=runtime_capability,
            )
            with pytest.raises(TypeError):
                proof_export.MCPGenuineProofLease()
            shell = object.__new__(proof_export.MCPGenuineProofLease)
            with pytest.raises(RuntimeError, match="registered"):
                shell.verify()
            with pytest.raises(RuntimeError, match="registered"):
                shell.close()
            with pytest.raises(TypeError):

                class ForgedLease(proof_export.MCPGenuineProofLease):
                    pass

            for operation in (copy.copy, copy.deepcopy, pickle.dumps):
                with pytest.raises(TypeError):
                    operation(lease)

            output_capability.mkdir("bad-pack")
            output_capability.mkdir("bad-envelope")
            bad_pack = output_capability.detach_subdirectory("bad-pack")
            bad_envelope = output_capability.detach_subdirectory("bad-envelope")
            with pytest.raises(RuntimeError):
                proof_export._mint_mcp_genuine_proof_lease(bad_pack, bad_envelope)
            with pytest.raises(RuntimeError):
                MCP_ACTION_PROOF_CODEC.read_exact_pack_attested(bad_pack)
            lease.close()

    asyncio.run(run())


def test_concurrent_verify_close_and_fd_reuse_fail_closed(tmp_path: Path) -> None:
    import asyncio
    import os
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from gove_zone.mcp_proof_export import export_genuine_mcp_proof
    from gove_zone.proof_pack import PinnedOutputRoot

    async def run() -> None:
        output = tmp_path / "output"
        runtime = tmp_path / "runtime"
        with (
            PinnedOutputRoot.create(output) as output_root,
            output_root.attest() as output_capability,
            PinnedOutputRoot.create(runtime) as runtime_root,
            runtime_root.attest() as runtime_capability,
        ):
            lease = await export_genuine_mcp_proof(
                output / "proof-pack",
                output / "verification-envelope",
                runtime_root=runtime_capability.display_path,
                output_capability=output_capability,
                runtime_capability=runtime_capability,
            )
            expected = lease.pack_digest
            barrier = Barrier(2)

            def verify() -> str:
                barrier.wait()
                return lease.verify()

            def close() -> None:
                barrier.wait()
                lease.close()

            with ThreadPoolExecutor(max_workers=2) as pool:
                verify_future = pool.submit(verify)
                close_future = pool.submit(close)
                close_future.result()
                try:
                    assert verify_future.result() == expected
                except RuntimeError as exc:
                    assert "closed" in str(exc)

            reused = [os.open("/dev/null", os.O_RDONLY) for _ in range(32)]
            try:
                with pytest.raises(RuntimeError, match="closed"):
                    lease.verify()
            finally:
                for descriptor in reused:
                    os.close(descriptor)

    asyncio.run(run())
