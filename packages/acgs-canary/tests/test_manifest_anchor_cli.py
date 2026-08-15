from __future__ import annotations

import json
import subprocess
import sys

import pytest
from acgs_canary.anchor import (
    STATE_CONFIRMED,
    STATE_SUBMITTED,
    AnchorEvidence,
    FixtureVerifier,
    ProductionAnchorUnavailable,
    anchor_predates,
    build_anchor_bundle,
    bundle_hash,
)
from acgs_canary.errors import AnchorError, ManifestError
from acgs_canary.licensee import ensure_ref_key, licensee_ref
from acgs_canary.manifest import (
    build_manifest,
    load_manifest,
    new_variant_id,
    store_manifest,
    update_manifest,
)
from acgs_canary.protocol import PROTOCOL, protocol_hash

T = "2026-08-15T00:00:00Z"
H = "11" * 32


def _manifest(**overrides):
    base = dict(
        variant_id=new_variant_id(),
        tier="T1",
        source_release="rel",
        source_tree_sha256=H,
        canary_commitment_hex=H,
        placement_commitment_hex=H,
        created_at=T,
        protocol_sha256=protocol_hash(),
        issuer_ref="issuer:test",
    )
    base.update(overrides)
    return build_manifest(**base)


class TestManifest:
    def test_roundtrip_and_uniqueness(self, store):
        m = _manifest()
        store_manifest(store, m)
        assert load_manifest(store, m["variant_id"]) == m
        with pytest.raises(ManifestError):
            store_manifest(store, m)

    def test_bad_variant_id_rejected(self):
        with pytest.raises(ManifestError):
            _manifest(variant_id="vt_short")
        with pytest.raises(ManifestError):
            _manifest(variant_id="xx_" + "aa" * 16)

    def test_unknown_field_rejected(self, store):
        m = _manifest()
        m["surprise"] = 1
        from acgs_canary.manifest import validate_manifest

        with pytest.raises(ManifestError):
            validate_manifest(m)

    def test_injected_tree_requires_regenerated_derived_artifacts(self):
        with pytest.raises(ManifestError):
            _manifest(injected_tree_sha256="22" * 32, derived_artifacts_status="pending")
        m = _manifest(injected_tree_sha256="22" * 32, derived_artifacts_status="regenerated")
        assert m["derived_artifacts_status"] == "regenerated"

    def test_update_paths(self, store):
        m = _manifest()
        store_manifest(store, m)
        with pytest.raises(ManifestError):
            update_manifest(
                store, m["variant_id"], injected_tree_sha256="22" * 32
            )  # still pending → refused
        updated = update_manifest(
            store,
            m["variant_id"],
            injected_tree_sha256="22" * 32,
            derived_artifacts_status="regenerated",
        )
        assert updated["injected_tree_sha256"] == "22" * 32
        with pytest.raises(ManifestError):
            update_manifest(store, m["variant_id"], tier="T0")

    def test_source_vs_injected_tree_confusion_refused(self, store):
        # The injected tree hash may never silently equal-and-replace the
        # source hash role: both are present, distinct fields, and the
        # source field is immutable after creation.
        m = _manifest()
        store_manifest(store, m)
        with pytest.raises(ManifestError):
            update_manifest(store, m["variant_id"], source_tree_sha256="99" * 32)


class TestLicenseeRef:
    def test_refs_are_domain_separated_across_stores(self, tmp_path):
        import os

        from acgs_canary.store import RestrictedFileStore

        dirs = []
        for name in ("s1", "s2"):
            d = tmp_path / name
            d.mkdir(mode=0o700)
            os.chmod(d, 0o700)
            s = RestrictedFileStore(d)
            s.initialize(operator="t")
            ensure_ref_key(s)
            dirs.append(s)
        # Same identity, different stores (different keys) → unlinkable refs.
        r1 = licensee_ref(dirs[0], "alice@example.com")
        r2 = licensee_ref(dirs[1], "alice@example.com")
        assert r1 != r2

    def test_ref_is_not_plain_hash(self, store):
        import hashlib

        ensure_ref_key(store)
        identity = "alice@example.com"
        ref = licensee_ref(store, identity)
        assert hashlib.sha256(identity.encode()).hexdigest() not in ref

    def test_ref_deterministic_within_store(self, store):
        ensure_ref_key(store)
        assert licensee_ref(store, "x") == licensee_ref(store, "x")


class TestAnchor:
    def _bundle(self):
        return build_anchor_bundle(
            ledger_head_hash=H,
            pool_manifest_sha256=H,
            protocol_sha256=protocol_hash(),
            commitment_roots_hex=["22" * 32],
            created_at=T,
        )

    def test_mirror_never_independent(self):
        bundle = self._bundle()
        mirror = AnchorEvidence(
            kind="mirror",
            state=STATE_CONFIRMED,
            bundle_sha256=bundle_hash(bundle),
            evidence_ref="hf",
            anchored_at=T,
            production=False,
        )
        with pytest.raises(AnchorError):
            anchor_predates(
                mirror,
                bundle,
                observation_time="2026-08-16T00:00:00Z",
                verifier=FixtureVerifier({}),
            )
        # No free-standing label helper exists to consult: labels come only
        # from the ledger's issuance-state paths (see anchor.py note).
        assert not hasattr(__import__("acgs_canary.anchor", fromlist=["_"]), "evidence_label")

    def test_unconfirmed_evidence_fails(self):
        bundle = self._bundle()
        ev = AnchorEvidence(
            kind="rfc3161",
            state=STATE_SUBMITTED,
            bundle_sha256=bundle_hash(bundle),
            evidence_ref="f1",
            anchored_at=T,
            production=False,
        )
        fx = FixtureVerifier({"f1": {"bundle_sha256": bundle_hash(bundle)}})
        assert not anchor_predates(ev, bundle, observation_time="2026-08-16T00:00:00Z", verifier=fx)

    def test_stale_anchor_after_observation_fails(self):
        bundle = self._bundle()
        ev = AnchorEvidence(
            kind="rfc3161",
            state=STATE_CONFIRMED,
            bundle_sha256=bundle_hash(bundle),
            evidence_ref="f1",
            anchored_at="2026-08-17T00:00:00Z",
            production=False,
        )
        fx = FixtureVerifier({"f1": {"bundle_sha256": bundle_hash(bundle)}})
        assert not anchor_predates(ev, bundle, observation_time="2026-08-16T00:00:00Z", verifier=fx)

    def test_substituted_bundle_fails(self):
        bundle = self._bundle()
        other = build_anchor_bundle(
            ledger_head_hash="44" * 32,
            pool_manifest_sha256=H,
            protocol_sha256=protocol_hash(),
            commitment_roots_hex=[],
            created_at=T,
        )
        ev = AnchorEvidence(
            kind="rfc3161",
            state=STATE_CONFIRMED,
            bundle_sha256=bundle_hash(other),
            evidence_ref="f1",
            anchored_at=T,
            production=False,
        )
        fx = FixtureVerifier({"f1": {"bundle_sha256": bundle_hash(other)}})
        assert not anchor_predates(ev, bundle, observation_time="2026-08-16T00:00:00Z", verifier=fx)

    def test_fixture_verifier_refuses_production_evidence(self):
        bundle = self._bundle()
        ev = AnchorEvidence(
            kind="rfc3161",
            state=STATE_CONFIRMED,
            bundle_sha256=bundle_hash(bundle),
            evidence_ref="f1",
            anchored_at=T,
            production=True,
        )
        with pytest.raises(AnchorError):
            FixtureVerifier({}).verify(ev, bundle)

    def test_production_slot_refuses_in_r0(self):
        bundle = self._bundle()
        ev = AnchorEvidence(
            kind="rfc3161",
            state=STATE_CONFIRMED,
            bundle_sha256=bundle_hash(bundle),
            evidence_ref="real",
            anchored_at=T,
            production=True,
        )
        with pytest.raises(AnchorError):
            ProductionAnchorUnavailable().verify(ev, bundle)


class TestProtocol:
    def test_hash_stable(self):
        assert protocol_hash() == protocol_hash()

    def test_semantic_change_changes_hash(self):
        import copy

        from acgs_canary.canonical import canonical_sha256_hex

        mutated = copy.deepcopy(PROTOCOL)
        mutated["merkle"]["odd_nodes"] = "duplicated"
        assert canonical_sha256_hex(mutated) != protocol_hash()

    def test_evidentiary_limits_present(self):
        limits = PROTOCOL["evidentiary_limits"]
        assert limits["frameproof_against_publisher"] is False
        assert limits["dilute_pretraining_detection"] == "not claimed"
        assert limits["absence_of_canary"] == "never exculpatory"


def _run_cli(*args: str, env: dict[str, str] | None = None):
    import os

    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    return subprocess.run(
        [sys.executable, "-m", "acgs_canary.cli", *args],
        capture_output=True,
        text=True,
        env=full_env,
        timeout=120,
    )


class TestCli:
    def test_protocol_hash_single_json_object(self):
        res = _run_cli("protocol-hash")
        assert res.returncode == 0
        payload = json.loads(res.stdout)
        assert payload["protocol_sha256"] == protocol_hash()
        assert res.stdout.count("\n") == 1

    def test_store_refusal_exit_code(self, tmp_path):
        res = _run_cli("pool-validate", "--store", str(tmp_path / "absent"))
        assert res.returncode == 3
        payload = json.loads(res.stdout)
        assert payload["ok"] is False

    def test_burn_requires_confirm(self, store_dir):
        env = {"ACGS_CANARY_STORE": str(store_dir)}
        assert (
            _run_cli(
                "pool-init", "--pool-id", "p", "--operator", "t", "--init-store", env=env
            ).returncode
            == 0
        )
        gen = _run_cli("pool-generate", "--tier", "T0", "--count", "2", env=env)
        cid = json.loads(gen.stdout)["canary_ids"][0]
        res = _run_cli("pool-burn", "--canary-id", cid, "--status", "burned", env=env)
        assert res.returncode == 5  # policy refusal without --confirm
        res2 = _run_cli("pool-burn", "--canary-id", cid, "--status", "burned", "--confirm", env=env)
        assert res2.returncode == 0

    def test_selfcheck_invariants_and_no_secret_leak(self, store_dir):
        res = _run_cli("r0-selfcheck")
        assert res.returncode == 0
        lines = res.stdout.strip().split("\n")
        assert len(lines) == 1  # exactly one JSON object on stdout
        payload = json.loads(lines[0])
        assert payload["all_invariants_hold"] is True
        assert "TEST/DEVELOPMENT ARTIFACT" in payload["disclaimer"]
        # Secret-leak scan over stdout+stderr: no token_hex/salt/key fields.
        combined = res.stdout + res.stderr
        for marker in ("token_hex", "selection_salt", "key_hex", "probe_seed"):
            assert marker not in combined

    def test_cli_end_to_end_prepare_and_verify(self, store_dir):
        env = {"ACGS_CANARY_STORE": str(store_dir)}
        _run_cli("pool-init", "--pool-id", "p", "--operator", "t", "--init-store", env=env)
        _run_cli("pool-generate", "--tier", "T1", "--count", "6", env=env)
        prep = _run_cli(
            "variant-prepare",
            "--tier",
            "T1",
            "--shared",
            "2",
            "--unique",
            "2",
            "--source-release",
            "rel",
            "--source-tree-sha256",
            H,
            "--issuer-ref",
            "issuer:test",
            env=env,
        )
        assert prep.returncode == 0, prep.stdout + prep.stderr
        vid = json.loads(prep.stdout)["variant_id"]
        ver = _run_cli("variant-verify", "--variant-id", vid, env=env)
        assert ver.returncode == 0
        payload = json.loads(ver.stdout)
        assert payload["commitment_ok"] and payload["placement_ok"] and payload["protocol_ok"]
        led = _run_cli("ledger-init", "--operator", "t", env=env)
        assert led.returncode == 0
        lv = _run_cli("ledger-verify", env=env)
        assert lv.returncode == 0
        # secret scan over the full CLI transcript
        transcript = "".join(r.stdout + r.stderr for r in (prep, ver, led, lv))
        for marker in ("token_hex", "selection_salt", "key_hex", "probe_seed"):
            assert marker not in transcript


class TestBundleValidation:
    def _bundle(self):
        return build_anchor_bundle(
            ledger_head_hash=H,
            pool_manifest_sha256=H,
            protocol_sha256=protocol_hash(),
            commitment_roots_hex=["22" * 32],
            created_at=T,
        )

    def test_missing_field_rejected(self):
        for field in (
            "ledger_head_hash",
            "pool_manifest_sha256",
            "protocol_sha256",
            "commitment_roots_hex",
            "created_at",
        ):
            incomplete = self._bundle()
            del incomplete[field]
            with pytest.raises(AnchorError):
                bundle_hash(incomplete)

    def test_unknown_field_rejected(self):
        bundle = self._bundle()
        bundle["extra"] = 1
        with pytest.raises(AnchorError):
            bundle_hash(bundle)

    def test_malformed_digest_rejected(self):
        bundle = self._bundle()
        bundle["ledger_head_hash"] = "zz" * 32
        with pytest.raises(AnchorError):
            bundle_hash(bundle)

    def test_unsorted_roots_rejected(self):
        bundle = self._bundle()
        bundle["commitment_roots_hex"] = ["33" * 32, "22" * 32]
        with pytest.raises(AnchorError):
            bundle_hash(bundle)

    def test_bad_created_at_rejected(self):
        bundle = self._bundle()
        bundle["created_at"] = "not-a-timestamp"
        with pytest.raises(AnchorError):
            bundle_hash(bundle)

    def test_serialize_validates_too(self):
        from acgs_canary.anchor import serialize_bundle

        bundle = self._bundle()
        del bundle["created_at"]
        with pytest.raises(AnchorError):
            serialize_bundle(bundle)


class TestCliHardening:
    def test_usage_error_emits_json_envelope(self):
        res = _run_cli("no-such-command")
        assert res.returncode == 2
        lines = res.stdout.strip().split("\n")
        assert len(lines) == 1  # one-JSON-object stdout contract holds
        payload = json.loads(lines[0])
        assert payload["ok"] is False
        assert payload["error_class"] == "UsageError"

    def test_prepare_validates_manifest_before_allocation(self, store_dir):
        # A manifest input rejection must not strand unique allocations:
        # with exactly enough T1 canaries, two failed prepares followed by a
        # valid one must still succeed.
        env = {"ACGS_CANARY_STORE": str(store_dir)}
        _run_cli("pool-init", "--pool-id", "p", "--operator", "t", "--init-store", env=env)
        _run_cli("pool-generate", "--tier", "T1", "--count", "4", env=env)
        good = dict(env)
        args = [
            "variant-prepare",
            "--tier",
            "T1",
            "--shared",
            "2",
            "--unique",
            "2",
            "--source-release",
            "rel",
            "--issuer-ref",
            "issuer:test",
        ]
        for _ in range(2):
            bad = _run_cli(*args, "--source-tree-sha256", "not-hex", env=good)
            assert bad.returncode != 0
        ok = _run_cli(*args, "--source-tree-sha256", "11" * 32, env=good)
        assert ok.returncode == 0, ok.stdout + ok.stderr


class TestProbeStoreCli:
    def test_probe_store_split_via_cli(self, tmp_path):
        import os

        token_dir = tmp_path / "tokens"
        token_dir.mkdir(mode=0o700)
        os.chmod(token_dir, 0o700)
        probe_dir = tmp_path / "probes"
        probe_dir.mkdir(mode=0o700)
        os.chmod(probe_dir, 0o700)
        env = {"ACGS_CANARY_STORE": str(token_dir)}
        init = _run_cli(
            "pool-init",
            "--pool-id",
            "p",
            "--operator",
            "t",
            "--init-store",
            "--probe-store",
            str(probe_dir),
            env=env,
        )
        assert init.returncode == 0, init.stdout + init.stderr
        gen = _run_cli(
            "pool-generate",
            "--tier",
            "T0",
            "--count",
            "2",
            "--probe-store",
            str(probe_dir),
            env=env,
        )
        assert gen.returncode == 0, gen.stdout + gen.stderr
        # Probe records live only in the probe store.
        token_names = {p.name for p in token_dir.iterdir()}
        probe_names = {p.name for p in probe_dir.iterdir()}
        assert not any(n.startswith("probe-") for n in token_names)
        assert any(n.startswith("probe-") for n in probe_names)
        # Validation needs the probe store; without it the pool fails closed.
        ok = _run_cli("pool-validate", "--probe-store", str(probe_dir), env=env)
        assert ok.returncode == 0
        missing = _run_cli("pool-validate", env=env)
        assert missing.returncode != 0
