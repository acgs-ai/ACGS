from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

HERE = Path(__file__).resolve().parent
PACKAGE = HERE.parent
sys.path.insert(0, str(PACKAGE))

import artifact_replay  # noqa: E402
import cutover_gate  # noqa: E402
import exclusivity_model as model  # noqa: E402
import identity_pseudonym  # noqa: E402
import privilege_context  # noqa: E402
import release_manifest  # noqa: E402
import root_equivalence  # noqa: E402
import table16_metrics  # noqa: E402


def load(name: str) -> dict:
    return json.loads((PACKAGE / name).read_text(encoding="utf-8"))


class TestDerivedClassification(unittest.TestCase):
    def setUp(self):
        self.registry = load("ROOT_EQUIVALENCE_REGISTRY.json")
        self.topology = load("PRIVILEGE_TOPOLOGY_FINAL.json")
        self.surfaces = load("SURFACE_REGISTRY.json")

    def collect(self, registry=None, topology=None):
        return model.collect(
            registry or self.registry,
            topology or self.topology,
            surface_registry=self.surfaces,
        )

    def test_summary_mismatch_is_blocking(self):
        registry = copy.deepcopy(self.registry)
        registry["root_equivalent_paths"] = []
        result = self.collect(registry=registry)
        self.assertIn(
            "inventory:ROOT_EQUIVALENCE_REGISTRY_root_summary_mismatch",
            result["unresolved_privilege_paths"],
        )
        self.assertIn("docker_rootful", result["root_equivalent_paths"])

    def test_q_is_derived_from_entry_classification(self):
        registry = copy.deepcopy(self.registry)
        registry["mechanisms"]["docker_rootful"]["classification"] = "AUTHORITY_EQUIVALENT"
        registry["root_equivalent_paths"] = []
        registry["authority_equivalent_paths"] = ["docker_rootful"]
        result = self.collect(registry=registry)
        self.assertIn("docker_rootful", result["authority_equivalent_paths"])
        self.assertNotIn("docker_rootful", result["root_equivalent_paths"])


class TestCredentialContract(unittest.TestCase):
    def setUp(self):
        self.registry = load("ROOT_EQUIVALENCE_REGISTRY.json")
        self.topology = load("PRIVILEGE_TOPOLOGY_FINAL.json")
        self.surfaces = load("SURFACE_REGISTRY.json")

    def test_self_declared_host_representative_is_ignored(self):
        context = copy.deepcopy(self.registry["measurement_context"])
        context["status"]["Groups"] = "10 1000"
        context["host_representative"] = True
        self.assertFalse(privilege_context.is_host_representative(context))

    def test_cross_inventory_credential_mismatch_blocks(self):
        topology = copy.deepcopy(self.topology)
        topology["measurement_context"]["status"]["Groups"] = "10 1000"
        result = model.collect(self.registry, topology, surface_registry=self.surfaces)
        self.assertFalse(result["inventory_admissibility"]["PRIVILEGE_TOPOLOGY"])
        self.assertIn(
            "inventory:PRIVILEGE_TOPOLOGY_credential_not_expected",
            result["unresolved_privilege_paths"],
        )


class TestSurfaceRegistry(unittest.TestCase):
    def test_only_successful_completed_surface_counts(self):
        registry = load("ROOT_EQUIVALENCE_REGISTRY.json")
        topology = load("PRIVILEGE_TOPOLOGY_FINAL.json")
        surfaces = load("SURFACE_REGISTRY.json")
        for status in ("ERROR", "UNAVAILABLE"):
            mutated = copy.deepcopy(topology)
            mutated["surface_results"]["setuid"] = {
                "status": status,
                "completed": False,
            }
            result = model.collect(registry, mutated, surface_registry=surfaces)
            self.assertIn("setuid", result["surfaces_missing"])
            self.assertIn(
                "coverage:setuid_not_successfully_completed",
                result["unresolved_privilege_paths"],
            )

    def test_missing_result_is_uncovered(self):
        registry = load("ROOT_EQUIVALENCE_REGISTRY.json")
        topology = load("PRIVILEGE_TOPOLOGY_FINAL.json")
        surfaces = load("SURFACE_REGISTRY.json")
        del topology["surface_results"]["sudo"]
        result = model.collect(registry, topology, surface_registry=surfaces)
        self.assertIn("sudo", result["surfaces_missing"])


class TestPureReplay(unittest.TestCase):
    def test_cutover_gate_regenerates_from_current_evidence(self):
        result = cutover_gate.evaluate()
        self.assertEqual(result["verdict"], model.BLOCKED_ROOT)

    def test_shipped_evidence_replays_without_host_or_docker(self):
        result = artifact_replay.replay()
        self.assertEqual(result["mode"], "PURE_ARTIFACT_REPLAY")
        self.assertFalse(result["host_probe_performed"])
        self.assertFalse(result["docker_invoked"])
        self.assertEqual(result["verdict"], model.BLOCKED_ROOT)
        self.assertEqual(result["derived"]["integrity_errors"], [])
        self.assertEqual(
            result,
            load("REPLAY_RESULT.json"),
        )

    def test_default_docker_probe_does_not_execute(self):
        original = root_equivalence._run
        root_equivalence._run = lambda *args, **kwargs: self.fail(
            "default Docker path executed a command"
        )
        try:
            result = root_equivalence.docker_rootful()
        finally:
            root_equivalence._run = original
        self.assertEqual(result["probe"]["status"], "UNAVAILABLE")
        self.assertEqual(result["probe"]["probe_class"], "ACTIVE_MUTATION")

    def test_active_docker_probe_requires_disposable_ack(self):
        with self.assertRaises(ValueError):
            root_equivalence.docker_rootful(active=True)

    def test_active_helper_failure_is_error(self):
        completed = subprocess.CompletedProcess(["docker", "info"], 127, "", "docker info failed")
        with (
            mock.patch.object(root_equivalence.os.path, "exists", return_value=True),
            mock.patch.object(root_equivalence.os, "access", return_value=True),
            mock.patch.object(root_equivalence, "_run", return_value=completed),
        ):
            result = root_equivalence.docker_rootful(active=True, acknowledge_disposable=True)
        self.assertEqual(result["classification"], root_equivalence.UNKNOWN)
        self.assertEqual(result["probe"]["status"], "ERROR")
        self.assertFalse(result["probe"]["cleanup_complete"])

    def test_active_not_present_is_not_success(self):
        with mock.patch.object(root_equivalence.os.path, "exists", return_value=False):
            result = root_equivalence.docker_rootful(active=True, acknowledge_disposable=True)
        self.assertEqual(result["classification"], root_equivalence.NOT_PRESENT)
        self.assertEqual(result["probe"]["status"], "NOT_PRESENT")
        self.assertFalse(result["probe"]["cleanup_complete"])

    def test_real_active_helper_records_complete_mutation_metadata(self):
        real_exists = root_equivalence.os.path.exists
        real_access = root_equivalence.os.access
        real_stat = root_equivalence.os.stat
        runs = [
            subprocess.CompletedProcess([], 0, "/var/lib/docker|[]\n", ""),
            subprocess.CompletedProcess([], 0, "test:image\n", ""),
            subprocess.CompletedProcess([], 0, "0\n0 0 4294967295\ndone\n", ""),
            subprocess.CompletedProcess([], 0, "", ""),
        ]

        def exists(path):
            if str(path) in ("/var/run/docker.sock", "/run/docker.sock"):
                return str(path) == "/var/run/docker.sock"
            return real_exists(path)

        def access(path, mode):
            if str(path) == "/var/run/docker.sock":
                return True
            return real_access(path, mode)

        def stat(path):
            if str(path).startswith("/tmp/cspa3-rootprobe-") and str(path).endswith("/f"):
                return SimpleNamespace(st_size=10, st_uid=4242)
            return real_stat(path)

        with (
            mock.patch.object(root_equivalence.os.path, "exists", side_effect=exists),
            mock.patch.object(root_equivalence.os, "access", side_effect=access),
            mock.patch.object(root_equivalence.os, "stat", side_effect=stat),
            mock.patch.object(root_equivalence, "_run", side_effect=runs),
        ):
            result = root_equivalence.docker_rootful(active=True, acknowledge_disposable=True)

        self.assertEqual(result["probe"]["status"], "SUCCESS")
        self.assertTrue(result["probe"]["cleanup_complete"])
        evidence = result["evidence"]["active_probe"]
        mutation_command = evidence["mutation_command"]
        self.assertTrue(mutation_command["argv"])
        self.assertEqual(mutation_command["returncode"], 0)
        self.assertEqual(mutation_command["outcome"], "COMMAND_SUCCEEDED")
        self.assertEqual(len(evidence["mutations"]), 3)
        self.assertTrue(
            all(
                isinstance(item["command_returncode"], int) and item["outcome"]
                for item in evidence["mutations"]
            )
        )
        cleanup_command = evidence["cleanup_command"]
        self.assertTrue(cleanup_command["argv"])
        self.assertEqual(cleanup_command["returncode"], 0)
        self.assertEqual(cleanup_command["outcome"], "COMMAND_SUCCEEDED")
        self.assertEqual(evidence["cleanup_status"], "REMOVED")
        self.assertEqual(len(evidence["cleanup"]), 3)
        self.assertTrue(
            all(
                isinstance(item["command_returncode"], int) and item["outcome"]
                for item in evidence["cleanup"][:2]
            )
        )
        self.assertEqual(evidence["cleanup"][2]["action_returncode"], 0)
        self.assertEqual(evidence["cleanup"][2]["outcome"], "REMOVED")
        self.assertTrue(evidence["cleanup"][2]["removed"])

    def test_historical_docker_result_does_not_claim_active_metadata(self):
        docker = load("ROOT_EQUIVALENCE_REGISTRY.json")["mechanisms"]["docker_rootful"]
        self.assertEqual(docker["probe"]["status"], "HISTORICAL_RESULT")
        self.assertFalse(docker["probe"]["active_evidence_recorded"])
        self.assertNotIn("active_probe", docker["evidence"])

    def test_complete_manifest_closure_is_pseudonymized(self):
        forbidden_identity = "".join(chr(code) for code in (109, 97, 114, 116, 105, 110))
        manifest_entries = [
            line.split("  ", 1)[1]
            for line in (PACKAGE / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
            if line
        ]
        self.assertEqual(
            manifest_entries,
            [path.relative_to(PACKAGE).as_posix() for path in release_manifest.release_files()],
        )
        for relative in manifest_entries:
            path = PACKAGE / relative
            if path.suffix == ".pdf":
                extracted = subprocess.run(
                    ["pdftotext", str(path), "-"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(extracted.returncode, 0, extracted.stderr)
                text = extracted.stdout
            else:
                text = path.read_text(encoding="utf-8")
            legacy_placeholder = "<" + identity_pseudonym.PSEUDONYM + ">"
            machine_tmp_prefix = "/tmp/" + "claude" + "-"
            self.assertNotIn(forbidden_identity, text, relative)
            self.assertNotIn(legacy_placeholder, text, relative)
            self.assertNotIn(machine_tmp_prefix, text, relative)
        self.assertEqual(identity_pseudonym.PSEUDONYM, "agent-user")
        self.assertEqual(
            load("AUTHORITY_PRINCIPAL_ANALYSIS.json")["agent_user"],
            identity_pseudonym.PSEUDONYM,
        )


class TestTable16Metrics(unittest.TestCase):
    def test_every_published_number_matches_recomputation(self):
        ok, errors = table16_metrics.verify_paper()
        self.assertTrue(ok, errors)
        for name in table16_metrics.RUNTIME_FILES:
            self.assertTrue((PACKAGE / name).is_file(), name)


class TestReleaseManifest(unittest.TestCase):
    def test_every_shipped_file_is_checksum_bound(self):
        ok, errors = release_manifest.verify_manifest()
        self.assertTrue(ok, errors)
        manifest = (PACKAGE / "SHA256SUMS").read_text(encoding="utf-8")
        self.assertNotIn("  SHA256SUMS\n", manifest)


class TestDeterministicRenderer(unittest.TestCase):
    def test_render_twice_is_identical_and_extractable(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / "first.pdf"
            second = Path(tmp) / "second.pdf"
            hashes = []
            for output in (first, second):
                run = subprocess.run(
                    [
                        sys.executable,
                        str(PACKAGE / "render_pdf.py"),
                        "--output",
                        str(output),
                    ],
                    cwd=PACKAGE,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(run.returncode, 0, run.stderr)
                hashes.append(__import__("hashlib").sha256(output.read_bytes()).hexdigest())
            self.assertEqual(hashes[0], hashes[1])
            text_path = Path(tmp) / "paper.txt"
            extracted = subprocess.run(
                ["pdftotext", str(first), str(text_path)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(extracted.returncode, 0, extracted.stderr)
            text = text_path.read_text(encoding="utf-8")
            self.assertIn("Evidence-Backed Authority Verification", text)
            self.assertIn("BLOCKED_ROOT_EQUIVALENCE", text)


if __name__ == "__main__":
    unittest.main()
