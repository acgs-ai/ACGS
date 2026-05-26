"""Smoke tests for the post-refactor import surface.

The mcp_server.py 726->81 line split (see commits 4abfaaf..e2fc648)
moved domain types, IO helpers, policy engine, replay verification, and
the GovernedMCPServer class into dedicated modules.  mcp_server now
re-exports the public names so external callers keep working.  These
tests pin both contracts:

  1) every name historically importable from mcp_server still resolves
     (back-compat shim);
  2) every name resolves from its new dedicated module (new code path).

If either drift, this test catches it — no need to wait for an
integration suite to fail on a stale import path.
"""
from __future__ import annotations


def test_back_compat_imports_from_mcp_server_shim() -> None:
    """Names callers used before the refactor must still import from mcp_server."""
    from governed_mcp_v0.mcp_server import (
        AdmissionDecision,
        DeterministicPolicyEngine,
        GovernanceDenied,
        GovernanceStorageError,
        GovernedMCPServer,
        ReplayResult,
        RuntimeTargets,
        build_fastmcp_server,
        create_fixture_environment,
        verify_replay_bundle,
    )

    # Touch each binding to silence unused-import lints in stricter CI.
    assert AdmissionDecision.__name__ == "AdmissionDecision"
    assert DeterministicPolicyEngine.__name__ == "DeterministicPolicyEngine"
    assert issubclass(GovernanceDenied, RuntimeError)
    assert issubclass(GovernanceStorageError, RuntimeError)
    assert GovernedMCPServer.__name__ == "GovernedMCPServer"
    assert ReplayResult.__name__ == "ReplayResult"
    assert RuntimeTargets.__name__ == "RuntimeTargets"
    assert callable(build_fastmcp_server)
    assert callable(create_fixture_environment)
    assert callable(verify_replay_bundle)


def test_new_imports_from_dedicated_modules() -> None:
    """New code should import from the dedicated modules, not the shim."""
    from governed_mcp_v0.errors import GovernanceDenied, GovernanceStorageError
    from governed_mcp_v0.fixtures import create_fixture_environment
    from governed_mcp_v0.models import (
        AdmissionDecision,
        PolicyEngine,
        ReplayResult,
        RuntimeTargets,
    )
    from governed_mcp_v0.policy import DeterministicPolicyEngine
    from governed_mcp_v0.server import GovernedMCPServer
    from governed_mcp_v0.verify import verify_replay_bundle

    assert issubclass(GovernanceDenied, RuntimeError)
    assert issubclass(GovernanceStorageError, RuntimeError)
    assert AdmissionDecision.__name__ == "AdmissionDecision"
    assert PolicyEngine.__name__ == "PolicyEngine"
    assert ReplayResult.__name__ == "ReplayResult"
    assert RuntimeTargets.__name__ == "RuntimeTargets"
    assert DeterministicPolicyEngine.__name__ == "DeterministicPolicyEngine"
    assert GovernedMCPServer.__name__ == "GovernedMCPServer"
    assert callable(create_fixture_environment)
    assert callable(verify_replay_bundle)


def test_shim_and_dedicated_modules_export_same_objects() -> None:
    """Re-exports must be identity-equal — no accidental shadow definitions."""
    from governed_mcp_v0 import mcp_server, models, policy, server, verify

    assert mcp_server.AdmissionDecision is models.AdmissionDecision
    assert mcp_server.ReplayResult is models.ReplayResult
    assert mcp_server.RuntimeTargets is models.RuntimeTargets
    assert mcp_server.DeterministicPolicyEngine is policy.DeterministicPolicyEngine
    assert mcp_server.GovernedMCPServer is server.GovernedMCPServer
    assert mcp_server.verify_replay_bundle is verify.verify_replay_bundle


def test_package_init_re_exports_match_mcp_server() -> None:
    """governed_mcp_v0 package surface must equal what mcp_server re-exports."""
    import governed_mcp_v0
    from governed_mcp_v0 import mcp_server

    for name in (
        "AdmissionDecision",
        "GovernanceDenied",
        "GovernanceStorageError",
        "GovernedMCPServer",
        "ReplayResult",
        "RuntimeTargets",
        "create_fixture_environment",
        "verify_replay_bundle",
    ):
        assert getattr(governed_mcp_v0, name) is getattr(mcp_server, name), name
