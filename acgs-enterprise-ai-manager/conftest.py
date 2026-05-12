"""Repository-wide pytest isolation."""

import pytest


@pytest.fixture(autouse=True)
def isolated_governance_state(tmp_path, monkeypatch):
    """Keep singleton governance and audit logs isolated per test."""
    monkeypatch.setenv("ACGS_AUDIT_DIR", str(tmp_path / "audit_logs"))
    import backend.governance.acgs_integration as acgs_integration

    acgs_integration._governance_instance = None
    yield
    acgs_integration._governance_instance = None
