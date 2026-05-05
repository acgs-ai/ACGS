from __future__ import annotations

import pytest

from governance.policy_loader import load_policy_bundle, load_roles


@pytest.fixture()
def roles_bundle():
    return load_roles("governance/roles.json")


@pytest.fixture()
def policy_bundle():
    return load_policy_bundle("governance/policies/2026-05")
