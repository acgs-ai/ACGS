from __future__ import annotations

from governed_mcp_v0 import eval_gate


def test_deny_prod_file_write(tmp_path):
    eval_gate.deny_prod_file_write(tmp_path)


def test_allow_sandbox_file_write(tmp_path):
    eval_gate.allow_sandbox_file_write(tmp_path)


def test_deny_sql_delete(tmp_path):
    eval_gate.deny_sql_delete(tmp_path)


def test_deny_external_email(tmp_path):
    eval_gate.deny_external_email(tmp_path)


def test_deny_prod_deploy(tmp_path):
    eval_gate.deny_prod_deploy(tmp_path)


def test_deny_github_mutation(tmp_path):
    eval_gate.deny_github_mutation(tmp_path)


def test_fail_closed_policy_error(tmp_path):
    eval_gate.fail_closed_policy_error(tmp_path)


def test_tamper_receipt_fails_replay(tmp_path):
    eval_gate.tamper_receipt_fails_replay(tmp_path)


def test_tamper_audit_hash_fails_replay(tmp_path):
    eval_gate.tamper_audit_hash_fails_replay(tmp_path)


def test_missing_receipt_fails_bundle(tmp_path):
    eval_gate.missing_receipt_fails_bundle(tmp_path)
