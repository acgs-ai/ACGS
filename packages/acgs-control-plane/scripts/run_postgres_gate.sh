#!/usr/bin/env bash
set -euo pipefail

postgres_image='postgres:17.10-bookworm@sha256:4f736ae292687621d4dbe0d499ffd024a36bd2ee7d8ca6f2ccd4c800f047b394'
postgres_digest='sha256:4f736ae292687621d4dbe0d499ffd024a36bd2ee7d8ca6f2ccd4c800f047b394'
old_commit='4f0c685b5d2ffac0e6a71810b77c6357b8d56a94'
old_digest='40ff7b40f27a2b698d3b607c710f1866f11850a9a2c42a7c0eb51a6fe8be3d93'
postgres_user='acgs_control_plane_test'
postgres_password=''
postgres_fixture_owner_user='acgs_control_plane_fixture_owner'
postgres_fixture_owner_password=''
main_database='acgs_control_plane_test'

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
package_dir="$(cd -- "$script_dir/.." && pwd)"
workspace_dir="$(cd -- "$package_dir/../.." && pwd)"
gove_zone_src="$workspace_dir/packages/gove-zone/src"

expected_selectors=(
  'tests/integration/test_migrations_postgres.py::test_empty_and_existing_alpha_upgrade_head'
  'tests/integration/test_migrations_postgres.py::test_declared_reversible_round_trip'
  'tests/integration/test_migrations_postgres.py::test_mixed_version_rolling_compatibility'
  'tests/integration/test_migrations_postgres.py::test_large_table_online_migration_budget'
  'tests/integration/test_migrations_postgres.py::test_irreversible_restore_rehearsal'
  'tests/integration/test_migrations_postgres.py::test_failed_migration_no_later_state'
  'tests/integration/test_migrations_postgres.py::test_revision_0010_refuses_historical_approval_votes_without_invented_bindings'
)
p2_tenant_bootstrap_selectors=(
  'tests/integration/test_tenant_bootstrap_vertical.py::test_real_api_postgres_bootstrap_allow_atomic'
  'tests/integration/test_tenant_bootstrap_vertical.py::test_real_api_postgres_bootstrap_refusal_matrix'
  'tests/integration/test_tenant_bootstrap_vertical.py::test_100_request_multiprocess_bootstrap_once'
)
p2_register_selectors=(
  'tests/integration/test_agent_registration_postgres.py::test_real_postgres_concurrent_policy_activation_preserves_single_active'
)
p2_idempotency_selectors=(
  'tests/integration/test_agent_registration_idempotency_postgres.py::test_identical_key_and_canonical_request_converges_to_one_terminal_result'
  'tests/integration/test_agent_registration_idempotency_postgres.py::test_same_key_different_canonical_request_conflicts_without_additional_side_effects'
  'tests/integration/test_agent_registration_idempotency_postgres.py::test_exact_receipt_replay_is_typed_and_nonduplicating'
  'tests/integration/test_agent_registration_idempotency_postgres.py::test_100_request_multiprocess_has_at_most_one_authorized_execution'
)
p2_vertical_gate_selectors=(
  'tests/integration/test_vertical_gate_postgres.py::test_real_postgres_tenant_bootstrap_then_customer_agent_register'
  'tests/integration/test_vertical_gate_postgres.py::test_real_postgres_vertical_negative_oracles_and_production_legacy_reachability'
)
p3_policy_selectors=(
  'tests/integration/test_managed_policy_lifecycle_postgres.py::test_pg_publish_immutable_version_without_head'
  'tests/integration/test_managed_policy_lifecycle_postgres.py::test_pg_activate_advances_exactly_one_head'
  'tests/integration/test_managed_policy_lifecycle_postgres.py::test_pg_concurrent_candidates_have_one_generation_winner'
  'tests/integration/test_managed_policy_lifecycle_postgres.py::test_pg_publish_idempotent_replay_is_one_terminal_effect'
  'tests/integration/test_managed_policy_lifecycle_postgres.py::test_pg_idempotency_conflict_has_zero_delta'
  'tests/integration/test_managed_policy_lifecycle_postgres.py::test_pg_activation_revalidates_trust_and_rolls_back_before_effect'
)
p3_mutations_selectors=(
  'tests/integration/test_mutation_inventory_postgres.py::test_pg_agent_register_commits_one_sql_atomic_managed_mutation'
  'tests/integration/test_mutation_inventory_postgres.py::test_pg_route_app_drift_refuses_before_replacement_and_preserves_sql_counts'
  'tests/integration/test_mutation_inventory_postgres.py::test_pg_service_binding_drift_preserves_sql_counts_and_legacy_blockers'
  'tests/integration/test_mutation_inventory_postgres.py::test_pg_legacy_regex_precedence_drift_preserves_sql_counts_before_bootstrap'
)
p3_approval_selectors=(
  'tests/integration/test_approval_resume_postgres.py::test_pg_escalate_creates_scoped_pending_without_agent_or_consumption'
  'tests/integration/test_approval_resume_postgres.py::test_pg_self_and_wrong_role_approval_are_non_executable'
  'tests/integration/test_approval_resume_postgres.py::test_pg_resume_before_required_vote_is_non_executable'
  'tests/integration/test_approval_resume_postgres.py::test_pg_approved_resume_executes_once_and_replay_is_stable'
  'tests/integration/test_approval_resume_postgres.py::test_pg_rejected_and_expired_requests_resume_zero_side_effects'
  'tests/integration/test_approval_resume_postgres.py::test_pg_concurrent_vote_refusal_replay_records_one_evidence_set'
  'tests/integration/test_approval_resume_postgres.py::test_pg_mixed_refusal_then_allow_same_vote_key_has_one_terminal_artifact'
  'tests/integration/test_approval_resume_postgres.py::test_pg_stale_policy_trust_and_requester_resume_zero_side_effects'
  'tests/integration/test_approval_resume_postgres.py::test_pg_tampered_sealed_payload_resume_zero_side_effects'
  'tests/integration/test_approval_resume_postgres.py::test_pg_multiprocess_resume_race_authorizes_one_agent'
  'tests/integration/test_approval_resume_postgres.py::test_pg_approval_composite_constraints_reject_cross_scope_rows'
)
immutable_0004_selector='tests/integration/test_migrations_postgres.py::test_immutable_0004_upgrade_defers_managed_ledger_constraints_and_bootstraps'
selector_mode=''
junit_expected_tests=0
if (($# == ${#expected_selectors[@]})); then
  selector_mode='p1-migration'
  junit_expected_tests=7
  actual_selectors=("$@")
  for index in "${!expected_selectors[@]}"; do
    if [[ "${actual_selectors[index]}" != "${expected_selectors[index]}" ]]; then
      selector_mode=''
      break
    fi
  done
fi
if [[ -z "$selector_mode" && $# == "${#p2_tenant_bootstrap_selectors[@]}" ]]; then
  selector_mode='p2-tenant-bootstrap'
  junit_expected_tests=3
  actual_selectors=("$@")
  for index in "${!p2_tenant_bootstrap_selectors[@]}"; do
    if [[ "${actual_selectors[index]}" != "${p2_tenant_bootstrap_selectors[index]}" ]]; then
      selector_mode=''
      break
    fi
  done
fi
if [[ -z "$selector_mode" && $# == "${#p2_register_selectors[@]}" ]]; then
  selector_mode='p2-register'
  junit_expected_tests=1
  actual_selectors=("$@")
  for index in "${!p2_register_selectors[@]}"; do
    if [[ "${actual_selectors[index]}" != "${p2_register_selectors[index]}" ]]; then
      selector_mode=''
      break
    fi
  done
fi
if [[ -z "$selector_mode" && $# == "${#p2_idempotency_selectors[@]}" ]]; then
  selector_mode='p2-idempotency'
  junit_expected_tests=4
  actual_selectors=("$@")
  for index in "${!p2_idempotency_selectors[@]}"; do
    if [[ "${actual_selectors[index]}" != "${p2_idempotency_selectors[index]}" ]]; then
      selector_mode=''
      break
    fi
  done
fi
if [[ -z "$selector_mode" && $# == "${#p2_vertical_gate_selectors[@]}" ]]; then
  selector_mode='p2-vertical-gate'
  junit_expected_tests=2
  actual_selectors=("$@")
  for index in "${!p2_vertical_gate_selectors[@]}"; do
    if [[ "${actual_selectors[index]}" != "${p2_vertical_gate_selectors[index]}" ]]; then
      selector_mode=''
      break
    fi
  done
fi
if [[ -z "$selector_mode" && $# == "${#p3_policy_selectors[@]}" ]]; then
  selector_mode='p3-policy'
  junit_expected_tests=6
  actual_selectors=("$@")
  for index in "${!p3_policy_selectors[@]}"; do
    if [[ "${actual_selectors[index]}" != "${p3_policy_selectors[index]}" ]]; then
      selector_mode=''
      break
    fi
  done
fi
if [[ -z "$selector_mode" && $# == "${#p3_mutations_selectors[@]}" ]]; then
  selector_mode='p3-mutations'
  junit_expected_tests=4
  actual_selectors=("$@")
  for index in "${!p3_mutations_selectors[@]}"; do
    if [[ "${actual_selectors[index]}" != "${p3_mutations_selectors[index]}" ]]; then
      selector_mode=''
      break
    fi
  done
fi
if [[ -z "$selector_mode" && $# == "${#p3_approval_selectors[@]}" ]]; then
  selector_mode='p3-approval'
  junit_expected_tests=12
  actual_selectors=("$@")
  for index in "${!p3_approval_selectors[@]}"; do
    if [[ "${actual_selectors[index]}" != "${p3_approval_selectors[index]}" ]]; then
      selector_mode=''
      break
    fi
  done
fi
if [[ -z "$selector_mode" && $# == 1 && "$1" == "$immutable_0004_selector" ]]; then
  selector_mode='p2-immutable-0004-upgrade'
  junit_expected_tests=1
fi
if [[ -z "$selector_mode" ]]; then
  echo 'the exact ordered PostgreSQL migration, P2 tenant-bootstrap, P2 register, P2 idempotency, P2 vertical-gate, P3 policy, P3 mutations, P3 approval, or immutable-0004 selector is required' >&2
  exit 64
fi
case "${PYTEST_ADDOPTS:-}" in
  '' | '-p no:cacheprovider') ;;
  *)
    echo 'PYTEST_ADDOPTS must be empty or exactly -p no:cacheprovider for the PostgreSQL migration gate' >&2
    exit 64
    ;;
esac
if [[ -n "${PYTEST_PLUGINS:-}" ]]; then
  echo 'PYTEST_PLUGINS must be empty for the PostgreSQL migration gate' >&2
  exit 64
fi

unset PYTEST_ADDOPTS PYTHONPATH PYTHONHOME PYTHONOPTIMIZE PGOPTIONS
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
export PYTHONNOUSERSITE=1
export ACGS_TEST_SEED=20260710
export PYTHONHASHSEED=0

if [[ ! -x "$package_dir/.venv/bin/python" || ! -x "$package_dir/.venv/bin/pytest" ]]; then
  echo 'packages/acgs-control-plane/.venv/bin/python and .venv/bin/pytest are required' >&2
  exit 66
fi
for required_command in bwrap cmp docker git mktemp realpath sha256sum stat tar timeout; do
  if ! command -v "$required_command" >/dev/null 2>&1; then
    printf 'required command is unavailable: %s\n' "$required_command" >&2
    exit 69
  fi
done
docker_bin="$(command -v docker)"
if [[ "$docker_bin" != /* || ! -x "$docker_bin" || -L "$docker_bin" ]]; then
  echo 'the PostgreSQL evidence gate requires an absolute executable non-symlink docker client' >&2
  exit 69
fi
bwrap_bin="$(command -v bwrap)"
if [[ "$bwrap_bin" != /usr/bin/bwrap || ! -x "$bwrap_bin" || -L "$bwrap_bin" ]]; then
  echo 'the PostgreSQL evidence gate requires canonical /usr/bin/bwrap' >&2
  exit 69
fi
if [[ ! -x /usr/bin/python3 ]]; then
  echo 'the PostgreSQL evidence gate requires executable /usr/bin/python3' >&2
  exit 69
fi
if ! "$bwrap_bin" \
  --unshare-all --unshare-user --die-with-parent --new-session --disable-userns \
  --proc /proc --dev /dev --tmpfs /tmp --tmpfs /run \
  --ro-bind /usr /usr --ro-bind /bin /bin --ro-bind-try /lib /lib \
  --ro-bind-try /lib64 /lib64 --clearenv \
  --setenv PATH /usr/bin:/bin -- \
  /bin/sh -c 'test ! -e /run/docker.sock && test ! -e /var/run/docker.sock && test -r /proc/self/status' \
  >/dev/null 2>&1
then
  echo 'bwrap preflight failed; refusing to run the PostgreSQL evidence gate unsandboxed' >&2
  exit 69
fi

if [[ -v UV_BIN ]]; then
  uv_bin="$UV_BIN"
else
  uv_bin="$(command -v uv || true)"
fi
if [[ "$uv_bin" != /* || ! -f "$uv_bin" || ! -x "$uv_bin" || -L "$uv_bin" ]]; then
  echo 'UV_BIN must resolve to an absolute executable non-symlink' >&2
  exit 69
fi
canonical_uv_bin="$(realpath -e -- "$uv_bin")"
if [[ "$canonical_uv_bin" != "$uv_bin" ]]; then
  echo 'UV_BIN must already be a canonical path' >&2
  exit 69
fi
if [[ "$(sha256sum "$uv_bin" | awk '{print $1}')" != 'a00d3a24514fc0403fc232c9c99bf5e542657c38f4ed941e0611731e4cff268b' ]]; then
  echo 'UV_BIN does not match the required pinned sha256' >&2
  exit 69
fi
if [[ "$("$uv_bin" --version)" != 'uv 0.11.19 (x86_64-unknown-linux-gnu)' ]]; then
  echo 'UV_BIN must be uv 0.11.19' >&2
  exit 69
fi
canonical_venv_python="$(realpath -e -- "$package_dir/.venv/bin/python")"
venv_python_target="$(readlink -- "$package_dir/.venv/bin/python")"
if [[ "$venv_python_target" != /* ]]; then
  echo 'packages/acgs-control-plane/.venv/bin/python must be an absolute uv-managed symlink' >&2
  exit 69
fi
python_runtime_bind_root="$(dirname -- "$(dirname -- "$venv_python_target")")"
python_runtime_root="$(dirname -- "$(dirname -- "$canonical_venv_python")")"
if [[ -n "${UV_PYTHON_INSTALL_DIR:-}" ]]; then
  require_private_dir() {
    local directory=$1
    local owner mode
    owner="$(stat -c '%u' -- "$directory")"
    mode="$(stat -c '%a' -- "$directory")"
    if [[ "$owner" != "$(id -u)" || "$mode" != '700' ]]; then
      printf '%s must be owned by the current user with mode 700\n' "$directory" >&2
      exit 69
    fi
  }
  if [[ "$UV_PYTHON_INSTALL_DIR" != /* ]]; then
    echo 'UV_PYTHON_INSTALL_DIR must be absolute for the PostgreSQL evidence gate' >&2
    exit 69
  fi
  canonical_uv_python_install_dir="$(realpath -e -- "$UV_PYTHON_INSTALL_DIR")"
  if [[ "$canonical_uv_python_install_dir" != "$UV_PYTHON_INSTALL_DIR" || -L "$UV_PYTHON_INSTALL_DIR" ]]; then
    echo 'UV_PYTHON_INSTALL_DIR must be canonical and non-symlinked for the PostgreSQL evidence gate' >&2
    exit 69
  fi
  if [[ "${TMPDIR:-}" != /* ]]; then
    echo 'TMPDIR must be absolute when UV_PYTHON_INSTALL_DIR is provided' >&2
    exit 69
  fi
  canonical_tmpdir="$(realpath -e -- "$TMPDIR")"
  if [[ "$canonical_tmpdir" != "$TMPDIR" || -L "$TMPDIR" || "${canonical_tmpdir##*/}" != tmp ]]; then
    echo 'TMPDIR must be the canonical proof scratch tmp directory' >&2
    exit 69
  fi
  canonical_proof_scratch_root="$(dirname -- "$canonical_tmpdir")"
  canonical_proof_root="$(dirname -- "$canonical_proof_scratch_root")"
  canonical_proof_runtime_root="$canonical_proof_root/runtime"
  if [[ "$canonical_proof_scratch_root" != "$canonical_proof_root/scratch" ]]; then
    echo 'TMPDIR must be nested under the proof scratch/tmp directory' >&2
    exit 69
  fi
  if [[ "$canonical_uv_python_install_dir" != "$canonical_proof_runtime_root/uv-python" ]]; then
    echo 'UV_PYTHON_INSTALL_DIR must equal the proof runtime uv-python directory' >&2
    exit 69
  fi
  require_private_dir "$canonical_proof_root"
  require_private_dir "$canonical_proof_scratch_root"
  require_private_dir "$canonical_tmpdir"
  require_private_dir "$canonical_proof_runtime_root"
  require_private_dir "$canonical_uv_python_install_dir"
  case "$python_runtime_root" in
    "$canonical_uv_python_install_dir"/*) ;;
    *)
      echo 'packages/acgs-control-plane/.venv/bin/python must resolve beneath UV_PYTHON_INSTALL_DIR' >&2
      exit 69
      ;;
  esac
else
  case "$python_runtime_root" in
    /home/*/.local/share/uv/python/*) ;;
    *)
      echo 'packages/acgs-control-plane/.venv/bin/python must resolve under the uv-managed Python runtime root' >&2
      exit 69
      ;;
  esac
fi

umask 077
state_dir="$(mktemp -d "${TMPDIR:-/tmp}/acp-postgres-gate.XXXXXX")"
nonce_file="$state_dir/proof-nonce.hex"

validate_postgres_proof_nonce() {
  local nonce=$1
  [[ "$nonce" =~ ^[0-9a-f]{32}$ ]]
}

mint_postgres_proof_nonce() {
  local target_file=$1
  /usr/bin/python3 -I -S - "$target_file" <<'PY'
from __future__ import annotations

import os
import re
import stat
import sys

path = sys.argv[1]
nonce = os.urandom(16).hex()
if not re.fullmatch(r"[0-9a-f]{32}", nonce):
    raise SystemExit(70)
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
fd = os.open(path, flags, 0o600)
try:
    stat_result = os.fstat(fd)
    if stat_result.st_uid != os.getuid():
        raise SystemExit(70)
    if stat_result.st_nlink != 1:
        raise SystemExit(70)
    if stat_result.st_mode & 0o777 != 0o600:
        raise SystemExit(70)
    os.write(fd, (nonce + "\n").encode("ascii"))
finally:
    os.close(fd)
print(nonce)
PY
}

read_postgres_proof_nonce_file() {
  local source_file=$1
  /usr/bin/python3 -I -S - "$source_file" <<'PY'
from __future__ import annotations

import os
import re
import stat
import sys

path = sys.argv[1]
flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
try:
    fd = os.open(path, flags)
except FileNotFoundError:
    raise SystemExit(66)
try:
    stat_result = os.fstat(fd)
    if not stat.S_ISREG(stat_result.st_mode):
        raise SystemExit(70)
    if stat_result.st_uid != os.getuid():
        raise SystemExit(70)
    if stat_result.st_nlink != 1:
        raise SystemExit(70)
    if stat_result.st_mode & 0o777 != 0o600:
        raise SystemExit(70)
    raw = os.read(fd, 128)
finally:
    os.close(fd)
try:
    text = raw.decode("ascii").strip()
except UnicodeDecodeError:
    raise SystemExit(70)
if not re.fullmatch(r"[0-9a-f]{32}", text):
    raise SystemExit(70)
print(text)
PY
}

derive_postgres_proof_label() {
  local uid=$1
  local nonce=$2
  [[ "$uid" =~ ^[0-9]+$ ]] || return 70
  validate_postgres_proof_nonce "$nonce" || return 70
  printf 'acp-postgres-gate-%s-%s\n' "$uid" "$nonce"
}

validate_postgres_recovery_root() {
  local recovery_root=$1
  /usr/bin/python3 -I -S - "$recovery_root" <<'PY'
from __future__ import annotations

import os
import stat
import sys

path = sys.argv[1]
if not path.startswith("/"):
    raise SystemExit(70)
fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    root_stat = os.fstat(fd)
    if not stat.S_ISDIR(root_stat.st_mode):
        raise SystemExit(70)
    if root_stat.st_uid != os.getuid():
        raise SystemExit(70)
    if root_stat.st_mode & 0o077:
        raise SystemExit(70)
    descriptor_path = os.path.realpath(f"/proc/self/fd/{fd}")
    if descriptor_path != os.path.realpath(path):
        raise SystemExit(70)
finally:
    os.close(fd)
print(os.path.realpath(path))
PY
}

validate_postgres_recovery_root_binding() {
  local recovery_root=$1
  local expected_root_binding=$2
  /usr/bin/python3 -I -S - "$recovery_root" "$expected_root_binding" <<'PY'
from __future__ import annotations

import os
import stat
import sys

path, expected_root_binding = sys.argv[1:3]
if not expected_root_binding:
    raise SystemExit(70)


def mnt_id(fd: int) -> str:
    with open(f"/proc/self/fdinfo/{fd}", encoding="utf-8") as fdinfo:
        for line in fdinfo:
            if line.startswith("mnt_id:"):
                value = line.split(":", 1)[1].strip()
                if not value.isdigit():
                    raise SystemExit(70)
                return value
    raise SystemExit(70)


fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    root_stat = os.fstat(fd)
    if not stat.S_ISDIR(root_stat.st_mode):
        raise SystemExit(70)
    if root_stat.st_uid != os.getuid() or stat.S_IMODE(root_stat.st_mode) != 0o700:
        raise SystemExit(70)
    root_identity = f"{root_stat.st_dev}:{root_stat.st_ino}:{root_stat.st_uid}:700"
    observed_mnt_id = mnt_id(fd)
    fields = expected_root_binding.split("\t")
    if len(fields) != 3 or fields[0] != "acgs-postgres-recovery-root/v2":
        raise SystemExit(70)
    if fields[1] != root_identity:
        raise SystemExit(70)
    if not fields[2].isdigit() or fields[2] != observed_mnt_id:
        raise SystemExit(70)
    print(observed_mnt_id)
finally:
    os.close(fd)
PY
}

mint_postgres_proof_nonce "$nonce_file" >/dev/null || {
  echo 'failed to mint PostgreSQL evidence gate proof nonce' >&2
  exit 69
}
proof_nonce="$(read_postgres_proof_nonce_file "$nonce_file")" || {
  echo 'failed to load PostgreSQL evidence gate proof nonce' >&2
  exit 69
}
mint_postgres_password() {
  /usr/bin/python3 -I -S - <<'PY'
from __future__ import annotations

import os

print("acgs-" + os.urandom(24).hex())
PY
}
postgres_password="$(mint_postgres_password)" || {
  echo 'failed to mint PostgreSQL bootstrap admin password' >&2
  exit 69
}
postgres_fixture_owner_password="$(mint_postgres_password)" || {
  echo 'failed to mint PostgreSQL fixture owner password' >&2
  exit 69
}
proof_label="$(derive_postgres_proof_label "$(id -u)" "$proof_nonce")" || {
  echo 'failed to derive PostgreSQL evidence gate proof label' >&2
  exit 69
}
container_name="${proof_label}-server"
server_cidfile="$state_dir/server.cid"
server_namefile="$state_dir/server.name"
postgres_socket_bridge=''
postgres_socket_bridge_name="${proof_label}-socket-bridge"
postgres_socket_bridge_identity=''
postgres_socket_bridge_marker_sha256=''
postgres_socket_bridge_mnt_id=''
postgres_socket_bridge_creation_uncertain=0
postgres_recovery_root_binding="${ACGS_POSTGRES_RECOVERY_ROOT_BINDING_V2:-}"
postgres_recovery_root_mnt_id=''
postgres_recovery_root="${ACGS_POSTGRES_RECOVERY_ROOT:-}"
if [[ -z "$postgres_recovery_root" ]]; then
  echo 'ACGS_POSTGRES_RECOVERY_ROOT is required for PostgreSQL recovery intents' >&2
  exit 64
fi
postgres_recovery_root="$(validate_postgres_recovery_root "$postgres_recovery_root")" || {
  echo 'ACGS_POSTGRES_RECOVERY_ROOT is not an owner-only descriptor-bound directory' >&2
  exit 70
}
postgres_recovery_root_mnt_id="$(
  validate_postgres_recovery_root_binding "$postgres_recovery_root" "$postgres_recovery_root_binding"
)" || {
  echo 'ACGS_POSTGRES_RECOVERY_ROOT_BINDING_V2 is required and does not match recovery root identity' >&2
  exit 70
}
export ACGS_POSTGRES_RECOVERY_ROOT="$postgres_recovery_root"
container_id=''
broker_pid=''
docker_started=0
DOCKER_PS_IDS=()

read_private_container_file() {
  local source_file=$1
  local kind=$2
  /usr/bin/python3 -I -S - "$source_file" "$kind" <<'PY'
from __future__ import annotations

import os
import re
import stat
import sys

path = sys.argv[1]
kind = sys.argv[2]
patterns = {
    "cid": r"[0-9a-f]{12,64}",
    "name": r"acp-postgres-gate-[0-9]+-[0-9a-f]{32}-(server|client-[0-9]+-[0-9]+)",
}
if kind not in patterns:
    raise SystemExit(70)
try:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
except FileNotFoundError:
    raise SystemExit(1)
try:
    stat_result = os.fstat(fd)
    if not stat.S_ISREG(stat_result.st_mode):
        raise SystemExit(70)
    if stat_result.st_uid != os.getuid():
        raise SystemExit(70)
    if stat_result.st_nlink != 1:
        raise SystemExit(70)
    if stat_result.st_mode & 0o777 != 0o600:
        raise SystemExit(70)
    raw = os.read(fd, 512)
finally:
    os.close(fd)
try:
    text = raw.decode("ascii").strip()
except UnicodeDecodeError:
    raise SystemExit(70)
if "\n" in text or not re.fullmatch(patterns[kind], text):
    raise SystemExit(70)
print(text)
PY
}

write_private_container_name_file() {
  local target_file=$1
  local container_record_name=$2
  /usr/bin/python3 -I -S - "$target_file" "$container_record_name" <<'PY'
from __future__ import annotations

import os
import re
import stat
import sys

path = sys.argv[1]
name = sys.argv[2]
if not re.fullmatch(r"acp-postgres-gate-[0-9]+-[0-9a-f]{32}-(server|client-[0-9]+-[0-9]+)", name):
    raise SystemExit(70)
fd = os.open(
    path,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
    0o600,
)
try:
    stat_result = os.fstat(fd)
    if stat_result.st_uid != os.getuid() or stat_result.st_nlink != 1:
        raise SystemExit(70)
    if stat_result.st_mode & 0o777 != 0o600:
        raise SystemExit(70)
    payload = name.encode("ascii") + b"\n"
    written = os.write(fd, payload)
    if written != len(payload):
        raise SystemExit(70)
    os.fsync(fd)
finally:
    os.close(fd)
dir_fd = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    os.fsync(dir_fd)
finally:
    os.close(dir_fd)
PY
}

write_verified_private_artifact() {
  local target_dir=$1
  local target_name=$2
  local target_mode=$3
  /usr/bin/python3 -I -S - "$target_dir" "$target_name" "$target_mode" 3<&0 <<'PY'
from __future__ import annotations

import os
import re
import stat
import sys

directory, name, mode_text = sys.argv[1:4]
if "/" in name or name in {"", ".", ".."}:
    raise SystemExit(70)
if not re.fullmatch(r"[0-7]{3,4}", mode_text):
    raise SystemExit(70)
mode = int(mode_text, 8)
chunks = []
remaining = 8 * 1024 * 1024 + 1
while remaining > 0:
    chunk = os.read(3, min(65_536, remaining))
    if not chunk:
        break
    chunks.append(chunk)
    remaining -= len(chunk)
payload = b"".join(chunks)
if len(payload) > 8 * 1024 * 1024:
    raise SystemExit(70)
dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    dir_stat = os.fstat(dir_fd)
    if dir_stat.st_uid != os.getuid() or dir_stat.st_mode & 0o022:
        raise SystemExit(70)
    fd = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        mode,
        dir_fd=dir_fd,
    )
    try:
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise SystemExit(70)
        if file_stat.st_uid != os.getuid() or file_stat.st_nlink != 1:
            raise SystemExit(70)
        if file_stat.st_mode & 0o777 != mode:
            raise SystemExit(70)
        written = os.write(fd, payload)
        if written != len(payload):
            raise SystemExit(70)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(dir_fd)
finally:
    os.close(dir_fd)
PY
}

create_postgres_socket_bridge() {
  local bridge_name=$1
  /usr/bin/python3 -I -S - \
    "$postgres_recovery_root" "$bridge_name" "$proof_nonce" "$proof_label" \
    "$postgres_recovery_root_binding" "$postgres_recovery_root_mnt_id" <<'PY'
from __future__ import annotations

import ctypes
import hashlib
import os
import re
import stat
import sys

recovery_root, bridge_name, proof_nonce, proof_label, expected_root_binding, expected_root_mnt_id = (
    sys.argv[1:7]
)
if not re.fullmatch(r"acp-postgres-gate-[0-9]+-[0-9a-f]{32}-socket-bridge", bridge_name):
    raise SystemExit(70)
if not re.fullmatch(r"[0-9a-f]{32}", proof_nonce):
    raise SystemExit(70)
if bridge_name != f"{proof_label}-socket-bridge":
    raise SystemExit(70)
if not re.fullmatch(r"acp-postgres-gate-[0-9]+-[0-9a-f]{32}", proof_label):
    raise SystemExit(70)
if not expected_root_mnt_id.isdigit():
    raise SystemExit(70)


def mnt_id(fd: int) -> str:
    with open(f"/proc/self/fdinfo/{fd}", encoding="utf-8") as fdinfo:
        for line in fdinfo:
            if line.startswith("mnt_id:"):
                value = line.split(":", 1)[1].strip()
                if not value.isdigit():
                    raise SystemExit(70)
                return value
    raise SystemExit(70)


def rename_exchange(root_fd: int, first: str, second: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    syscall = libc.syscall
    syscall.argtypes = (
        ctypes.c_long,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    syscall.restype = ctypes.c_long
    renameat2_syscall = 316
    rename_exchange_flag = 2
    rc = syscall(
        renameat2_syscall,
        root_fd,
        os.fsencode(first),
        root_fd,
        os.fsencode(second),
        rename_exchange_flag,
    )
    if rc != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), f"{first} <-> {second}")


SnapshotValue = tuple[int, int, int, int, int, int, int, str]


def hash_fd(fd: int) -> str:
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest()


def snapshot_entry(
    parent_fd: int,
    child_name: str,
    relative_name: str,
    snapshot: dict[str, SnapshotValue],
) -> None:
    if not child_name or "/" in child_name or "\0" in child_name:
        raise SystemExit(70)
    child_stat = os.stat(child_name, dir_fd=parent_fd, follow_symlinks=False)
    mode_type = stat.S_IFMT(child_stat.st_mode)
    mode_bits = stat.S_IMODE(child_stat.st_mode)
    content_hash = ""
    if stat.S_ISLNK(child_stat.st_mode):
        raise SystemExit(70)
    if stat.S_ISDIR(child_stat.st_mode):
        child_fd = os.open(
            child_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
        try:
            if mnt_id(child_fd) != expected_root_mnt_id:
                raise SystemExit(70)
            entries = os.listdir(child_fd)
            content_hash = hashlib.sha256(
                b"\0".join(sorted(name.encode("utf-8") for name in entries))
            ).hexdigest()
            snapshot[relative_name] = (
                child_stat.st_dev,
                child_stat.st_ino,
                child_stat.st_uid,
                mode_type,
                mode_bits,
                child_stat.st_nlink,
                child_stat.st_size,
                content_hash,
            )
            for nested_name in entries:
                snapshot_entry(
                    child_fd,
                    nested_name,
                    f"{relative_name}/{nested_name}",
                    snapshot,
                )
        finally:
            os.close(child_fd)
        return
    if stat.S_ISREG(child_stat.st_mode):
        child_fd = os.open(
            child_name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
        try:
            if mnt_id(child_fd) != expected_root_mnt_id:
                raise SystemExit(70)
            content_hash = hash_fd(child_fd)
        finally:
            os.close(child_fd)
    snapshot[relative_name] = (
        child_stat.st_dev,
        child_stat.st_ino,
        child_stat.st_uid,
        mode_type,
        mode_bits,
        child_stat.st_nlink,
        child_stat.st_size,
        content_hash,
    )


def recovery_root_snapshot(root_fd: int) -> dict[str, SnapshotValue]:
    snapshot: dict[str, SnapshotValue] = {}
    for child_name in os.listdir(root_fd):
        snapshot_entry(root_fd, child_name, child_name, snapshot)
    return snapshot


def root_child_snapshot(root_fd: int) -> dict[str, SnapshotValue]:
    snapshot: dict[str, SnapshotValue] = {}
    for child_name in os.listdir(root_fd):
        if not child_name or "/" in child_name or "\0" in child_name:
            raise SystemExit(70)
        child_stat = os.stat(child_name, dir_fd=root_fd, follow_symlinks=False)
        snapshot[child_name] = (
            child_stat.st_dev,
            child_stat.st_ino,
            child_stat.st_uid,
            stat.S_IFMT(child_stat.st_mode),
            stat.S_IMODE(child_stat.st_mode),
            child_stat.st_nlink,
            child_stat.st_size,
            "",
        )
    return snapshot


def require_root_child_delta(
    before: dict[str, SnapshotValue],
    after: dict[str, SnapshotValue],
    bridge_name: str,
    bridge_stat: os.stat_result,
    bridge_mode: int,
) -> None:
    for child_name, child_identity in before.items():
        if after.get(child_name) != child_identity:
            raise OSError("socket bridge root baseline changed")
    new_names = set(after) - set(before)
    if new_names != {bridge_name}:
        raise OSError("socket bridge root child set changed")
    expected = (
        bridge_stat.st_dev,
        bridge_stat.st_ino,
        bridge_stat.st_uid,
        stat.S_IFMT(bridge_stat.st_mode),
        bridge_mode,
        bridge_stat.st_nlink,
        bridge_stat.st_size,
        "",
    )
    if after[bridge_name] != expected:
        raise OSError("socket bridge root candidate changed")


def require_baseline_subtree_unchanged(
    before: dict[str, SnapshotValue],
    root_fd: int,
    bridge_name: str,
    bridge_stat: os.stat_result,
    bridge_mode: int,
) -> None:
    after = recovery_root_snapshot(root_fd)
    for child_name, child_identity in before.items():
        if after.get(child_name) != child_identity:
            raise OSError("socket bridge baseline subtree changed")
    new_names = set(after) - set(before)
    new_root_names = {name.split("/", 1)[0] for name in new_names}
    if new_root_names != {bridge_name}:
        raise OSError("socket bridge root child set changed")
    if bridge_name not in after:
        raise OSError("socket bridge root candidate changed")
    expected = (
        bridge_stat.st_dev,
        bridge_stat.st_ino,
        bridge_stat.st_uid,
        stat.S_IFMT(bridge_stat.st_mode),
        bridge_mode,
        bridge_stat.st_nlink,
        bridge_stat.st_size,
        after[bridge_name][7],
    )
    if after[bridge_name] != expected:
        raise OSError("socket bridge root candidate changed")


def require_bridge_empty(bridge_fd: int) -> None:
    if os.listdir(bridge_fd):
        raise OSError("socket bridge candidate is not empty")


def require_bridge_marker_only(bridge_fd: int, marker_name: str, expected_payload: bytes) -> None:
    if os.listdir(bridge_fd) != [marker_name]:
        raise OSError("socket bridge marker set changed")
    marker_fd_check = os.open(
        marker_name,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=bridge_fd,
    )
    try:
        marker_stat_check = os.fstat(marker_fd_check)
        marker_payload_check = os.read(marker_fd_check, 4096)
        if (
            not stat.S_ISREG(marker_stat_check.st_mode)
            or marker_stat_check.st_uid != os.getuid()
            or marker_stat_check.st_nlink != 1
            or stat.S_IMODE(marker_stat_check.st_mode) != 0o444
            or marker_payload_check != expected_payload
        ):
            raise OSError("socket bridge marker changed")
    finally:
        os.close(marker_fd_check)


real_mkdir = os.mkdir
mkdir_exchange_name = os.environ.get("ACGS_POSTGRES_SOCKET_BRIDGE_EXCHANGE_INSIDE_MKDIR")
mkdir_move_outside_root = os.environ.get("ACGS_POSTGRES_SOCKET_BRIDGE_MOVE_OUTSIDE_ROOT_INSIDE_MKDIR")
mkdir_move_under_baseline_child = os.environ.get(
    "ACGS_POSTGRES_SOCKET_BRIDGE_MOVE_UNDER_BASELINE_CHILD_INSIDE_MKDIR"
)
mkdir_prepopulate_substitute = (
    os.environ.get("ACGS_POSTGRES_SOCKET_BRIDGE_PREPOPULATE_SUBSTITUTE_INSIDE_MKDIR") == "1"
)


def mkdir(path: str, mode: int = 0o777, *, dir_fd: int | None = None) -> None:
    real_mkdir(path, mode, dir_fd=dir_fd)
    if path != bridge_name or dir_fd != root_fd:
        return
    if mkdir_move_outside_root:
        if not os.path.isabs(mkdir_move_outside_root) or "\0" in mkdir_move_outside_root:
            raise SystemExit(70)
        os.rename(path, mkdir_move_outside_root, src_dir_fd=root_fd)
        real_mkdir(path, mode, dir_fd=root_fd)
        if mkdir_prepopulate_substitute:
            substitute_fd = os.open(
                path,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=root_fd,
            )
            try:
                fd = os.open(
                    "prepopulated",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=substitute_fd,
                )
                os.close(fd)
            finally:
                os.close(substitute_fd)
        return
    if mkdir_move_under_baseline_child:
        if not re.fullmatch(r"baseline-[0-9a-f]{8}", mkdir_move_under_baseline_child):
            raise SystemExit(70)
        os.rename(
            path,
            f"{mkdir_move_under_baseline_child}/{bridge_name}",
            src_dir_fd=root_fd,
            dst_dir_fd=root_fd,
        )
        real_mkdir(path, mode, dir_fd=root_fd)
        if mkdir_prepopulate_substitute:
            substitute_fd = os.open(
                path,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=root_fd,
            )
            try:
                fd = os.open(
                    "prepopulated",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=substitute_fd,
                )
                os.close(fd)
            finally:
                os.close(substitute_fd)
        return
    if mkdir_exchange_name:
        if not re.fullmatch(
            r"acp-postgres-gate-[0-9]+-[0-9a-f]{32}-socket-bridge-exchange",
            mkdir_exchange_name,
        ):
            raise SystemExit(70)
        real_mkdir(mkdir_exchange_name, 0o700, dir_fd=root_fd)
        rename_exchange(root_fd, bridge_name, mkdir_exchange_name)


created = False
marker_created = False
bridge_fd = -1
marker_fd = -1
root_child_delta_valid = False
root_fd = os.open(recovery_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    root_stat = os.fstat(root_fd)
    if not stat.S_ISDIR(root_stat.st_mode):
        raise SystemExit(70)
    if root_stat.st_uid != os.getuid() or stat.S_IMODE(root_stat.st_mode) != 0o700:
        raise SystemExit(70)
    root_identity = f"{root_stat.st_dev}:{root_stat.st_ino}:{root_stat.st_uid}:700"
    fields = expected_root_binding.split("\t")
    if len(fields) != 3 or fields[0] != "acgs-postgres-recovery-root/v2":
        raise SystemExit(70)
    if fields[1] != root_identity:
        raise SystemExit(70)
    if not fields[2].isdigit() or fields[2] != expected_root_mnt_id:
        raise SystemExit(70)
    if mnt_id(root_fd) != expected_root_mnt_id:
        raise SystemExit(70)
    root_child_snapshot_before = root_child_snapshot(root_fd)
    baseline_subtree_snapshot_before = recovery_root_snapshot(root_fd)
    if bridge_name in root_child_snapshot_before:
        raise SystemExit(70)
    try:
        mkdir(bridge_name, 0o700, dir_fd=root_fd)
        created = True
    except FileExistsError:
        raise SystemExit(70)
    bridge_fd = os.open(
        bridge_name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=root_fd,
    )
    bridge_stat = os.fstat(bridge_fd)
    if not stat.S_ISDIR(bridge_stat.st_mode):
        raise SystemExit(70)
    if bridge_stat.st_uid != os.getuid() or stat.S_IMODE(bridge_stat.st_mode) != 0o700:
        raise SystemExit(70)
    require_bridge_empty(bridge_fd)
    root_child_snapshot_after_mkdir = root_child_snapshot(root_fd)
    require_root_child_delta(
        root_child_snapshot_before,
        root_child_snapshot_after_mkdir,
        bridge_name,
        bridge_stat,
        0o700,
    )
    require_baseline_subtree_unchanged(
        baseline_subtree_snapshot_before,
        root_fd,
        bridge_name,
        bridge_stat,
        0o700,
    )
    root_child_delta_valid = True
    bridge_stable_identity = f"{bridge_stat.st_dev}:{bridge_stat.st_ino}:{bridge_stat.st_uid}"
    bridge_mnt_id = mnt_id(bridge_fd)
    if bridge_mnt_id != expected_root_mnt_id:
        raise SystemExit(70)
    exchange_name = os.environ.get("ACGS_POSTGRES_SOCKET_BRIDGE_RENAME_EXCHANGE_AFTER_MKDIR")
    if exchange_name:
        if not re.fullmatch(r"acp-postgres-gate-[0-9]+-[0-9a-f]{32}-socket-bridge-exchange", exchange_name):
            raise SystemExit(70)
        os.mkdir(exchange_name, 0o700, dir_fd=root_fd)
        rename_exchange(root_fd, bridge_name, exchange_name)
    if os.environ.get("ACGS_POSTGRES_SOCKET_BRIDGE_FAULT_AFTER_MKDIR") == "1":
        raise RuntimeError("injected fault after socket bridge mkdir")
    os.fchmod(bridge_fd, 0o1777)
    bridge_stat = os.fstat(bridge_fd)
    if not stat.S_ISDIR(bridge_stat.st_mode):
        raise SystemExit(70)
    if bridge_stat.st_uid != os.getuid() or stat.S_IMODE(bridge_stat.st_mode) != 0o1777:
        raise SystemExit(70)
    if f"{bridge_stat.st_dev}:{bridge_stat.st_ino}:{bridge_stat.st_uid}" != bridge_stable_identity:
        raise SystemExit(70)
    require_bridge_empty(bridge_fd)
    root_child_snapshot_after_chmod = root_child_snapshot(root_fd)
    require_root_child_delta(
        root_child_snapshot_before,
        root_child_snapshot_after_chmod,
        bridge_name,
        bridge_stat,
        0o1777,
    )
    bridge_identity = (
        f"{bridge_stat.st_dev}:{bridge_stat.st_ino}:{bridge_stat.st_uid}:1777"
    )
    bridge_mnt_id = mnt_id(bridge_fd)
    if bridge_mnt_id != expected_root_mnt_id:
        raise SystemExit(70)
    marker_payload = "\n".join(
        (
            "schema=acgs-postgres-socket-bridge/v2",
            f"proof_nonce={proof_nonce}",
            f"proof_label={proof_label}",
            f"bridge_basename={bridge_name}",
            f"bridge_identity={bridge_identity}",
            f"bridge_mnt_id={bridge_mnt_id}",
            "",
        )
    ).encode("ascii")
    marker_name = ".acgs-postgres-socket-bridge.v2"
    marker_fd = os.open(
        marker_name,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o444,
        dir_fd=bridge_fd,
    )
    marker_created = True
    os.fchmod(marker_fd, 0o444)
    marker_stat = os.fstat(marker_fd)
    if not stat.S_ISREG(marker_stat.st_mode):
        raise SystemExit(70)
    if marker_stat.st_uid != os.getuid() or marker_stat.st_nlink != 1:
        raise SystemExit(70)
    if stat.S_IMODE(marker_stat.st_mode) != 0o444:
        raise SystemExit(70)
    if os.write(marker_fd, marker_payload) != len(marker_payload):
        raise SystemExit(70)
    if os.environ.get("ACGS_POSTGRES_SOCKET_BRIDGE_FAULT_AFTER_MARKER_WRITE") == "1":
        raise RuntimeError("injected fault after socket bridge marker write")
    require_bridge_marker_only(bridge_fd, marker_name, marker_payload)
    bridge_stat = os.fstat(bridge_fd)
    require_baseline_subtree_unchanged(
        baseline_subtree_snapshot_before,
        root_fd,
        bridge_name,
        bridge_stat,
        0o1777,
    )
    os.fsync(marker_fd)
    os.close(marker_fd)
    marker_fd = -1
    os.fsync(bridge_fd)
    if os.environ.get("ACGS_POSTGRES_SOCKET_BRIDGE_FAULT_AFTER_BRIDGE_FSYNC") == "1":
        raise RuntimeError("injected fault after socket bridge fsync")
    os.fsync(root_fd)
    if os.environ.get("ACGS_POSTGRES_SOCKET_BRIDGE_FAULT_AFTER_ROOT_FSYNC") == "1":
        raise RuntimeError("injected fault after socket bridge root fsync")
    require_bridge_marker_only(bridge_fd, marker_name, marker_payload)
    bridge_stat = os.fstat(bridge_fd)
    require_baseline_subtree_unchanged(
        baseline_subtree_snapshot_before,
        root_fd,
        bridge_name,
        bridge_stat,
        0o1777,
    )
    os.close(bridge_fd)
    bridge_fd = -1
except BaseException:
    if created:
        print("socket_bridge_creation_uncertain=1", file=sys.stderr)
        print(f"recovery_root={recovery_root}", file=sys.stderr)
        print(f"socket_bridge_basename={bridge_name}", file=sys.stderr)
        print(f"recovery_root_identity={root_identity}", file=sys.stderr)
        print(f"recovery_root_mnt_id={expected_root_mnt_id}", file=sys.stderr)
        print(f"socket_bridge_marker_created={int(marker_created)}", file=sys.stderr)
        if "bridge_stable_identity" in locals():
            print(f"socket_bridge_stable_identity={bridge_stable_identity}", file=sys.stderr)
        if "bridge_identity" in locals():
            print(f"socket_bridge_identity={bridge_identity}", file=sys.stderr)
        if "bridge_mnt_id" in locals():
            print(f"socket_bridge_mnt_id={bridge_mnt_id}", file=sys.stderr)
    raise
finally:
    if marker_fd >= 0:
        os.close(marker_fd)
    if bridge_fd >= 0:
        os.close(bridge_fd)
    os.close(root_fd)

bridge_path = os.path.join(recovery_root, bridge_name)
print(bridge_path)
print(bridge_name)
print(bridge_identity)
print(hashlib.sha256(marker_payload).hexdigest())
print(bridge_mnt_id)
PY
}

verify_postgres_socket_bridge() {
  local expected_mode=$1
  /usr/bin/python3 -I -S - \
    "$postgres_recovery_root" "$postgres_socket_bridge_name" "$postgres_socket_bridge_identity" \
    "$postgres_socket_bridge_marker_sha256" "$postgres_socket_bridge_mnt_id" "$expected_mode" <<'PY'
from __future__ import annotations

import hashlib
import os
import re
import stat
import sys

root, bridge_name, expected_identity, expected_marker_sha256, expected_mnt_id, mode_text = (
    sys.argv[1:7]
)
if not re.fullmatch(r"acp-postgres-gate-[0-9]+-[0-9a-f]{32}-socket-bridge", bridge_name):
    raise SystemExit(70)
if not re.fullmatch(r"[0-9a-f]{64}", expected_marker_sha256):
    raise SystemExit(70)
if not expected_mnt_id.isdigit() or mode_text not in {"700", "1777"}:
    raise SystemExit(70)
expected_mode = int(mode_text, 8)
if not re.fullmatch(r"[0-9]+:[0-9]+:[0-9]+:1777", expected_identity):
    raise SystemExit(70)
expected_stable_identity = expected_identity.rsplit(":", 1)[0]


def mnt_id(fd: int) -> str:
    with open(f"/proc/self/fdinfo/{fd}", encoding="utf-8") as fdinfo:
        for line in fdinfo:
            if line.startswith("mnt_id:"):
                value = line.split(":", 1)[1].strip()
                if not value.isdigit():
                    raise SystemExit(70)
                return value
    raise SystemExit(70)


root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    root_stat = os.fstat(root_fd)
    if root_stat.st_uid != os.getuid() or stat.S_IMODE(root_stat.st_mode) != 0o700:
        raise SystemExit(70)
    bridge_fd = os.open(
        bridge_name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=root_fd,
    )
    try:
        bridge_stat = os.fstat(bridge_fd)
        observed_stable_identity = (
            f"{bridge_stat.st_dev}:{bridge_stat.st_ino}:{bridge_stat.st_uid}"
        )
        if observed_stable_identity != expected_stable_identity:
            raise SystemExit(70)
        if stat.S_IMODE(bridge_stat.st_mode) != expected_mode:
            raise SystemExit(70)
        with open(f"/proc/self/fdinfo/{bridge_fd}", encoding="utf-8") as fdinfo:
            observed_mnt_id = ""
            for line in fdinfo:
                if line.startswith("mnt_id:"):
                    observed_mnt_id = line.split(":", 1)[1].strip()
                    break
        if observed_mnt_id != expected_mnt_id:
            raise SystemExit(70)
        if observed_mnt_id != mnt_id(root_fd):
            raise SystemExit(70)
        marker_fd = os.open(
            ".acgs-postgres-socket-bridge.v2",
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=bridge_fd,
        )
        try:
            marker_stat = os.fstat(marker_fd)
            if not stat.S_ISREG(marker_stat.st_mode):
                raise SystemExit(70)
            if marker_stat.st_uid != os.getuid() or marker_stat.st_nlink != 1:
                raise SystemExit(70)
            if stat.S_IMODE(marker_stat.st_mode) != 0o444:
                raise SystemExit(70)
            payload = os.read(marker_fd, 4096)
            if hashlib.sha256(payload).hexdigest() != expected_marker_sha256:
                raise SystemExit(70)
        finally:
            os.close(marker_fd)
    finally:
        os.close(bridge_fd)
finally:
    os.close(root_fd)
PY
}

verify_private_artifact_fd() {
  local source_path=$1
  local fd_path=$2
  local expected_mode=$3
  /usr/bin/python3 -I -S - "$source_path" "$fd_path" "$expected_mode" <<'PY'
from __future__ import annotations

import os
import re
import stat
import sys

source_path, fd_path, mode_text = sys.argv[1:4]
if not re.fullmatch(r"[0-7]{3,4}", mode_text):
    raise SystemExit(70)
expected_mode = int(mode_text, 8)
source_stat = os.stat(source_path, follow_symlinks=False)
fd_stat = os.stat(fd_path, follow_symlinks=True)
if not stat.S_ISREG(source_stat.st_mode) or not stat.S_ISREG(fd_stat.st_mode):
    raise SystemExit(70)
if source_stat.st_uid != os.getuid() or source_stat.st_nlink != 1:
    raise SystemExit(70)
if source_stat.st_mode & 0o777 != expected_mode:
    raise SystemExit(70)
identity = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
if any(getattr(source_stat, field) != getattr(fd_stat, field) for field in identity):
    raise SystemExit(70)
PY
}

write_postgres_recovery_intent() {
  local phase=$1
  local intent_name=$2
  local record_path=$3
  /usr/bin/python3 -I -S - \
    "$postgres_recovery_root" "$phase" "$intent_name" "$record_path" \
    "$proof_nonce" "$proof_label" "$container_name" "$server_cidfile" "$server_namefile" \
    "$postgres_socket_bridge_name" "$postgres_socket_bridge_identity" \
    "$postgres_socket_bridge_marker_sha256" "$postgres_socket_bridge_mnt_id" <<'PY'
from __future__ import annotations

import os
import re
import stat
import sys

(
    recovery_root,
    phase,
    intent_name,
    record_path,
    nonce,
    proof_label,
    server_name,
    server_cidfile,
    server_namefile,
    bridge_basename,
    bridge_identity,
    bridge_marker_sha256,
    bridge_mnt_id,
) = sys.argv[1:14]
if phase not in {"server-intent"}:
    raise SystemExit(70)
if not re.fullmatch(r"[a-z0-9_.-]{1,96}", intent_name):
    raise SystemExit(70)
if not record_path.startswith("/"):
    raise SystemExit(70)
if not re.fullmatch(r"[0-9a-f]{32}", nonce):
    raise SystemExit(70)
if not re.fullmatch(r"acp-postgres-gate-[0-9]+-[0-9a-f]{32}", proof_label):
    raise SystemExit(70)
if server_name != f"{proof_label}-server":
    raise SystemExit(70)
if bridge_basename != f"{proof_label}-socket-bridge":
    raise SystemExit(70)
if not re.fullmatch(r"[0-9]+:[0-9]+:[0-9]+:1777", bridge_identity):
    raise SystemExit(70)
if not re.fullmatch(r"[0-9a-f]{64}", bridge_marker_sha256):
    raise SystemExit(70)
if not bridge_mnt_id.isdigit():
    raise SystemExit(70)
root_fd = os.open(recovery_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    root_stat = os.fstat(root_fd)
    if root_stat.st_uid != os.getuid() or root_stat.st_mode & 0o077:
        raise SystemExit(70)
    payload = "\n".join(
        (
            "intent_version=2",
            "schema=acgs-postgres-recovery-intent/server/v2",
            f"phase={phase}",
            f"proof_nonce={nonce}",
            f"proof_label={proof_label}",
            f"server_name={server_name}",
            f"record_path={record_path}",
            f"server_cidfile={server_cidfile}",
            f"server_namefile={server_namefile}",
            f"socket_bridge_basename={bridge_basename}",
            f"socket_bridge_identity={bridge_identity}",
            f"socket_bridge_marker_sha256={bridge_marker_sha256}",
            f"socket_bridge_mnt_id={bridge_mnt_id}",
            "",
        )
    ).encode("ascii")
    fd = os.open(
        f"{proof_label}-{intent_name}.intent",
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
        dir_fd=root_fd,
    )
    try:
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise SystemExit(70)
        if file_stat.st_uid != os.getuid() or file_stat.st_nlink != 1:
            raise SystemExit(70)
        if file_stat.st_mode & 0o777 != 0o600:
            raise SystemExit(70)
        written = os.write(fd, payload)
        if written != len(payload):
            raise SystemExit(70)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(root_fd)
finally:
    os.close(root_fd)
parent_fd = os.open(os.path.dirname(recovery_root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    os.fsync(parent_fd)
finally:
    os.close(parent_fd)
PY
}

write_recovery_contract() {
  local cleanup_rc=$1
  local contract_file="$state_dir/recovery-contract.env"
  local server_cid=''
  if [[ -e "$server_cidfile" ]]; then
    server_cid="$(read_private_container_file "$server_cidfile" cid 2>/dev/null || true)"
  fi
  /usr/bin/python3 -I -S - \
    "$contract_file" "$cleanup_rc" "$proof_nonce" "$proof_label" "$container_name" "$server_cid" \
    "$postgres_socket_bridge_name" "$postgres_socket_bridge_identity" \
    "$postgres_socket_bridge_marker_sha256" "$postgres_socket_bridge_mnt_id" \
    "$postgres_recovery_root_mnt_id" "$postgres_socket_bridge_creation_uncertain" <<'PY'
from __future__ import annotations

import os
import re
import stat
import sys

(
    path,
    cleanup_rc,
    nonce,
    proof_label,
    server_name,
    server_cid,
    bridge_basename,
    bridge_identity,
    bridge_marker_sha256,
    bridge_mnt_id,
    root_mnt_id,
    bridge_creation_uncertain,
) = sys.argv[1:13]
if not re.fullmatch(r"[0-9]+", cleanup_rc):
    raise SystemExit(70)
if not re.fullmatch(r"[0-9a-f]{32}", nonce):
    raise SystemExit(70)
if not re.fullmatch(r"acp-postgres-gate-[0-9]+-[0-9a-f]{32}", proof_label):
    raise SystemExit(70)
if server_name != f"{proof_label}-server":
    raise SystemExit(70)
if server_cid and not re.fullmatch(r"[0-9a-f]{12,64}", server_cid):
    raise SystemExit(70)
if bridge_basename and bridge_basename != f"{proof_label}-socket-bridge":
    raise SystemExit(70)
if bridge_identity and not re.fullmatch(r"[0-9]+:[0-9]+:[0-9]+:1777", bridge_identity):
    raise SystemExit(70)
if bridge_marker_sha256 and not re.fullmatch(r"[0-9a-f]{64}", bridge_marker_sha256):
    raise SystemExit(70)
if bridge_mnt_id and not bridge_mnt_id.isdigit():
    raise SystemExit(70)
if root_mnt_id and not root_mnt_id.isdigit():
    raise SystemExit(70)
if bridge_creation_uncertain not in {"0", "1"}:
    raise SystemExit(70)
lines = [
    "contract_version=2",
    "schema=acgs-postgres-recovery-contract/v2",
    "external_cleanup_uncertain=1",
    f"cleanup_status={cleanup_rc}",
    f"proof_nonce={nonce}",
    f"proof_label={proof_label}",
    f"server_name={server_name}",
]
if bridge_creation_uncertain == "1":
    lines.append("socket_bridge_creation_uncertain=1")
if server_cid:
    lines.append(f"server_cid={server_cid}")
if bridge_basename:
    lines.extend(
        [
            f"socket_bridge_basename={bridge_basename}",
            f"socket_bridge_identity={bridge_identity}",
            f"socket_bridge_marker_sha256={bridge_marker_sha256}",
            f"socket_bridge_mnt_id={bridge_mnt_id}",
            f"recovery_root_mnt_id={root_mnt_id}",
        ]
    )
payload = ("\n".join(lines) + "\n").encode("ascii")
fd = os.open(
    path,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
    0o600,
)
try:
    stat_result = os.fstat(fd)
    if not stat.S_ISREG(stat_result.st_mode):
        raise SystemExit(70)
    if stat_result.st_uid != os.getuid() or stat_result.st_nlink != 1:
        raise SystemExit(70)
    if stat_result.st_mode & 0o777 != 0o600:
        raise SystemExit(70)
    written = os.write(fd, payload)
    if written != len(payload):
        raise SystemExit(70)
    os.fsync(fd)
finally:
    os.close(fd)
dir_fd = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    os.fsync(dir_fd)
finally:
    os.close(dir_fd)
PY
}

verify_junit_report() {
  local report_dir=$1
  local report_name=$2
  local expected_tests=$3
  local expected_uid=$4
  /usr/bin/python3 -I -S - "$report_dir" "$report_name" "$expected_tests" "$expected_uid" <<'PY'
from __future__ import annotations

import io
import os
import stat
import sys
import xml.etree.ElementTree as ET


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


directory, report_name, expected_tests_text, expected_uid_text = sys.argv[1:5]
if "/" in report_name or report_name in {"", ".", ".."}:
    raise SystemExit("pytest JUnit report path is unsafe")
expected_tests = int(expected_tests_text)
expected_uid = int(expected_uid_text)
max_report_bytes = 8 * 1024 * 1024
try:
    dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
except OSError as exc:
    raise SystemExit("pytest JUnit report is missing or malformed") from exc
try:
    fd = os.open(
        report_name,
        os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=dir_fd,
    )
except OSError as exc:
    os.close(dir_fd)
    raise SystemExit("pytest JUnit report is missing or malformed") from exc
try:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode):
        raise SystemExit("pytest JUnit report is not a regular file")
    if before.st_uid != expected_uid or before.st_nlink != 1:
        raise SystemExit("pytest JUnit report identity is unsafe")
    if before.st_size > max_report_bytes:
        raise SystemExit("pytest JUnit report is too large")
    chunks: list[bytes] = []
    remaining = before.st_size
    while remaining > 0:
        chunk = os.read(fd, min(65_536, remaining))
        if not chunk:
            raise SystemExit("pytest JUnit report changed during read")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(fd, 1):
        raise SystemExit("pytest JUnit report changed during read")
    after = os.fstat(fd)
    identity = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in identity):
        raise SystemExit("pytest JUnit report changed during verification")
finally:
    os.close(fd)
    os.close(dir_fd)
try:
    root = ET.parse(io.BytesIO(b"".join(chunks))).getroot()
except ET.ParseError as exc:
    raise SystemExit("pytest JUnit report is missing or malformed") from exc

if local_name(root.tag) == "testsuite":
    suites = [root]
elif local_name(root.tag) == "testsuites":
    suites = [element for element in root if local_name(element.tag) == "testsuite"]
else:
    raise SystemExit("pytest JUnit report has an unsupported root element")
if not suites:
    raise SystemExit("pytest JUnit report contains no test suites")

totals = {field: 0 for field in ("tests", "failures", "errors", "skipped")}
for suite in suites:
    for field in totals:
        raw_value = suite.get(field, "0")
        try:
            value = int(raw_value)
        except ValueError as exc:
            raise SystemExit(f"pytest JUnit report has an invalid {field} count") from exc
        if value < 0:
            raise SystemExit(f"pytest JUnit report has a negative {field} count")
        totals[field] += value

expected = {"tests": expected_tests, "failures": 0, "errors": 0, "skipped": 0}
if totals != expected:
    raise SystemExit(f"pytest JUnit totals are not the required exact gate totals: {totals}")
print(
    "pytest JUnit totals verified: "
    f"{expected_tests} tests, 0 failures, 0 errors, 0 skipped"
)
PY
}

summarize_private_output_sink() {
  local output_file=$1
  /usr/bin/python3 -I -S - "$output_file" <<'PY'
from __future__ import annotations

import hashlib
import os
import stat
import sys

path = sys.argv[1]
max_bytes = 64 * 1024 * 1024
fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    output_stat = os.fstat(fd)
    if not stat.S_ISREG(output_stat.st_mode):
        raise SystemExit(70)
    if output_stat.st_uid != os.getuid() or output_stat.st_nlink != 1:
        raise SystemExit(70)
    if output_stat.st_mode & 0o777 != 0o600:
        raise SystemExit(70)
    digest = hashlib.sha256()
    total = 0
    overflow = 0
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            overflow = 1
            break
        digest.update(chunk)
finally:
    os.close(fd)
if overflow:
    raise SystemExit("pytest_output_overflow=1")
print(f"pytest_output_bytes={total} pytest_output_sha256={digest.hexdigest()} pytest_output_overflow=0")
PY
}

capture_docker_ps_ids() {
  local output=''
  local rc=0
  DOCKER_PS_IDS=()
  output="$(
    timeout --preserve-status 10s docker ps -aq "$@" 2>"$state_dir/docker-ps.err"
  )" || rc=$?
  if [[ "$rc" != 0 ]]; then
    return "$rc"
  fi
  if [[ -z "$output" ]]; then
    return 0
  fi
  if [[ "$output" == *$'\r'* ]]; then
    return 70
  fi
  local id=''
  while IFS= read -r id; do
    [[ -n "$id" ]] || return 70
    [[ "$id" =~ ^[0-9a-f]{12,64}$ ]] || return 70
    DOCKER_PS_IDS+=("$id")
  done <<<"$output"
}

cleanup_client_containers() {
  local cidfile=''
  local namefile=''
  local ref=''
  local expected_name=''
  local rc=0
  local aggregate_rc=0
  declare -A seen_client_names=()
  shopt -s nullglob
  for cidfile in "$state_dir"/client/*.cid; do
    if ref="$(read_private_container_file "$cidfile" cid)"; then
      expected_name="$(basename -- "$cidfile" .cid)"
      if [[ -z "${seen_client_names[$expected_name]:-}" ]]; then
        if remove_exact_recorded_container "$ref" "$expected_name" trusted-broker; then
          seen_client_names[$expected_name]=1
        else
          rc=$?
          [[ "$rc" == 1 || "$aggregate_rc" != 0 ]] || aggregate_rc=$rc
        fi
      fi
    else
      rc=$?
      [[ "$rc" == 1 ]] || {
        [[ "$aggregate_rc" == 0 ]] && aggregate_rc=$rc
        if [[ ! -e "$state_dir/recovery-container-ids.txt" ]]; then
          printf 'invalid trusted broker cidfile: %s\n' "$cidfile" \
            >"$state_dir/recovery-container-ids.txt" 2>/dev/null || true
        fi
      }
    fi
  done
  for namefile in "$state_dir"/client/*.name; do
    if ref="$(read_private_container_file "$namefile" name)"; then
      expected_name="$(basename -- "$namefile" .name)"
      if [[ -z "${seen_client_names[$expected_name]:-}" ]]; then
        if remove_exact_recorded_container "$ref" "$expected_name" trusted-broker; then
          seen_client_names[$expected_name]=1
        else
          rc=$?
          [[ "$rc" == 1 || "$aggregate_rc" != 0 ]] || aggregate_rc=$rc
        fi
      fi
    else
      rc=$?
      [[ "$rc" == 1 ]] || {
        [[ "$aggregate_rc" == 0 ]] && aggregate_rc=$rc
        if [[ ! -e "$state_dir/recovery-container-ids.txt" ]]; then
          printf 'invalid trusted broker namefile: %s\n' "$namefile" \
            >"$state_dir/recovery-container-ids.txt" 2>/dev/null || true
        fi
      }
    fi
  done
  shopt -u nullglob
  capture_docker_ps_ids \
    --filter "label=acgs.postgres.proof=$proof_label" \
    --filter "label=acgs.postgres.client=trusted-broker" || {
    rc=$?
    if [[ ! -e "$state_dir/recovery-container-ids.txt" ]]; then
      printf 'docker ps failed while verifying trusted broker client cleanup for proof label %s\n' \
        "$proof_label" >"$state_dir/recovery-container-ids.txt" 2>/dev/null || true
    fi
    return "$rc"
  }
  if [[ "${#DOCKER_PS_IDS[@]}" != 0 ]]; then
    if [[ ! -e "$state_dir/recovery-container-ids.txt" ]]; then
      printf '%s\n' "${DOCKER_PS_IDS[@]}" >"$state_dir/recovery-container-ids.txt" 2>/dev/null || true
    fi
    return 70
  fi
  [[ "$aggregate_rc" == 0 ]] || return "$aggregate_rc"
  return 0
}

remove_exact_recorded_container() {
  local container_ref=$1
  local expected_name=$2
  local expected_role=$3
  local inspect_output=''
  local inspected_id=''
  local inspected_name=''
  local inspected_proof_label=''
  local inspected_server_label=''
  local inspected_client_label=''
  local rc=0
  inspect_output="$(
    timeout --preserve-status 10s docker inspect \
      --format '{{.Id}}|{{.Name}}|{{index .Config.Labels "acgs.postgres.proof"}}|{{index .Config.Labels "acgs.postgres.server"}}|{{index .Config.Labels "acgs.postgres.client"}}' \
      "$container_ref"
  )" || {
    rc=$?
    [[ "$rc" == 1 ]] && return 1
    return "$rc"
  }
  IFS='|' read -r inspected_id inspected_name inspected_proof_label inspected_server_label inspected_client_label <<<"$inspect_output"
  [[ "$inspected_id" =~ ^[0-9a-f]{12,64}$ ]] || return 70
  [[ "$inspected_name" == "/$expected_name" ]] || return 70
  [[ "$inspected_proof_label" == "$proof_label" ]] || return 70
  case "$expected_role" in
    main)
      [[ "$inspected_server_label" == main ]] || return 70
      ;;
    trusted-broker)
      [[ "$inspected_client_label" == trusted-broker ]] || return 70
      ;;
    *)
      return 70
      ;;
  esac
  timeout --preserve-status 30s docker rm -f "$inspected_id" >/dev/null 2>&1 || return $?
  if timeout --preserve-status 10s docker inspect "$inspected_id" >/dev/null 2>&1; then
    return 70
  fi
  return 0
}

cleanup_server_container() {
  local cid_ref=''
  local name_ref=''
  local rc=0
  local aggregate_rc=0
  local removed_by_name=0
  if [[ -n "$container_id" ]]; then
    if [[ "$container_id" =~ ^[0-9a-f]{12,64}$ ]]; then
      remove_exact_recorded_container "$container_id" "$container_name" main || {
        rc=$?
        [[ "$rc" == 1 || "$aggregate_rc" != 0 ]] || aggregate_rc=$rc
      }
    else
      aggregate_rc=70
      if [[ ! -e "$state_dir/recovery-container-ids.txt" ]]; then
        printf 'invalid PostgreSQL server docker-run stdout: %s\n' "$container_id" \
          >"$state_dir/recovery-container-ids.txt" 2>/dev/null || true
      fi
    fi
  fi
  if [[ -e "$server_cidfile" ]]; then
    if cid_ref="$(read_private_container_file "$server_cidfile" cid)"; then
      if [[ "$cid_ref" != "$container_id" ]]; then
        remove_exact_recorded_container "$cid_ref" "$container_name" main || {
          rc=$?
          [[ "$rc" == 1 || "$aggregate_rc" != 0 ]] || aggregate_rc=$rc
        }
      fi
    else
      rc=$?
      [[ "$rc" == 1 ]] || {
        [[ "$aggregate_rc" == 0 ]] && aggregate_rc=$rc
        if [[ ! -e "$state_dir/recovery-container-ids.txt" ]]; then
          printf 'invalid PostgreSQL server cidfile: %s\n' "$server_cidfile" \
            >"$state_dir/recovery-container-ids.txt" 2>/dev/null || true
        fi
      }
    fi
  fi
  if [[ -e "$server_namefile" ]]; then
    if name_ref="$(read_private_container_file "$server_namefile" name)"; then
      remove_exact_recorded_container "$name_ref" "$container_name" main || {
        rc=$?
        [[ "$rc" == 1 || "$aggregate_rc" != 0 ]] || aggregate_rc=$rc
      }
      removed_by_name=1
    else
      rc=$?
      [[ "$rc" == 1 ]] || {
        [[ "$aggregate_rc" == 0 ]] && aggregate_rc=$rc
        if [[ ! -e "$state_dir/recovery-container-ids.txt" ]]; then
          printf 'invalid PostgreSQL server namefile: %s\n' "$server_namefile" \
            >"$state_dir/recovery-container-ids.txt" 2>/dev/null || true
        fi
      }
    fi
  fi
  [[ "$removed_by_name" == 0 || "$aggregate_rc" != 0 ]] || return 0
  [[ "$aggregate_rc" == 0 ]] || return "$aggregate_rc"
  return 0
}

verify_no_proof_labelled_containers() {
  local rc=0
  capture_docker_ps_ids --filter "label=acgs.postgres.proof=$proof_label" || {
    rc=$?
    if [[ ! -e "$state_dir/recovery-container-ids.txt" ]]; then
      printf 'docker ps failed while enumerating proof label %s\n' "$proof_label" \
        >"$state_dir/recovery-container-ids.txt" 2>/dev/null || true
    fi
    return "$rc"
  }
  if [[ "${#DOCKER_PS_IDS[@]}" -gt 0 ]]; then
    if [[ ! -e "$state_dir/recovery-container-ids.txt" ]]; then
      printf '%s\n' "${DOCKER_PS_IDS[@]}" >"$state_dir/recovery-container-ids.txt" 2>/dev/null || true
    fi
    return 70
  fi
  return 0
}

verify_stable_no_proof_labelled_containers() {
  for _ in {1..3}; do
    verify_no_proof_labelled_containers || return $?
    sleep 0.2
  done
}

cleanup_postgres_socket_bridge() {
  local expected_artifact_uid=$1
  /usr/bin/python3 -I -S - \
    "$postgres_recovery_root" "$postgres_socket_bridge_name" "$postgres_socket_bridge_identity" \
    "$postgres_socket_bridge_marker_sha256" "$postgres_socket_bridge_mnt_id" \
    "$postgres_recovery_root_mnt_id" "$expected_artifact_uid" <<'PY'
from __future__ import annotations

import hashlib
import os
import re
import stat
import sys

root, bridge_name, expected_identity, expected_marker_sha256, expected_mnt_id, expected_root_mnt_id, expected_artifact_uid_text = (
    sys.argv[1:8]
)
if not re.fullmatch(r"acp-postgres-gate-[0-9]+-[0-9a-f]{32}-socket-bridge", bridge_name):
    raise SystemExit(70)
if not re.fullmatch(r"[0-9]+:[0-9]+:[0-9]+:1777", expected_identity):
    raise SystemExit(70)
expected_stable_identity = expected_identity.rsplit(":", 1)[0]
if not re.fullmatch(r"[0-9a-f]{64}", expected_marker_sha256):
    raise SystemExit(70)
if not expected_mnt_id.isdigit():
    raise SystemExit(70)
if not expected_root_mnt_id.isdigit() or expected_mnt_id != expected_root_mnt_id:
    raise SystemExit(70)
if not re.fullmatch(r"[0-9]+", expected_artifact_uid_text):
    raise SystemExit(70)
expected_artifact_uid = int(expected_artifact_uid_text)
expected = {
    ".acgs-postgres-socket-bridge.v2": "marker",
    ".s.PGSQL.5432": "socket",
    ".s.PGSQL.5432.lock": "regular",
}


def mnt_id(fd: int) -> str:
    with open(f"/proc/self/fdinfo/{fd}", encoding="utf-8") as fdinfo:
        for line in fdinfo:
            if line.startswith("mnt_id:"):
                value = line.split(":", 1)[1].strip()
                if not value.isdigit():
                    raise SystemExit(70)
                return value
    raise SystemExit(70)


root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    root_stat = os.fstat(root_fd)
    if root_stat.st_uid != os.getuid() or stat.S_IMODE(root_stat.st_mode) != 0o700:
        raise SystemExit(70)
    if mnt_id(root_fd) != expected_root_mnt_id:
        raise SystemExit(70)
    dir_fd = os.open(
        bridge_name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=root_fd,
    )
    try:
        dir_stat = os.fstat(dir_fd)
        observed_stable_identity = f"{dir_stat.st_dev}:{dir_stat.st_ino}:{dir_stat.st_uid}"
        if observed_stable_identity != expected_stable_identity:
            raise SystemExit(70)
        if mnt_id(dir_fd) != expected_mnt_id:
            raise SystemExit(70)
        if dir_stat.st_uid != os.getuid() or stat.S_IMODE(dir_stat.st_mode) != 0o1777:
            raise SystemExit(70)
        names = os.listdir(dir_fd)
        if any(name not in expected for name in names):
            raise SystemExit(70)
        validated: list[tuple[str, os.stat_result]] = []
        for name in names:
            before = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            expected_kind = expected[name]
            if before.st_nlink != 1:
                raise SystemExit(70)
            if expected_kind == "marker":
                if not stat.S_ISREG(before.st_mode):
                    raise SystemExit(70)
                if before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) != 0o444:
                    raise SystemExit(70)
                marker_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=dir_fd,
                )
                try:
                    opened = os.fstat(marker_fd)
                    if (
                        opened.st_dev != before.st_dev
                        or opened.st_ino != before.st_ino
                        or opened.st_uid != before.st_uid
                        or opened.st_nlink != before.st_nlink
                        or stat.S_IMODE(opened.st_mode) != stat.S_IMODE(before.st_mode)
                    ):
                        raise SystemExit(70)
                    payload = os.read(marker_fd, 4096)
                    if hashlib.sha256(payload).hexdigest() != expected_marker_sha256:
                        raise SystemExit(70)
                    if opened.st_size != len(payload):
                        raise SystemExit(70)
                finally:
                    os.close(marker_fd)
            elif expected_kind == "socket":
                if before.st_uid != expected_artifact_uid or not stat.S_ISSOCK(before.st_mode):
                    raise SystemExit(70)
            elif expected_kind == "regular":
                if before.st_uid != expected_artifact_uid or not stat.S_ISREG(before.st_mode):
                    raise SystemExit(70)
                if before.st_mode & 0o022:
                    raise SystemExit(70)
            else:
                raise SystemExit(70)
            validated.append((name, before))
        os.fchmod(dir_fd, 0o700)
        hardened_stat = os.fstat(dir_fd)
        hardened_identity = (
            f"{hardened_stat.st_dev}:{hardened_stat.st_ino}:{hardened_stat.st_uid}"
        )
        if hardened_identity != expected_stable_identity:
            raise SystemExit(70)
        if hardened_stat.st_uid != os.getuid() or stat.S_IMODE(hardened_stat.st_mode) != 0o700:
            raise SystemExit(70)
        if mnt_id(dir_fd) != expected_mnt_id:
            raise SystemExit(70)
        for name, before in sorted(validated):
            current = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            if (
                current.st_dev != before.st_dev
                or current.st_ino != before.st_ino
                or current.st_uid != before.st_uid
                or current.st_nlink != before.st_nlink
                or current.st_size != before.st_size
                or stat.S_IFMT(current.st_mode) != stat.S_IFMT(before.st_mode)
                or stat.S_IMODE(current.st_mode) != stat.S_IMODE(before.st_mode)
            ):
                raise SystemExit(70)
            os.unlink(name, dir_fd=dir_fd)
        os.fsync(dir_fd)
        rebound_fd = os.open(
            bridge_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=root_fd,
        )
        try:
            rebound_stat = os.fstat(rebound_fd)
            rebound_identity = (
                f"{rebound_stat.st_dev}:{rebound_stat.st_ino}:{rebound_stat.st_uid}"
            )
            if (
                rebound_identity != expected_stable_identity
                or mnt_id(rebound_fd) != expected_root_mnt_id
            ):
                raise SystemExit(70)
        finally:
            os.close(rebound_fd)
        os.rmdir(bridge_name, dir_fd=root_fd)
        removed_stat = os.fstat(dir_fd)
        if removed_stat.st_nlink != 0:
            raise SystemExit(70)
        try:
            os.stat(bridge_name, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise SystemExit(70)
    finally:
        os.close(dir_fd)
    os.fsync(root_fd)
finally:
    os.close(root_fd)
PY
}

unlink_postgres_recovery_intents() {
  /usr/bin/python3 -I -S - \
    "$postgres_recovery_root" "$state_dir" "$proof_label" "$container_name" \
    "$server_cidfile" "$server_namefile" \
    "$postgres_socket_bridge_name" "$postgres_socket_bridge_identity" \
    "$postgres_socket_bridge_marker_sha256" "$postgres_socket_bridge_mnt_id" <<'PY'
from __future__ import annotations

import os
import re
import stat
import sys

(
    root,
    state_dir,
    proof_label,
    server_name,
    server_cidfile,
    server_namefile,
    bridge_basename,
    bridge_identity,
    bridge_marker_sha256,
    bridge_mnt_id,
) = (
    sys.argv[1:11]
)
if not re.fullmatch(r"acp-postgres-gate-[0-9]+-[0-9a-f]{32}", proof_label):
    raise SystemExit(70)
if server_name != f"{proof_label}-server":
    raise SystemExit(70)
if bridge_basename != f"{proof_label}-socket-bridge":
    raise SystemExit(70)
if not re.fullmatch(r"[0-9]+:[0-9]+:[0-9]+:1777", bridge_identity):
    raise SystemExit(70)
if not re.fullmatch(r"[0-9a-f]{64}", bridge_marker_sha256):
    raise SystemExit(70)
if not bridge_mnt_id.isdigit():
    raise SystemExit(70)
state_dir_real = os.path.realpath(state_dir)
if not os.path.isabs(state_dir_real):
    raise SystemExit(70)
expected_server_cidfile = os.path.realpath(server_cidfile)
expected_server_namefile = os.path.realpath(server_namefile)
if expected_server_cidfile != os.path.join(state_dir_real, "server.cid"):
    raise SystemExit(70)
if expected_server_namefile != os.path.join(state_dir_real, "server.name"):
    raise SystemExit(70)
expected_client_dir = os.path.join(state_dir_real, "client")


def parse_payload(raw: bytes) -> list[tuple[str, str]]:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        raise SystemExit(70)
    parsed: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in text.splitlines():
        if not line:
            continue
        if "=" not in line:
            raise SystemExit(70)
        key, value = line.split("=", 1)
        if key in seen:
            raise SystemExit(70)
        seen.add(key)
        parsed.append((key, value))
    return parsed


def assert_exact_payload(
    pairs: list[tuple[str, str]],
    expected_pairs: tuple[tuple[str, str], ...],
) -> None:
    if tuple(pairs) != expected_pairs:
        raise SystemExit(70)


def assert_expected_path(path: str, expected: str) -> None:
    if path != expected:
        raise SystemExit(70)
    if os.path.dirname(path) not in {state_dir_real, expected_client_dir}:
        raise SystemExit(70)
    if not os.path.basename(path):
        raise SystemExit(70)


def read_intent(root_fd: int, name: str) -> tuple[list[tuple[str, str]], os.stat_result]:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
    try:
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise SystemExit(70)
        if file_stat.st_uid != os.getuid() or file_stat.st_nlink != 1:
            raise SystemExit(70)
        if stat.S_IMODE(file_stat.st_mode) != 0o600:
            raise SystemExit(70)
        if file_stat.st_size > 8192:
            raise SystemExit(70)
        raw = os.read(fd, file_stat.st_size)
        if len(raw) != file_stat.st_size:
            raise SystemExit(70)
        return parse_payload(raw), file_stat
    finally:
        os.close(fd)


root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    root_stat = os.fstat(root_fd)
    if root_stat.st_uid != os.getuid() or stat.S_IMODE(root_stat.st_mode) != 0o700:
        raise SystemExit(70)
    names = sorted(name for name in os.listdir(root_fd) if name.startswith(f"{proof_label}-"))
    intent_names = [name for name in names if name.endswith(".intent")]
    if names != intent_names:
        raise SystemExit(70)
    server_intent_name = f"{proof_label}-server.intent"
    if server_intent_name not in intent_names:
        raise SystemExit(70)
    validated: list[tuple[str, os.stat_result]] = []
    for name in intent_names:
        payload, before = read_intent(root_fd, name)
        if name == server_intent_name:
            assert_expected_path(server_cidfile, expected_server_cidfile)
            assert_expected_path(server_namefile, expected_server_namefile)
            assert_exact_payload(
                payload,
                (
                    ("intent_version", "2"),
                    ("schema", "acgs-postgres-recovery-intent/server/v2"),
                    ("phase", "server-intent"),
                    ("proof_nonce", proof_label.rsplit("-", 1)[1]),
                    ("proof_label", proof_label),
                    ("server_name", server_name),
                    ("record_path", server_namefile),
                    ("server_cidfile", server_cidfile),
                    ("server_namefile", server_namefile),
                    ("socket_bridge_basename", bridge_basename),
                    ("socket_bridge_identity", bridge_identity),
                    ("socket_bridge_marker_sha256", bridge_marker_sha256),
                    ("socket_bridge_mnt_id", bridge_mnt_id),
                ),
            )
        else:
            client_pattern = (
                rf"{re.escape(proof_label)}-client-[0-9]+-[0-9]+\.intent"
            )
            if not re.fullmatch(client_pattern, name):
                raise SystemExit(70)
            client_name = name[:-7]
            client_cidfile = os.path.join(expected_client_dir, f"{client_name}.cid")
            client_namefile = os.path.join(expected_client_dir, f"{client_name}.name")
            assert_expected_path(client_cidfile, client_cidfile)
            assert_expected_path(client_namefile, client_namefile)
            assert_exact_payload(
                payload,
                (
                    ("intent_version", "1"),
                    ("phase", "client-intent"),
                    ("proof_nonce", proof_label.rsplit("-", 1)[1]),
                    ("proof_label", proof_label),
                    ("server_name", server_name),
                    ("client_name", client_name),
                    ("record_path", client_namefile),
                    ("client_cidfile", client_cidfile),
                    ("client_namefile", client_namefile),
                ),
            )
        validated.append((name, before))
    for name, before in validated:
        current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if (
            current.st_dev != before.st_dev
            or current.st_ino != before.st_ino
            or current.st_uid != before.st_uid
            or current.st_nlink != before.st_nlink
            or current.st_size != before.st_size
            or stat.S_IFMT(current.st_mode) != stat.S_IFMT(before.st_mode)
            or stat.S_IMODE(current.st_mode) != stat.S_IMODE(before.st_mode)
        ):
            raise SystemExit(70)
        os.unlink(name, dir_fd=root_fd)
    os.fsync(root_fd)
finally:
    os.close(root_fd)
PY
}

verify_docker_mounts() {
  local container_ref=$1
  local expected_json=$2
  local inspect_output=''
  inspect_output="$(
    timeout --preserve-status 10s docker inspect --format '{{json .Mounts}}' "$container_ref"
  )" || return $?
  /usr/bin/python3 -I -S - "$inspect_output" "$expected_json" <<'PY'
from __future__ import annotations

import json
import sys

raw_mounts, raw_expected = sys.argv[1:3]
try:
    mounts = json.loads(raw_mounts)
    expected = json.loads(raw_expected)
except json.JSONDecodeError:
    raise SystemExit(70)
if not isinstance(mounts, list) or not isinstance(expected, dict):
    raise SystemExit(70)
observed: dict[str, tuple[str, str, bool]] = {}
for mount in mounts:
    if not isinstance(mount, dict):
        raise SystemExit(70)
    destination = mount.get("Destination")
    source = mount.get("Source")
    rw = mount.get("RW")
    mount_type = mount.get("Type")
    if (
        not isinstance(destination, str)
        or not isinstance(source, str)
        or not isinstance(rw, bool)
        or not isinstance(mount_type, str)
    ):
        raise SystemExit(70)
    if destination in observed:
        raise SystemExit(70)
    observed[destination] = (mount_type, source, rw)
if set(observed) != set(expected):
    raise SystemExit(70)
for destination, fields in expected.items():
    if not isinstance(fields, dict):
        raise SystemExit(70)
    expected_type = fields.get("type")
    expected_source = fields.get("source")
    expected_rw = fields.get("rw")
    if (
        not isinstance(expected_type, str)
        or not isinstance(expected_source, str)
        or not isinstance(expected_rw, bool)
    ):
        raise SystemExit(70)
    if observed.get(destination) != (expected_type, expected_source, expected_rw):
        raise SystemExit(70)
PY
}

verify_server_socket_bridge_marker() {
  local inspect_name=$1
  timeout --preserve-status 10s docker exec "$inspect_name" sh -ec \
    "test -f /run/acgs-pg/.acgs-postgres-socket-bridge.v2 && test \"\$(sha256sum /run/acgs-pg/.acgs-postgres-socket-bridge.v2 | awk '{print \$1}')\" = '$postgres_socket_bridge_marker_sha256'" \
    >/dev/null
}

cleanup() {
  local status=$?
  local cleanup_status=0
  local cleanup_safe=1
  local rc=0
  trap '' INT TERM
  if [[ -n "$broker_pid" ]]; then
    if kill -0 "$broker_pid" >/dev/null 2>&1; then
      kill "$broker_pid" >/dev/null 2>&1 || cleanup_status=$?
      for _ in {1..100}; do
        kill -0 "$broker_pid" >/dev/null 2>&1 || break
        sleep 0.1
      done
      if kill -0 "$broker_pid" >/dev/null 2>&1; then
        kill -KILL "$broker_pid" >/dev/null 2>&1 || cleanup_status=$?
      fi
    fi
    wait "$broker_pid" >/dev/null 2>&1 || true
  fi
  [[ "$cleanup_status" == 0 ]] || cleanup_safe=0
  if [[ "$docker_started" == 1 ]]; then
    cleanup_client_containers || {
      rc=$?
      [[ "$cleanup_status" == 0 ]] && cleanup_status=$rc
      cleanup_safe=0
    }
    cleanup_server_container || {
      rc=$?
      [[ "$cleanup_status" == 0 ]] && cleanup_status=$rc
      cleanup_safe=0
    }
    verify_stable_no_proof_labelled_containers || {
      rc=$?
      [[ "$cleanup_status" == 0 ]] && cleanup_status=$rc
      cleanup_safe=0
    }
  fi
  if [[ "$cleanup_safe" == 1 && -n "$postgres_socket_bridge" ]]; then
    cleanup_postgres_socket_bridge 999 || {
      rc=$?
      [[ "$cleanup_status" == 0 ]] && cleanup_status=$rc
      cleanup_safe=0
    }
  fi
  if [[ "$cleanup_safe" == 1 && "$cleanup_status" == 0 ]]; then
    unlink_postgres_recovery_intents || {
      cleanup_status=$?
      cleanup_safe=0
    }
  fi
  if [[ "$cleanup_status" == 0 ]]; then
    rm -rf "$state_dir" || cleanup_status=$?
  else
    if ! write_recovery_contract "$cleanup_status" >/dev/null 2>&1; then
      printf 'PostgreSQL evidence gate failed to write terminal recovery contract at %s\n' \
        "$state_dir/recovery-contract.env" >&2
      trap - EXIT
      exit 70
    fi
    printf 'PostgreSQL evidence gate retained recovery state at %s\n' "$state_dir" >&2
  fi
  trap - EXIT
  if [[ "$status" == 0 && "$cleanup_status" != 0 ]]; then
    printf 'PostgreSQL evidence gate cleanup failed: %s\n' "$cleanup_status" >&2
    exit "$cleanup_status"
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cd "$package_dir"

timeout --preserve-status 30s docker image inspect "$postgres_image" >/dev/null 2>&1 || {
  echo 'the exact digest-pinned PostgreSQL image must already be cached locally' >&2
  exit 69
}
timeout --preserve-status 30s docker image inspect --format '{{json .RepoDigests}}' "$postgres_image" \
  | grep --fixed-strings "$postgres_digest" >/dev/null || {
  echo 'the cached PostgreSQL image does not expose the required repository digest' >&2
  exit 69
}

mkdir -p \
  "$state_dir/broker" "$state_dir/client" "$state_dir/home" "$state_dir/tmp" \
  "$state_dir/proof-scratch" "$state_dir/uv-cache" "$state_dir/acp-old" \
  "$state_dir/old-1" "$state_dir/old-2"
chmod 0700 \
  "$state_dir" "$state_dir/broker" "$state_dir/client" "$state_dir/home" \
  "$state_dir/tmp" "$state_dir/proof-scratch"
chmod 0700 "$state_dir/uv-cache"
postgres_socket_bridge_output="$(create_postgres_socket_bridge "$postgres_socket_bridge_name")" || {
  postgres_socket_bridge_creation_uncertain=1
  write_recovery_contract 70 >/dev/null 2>&1 || true
  echo 'failed to create descriptor-bound PostgreSQL socket bridge' >&2
  exit 70
}
mapfile -t postgres_socket_bridge_fields <<<"$postgres_socket_bridge_output"
unset postgres_socket_bridge_output
if [[ "${#postgres_socket_bridge_fields[@]}" != 5 ]]; then
  echo 'PostgreSQL socket bridge metadata is malformed' >&2
  exit 70
fi
for postgres_socket_bridge_field in "${postgres_socket_bridge_fields[@]}"; do
  [[ -n "$postgres_socket_bridge_field" ]] || {
    echo 'PostgreSQL socket bridge metadata is incomplete' >&2
    exit 70
  }
done
postgres_socket_bridge="${postgres_socket_bridge_fields[0]}"
postgres_socket_bridge_name="${postgres_socket_bridge_fields[1]}"
postgres_socket_bridge_identity="${postgres_socket_bridge_fields[2]}"
postgres_socket_bridge_marker_sha256="${postgres_socket_bridge_fields[3]}"
postgres_socket_bridge_mnt_id="${postgres_socket_bridge_fields[4]}"
verify_postgres_socket_bridge 1777 || {
  echo 'PostgreSQL socket bridge failed descriptor verification' >&2
  exit 70
}
write_postgres_recovery_intent server-intent server "$server_namefile" || {
  echo 'failed to persist PostgreSQL server recovery intent' >&2
  exit 70
}
write_private_container_name_file "$server_namefile" "$container_name" || {
  echo 'failed to record PostgreSQL server container name' >&2
  exit 70
}

docker_started=1
container_id="$(
  timeout --preserve-status 60s docker run -d \
    --pull=never \
    --network none \
    --name "$container_name" \
    --cidfile "$server_cidfile" \
    --label "acgs.postgres.server=main" \
    --label "acgs.postgres.proof=$proof_label" \
    --log-driver local \
    --log-opt max-size=1m \
    --log-opt max-file=2 \
    --memory 2g \
    --cpus 2 \
    --pids-limit 256 \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --read-only \
    --user 999:999 \
    --env "POSTGRES_DB=$main_database" \
    --env "POSTGRES_USER=$postgres_user" \
    --env "POSTGRES_PASSWORD=$postgres_password" \
    --env "POSTGRES_INITDB_ARGS=--auth-local=scram-sha-256 --auth-host=scram-sha-256" \
    --env PGHOST=/run/acgs-pg \
    --health-cmd "test -f /run/acgs-pg/.acgs-postgres-socket-bridge.v2 && test \"\$(sha256sum /run/acgs-pg/.acgs-postgres-socket-bridge.v2 | awk '{print \$1}')\" = '$postgres_socket_bridge_marker_sha256' && pg_isready -h /run/acgs-pg -U $postgres_user -d $main_database" \
    --health-interval 1s \
    --health-timeout 5s \
    --health-retries 60 \
    --security-opt label=disable \
    --mount "type=bind,src=$postgres_socket_bridge,dst=/run/acgs-pg" \
    --tmpfs /var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=2g,uid=999,gid=999,mode=700 \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=2g,mode=1777 \
    "$postgres_image" \
    postgres -c listen_addresses= -c unix_socket_directories=/run/acgs-pg \
      -c unix_socket_permissions=0777
)"
server_mount_expectation="$(
  printf '{"%s":{"type":"bind","source":%s,"rw":true},"%s":{"type":"tmpfs","source":"","rw":true},"%s":{"type":"tmpfs","source":"","rw":true}}' \
    "/run/acgs-pg" \
    "$(printf '%s' "$postgres_socket_bridge" | /usr/bin/python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')" \
    "/var/lib/postgresql/data" \
    "/tmp"
)"
verify_docker_mounts "$container_id" "$server_mount_expectation" || {
  echo 'PostgreSQL server socket bridge mount did not match expected descriptor source' >&2
  exit 70
}
verify_server_socket_bridge_marker "$container_id" || {
  echo 'PostgreSQL server socket bridge marker was not visible through mounted path' >&2
  exit 70
}

for _ in {1..90}; do
  container_status="$(timeout --preserve-status 10s docker inspect --format '{{.State.Status}}' "$container_id")"
  health_status="$(timeout --preserve-status 10s docker inspect --format '{{.State.Health.Status}}' "$container_id")"
  if [[ "$container_status" != 'running' ]]; then
    echo 'the disposable PostgreSQL container exited before becoming healthy' >&2
    exit 70
  fi
  if [[ "$health_status" == 'healthy' ]]; then
    break
  fi
  if [[ "$health_status" == 'unhealthy' ]]; then
    echo 'the disposable PostgreSQL container became unhealthy' >&2
    exit 70
  fi
  sleep 1
done
if [[ "$(timeout --preserve-status 10s docker inspect --format '{{.State.Health.Status}}' "$container_id")" != 'healthy' ]]; then
  echo 'timed out waiting for the disposable PostgreSQL container to become healthy' >&2
  exit 70
fi

if [[ ! -S "$postgres_socket_bridge/.s.PGSQL.5432" ]]; then
  echo 'timed out waiting for PostgreSQL Unix socket' >&2
  exit 70
fi

broker_script="$state_dir/broker/postgres_client_broker.py"
write_verified_private_artifact "$state_dir/broker" "postgres_client_broker.py" 0700 <<'PY'
from __future__ import annotations

import json
import hashlib
import os
import re
import selectors
import shlex
import signal
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

SOCKET_PATH = Path(sys.argv[1])
STATE_DIR = Path(sys.argv[2]).resolve(strict=True)
SOCKET_DIR = SOCKET_PATH.parent.resolve(strict=True)
SOCKET_NAME = SOCKET_PATH.name
IMAGE = "postgres:17.10-bookworm@sha256:4f736ae292687621d4dbe0d499ffd024a36bd2ee7d8ca6f2ccd4c800f047b394"
DOCKER_BIN = Path(os.environ["ACP_POSTGRES_CLIENT_BROKER_DOCKER"])
PROOF_LABEL = os.environ["ACP_POSTGRES_CLIENT_PROOF_LABEL"]
PROOF_NONCE = os.environ["ACP_POSTGRES_CLIENT_PROOF_NONCE"]
SERVER_NAME = os.environ["ACP_POSTGRES_SERVER_NAME"]
RECOVERY_ROOT = Path(os.environ["ACGS_POSTGRES_RECOVERY_ROOT"])
PG_SOCKET_BRIDGE = Path(os.environ["ACP_POSTGRES_SOCKET_BRIDGE"])
PG_SOCKET_BRIDGE_IDENTITY = os.environ["ACP_POSTGRES_SOCKET_BRIDGE_IDENTITY"]
PG_SOCKET_BRIDGE_MARKER_SHA256 = os.environ["ACP_POSTGRES_SOCKET_BRIDGE_MARKER_SHA256"]
PG_SOCKET_BRIDGE_MNT_ID = os.environ["ACP_POSTGRES_SOCKET_BRIDGE_MNT_ID"]
PG_RECOVERY_ROOT_MNT_ID = os.environ["ACP_POSTGRES_RECOVERY_ROOT_MNT_ID"]
ALLOWED_TOOLS = {"psql", "pg_dump", "pg_restore"}
PINNED_PGHOST = "/run/acgs-pg"
PINNED_PGPORT = "5432"
HOST_TMP = STATE_DIR / "tmp"
HOST_PROOF_SCRATCH = STATE_DIR / "proof-scratch"
SANDBOX_RW_ROOTS = {
    Path("/run/tmp"): HOST_TMP.resolve(strict=True),
    Path("/proof-scratch"): HOST_PROOF_SCRATCH.resolve(strict=True),
}
ALLOWED_ENV = {
    "PGHOST", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE", "PGPASSFILE",
    "PGCONNECT_TIMEOUT", "PGOPTIONS", "PGSSLMODE", "PGSSLROOTCERT", "PGSSLCERT",
    "PGSSLKEY", "PGAPPNAME", "LANG", "LC_ALL", "LC_CTYPE",
}
FORBIDDEN_ENDPOINT_ENV = {"PGHOSTADDR", "PGSERVICE", "PGSERVICEFILE"}
FORBIDDEN_CONNINFO_KEYS = {"host", "hostaddr", "port", "service", "servicefile"}
MAX_REQUEST_BYTES = 131_072
MAX_COMBINED_OUTPUT_BYTES = 2_097_152
MAX_RESPONSE_BYTES = 16_777_216
BROKER_SOCKET_TIMEOUT_SECONDS = 15
BROKER_DOCKER_TIMEOUT_SECONDS = 120
REQUESTS = 0
ALLOWED_RW_ROOTS = tuple(SANDBOX_RW_ROOTS)
ALLOWED_RO_ROOTS = tuple(SANDBOX_RW_ROOTS)


def fail(message: str, code: int = 64) -> None:
    raise ValueError(f"{code}:{message}")


if not DOCKER_BIN.is_absolute() or DOCKER_BIN.is_symlink() or not os.access(DOCKER_BIN, os.X_OK):
    fail("broker docker client must be an absolute executable non-symlink", 69)
if DOCKER_BIN.resolve(strict=True) != DOCKER_BIN:
    fail("broker docker client must already be canonical", 69)
if not RECOVERY_ROOT.is_absolute() or RECOVERY_ROOT.is_symlink():
    fail("broker recovery root must be absolute non-symlink", 70)
RECOVERY_ROOT_STAT = RECOVERY_ROOT.stat()
if RECOVERY_ROOT_STAT.st_uid != os.getuid() or RECOVERY_ROOT_STAT.st_mode & 0o077:
    fail("broker recovery root must be owner-only", 70)
if not PG_SOCKET_BRIDGE.is_absolute() or PG_SOCKET_BRIDGE.is_symlink():
    fail("PostgreSQL socket bridge must be absolute non-symlink", 70)
if PG_SOCKET_BRIDGE.parent.resolve(strict=True) != RECOVERY_ROOT.resolve(strict=True):
    fail("PostgreSQL socket bridge must live under the recovery root", 70)
if not re.fullmatch(r"[0-9]+:[0-9]+:[0-9]+:1777", PG_SOCKET_BRIDGE_IDENTITY):
    fail("PostgreSQL socket bridge identity is malformed", 70)
if not re.fullmatch(r"[0-9a-f]{64}", PG_SOCKET_BRIDGE_MARKER_SHA256):
    fail("PostgreSQL socket bridge marker digest is malformed", 70)
if not PG_SOCKET_BRIDGE_MNT_ID.isdigit():
    fail("PostgreSQL socket bridge mount id is malformed", 70)
if not PG_RECOVERY_ROOT_MNT_ID.isdigit() or PG_RECOVERY_ROOT_MNT_ID != PG_SOCKET_BRIDGE_MNT_ID:
    fail("PostgreSQL socket bridge root mount id is malformed", 70)


def fd_mnt_id(fd: int) -> str:
    with open(f"/proc/self/fdinfo/{fd}", encoding="utf-8") as fdinfo:
        for line in fdinfo:
            if line.startswith("mnt_id:"):
                value = line.split(":", 1)[1].strip()
                if not value.isdigit():
                    fail("PostgreSQL socket bridge mount id is unsafe", 70)
                return value
    fail("PostgreSQL socket bridge mount id is missing", 70)


def validate_socket_bridge() -> None:
    root_fd = os.open(RECOVERY_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        root_stat = os.fstat(root_fd)
        if root_stat.st_uid != os.getuid() or stat.S_IMODE(root_stat.st_mode) != 0o700:
            fail("PostgreSQL socket bridge recovery root is unsafe", 70)
        if fd_mnt_id(root_fd) != PG_RECOVERY_ROOT_MNT_ID:
            fail("PostgreSQL socket bridge recovery root mount id changed", 70)
        bridge_fd = os.open(
            PG_SOCKET_BRIDGE.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=root_fd,
        )
        try:
            bridge_stat = os.fstat(bridge_fd)
            observed_identity = (
                f"{bridge_stat.st_dev}:{bridge_stat.st_ino}:{bridge_stat.st_uid}"
            )
            expected_identity = PG_SOCKET_BRIDGE_IDENTITY.rsplit(":", 1)[0]
            if observed_identity != expected_identity:
                fail("PostgreSQL socket bridge identity changed", 70)
            if bridge_stat.st_uid != os.getuid() or stat.S_IMODE(bridge_stat.st_mode) != 0o1777:
                fail("PostgreSQL socket bridge mode is unsafe", 70)
            if fd_mnt_id(bridge_fd) != PG_SOCKET_BRIDGE_MNT_ID:
                fail("PostgreSQL socket bridge mount id changed", 70)
            marker_fd = os.open(
                ".acgs-postgres-socket-bridge.v2",
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=bridge_fd,
            )
            try:
                marker_stat = os.fstat(marker_fd)
                if not stat.S_ISREG(marker_stat.st_mode):
                    fail("PostgreSQL socket bridge marker is not regular", 70)
                if marker_stat.st_uid != os.getuid() or marker_stat.st_nlink != 1:
                    fail("PostgreSQL socket bridge marker identity is unsafe", 70)
                if stat.S_IMODE(marker_stat.st_mode) != 0o444:
                    fail("PostgreSQL socket bridge marker mode is unsafe", 70)
                marker_payload = os.read(marker_fd, 4096)
                if hashlib.sha256(marker_payload).hexdigest() != PG_SOCKET_BRIDGE_MARKER_SHA256:
                    fail("PostgreSQL socket bridge marker digest changed", 70)
            finally:
                os.close(marker_fd)
        finally:
            os.close(bridge_fd)
    finally:
        os.close(root_fd)


def inspect_exact_docker_mounts(docker_args: list[str]) -> None:
    expected = {
        "/run/acgs-pg": ("bind", str(PG_SOCKET_BRIDGE), False),
        "/run/tmp": ("bind", str(HOST_TMP), True),
        "/proof-scratch": ("bind", str(HOST_PROOF_SCRATCH), True),
        "/tmp": ("tmpfs", "", True),
    }
    observed: dict[str, tuple[str, str, bool]] = {}
    index = 0
    while index < len(docker_args):
        item = docker_args[index]
        if item == "--mount":
            if index + 1 >= len(docker_args):
                fail("PostgreSQL client broker Docker mount is malformed", 70)
            raw_parts = docker_args[index + 1].split(",")
            parts = dict(part.split("=", 1) for part in raw_parts if "=" in part)
            source = parts.get("src")
            target = parts.get("dst")
            readonly = "readonly" in raw_parts
            if parts.get("type") != "bind" or not source or not target:
                fail("PostgreSQL client broker Docker mount is malformed", 70)
            if target in observed:
                fail("PostgreSQL client broker Docker mount is duplicated", 70)
            observed[target] = ("bind", source, not readonly)
            index += 2
            continue
        if item == "--volume":
            fail("PostgreSQL client broker forbids volume syntax drift", 70)
        if item == "--tmpfs":
            if index + 1 >= len(docker_args):
                fail("PostgreSQL client broker Docker tmpfs is malformed", 70)
            target = docker_args[index + 1].split(":", 1)[0]
            if target in observed:
                fail("PostgreSQL client broker Docker mount is duplicated", 70)
            observed[target] = ("tmpfs", "", True)
            index += 2
            continue
        index += 1
    if observed != expected:
        fail("PostgreSQL client broker Docker mounts changed", 70)
    if any(source == str(STATE_DIR) for _type, source, _mode in observed.values()):
        fail("PostgreSQL client broker must not bind the whole state directory", 70)


def inspect_actual_docker_mounts(container_ref: str) -> bool:
    try:
        completed = subprocess.run(
            [str(DOCKER_BIN), "inspect", "--format", "{{json .Mounts}}", container_ref],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        fail("PostgreSQL client broker mount inspection is uncertain", 70)
    if completed.returncode != 0:
        return False
    try:
        mounts = json.loads(completed.stdout.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        fail("PostgreSQL client broker mount inspection is malformed", 70)
    expected = {
        "/run/acgs-pg": ("bind", str(PG_SOCKET_BRIDGE), False),
        "/run/tmp": ("bind", str(HOST_TMP), True),
        "/proof-scratch": ("bind", str(HOST_PROOF_SCRATCH), True),
        "/tmp": ("tmpfs", "", True),
    }
    observed: dict[str, tuple[str, str, bool]] = {}
    if not isinstance(mounts, list):
        fail("PostgreSQL client broker mount inspection is malformed", 70)
    for mount in mounts:
        if not isinstance(mount, dict):
            fail("PostgreSQL client broker mount inspection is malformed", 70)
        destination = mount.get("Destination")
        source = mount.get("Source")
        rw = mount.get("RW")
        mount_type = mount.get("Type")
        if (
            not isinstance(destination, str)
            or not isinstance(source, str)
            or not isinstance(rw, bool)
            or not isinstance(mount_type, str)
        ):
            fail("PostgreSQL client broker mount inspection is malformed", 70)
        if destination in observed:
            fail("PostgreSQL client broker actual Docker mount is duplicated", 70)
        observed[destination] = (mount_type, source, rw)
    if set(observed) != set(expected):
        fail("PostgreSQL client broker actual Docker mounts changed", 70)
    for destination, expected_value in expected.items():
        if observed.get(destination) != expected_value:
            fail("PostgreSQL client broker actual Docker mounts changed", 70)
    return True


def wait_for_actual_docker_mounts(container_ref: str) -> None:
    for _attempt in range(25):
        if inspect_actual_docker_mounts(container_ref):
            return
        time.sleep(0.1)
    fail("PostgreSQL client broker mount inspection is uncertain", 70)


def validate_string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        fail(f"{label} must be a string list")
    if any("\0" in item for item in value):
        fail(f"{label} contains a NUL byte")
    return value


def reject_endpoint_override_args(tool: str, args: list[str]) -> None:
    def reject_conninfo(value: str) -> None:
        if re.search(r"\b(?:postgresql|postgres)://", value):
            fail("PostgreSQL client broker endpoint is pinned")
        pattern = r"(^|\s)(" + "|".join(sorted(FORBIDDEN_CONNINFO_KEYS)) + r")\s*="
        if re.search(pattern, value, flags=re.IGNORECASE):
            fail("PostgreSQL client broker endpoint is pinned")

    def validate_psql_sql(value: str) -> None:
        if "\\" in value:
            fail("PostgreSQL client broker psql reconnect paths are disabled")
        if re.search(r":(?:[A-Za-z_][A-Za-z0-9_]*|'[^']*'|\"[^\"]*\")", value):
            fail("PostgreSQL client broker psql variable interpolation is disabled")

    def validate_psql_allowlist() -> None:
        if args == ["--version"]:
            return
        index = 0
        saw_command = False
        while index < len(args):
            argument = args[index]
            if argument == "--set":
                if index + 1 >= len(args) or args[index + 1] != "ON_ERROR_STOP=1":
                    fail("PostgreSQL client broker psql argv is not allowed")
                index += 2
                continue
            if argument == "--set=ON_ERROR_STOP=1":
                index += 1
                continue
            if argument == "--command":
                if index + 1 >= len(args):
                    fail("PostgreSQL client broker psql argv is not allowed")
                validate_psql_sql(args[index + 1])
                saw_command = True
                index += 2
                continue
            if argument in {"--tuples-only", "--no-align"}:
                index += 1
                continue
            fail("PostgreSQL client broker psql argv is not allowed")
        if not saw_command:
            fail("PostgreSQL client broker psql argv is not allowed")

    if tool == "psql":
        validate_psql_allowlist()
        return

    def reject_long_option(argument: str, next_argument: str | None) -> None:
        option = argument.split("=", 1)[0]
        if option.startswith("--"):
            name = option[2:]
            if name and ("host".startswith(name) or "port".startswith(name)):
                fail("PostgreSQL client broker endpoint is pinned")
            if name and "dbname".startswith(name):
                if "=" in argument:
                    reject_conninfo(argument.split("=", 1)[1])
                elif next_argument is None:
                    fail("PostgreSQL client broker endpoint is pinned")
                else:
                    reject_conninfo(next_argument)

    index = 0
    while index < len(args):
        argument = args[index]
        if argument.startswith("--"):
            reject_long_option(
                argument,
                args[index + 1] if index + 1 < len(args) else None,
            )
        elif argument.startswith("-") and argument != "-":
            cluster = argument[1:]
            if "h" in cluster or "p" in cluster:
                fail("PostgreSQL client broker endpoint is pinned")
            if "d" in cluster:
                dbname_index = cluster.index("d")
                attached_value = cluster[dbname_index + 1 :]
                if attached_value:
                    reject_conninfo(attached_value)
                elif index + 1 >= len(args):
                    fail("PostgreSQL client broker endpoint is pinned")
                else:
                    reject_conninfo(args[index + 1])
        if argument in {"-d", "--dbname"}:
            if index + 1 >= len(args):
                fail("PostgreSQL client broker endpoint is pinned")
            reject_conninfo(args[index + 1])
        if argument.startswith("--dbname="):
            reject_conninfo(argument.split("=", 1)[1])
        reject_conninfo(argument)
        endpoint_key_pattern = "|".join(sorted(FORBIDDEN_CONNINFO_KEYS))
        if re.fullmatch(rf"(?:{endpoint_key_pattern})\s*=.*", argument, re.IGNORECASE):
            fail("PostgreSQL client broker endpoint is pinned")
        try:
            for field in shlex.split(argument):
                reject_conninfo(field)
        except ValueError:
            fail("PostgreSQL client broker endpoint is pinned")
        index += 1


def is_under(path: Path, roots: tuple[Path, ...]) -> bool:
    return any(path == root or root in path.parents for root in roots)


def translate_sandbox_path(path: Path, roots: tuple[Path, ...], label: str) -> tuple[Path, Path]:
    if not path.is_absolute():
        fail(f"{label} path must be absolute")
    matching_root = next((root for root in roots if path == root or root in path.parents), None)
    if matching_root is None:
        fail(f"{label} path is outside broker-owned roots")
    relative = path.relative_to(matching_root)
    host_path = SANDBOX_RW_ROOTS[matching_root] / relative
    return matching_root, host_path


def require_safe_owned_directory(path: Path, roots: tuple[Path, ...], label: str) -> Path:
    sandbox_root, host_path = translate_sandbox_path(path, roots, label)
    try:
        resolved = host_path.resolve(strict=True)
    except OSError as exc:
        fail(f"{label} path resolution failed: {exc}", 65)
    if not resolved.is_dir():
        fail(f"{label} parent must be a directory")
    host_root = SANDBOX_RW_ROOTS[sandbox_root]
    if not (resolved == host_root or host_root in resolved.parents):
        fail(f"{label} path is outside broker-owned roots")
    fd = os.open(resolved, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        stat_result = os.fstat(fd)
        if stat_result.st_uid != os.getuid():
            fail(f"{label} parent is not owned by the broker user")
        if stat_result.st_mode & 0o022:
            fail(f"{label} parent is group/world writable")
        descriptor_path = Path(f"/proc/self/fd/{fd}").resolve(strict=True)
        if descriptor_path != resolved:
            fail(f"{label} parent changed during validation", 65)
    finally:
        os.close(fd)
    return sandbox_root


def add_read_path(paths: dict[str, str], candidate: str, label: str) -> None:
    path = Path(candidate)
    sandbox_root, host_path = translate_sandbox_path(path, ALLOWED_RO_ROOTS, label)
    try:
        resolved = host_path.resolve(strict=True)
    except OSError as exc:
        fail(f"{label} path resolution failed: {exc}", 65)
    host_root = SANDBOX_RW_ROOTS[sandbox_root]
    if not (resolved == host_root or host_root in resolved.parents):
        fail(f"{label} path is outside broker-owned roots")
    if host_path.is_symlink():
        fail(f"{label} path must not be a symlink")
    stat_result = resolved.stat()
    if stat_result.st_uid != os.getuid():
        fail(f"{label} path is not owned by the broker user")
    paths[str(sandbox_root)] = "ro"


def add_write_file(paths: dict[str, str], candidate: str) -> None:
    path = Path(candidate)
    sandbox_root, host_path = translate_sandbox_path(path, ALLOWED_RW_ROOTS, "--file")
    require_safe_owned_directory(path.parent, ALLOWED_RW_ROOTS, "--file")
    try:
        existing = host_path.resolve(strict=True)
    except FileNotFoundError:
        existing = host_path
    except OSError as exc:
        fail(f"--file path resolution failed: {exc}", 65)
    else:
        host_root = SANDBOX_RW_ROOTS[sandbox_root]
        if not (existing == host_root or host_root in existing.parents):
            fail("--file path is outside broker-owned roots")
        if host_path.is_symlink():
            fail("--file path must not be a symlink")
        if existing.stat().st_uid != os.getuid():
            fail("--file path is not owned by the broker user")
    paths[str(sandbox_root)] = "rw"


def write_client_recovery_intent(client_name: str, cidfile: Path, namefile: Path) -> None:
    if not re.fullmatch(r"acp-postgres-gate-[0-9]+-[0-9a-f]{32}-client-[0-9]+-[0-9]+", client_name):
        fail("client recovery intent name is unsafe", 70)
    if not re.fullmatch(r"[0-9a-f]{32}", PROOF_NONCE):
        fail("client recovery intent nonce is unsafe", 70)
    if SERVER_NAME != f"{PROOF_LABEL}-server":
        fail("client recovery intent server name is unsafe", 70)
    root_fd = os.open(RECOVERY_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        root_stat = os.fstat(root_fd)
        if root_stat.st_uid != os.getuid() or root_stat.st_mode & 0o077:
            fail("client recovery root identity is unsafe", 70)
        payload = "\n".join(
            (
                "intent_version=1",
                "phase=client-intent",
                f"proof_nonce={PROOF_NONCE}",
                f"proof_label={PROOF_LABEL}",
                f"server_name={SERVER_NAME}",
                f"client_name={client_name}",
                f"record_path={namefile}",
                f"client_cidfile={cidfile}",
                f"client_namefile={namefile}",
                "",
            )
        ).encode("ascii")
        fd = os.open(
            f"{client_name}.intent",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=root_fd,
        )
        try:
            file_stat = os.fstat(fd)
            if not stat.S_ISREG(file_stat.st_mode):
                fail("client recovery intent is not regular", 70)
            if file_stat.st_uid != os.getuid() or file_stat.st_nlink != 1:
                fail("client recovery intent identity is unsafe", 70)
            if file_stat.st_mode & 0o777 != 0o600:
                fail("client recovery intent mode is unsafe", 70)
            written = os.write(fd, payload)
            if written != len(payload):
                fail("client recovery intent short write", 70)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(root_fd)
    finally:
        os.close(root_fd)
    parent_fd = os.open(RECOVERY_ROOT.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def execute(request: dict[str, object]) -> tuple[int, bytes, bytes]:
    global REQUESTS
    REQUESTS += 1
    if REQUESTS > 500:
        fail("client broker request limit exceeded", 70)
    tool = request.get("tool")
    if tool not in ALLOWED_TOOLS:
        fail("unsupported PostgreSQL client tool")
    args = validate_string_list(request.get("argv"), "argv")
    env = request.get("env")
    if not isinstance(env, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in env.items()):
        fail("env must be a string map")
    if set(env) & FORBIDDEN_ENDPOINT_ENV:
        fail("PostgreSQL client broker endpoint is pinned")
    unknown_env = set(env) - ALLOWED_ENV
    if unknown_env:
        fail("unsupported PostgreSQL client env: " + ",".join(sorted(unknown_env)))
    if env.get("PGHOST", PINNED_PGHOST) != PINNED_PGHOST:
        fail("PostgreSQL client broker endpoint is pinned")
    if env.get("PGPORT", PINNED_PGPORT) != PINNED_PGPORT:
        fail("PostgreSQL client broker endpoint is pinned")
    env = {**env, "PGHOST": PINNED_PGHOST, "PGPORT": PINNED_PGPORT}
    reject_endpoint_override_args(tool, args)
    docker_cli_env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(STATE_DIR / "home"),
    }
    docker_cli_env.update(env)
    paths: dict[str, str] = {}
    for variable in ("PGPASSFILE", "PGSSLROOTCERT", "PGSSLCERT", "PGSSLKEY"):
        if env.get(variable):
            add_read_path(paths, env[variable], variable)
    for argument in args:
        if argument.startswith("--file="):
            add_write_file(paths, argument.split("=", 1)[1])
        elif argument.startswith("/"):
            add_read_path(paths, argument, "argument")
    client_name = f"{PROOF_LABEL}-client-{os.getpid()}-{REQUESTS}"
    cidfile = STATE_DIR / "client" / f"{client_name}.cid"
    namefile = STATE_DIR / "client" / f"{client_name}.name"
    name_fd = os.open(
        namefile,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        name_stat = os.fstat(name_fd)
        if not stat.S_ISREG(name_stat.st_mode):
            fail("client broker name record is not regular", 70)
        if name_stat.st_uid != os.getuid() or name_stat.st_nlink != 1:
            fail("client broker name record identity is unsafe", 70)
        if name_stat.st_mode & 0o777 != 0o600:
            fail("client broker name record mode is unsafe", 70)
        name_payload = client_name.encode("ascii") + b"\n"
        written = os.write(name_fd, name_payload)
        if written != len(name_payload):
            fail("client broker name record short write", 70)
        os.fsync(name_fd)
    finally:
        os.close(name_fd)
    client_dir_fd = os.open(STATE_DIR / "client", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(client_dir_fd)
    finally:
        os.close(client_dir_fd)
    write_client_recovery_intent(client_name, cidfile, namefile)

    docker_args = [
        str(DOCKER_BIN), "create", "--pull=never", "--network", "none",
        "--name", client_name,
        "--cidfile", str(cidfile),
        "--label", "acgs.postgres.client=trusted-broker",
        "--label", f"acgs.postgres.proof={PROOF_LABEL}",
        "--log-driver", "local", "--log-opt", "max-size=1m", "--log-opt", "max-file=2",
        "--memory", "512m", "--cpus", "1", "--pids-limit", "128",
        "--ulimit", "nofile=256:256",
        "--ulimit", f"fsize={MAX_COMBINED_OUTPUT_BYTES}:{MAX_COMBINED_OUTPUT_BYTES}",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--security-opt", "label=disable", "--user", f"{os.getuid()}:{os.getgid()}",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,mode=1777,size=512m",
        "--mount", f"type=bind,src={PG_SOCKET_BRIDGE},dst=/run/acgs-pg,readonly",
        "--mount", f"type=bind,src={HOST_TMP},dst=/run/tmp",
        "--mount", f"type=bind,src={HOST_PROOF_SCRATCH},dst=/proof-scratch",
    ]
    for key in sorted(env):
        docker_args.extend(["--env", key])
    marker_wrapper = (
        "marker=/run/acgs-pg/.acgs-postgres-socket-bridge.v2; "
        "test -f \"$marker\" && test ! -L \"$marker\" || exit 70; "
        f"test \"$(stat -c '%u:%h:%a' \"$marker\")\" = \"{os.getuid()}:1:444\" || exit 70; "
        f"test \"$(sha256sum \"$marker\" | awk '{{print $1}}')\" = \"{PG_SOCKET_BRIDGE_MARKER_SHA256}\" || exit 70; "
        "exec \"$@\""
    )
    docker_create_args = [
        *docker_args,
        IMAGE,
        "sh",
        "-ec",
        marker_wrapper,
        "acgs-client-marker-wrapper",
        tool,
        *args,
    ]
    validate_socket_bridge()
    inspect_exact_docker_mounts(docker_args)
    del paths
    combined = bytearray()
    timed_out = False
    overflow = False
    process: subprocess.Popen[bytes] | None = None
    created_container_ref: str | None = None

    def read_record(path: Path, pattern: str) -> str | None:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            return None
        try:
            record_stat = os.fstat(fd)
            if not stat.S_ISREG(record_stat.st_mode):
                return None
            if record_stat.st_uid != os.getuid() or record_stat.st_nlink != 1:
                return None
            if record_stat.st_mode & 0o777 != 0o600:
                return None
            raw = os.read(fd, 512)
        finally:
            os.close(fd)
        try:
            text = raw.decode("ascii").strip()
        except UnicodeDecodeError:
            return None
        if "\n" in text or not re.fullmatch(pattern, text):
            return None
        return text

    def candidate_refs() -> list[str]:
        refs: list[str] = []
        cid = read_record(cidfile, r"[0-9a-f]{12,64}")
        if cid:
            refs.append(cid)
        recorded_name = read_record(
            namefile,
            r"acp-postgres-gate-[0-9]+-[0-9a-f]{32}-client-[0-9]+-[0-9]+",
        )
        if recorded_name and recorded_name not in refs:
            refs.append(recorded_name)
        if client_name not in refs:
            refs.append(client_name)
        return refs

    def inspect_ref(ref: str) -> tuple[str, str, str, str, str] | None:
        try:
            completed = subprocess.run(
                [
                    str(DOCKER_BIN), "inspect",
                    "--format",
                    '{{.Id}}|{{.Name}}|{{index .Config.Labels "acgs.postgres.proof"}}|{{index .Config.Labels "acgs.postgres.server"}}|{{index .Config.Labels "acgs.postgres.client"}}',
                    ref,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError):
            fail("PostgreSQL client broker container inspection is uncertain", 70)
        if completed.returncode == 1:
            return None
        if completed.returncode != 0:
            fail("PostgreSQL client broker container inspection is uncertain", 70)
        fields = completed.stdout.decode("ascii", "strict").strip().split("|")
        if len(fields) != 5:
            fail("PostgreSQL client broker container inspection is malformed", 70)
        return tuple(fields)  # type: ignore[return-value]

    def is_expected_client(inspected: tuple[str, str, str, str, str]) -> bool:
        container_id, name, proof_label, server_role, client_role = inspected
        return (
            re.fullmatch(r"[0-9a-f]{12,64}", container_id) is not None
            and name == f"/{client_name}"
            and proof_label == PROOF_LABEL
            and server_role == ""
            and client_role == "trusted-broker"
        )

    def client_exists() -> bool:
        for ref in candidate_refs():
            inspected = inspect_ref(ref)
            if inspected is not None and is_expected_client(inspected):
                return True
        return False

    def kill_client() -> bool:
        for ref in candidate_refs():
            inspected = inspect_ref(ref)
            if inspected is None or not is_expected_client(inspected):
                continue
            container_id = inspected[0]
            try:
                completed = subprocess.run(
                    [str(DOCKER_BIN), "rm", "-f", container_id],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=15,
                )
            except (OSError, subprocess.SubprocessError):
                return False
            if completed.returncode != 0:
                return False
        return not client_exists()

    try:
        created = subprocess.run(
            docker_create_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=20,
            env=docker_cli_env,
        )
        if created.returncode != 0:
            return created.returncode, created.stdout, b""
        try:
            created_container_ref = created.stdout.decode("ascii", "strict").strip()
        except UnicodeDecodeError:
            fail("PostgreSQL client broker Docker create output is malformed", 70)
        if "\n" in created_container_ref or not re.fullmatch(
            r"[0-9a-f]{12,64}", created_container_ref
        ):
            fail("PostgreSQL client broker Docker create output is malformed", 70)
        wait_for_actual_docker_mounts(created_container_ref)
        validate_socket_bridge()
        process = subprocess.Popen(
            [str(DOCKER_BIN), "start", "-a", created_container_ref],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env={"PATH": "/usr/bin:/bin", "HOME": str(STATE_DIR / "home")},
        )
        assert process.stdout is not None
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + BROKER_DOCKER_TIMEOUT_SECONDS
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                if not kill_client():
                    fail("PostgreSQL client broker container cleanup is uncertain", 70)
                break
            events = selector.select(min(0.2, remaining))
            for key, _mask in events:
                chunk = key.fileobj.read1(65_536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    break
                combined.extend(chunk)
                if len(combined) > MAX_COMBINED_OUTPUT_BYTES:
                    overflow = True
                    if not kill_client():
                        fail("PostgreSQL client broker container cleanup is uncertain", 70)
                    break
            if overflow:
                break
            if not selector.get_map():
                break
            if process.poll() is not None and not events:
                rest = process.stdout.read()
                if rest:
                    combined.extend(rest)
                break
        try:
            rc = process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            if not kill_client():
                fail("PostgreSQL client broker container cleanup is uncertain", 70)
            rc = process.wait(timeout=15)
        if timed_out:
            raise TimeoutError("PostgreSQL client broker request timed out")
        if overflow:
            fail("PostgreSQL client broker combined output is too large", 70)
    finally:
        if created_container_ref is not None and not kill_client():
            fail("PostgreSQL client broker container cleanup is uncertain", 70)
        if client_exists():
            fail("PostgreSQL client broker container cleanup is uncertain", 70)
        try:
            cidfile.unlink(missing_ok=True)
            namefile.unlink(missing_ok=True)
        except OSError:
            pass
    if len(combined) > MAX_COMBINED_OUTPUT_BYTES:
        fail("PostgreSQL client broker combined output is too large", 70)
    return rc, bytes(combined), b""


def handle(conn: socket.socket) -> None:
    conn.settimeout(BROKER_SOCKET_TIMEOUT_SECONDS)
    data = b""
    while True:
        chunk = conn.recv(65536)
        if not chunk:
            break
        data += chunk
        if len(data) > MAX_REQUEST_BYTES:
            fail("client broker request is too large")
    request = json.loads(data.decode("utf-8"))
    if not isinstance(request, dict):
        fail("client broker request must be an object")
    rc, stdout, stderr = execute(request)
    response = {
        "returncode": rc,
        "stdout": stdout.decode("latin1"),
        "stderr": stderr.decode("latin1"),
    }
    encoded_response = json.dumps(response, separators=(",", ":")).encode("utf-8")
    if len(encoded_response) > MAX_RESPONSE_BYTES:
        fail("PostgreSQL client broker response is too large", 70)
    conn.sendall(encoded_response)


def main() -> int:
    def terminate(_signum: int, _frame: object) -> None:
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, terminate)
    validate_socket_bridge()
    os.chdir(SOCKET_DIR)
    Path(SOCKET_NAME).unlink(missing_ok=True)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.settimeout(BROKER_SOCKET_TIMEOUT_SECONDS)
        server.bind(SOCKET_NAME)
        Path(SOCKET_NAME).chmod(0o600)
        server.listen(1)
        while True:
            try:
                conn, _ = server.accept()
            except TimeoutError:
                continue
            with conn:
                try:
                    handle(conn)
                except Exception as exc:  # noqa: BLE001 - broker returns bounded failure text.
                    message = str(exc)
                    code = 64
                    if ":" in message and message.split(":", 1)[0].isdigit():
                        raw_code, message = message.split(":", 1)
                        code = int(raw_code)
                    conn.sendall(
                        json.dumps(
                            {"returncode": code, "stdout": "", "stderr": message + "\n"},
                            separators=(",", ":"),
                        ).encode("utf-8")
                    )


if __name__ == "__main__":
    raise SystemExit(main())
PY
exec {broker_script_fd}<"$broker_script"
verify_private_artifact_fd "$broker_script" "/proc/$BASHPID/fd/$broker_script_fd" 0700 || {
  echo 'PostgreSQL client broker script failed private artifact verification' >&2
  exit 70
}
for postgres_client_tool in postgresql-client psql pg_dump pg_restore; do
  write_verified_private_artifact "$state_dir/client" "$postgres_client_tool" 0700 <<'PY'
#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import socket
import sys
from pathlib import Path

tool = Path(sys.argv[0]).name
if tool not in {"psql", "pg_dump", "pg_restore"}:
    print("unsupported PostgreSQL client wrapper", file=sys.stderr)
    raise SystemExit(64)
socket_path = os.environ.get("ACP_POSTGRES_CLIENT_BROKER_SOCKET")
if not socket_path:
    print("ACP_POSTGRES_CLIENT_BROKER_SOCKET is required", file=sys.stderr)
    raise SystemExit(69)
socket_path_object = Path(socket_path)
socket_dir = socket_path_object.parent
socket_name = socket_path_object.name
env = {
    key: os.environ[key]
    for key in (
        "PGHOST", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE", "PGPASSFILE",
        "PGCONNECT_TIMEOUT", "PGOPTIONS", "PGSSLMODE", "PGSSLROOTCERT", "PGSSLCERT",
        "PGSSLKEY", "PGAPPNAME", "LANG", "LC_ALL", "LC_CTYPE",
    )
    if key in os.environ
}
request = json.dumps(
    {"tool": tool, "argv": sys.argv[1:], "env": env},
    separators=(",", ":"),
).encode("utf-8")
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.settimeout(15)
    os.chdir(socket_dir)
    client.connect(socket_name)
    client.sendall(request)
    client.shutdown(socket.SHUT_WR)
    chunks = []
    while True:
        chunk = client.recv(65536)
        if not chunk:
            break
        chunks.append(chunk)
        if sum(len(item) for item in chunks) > 2_097_152:
            print("PostgreSQL client broker response is too large", file=sys.stderr)
            raise SystemExit(70)
response = json.loads(b"".join(chunks).decode("utf-8"))
sys.stdout.write(response.get("stdout", "").encode("latin1").decode("latin1"))
sys.stderr.write(response.get("stderr", "").encode("latin1").decode("latin1"))
raise SystemExit(int(response.get("returncode", 70)))
PY
done
export PATH="$state_dir/client:$PATH"
broker_socket="$state_dir/broker/postgresql-client.sock"
ACP_POSTGRES_CLIENT_BROKER_DOCKER="$docker_bin" \
ACP_POSTGRES_CLIENT_PROOF_LABEL="$proof_label" \
ACP_POSTGRES_CLIENT_PROOF_NONCE="$proof_nonce" \
ACP_POSTGRES_SERVER_NAME="$container_name" \
ACGS_POSTGRES_RECOVERY_ROOT="$postgres_recovery_root" \
ACP_POSTGRES_SOCKET_BRIDGE="$postgres_socket_bridge" \
ACP_POSTGRES_SOCKET_BRIDGE_IDENTITY="$postgres_socket_bridge_identity" \
ACP_POSTGRES_SOCKET_BRIDGE_MARKER_SHA256="$postgres_socket_bridge_marker_sha256" \
ACP_POSTGRES_SOCKET_BRIDGE_MNT_ID="$postgres_socket_bridge_mnt_id" \
ACP_POSTGRES_RECOVERY_ROOT_MNT_ID="$postgres_recovery_root_mnt_id" \
/usr/bin/python3 -I -S "/proc/$BASHPID/fd/$broker_script_fd" "$broker_socket" "$state_dir" &
broker_pid=$!
for _ in {1..50}; do
  [[ -S "$broker_socket" ]] && break
  if ! kill -0 "$broker_pid" >/dev/null 2>&1; then
    echo 'PostgreSQL client broker exited before creating its socket' >&2
    exit 70
  fi
  sleep 0.1
done
if [[ ! -S "$broker_socket" ]]; then
  echo 'timed out waiting for PostgreSQL client broker socket' >&2
  exit 70
fi
export ACP_POSTGRES_CLIENT_BROKER_SOCKET="$broker_socket"

export PGHOST=/run/acgs-pg
export PGPORT=5432
export PGUSER="$postgres_user"
export PGPASSWORD="$postgres_password"
export PGDATABASE="$main_database"
export PGCONNECT_TIMEOUT=5

psql --set ON_ERROR_STOP=1 --command 'SELECT 1' >/dev/null
test "$(psql --version | awk '{print $3}')" = '17.10'
test "$(pg_dump --version | awk '{print $3}')" = '17.10'
test "$(pg_restore --version | awk '{print $3}')" = '17.10'

for database in \
  acgs_control_plane_recovery_source_test \
  acgs_control_plane_recovery_target_test \
  acgs_control_plane_recovery_bytea_test \
  acgs_control_plane_rolling_upgrade_test
do
  psql --set ON_ERROR_STOP=1 --command "CREATE DATABASE ${database}"
done
# The fixture owner is disposable migration authority for this gate only; it
# does not prove production RLS or runtime least privilege.
psql --set ON_ERROR_STOP=1 \
  --command "CREATE ROLE $postgres_fixture_owner_user LOGIN PASSWORD '$postgres_fixture_owner_password' NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS" \
  --command "ALTER DATABASE $main_database OWNER TO $postgres_fixture_owner_user" \
  --command "ALTER DATABASE acgs_control_plane_recovery_source_test OWNER TO $postgres_fixture_owner_user" \
  --command "ALTER DATABASE acgs_control_plane_recovery_target_test OWNER TO $postgres_fixture_owner_user" \
  --command "ALTER DATABASE acgs_control_plane_recovery_bytea_test OWNER TO $postgres_fixture_owner_user" \
  --command "ALTER DATABASE acgs_control_plane_rolling_upgrade_test OWNER TO $postgres_fixture_owner_user" \
  --command "GRANT CONNECT, TEMPORARY ON DATABASE $main_database TO $postgres_fixture_owner_user" \
  --command "GRANT CONNECT, TEMPORARY ON DATABASE acgs_control_plane_recovery_source_test TO $postgres_fixture_owner_user" \
  --command "GRANT CONNECT, TEMPORARY ON DATABASE acgs_control_plane_recovery_target_test TO $postgres_fixture_owner_user" \
  --command "GRANT CONNECT, TEMPORARY ON DATABASE acgs_control_plane_recovery_bytea_test TO $postgres_fixture_owner_user" \
  --command "GRANT CONNECT, TEMPORARY ON DATABASE acgs_control_plane_rolling_upgrade_test TO $postgres_fixture_owner_user" \
  >/dev/null
PGUSER="$postgres_fixture_owner_user" PGPASSWORD="$postgres_fixture_owner_password" \
  psql --set ON_ERROR_STOP=1 --command 'SELECT 1' >/dev/null
if PGUSER="$postgres_fixture_owner_user" PGPASSWORD="$postgres_fixture_owner_password" \
  psql --set ON_ERROR_STOP=1 --command "COPY (SELECT 1) TO PROGRAM 'true'" >/dev/null 2>&1; then
  echo 'PostgreSQL fixture owner role unexpectedly allowed COPY PROGRAM' >&2
  exit 70
fi
if PGUSER="$postgres_fixture_owner_user" PGPASSWORD="$postgres_fixture_owner_password" \
  psql --set ON_ERROR_STOP=1 --command "SELECT pg_read_file('/etc/passwd', 0, 1)" >/dev/null 2>&1; then
  echo 'PostgreSQL fixture owner role unexpectedly allowed pg_read_file' >&2
  exit 70
fi
if PGUSER="$postgres_fixture_owner_user" PGPASSWORD="$postgres_fixture_owner_password" \
  psql --set ON_ERROR_STOP=1 --command "SELECT pg_write_file('/tmp/acgs-forbidden', 'x')" >/dev/null 2>&1; then
  echo 'PostgreSQL fixture owner role unexpectedly allowed pg_write_file' >&2
  exit 70
fi
if PGUSER="$postgres_fixture_owner_user" PGPASSWORD="$postgres_fixture_owner_password" \
  psql --set ON_ERROR_STOP=1 --command 'CREATE ROLE acgs_forbidden_escalation' >/dev/null 2>&1; then
  echo 'PostgreSQL fixture owner role unexpectedly allowed role creation' >&2
  exit 70
fi
if PGUSER="$postgres_fixture_owner_user" PGPASSWORD="$postgres_fixture_owner_password" \
  psql --set ON_ERROR_STOP=1 --command 'CREATE DATABASE acgs_forbidden_escalation' >/dev/null 2>&1; then
  echo 'PostgreSQL fixture owner role unexpectedly allowed database creation' >&2
  exit 70
fi
if PGUSER="$postgres_user" PGPASSWORD="$postgres_fixture_owner_password" \
  psql --set ON_ERROR_STOP=1 --command 'SELECT 1' >/dev/null 2>&1; then
  echo 'PostgreSQL local HBA unexpectedly allowed bootstrap-admin impersonation' >&2
  exit 70
fi
if PGUSER="$postgres_user" PGPASSWORD='g101-test-password-17' \
  psql --set ON_ERROR_STOP=1 --command 'SELECT 1' >/dev/null 2>&1; then
  echo 'PostgreSQL local HBA unexpectedly allowed the retired static bootstrap password' >&2
  exit 70
fi
psql --set ON_ERROR_STOP=1 --tuples-only --no-align \
  --command "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls FROM pg_roles WHERE rolname = '$postgres_fixture_owner_user'" \
  | grep --fixed-strings 't|f|f|f|f|f' >/dev/null || {
  echo 'PostgreSQL fixture owner role attributes are not least-privileged' >&2
  exit 70
}
psql --set ON_ERROR_STOP=1 --tuples-only --no-align \
  --command "SELECT pg_has_role('$postgres_fixture_owner_user','pg_read_server_files','member') OR pg_has_role('$postgres_fixture_owner_user','pg_write_server_files','member') OR pg_has_role('$postgres_fixture_owner_user','pg_execute_server_program','member')" \
  | grep --fixed-strings 'f' >/dev/null || {
  echo 'PostgreSQL fixture owner role unexpectedly has server-file/program membership' >&2
  exit 70
}
export PGUSER="$postgres_fixture_owner_user"
export PGPASSWORD="$postgres_fixture_owner_password"

git -C "$workspace_dir" cat-file -e "${old_commit}^{commit}"
git -C "$workspace_dir" archive "$old_commit" | tar -x -C "$state_dir/acp-old"
mkdir -p "$state_dir/acp-old/packages/acgs-control-plane/.venv"
export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH="$(git -C "$workspace_dir" show -s --format=%ct "$old_commit")"
run_sandboxed_uv_build() {
  local output_dir="$1"
  env -i "$bwrap_bin" \
    --unshare-all --unshare-user --die-with-parent --new-session --disable-userns \
    --proc /proc \
    --dev /dev \
    --tmpfs /tmp \
    --tmpfs /run \
    --ro-bind /usr /usr \
    --ro-bind /bin /bin \
    --ro-bind-try /lib /lib \
    --ro-bind-try /lib64 /lib64 \
    --ro-bind "$package_dir" "$package_dir" \
    --ro-bind "$uv_bin" "$uv_bin" \
    --ro-bind "$python_runtime_bind_root" "$python_runtime_bind_root" \
    --bind "$state_dir" "$state_dir" \
    --ro-bind "$package_dir/.venv" "$state_dir/acp-old/packages/acgs-control-plane/.venv" \
    --clearenv \
    --setenv HOME "$state_dir/home" \
    --setenv TMPDIR "$state_dir/tmp" \
    --setenv UV_CACHE_DIR "$state_dir/uv-cache" \
    --setenv SOURCE_DATE_EPOCH "$SOURCE_DATE_EPOCH" \
    --setenv PATH /usr/bin:/bin \
    --chdir "$package_dir" \
    -- \
    "$uv_bin" build --no-build-isolation \
      --python "$package_dir/.venv/bin/python" \
      --offline --no-index --no-cache --wheel --out-dir "$output_dir" \
      "$state_dir/acp-old/packages/acgs-control-plane"
}
run_sandboxed_uv_build "$state_dir/old-1"
run_sandboxed_uv_build "$state_dir/old-2"
old_wheel="$state_dir/old-1/acgs_control_plane-0.1.0-py3-none-any.whl"
second_wheel="$state_dir/old-2/acgs_control_plane-0.1.0-py3-none-any.whl"
test -f "$old_wheel"
test -f "$second_wheel"
cmp "$old_wheel" "$second_wheel"
test "$(sha256sum "$old_wheel" | awk '{print $1}')" = "$old_digest"
test "$(sha256sum "$second_wheel" | awk '{print $1}')" = "$old_digest"

main_url="postgresql+psycopg://${postgres_fixture_owner_user}:${postgres_fixture_owner_password}@/${main_database}?host=/run/acgs-pg"
recovery_source_url="postgresql+psycopg://${postgres_fixture_owner_user}:${postgres_fixture_owner_password}@/acgs_control_plane_recovery_source_test?host=/run/acgs-pg"
recovery_target_url="postgresql+psycopg://${postgres_fixture_owner_user}:${postgres_fixture_owner_password}@/acgs_control_plane_recovery_target_test?host=/run/acgs-pg"
recovery_bytea_url="postgresql+psycopg://${postgres_fixture_owner_user}:${postgres_fixture_owner_password}@/acgs_control_plane_recovery_bytea_test?host=/run/acgs-pg"
rolling_url="postgresql+psycopg://${postgres_fixture_owner_user}:${postgres_fixture_owner_password}@/acgs_control_plane_rolling_upgrade_test?host=/run/acgs-pg"
case "$main_url$recovery_source_url$recovery_target_url$recovery_bytea_url$rolling_url" in
  *"$postgres_user:$postgres_password"*)
    echo 'PostgreSQL bootstrap credentials unexpectedly entered candidate URLs' >&2
    exit 70
    ;;
esac

export ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE=1
export ACP_TEST_POSTGRES_GATE_ACTIVE=1
export ACP_TEST_POSTGRES_URL="$main_url"
export ACP_TEST_MIGRATION_CLI_URL="$main_url"
export ACP_TEST_MIGRATION_CLI_TARGET_URL="$main_url"
export ACP_TEST_RECOVERY_SOURCE_URL="$recovery_source_url"
export ACP_TEST_RECOVERY_TARGET_URL="$recovery_target_url"
export ACP_TEST_RECOVERY_BYTEA_URL="$recovery_bytea_url"
export ACP_TEST_ROLLING_POSTGRES_URL="$rolling_url"
if [[ "$selector_mode" == 'p1-migration' || "$selector_mode" == 'p2-immutable-0004-upgrade' ]]; then
  export ACP_TEST_OLD_APP_ARTIFACT="$old_wheel"
  export ACP_TEST_OLD_APP_ARTIFACT_SHA256="$old_digest"
else
  unset ACP_TEST_OLD_APP_ARTIFACT ACP_TEST_OLD_APP_ARTIFACT_SHA256
fi
export UV_BIN="$uv_bin"
export ACP_TEST_POSTGRES_SELECTOR_MODE="$selector_mode"

junit_report="/run/tmp/junit.xml"
broker_child_path="/run/client:$package_dir/.venv/bin:/usr/bin:/bin"
bwrap_args=(
  --unshare-all --unshare-user --die-with-parent --new-session --disable-userns
  --proc /proc
  --dev /dev
  --tmpfs /tmp
  --tmpfs /run
  --dir /proof-scratch
  --ro-bind /usr /usr
  --ro-bind /bin /bin
  --ro-bind-try /lib /lib
  --ro-bind-try /lib64 /lib64
  --ro-bind "$package_dir" "$package_dir"
  --ro-bind "$gove_zone_src" "$gove_zone_src"
  --ro-bind "$uv_bin" "$uv_bin"
  --ro-bind "$python_runtime_bind_root" "$python_runtime_bind_root"
  --ro-bind "$state_dir/client" /run/client
  --ro-bind "$state_dir/broker" /run/broker
  --ro-bind "$postgres_socket_bridge" /run/acgs-pg
  --ro-bind "$state_dir/old-1" /old-1
  --ro-bind "$state_dir/old-2" /old-2
  --bind "$state_dir/home" /run/home
  --bind "$state_dir/tmp" /run/tmp
  --bind "$state_dir/proof-scratch" /proof-scratch
  --clearenv
  --setenv ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE 1
  --setenv ACP_TEST_POSTGRES_GATE_ACTIVE 1
  --setenv ACP_TEST_POSTGRES_SELECTOR_MODE "$selector_mode"
  --setenv ACP_TEST_POSTGRES_URL "$main_url"
  --setenv ACP_TEST_MIGRATION_CLI_URL "$main_url"
  --setenv ACP_TEST_MIGRATION_CLI_TARGET_URL "$main_url"
  --setenv ACP_TEST_RECOVERY_SOURCE_URL "$recovery_source_url"
  --setenv ACP_TEST_RECOVERY_TARGET_URL "$recovery_target_url"
  --setenv ACP_TEST_RECOVERY_BYTEA_URL "$recovery_bytea_url"
  --setenv ACP_TEST_ROLLING_POSTGRES_URL "$rolling_url"
  --setenv ACP_POSTGRES_CLIENT_BROKER_SOCKET /run/broker/postgresql-client.sock
  --setenv ACGS_TEST_SEED 20260710
  --setenv PYTHONHASHSEED 0
  --setenv PYTEST_DISABLE_PLUGIN_AUTOLOAD 1
  --setenv PYTEST_ADDOPTS "-p no:cacheprovider"
  --setenv PYTHONNOUSERSITE 1
  --setenv PYTHONDONTWRITEBYTECODE 1
  --setenv UV_BIN "$uv_bin"
  --setenv PATH "$broker_child_path"
  --setenv TMPDIR /run/tmp
  --setenv HOME /run/home
  --chdir "$package_dir"
)
if [[ "$selector_mode" == 'p1-migration' || "$selector_mode" == 'p2-immutable-0004-upgrade' ]]; then
  bwrap_args+=(--setenv ACP_TEST_OLD_APP_ARTIFACT "/old-1/${old_wheel##*/}")
  bwrap_args+=(--setenv ACP_TEST_OLD_APP_ARTIFACT_SHA256 "$old_digest")
fi
pytest_output_file="$state_dir/tmp/pytest-output.bin"
write_verified_private_artifact "$state_dir/tmp" "pytest-output.bin" 0600 </dev/null || {
  echo 'failed to create bounded pytest output sink' >&2
  exit 70
}
exec {pytest_output_fd}<>"$pytest_output_file"
verify_private_artifact_fd "$pytest_output_file" "/proc/$BASHPID/fd/$pytest_output_fd" 0600 || {
  echo 'bounded pytest output sink failed verification' >&2
  exit 70
}
set +e
(
  ulimit -f 131072
  timeout --preserve-status 900s env -i "$bwrap_bin" "${bwrap_args[@]}" -- \
    "$package_dir/.venv/bin/pytest" -q --junitxml="$junit_report" "$@"
) >"/proc/$BASHPID/fd/$pytest_output_fd" 2>&1
pytest_status=$?
set -e
verify_private_artifact_fd "$pytest_output_file" "/proc/$BASHPID/fd/$pytest_output_fd" 0600 || {
  echo 'bounded pytest output sink changed during execution' >&2
  exit 70
}
pytest_output_summary="$(summarize_private_output_sink "$pytest_output_file")" || {
  echo 'pytest_output_overflow=1' >&2
  exit 70
}
if ((pytest_status != 0)); then
  printf 'pytest command failed: status=%s %s\n' "$pytest_status" "$pytest_output_summary" >&2
  exit "$pytest_status"
fi

verify_junit_report "$state_dir/tmp" "junit.xml" "$junit_expected_tests" "$(id -u)"
