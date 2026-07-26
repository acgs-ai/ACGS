#!/usr/bin/env bash
set -euo pipefail

postgres_image='postgres:17.10-bookworm@sha256:4f736ae292687621d4dbe0d499ffd024a36bd2ee7d8ca6f2ccd4c800f047b394'
postgres_digest='sha256:4f736ae292687621d4dbe0d499ffd024a36bd2ee7d8ca6f2ccd4c800f047b394'
old_commit='4f0c685b5d2ffac0e6a71810b77c6357b8d56a94'
old_digest='40ff7b40f27a2b698d3b607c710f1866f11850a9a2c42a7c0eb51a6fe8be3d93'
postgres_user='acgs_control_plane_test'
postgres_password='g101-test-password-17'
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
immutable_0004_selector='tests/integration/test_migrations_postgres.py::test_immutable_0004_upgrade_defers_managed_ledger_constraints_and_bootstraps'
selector_mode=''
junit_expected_tests=0
if (($# == ${#expected_selectors[@]})); then
  selector_mode='p1-migration'
  junit_expected_tests=6
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
if [[ -z "$selector_mode" && $# == 1 && "$1" == "$immutable_0004_selector" ]]; then
  selector_mode='p2-immutable-0004-upgrade'
  junit_expected_tests=1
fi
if [[ -z "$selector_mode" ]]; then
  echo 'the exact ordered PostgreSQL migration, P2 tenant-bootstrap, P2 register, P2 idempotency, P2 vertical-gate, P3 policy, or immutable-0004 selector is required' >&2
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
for required_command in bwrap cmp docker git mktemp realpath sha256sum stat tar; do
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
container_name="acp-postgres-gate-$(id -u)-$$-$RANDOM"
container_id=''
broker_pid=''

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n "$broker_pid" ]]; then
    kill "$broker_pid" >/dev/null 2>&1 || true
    wait "$broker_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$container_id" ]]; then
    docker rm -f "$container_id" >/dev/null 2>&1 || true
  fi
  if [[ -d "$state_dir/pg" ]]; then
    docker run --rm --pull=never --network none --security-opt label=disable \
      --volume "$state_dir/pg:/run/acgs-pg:rw" \
      "$postgres_image" sh -c 'rm -f /run/acgs-pg/.s.PGSQL.5432 /run/acgs-pg/.s.PGSQL.5432.lock' \
      >/dev/null 2>&1 || true
  fi
  rm -rf "$state_dir"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cd "$package_dir"

docker image inspect "$postgres_image" >/dev/null 2>&1 || {
  echo 'the exact digest-pinned PostgreSQL image must already be cached locally' >&2
  exit 69
}
docker image inspect --format '{{json .RepoDigests}}' "$postgres_image" \
  | grep --fixed-strings "$postgres_digest" >/dev/null || {
  echo 'the cached PostgreSQL image does not expose the required repository digest' >&2
  exit 69
}

mkdir -p \
  "$state_dir/broker" "$state_dir/client" "$state_dir/home" "$state_dir/tmp" \
  "$state_dir/proof-scratch" "$state_dir/uv-cache" "$state_dir/acp-old" "$state_dir/pg" \
  "$state_dir/old-1" "$state_dir/old-2"
chmod 0700 \
  "$state_dir" "$state_dir/broker" "$state_dir/client" "$state_dir/home" \
  "$state_dir/tmp" "$state_dir/proof-scratch"
chmod 0777 "$state_dir/pg"
chmod 0700 "$state_dir/uv-cache"

container_id="$(
  docker run -d \
    --pull=never \
    --network none \
    --name "$container_name" \
    --env "POSTGRES_DB=$main_database" \
    --env "POSTGRES_USER=$postgres_user" \
    --env "POSTGRES_PASSWORD=$postgres_password" \
    --env PGHOST=/run/acgs-pg \
    --health-cmd "pg_isready -h /run/acgs-pg -U $postgres_user -d $main_database" \
    --health-interval 1s \
    --health-timeout 5s \
    --health-retries 60 \
    --security-opt label=disable \
    --volume "$state_dir/pg:/run/acgs-pg:rw" \
    --volume "$state_dir/pg:/var/run/postgresql:rw" \
    --tmpfs /var/lib/postgresql/data:rw,noexec,nosuid,nodev \
    "$postgres_image" \
    postgres -c listen_addresses= -c unix_socket_directories=/run/acgs-pg \
      -c unix_socket_permissions=0777
)"

for _ in {1..90}; do
  container_status="$(docker inspect --format '{{.State.Status}}' "$container_id")"
  health_status="$(docker inspect --format '{{.State.Health.Status}}' "$container_id")"
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
if [[ "$(docker inspect --format '{{.State.Health.Status}}' "$container_id")" != 'healthy' ]]; then
  echo 'timed out waiting for the disposable PostgreSQL container to become healthy' >&2
  exit 70
fi

if [[ ! -S "$state_dir/pg/.s.PGSQL.5432" ]]; then
  echo 'timed out waiting for PostgreSQL Unix socket' >&2
  exit 70
fi

cat >"$state_dir/broker/postgres_client_broker.py" <<'PY'
from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
from pathlib import Path

SOCKET_PATH = Path(sys.argv[1])
STATE_DIR = SOCKET_PATH.parent.parent.resolve(strict=True)
SOCKET_DIR = SOCKET_PATH.parent.resolve(strict=True)
SOCKET_NAME = SOCKET_PATH.name
IMAGE = "postgres:17.10-bookworm@sha256:4f736ae292687621d4dbe0d499ffd024a36bd2ee7d8ca6f2ccd4c800f047b394"
DOCKER_BIN = Path(os.environ["ACP_POSTGRES_CLIENT_BROKER_DOCKER"])
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
MAX_REQUEST_BYTES = 131_072
REQUESTS = 0
ALLOWED_RW_ROOTS = tuple(SANDBOX_RW_ROOTS)
ALLOWED_RO_ROOTS = tuple(SANDBOX_RW_ROOTS)


def fail(message: str, code: int = 64) -> None:
    raise ValueError(f"{code}:{message}")


if not DOCKER_BIN.is_absolute() or DOCKER_BIN.is_symlink() or not os.access(DOCKER_BIN, os.X_OK):
    fail("broker docker client must be an absolute executable non-symlink", 69)
if DOCKER_BIN.resolve(strict=True) != DOCKER_BIN:
    fail("broker docker client must already be canonical", 69)


def validate_string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        fail(f"{label} must be a string list")
    if any("\0" in item for item in value):
        fail(f"{label} contains a NUL byte")
    return value


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
    unknown_env = set(env) - ALLOWED_ENV
    if unknown_env:
        fail("unsupported PostgreSQL client env: " + ",".join(sorted(unknown_env)))
    if env.get("PGHOST", PINNED_PGHOST) != PINNED_PGHOST:
        fail("PostgreSQL client broker endpoint is pinned")
    if env.get("PGPORT", PINNED_PGPORT) != PINNED_PGPORT:
        fail("PostgreSQL client broker endpoint is pinned")
    env = {**env, "PGHOST": PINNED_PGHOST, "PGPORT": PINNED_PGPORT}
    paths: dict[str, str] = {}
    for variable in ("PGPASSFILE", "PGSSLROOTCERT", "PGSSLCERT", "PGSSLKEY"):
        if env.get(variable):
            add_read_path(paths, env[variable], variable)
    for argument in args:
        if argument.startswith("--file="):
            add_write_file(paths, argument.split("=", 1)[1])
        elif argument.startswith("/"):
            add_read_path(paths, argument, "argument")

    docker_args = [
        str(DOCKER_BIN), "run", "--rm", "--pull=never", "--network", "none",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--security-opt", "label=disable", "--user", f"{os.getuid()}:{os.getgid()}",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,mode=1777",
        "--volume", f"{STATE_DIR / 'pg'}:/run/acgs-pg:ro",
        "--volume", f"{HOST_TMP}:/run/tmp:rw",
        "--volume", f"{HOST_PROOF_SCRATCH}:/proof-scratch:rw",
    ]
    for key in sorted(env):
        docker_args.extend(["--env", key])
    del paths
    completed = subprocess.run(
        [*docker_args, IMAGE, tool, *args],
        env={key: env[key] for key in env},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return completed.returncode, completed.stdout, completed.stderr


def handle(conn: socket.socket) -> None:
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
    conn.sendall(json.dumps(response, separators=(",", ":")).encode("utf-8"))


def main() -> int:
    def terminate(_signum: int, _frame: object) -> None:
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, terminate)
    os.chdir(SOCKET_DIR)
    Path(SOCKET_NAME).unlink(missing_ok=True)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(SOCKET_NAME)
        Path(SOCKET_NAME).chmod(0o600)
        server.listen(1)
        while True:
            conn, _ = server.accept()
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
cat >"$state_dir/client/postgresql-client" <<'PY'
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
response = json.loads(b"".join(chunks).decode("utf-8"))
sys.stdout.write(response.get("stdout", "").encode("latin1").decode("latin1"))
sys.stderr.write(response.get("stderr", "").encode("latin1").decode("latin1"))
raise SystemExit(int(response.get("returncode", 70)))
PY
chmod 0755 "$state_dir/client/postgresql-client"
ln -s postgresql-client "$state_dir/client/psql"
ln -s postgresql-client "$state_dir/client/pg_dump"
ln -s postgresql-client "$state_dir/client/pg_restore"
export PATH="$state_dir/client:$PATH"
broker_socket="$state_dir/broker/postgresql-client.sock"
ACP_POSTGRES_CLIENT_BROKER_DOCKER="$docker_bin" \
  "$package_dir/.venv/bin/python" "$state_dir/broker/postgres_client_broker.py" "$broker_socket" &
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

main_url="postgresql+psycopg://${postgres_user}:${postgres_password}@/${main_database}?host=/run/acgs-pg"
recovery_source_url="postgresql+psycopg://${postgres_user}:${postgres_password}@/acgs_control_plane_recovery_source_test?host=/run/acgs-pg"
recovery_target_url="postgresql+psycopg://${postgres_user}:${postgres_password}@/acgs_control_plane_recovery_target_test?host=/run/acgs-pg"
recovery_bytea_url="postgresql+psycopg://${postgres_user}:${postgres_password}@/acgs_control_plane_recovery_bytea_test?host=/run/acgs-pg"
rolling_url="postgresql+psycopg://${postgres_user}:${postgres_password}@/acgs_control_plane_rolling_upgrade_test?host=/run/acgs-pg"

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
  --ro-bind "$state_dir/pg" /run/acgs-pg
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
set +e
env -i "$bwrap_bin" "${bwrap_args[@]}" -- \
  "$package_dir/.venv/bin/pytest" -q --junitxml="$junit_report" "$@"
pytest_status=$?
set -e
if ((pytest_status != 0)); then
  exit "$pytest_status"
fi

.venv/bin/python - "$state_dir/tmp/junit.xml" "$junit_expected_tests" <<'PY'
from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


report = Path(sys.argv[1])
expected_tests = int(sys.argv[2])
try:
    root = ET.parse(report).getroot()
except (OSError, ET.ParseError) as exc:
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
