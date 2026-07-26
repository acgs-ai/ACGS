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
if [[ -z "$selector_mode" && $# == 1 && "$1" == "$immutable_0004_selector" ]]; then
  selector_mode='p2-immutable-0004-upgrade'
  junit_expected_tests=1
fi
if [[ -z "$selector_mode" ]]; then
  echo 'the exact ordered PostgreSQL migration, P2 tenant-bootstrap, P2 register, P2 idempotency, or immutable-0004 selector is required' >&2
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
for required_command in bwrap cmp docker git mktemp realpath sha256sum tar; do
  if ! command -v "$required_command" >/dev/null 2>&1; then
    printf 'required command is unavailable: %s\n' "$required_command" >&2
    exit 69
  fi
done
bwrap_bin="$(command -v bwrap)"
if [[ "$bwrap_bin" != /usr/bin/bwrap || ! -x "$bwrap_bin" || -L "$bwrap_bin" ]]; then
  echo 'the PostgreSQL evidence gate requires canonical /usr/bin/bwrap' >&2
  exit 69
fi
if ! "$bwrap_bin" \
  --unshare-all --unshare-user --share-net --die-with-parent --new-session \
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
  "$state_dir/uv-cache" "$state_dir/acp-old" "$state_dir/old-1" "$state_dir/old-2"
chmod 0700 "$state_dir" "$state_dir/broker" "$state_dir/client" "$state_dir/home" "$state_dir/tmp"
chmod 0700 "$state_dir/uv-cache"

container_id="$(
  docker run -d \
    --pull=never \
    --name "$container_name" \
    --publish 127.0.0.1::5432 \
    --env "POSTGRES_DB=$main_database" \
    --env "POSTGRES_USER=$postgres_user" \
    --env "POSTGRES_PASSWORD=$postgres_password" \
    --health-cmd "pg_isready -U $postgres_user -d $main_database" \
    --health-interval 1s \
    --health-timeout 5s \
    --health-retries 60 \
    --tmpfs /var/lib/postgresql/data:rw,noexec,nosuid,nodev \
    "$postgres_image"
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

pg_port="$(
  docker port "$container_id" 5432/tcp \
    | awk -F: '/127[.]0[.]0[.]1/ {print $NF; exit}'
)"
if [[ -z "$pg_port" ]]; then
  echo "failed to discover private PostgreSQL host port" >&2
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
IMAGE = "postgres:17.10-bookworm@sha256:4f736ae292687621d4dbe0d499ffd024a36bd2ee7d8ca6f2ccd4c800f047b394"
ALLOWED_TOOLS = {"psql", "pg_dump", "pg_restore"}
ALLOWED_ENV = {
    "PGHOST", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE", "PGPASSFILE",
    "PGCONNECT_TIMEOUT", "PGOPTIONS", "PGSSLMODE", "PGSSLROOTCERT", "PGSSLCERT",
    "PGSSLKEY", "PGAPPNAME", "LANG", "LC_ALL", "LC_CTYPE",
}
MAX_REQUEST_BYTES = 131_072
REQUESTS = 0


def fail(message: str, code: int = 64) -> None:
    raise ValueError(f"{code}:{message}")


def validate_string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        fail(f"{label} must be a string list")
    if any("\0" in item for item in value):
        fail(f"{label} contains a NUL byte")
    return value


def add_path_parent(paths: dict[str, str], candidate: str, access: str) -> None:
    path = Path(candidate)
    parent = path if path.is_dir() else path.parent
    try:
        resolved = str(parent.resolve(strict=False))
    except OSError as exc:
        fail(f"path resolution failed: {exc}", 65)
    if not resolved.startswith("/"):
        fail("path must resolve under an absolute root")
    current = paths.get(resolved)
    if access == "rw" or current is None:
        paths[resolved] = access


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
    paths: dict[str, str] = {}
    for variable in ("PGPASSFILE", "PGSSLROOTCERT", "PGSSLCERT", "PGSSLKEY"):
        if env.get(variable):
            add_path_parent(paths, env[variable], "ro")
    for argument in args:
        if argument.startswith("--file="):
            add_path_parent(paths, argument.split("=", 1)[1], "rw")
        elif argument.startswith("/"):
            add_path_parent(paths, argument, "ro")

    docker_args = ["docker", "run", "--rm", "--pull=never", "--network", "host"]
    rootless = subprocess.run(
        ["docker", "info", "--format", "{{json .SecurityOptions}}"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if "rootless" not in rootless.stdout:
        docker_args.extend(["--user", f"{os.getuid()}:{os.getgid()}"])
    for key in sorted(env):
        docker_args.extend(["--env", key])
    for directory, access in sorted(paths.items()):
        mode = "rw" if access == "rw" else "ro"
        docker_args.extend(["--volume", f"{directory}:{directory}:{mode},Z"])
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
    SOCKET_PATH.unlink(missing_ok=True)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(SOCKET_PATH))
        SOCKET_PATH.chmod(0o600)
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
    client.connect(socket_path)
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

export PGHOST=127.0.0.1
export PGPORT="$pg_port"
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
export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH="$(git -C "$workspace_dir" show -s --format=%ct "$old_commit")"
run_sandboxed_uv_build() {
  local output_dir="$1"
  env -i "$bwrap_bin" \
    --unshare-all --unshare-user --die-with-parent --new-session --disable-userns \
    --ro-bind / / \
    --proc /proc \
    --dev /dev \
    --tmpfs /tmp \
    --tmpfs /run \
    --bind "$state_dir" "$state_dir" \
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

main_url="postgresql+psycopg://${postgres_user}:${postgres_password}@127.0.0.1:${pg_port}/${main_database}"
recovery_source_url="postgresql+psycopg://${postgres_user}:${postgres_password}@127.0.0.1:${pg_port}/acgs_control_plane_recovery_source_test"
recovery_target_url="postgresql+psycopg://${postgres_user}:${postgres_password}@127.0.0.1:${pg_port}/acgs_control_plane_recovery_target_test"
recovery_bytea_url="postgresql+psycopg://${postgres_user}:${postgres_password}@127.0.0.1:${pg_port}/acgs_control_plane_recovery_bytea_test"
rolling_url="postgresql+psycopg://${postgres_user}:${postgres_password}@127.0.0.1:${pg_port}/acgs_control_plane_rolling_upgrade_test"

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

junit_report="$state_dir/junit.xml"
broker_child_path="$state_dir/client:$package_dir/.venv/bin:/usr/bin:/bin"
bwrap_args=(
  --unshare-all --unshare-user --share-net --die-with-parent --new-session --disable-userns
  --ro-bind / /
  --proc /proc
  --dev /dev
  --tmpfs /tmp
  --tmpfs /run
  --bind "$state_dir" "$state_dir"
  --bind "$state_dir/home" "$state_dir/home"
  --bind "$state_dir/tmp" "$state_dir/tmp"
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
  --setenv ACP_POSTGRES_CLIENT_BROKER_SOCKET "$broker_socket"
  --setenv ACGS_TEST_SEED 20260710
  --setenv PYTHONHASHSEED 0
  --setenv PYTEST_DISABLE_PLUGIN_AUTOLOAD 1
  --setenv PYTEST_ADDOPTS "-p no:cacheprovider"
  --setenv PYTHONNOUSERSITE 1
  --setenv PYTHONDONTWRITEBYTECODE 1
  --setenv UV_BIN "$uv_bin"
  --setenv PATH "$broker_child_path"
  --setenv TMPDIR "$state_dir/tmp"
  --setenv HOME "$state_dir/home"
  --chdir "$package_dir"
)
if [[ "$selector_mode" == 'p1-migration' || "$selector_mode" == 'p2-immutable-0004-upgrade' ]]; then
  bwrap_args+=(--setenv ACP_TEST_OLD_APP_ARTIFACT "$old_wheel")
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

.venv/bin/python - "$junit_report" "$junit_expected_tests" <<'PY'
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
