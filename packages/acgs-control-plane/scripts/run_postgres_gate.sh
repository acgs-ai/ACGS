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
if (($# != ${#expected_selectors[@]})); then
  echo 'the exact six ordered PostgreSQL migration selectors are required' >&2
  exit 64
fi
actual_selectors=("$@")
for index in "${!expected_selectors[@]}"; do
  if [[ "${actual_selectors[index]}" != "${expected_selectors[index]}" ]]; then
    echo 'the PostgreSQL migration selectors were substituted or reordered' >&2
    exit 64
  fi
done
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

if [[ ! -x "$package_dir/.venv/bin/python" || ! -x "$package_dir/.venv/bin/pytest" ]]; then
  echo 'packages/acgs-control-plane/.venv/bin/python and .venv/bin/pytest are required' >&2
  exit 66
fi
for required_command in cmp docker git mktemp realpath sha256sum tar; do
  if ! command -v "$required_command" >/dev/null 2>&1; then
    printf 'required command is unavailable: %s\n' "$required_command" >&2
    exit 69
  fi
done

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

cleanup() {
  local status=$?
  trap - EXIT INT TERM
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

mkdir -p "$state_dir/client" "$state_dir/acp-old" "$state_dir/old-1" "$state_dir/old-2"
chmod 0700 "$state_dir" "$state_dir/client"

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

cat >"$state_dir/client/postgresql-client" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
image='postgres:17.10-bookworm@sha256:4f736ae292687621d4dbe0d499ffd024a36bd2ee7d8ca6f2ccd4c800f047b394'
tool="$(basename "$0")"
case "$tool" in
  psql|pg_dump|pg_restore) ;;
  *) echo 'unsupported PostgreSQL client wrapper' >&2; exit 64 ;;
esac

declare -A read_only_directories=()
declare -A read_write_directories=()
add_path_parent() {
  local candidate="$1"
  local access="$2"
  local directory
  if [[ -d "$candidate" ]]; then
    directory="$(realpath "$candidate")"
  else
    directory="$(realpath -m "$(dirname "$candidate")")"
  fi
  if [[ "$access" == 'rw' ]]; then
    read_write_directories["$directory"]=1
    read_only_directories["$directory"]=0
  elif [[ -z "${read_write_directories[$directory]:-}" ]]; then
    read_only_directories["$directory"]=1
  fi
}

for variable in PGPASSFILE PGSSLROOTCERT PGSSLCERT PGSSLKEY; do
  if [[ -n "${!variable:-}" ]]; then
    add_path_parent "${!variable}" ro
  fi
done
for argument in "$@"; do
  case "$argument" in
    --file=*) add_path_parent "${argument#--file=}" rw ;;
    /*) add_path_parent "$argument" ro ;;
  esac
done

docker_arguments=(run --rm --pull=never --network host)
if ! docker info --format '{{json .SecurityOptions}}' | grep --quiet rootless; then
  docker_arguments+=(--user "$(id -u):$(id -g)")
fi
for variable in \
  PGHOST PGPORT PGUSER PGPASSWORD PGDATABASE PGPASSFILE \
  PGCONNECT_TIMEOUT PGOPTIONS PGSSLMODE PGSSLROOTCERT PGSSLCERT PGSSLKEY \
  PGAPPNAME LANG LC_ALL LC_CTYPE
do
  if [[ -v "$variable" ]]; then
    docker_arguments+=(--env "$variable")
  fi
done
for directory in "${!read_only_directories[@]}"; do
  [[ "${read_only_directories[$directory]}" == '1' ]] || continue
  docker_arguments+=(--volume "$directory:$directory:ro,Z")
done
for directory in "${!read_write_directories[@]}"; do
  docker_arguments+=(--volume "$directory:$directory:rw,Z")
done
exec docker "${docker_arguments[@]}" "$image" "$tool" "$@"
BASH
chmod 0755 "$state_dir/client/postgresql-client"
ln -s postgresql-client "$state_dir/client/psql"
ln -s postgresql-client "$state_dir/client/pg_dump"
ln -s postgresql-client "$state_dir/client/pg_restore"
export PATH="$state_dir/client:$PATH"

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
"$uv_bin" build --no-build-isolation \
  --python "$package_dir/.venv/bin/python" \
  --offline --no-index --no-cache --wheel --out-dir "$state_dir/old-1" \
  "$state_dir/acp-old/packages/acgs-control-plane"
"$uv_bin" build --no-build-isolation \
  --python "$package_dir/.venv/bin/python" \
  --offline --no-index --no-cache --wheel --out-dir "$state_dir/old-2" \
  "$state_dir/acp-old/packages/acgs-control-plane"
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
export ACP_TEST_OLD_APP_ARTIFACT="$old_wheel"
export ACP_TEST_OLD_APP_ARTIFACT_SHA256="$old_digest"
export UV_BIN="$uv_bin"

junit_report="$state_dir/junit.xml"
set +e
.venv/bin/pytest -q --junitxml="$junit_report" "$@"
pytest_status=$?
set -e
if ((pytest_status != 0)); then
  exit "$pytest_status"
fi

.venv/bin/python - "$junit_report" <<'PY'
from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


report = Path(sys.argv[1])
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

expected = {"tests": 6, "failures": 0, "errors": 0, "skipped": 0}
if totals != expected:
    raise SystemExit(f"pytest JUnit totals are not the required exact gate totals: {totals}")
print("pytest JUnit totals verified: 6 tests, 0 failures, 0 errors, 0 skipped")
PY
