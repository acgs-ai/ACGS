#!/usr/bin/env bash
set -euo pipefail

use_vercel_curl=false
if [[ "${1:-}" == "--vercel-curl" ]]; then
  use_vercel_curl=true
  shift
fi

if [[ $# -ne 1 ]]; then
  echo "usage: $0 [--vercel-curl] https://your-vercel-deployment.example" >&2
  exit 2
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd -- "${script_dir}/.." && pwd)"
base_url="${1%/}"
vercel_scope="${VERCEL_SCOPE:-acgs}"
spa_path="${SPA_SMOKE_PATH:-/ordinary-marketing-route}"
paths=(
  "/AGENTS.md"
  "/CLAUDE.md"
  "/DESIGN.md"
  "/DEPLOY.md"
  "/nested/AGENTS.md"
  "/nested/CLAUDE.md"
  "/nested/DESIGN.md"
  "/nested/DEPLOY.md"
)

for path in "${paths[@]}"; do
  body_file="$(mktemp)"
  if [[ "${use_vercel_curl}" == "true" ]]; then
    status="$(
      cd "${project_dir}" &&
        vercel curl "${path}" --deployment "${base_url}" --scope "${vercel_scope}" -- \
          -sS -o "${body_file}" -w "%{http_code}" || true
    )"
    status="$(printf "%s" "${status}" | tail -n 1)"
  else
    status="$(
      curl -sS -o "${body_file}" -w "%{http_code}" "${base_url}${path}" || true
    )"
  fi
  if [[ "${status}" != "404" ]]; then
    echo "expected 404 for ${path}, got ${status}" >&2
    rm -f "${body_file}"
    exit 1
  fi
  if grep -qi '<div id="root"' "${body_file}"; then
    echo "${path} returned the SPA fallback body" >&2
    rm -f "${body_file}"
    exit 1
  fi
  rm -f "${body_file}"
done

body_file="$(mktemp)"
if [[ "${use_vercel_curl}" == "true" ]]; then
  status="$(
    cd "${project_dir}" &&
      vercel curl "${spa_path}" --deployment "${base_url}" --scope "${vercel_scope}" -- \
        -sS -o "${body_file}" -w "%{http_code}" || true
  )"
  status="$(printf "%s" "${status}" | tail -n 1)"
else
  status="$(
    curl -sS -o "${body_file}" -w "%{http_code}" "${base_url}${spa_path}" || true
  )"
fi
if [[ "${status}" != "200" ]]; then
  echo "expected 200 SPA fallback for ${spa_path}, got ${status}" >&2
  rm -f "${body_file}"
  exit 1
fi
if ! grep -qi '<div id="root"' "${body_file}"; then
  echo "${spa_path} did not return the SPA fallback body" >&2
  rm -f "${body_file}"
  exit 1
fi
rm -f "${body_file}"

echo "internal doc denial smoke passed for ${base_url}"
