#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: scripts/postdeploy-verify.sh https://console-origin.example

Verifies the deployed console origin against DEPLOY.md / PLAN.md gates:
  - strict security headers on the entry document
  - /healthz returns ok=true, expected served_hash, and deployed build_id
  - live deployed assets and the local production bundle have no inline style= attributes
  - live deployed assets and the local production bundle have no unexpected third-party URLs
  - live deployed JS assets do not contain demo-auth sentinels

Environment:
  EXPECTED_SERVED_HASH  expected /healthz served_hash (default: 608508a9bd224290)
  EXPECTED_BUILD_ID     exact /healthz build_id to require (optional; if unset, must be non-empty and not "local")
  DIST_DIR              production bundle directory to scan (default: dist)
USAGE
}

if [[ "${1:-}" == "--" ]]; then
  shift
fi

if [[ $# -ne 1 ]]; then
  usage
  exit 2
fi

base_url="${1%/}"
expected_served_hash="${EXPECTED_SERVED_HASH:-608508a9bd224290}"
expected_build_id="${EXPECTED_BUILD_ID:-}"
dist_dir="${DIST_DIR:-dist}"
failures=()
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

fail() {
  failures+=("$1")
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "missing required command: $1"
  fi
}

require_cmd curl
require_cmd python3

headers_file="${tmp_dir}/headers.txt"
body_file="${tmp_dir}/body.html"
if ! curl -fsS -D "${headers_file}" -o "${body_file}" "${base_url}/"; then
  fail "failed to fetch console entry document: ${base_url}/"
else
  tr -d '\r' <"${headers_file}" >"${headers_file}.clean"
  mv "${headers_file}.clean" "${headers_file}"
fi

header_value() {
  local name="$1"
  awk -v wanted="${name,,}" '
    BEGIN { FS=":" }
    tolower($1) == wanted {
      sub(/^[^:]*:[[:space:]]*/, "", $0)
      print $0
      exit
    }
  ' "${headers_file}" 2>/dev/null || true
}

check_header_present() {
  local name="$1"
  local value
  value="$(header_value "$name")"
  if [[ -z "${value}" ]]; then
    fail "missing response header: ${name}"
  fi
}

if [[ -f "${headers_file}" ]]; then
  check_header_present "Strict-Transport-Security"
  check_header_present "Content-Security-Policy"
  check_header_present "X-Content-Type-Options"
  check_header_present "X-Frame-Options"
  check_header_present "Referrer-Policy"

  csp="$(header_value "Content-Security-Policy")"
  if [[ -n "${csp}" ]]; then
    [[ "${csp}" == *"default-src 'self'"* ]] || fail "CSP must include default-src 'self'"
    [[ "${csp}" == *"script-src 'self'"* ]] || fail "CSP must include script-src 'self'"
    [[ "${csp}" == *"style-src 'self'"* ]] || fail "CSP must include style-src 'self'"
    [[ "${csp}" == *"frame-ancestors 'none'"* ]] || fail "CSP must include frame-ancestors 'none'"
    [[ "${csp}" != *"'unsafe-inline'"* ]] || fail "CSP must not allow unsafe-inline"
  fi

  [[ "$(header_value "X-Frame-Options")" == *"DENY"* ]] || fail "X-Frame-Options must be DENY"
  [[ "$(header_value "Referrer-Policy")" == *"no-referrer"* ]] || fail "Referrer-Policy must be no-referrer"
fi

live_assets_dir="${tmp_dir}/live-assets"
asset_list="${tmp_dir}/live-assets.txt"
mkdir -p "${live_assets_dir}"
if [[ -f "${body_file}" ]]; then
  BODY_FILE="${body_file}" BASE_URL="${base_url}" python3 - <<'PY' >"${asset_list}" || fail "failed to parse live asset URLs from entry document"
from html.parser import HTMLParser
import os
from pathlib import Path
from urllib.parse import urlparse

body = Path(os.environ["BODY_FILE"]).read_text(encoding="utf-8", errors="ignore")
base = urlparse(os.environ["BASE_URL"])
assets: set[str] = set()


def normalize(value: str) -> str | None:
    parsed = urlparse(value)
    if parsed.scheme or parsed.netloc:
        if parsed.scheme not in {"http", "https"} or parsed.netloc != base.netloc:
            return None
        path = parsed.path
    else:
        path = value
    if not path.startswith("/assets/"):
        return None
    return path


class AssetParser(HTMLParser):
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if name not in {"src", "href"} or not value:
                continue
            asset = normalize(value)
            if asset:
                assets.add(asset)


AssetParser().feed(body)
for asset in sorted(assets):
    print(asset)
PY
  if [[ ! -s "${asset_list}" ]]; then
    fail "entry document did not reference live /assets resources"
  else
    while IFS= read -r asset_path; do
      [[ -n "${asset_path}" ]] || continue
      output_path="${live_assets_dir}${asset_path}"
      mkdir -p "$(dirname "${output_path}")"
      if ! curl -fsS -o "${output_path}" "${base_url}${asset_path}"; then
        fail "failed to fetch live deployed asset: ${asset_path}"
      fi
    done <"${asset_list}"
  fi
fi

if [[ -d "${live_assets_dir}/assets" ]]; then
  if grep -R -n --include='*.html' --include='*.js' --include='*.css' 'style=' "${live_assets_dir}" >"${tmp_dir}/live-inline-style.txt" 2>/dev/null; then
    fail "live deployed asset contains inline style= attributes: $(head -1 "${tmp_dir}/live-inline-style.txt")"
  fi

  SCAN_ROOT="${live_assets_dir}" python3 - <<'PY' >"${tmp_dir}/live-demo-auth.txt" 2>&1 || fail "live deployed asset contains demo auth sentinel: $(head -1 "${tmp_dir}/live-demo-auth.txt")"
import os
import sys
from pathlib import Path

root = Path(os.environ["SCAN_ROOT"])
for path in sorted(root.rglob("*.js")):
    text = path.read_text(encoding="utf-8", errors="ignore")
    for sentinel in ("acgs.console.session", "createSession is development-only"):
        if sentinel in text:
            print(f"{path}: demo auth sentinel {sentinel}", file=sys.stderr)
            sys.exit(1)
    offset = text.find("sessionStorage")
    while offset != -1:
        context = text[max(0, offset - 320): offset + 320]
        if (
            "tsr-scroll-restoration" not in context
            and "[ts-router] Could not persist scroll restoration state" not in context
        ):
            print(f"{path}: unexpected sessionStorage use outside TanStack Router scroll restoration", file=sys.stderr)
            sys.exit(1)
        offset = text.find("sessionStorage", offset + len("sessionStorage"))
PY

  SCAN_ROOT="${live_assets_dir}" python3 - <<'PY' || fail "live deployed assets contain unexpected third-party URLs"
import os
import re
import sys
from pathlib import Path

root = Path(os.environ["SCAN_ROOT"])
allowed = re.compile(r"^https?://(www\.w3\.org/|react\.dev/errors/|localhost(?::\d+)?(?:/|$)|127\.0\.0\.1(?::\d+)?(?:/|$))")
url_re = re.compile(r"https?://[^\s\"'`<>),]+")
violations: list[str] = []
for path in sorted(root.rglob("*")):
    if not path.is_file() or path.suffix not in {".html", ".js", ".css"}:
        continue
    text = path.read_text(encoding="utf-8", errors="ignore")
    for match in sorted(set(url_re.findall(text))):
        if not allowed.match(match):
            violations.append(f"{path}: {match}")

if violations:
    print("unexpected third-party URL literals in live deployed assets:", file=sys.stderr)
    for item in violations[:20]:
        print(f"- {item}", file=sys.stderr)
    sys.exit(1)
PY
fi

health_body=""
if ! health_body="$(curl -fsS "${base_url}/healthz")"; then
  fail "failed to fetch ${base_url}/healthz"
else
  HEALTH_BODY="${health_body}" \
  EXPECTED_SERVED_HASH="${expected_served_hash}" \
  EXPECTED_BUILD_ID="${expected_build_id}" \
  python3 - <<'PY' || fail "/healthz JSON did not satisfy served_hash/build_id contract"
import json
import os
import sys

body = os.environ["HEALTH_BODY"]
expected_hash = os.environ["EXPECTED_SERVED_HASH"]
expected_build = os.environ.get("EXPECTED_BUILD_ID", "")
try:
    payload = json.loads(body)
except json.JSONDecodeError as exc:
    print(f"invalid healthz JSON: {exc}", file=sys.stderr)
    sys.exit(1)

errors: list[str] = []
if payload.get("ok") is not True:
    errors.append("ok must be true")
if payload.get("served_hash") != expected_hash:
    errors.append(
        f"served_hash mismatch: expected {expected_hash}, got {payload.get('served_hash')!r}"
    )
build_id = payload.get("build_id")
if expected_build:
    if build_id != expected_build:
        errors.append(f"build_id mismatch: expected {expected_build}, got {build_id!r}")
elif not build_id or build_id == "local":
    errors.append("build_id must be non-empty and not the local fallback")

if errors:
    for error in errors:
        print(error, file=sys.stderr)
    sys.exit(1)
PY
fi

# Console deep-link fail-closed probe -- DEPLOY.md section 7 / Caddyfile @console_routes.
# Production twin of the Docker `smoke:bus-proxy` console assertion: against a live
# console origin, /console must sit behind the forward_auth wall and return a non-2xx
# status (an IdP/login redirect, 401/403, or a 502 when the authorizer is unreachable),
# never a 200 SPA shell served by the try_files fallback. curl does not follow redirects
# here (no -L) so a 3xx login redirect is observed as the fail-closed wall, not a page.
console_status="$(curl -sS -o /dev/null -w '%{http_code}' "${base_url}/console" || echo 000)"
if [[ "${console_status}" == "000" ]]; then
  fail "failed to probe console deep link: ${base_url}/console"
elif [[ "${console_status}" -ge 200 && "${console_status}" -lt 300 ]]; then
  fail "console fail-closed breach: ${base_url}/console returned ${console_status} (expected non-2xx auth wall, not a 200 SPA page)"
fi

if [[ ! -d "${dist_dir}/assets" ]]; then
  fail "missing production bundle assets directory: ${dist_dir}/assets"
else
  if grep -R -n --include='*.html' --include='*.js' --include='*.css' 'style=' "${dist_dir}" >/tmp/gove-zone-postdeploy-inline-style.$$ 2>/dev/null; then
    fail "production bundle contains inline style= attributes: $(head -1 /tmp/gove-zone-postdeploy-inline-style.$$)"
  fi
  rm -f /tmp/gove-zone-postdeploy-inline-style.$$

  DIST_DIR="${dist_dir}" python3 - <<'PY' || fail "production bundle contains unexpected third-party URLs"
import os
import re
import sys
from pathlib import Path

root = Path(os.environ["DIST_DIR"])
# Static namespace / diagnostics strings emitted by React or SVG/CSS tooling.
# These are inert literals, not operational third-party origins contacted by
# the console. Everything else is blocked until explicitly reviewed.
allowed = re.compile(r"^https?://(www\.w3\.org/|react\.dev/errors/)")
url_re = re.compile(r"https?://[^\s\"'`<>),]+")
violations: list[str] = []
for path in [root / "index.html", *sorted((root / "assets").glob("*"))]:
    if not path.is_file() or path.suffix not in {".html", ".js", ".css"}:
        continue
    text = path.read_text(encoding="utf-8", errors="ignore")
    for match in sorted(set(url_re.findall(text))):
        if not allowed.match(match):
            violations.append(f"{path}: {match}")

if violations:
    print("unexpected third-party URL literals:", file=sys.stderr)
    for item in violations[:20]:
        print(f"- {item}", file=sys.stderr)
    sys.exit(1)
PY
fi

if (( ${#failures[@]} > 0 )); then
  echo "postdeploy verification failed for ${base_url}:" >&2
  for failure in "${failures[@]}"; do
    echo "- ${failure}" >&2
  done
  exit 1
fi

echo "postdeploy verification passed for ${base_url}"
