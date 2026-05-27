#!/usr/bin/env bash
# hygiene-bench.sh — Sealed benchmark for repo-structure-hygiene self-improvement loop.
#
# Computes a composite hygiene_score in [0,1] from four sub-components:
#   - lint_score        (35%)  ruff (Python) + biome (TS/JS) error counts
#   - agents_coverage   (25%)  AGENTS.md/CLAUDE.md presence in frozen warranting dirs
#   - dead_export_score (25%)  ruff F401/F811/F841 unused-import/var/redef counts
#   - duplicate_score   (15%)  groups of 2+ tracked files sharing SHA-256 (>=256B, allowlist exts)
#
# All denominators and the warranting-dirs set are FROZEN at first-run baseline
# in state/baseline_components.json (frozen:true). The bench refuses to overwrite
# the frozen baseline. Output is byte-identical across runs on the same git tree.
#
# Tool requirements (HARD): ruff, biome, sha256sum, find, git, jq, sort.
# Missing eslint/knip is intentional — biome is the project's actual TS/JS linter
# and ruff covers Python dead-export detection (F401/F811/F841). Substitution is
# documented in the handoff report.

set -uo pipefail
export LC_ALL=C
export LANG=C

# Resolve repo root from script location: <repo>/scripts/hygiene-bench.sh -> <repo>
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

BASELINE_FILE=".omc/self-improve/topics/repo-structure-hygiene/state/baseline_components.json"

emit_tool_missing() {
    # JSON to stderr, machine-parseable; non-zero exit.
    printf '{"error":"tool_missing","tool":"%s"}\n' "$1" >&2
    exit 1
}

emit_error() {
    printf '{"error":"%s","detail":"%s"}\n' "$1" "$2" >&2
    exit 1
}

# --- Tool availability gate (HARD fail) ---------------------------------------
for tool in ruff biome sha256sum find git jq sort; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        emit_tool_missing "${tool}"
    fi
done

if ! git rev-parse --git-dir >/dev/null 2>&1; then
    emit_error "not_a_git_repo" "${REPO_ROOT}"
fi

# --- Helper: list tracked files (sorted, deterministic) -----------------------
tracked_files() {
    git ls-files -z | tr '\0' '\n' | LC_ALL=C sort
}

count_tracked_files() {
    tracked_files | wc -l | tr -d ' '
}

# --- Component: lint errors ---------------------------------------------------
# Python via ruff (default rule set, all tracked dirs from repo root).
# TS/JS via biome (acgi-ai project, mirroring package.json `lint` scoping).
# Returns total error count (Python ruff diagnostics + biome errors).
compute_lint_errors() {
    local py_count=0
    local ts_count=0

    # ruff: --output-format=json prints a JSON array even with zero issues.
    # ruff exits non-zero when issues exist; capture stdout regardless.
    local ruff_json
    ruff_json="$(ruff check . --output-format=json --exit-zero 2>/dev/null || true)"
    if [[ -z "${ruff_json}" ]]; then
        ruff_json="[]"
    fi
    py_count="$(printf '%s' "${ruff_json}" | jq 'length' 2>/dev/null || echo 0)"
    [[ -z "${py_count}" ]] && py_count=0

    # biome: scoped to acgi-ai with its own biome.json. Mirror package.json `lint`.
    if [[ -d "acgi-ai" && -f "acgi-ai/biome.json" ]]; then
        local biome_json
        # biome emits an experimental-warning to stderr — we discard it.
        biome_json="$(cd acgi-ai && biome check --reporter=json \
            src index.html package.json vite.config.ts \
            tsconfig.json tsconfig.app.json tsconfig.node.json biome.json \
            2>/dev/null || true)"
        if [[ -z "${biome_json}" ]]; then
            biome_json='{"summary":{"errors":0,"warnings":0}}'
        fi
        # Count errors only (warnings excluded — keeps signal tight).
        ts_count="$(printf '%s' "${biome_json}" | jq '.summary.errors // 0' 2>/dev/null || echo 0)"
        [[ -z "${ts_count}" ]] && ts_count=0
    fi

    echo $((py_count + ts_count))
}

# --- Component: dead exports (Python only via ruff) ---------------------------
# F401: unused imports, F811: redefinition of unused, F841: unused local
compute_dead_exports() {
    local ruff_json
    ruff_json="$(ruff check . --select F401,F811,F841 --output-format=json --exit-zero 2>/dev/null || true)"
    if [[ -z "${ruff_json}" ]]; then
        ruff_json="[]"
    fi
    local n
    n="$(printf '%s' "${ruff_json}" | jq 'length' 2>/dev/null || echo 0)"
    [[ -z "${n}" ]] && n=0
    echo "${n}"
}

# --- Component: duplicate groups ---------------------------------------------
# 2+ tracked files with identical SHA-256, file size >= 256, ext in allowlist.
# "Duplicate groups" = number of distinct hashes with >= 2 files.
compute_duplicate_groups() {
    local exts_re='\.(ts|tsx|js|jsx|py|md|sh|json|yaml|yml|toml)$'
    local hashes
    # tracked files matching ext, exists, size >= 256 -> sha256, then count groups.
    hashes="$(
        tracked_files \
        | grep -E "${exts_re}" \
        | while IFS= read -r f; do
            [[ -f "${f}" ]] || continue
            local sz
            sz="$(stat -c '%s' -- "${f}" 2>/dev/null || echo 0)"
            [[ "${sz}" -ge 256 ]] || continue
            sha256sum -- "${f}" 2>/dev/null
          done \
        | awk '{print $1}' \
        | LC_ALL=C sort \
        | uniq -c \
        | awk '$1 >= 2 {n++} END {print n+0}'
    )"
    [[ -z "${hashes}" ]] && hashes=0
    echo "${hashes}"
}

# --- Component: warranting dirs (frozen at baseline) --------------------------
# A dir warrants AGENTS.md/CLAUDE.md if it contains >=1 tracked source file
# (*.ts *.tsx *.js *.jsx *.py *.sh) at any depth, depth>=1 from repo root,
# and is NOT inside .omc/, node_modules/, dist/, build/, coverage/, __pycache__/.
compute_warranting_dirs() {
    local src_re='\.(ts|tsx|js|jsx|py|sh)$'
    local exclude_re='(^|/)(\.omc|node_modules|dist|build|coverage|__pycache__)(/|$)'

    tracked_files \
        | grep -E "${src_re}" \
        | while IFS= read -r f; do
            local d
            d="$(dirname -- "${f}")"
            [[ "${d}" == "." ]] && continue
            # Walk up emitting all ancestor dirs (depth>=1 from repo root).
            while [[ "${d}" != "." && "${d}" != "/" ]]; do
                printf '%s\n' "${d}"
                d="$(dirname -- "${d}")"
            done
        done \
        | LC_ALL=C sort -u \
        | grep -Ev "${exclude_re}" \
        || true
}

# --- Component: AGENTS.md numerator -------------------------------------------
# A frozen warranting dir "has docs" if it contains a tracked file named
# AGENTS.md or CLAUDE.md at depth <=1 inside it (i.e. directly in dir or one
# level deeper), >=200 bytes, and contains at least one '#' heading line.
dir_has_docs() {
    local d="$1"
    # Find candidates among tracked files at depth <=1
    local candidates
    candidates="$(tracked_files \
        | awk -v d="${d}" 'BEGIN{n=split(d, _, "/")} {
            f=$0
            if (index(f, d "/") == 1) {
                rest = substr(f, length(d)+2)
                # Count "/" in rest -> depth-1 from d. Allow 0 (direct) or 1.
                slashes = gsub("/", "/", rest)
                if (slashes <= 1) {
                    base = rest
                    sub(".*/", "", base)
                    if (base == "AGENTS.md" || base == "CLAUDE.md") print f
                }
            }
        }')"
    [[ -z "${candidates}" ]] && return 1
    while IFS= read -r f; do
        [[ -z "${f}" ]] && continue
        [[ -f "${f}" ]] || continue
        local sz
        sz="$(stat -c '%s' -- "${f}" 2>/dev/null || echo 0)"
        [[ "${sz}" -ge 200 ]] || continue
        if grep -qE '^#' -- "${f}" 2>/dev/null; then
            return 0
        fi
    done <<< "${candidates}"
    return 1
}

# --- Baseline read/write ------------------------------------------------------
read_baseline_field() {
    jq -r --arg k "$1" '.[$k]' "${BASELINE_FILE}"
}

read_baseline_array() {
    jq -r --arg k "$1" '.[$k][]' "${BASELINE_FILE}"
}

write_baseline_if_absent() {
    if [[ -f "${BASELINE_FILE}" ]]; then
        local frozen
        frozen="$(jq -r '.frozen // false' "${BASELINE_FILE}" 2>/dev/null || echo false)"
        if [[ "${frozen}" == "true" ]]; then
            return 0  # already frozen, just read
        fi
        # Exists but not frozen — refuse to overwrite to be safe.
        emit_error "baseline_unfrozen_exists" "${BASELINE_FILE}"
    fi

    mkdir -p "$(dirname "${BASELINE_FILE}")"

    local lint_errors dead_exports dup_groups tracked_count head_sha now
    lint_errors="$(compute_lint_errors)"
    dead_exports="$(compute_dead_exports)"
    dup_groups="$(compute_duplicate_groups)"
    tracked_count="$(count_tracked_files)"
    head_sha="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
    now="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

    # Build warranting dirs JSON array (sorted).
    local warranting_json
    warranting_json="$(compute_warranting_dirs | jq -R . | jq -s 'sort | unique')"

    jq -n -S \
        --argjson le "${lint_errors}" \
        --argjson de "${dead_exports}" \
        --argjson dg "${dup_groups}" \
        --argjson tc "${tracked_count}" \
        --arg sha "${head_sha}" \
        --arg ts "${now}" \
        --argjson wd "${warranting_json}" \
        '{
            frozen: true,
            lint_errors: $le,
            dead_exports: $de,
            duplicate_groups: $dg,
            frozen_warranting_dirs: $wd,
            tracked_files_count: $tc,
            frozen_at_commit: $sha,
            frozen_at: $ts
        }' > "${BASELINE_FILE}"
}

# --- Main: emit per-run JSON --------------------------------------------------
write_baseline_if_absent

# Read frozen denominators
B_LINT="$(jq -r '.lint_errors' "${BASELINE_FILE}")"
B_DEAD="$(jq -r '.dead_exports' "${BASELINE_FILE}")"
B_DUP="$(jq -r '.duplicate_groups' "${BASELINE_FILE}")"

# Compute current raw counts
N_LINT="$(compute_lint_errors)"
N_DEAD="$(compute_dead_exports)"
N_DUP="$(compute_duplicate_groups)"
N_TRACKED="$(count_tracked_files)"

# AGENTS.md coverage over the FROZEN warranting set
COVERED=0
TOTAL_FROZEN=0
while IFS= read -r d; do
    [[ -z "${d}" ]] && continue
    TOTAL_FROZEN=$((TOTAL_FROZEN + 1))
    if dir_has_docs "${d}"; then
        COVERED=$((COVERED + 1))
    fi
done < <(read_baseline_array "frozen_warranting_dirs")

# typecheck guard (suppressed when no node_modules)
TYPECHECK_STATUS="skipped"
if [[ -d "acgi-ai/node_modules" ]]; then
    if (cd acgi-ai && pnpm exec tsc -b --noEmit >/dev/null 2>&1); then
        TYPECHECK_STATUS="pass"
    else
        TYPECHECK_STATUS="fail"
    fi
fi

# --- Score formulas (clamped to [0,1]) ----------------------------------------
# All scores: when baseline raw is 0, clean tree -> 1.0; otherwise
# 1 - min(1, current/max(1, baseline)).
score_ratio() {
    # args: current baseline
    local cur="$1" base="$2"
    awk -v c="${cur}" -v b="${base}" 'BEGIN{
        denom = (b < 1 ? 1 : b)
        ratio = c / denom
        if (ratio > 1) ratio = 1
        s = 1 - ratio
        if (s < 0) s = 0
        if (s > 1) s = 1
        printf "%.4f", s
    }'
}

score_coverage() {
    local cov="$1" tot="$2"
    awk -v c="${cov}" -v t="${tot}" 'BEGIN{
        if (t <= 0) { printf "%.4f", 1.0; exit }
        s = c / t
        if (s < 0) s = 0
        if (s > 1) s = 1
        printf "%.4f", s
    }'
}

LINT_SCORE="$(score_ratio "${N_LINT}" "${B_LINT}")"
DEAD_SCORE="$(score_ratio "${N_DEAD}" "${B_DEAD}")"
DUP_SCORE="$(score_ratio "${N_DUP}" "${B_DUP}")"
AGENTS_SCORE="$(score_coverage "${COVERED}" "${TOTAL_FROZEN}")"

HYGIENE="$(awk -v l="${LINT_SCORE}" -v a="${AGENTS_SCORE}" -v d="${DEAD_SCORE}" -v u="${DUP_SCORE}" \
    'BEGIN{ printf "%.4f", 0.35*l + 0.25*a + 0.25*d + 0.15*u }')"

# --- Emit final JSON (sorted keys, no timestamps) -----------------------------
jq -n -S \
    --argjson hyg "${HYGIENE}" \
    --argjson ls "${LINT_SCORE}" \
    --argjson as "${AGENTS_SCORE}" \
    --argjson ds "${DEAD_SCORE}" \
    --argjson us "${DUP_SCORE}" \
    --argjson nl "${N_LINT}" \
    --argjson cov "${COVERED}" \
    --argjson tot "${TOTAL_FROZEN}" \
    --argjson nd "${N_DEAD}" \
    --argjson nu "${N_DUP}" \
    --argjson nt "${N_TRACKED}" \
    --arg ts "${TYPECHECK_STATUS}" \
    '{
        hygiene_score: $hyg,
        components: {
            lint_score: $ls,
            agents_coverage: $as,
            dead_export_score: $ds,
            duplicate_score: $us
        },
        raw: {
            lint_errors: $nl,
            agents_dirs_covered: $cov,
            agents_dirs_total_frozen: $tot,
            dead_exports: $nd,
            duplicate_groups: $nu,
            tracked_files_count: $nt,
            typecheck_status: $ts
        },
        weights: {"lint":0.35,"agents":0.25,"dead":0.25,"dup":0.15}
    }'
