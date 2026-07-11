# govern-zone monorepo top-level Makefile.
#
# Conventions:
#   - JS/TS surfaces go through Turborepo (`pnpm turbo run <task>`).
#   - Python surfaces go through uv workspace.
#   - Per-package gates are still authoritative; this is fan-out only.
#
# Commands:
#   make install      pnpm install + uv sync
#   make verify       lint + typecheck + test
#   make platform-readiness
#                    local readiness audit for deploy/platform proof
#   make release-evidence
#                    write local release-readiness evidence bundle
#   make verify-js-node24
#                    run acgi-ai readiness with the exact Node 24 toolchain
#   make build        produce all artifacts
#   make all          verify + build
#   make clean        drop build outputs + node_modules + .venv
#
# Per-package targets:
#   make lint-js / lint-py / test-js / test-py / build-js / build-py

PYTHON_PACKAGES := \
	packages/acgs-lite \
	packages/Acgs-Swarm \
	packages/gove-zone \
	packages/agent-bus-analyzer \
	packages/research-engine \
	acgs_governance_eval_mvp \
	acgs-cft-governance-pack

# Packages whose mypy run is STRICT and gating — clean today and part of buyer
# typecheck evidence. Every other [tool.mypy] package runs INFORMATIONAL (its
# findings are reported but do not fail the build), so legacy mypy noise is never
# silently conflated with strict-clean evidence. Promote a package here only once
# it is mypy-clean.
STRICT_TYPECHECK_PACKAGES := \
	packages/gove-zone \
	packages/agent-bus-analyzer \
	packages/research-engine

PNPM ?= pnpm
UV ?= uv

.PHONY: help all install build test lint typecheck verify clean openapi platform-readiness release-evidence verify-js-node24 production-blocker-evidence production-launch-preflight \
        build-js test-js lint-js typecheck-js \
        build-py test-py lint-py typecheck-py lint-docs \
        submodule-status verify-fresh

help:
	@echo "govern-zone monorepo"
	@echo ""
	@echo "  make install       Install JS + Python deps (pnpm + uv)"
	@echo "  make build         Build all packages (JS via turbo, Python via uv)"
	@echo "  make test          Run all tests"
	@echo "  make lint          Lint everything"
	@echo "  make typecheck     Type-check everything"
	@echo "  make verify        lint + typecheck + test"
	@echo "  make openapi       Export analyzer OpenAPI for the console"
	@echo "  make platform-readiness  Local platform/deploy-readiness audit"
	@echo "  make release-evidence    Write local release-readiness evidence bundle"
	@echo "  make verify-js-node24    Run acgi-ai readiness with exact Node 24 via fnm"
	@echo "  make lint-docs     Check root governance docs invariants"
	@echo "  make all           verify + build"
	@echo "  make clean         Drop node_modules, .venv, build artifacts"
	@echo "  make verify-fresh  clean + install + verify (CI-friendly)"
	@echo ""
	@echo "Per-stack:"
	@echo "  make {build,test,lint,typecheck}-js   JS only (turbo)"
	@echo "  make {build,test,lint,typecheck}-py   Python only (uv)"

all: verify build

install:
	$(PNPM) install
	$(UV) sync --all-extras

# ---- JS / TS surfaces (Turborepo) ----

build-js:
	$(PNPM) turbo run build

test-js:
	$(PNPM) turbo run test

lint-js:
	$(PNPM) turbo run lint

typecheck-js:
	$(PNPM) turbo run typecheck

verify-js-node24:
	./scripts/run_acgi_node24_gate.sh $(PNPM) -F acgi-ai run test:all

# ---- Python surfaces (uv workspace) ----

build-py:
	@for pkg in $(PYTHON_PACKAGES); do \
		if [ -f "$$pkg/pyproject.toml" ]; then \
			echo "==> build $$pkg"; \
			(cd "$$pkg" && $(UV) build) || exit 1; \
		fi; \
	done

test-py:
	@set -e; \
	$(MAKE) -C packages/acgs-lite test; \
	for pkg in packages/Acgs-Swarm packages/gove-zone packages/agent-bus-analyzer packages/research-engine acgs_governance_eval_mvp acgs-cft-governance-pack; do \
	  echo "==> test $$pkg"; \
	  (cd $$pkg && $(UV) run python -m pytest --import-mode=importlib) || exit $$?; \
	done

lint-py:
	@set -e; \
	$(UV) run ruff check packages/gove-zone packages/agent-bus-analyzer packages/research-engine acgs_governance_eval_mvp acgs-cft-governance-pack; \
	$(UV) run ruff format --check packages/gove-zone packages/agent-bus-analyzer packages/research-engine acgs_governance_eval_mvp acgs-cft-governance-pack; \
	$(MAKE) -C packages/acgs-lite lint; \
	(cd packages/Acgs-Swarm && $(UV) run ruff check src/)

# Two tiers, made explicit so buyer evidence never conflates them:
#   [STRICT]        package in STRICT_TYPECHECK_PACKAGES; mypy runs and a failure
#                   fails the build. This is the gated buyer typecheck evidence.
#   [INFORMATIONAL] every other package; mypy findings (or absence of config) are
#                   reported but never fail the build, so legacy mypy noise stays
#                   visible without masquerading as strict-clean evidence.
typecheck-py:
	@strict=""; informational=""; \
	for pkg in $(PYTHON_PACKAGES); do \
		[ -f "$$pkg/pyproject.toml" ] || continue; \
		extra=""; \
		if grep -q '^crypto = ' "$$pkg/pyproject.toml"; then extra="--extra crypto"; fi; \
		if grep -q '^files = ' "$$pkg/pyproject.toml"; then mypy_args=""; else mypy_args="src tests"; fi; \
		if ! grep -q '^\[tool\.mypy\]' "$$pkg/pyproject.toml"; then \
			echo "==> typecheck $$pkg [INFORMATIONAL — no [tool.mypy]; not gated]"; \
			informational="$$informational $$pkg"; \
		elif echo " $(STRICT_TYPECHECK_PACKAGES) " | grep -q " $$pkg "; then \
			echo "==> typecheck $$pkg [STRICT]"; \
			(cd "$$pkg" && $(UV) run $$extra mypy $$mypy_args) || exit $$?; \
			strict="$$strict $$pkg"; \
		else \
			echo "==> typecheck $$pkg [INFORMATIONAL — legacy mypy noise; not gated, excluded from strict typecheck evidence]"; \
			(cd "$$pkg" && $(UV) run $$extra mypy $$mypy_args) || echo "    (informational mypy findings above; not gating)"; \
			informational="$$informational $$pkg"; \
		fi; \
	done; \
	echo ""; \
	echo "typecheck summary (see STRICT_TYPECHECK_PACKAGES in Makefile):"; \
	echo "  STRICT (gated, clean):$$strict"; \
	echo "  INFORMATIONAL (reported, not gated):$$informational"

# ---- Root governance docs ----

lint-docs:
	python3 scripts/check_governance_stack_index.py
	$(MAKE) -C packages/ai-governance-research validate

# Root docs + examples smoke: claim-safety invariants + runnable example demos
# (each EXAMPLE_SCRIPTS demo is executed and must exit 0 with status:"pass").
test-docs:
	$(UV) run python -m pytest tests/docs --import-mode=importlib -q

platform-readiness:
	$(UV) run python scripts/platform_readiness_report.py

release-evidence:
	$(UV) run python scripts/build_release_evidence.py

production-blocker-evidence:
	$(UV) run python scripts/build_production_blocker_evidence.py

production-launch-preflight: release-evidence
	$(UV) run python scripts/production_launch_preflight.py --out dist-release-evidence/production-launch-preflight.json

# ---- Combined ----

build: build-js build-py
test: test-js test-py test-docs
lint: lint-js lint-py lint-docs
typecheck: typecheck-js typecheck-py

# Surface nested/private submodules that are absent so a missing repo is logged
# loudly instead of being silently skipped. Never fails: a private submodule that
# is not checked out (e.g. clinicalguard without SUBMODULE_TOKEN) is EXCLUDED from
# buyer evidence, not a hard error. Run as the first step of `verify` so the
# exclusion is visible before any gate output.
submodule-status:
	@echo "==> submodule status (nested repos)"; \
	for sub in packages/acgs-lite packages/Acgs-Swarm packages/clinicalguard; do \
		if [ -n "$$(ls -A "$$sub" 2>/dev/null)" ]; then \
			echo "    present  : $$sub"; \
		else \
			echo "    MISSING  : $$sub — nested repo not checked out (private submodules need SUBMODULE_TOKEN); EXCLUDED from buyer evidence"; \
		fi; \
	done

verify: submodule-status lint typecheck test

openapi:
	$(UV) run --package agent-bus-analyzer agent-bus-analyzer export-openapi --output acgi-ai/contracts/bus.openapi.json
	$(PNPM) -F acgi-ai exec biome format --write contracts/bus.openapi.json
	cp acgi-ai/contracts/bus.openapi.json acgi-ai/src/api/openapi.json
	$(PNPM) -F acgi-ai run gen:api

clean:
	-$(PNPM) turbo run clean 2>/dev/null
	rm -rf node_modules .venv .turbo
	find . -type d -name '__pycache__' -prune -exec rm -rf {} +
	find . -type d -name '.pytest_cache' -prune -exec rm -rf {} +
	find . -type d -name '.ruff_cache' -prune -exec rm -rf {} +

verify-fresh: clean install verify
