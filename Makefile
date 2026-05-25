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
#   make production-launch-preflight
#                    summarize whether release evidence is ready or blocked
#   make production-blocker-evidence
#                    refresh deployment-blocked production evidence packet
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
	acgs_governance_eval_mvp \
	acgs-cft-governance-pack

PNPM ?= pnpm
UV ?= uv

.PHONY: help all install build test lint typecheck verify clean openapi platform-readiness release-evidence production-launch-preflight production-blocker-evidence verify-js-node24 \
        build-js test-js lint-js typecheck-js \
        build-py test-py lint-py typecheck-py lint-docs \
        verify-fresh

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
	@echo "  make production-launch-preflight  Summarize ready/blocked launch state"
	@echo "  make production-blocker-evidence  Refresh deployment-blocked evidence packet"
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
	bash scripts/run_acgi_node24_gate.sh $(PNPM) -F acgi-ai run test:all

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
	for pkg in packages/Acgs-Swarm packages/gove-zone packages/agent-bus-analyzer acgs_governance_eval_mvp acgs-cft-governance-pack; do \
	  echo "==> test $$pkg"; \
	  (cd $$pkg && $(UV) run python -m pytest --import-mode=importlib) || exit $$?; \
	done

lint-py:
	@set -e; \
	$(UV) run ruff check packages/gove-zone packages/agent-bus-analyzer acgs_governance_eval_mvp acgs-cft-governance-pack; \
	$(UV) run ruff format --check packages/gove-zone packages/agent-bus-analyzer acgs_governance_eval_mvp acgs-cft-governance-pack; \
	$(MAKE) -C packages/acgs-lite lint; \
	(cd packages/Acgs-Swarm && $(UV) run ruff check src/)

typecheck-py:
	@for pkg in $(PYTHON_PACKAGES); do \
		if [ -f "$$pkg/pyproject.toml" ]; then \
			if grep -q '^\[tool\.mypy\]' "$$pkg/pyproject.toml"; then \
				echo "==> typecheck $$pkg"; \
				if grep -q '^files = ' "$$pkg/pyproject.toml"; then \
					(cd "$$pkg" && $(UV) run mypy) || exit $$?; \
				else \
					(cd "$$pkg" && $(UV) run mypy src tests) || exit $$?; \
				fi; \
			else \
				echo "==> typecheck $$pkg"; \
				echo "    (mypy skipped — not configured for $$pkg)"; \
			fi; \
		fi; \
	done

# ---- Root governance docs ----

lint-docs:
	python3 scripts/check_governance_stack_index.py

platform-readiness:
	$(UV) run python scripts/platform_readiness_report.py

release-evidence:
	$(UV) run python scripts/build_release_evidence.py

production-launch-preflight: release-evidence
	$(UV) run python scripts/production_launch_preflight.py --manifest dist-release-evidence/manifest.json

production-blocker-evidence:
	$(UV) run python scripts/build_production_blocker_evidence.py

# ---- Combined ----

build: build-js build-py
test: test-js test-py
lint: lint-js lint-py lint-docs
typecheck: typecheck-js typecheck-py

verify: lint typecheck test

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
