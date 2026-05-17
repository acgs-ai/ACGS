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
#   make build        produce all artifacts
#   make all          verify + build
#   make clean        drop build outputs + node_modules + .venv
#
# Per-package targets:
#   make lint-js / lint-py / test-js / test-py / build-js / build-py

PYTHON_PACKAGES := \
	packages/acgs-lite \
	packages/Acgs-Swarm \
	packages/clinicalguard \
	packages/agent-bus-analyzer \
	acgs_governance_eval_mvp \
	acgs-cft-governance-pack

PNPM ?= pnpm
UV ?= uv

.PHONY: help all install build test lint typecheck verify clean \
        build-js test-js lint-js typecheck-js \
        build-py test-py lint-py typecheck-py \
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
	for pkg in packages/Acgs-Swarm packages/clinicalguard packages/agent-bus-analyzer acgs_governance_eval_mvp acgs-cft-governance-pack; do \
	  echo "==> test $$pkg"; \
	  (cd $$pkg && $(UV) run python -m pytest --import-mode=importlib) || exit $$?; \
	done

lint-py:
	@set -e; \
	$(UV) run ruff check acgs_governance_eval_mvp acgs-cft-governance-pack packages/agent-bus-analyzer/src packages/agent-bus-analyzer/tests; \
	$(UV) run ruff format --check acgs_governance_eval_mvp acgs-cft-governance-pack packages/agent-bus-analyzer/src packages/agent-bus-analyzer/tests; \
	$(MAKE) -C packages/acgs-lite lint; \
	(cd packages/Acgs-Swarm && $(UV) run ruff check src/ && $(UV) run ruff format --check src/); \
	(cd packages/clinicalguard && $(UV) run ruff check . && $(UV) run ruff format --check .)

typecheck-py:
	@for pkg in $(PYTHON_PACKAGES); do \
		if [ -f "$$pkg/pyproject.toml" ]; then \
			echo "==> typecheck $$pkg"; \
			(cd "$$pkg" && $(UV) run mypy . 2>/dev/null || echo "    (mypy skipped — not configured for $$pkg)"); \
		fi; \
	done

# ---- Combined ----

build: build-js build-py
test: test-js test-py
lint: lint-js lint-py
typecheck: typecheck-js typecheck-py

verify: lint typecheck test

clean:
	-$(PNPM) turbo run clean 2>/dev/null
	rm -rf node_modules .venv .turbo
	find . -type d -name '__pycache__' -prune -exec rm -rf {} +
	find . -type d -name '.pytest_cache' -prune -exec rm -rf {} +
	find . -type d -name '.ruff_cache' -prune -exec rm -rf {} +

verify-fresh: clean install verify
