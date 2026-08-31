.PHONY: help secret-boundary-check check makefile-regression lint typecheck test build migration integration restart-test log-scan accessibility real-persistence audit residual verify service-check service-lint service-typecheck service-test service-build service-verify service-run service-worker-once db-up db-down migrate

REPO_ROOT := ../..
SERVICE_MANIFEST := service/pyproject.toml
WEB_MANIFEST := web/package.json
COMPOSE_FILE := compose.yaml
MIGRATION_DIR := service/migrations/versions
E2E_TEST := web/tests/e2e/primary-journey.spec.ts
MIGRATION_TEST := service/tests/test_migrations.py
INTEGRATION_DIR := service/tests/integration
RESTART_TESTS := service/tests/test_ingestion.py service/tests/test_purge.py
LOG_TEST := service/tests/test_logging_privacy.py
ACCESSIBILITY_TEST := web/tests/accessibility.spec.ts

help:
	@echo "Second Brain v0.1 planning scaffold"
	@echo "Targets intentionally fail until implementation surfaces exist."
	@echo "  secret-boundary-check prove Compose local secrets are Git-ignored"
	@echo "  check      prove required manifests and proof surfaces exist"
	@echo "  lint       run service and web lint gates"
	@echo "  typecheck  run service and web type checks"
	@echo "  test       run service, web, and browser tests"
	@echo "  build      build the service and web application"
	@echo "  migration  prove empty-DB relations, policies, downgrade/upgrade"
	@echo "  integration prove API/DB/worker wiring"
	@echo "  restart-test prove durable worker recovery without duplication"
	@echo "  log-scan   prove seeded private text is absent from logs"
	@echo "  accessibility run keyboard and viewport accessibility checks"
	@echo "  real-persistence run Playwright without mocked persistence"
	@echo "  audit      audit production web dependencies"
	@echo "  residual   reject forbidden web response casts and upload copies"
	@echo "  service-verify verify the Phase 2 backend foundation"
	@echo "  verify     run every required local acceptance gate"

db-up:
	podman compose -f compose.yaml up -d postgres

db-down:
	podman compose -f compose.yaml down

service-run: service-check
	cd service && uv run python -m second_brain.launcher

service-worker-once: service-check
	cd service && uv run python -m second_brain.worker --once

migrate: service-check
	cd service && uv run alembic upgrade head

service-check:
	@test -f $(SERVICE_MANIFEST) || { echo "MISSING: $(SERVICE_MANIFEST)" >&2; exit 1; }
	@test -f service/alembic.ini || { echo "MISSING: service/alembic.ini" >&2; exit 1; }
	@test -d $(MIGRATION_DIR) || { echo "MISSING: $(MIGRATION_DIR)" >&2; exit 1; }
	@test -f $(COMPOSE_FILE) || { echo "MISSING: $(COMPOSE_FILE)" >&2; exit 1; }

service-lint: service-check
	cd service && uv run ruff check .
	cd service && uv run ruff format --check .

service-typecheck: service-check
	cd service && uv run mypy src tests migrations

service-test: service-check
	cd service && uv run pytest -q

service-build: service-check
	cd service && uv build

service-verify: service-lint service-typecheck service-test service-build

secret-boundary-check:
	@git -C $(REPO_ROOT) check-ignore -q apps/second-brain/.env.compose.local || { echo "ERROR: apps/second-brain/.env.compose.local is not Git-ignored; refusing to continue" >&2; exit 1; }

check: secret-boundary-check
	@test -f $(SERVICE_MANIFEST) || { echo "MISSING: $(SERVICE_MANIFEST)" >&2; exit 1; }
	@test -f $(WEB_MANIFEST) || { echo "MISSING: $(WEB_MANIFEST)" >&2; exit 1; }
	@test -f $(COMPOSE_FILE) || { echo "MISSING: $(COMPOSE_FILE)" >&2; exit 1; }
	@test -d $(MIGRATION_DIR) || { echo "MISSING: $(MIGRATION_DIR)" >&2; exit 1; }
	@test -f $(E2E_TEST) || { echo "MISSING: $(E2E_TEST)" >&2; exit 1; }
	@test -f $(MIGRATION_TEST) || { echo "MISSING: $(MIGRATION_TEST)" >&2; exit 1; }
	@test -d $(INTEGRATION_DIR) || { echo "MISSING: $(INTEGRATION_DIR)" >&2; exit 1; }
	@for path in $(RESTART_TESTS); do \
		test -f "$$path" || { echo "MISSING: $$path" >&2; exit 1; }; \
	done
	@test -f $(LOG_TEST) || { echo "MISSING: $(LOG_TEST)" >&2; exit 1; }
	@test -f $(ACCESSIBILITY_TEST) || { echo "MISSING: $(ACCESSIBILITY_TEST)" >&2; exit 1; }

makefile-regression:
	@dry_run="$$( $(MAKE) --no-print-directory -n check )"; \
		if printf '%s\n' "$$dry_run" | grep -Fq 'test -f  ||'; then \
			echo "ERROR: make -n check contains an empty test -f path" >&2; exit 1; \
		fi; \
		for path in $(RESTART_TESTS); do \
			printf '%s\n' "$$dry_run" | grep -Fq "$$path" || \
				{ echo "ERROR: make -n check does not validate $$path" >&2; exit 1; }; \
		done; \
		verify_run="$$( $(MAKE) --no-print-directory -n verify )"; \
		build_line="$$(printf '%s\n' "$$verify_run" | grep -n -m1 'pnpm --dir web build' | cut -d: -f1)"; \
		browser_line="$$(printf '%s\n' "$$verify_run" | grep -n -m1 'playwright test$$' | cut -d: -f1)"; \
		test -n "$$build_line" -a -n "$$browser_line" -a "$$build_line" -lt "$$browser_line" || \
			{ echo "ERROR: make verify does not build web before browser tests" >&2; exit 1; }

lint: check
	cd service && uv run ruff check .
	cd service && uv run ruff format --check .
	fnm exec --using 24 pnpm --dir web lint

typecheck: check
	cd service && uv run mypy src tests migrations
	fnm exec --using 24 pnpm --dir web typecheck

test: build
	cd service && uv run pytest -q
	fnm exec --using 24 pnpm --dir web test
	fnm exec --using 24 pnpm --dir web exec playwright test

build: check
	cd service && uv build
	fnm exec --using 24 pnpm --dir web build

migration: service-check
	@echo "Guarded migration harness only: disposable second_brain_test_* DB on known loopback host"
	cd service && uv run pytest -q tests/test_migrations.py

integration: check
	cd service && uv run pytest -q tests/integration

restart-test: service-check
	cd service && uv run pytest -q \
		tests/test_ingestion.py::test_url_partial_stage_is_reconciled_after_worker_restart \
		tests/test_ingestion.py::test_restart_from_lexical_checkpoint_skips_parser_and_deduplicates \
		tests/test_ingestion.py::test_killed_claim_process_is_reclaimed_once_without_duplicates \
		tests/test_purge.py::test_purge_restarts_after_object_delete_without_duplicate_or_loss

log-scan: service-check
	cd service && uv run pytest -q tests/test_logging_privacy.py

accessibility: check
	fnm exec --using 24 pnpm --dir web exec playwright test tests/accessibility.spec.ts

real-persistence: build
	cd service && uv run python -m unittest discover -s ../web/tests/e2e -p 'test_harness_privacy.py'
	fnm exec --using 24 pnpm --dir web test:e2e:real

audit: check
	fnm exec --using 24 pnpm --dir web audit --prod

residual: check
	@for path in web/src/lib/browser-api.ts web/src/lib/streaming-sha256.ts web/src/lib/bounded-body.ts web/src/lib/upstream-request.ts web/src/app/api/backend; do \
		if rg -n 'payload as|arrayBuffer\(|new Blob\(|Buffer\.from\(' "$$path"; then \
			echo "ERROR: forbidden web response cast or upload copy remains in $$path" >&2; exit 1; \
		fi; \
	done

verify: check lint typecheck test build migration integration restart-test log-scan accessibility real-persistence audit residual
