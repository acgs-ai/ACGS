SHELL := /bin/bash

REQUIRED_FILES := \
	README.md \
	GOVERNANCE_HUB_PRINCIPLES.md \
	agent-decision-protocol.md \
	problem-solution-map.md \
	solution-catalog/README.md \
	solution-catalog/runtime-governance.md \
	solution-catalog/auditability-and-receipts.md \
	solution-catalog/human-oversight.md \
	solution-catalog/policy-as-code.md \
	solution-catalog/risk-classification.md \
	solution-catalog/incident-response.md \
	playbooks/README.md \
	playbooks/choose-a-governance-pattern.md \
	playbooks/govern-an-agent-tool-call.md \
	playbooks/produce-an-audit-trail.md \
	playbooks/escalate-to-human-review.md \
	templates/governance-case.md \
	templates/decision-record.md \
	templates/control-matrix.md \
	templates/agent-evaluation-checklist.md \
	evidence/README.md \
	evidence/source-register.md \
	validation/README.md \
	validation/docs-quality-checklist.md \
	validation/check_internal_links.py

.PHONY: validate check

check: validate

validate:
	@set -euo pipefail; \
	for f in $(REQUIRED_FILES); do \
		test -f "$$f" || { echo "missing required file: $$f"; exit 1; }; \
	done; \
	if grep --exclude=Makefile -RInE 'TODO|TBD|compliance-certified|production-ready|production-validated|regulatory-compliant' -- .; then \
		echo "forbidden placeholder or overclaim found"; exit 1; \
	fi; \
	for f in solution-catalog/*.md; do \
		[[ "$$f" == "solution-catalog/README.md" ]] && continue; \
		for h in '## When to use' '## When not to use' '## Required inputs' '## Expected outputs' '## Evidence required' '## Failure modes' '## Agent instruction block'; do \
			grep -q "$$h" "$$f" || { echo "missing heading $$h in $$f"; exit 1; }; \
		done; \
	done; \
	grep -q 'ALLOW / DENY / ESCALATE / ASK' agent-decision-protocol.md || { echo "decision protocol missing decision vocabulary"; exit 1; }; \
	grep -q 'NIST AI Risk Management Framework' evidence/source-register.md || { echo "source register missing NIST AI RMF"; exit 1; }; \
	grep -q 'OWASP Top 10 for LLM Applications' evidence/source-register.md || { echo "source register missing OWASP LLM Top 10"; exit 1; }; \
	python3 validation/check_internal_links.py; \
	echo "AI governance hub docs validation passed: $$(find . -type f | wc -l) files checked"
