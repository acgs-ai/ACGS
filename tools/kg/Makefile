# govern-zone knowledge graph — Neo4j
# All targets are local-only; nothing here touches CI or the parent gates.
SHELL := /bin/bash
COMPOSE ?= docker compose
PY ?= uv run --with neo4j --with pyyaml python
NEO4J_PASSWORD ?= acgs-kg-local
export NEO4J_PASSWORD

.PHONY: help up down extract load verify reload all shell browser logs reset nuke

help:
	@echo "make up       - start Neo4j (localhost:7474 browser, 7687 bolt)"
	@echo "make extract  - build build/graph.json from the repo"
	@echo "make load     - wipe + load graph.json into Neo4j"
	@echo "make verify   - shape, join-health and catalog-query evidence"
	@echo "make all      - up + extract + load + verify"
	@echo "make shell    - interactive cypher-shell"
	@echo "make down     - stop the container (data volume kept)"
	@echo "make nuke     - stop and delete the data volume"

up:
	$(COMPOSE) up -d
	@echo "waiting for neo4j..."
	@for i in $$(seq 1 60); do \
		if docker exec acgs-kg-neo4j cypher-shell -u neo4j -p $(NEO4J_PASSWORD) 'RETURN 1' >/dev/null 2>&1; then \
			echo "neo4j ready"; exit 0; fi; sleep 2; done; \
	echo "neo4j did not become ready"; exit 1

extract:
	$(PY) extract.py

load:
	$(PY) load.py --wipe

verify:
	$(PY) verify.py

reload: extract load verify

all: up extract load verify

shell:
	docker exec -it acgs-kg-neo4j cypher-shell -u neo4j -p $(NEO4J_PASSWORD)

browser:
	@echo "http://localhost:7474  (neo4j / $(NEO4J_PASSWORD))"

logs:
	$(COMPOSE) logs -f neo4j

down:
	$(COMPOSE) down

nuke:
	$(COMPOSE) down -v
