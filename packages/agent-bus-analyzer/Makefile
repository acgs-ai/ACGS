.PHONY: lint typecheck test verify clean

lint:
	ruff check .

typecheck:
	mypy src/

test:
	pytest -q

verify: lint typecheck test

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache **/__pycache__
