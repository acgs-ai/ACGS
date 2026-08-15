.PHONY: lint typecheck test verify clean

lint:
	uv run ruff check .

typecheck:
	uv run mypy src/

test:
	uv run pytest -q -m "not benchmark"

verify: lint typecheck test

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache **/__pycache__
