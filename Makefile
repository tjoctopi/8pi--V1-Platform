.PHONY: help install test cov lint type check fmt range-up range-down clean

help:
	@echo "Targets: install test cov lint type check fmt range-up range-down clean"

install:  ## Create venv and install with dev extras
	uv venv --python 3.11
	uv pip install -e ".[dev]"

test:  ## Run the full test suite (no external services needed)
	.venv/bin/pytest

cov:  ## Run tests with coverage report
	.venv/bin/pytest --cov

lint:  ## Ruff lint
	.venv/bin/ruff check src tests

fmt:  ## Ruff autofix + format
	.venv/bin/ruff check src tests --fix
	.venv/bin/ruff format src tests

type:  ## Mypy type-check
	.venv/bin/mypy src

check: lint type test  ## Lint + type-check + test (CI gate)

range-up:  ## Start the ground-truth cyber range
	.venv/bin/attack-engine range up

range-down:  ## Tear down the range
	.venv/bin/attack-engine range down

clean:
	rm -rf dist build .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +
