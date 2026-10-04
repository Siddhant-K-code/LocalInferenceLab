.PHONY: format lint type test build fixture validate

format:
	uv run ruff format .
	uv run ruff check --fix .

lint:
	uv run ruff format --check .
	uv run ruff check .

type:
	uv run mypy

test:
	uv run pytest --cov --cov-report=term-missing

build:
	UV_NO_NETWORK=1 uv build

fixture:
	rm -rf .artifacts
	mkdir .artifacts
	uv run localinferencelab fixture compile .artifacts
	uv run localinferencelab bundle replay .artifacts/localinferencelab-fixture-v1-*
	uv run localinferencelab ollama fixture-compile .artifacts
	for bundle in .artifacts/localinferencelab-ollama-*-synthetic-v1-*; do \
		uv run localinferencelab ollama evidence-replay "$$bundle"; \
	done

validate: lint type test build fixture
