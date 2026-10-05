.PHONY: format lint type test build build-smoke fixture validate

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

build-smoke: build
	rm -rf .artifacts/install-wheel .artifacts/install-sdist
	uv venv .artifacts/install-wheel
	UV_NO_NETWORK=1 uv pip install --python .artifacts/install-wheel/bin/python --no-index dist/*.whl
	.artifacts/install-wheel/bin/python -c "import localinferencelab; assert localinferencelab.__version__ == '0.1.0'"
	uv venv .artifacts/install-sdist
	UV_NO_NETWORK=1 uv pip install --python .artifacts/install-sdist/bin/python dist/*.tar.gz
	.artifacts/install-sdist/bin/python -c "import localinferencelab; assert localinferencelab.__version__ == '0.1.0'"

fixture:
	rm -rf .artifacts
	mkdir .artifacts
	uv run localinferencelab fixture compile .artifacts
	uv run localinferencelab bundle replay .artifacts/localinferencelab-fixture-v1-*
	uv run localinferencelab ollama fixture-compile .artifacts
	for bundle in .artifacts/localinferencelab-ollama-*-synthetic-v1-*; do \
		uv run localinferencelab ollama evidence-replay "$$bundle"; \
	done
	mkdir .artifacts/declaration-a .artifacts/declaration-b
	uv run localinferencelab ollama declaration-fixture-compile .artifacts/declaration-a
	uv run localinferencelab ollama declaration-fixture-compile .artifacts/declaration-b
	bundle_a=$$(find .artifacts/declaration-a -mindepth 1 -maxdepth 1 -type d -name 'localinferencelab-ollama-declaration-synthetic-v1-*' -print -quit); \
	bundle_b=$$(find .artifacts/declaration-b -mindepth 1 -maxdepth 1 -type d -name 'localinferencelab-ollama-declaration-synthetic-v1-*' -print -quit); \
	diff -r "$$bundle_a" "$$bundle_b"; \
	uv run localinferencelab ollama declaration-replay "$$bundle_a"

validate: lint type test build-smoke fixture
