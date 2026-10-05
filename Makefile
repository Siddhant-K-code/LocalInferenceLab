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
	UV_NO_NETWORK=1 uv pip install --offline --python .artifacts/install-sdist/bin/python 'hatchling==1.27.0'
	UV_NO_NETWORK=1 uv pip install --python .artifacts/install-sdist/bin/python --no-index --no-build-isolation dist/*.tar.gz
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
	diff -r "$$bundle_a" "$$bundle_b" && \
	uv run localinferencelab ollama declaration-replay "$$bundle_a"
	mkdir .artifacts/attestation-a .artifacts/attestation-b
	uv run localinferencelab ollama attestation-fixture-compile .artifacts/attestation-a
	uv run localinferencelab ollama attestation-fixture-compile .artifacts/attestation-b
	attestation_a=$$(find .artifacts/attestation-a -mindepth 1 -maxdepth 1 -type d -name 'localinferencelab-ollama-attestation-synthetic-v1-*' -print -quit); \
	attestation_b=$$(find .artifacts/attestation-b -mindepth 1 -maxdepth 1 -type d -name 'localinferencelab-ollama-attestation-synthetic-v1-*' -print -quit); \
	diff -r "$$attestation_a" "$$attestation_b" && \
	uv run localinferencelab ollama attestation-replay "$$attestation_a"
	mkdir .artifacts/mlx-a .artifacts/mlx-b
	uv run localinferencelab mlx fixture-compile .artifacts/mlx-a
	uv run localinferencelab mlx fixture-compile .artifacts/mlx-b
	mlx_a=$$(find .artifacts/mlx-a -mindepth 1 -maxdepth 1 -type d -name 'localinferencelab-mlx-direct-refused-synthetic-v1-*' -print -quit); \
	mlx_b=$$(find .artifacts/mlx-b -mindepth 1 -maxdepth 1 -type d -name 'localinferencelab-mlx-direct-refused-synthetic-v1-*' -print -quit); \
	diff -r "$$mlx_a" "$$mlx_b" && \
	uv run localinferencelab mlx fixture-replay "$$mlx_a"

validate: lint type test build-smoke fixture
