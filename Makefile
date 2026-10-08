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
	.artifacts/install-wheel/bin/python -c "from localinferencelab.mlx_qualification_publication import committed_qualification_publication_record as load; assert load()['record_id'] == 'sha256:3d789caf4e65581265dc686aed30df0d4612388710b20a2dabc36e2d906711df'"
	uv venv .artifacts/install-sdist
	UV_NO_NETWORK=1 uv pip install --python .artifacts/install-sdist/bin/python hatchling==1.27.0
	UV_NO_NETWORK=1 uv pip install --python .artifacts/install-sdist/bin/python --no-index --no-build-isolation dist/*.tar.gz
	.artifacts/install-sdist/bin/python -c "import localinferencelab; assert localinferencelab.__version__ == '0.1.0'"
	.artifacts/install-sdist/bin/python -c "from localinferencelab.mlx_qualification_publication import committed_qualification_publication_record as load; assert load()['record_id'] == 'sha256:3d789caf4e65581265dc686aed30df0d4612388710b20a2dabc36e2d906711df'"

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
	mkdir .artifacts/qualification-a .artifacts/qualification-b
	uv run localinferencelab mlx runtime-qualification-fixture-compile .artifacts/qualification-a
	uv run localinferencelab mlx runtime-qualification-fixture-compile .artifacts/qualification-b
	qualification_a=$$(find .artifacts/qualification-a -mindepth 1 -maxdepth 1 -type d -name 'localinferencelab-mlx-runtime-qualification-synthetic-v1-*' -print -quit); \
	qualification_b=$$(find .artifacts/qualification-b -mindepth 1 -maxdepth 1 -type d -name 'localinferencelab-mlx-runtime-qualification-synthetic-v1-*' -print -quit); \
	diff -r "$$qualification_a" "$$qualification_b" && \
	uv run localinferencelab mlx runtime-qualification-replay "$$qualification_a"
	uv run localinferencelab mlx runtime-qualification-publication-replay \
		evidence/mlx-runtime-qualification-mlx-0.30.4-mlx-lm-0.30.6-macos-arm64-py313-v1.json
	mkdir .artifacts/preflight-contract-a .artifacts/preflight-contract-b
	uv run localinferencelab mlx runtime-preflight-1-1-fixture-compile .artifacts/preflight-contract-a
	uv run localinferencelab mlx runtime-preflight-1-1-fixture-compile .artifacts/preflight-contract-b
	preflight_contract_a=$$(find .artifacts/preflight-contract-a -mindepth 1 -maxdepth 1 -type d -name 'localinferencelab-mlx-runtime-preflight-contract-synthetic-v1-1-*' -print -quit); \
	preflight_contract_b=$$(find .artifacts/preflight-contract-b -mindepth 1 -maxdepth 1 -type d -name 'localinferencelab-mlx-runtime-preflight-contract-synthetic-v1-1-*' -print -quit); \
	diff -r "$$preflight_contract_a" "$$preflight_contract_b" && \
	uv run localinferencelab mlx runtime-preflight-1-1-fixture-replay "$$preflight_contract_a"
	mkdir .artifacts/determinism-canary-a .artifacts/determinism-canary-b
	uv run localinferencelab mlx determinism-canary-fixture-compile .artifacts/determinism-canary-a
	uv run localinferencelab mlx determinism-canary-fixture-compile .artifacts/determinism-canary-b
	canary_a=$$(find .artifacts/determinism-canary-a -mindepth 1 -maxdepth 1 -type d -name 'localinferencelab-mlx-determinism-canary-synthetic-v1-*' -print -quit); \
	canary_b=$$(find .artifacts/determinism-canary-b -mindepth 1 -maxdepth 1 -type d -name 'localinferencelab-mlx-determinism-canary-synthetic-v1-*' -print -quit); \
	diff -r "$$canary_a" "$$canary_b" && \
	uv run localinferencelab mlx determinism-canary-replay "$$canary_a"

validate: lint type test build-smoke fixture
