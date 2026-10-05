# Prospective direct MLX study preparation

This runbook performs static, offline preparation only. It must not be used to locate/download a
model, import MLX/MLX-LM, query Metal, load a tokenizer/model, run inference, or start a worker.

## 1. Inspect the pinned contract and capability boundary

```bash
localinferencelab mlx capability-report
localinferencelab mlx prospective-spec > mlx-study-spec.json
```

The capability report must show `production_worker_launch=false`,
`production_worker_private_ipc_protocol_and_result_validation_implementation=false`,
`applicable_dependency_distribution_closure=false`, `python_standard_library_closure=false`,
`python_native_runtime_and_dynamic_loader_closure=false`, `runtime_import=false`,
`strict_model_parameter_key_shape_load_evidence=false`, `device_query=false`,
`metal_initialization=false`, `inference=false`, `network=false`, and `subprocess=false`.

## 2. Optionally compile an explicit supplied package-root byte closure

Prepare a canonical `mlx_runtime_scan_spec` 1.0 containing:

- exact Python implementation, version, ABI, and platform strings;
- the unique sorted set of every direct distribution name/version present under the explicit
  package root, including `mlx` and `mlx-lm`;
- the sorted selected module files, including `mlx/__init__.py`, `mlx_lm/__init__.py`,
  `generate.py`, `utils.py`, `sample_utils.py`, and `models/cache.py`;
- the exact closed environment emitted by the contract.

Then identify, without executing them, an actual regular-file interpreter, package root, and future
worker file:

```bash
localinferencelab mlx runtime-manifest-create \
  runtime-scan-spec.json /explicit/runtime-root /explicit/python /explicit/worker.py \
  runtime-manifest.json
```

The command scans only the supplied paths. It neither imports nor executes their bytes. Symlinked
virtual-environment interpreters, hard-linked cache files, `.pth`, editable installs, mutable
aliases, unlisted direct metadata present in that root, or private-path injection fail closed. Do
not copy or mutate an installed runtime merely to satisfy this milestone.

The result proves only a complete byte closure of that supplied package root. Raw `Requires-Dist`
headers are recorded but markers/extras are not evaluated, and applicable dependency
distributions are not required. The interpreter's standard library, `lib-dynload`, `libpython`,
dynamic loader, native shared libraries, and frameworks are also outside this manifest. Do not
describe it as a complete Python dependency or execution-runtime closure.

## 3. Optionally compile an already identified supplied model-root byte closure

Only use a model directory the operator already identified before this runbook. Do not search a
Hugging Face cache, resolve a repository/revision, download a snapshot, materialize symlinks, or
rewrite files.

```bash
localinferencelab mlx model-manifest-create \
  /explicit/preexisting/materialized-mlx-snapshot model-manifest.json
```

The compiler reads no-follow regular files only and rejects custom code, remote-code markers,
symlinks, special files, nested paths, executable files, mixed monolith/shard layouts, malformed
or incomplete canonical shard sets, inconsistent shard indexes, and Safetensors outside the pinned
`model*.safetensors` loader scope. Without an index, the sole weight must be exactly
`model.safetensors`. It does not load config through MLX/Transformers, instantiate a
tokenizer/model, validate parameter keys/shapes, or mutate a cache.

This manifest proves supplied bytes and exact present projections, not semantic model completeness.
A future positive worker must use the pinned normal non-distributed (`sharding=None`)
`mlx_lm.utils.load` / `load_model` path with strict weight loading and bind the successful
key/shape validation as observed evidence.

If no suitable path is already known, skip this step. Absence is the correct built-in state.

## 4. Construct and inspect the prospective package

With no manifests:

```bash
localinferencelab mlx prospective-create \
  mlx-study-spec.json mlx-prospective.json
```

Or with both static manifests:

```bash
localinferencelab mlx prospective-create \
  mlx-study-spec.json mlx-prospective.json \
  --runtime-manifest runtime-manifest.json \
  --model-manifest model-manifest.json
```

Then verify and inspect:

```bash
localinferencelab mlx prospective-verify mlx-prospective.json
localinferencelab mlx eligibility-inspect mlx-prospective.json
```

Static supplied package/model-root byte closure does not grant execution. The result remains
ineligible because applicable dependency semantics, Python standard-library/native-loader closure,
production private IPC/protocol/result validation, worker start, process/import/backend
synchronization attestation, strict model parameter key/shape load evidence, exact memory limits,
output-root instance, and one-shot authorization are absent. No command exists to authorize or
execute it.

## 5. Repository-only deterministic validation

```bash
mkdir -p .artifacts/mlx-a .artifacts/mlx-b
localinferencelab mlx fixture-compile .artifacts/mlx-a
localinferencelab mlx fixture-compile .artifacts/mlx-b
diff -r .artifacts/mlx-a .artifacts/mlx-b
localinferencelab mlx fixture-replay \
  .artifacts/mlx-a/localinferencelab-mlx-direct-refused-synthetic-v1-*
```

The fixture contains fake non-model bytes and never invokes a fake transport or worker. Replay
reconstructs the exact ineligible package from sealed values and rejects extra/missing files,
noncanonical JSON, manifest/package identity drift, positive eligibility, or coordinated
record/index/receipt tampering.

## 6. Future positive milestone

Do not add a launch by calling a generic subprocess helper. A separately reviewed versioned schema
must implement, test, and authorize all of the following together:

1. Applicable dependency resolution plus exact Python standard-library, native-runtime,
   dynamic-loader, interpreter, package-root, and model descriptor closure/revalidation.
2. Parent-created private inherited IPC with unrelated descriptors closed, implemented frame/state
   validation, bounded result validation, timeout, termination, and terminal-error behavior.
3. Worker process-birth, executable, worker-byte, import-module, environment, device/backend, cache,
   limit, and stream identity bound before authorization.
4. Pinned normal MLX-LM model construction and `model.load_weights(..., strict=True)` key/shape
   validation bound to that same worker and package.
5. One-shot committed nonce custody and reserve-before-side-effect action ledger.
6. One request per worker, concurrency 1, no retries/warmups/selective reruns.
7. Exact prompt/template/token/sampler/cache controls and terminal raw-artifact custody.
8. Final synchronization and correctly scoped native metrics.
9. Explicit claim scope that does not overstate per-kernel Metal proof.

Until that milestone is approved, a real execution request must remain mechanically unreachable.
