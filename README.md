# LocalInferenceLab

**Evidence-first determinism experiments for local LLM inference on Apple Silicon.**

LocalInferenceLab treats repeatability as a provenance and custody problem. It binds exact inputs,
runtime and model identities, process and model instances, cache-preparation lineage, effective
concurrency, exact execution order, native metrics, and raw outputs before it compares runs. It is
not a tokens-per-second leaderboard and it does not infer determinism from a seed.

> The Ollama runner is implemented but fail-closed. It can prepare and verify exact prospective
> packages offline and perform separately authorized read-only loopback preflight calls. The
> additive `ollama_repeatability_study_declaration` schema 1.0 freezes the planned Qwen3 study
> without probing Ollama or precreating a host-bound output marker. The additive schema-1.0
> attestation assessment now records the reviewed result: public nonprivileged macOS and Ollama
> surfaces are **insufficient** to content-bind the exact accepted connection and request to one
> stable listener process and active runner/model/Metal instance through response. Observed
> generation and replay therefore remain disabled. Repository tests and recorded evidence use
> no-socket fixtures: they do not contact Ollama, inspect a live process, execute a model, or make
> a benchmark claim.
>
> The direct MLX milestones avoid that listener gap with a parent-owned private-descriptor worker.
> Strict additive schema-1.0 records bind a complete explicitly supplied package-root byte
> closure, raw dependency metadata, supplied model-root bytes and present weight projection, worker
> bytes, a closed environment, finite protocol design, exact controls, result semantics, and future
> custody. A separate inert-custody schema now exercises the real POSIX process, exact FD 3 private
> socket, canonical finite exchange, one-shot refusal authorization, physical output-root binding,
> terminal wait, closed publication, and process-free replay. The sealed worker can only return
> `mlx_execution_unimplemented_and_unauthorized`; no generated-result producer exists. These
> records do not prove
> applicable dependency semantics, Python standard-library/native-loader closure, or a production
> generated-result implementation. The model manifest binds supplied bytes
> and exact present canonical shard projections, not semantic parameter key/shape completeness;
> future pinned strict-load evidence is also an explicit blocker.
> The deliberately explicit `mlx custody-self-test` command starts exactly one inert child and one
> private socketpair. All other MLX commands remain process-free. No command imports installed
> MLX/MLX-LM modules, initializes/queries Metal, loads a tokenizer/model, runs inference,
> resolves/downloads a snapshot, mutates a model cache, or makes network/cloud/spend actions.

## Trust boundary

```mermaid
flowchart LR
    P[Prospective protocol] --> I[Exact host, runtime, and model identities]
    I --> A{Content-addressed declaration}
    A -->|Forbidden or mismatch| X[No model action]
    A -->|Ollama| G[Separate one-shot authorization gates]
    A -->|Direct MLX custody| W[Parent-owned private descriptor worker]
    G --> R[Raw run records and native counters]
    W -->|Sealed refusal only| X
    F[Synthetic fixtures] --> C[Atomic closed bundle]
    R --> C
    C --> O[Strict offline replay]
    O --> N[Within-backend analysis]
```

The Ollama `G` node exists but is unreachable from a protocol, environment variable, generic
network flag, or package alone. The exact declaration binds the numeric-loopback endpoint, output
root, request bytes, runtime and model artifacts, process/model/cache/concurrency state, nine-call
schedule, deadlines, and byte/action budgets. Each authorization nonce digest is committed by the
declaration before the nonce is revealed; the later artifact proves possession of the nonce
preimage. A distinct identity authorization is consumed before
four pre- and four post-request checks; a distinct generation authorization is consumed only after
the pre-check passes. Neither gate can start Ollama, pull or mutate a model, follow a redirect, use
a proxy, or retry. Production generation currently refuses before consumption or socket access
because the canonical attestation verdict is `insufficient`. Loopback proves locality, not process
authentication. Metadata identity and `/api/ps` load state do not prove which process accepted the
connection or which internal runner and Metal backend serviced the exact request.

The MLX `W` node has a real refusal-only custody path. The parent validates a trusted exact
interpreter, copies verified standalone-worker bytes into an unlinked mode-0400 snapshot under the
retained private output-root descriptor, and launches that snapshot on stdin with `os.posix_spawn`.
It installs the private socket endpoint at child FD 3, closes enumerated unrelated descriptors,
supplies a closed environment, enforces one bounded canonical exchange under one absolute deadline,
atomically consumes one authorization, and waits for its child. The repository worker path cannot
be substituted after verification because the child never reopens it. The worker has no accepted
or invalid generated-result branch. The static
runtime manifest still covers only its supplied package-root bytes: dependency markers/extras,
applicable dependency distributions, Python standard-library bytes, `lib-dynload`, `libpython`,
native shared libraries/frameworks, and the dynamic loader are not proven. Official MLX APIs cannot
prove individual Metal kernels executed. The model-root manifest cannot prove tensor key/shape
completeness without future pinned `model.load_weights(..., strict=True)` evidence.

## Benchmark matrix

| Surface | MLX-LM | llama.cpp with Metal | Ollama |
|---|---|---|---|
| Runtime identity schema | Package or immutable install manifest plus structured runner and Metal facts | Binary digest, build version, commit, runner, and Metal state | Binary or package digest, version, selected internal runner, and Metal state |
| Model identity schema | Snapshot file manifest, config, tokenizer | GGUF bytes and metadata | Manifest and layer digests |
| Cache cohort contract | Prompt and KV cache state | Process, model, prompt/KV, context shift | Outer API state plus active runner and cache state |
| Native metrics | Preserved when exposed | Preserved when exposed | Durations and token counts in native nanosecond units |
| Live execution in v1 | One inert refusal-only custody child; generation remains absent and ineligible | Forbidden | Read-only preflight only; generation is implemented for fake contract evidence but production-refused pending listener/runner attestation |
| Synthetic fixture | Direct-worker refusal package plus foundation exact-repeat group | Text and token divergence group | Accepted, invalid, and identity-refused sealed-script bundles |

MLX snapshots, GGUF files, and Ollama manifests are separate representations. A shared marketing
name does not establish byte or behavioral equivalence. Cross-representation equivalence remains
`unproven` in v1. Mapping digests and mapped states are rejected until a typed, indexed mapping
artifact contract exists.

## Quickstart

Python 3.12 or newer and [uv](https://docs.astral.sh/uv/) are required.

```bash
uv sync --locked --all-groups
mkdir -p .artifacts
uv run localinferencelab fixture compile .artifacts
uv run localinferencelab bundle replay .artifacts/localinferencelab-fixture-v1-*
```

The committed fixture deterministically produces:

| Result | Value |
|---|---:|
| Bundle content root | `sha256:c4401fe71dee474a610eb95cf071fea72a0c09a3b221d80bd023c603f618617e` |
| Protocol identity | `sha256:a23da6973f43faa2a9ae5e3d9bb912a43434f185507760e9363689956dfa5df5` |
| Runs | 4 |
| Exact scheduled slots | 4 |
| Isolated cache cohorts | 2 |
| Exactly repeatable groups | 1 |
| Divergent text/token groups | 1 |
| Model, network, and download actions | 0 |

These are synthetic contract results, not benchmark claims about hardware, a model, or a backend.

The direct MLX refusal fixture deterministically produces:

| Result | Value |
|---|---:|
| Runtime / model / package schemas | `mlx_runtime_manifest` / `mlx_model_manifest` / `mlx_direct_prospective_package` 1.0 |
| Runtime manifest identity | `sha256:226617353dc742bda9efa02f6083b3733832659f77add8fb20c4da0e953c31b0` |
| Model manifest identity | `sha256:b29d33d9fba77c827dc62c4b5b83536f65b5b78ad24d3bf5b84cf7379a08ebcf` |
| Package identity | `sha256:7710436299a426d07cb235084a1891db87ed4c810b65a5e5215fba69b6797ddb` |
| Synthetic bundle root | `sha256:fd99954d8c0643719510a8f3b9f3ed15e342bc1f775a3e0d6d2cd37b5e489454` |
| Decision / missing requirements | `ineligible` / 16 |
| Framework imports, Metal/device, model, process, socket, network, cloud, spend actions | 0 |

Its sealed files are fake non-model bytes. Replay reconstructs closure and refusal semantics; it
does not instantiate a fake worker/transport, claim producer-reachable generation, or record
performance.

The recorded Ollama sealed-script fixtures deterministically produce:

| Outcome | Bundle content root | Logical calls | Model/network side effects |
|---|---|---:|---:|
| Accepted | `sha256:f24cdd03797444f260bcb405cf5da374f36a72e83278ad48e2d3b382142e64e5` | 9 | 0 |
| Digest-safe invalid | `sha256:0f164344931d9dc1ed253ce8147b1994e5917a18b22eea2554e9b9585e67b707` | 9 | 0 |
| Identity-refused | `sha256:4a0e505cf8a28e6f81790d47f6f201bdb87df780d616fa642f8279227a6a8480` | 4 | 0 |

Logical scripted calls exercise ordering, budgets, bounded response custody, and replay only. The
public synthetic API cannot receive a transport object, and each response is action-indexed for
offline reconstruction. Their counters and timings are not observed Ollama behavior or performance
evidence.

The declaration fixture separately freezes five prospective Qwen3 8B Q8 repeats:

| Result | Value |
|---|---:|
| Declaration schema | `ollama_repeatability_study_declaration` 1.0 |
| Foundation commit | `7f89682bdc50a944cf74e4729f5acffa48dc6f1a` |
| Ollama version evidence | `0.35.1` from prior user-provided identity |
| Qwen3 manifest digest | `sha256:e56358ca25dd14db6853a9f68a92d717aaa6f0a94250a72d1a0f3d86a9f30130` |
| Repeats / concurrency / attempts | 5 / 1 / 1 each |
| Supported cache cohort | `cold_model_warm_process` only |
| Declaration identity | `sha256:ebf8c3758c83c353e6e0bd9ab0f12d4aeb30ed9d7c1ed8f20669f7948f30022e` |
| Synthetic declaration bundle root | `sha256:52d39c95991d3151423f9de455eb734bfe0d9a0e17f516f4ad05771bb9c9714a` |
| Physical network, socket, model, cloud, spend actions | 0 |

The fixture is intentionally incomplete: no runtime artifact digest, selected internal runner,
Metal state, manifest/config/layer byte closure, exact per-run prospective package, output-root
instance, or authorization nonce is manufactured. Completeness and metadata-preflight permission
are separate from generation eligibility. Generation and generation replay remain ineligible
specifically because schema 1.0 has no content-bound listener-owner or active internal
runner/Metal attestation.

The independent offline attestation fixture freezes the feasibility decision:

| Result | Value |
|---|---:|
| Assessment schema | `ollama_attestation_assessment` 1.0 |
| Bound PR #3 declaration identity | `sha256:ebf8c3758c83c353e6e0bd9ab0f12d4aeb30ed9d7c1ed8f20669f7948f30022e` |
| Assessment identity | `sha256:d84a278868c3f0d3c5ec516f39825d10d01e307dffabaa04e2368d8acc48bcb6` |
| Feasibility identity | `sha256:caa1d2a3cb421325de24ba147441476001c6e0938c8fe8287c3f09f3f5751534` |
| Verdict identity | `sha256:5de010f84328e24eed9d4b2efd635eb7390227b04ae623cd36189e1a44091ebe` |
| Verdict | `insufficient` |
| Synthetic bundle root | `sha256:1e189da8cde51544a361b98c4f0376b70cd5f223b5e0db112b6d18accb997460` |
| Live process probes, sockets, subprocesses, Ollama/model actions | 0 |

The record distinguishes normative requirements from candidate evidence and from the final
verdict. Darwin `libproc`, TCP PCB data, and code-signing APIs are authoritative only for their
documented fields; their separate snapshots do not create a request-scoped ownership assertion.
Pinned Ollama source retains `runnerRef`, child PID, model state, and internal completion transport
inside the server, but the public API does not export a content-bound chain. A future positive path
would need both a privileged retained accepted-socket/process assertion and reviewed in-process
Ollama cooperation binding the request digest, runner/load instance, model closure, and actual
Metal execution through the response. The assessment is a separate record that explains and
retains the declaration's existing ineligibility; it does not revise, migrate, or embed itself in
the strict declaration schema.

## CLI

```text
localinferencelab contract verify RECORD.json
localinferencelab fixture compile OUTPUT_ROOT
localinferencelab bundle verify BUNDLE
localinferencelab bundle replay BUNDLE
localinferencelab host probe
localinferencelab backend plan {mlx-lm,llama.cpp,ollama}
localinferencelab backend probe BACKEND ARTIFACT --version VERSION [--commit COMMIT]
localinferencelab mlx capability-report
localinferencelab mlx custody-capability-report
localinferencelab mlx prospective-spec > MLX-STUDY-SPEC.json
localinferencelab mlx runtime-manifest-create RUNTIME-SCAN-SPEC.json \
  RUNTIME_ROOT PYTHON_EXECUTABLE WORKER_PROGRAM RUNTIME-MANIFEST.json
localinferencelab mlx model-manifest-create LOCAL-SNAPSHOT MODEL-MANIFEST.json
localinferencelab mlx prospective-create MLX-STUDY-SPEC.json PACKAGE.json \
  [--runtime-manifest RUNTIME-MANIFEST.json] [--model-manifest MODEL-MANIFEST.json]
localinferencelab mlx prospective-verify PACKAGE.json
localinferencelab mlx eligibility-inspect PACKAGE.json
localinferencelab mlx fixture-compile OUTPUT_ROOT
localinferencelab mlx fixture-replay CLOSED-BUNDLE
localinferencelab mlx custody-self-test MODE_0700_OUTPUT_ROOT
localinferencelab mlx custody-replay CLOSED-CUSTODY-BUNDLE
localinferencelab mlx custody-inspect CLOSED-CUSTODY-BUNDLE
localinferencelab ollama output-root-init OUTPUT_ROOT --nonce NONCE
localinferencelab ollama authorization-nonce-init NONCE_FILE
localinferencelab ollama prospective-create SPEC OUTPUT --runtime-artifact FILE \
  --model-manifest FILE --blob-root DIR
localinferencelab ollama prospective-verify PACKAGE
localinferencelab ollama declaration-spec > STUDY-SPEC.json
localinferencelab ollama declaration-create STUDY-SPEC.json DECLARATION.json \
  [--prospective-package EXACT-PACKAGE.json ...]
localinferencelab ollama declaration-verify DECLARATION.json
localinferencelab ollama declaration-inspect DECLARATION.json
localinferencelab ollama declaration-fixture-compile OUTPUT_ROOT
localinferencelab ollama declaration-replay CLOSED-BUNDLE
localinferencelab ollama attestation-spec
localinferencelab ollama attestation-create ASSESSMENT.json [--spec PINNED-SPEC.json]
localinferencelab ollama attestation-verify ASSESSMENT.json
localinferencelab ollama attestation-inspect ASSESSMENT.json
localinferencelab ollama attestation-fixture-compile OUTPUT_ROOT
localinferencelab ollama attestation-replay CLOSED-BUNDLE
localinferencelab ollama authorize PACKAGE {preflight_only,identity_guard,generation} \
  AUTHORIZATION --nonce-file NONCE_FILE
localinferencelab ollama preflight PACKAGE AUTHORIZATION OUTPUT_ROOT \
  --runtime-artifact FILE --model-manifest FILE --blob-root DIR
localinferencelab ollama execute PACKAGE IDENTITY_AUTH GENERATION_AUTH OUTPUT_ROOT \
  --runtime-artifact FILE --model-manifest FILE --blob-root DIR
localinferencelab ollama evidence-replay BUNDLE
localinferencelab ollama fixture-compile OUTPUT_ROOT
```

`host probe` is read-only and excludes usernames, home paths, hostnames, serial numbers, and UUIDs.
Linux output is portability evidence only and never claims Apple Silicon eligibility. `backend
probe` hashes one no-follow file descriptor without executing it and records only its basename.
Static probes remain explicitly incomplete until backend-specific observed capability evidence
exists. Literal absence markers such as `unobserved`, `unknown`, and `unavailable` never satisfy an
observed identity requirement.

The MLX manifest, prospective, fixture, replay, and inspection commands are process-free and
offline. Runtime compilation scans an explicitly supplied
regular-file interpreter, package root, worker bytes, distribution metadata, selected modules, and
closed environment without importing or executing them. Model compilation scans one explicit,
already-identified materialized directory; it never searches caches or resolves/downloads a
snapshot. Symlinks, special files, hard-link aliases, path/import injection, remote/custom code,
Safetensors outside the pinned loader scope, mixed or malformed/incomplete canonical shards, and
inconsistent indexes fail closed. Supplying both manifests still cannot make execution eligible:
applicable dependencies, Python
standard-library/native-loader bytes, generated-result production/validation, strict model
parameter key/shape load evidence, exact limits, model-action authorization, active
import/backend/cache evidence, cross-platform parent-observed running executable identity, and
final synchronization remain missing.

`mlx custody-self-test` is the sole processful MLX command. It requires an explicit preexisting
current-owner mode-0700 directory, starts one inert local child and one private `AF_UNIX`
socketpair, consumes one synthetic one-shot authorization for `action=inert_refusal_only`, and
publishes a bounded receipt-closed transcript. It performs zero MLX/MLX-LM imports, Metal/device
actions, tokenizer/model loads, inference, snapshot resolution/download, cache mutation, network,
cloud, or spend actions. `custody-replay` and `custody-inspect` are process- and socket-free.

`declaration-spec`, `declaration-create`, `declaration-verify`, and `declaration-inspect` are
declaration-only operations. They do not probe the host, read an Ollama endpoint, create
authorization, initialize an output root, or execute a model. If exact prospective packages are
provided, all scheduled runs must be covered and each package is strictly verified, embedded, and
content-bound; every repeat must share one exact runtime, model, host, and output-root identity.
Filesystem paths and mutable model aliases are not identity. The metadata-preflight plan names the
first run's exact package and committed preflight nonce, but remains separately unauthorized. With
no packages those identities are `null`, and the declaration remains valid but explicitly
incomplete and ineligible.

The attestation commands are pure offline contract operations. `attestation-create` uses the
built-in pinned feasibility specification unless an exact canonical copy is supplied. It has no
live acquisition mode and cannot accept a transport or process probe. Verification recomputes the
only supported verdict; changing a candidate, omitting a requirement, adding a positive
attestation ID, or setting generation eligibility to true fails. `attestation-fixture-compile`
publishes the source specification and derived assessment through the same closed-bundle custody
path, and `attestation-replay` rebuilds the result with zero physical actions.

Ollama packages require an explicit `:local` request name. The canonical response/tag name is
derived mechanically by removing `:local` and adding `:latest` only when no tag was supplied; it is
not separately caller-controlled. Packages also require a complete local manifest/config/layer
closure. Production preflight transport accepts only
`http://127.0.0.1:PORT` or `http://[::1]:PORT`, uses standard-library direct HTTP without proxy
discovery, rejects redirects, verifies the connected peer, and permits only `/api/version`,
`/api/tags`, `/api/show`, and `/api/ps`. The frozen generation schedule additionally permits one
`/api/generate`, but observed generation is gated off pending listener-process attestation. The
generated request fixes
`stream=false`, `raw=true`, `shift=false`, `truncate=false`, `keep_alive=0`, `think`, seed, sampler,
context, and output limits. Token IDs remain unavailable because this API does not expose a
trustworthy generated-token sequence.

## Measurement semantics

- Exact repeatability compares raw response, UTF-8 text, observable token IDs, finish reason, and
  structured envelope digests inside one backend, identity set, protocol, process instance, model
  instance, cache preparation, effective concurrency state including peer request shape, request,
  and cache cohort. The exact schedule separately binds ordered concurrency waves.
- A valid output requires a finish reason. Missing token IDs make the group `not_comparable`;
  invalid output makes it `incomplete`. Neither state is reported as exact or divergent.
- Performance keeps backend-native names and units. Derived throughput is integer fixed-point and
  only exists when generation count and duration are available.
- TTFT, prompt evaluation, generation, total, and load measurements carry explicit availability
  reasons. Missing values are not synthesized.
- Memory is recorded only with a named method. Process RSS is never labeled Metal or GPU memory.
- Energy is unavailable in v1 because no privileged reviewed protocol exists.
- Cross-backend output is descriptive and identity-aware. It is not a superiority ranking or an
  equivalence claim.

## Durable custody

Bundles contain source fixture intent, protocol and exact run schedule, identities, process/model
instances, cache-preparation lineage, concurrency identity, declarations, eligibility decisions,
ordered run records, analysis, index, and receipt. Publication uses fsynced staged files, fsynced
directories, a platform no-replace rename, destination-parent fsync, and receipt-last exclusive
creation. Replay opens a verified bundle-root descriptor, traverses each component relative to
directory descriptors with no-follow and nonblocking flags, requires regular files before reading,
and rejects symlinks, traversal, special files, non-canonical JSON, unknown keys, identity drift,
extra or missing paths, swapped records, schedule drift, writable or foreign-owned bundle
directories, action-budget drift, source-intent drift, analysis drift, and absent receipts. Digest
and semantic checks use the same single-read byte snapshot.

Direct MLX replay requires exactly the sealed fixture source, pinned study specification,
synthetic runtime/model manifests, prospective package, index, and receipt. It reconstructs every
identity and the ineligible decision and rejects extra/missing files, noncanonical JSON,
closure/control/eligibility drift, or coordinated receipt-consistent tampering.

Inert custody replay additionally binds the fixed protocol and worker-code IDs, sealed worker
source digest, exact parent/worker frames, package and output-root IDs, authorization and exclusive
consumption evidence, action/non-action ledgers, refusal-only terminal state, and child wait
status. It mechanically splits the four broad prospective blockers exercised by this milestone,
then retains the model-action authorization, generated-result, runtime/model/backend, memory,
synchronization, and cross-platform executable-observation blockers. Replay opens no socket and
starts no process.

See [Architecture](docs/architecture.md), [Protocol](docs/protocol.md), and
[Current source research](docs/research/current-sources.md). The exact Ollama boundary is specified
in [Ollama runner contract](docs/ollama-runner-contract.md); prospective preparation is described in
the [Ollama study runbook](docs/runbooks/ollama-prospective-study.md). The new architecture is
specified in [Direct MLX worker contract](docs/mlx-direct-runner-contract.md) and its static-only
workflow in [Direct MLX runbook](docs/runbooks/mlx-prospective-study.md).

## Exact non-claims

The project does not claim that:

- a fixed seed proves determinism;
- synthetic metrics describe real Apple Silicon performance;
- MLX, GGUF, and Ollama representations are the same model;
- CUDA deterministic-mode work applies to Metal;
- process RSS measures GPU memory or energy;
- one backend is faster, more stable, or more accurate than another.

## Roadmap

1. Review the direct MLX supplied package/model-root byte closures and projections, protocol
   design, exact controls, and refusal fixture.
2. In a separately reviewed schema version, close applicable dependencies and Python
   standard-library/native-loader bytes, then implement retained runtime/model descriptors,
   parent-owned private IPC/protocol/result validation, same-process
   import/backend/cache/synchronization attestation, pinned strict model key/shape loading, and
   one-shot authorization before adding any production worker start.
3. Review the frozen Qwen3 declaration and fill only evidence obtainable without model or network
   action.
4. Design a separately authorized future milestone for the two primitives named by the negative
   assessment: privileged accepted-socket/process continuity plus in-process Ollama
   request-to-runner/model/Metal cooperation.
5. Add separately authorized, preinstalled-resource runners for other backends.
6. Publish observed bundles only after provenance, privacy, and positive-attestation review.
7. Define a typed, indexed mapping-artifact protocol before any mapped cross-representation study.

## Development

```bash
make validate
```

Validation formats and lints, type-checks in strict mode, runs adversarial tests with coverage,
builds an offline sdist and wheel, compiles the fixture, and replays the published bundle.

Apache-2.0. Contributions must preserve the fail-closed execution boundary.
