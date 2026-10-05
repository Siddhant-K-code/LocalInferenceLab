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

## Trust boundary

```mermaid
flowchart LR
    P[Prospective protocol] --> I[Exact host, runtime, and model identities]
    I --> A{Content-addressed declaration}
    A -->|Forbidden or mismatch| X[No model action]
    A -->|Exact declaration| G[Two one-shot authorization gates]
    G --> R[Raw run records and native counters]
    F[Synthetic fixture] --> R
    R --> C[Atomic closed bundle]
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

## Benchmark matrix

| Surface | MLX-LM | llama.cpp with Metal | Ollama |
|---|---|---|---|
| Runtime identity schema | Package or immutable install manifest plus structured runner and Metal facts | Binary digest, build version, commit, runner, and Metal state | Binary or package digest, version, selected internal runner, and Metal state |
| Model identity schema | Snapshot file manifest, config, tokenizer | GGUF bytes and metadata | Manifest and layer digests |
| Cache cohort contract | Prompt and KV cache state | Process, model, prompt/KV, context shift | Outer API state plus active runner and cache state |
| Native metrics | Preserved when exposed | Preserved when exposed | Durations and token counts in native nanosecond units |
| Live execution in v1 | Forbidden | Forbidden | Read-only preflight only; generation is implemented for fake contract evidence but production-refused pending listener/runner attestation |
| Synthetic fixture | Exact repeat group | Text and token divergence group | Accepted, invalid, and identity-refused sealed-script bundles |

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
| Declaration identity | `sha256:24ba4d251493cccf5f95b95bf06782b88a6f4cb09b3f22bc512975250f695f59` |
| Synthetic declaration bundle root | `sha256:00a7933522a88eaca321f8fdf2d01ccef389379bf28d2f661fb044bf1dfaf1c5` |
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
| Assessment identity | `sha256:5fab901d52f9038f3db6776bf69545bf290cfa4499f1e428b7e1e2aee603446b` |
| Feasibility identity | `sha256:d38b69ce1400cf9ff0974e48ae1161a24086069c44d2d124d84abe87f5e34b9f` |
| Verdict identity | `sha256:a7aed7b4abe6360a5d7d365b7a87c98c0866bd37bbbaae693a98a03940398990` |
| Verdict | `insufficient` |
| Synthetic bundle root | `sha256:e7e96b3b44c624bf955b048ab1f95bac5e1d0bf3ab8448ebc32154993e3ff87f` |
| Live process probes, sockets, subprocesses, Ollama/model actions | 0 |

The record distinguishes normative requirements from candidate evidence and from the final
verdict. Darwin `libproc`, TCP PCB data, and code-signing APIs are authoritative only for their
documented fields; their separate snapshots do not create a request-scoped ownership assertion.
Pinned Ollama source retains `runnerRef`, child PID, model state, and internal completion transport
inside the server, but the public API does not export a content-bound chain. A future positive path
would need both a privileged retained accepted-socket/process assertion and reviewed in-process
Ollama cooperation binding the request digest, runner/load instance, model closure, and actual
Metal execution through the response.

## CLI

```text
localinferencelab contract verify RECORD.json
localinferencelab fixture compile OUTPUT_ROOT
localinferencelab bundle verify BUNDLE
localinferencelab bundle replay BUNDLE
localinferencelab host probe
localinferencelab backend plan {mlx-lm,llama.cpp,ollama}
localinferencelab backend probe BACKEND ARTIFACT --version VERSION [--commit COMMIT]
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

See [Architecture](docs/architecture.md), [Protocol](docs/protocol.md), and
[Current source research](docs/research/current-sources.md). The exact Ollama boundary is specified
in [Ollama runner contract](docs/ollama-runner-contract.md); prospective preparation is described in
the [Ollama study runbook](docs/runbooks/ollama-prospective-study.md).

## Exact non-claims

The project does not claim that:

- a fixed seed proves determinism;
- synthetic metrics describe real Apple Silicon performance;
- MLX, GGUF, and Ollama representations are the same model;
- CUDA deterministic-mode work applies to Metal;
- process RSS measures GPU memory or energy;
- one backend is faster, more stable, or more accurate than another.

## Roadmap

1. Review the frozen Qwen3 declaration and fill only evidence obtainable without model or network
   action.
2. Design a separately authorized future milestone for the two primitives named by the negative
   assessment: privileged accepted-socket/process continuity plus in-process Ollama
   request-to-runner/model/Metal cooperation.
3. Add separately authorized, preinstalled-resource runners for other backends.
4. Publish observed bundles only after provenance, privacy, and positive-attestation review.
5. Define a typed, indexed mapping-artifact protocol before any mapped cross-representation study.

## Development

```bash
make validate
```

Validation formats and lints, type-checks in strict mode, runs adversarial tests with coverage,
builds an offline sdist and wheel, compiles the fixture, and replays the published bundle.

Apache-2.0. Contributions must preserve the fail-closed execution boundary.
