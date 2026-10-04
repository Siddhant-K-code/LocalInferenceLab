# LocalInferenceLab

**Evidence-first determinism experiments for local LLM inference on Apple Silicon.**

LocalInferenceLab treats repeatability as a provenance and custody problem. It binds exact inputs,
runtime and model identities, process and model instances, cache-preparation lineage, effective
concurrency, exact execution order, native metrics, and raw outputs before it compares runs. It is
not a tokens-per-second leaderboard and it does not infer determinism from a seed.

> The Ollama runner is implemented but fail-closed. It can prepare and verify exact prospective
> packages offline and perform separately authorized read-only loopback preflight calls. Observed
> generation remains disabled until the listening Ollama process and its active runner/Metal state
> can be mechanically attested. Repository tests and recorded evidence use a no-socket fake
> transport: they do not contact Ollama, execute a model, or make a benchmark claim.

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
because listener-process attestation is not yet portable and reviewed.

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

1. Review and freeze the Ollama package, authorization, transport, and evidence records.
2. Independently review one prospective Apple Silicon study and its out-of-band runner/Metal
   evidence before creating any real authorization artifact.
3. Add separately authorized, preinstalled-resource runners for other backends.
4. Publish observed bundles only after provenance and privacy review.
5. Define a typed, indexed mapping-artifact protocol before any mapped cross-representation study.

## Development

```bash
make validate
```

Validation formats and lints, type-checks in strict mode, runs adversarial tests with coverage,
builds an offline sdist and wheel, compiles the fixture, and replays the published bundle.

Apache-2.0. Contributions must preserve the fail-closed execution boundary.
