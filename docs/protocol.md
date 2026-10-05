# Experiment protocol

## Canonical form

Records use schema version `1.0` and canonical UTF-8 JSON:

- object keys are sorted;
- separators contain no insignificant whitespace;
- duplicate keys, unknown keys, floats, NaN, and infinity are rejected;
- exact bytes use unpadded URL-safe base64;
- identities use `sha256:<lowercase hex>` over canonical record bytes.
- identity allowlists are non-empty, unique, and sorted;
- surrogate code points are rejected in both values and object keys.

Integer units avoid cross-platform floating-point serialization. Sampler values use millionths,
durations use integer nanoseconds, sizes use bytes, and derived throughput uses millionths of a
token per second.

## Required identities

### Host

The host record binds architecture, chip, physical and logical core counts where available, memory, OS
version/build, and reviewed backend or device facts. An observed Apple Silicon experiment requires
an `apple_silicon` host from the safe macOS probe. Linux fixtures validate portability but remain
`non_apple_ci`. Linux physical cores are derived from CPU topology and remain `null` if unavailable
rather than copying the logical count.

### Runtime

Runtime identity binds:

- backend;
- executable or package name without a private path;
- exact version and commit when available;
- executable digest or immutable install-manifest digest;
- exactly one structured runner selection;
- exactly one structured Metal state;
- backend-specific version or build facts with unique names.

Static artifact probes are always incomplete and never claim runtime capability. Observed MLX-LM
identity requires an immutable install manifest plus both MLX and MLX-LM versions. Observed
llama.cpp identity requires executable bytes, commit/build evidence, an exact llama.cpp runner
selection, and an explicit Metal state.
Observed Ollama identity requires immutable runtime bytes or manifest plus the selected internal
runner because Ollama can route Apple Silicon models through different engines. Duplicate,
contradictory, unknown, and backend-inapplicable capability facts are rejected. Required version,
commit, and build facts must carry observed values. Literal absence markers including `unobserved`,
`unknown`, and `unavailable` do not complete an observed identity.

### Model

Representations have distinct identity shapes:

- `mlx_snapshot`: snapshot file manifest plus config and tokenizer digests;
- `gguf`: full file bytes plus GGUF metadata and tokenizer metadata;
- `ollama_manifest`: manifest/config/layer digest closure.

`cross_representation_equivalence` is fixed to `unproven` in v1. Mapping digests and `mapped`
states are rejected because v1 has no typed, indexed mapping artifact whose identity can be
recomputed and bound to both model records. Labels and marketing names never create equivalence.

The additive direct MLX runtime/model manifests are stricter prospective records. They bind
descriptor-relative physical file identity and digest closure without importing the packages or
loading the model. A manifest is not observed execution evidence. A future worker must revalidate
the same closures, report selected imported modules and active backend facts from the same process,
and satisfy authorization/custody before a run can be eligible.

## Prospective protocol

The protocol binds exact prompt bytes and digest, chat-template digest, sampler controls, output
and context limits, allowed cache cohorts, repeat count, fixed ordering, backend order, concurrency,
timeout, retries, exact runtime/model/host allowlists, and an exact ordered run schedule.

Each schedule slot binds sequence number, run ID, backend, runtime, model, host, process instance,
model instance, cache-preparation identity, concurrency identity, cache cohort, and exact request
digest. It also binds an ordered concurrency wave. V1 accepts only backend-blocked ordering, and
every scheduled slot must appear exactly once. Relabelled, reordered, duplicated, missing, or extra
run records fail replay.

Prompt bytes and template identity are separate because a backend can transform the same user text
into different tokenization inputs. A later observed runner must capture tokenization identity and
exact request bytes when observable.

## Cache cohorts

Runs are grouped into exactly one of:

| Cohort | Meaning |
|---|---|
| `cold_process_model` | New process or runtime and cold model state |
| `cold_model_warm_process` | Already-running runtime, exact model absent before request, and model absent again after `keep_alive=0` |
| `warm_model_cold_prompt_cache` | Model resident, prompt or KV reuse disabled or empty |
| `warm_prompt_kv_cache` | Prompt or KV state reused and identified |
| `unsupported` | Backend cannot establish a requested cache state |

A cohort label alone never defines a comparison group. Cohorts are never pooled silently, and
every run also binds:

- a content-addressed process instance with runtime, host, and maximum concurrency;
- a content-addressed model instance with model, process, context, batch, and GPU-layer settings;
- a content-addressed cache preparation with parent lineage, closed preparation actions, warm-up
  request digests, context-shift count, and prompt/KV token counts;
- a content-addressed effective concurrency identity with worker slot, active peer count, scheduling
  policy, and the exact peer request-digest multiset.

Analysis keys include all four identities plus backend, runtime, model, host, protocol, request,
and cohort. Exact schedule order remains independently enforced.

For Ollama, cold process/model is unsupported because the runner never starts or restarts the
runtime. Warm-model/cold-prompt and warm-prompt/KV are also unsupported in the pinned version:
prompt caching is always enabled internally and the public API cannot prove an empty or reusable KV
identity. Only `cold_model_warm_process` is executable, and only with exact `/api/ps` absence before
and after, `keep_alive=0`, no warm-up calls, `shift=false`, and `truncate=false`.

## Run observations

A valid run binds exact request bytes and digest, raw response bytes, UTF-8 text, token IDs when
observable, a required finish reason, structured response envelope bytes, backend-native metrics,
resource measurements, and all identity references. Every byte-bearing field carries a matching
digest. Observed runs also account for one inference request and zero or one model process start.

An invalid run carries the request digest and an error digest, but no partially trusted output.
This permits custody without turning malformed backend output into a successful observation.

Ollama does not expose a trustworthy generated-token sequence. Its deprecated `context` array is
not projected into `token_ids`. Valid runs preserve the exact response envelope in the run.
Malformed output or post-request identity/cache drift closes as digest-safe invalid run custody;
the untrusted exact transport bytes remain separately preserved and action-linked. Every
dispatched identity or generation action retains an indexed bounded response artifact, including
empty and partial transport failures. Replay reconstructs both identity snapshots from those raw
envelopes rather than trusting the stored projections. Native `eval_count` must be less than or
equal to the frozen output limit; no context/token equivalence is inferred.

## Ollama request and authorization protocol

The backend-specific package contains one run and exactly nine ordered calls: four read-only
identity calls, one `/api/generate`, and the same four identity calls immediately afterward. The
request body is generated from a closed allowlist and fixes `stream=false`, `raw=true`,
`shift=false`, `truncate=false`, an explicit `think` decision (or version-pinned omission),
`keep_alive=0`, seed, temperature, top-p, top-k, min-p, repetition penalty, context, and output
limit.

An explicit `:local` request name blocks Ollama's remote-manifest proxy path. Runtime binary bytes,
local manifest/config/layers, endpoint, mechanically derived canonical model name, output-root
instance, process/model/cache/concurrency identities, `/api/show` projection, request bytes, and
all budgets are fixed before authorization. Identity and generation require distinct one-shot
artifacts whose nonce hashes were already committed in the declaration. Action counts, request
bytes, and complete bounded-read allowances are reserved before their side effects; received bytes
are recorded separately. The timeout is one monotonic absolute deadline for the complete HTTP call,
not a renewed socket-operation timeout. Failures are never retried. Production generation is additionally
disabled until the loopback listener process and active runner/Metal state can be mechanically
attested.

## Direct MLX worker protocol

The direct architecture does not use a discoverable TCP listener. A future parent creates one
worker per run and one inherited private `AF_UNIX` socketpair endpoint at child FD 3. Frames are
bounded length-prefixed canonical JSON. The only order is:

```text
parent_hello -> worker_identity -> authorize_once -> authorization_ack ->
generate_once -> result_or_terminal_error -> shutdown -> shutdown_ack
```

The parent owns process birth and must bind PID/birth identity, executable bytes, worker bytes,
applicable dependency distributions, Python standard-library/native-runtime/dynamic-loader bytes,
the supplied package-root and model closures, actual selected module files, closed environment,
cache class/state, default device, compiled Metal availability, generation-stream device, and
exact memory limits before revealing the committed one-shot nonce. Unrelated descriptors, shell,
user commands, network aliases, retries, warmups, concurrency, and reruns are forbidden. The
future ledger reserves every action before side effects and closes accepted, invalid, refused, or
interrupted outcomes through the existing atomic bundle custody.

Schema 1.0 defines but does not implement that state machine. It also does not implement the
private-IPC framing, protocol order enforcement, timeout/termination logic, or untrusted worker
result validation. No launch, socketpair, authorization, model load, or generation function is
reachable. The deterministic fixture reconstructs a refused package from sealed fake byte
closures rather than simulating success.

The pinned sampler is greedy temperature-zero argmax. The seed is still recorded and must be set on
the generation thread because MLX random state is thread-local, but greedy sampling consumes no
PRNG. Fixed controls are not a determinism guarantee. Prompt/template/tokenization bytes, generated
token IDs, stop criteria, cache construction, prefill, KV quantization state, exact runtime cache
classes, memory limits, and final stream synchronization all remain part of the run identity.

Native prompt TPS includes prefill plus the first decode step. Native generation TPS is a
cumulative decode average after that first token. Peak memory is scoped since process start or the
last explicit reset; TTFT is unavailable. Device strings and stream completion do not prove
individual Metal kernels executed, so the protocol forbids that claim.

## Ollama repeatability-study declaration

`ollama_repeatability_study_declaration` schema 1.0 is additive to the existing foundation and
Ollama package schemas. It is a prospective declaration, not permission or observation. The
canonical Qwen3 plan binds:

- foundation commit `7f89682bdc50a944cf74e4729f5acffa48dc6f1a` and schema 1.0 contracts;
- prior user-provided Ollama `0.35.1`, Qwen3 8B Q8 manifest
  `sha256:e56358ca25dd14db6853a9f68a92d717aaa6f0a94250a72d1a0f3d86a9f30130`,
  and Apple M5 Pro/macOS identity without converting them into fresh observed evidence;
- one exact UTF-8 prompt, trusted generated request bytes/digest, explicit `think=false`,
  `raw=true`, `stream=false`, `shift=false`, `truncate=false`, `keep_alive=0`, every sampler
  control, context/output limit, numeric loopback endpoint, absolute call deadline, bounded reads,
  and zero redirects/proxies/retries;
- five serial, single-attempt, non-rerunnable repeats in
  `cold_model_warm_process`, with no warm-up or warm prompt/KV claim;
- a separately authorized four-call metadata preflight and per-run identity/generation phases;
- terminal accepted/invalid/refused/interrupted handling and within-backend analysis only.

Exact package closure is never inferred from a model name or path. Callers either provide every
scheduled canonical package, which is verified and embedded, or provide none and receive an
incomplete declaration. Bound repeats must share one exact runtime, model, host, and output-root
identity. The global metadata-preflight phase identifies the first run's exact package and
preflight nonce commitment; it remains separately unauthorized. Missing runtime/model bytes and
package/nonce identities remain null. Output-root markers and nonce preimages are never created by
declaration construction.

Completeness does not imply generation eligibility. Schema 1.0 always reports observed generation
and replay ineligible because it cannot content-bind the loopback listener owner or active internal
runner/Metal state. Its bytes and semantics remain unchanged from PR #3. The separate negative
attestation verdict described below binds the immutable declaration identity and explains why the
existing gate stays closed; it is not embedded in the declaration. Fixed seed and temperature
remain controls, not determinism guarantees.

## Ollama listener and runner attestation assessment

The additive schema-1.0 assessment is a feasibility contract, not live evidence. It binds the
merged declaration contract and exact built-in declaration identity, pinned source revisions,
exact Qwen3 generation request digest, numeric IPv4 loopback endpoint, and a macOS
27.0.1/arm64 non-root scope. Its normative requirements are intentionally stronger than process
discovery:

- the exact retained accepted connection must bind to owner UID, PID plus anti-reuse birth/unique
  identity, and no-follow executable bytes;
- that binding must survive close/rebind/replacement/proxy races through the response;
- the canonical external request must bind to the exact internal scheduler `runnerRef`,
  completion transport, runner process/artifact, model manifest/config/layer closure and one load
  lifecycle;
- actual backend and Metal execution must bind to that same internal request;
- one request-scoped content chain must cover every link.

Darwin `proc_pidinfo`/`proc_pidfdinfo`, TCP PCB data, dynamic code identity, endpoint checks,
process listings, and `lsof` are candidate observations, not a retained atomic chain. Pinned Ollama
`/api/ps` reports a load snapshot and pinned source holds richer state internally, but neither
public API returns the request-to-runner/model/Metal linkage. Mutable argv, environment, logs,
names, version strings, model tags, `size_vram`, and before/after agreement remain weak evidence.

The only supported verdict is therefore `insufficient`. Every required ID appears in
`missing_requirement_ids`, both observed-generation eligibility fields are false, and both positive
attestation IDs are null. Verification reconstructs those values from the immutable pinned spec,
so a caller cannot turn a negative result into eligibility. Metadata preflight remains a separate
generation-free authorization decision.

No acquisition abstraction is present. The offline commands and fixture perform no process probe,
socket inspection, socket or subprocess call, Ollama request, nonce consumption, output-root
consumption, model action, external network, cloud, or spend. A future positive schema requires a
separately authorized privileged accepted-socket/process primitive plus reviewed in-process Ollama
cooperation for runner/load/model/Metal dispatch and a cryptographic chain between them.

## Equality semantics

Within each backend, runtime, model, host, protocol, process instance, model instance, cache
preparation, effective concurrency identity, request, and cache cohort, replay independently compares:

- raw response digest;
- text digest;
- token ID sequence digest when every run exposes token IDs;
- finish reason;
- structured envelope digest.

`equal` means exact equality for that projection only. If any run is invalid, the group is
`incomplete`. If token IDs are unavailable, the token projection and terminal group classification
are `not_comparable`. Only fully comparable valid groups can be `exact` or `divergent`. A semantic
projection is not defined in v1. No LLM judge is used.

## Performance and resource semantics

Native metric names and units are preserved. The contract supports TTFT, prompt evaluation count
and duration, generation count and duration, total duration, and load duration with explicit
availability. It does not rename backend counters into false equivalents.

Derived throughput is computed only as:

```text
generation_count * 1_000_000_000_000_000 // generation_duration_ns
```

The result unit is `tokens_per_second_millionths`. Replay publishes the integer values rather than
a rounded cross-backend average.

Memory and energy require a named measurement method. Process RSS is not a proxy for Metal or GPU
memory. Energy is unavailable in v1.

## Fixture protocol

The built-in fixture contains four synthetic runs:

- two byte, text, token, finish, and envelope-identical MLX-LM records in one
  `warm_model_cold_prompt_cache` process/model instance, prepared from an indexed cold lineage
  before each run;
- two llama.cpp records with text, token, raw, and envelope divergence in
  `warm_prompt_kv_cache`;
- synthetic native durations and counts, plus explicit unavailable TTFT, memory, and energy;
- MLX snapshot and GGUF identities with equivalence `unproven`;
- two process instances, two model instances, explicit cold/warm cache-preparation lineage, one
  serial concurrency identity, and four exact schedule slots;
- two forbidden declarations with zero process, inference, network, and download budgets.

Synthetic availability exercises arithmetic and schema behavior. It is never converted into an
observed or hardware benchmark claim.
