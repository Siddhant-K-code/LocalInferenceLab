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

The direct architecture does not use a discoverable TCP listener. The inert custody parent creates one
worker per run and one inherited private `AF_UNIX` socketpair endpoint at child FD 3. Frames are
bounded length-prefixed canonical JSON. The only order is:

```text
parent_hello -> worker_identity -> authorize_once -> authorization_ack ->
generate_once -> result_or_terminal_error -> shutdown -> shutdown_ack
```

The inert parent owns process birth and binds PID/PPID, exact launch-target bytes, worker bytes,
the exact FD set, closed environment, package/protocol/spec IDs, nonces, physical output root,
authorization, terminal refusal, and wait status. Verified worker bytes are executed from a
parent-created unlinked private regular-file snapshot on stdin, not reopened from the repository
path. The selected interpreter bytes are executed from a private mode-0500 output-root snapshot;
transient FD 4 binds those exact bytes and is closed before the worker reports only `[0,1,2,3]`.
Replay cross-binds the authorization nonces/deadline and worker PID to the hello, identity, parent
process evidence, and wait result. A future generation-capable parent must also bind
applicable dependency distributions, Python standard-library/native-runtime/dynamic-loader bytes,
the supplied package/model-root byte closures, actual selected module files, closed environment,
cache class/state, default device, compiled Metal availability, generation-stream device, and
exact memory limits before revealing the committed one-shot nonce. Unrelated descriptors, shell,
user commands, network aliases, retries, warmups, concurrency, and reruns are forbidden. The inert
ledger admits only one refusal. Accepted and invalid generated results are unreachable.

The static model manifest binds supplied bytes and exact present monolith/canonical indexed-shard
projections, not semantic tensor completeness. Before authorization, the future worker must use
the pinned normal non-distributed (`sharding=None`) `mlx_lm.utils.load` / `load_model` path, require
`model.load_weights(..., strict=True)`, and bind successful parameter key/shape validation to the
same worker, package, and result.

The additive inert-custody schema 1.0 implements framing, exact order/direction, absolute deadlines,
termination/wait, authorization consumption, refusal validation, and output custody. It does not
implement or authorize MLX import, model load, device action, or generation. The legacy
prospective schema and deterministic static fixture remain unchanged. Its terminal action ledger
counts only completed actions. Failure custody separately records whether a child was spawned and,
when it was, the exact parent-owned wait evidence that proves reaping; pre-spawn failures carry no
child-reaped claim.

The additive runtime-preflight schema uses a distinct action, protocol, and worker. Public
schema-1.0 execution is unreachable because the reviewed MLX-LM `0.30.6` requirement
`mlx>=0.30.4` conflicts with the reviewed MLX `0.29.3` pin. The public command validates and
rejects that receipt before output-root access, socket/process creation, authorization, import, or
probe. No public flag unlocks it; a compatible source/version pair requires a separately reviewed
schema and new authorization. Exact internal synthetic fixtures continue to exercise this fixed
order:

```text
parent_hello -> worker_identity -> authorize_once -> authorization_ack ->
preflight_once -> preflight_result -> shutdown -> shutdown_ack
```

The authorization permits only exact distribution-version checks, imports of bound `mlx.core` and
`mlx_lm`, `default_device`, `metal.is_available`, `default_stream`, and `synchronize`. MLX imports
are absent before acknowledgment. The worker reports import timing and possible initialization,
strict backend/device/stream representations, synchronization completion, completed action and
its actual imported-module closure. Its ledgers are intentionally disjoint:
`completed_runtime_actions` records ordinary completed imports/probes,
`model_non_actions` records zero model/tokenizer/inference/cache/etc. actions,
`guarded_action_attempts` records Python-audited network/process-or-command/filesystem-mutation
attempts, and `completed_forbidden_actions` records worker-reported completion of those forbidden
categories and must be all zero. The audit hook is not an OS sandbox. A rejected worker frame is
untrusted, so its completed ledger is not accepted as parent proof. The parent requires all
non-stdlib module files to belong to the retained supplied-root manifest. Fileless stdlib aliases
are limited to Python 3.12's exact `typing.io` and `typing.re` compatibility entries; arbitrary
fileless origins remain invalid. Terminal import/probe errors remain closed and replayable;
protocol/process failures retain parent-owned wait custody. Replay imports nothing and starts no
process or socket.

The pinned sampler is greedy temperature-zero argmax. The seed is still recorded and must be set on
the generation thread because MLX random state is thread-local, but greedy sampling consumes no
PRNG. Fixed controls are not a determinism guarantee. Prompt/template/tokenization bytes, generated
token IDs, stop criteria, cache construction, prefill, KV quantization state, exact runtime cache
classes, memory limits, and final stream synchronization all remain part of the run identity.

## Runtime-independent determinism canary protocol

The determinism canary is an offline schema and analyzer, not an execution protocol. Schema 1.0
contains no canary launch, import, backend/device/Metal query, synchronization, model, MLX tensor, or
authorization command. Every committed output-bearing result is an embedded
`synthetic_fixture`; it is not evidence of real MLX/Metal behavior.

Schema 1.0 accepts only the pinned synthetic cases/results. It rejects
`authorized_observation`, physical result, and case-registry records even if they contain
well-formed self-asserted SHA-256 strings. A future physical-evidence milestone needs a distinct
schema and closed-bundle verifier that loads and independently validates the referenced
authorization, runtime, device, process, acquisition, and case-registry records.

The prospective matrix includes elementwise add and IEEE-edge identity, matmul, reduction sum,
softmax, RMS normalization, and paired fused/unfused multiply-add across `float32`, `float16`, and
`bfloat16`, each under explicit and deferred evaluation. Every one of the 48 cells is
`unverified_future_support`. Eight cells have exact embedded synthetic cases; 40 are explicitly
prospective-only and cannot produce a schema-1.0 result. A successor protocol must independently
prove support before changing a cell status.

Each operation has a content identity over its mathematical contract and full parameter schema.
Each represented case/result binds that identity, its exact matrix cell, and concrete parameters.
Reduction and normalization bind axes/keepdims, initial accumulator bytes, accumulation order and
precision, and stage rounding. RMS normalization additionally binds exact epsilon bits, mean
divisor, epsilon-add precision/rounding, reciprocal-square-root contract/rounding, and output
multiply precision/rounding. Matmul, softmax, and fused/unfused arithmetic similarly bind every
intermediate order, precision, fusion, and rounding decision. Verification re-derives all expected
fixture bytes with bounded standard-library scalar arithmetic.

Output comparison requires identical dtype, shape, endianness, element count, and exact byte
length. A mismatch rejects the record; it cannot yield a partial metric. For compatible records:

- bitwise equality compares payload bytes and canonical output digests compare the full descriptor;
- finite pairs report maximum absolute/relative error as exact big-endian binary64 hex and maximum
  native-dtype ULP distance;
- NaN pairs are numerically equal only when sign and payload bits match;
- infinity pairs are equal only when signs match;
- signed zeros have zero numerical/ULP error while their bit difference is counted;
- the ordered ULP mapping collapses both signed-zero encodings before cross-zero distance;
- non-finite pairs are excluded from finite error maxima and counted separately.

The future experiment declaration is precommitted: five repeated evaluations within one process,
five cold-process observations, paired five-CPU/five-GPU observations, paired five-fused/five-
unfused observations, and paired five-output-materialization-only/five-explicit-synchronization
observations.
Retries and selective replacement are zero. Same-condition repeatability accepts only when every
output is bitwise equal. CPU/GPU, fusion, and synchronization comparisons remain report-only
unless a separate reviewed protocol defines a threshold. Timing is forbidden unless a later
protocol separately authorizes it.

Native prompt TPS includes prefill plus the first decode step. Native generation TPS is a
cumulative decode average after that first token. Peak memory is scoped since process start or the
last explicit reset; TTFT is unavailable. Device strings and stream completion do not prove
individual Metal kernels executed, so the protocol forbids that claim.

## Static MLX runtime qualification protocol

The qualification gate has no transport, worker, nonce, authorization, or execution command. Its
canonical flow is:

```text
explicit qualification package -> strict static validation ->
dependency/wheel/closure/API assessment -> exactly one qualification record
```

The package binds one exact target environment; exact MLX/MLX-LM and supplied transitive
distribution versions; immutable source revisions/tags; wheel filenames, hashes, sizes, provenance
URLs, tags, and exact supplied wheel bytes; exact raw METADATA bytes; all supplied requirements and
markers; one `Requires-Python` specifier set for complete metadata; exact `==` pins for the
top-level `mlx` and `mlx-lm` selections; the forbid-all-extras policy; and immutable supplied source
evidence for the seven future preflight probes. Reviewed source records bind exact authoritative
repository/tag/commit/path/full-file hash facts plus minimal line-bounded excerpt bytes, excerpt
hashes, declaration identities, access forms, and static signatures. Marker and
`Requires-Python` evaluation use only the
package's explicit environment. Dependency explanations name the selected version or exact absence.
Closure is limited to supplied distribution metadata and never claims
stdlib/native-loader completeness.

Eligibility verifies that supplied wheel bytes match the declared size/digest, contain exactly one
bounded dist-info METADATA and WHEEL control record, and bind the same metadata bytes and filename
tag. Reviewed METADATA is parsed as bounded Core Metadata without canonicalizing away unrelated
headers or the description body; the whole payload must be valid UTF-8, identity and
`Requires-Python` are singleton fields, dependency values may not be folded or semantically
duplicated, and all raw bytes remain digest-bound. Reviewed probe evidence is reconstructed with
bounded AST/text checks; missing or duplicate definitions, dynamic generation or aliases,
signature or provenance drift, malformed boolean/integer fields, overclaims, self-attested
anchors, and coordinated rehashing are rejected. CPython `v3.13.0` commit
`60403a5409ff2c3f3b07dd2ca91a7a3e096839c7` separately binds
`importlib.metadata.version` and its `METADATA["Version"]` access. A real
reviewed candidate additionally needs an independently committed evidence anchor in the
qualification specification. The allowlist retains previously merged anchor
`sha256:e4bd7b6f5ce7656d1a490a6e4b39e23e1b9a6acaee55084744a8a267f0007f2c`
from before the target mutation. The target-bound MLX `0.30.4` / MLX-LM `0.30.6` package now
derives pending review anchor
`sha256:1382dfd5e9f5d19bfa74c8f3a7ad4db5b30d10caddfed3cd62c130242003f45f`,
which is intentionally not allowlisted in this change. Both exact wheel byte streams and exact raw
METADATA are embedded, so verification and reconstruction are offline. The worker-evidence spec
and source anchor remain
`sha256:6c83f627032a2c3db38eee34f804469a42e227a3af0a84ed5c0052a192d29e97`
and `sha256:10ab50cbfb94890bae1dd8c57180645d5781e454b1a8171b158c4d932121d9dd`.
The package binds prospective runtime target anchor
`sha256:008f7c3ac60614bc6909822180a4bc0b9be17eaf0aa3abc23829eb2842c4fdc0`.
The target is exact CPython 3.13.15 (`cpython-313`, `cp313`,
`cpython-313-darwin`) on macOS 27.0.1 build 26A434 arm64, with the interpreter's deployment target
11.0 and the runtime wheels' deployment target 15.0. Both exact wheel byte streams and exact raw
METADATA are embedded, so verification and reconstruction are offline. `Requires-Python` uses the
full 3.13.15 value; wheel compatibility remains `cp313`-scoped. The pair dependency and all seven
source/API surfaces are satisfied, while the absent `mlx-metal`, `numpy`, `transformers`,
`sentencepiece`, `protobuf`, `pyyaml`, and `jinja2` distributions plus unreviewed-anchor blocker
keep the result deterministically ineligible. The exact anchor blocker is
`reviewed_candidate_not_committed_in_spec:sha256:1382dfd5e9f5d19bfa74c8f3a7ad4db5b30d10caddfed3cd62c130242003f45f`.
No qualification record is committed in the target change. Historical projections are always
ineligible.

The prior prospective value 3.13.0 is superseded. A bounded development-host observation of an
already available 3.13.15 interpreter is retained in the target anchor without its private
absolute path and is explicitly not future runtime evidence. The failed historical receipt also
reported 3.13.15, but it is not accepted as target or runtime evidence and its existing evidence
IDs remain unchanged. Caller-supplied observation envelopes are structure-only claims. Exact
identity fields, `claimed_observer_relationship=independent_from_candidate`, and
`claimed_self_attested=false` remain self-asserted and can never satisfy qualification or
preflight. Replay always reports unavailable authoritative observer identity and unavailable
custody-bound executable/platform measurement. Structural validation rejects self-attestation,
provenance relabeling, ambiguous host promotion, executable/hash/realpath,
version/cache-tag/ABI/SOABI, macOS product/build/deployment, and architecture drift even when
claim identities are recomputed.

The evidence supports only source-surface availability. The import records prove intended module
names and declarations, not import or native-loader success. Callable declarations do not prove
runtime executability, backend or device availability, a positive Metal result, or completed
synchronization. `runtime-worker-api-evidence-verify` replays the committed evidence offline and
performs none of those physical actions.

The record reconstructs rather than trusts its decision and sorted blockers. Coordinated package
and record rehashing cannot preserve a stale assessment. All install/network/process/socket,
authorization, import, Metal/device/backend/synchronization, model/tokenizer/prompt/cache,
inference/generation/benchmark/cloud/spend counters are exactly zero and reject booleans.
`eligible_for_new_observed_authorization` is only a static prerequisite for human review. Schema
1.0 remains permanently disabled; a distinct schema-1.1 protocol/spec/worker review and fresh
explicit authorization are mandatory before any physical action.

### Scalable supplied-wheel closure custody

Large or numerous third-party wheels are not embedded in Git. The additive
`mlx_wheel_evidence_pack_manifest` binds their official PyPI identities, exact raw dist-info
METADATA/WHEEL bytes, applicable dependency graph for an externally acquired exact selection, and
source bindings. It contains no release inventory and does not prove global PyPI optimality,
non-yanked status, or highest wheel ranking. The canonical real manifest is
`evidence/mlx-wheel-closure-mlx-0.30.4-mlx-lm-0.30.6-macos-arm64-py313-v1.json`,
with manifest ID
`sha256:837deaf4265bf921e36712ee4ea7210eb7869b1487cc196e701689dd0fdd38be`
and pack-spec ID
`sha256:14b823fcf06c3107d76bbc41742353d6d2e57aa5683ab298533c9b7f84a714b7`.

The generic verifier requires that manifest ID as a caller-supplied content address and an exact local
directory containing all 34 named wheels and nothing else. It uses bounded no-follow descriptor
reads and inert ZIP inspection only. It rejects substituted bytes, links, unsafe basenames,
missing/extras, duplicate/case-colliding or overlapping ZIP entries, traversal, multiple dist-info
records, malformed UTF-8 metadata, raw METADATA/WHEEL drift, tag drift, marker-dependent omissions,
recursive gaps, and coordinated rehashing against the trusted ID. No network is available during
verification or record reconstruction.

A successful pack receipt proves only that those exact supplied bytes were present for that
verification. A committed manifest does not. A later record may remove distribution blockers only
by reconstructing with the pack present. Qualification separately requires membership in a
committed reviewed-manifest allowlist. This PR introduces the manifest but leaves that allowlist
empty, so `wheel_evidence_manifest_anchor_not_independently_reviewed` keeps the real reconstruction
ineligible even after the distribution and worker-API blockers close. No real qualification record
is committed here, and no runtime action is authorized.

## Prospective schema-1.1 model-free runtime-preflight protocol

Schema 1.1 is a contract/refusal layer only. It defines no worker or execution command. Its current
canonical flow is:

```text
committed schema-1.0 qualification record + optional caller-supplied authorization claim ->
strict canonical reconstruction -> prerequisite assessment ->
disabled/unreachable contract record -> process-free inspection or closed-fixture replay
```

The qualification prerequisite must be an eligible `reviewed_candidate` record derived from the
active schema-1.0 qualification spec, and its independently derived evidence anchor must be in that
spec's committed anchor set. The synthetic-positive fixture is rejected by candidate kind and
anchor membership even though it exercises the schema-1.0 positive decision. Historical
schema-1.0 records are rejected by candidate kind, decision, and anchor membership. Their frozen
records and identities are never rewritten.

The authorization prerequisite cannot be satisfied in this milestone. Authoritative acquisition,
current-expiry observation, exclusive consumption/non-reuse, and independently verified
output-root and nonce facts are unavailable. An optional
`mlx_runtime_preflight_authorization_claim` uses
`evidence_kind=caller_supplied_structure_only` and may carry claimed one-shot, unconsumed,
qualification, anchor, spec/protocol, root/nonce digest, and internally ordered time-window fields.
Validation uses no wall clock and treats every field as self-asserted. The claim never proves
current freshness, authoritative acquisition, independent binding, consumption, or non-reuse and
can never make `prerequisites_satisfied=true`.

The prospective future physical sequence is:

```text
validate committed real-candidate qualification ->
require authoritative authorization acquisition/expiry/consumption custody ->
require independently verified output-root and nonce facts ->
verify exact isolated supplied runtime closure ->
future parent launch/identity -> future authorization consumption ->
one model-free preflight -> strict parent validation -> shutdown/parent wait
```

The base action set is exact closure verification; imports of pinned `mlx.core` and `mlx_lm`;
bounded distribution-version, default-device, default-stream, and Metal-availability metadata.
One default-stream synchronization canary is conditional on a distinct explicit one-shot
authorization. There are no retries, warmups, concurrent probes, package retrieval/install,
model/tokenizer discovery or loading, prompt/cache/inference/generation, tensor allocation or
operations, benchmarks, cloud, or spend.

Every future result must keep three separate ledgers: `attempted_actions` for all attempted allowed
or forbidden actions, `completed_actions` only for proven completions, and `accepted_evidence` only
for the strict parent-validated subset. Python audit hooks are defense-in-depth attempted-action
telemetry, not an OS sandbox and not proof that an action did not occur. Current records contain no
runtime result: all ledgers are empty, all physical counters are zero, and prerequisite
satisfaction cannot make execution reachable.

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
