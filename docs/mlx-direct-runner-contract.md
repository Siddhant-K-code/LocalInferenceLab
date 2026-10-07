# Direct MLX worker contract

## Status and non-action boundary

The original schema-1.0 package contract remains prospective. It defines an exact supplied package-root byte closure,
an exact supplied model-root byte closure and present weight projection, a private finite worker
protocol design, determinism controls, result semantics, and future authorization/custody
requirements.
The additive inert-custody schema remains a frozen refusal-only worker launch, not a production MLX
worker. A separate additive runtime-preflight protocol defines one model-free
import/device/backend/synchronization observation and remains exercised by exact internal synthetic
fixtures. The reviewed MLX-LM `0.30.6` / MLX `0.29.3` pair is dependency-incompatible, so public
schema-1.0 execution is unreachable: `runtime-preflight` validates and rejects the receipt before
output-root access, socket/process creation, authorization, import, or probe. No public flag unlocks
it; a compatible source/version pair requires a separately reviewed schema and new authorization.
Only `custody-self-test` can currently start a public child/private socket; all
capability/spec/inspect/replay commands remain process-free.

The additive static runtime qualification gate does not relax that boundary. It can derive only
`eligible_for_new_observed_authorization` or `ineligible` from explicit candidate bytes and
metadata. The positive value means eligible for human review toward a distinct schema-1.1
milestone, not permission, runtime executability, import success, Metal availability, model
support, or synchronization. Schema 1.0 remains permanently disabled and the sole observed attempt
must never be rerun.

The built-in package is deliberately incomplete. No exact preexisting local MLX model was supplied
or discovered, and discovery would violate the explicit-path boundary. Wired/cache limits, active
runtime/backend evidence, applicable dependency closure, Python standard-library/native-loader
closure, production private-IPC/protocol/result-validation implementation, worker process birth,
strict model parameter key/shape load evidence, output-root identity, and authorization are also
absent. `observed_execution_reachable`, `worker_process_may_start`, and
`authorization_may_be_consumed` are therefore fixed `false`.

Runtime-preflight evidence closes or splits only runtime-scoped blockers. Model-action eligibility
remains false, including strict parameter load, exact cache class, memory limits, model
authorization, generated-result production, and per-kernel Metal proof.

## Threat model

The future study may trust the study operator, the current owner, and the OS kernel. It does not
trust:

- mutable path names, symlinks, hard-link aliases, special files, or replaced ancestors;
- ambient `PYTHONPATH`, user site, `.pth`, editable installs, namespace ambiguity, or imports that
  occur after authorization;
- Hugging Face revision/model names, environment-selected caches, snapshot resolution, redirects,
  proxies, DNS, or other network aliases;
- model or tokenizer custom code;
- arbitrary worker messages, success-shaped fallbacks, logs, version strings, or device labels as
  observed execution evidence.

Static manifests are declarations about one no-follow read. A future positive execution path must
re-scan and match the same closure, then bind the retained descriptors and selected imported files
to the same worker process before consuming one-shot authorization.

## Exact supplied package-root byte closure

`mlx_runtime_manifest` 1.0 is compiled only from explicit local paths. The compiler:

1. Opens every path component descriptor-relative with no-follow flags.
2. Requires current-owner, non-group/world-writable directories and regular files.
3. Rejects symlinks, special files, hard-link aliases, hidden entries, path traversal, `.pth`,
   `.egg-link`, and every top-level importable `sitecustomize` or `usercustomize` source, package,
   bytecode, or native-extension form.
4. Applies fixed file, entry, depth, path, individual-size, and aggregate-size bounds.
5. Hashes one stable descriptor snapshot and records relative path, device, inode, mode, link count,
   size, and digest without publishing an absolute path.
6. Binds the executable Python regular file, implementation/version/ABI/platform declaration,
   complete byte closure of the explicitly supplied package root, every direct
   `.dist-info/METADATA` name/version/digest and raw `Requires-Dist` header, any `direct_url.json`
   digest, selected MLX/MLX-LM module-file declarations, exact worker bytes, and the closed future
   worker environment. Verification reconstructs the runtime scan specification from those
   projections and requires its identity to match.

This is not a complete Python execution-runtime or dependency closure. The compiler records raw
`Requires-Dist` strings but does not parse/evaluate environment markers or extras and does not
require applicable dependency distributions or versions to be present. It binds the interpreter
file but does not discover or bind its standard library, `lib-dynload`, `libpython`, dynamic
loader, native shared libraries, or frameworks. Those are permanent explicit eligibility blockers
in this schema, even when filesystem runtime and model manifests are supplied.

`synthetic_fixture` and `offline_filesystem_manifest` evidence are mechanically separated: every
physical root and file scope must respectively be `synthetic_fixture` or `current_effective_user`.
Changing only the evidence discriminator cannot make sealed fake identities eligible.

The environment contains only:

```text
HF_HUB_OFFLINE=1
MLXLM_USE_MODELSCOPE=False
PYTHONHASHSEED=0
PYTHONDONTWRITEBYTECODE=1
PYTHONNOUSERSITE=1
TOKENIZERS_PARALLELISM=false
TRANSFORMERS_OFFLINE=1
```

These variables are defense in depth, not the primary network proof. Pinned MLX-LM source skips
snapshot resolution only when its input is already an existing local path. A future worker must
receive that retained, revalidated local directory and must be prevented from making network
syscalls.

That future interpreter must start with exact flags `-I -S -E -s` and a descriptor-bound runtime
root as its only explicit import root. Disabling user site alone is insufficient: `-S` prevents
startup execution through `sitecustomize` before worker identity validation.

## Exact supplied model-root byte closure

`mlx_model_manifest` 1.0 accepts one explicit, materialized, flat local directory. It requires:

- `config.json`, `tokenizer_config.json`, a tokenizer vocabulary artifact, and one or more
  `model*.safetensors` files;
- `model.safetensors.index.json` for every canonical shard-form layout, with the exact present set;
- the exact weight-index path, digest, and normalized referenced-shard projection;
- the complete no-follow regular-file closure and physical root identity;
- exact config, tokenizer-config, tokenizer, weight, and chat-template digests.

Without an index, the only permitted weight layout is exactly `model.safetensors`. Indexed weights
must use one canonical contiguous set from `model-00001-of-000NN.safetensors` through
`model-000NN-of-000NN.safetensors`, all with the same total and exactly matching both the present
files and index projection. Mixed monolith/shard layouts and malformed, incomplete, noncontiguous,
or inconsistent shard names are rejected. Additional Safetensors outside the pinned loader's
`model*.safetensors` scope are also rejected rather than retained as unused model-root bytes.

Only the pinned loader's data extensions are admitted. Python/shared-library/custom-code files,
executables, symlinks, special files, nested path escapes, remote-code markers (`model_file`,
`auto_map`, or enabled `trust_remote_code`), missing/extra shards, and runtime snapshot resolution
are rejected. If neither `chat_template.jinja` nor a non-empty `tokenizer_config.json` template is
present, the manifest remains valid static custody but eligibility reports `exact_chat_template`
missing.

The repository does not search local caches or infer a snapshot from a model name. The built-in
study therefore has no real model identity.

The manifest does not prove semantic model-parameter completeness. Only a future worker using the
pinned normal, non-custom-code, non-distributed (`sharding=None`) `mlx_lm.utils.load` / `load_model`
path and
`model.load_weights(..., strict=True)` can establish that tensor keys and shapes satisfy the
instantiated model. That future strict-load result must be bound to the same worker and package;
`strict_model_parameter_key_shape_load_evidence` remains a permanent schema-1.0 eligibility
blocker even for a valid filesystem model manifest.

## Private worker custody and protocol

The parent, not the worker, owns lifecycle and authorization. The frozen design uses one
parent-created inherited `AF_UNIX` socketpair descriptor, assigned to child FD 3. There is no bind,
listen, accept, DNS, proxy, redirect, shell, arbitrary command, or ambient user-controlled import.
Unrelated descriptors are closed before worker code runs.

Frames are a four-byte unsigned big-endian length followed by canonical JSON, bounded to 1 MiB.
The only sequence is:

```text
parent_hello
worker_identity
authorize_once
authorization_ack
generate_once
result_or_terminal_error
shutdown
shutdown_ack
```

Each declared run gets exactly one parent-owned worker, one generation request, concurrency 1, one
attempt, zero retries, zero warmups, and no selective rerun. `worker_identity` must bind process
birth/PID, executable bytes, worker bytes, runtime/package/module closure, active imported module
files, environment, default device, Metal availability, and generation-stream device. The parent
must revalidate those facts before revealing the committed nonce preimage. A future action ledger
reserves process and inference actions before side effects and closes accepted, invalid, refused,
or interrupted outcomes through receipt-last atomic publication.

The inert custody surface implements the finite exchange with `os.posix_spawn`, exact interpreter
flags, child FD 3, enumerated descriptor close actions, a closed environment, strict canonical
framing, one absolute deadline, parent-owned termination/wait, one-shot authorization, and
descriptor-relative publication. The no-follow worker-source and private output-root launch paths
reject untrusted writable components (while permitting protected sticky shared ancestors). The
selected interpreter bytes are stably read, copied into a private mode-0500 output-root snapshot,
and reopened read-only before spawn; verified worker bytes are copied into an unlinked mode-0400
snapshot and supplied on stdin. The
worker verifies the interpreter snapshot through transient FD 4 and closes it before reporting the
exact final descriptor set. The interpreter copy is removed only after wait because macOS kills a
running copied interpreter if its final name is unlinked. The selected source bytes are not
presented as cross-platform proof of the already-running parent interpreter; that remains an
explicit blocker. Its result validator accepts only the stable refusal
`mlx_execution_unimplemented_and_unauthorized`; no accepted or invalid generated-result producer
exists. The legacy production-IPC blocker is therefore split, not silently removed: inert
IPC/refusal validation is proven, while generated-result production/validation remains missing.
The public synthetic surface accepts only an output root and internally sealed immutable values;
it cannot receive custom dispatch, scripts, probes, transports, subclasses, or production objects.
Its action ledger records only completed physical actions and completed frame sends/validated
events, never reservations. A failure marker explicitly distinguishes `child_spawned=false` with
no wait claim from `child_spawned=true` with an exact successful parent-owned wait; terminal
failure publication requires either proven reaping or proof that no child was spawned.

## Determinism controls

The pinned prospective controls are:

- exact UTF-8 prompt bytes and digest;
- exact model-manifest chat-template digest; `apply_chat_template=true`, `tokenize=true`, and
  `add_generation_prompt=true`;
- `make_sampler` with temperature 0, top-p 1, min-p 0, top-k 0, XTC disabled, and greedy
  `mx.argmax` semantics;
- seed 424242 applied on the generation thread before sampling, while explicitly recording that
  greedy sampling consumes no PRNG and a seed is a control rather than a guarantee;
- `generate_step`, max 64 output tokens, tokenizer EOS or length stop, prefill step 2048,
  unbounded KV size, and no KV quantization;
- a fresh `make_prompt_cache` result per one-shot worker, with no save/load/reuse/trim/rotation;
- one worker main thread, no distributed launcher or child process;
- explicit first-token scalar evaluation and final generation-stream synchronization.

The exact runtime cache classes remain worker evidence because `make_prompt_cache` can defer to a
model-specific cache. Wired and cache memory byte limits are `null`; guessing host/model-dependent
limits would create false completeness, so both remain named eligibility blockers.

## Backend and Metal evidence

Pinned MLX source selects the default device from compiled backend availability.
`mx.metal.is_available()` distinguishes a Metal-enabled build from a no-Metal build; it does not
prove which kernels executed. A generation stream is created at MLX-LM import time from the then
default device. A future worker must therefore attest device/backend facts and stream identity
inside the same process, then synchronize that exact stream before returning.

Official programmatic APIs can show default device, compiled Metal availability, stream completion,
and memory counters. They do not prove per-kernel Metal execution, dispatch order, fusion, or a
physical GPU identity. GPU traces require external Metal capture configuration and manual Xcode
interpretation. The strongest available cohort claim is consequently **direct MLX runtime
execution with synchronized worker-side backend facts**, not proven per-kernel GPU execution.

## Result and metric semantics

A valid future result must preserve exact prompt token IDs, yielded generated token IDs, raw text
bytes/digest, and finish reason. Arbitrary worker bytes remain a bounded untrusted artifact until
the parent validates their schema and closure.

Native counters and rates retain their upstream meaning:

- prompt count is the tokenizer-produced input length;
- generation count is the yielded non-EOS token count;
- prompt TPS covers prefill plus the first decode step;
- generation TPS is the cumulative decode average after the first token;
- peak memory is process-wide since program start or the last explicit reset, so the contract
  requires a reset immediately before generation if that metric is used;
- TTFT is unavailable and is never manufactured.

Invalid/refused/interrupted terminal records carry digest-safe reason/raw-artifact custody without
partial success. No fixture metric is observed hardware evidence.

## Synthetic refusal fixture

The deterministic fixture contains sealed fake runtime/model byte closures and a complete
prospective package whose eligibility remains `ineligible`. It exercises strict identities,
closure replay, source intent, coordinated-tamper rejection, and custody while recording zero
MLX/MLX-LM imports, Metal/device actions, loads, inference, worker/process/socket/network actions,
downloads, cache mutation, authorization/output-root consumption, cloud, and spend.

The fixture is declaration/refusal evidence only. There is no synthetic accepted execution path,
because implementing a fake worker transport before the real process and attestation design is
reviewed would create misleading assurance.

## Physical inert custody self-test

Create an explicit private output directory and run:

```bash
mkdir -m 700 .artifacts/mlx-inert
localinferencelab mlx custody-self-test .artifacts/mlx-inert
localinferencelab mlx custody-replay \
  .artifacts/mlx-inert/localinferencelab-mlx-inert-custody-v1-*
localinferencelab mlx custody-inspect \
  .artifacts/mlx-inert/localinferencelab-mlx-inert-custody-v1-*
```

The self-test deliberately performs one process start, one private socketpair creation, eight
frames, one atomic authorization consumption, and one terminal wait. It publishes no absolute
path. The authorization binds the exact legacy built-in prospective package ID and full-record
digest, study/protocol/worker IDs, parent/worker nonces, physical output-root identity, action, wall
expiry, and monotonic deadline. The closed bundle records exact bounded frame bytes/digests, action
and non-action ledgers, child wait status, refusal, and blocker reconstruction.

On Linux the parent additionally compares `/proc/<pid>/exe` device/inode to the exact interpreter
launch target. macOS has no equally robust stdlib-only parent-observed running-executable primitive,
so cross-platform running-executable observation remains explicit. The worker's self-report is
never presented as sufficient proof by itself. Replay requires the worker PID to match both
parent-recorded process evidence and the parent-owned wait result, and requires authorization
nonces and deadlines to match the verified hello and worker identity.

## Physical runtime-only preflight

The first authorized observed attempt is a **failed-closed negative result**, not an accepted
runtime preflight. It consumed one authorization, started one child/socketpair, sent one
`preflight_once`, received a result frame, rejected that frame because it reported a forbidden
action attempt, and reaped the child. Retry count is zero.

The public command accepts only the canonical runtime manifest, artifact lock, and install receipt
and always refuses this repository-pinned pair before physical action:

```bash
localinferencelab mlx runtime-preflight \
  runtime-manifest.json runtime-lock.json install-receipt.json
localinferencelab mlx runtime-preflight-negative-replay \
  evidence/mlx-runtime-preflight-negative-v1.json
```

The synthetic harness starts its child as `python -I -S -E -s -B -`, supplies the sealed worker on
stdin, control at FD 3, transient interpreter identity at FD 4, and the retained synthetic package
root at FD 5. Before authorization, it imports no MLX module. After exact synthetic one-shot
consumption, it imports bound fake `mlx.core` and `mlx_lm` modules and exercises the same result
validation without allocating a tensor or claiming kernel execution.

The exact observed package selection retains MLX `0.29.3` and MLX-LM `0.30.6`. MLX-LM declares
`mlx>=0.30.4` on Darwin, so a normal resolver correctly refuses the pair. Preparation therefore
uses hash-locked no-substitution artifacts and records the conflict as
`applicable_dependency_distribution_semantic_closure`; it never presents that semantic closure as
satisfied. The receipt is execution-ineligible for schema 1.0. The retained protocol would check
imported Python modules against the retained supplied-root byte/physical closure. Complete stdlib,
native runtime, dynamic loader, and shared-library closure remain explicit blockers.

The original terminal path retained the terminal failure and authorization-consumption records but
not the rejected worker frame. Consequently, offline evidence proves only the stable category
`worker_reported_forbidden_action_attempt`; it cannot safely distinguish the exact audited event or
the worker's internal import/probe phase. It also cannot prove whether a forbidden action completed:
the missing worker ledgers cannot be reconstructed. The worker audit guard records Python-level
attempts only and is not an OS sandbox. The repository-pinned negative projection in
`evidence/mlx-runtime-preflight-negative-v1.json` binds the raw record digests/identities, sets
`observed_preflight_accepted=false` and `retry_count=0`, and closes no observed import,
module-closure, backend/device, synchronization, exact-attempt-category, or
completed-forbidden-action requirement. Exact unchanged raw terminal and consumption bytes are
durably retained in private owner-only session storage; their private path is intentionally not
published.

Revised terminal custody stores a bounded rejected-frame digest and a privacy-safe projection of
numeric `completed_runtime_actions`, `model_non_actions`, Python-audited
`guarded_action_attempts`, and separately unaccepted worker-reported
`completed_forbidden_actions`, plus validation category/digest, exact completed frame counts,
authorization/consumption bindings, and parent-owned wait status. It never publishes rejected
backend, synchronization, or completion bytes as accepted evidence. Both terminal records and the
committed negative projection have pure replay commands.

## Static qualification for a future schema 1.1

The process-free qualification package binds exact MLX/MLX-LM versions and immutable source
revision/tag provenance; exact wheel filenames, SHA-256 digests, sizes, URLs and tags; target
CPython ABI and macOS version/arm64 architecture; exact wheel bytes bound to embedded WHEEL tags
and METADATA; exact raw METADATA bytes/digests and normalized names/versions; every supplied
`Requires-Dist` entry and marker; one exact `Requires-Python` constraint evaluated against the
target interpreter; a forbid-all-extras policy; exact `==` pins for top-level `mlx` and `mlx-lm`;
the supplied top-level/transitive distribution graph; and immutable source-byte evidence for
`import_mlx`, `import_mlx_lm`, `distribution_versions`, `default_device`,
`metal_is_available`, `default_stream`, and `synchronize`.

The derived record includes marker applicability, `Requires-Python` compatibility, selected
dependency versions, exact satisfaction or failure explanations, wheel compatibility, graph
reachability, API-evidence presence, and sorted blockers. It claims closure only over supplied
distribution metadata. Complete Python
standard-library, native-runtime, dynamic-loader, shared-library, backend, device, Metal,
synchronization, and model semantics remain outside the gate.

The deterministic fixture contains two candidates. The frozen historical MLX `0.29.3` / MLX-LM
`0.30.6` requirement projection remains `ineligible` and binds the unchanged schema-1.0 negative
IDs without publishing historical raw evidence or its private path. A fully supplied synthetic
closure reaches `eligible_for_new_observed_authorization` solely to demonstrate the positive
contract; it is not evidence that any real pair is coherent. Both fixture records fix every
package/network/process/socket/authorization/import/backend/model/cloud/spend counter to zero.
Real reviewed candidates remain ineligible until independent review commits their derived evidence
anchor into the qualification specification.

The committed real-candidate evidence package
`evidence/mlx-runtime-candidate-mlx-0.30.4-mlx-lm-0.30.6-v1.json` supplies one such immutable
anchor for CPython 3.13.0 on macOS 15.0 arm64:
`sha256:9b7732e27af36ae36ba849a0321c66ba4515f852f3c8e91cbc4abb90583ca49b`.
It embeds only the exact MLX `0.30.4` and MLX-LM `0.30.6` wheels and their raw Core Metadata.
Those 952,038 wheel bytes are small enough to preserve the existing exact-byte verification
contract without a network replay. The 38,255,657-byte `mlx-metal` wheel and the other transitive
artifacts are not committed: they are outside this pair anchor, and substituting hash-only evidence
would not prove raw METADATA equality offline. Their absence remains explicit in the deterministic
`ineligible` blockers, together with the absent worker-API evidence.

The pair edge `mlx>=0.30.4; platform_system == "Darwin"` selects and accepts `mlx==0.30.4`.
That fact does not establish complete dependency closure. No accepted or ineligible qualification
record is committed beside the newly reviewed candidate; a later record change must reconstruct
the decision from the immutable package.

## Prospective schema-1.1 model-free contract

The additive schema-1.1 protocol/spec/contract-record layer prepares deterministic prerequisite
validation without enabling execution. It has only capability, protocol/spec emission,
record construction/verification/inspection, and deterministic closed-fixture replay commands.
There is no authorize, install, worker, or execute surface.

A record requires both:

1. an eligible schema-1.0 `reviewed_candidate` qualification record whose derived evidence anchor
   was committed through a separate review; and
2. future authoritative one-shot authorization acquisition, current-expiry observation,
   exclusive consumption/non-reuse, and independently verified output-root and nonce facts.

The current committed qualification anchor set includes the separately reviewed real-candidate
evidence anchor described above, but no eligible qualification record exists for it. The synthetic
positive fixture and the frozen historical record therefore deterministically refuse and cannot be
used as substitutes.
The authorization prerequisite is also categorically unsatisfied: caller-supplied claim structures
cannot establish custody or independent bindings. No current input combination can make
`prerequisites_satisfied=true`, and execution remains disabled.

The future allowed physical action set contains only exact isolated runtime closure verification,
imports of the pinned `mlx.core` and `mlx_lm` surfaces, and bounded distribution/backend/device/
default-stream/Metal metadata. One default-stream synchronization canary requires its own explicit
one-shot authorization. Model/tokenizer discovery or loading, prompt/cache/inference/generation,
tensor operations, benchmarks, retrieval/install, retries, cloud, and spend are forbidden.
Attempted actions, completed actions, and accepted evidence are separate ledgers. Audit hooks are
defense in depth and are not an OS sandbox. The current deterministic record and fixture ledgers
are empty and report zero physical actions.
