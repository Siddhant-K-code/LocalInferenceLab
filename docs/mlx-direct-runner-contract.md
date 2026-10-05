# Direct MLX worker contract

## Status and non-action boundary

This schema-1.0 contract is prospective. It defines an exact supplied package-root byte closure,
an exact model closure, a private finite worker protocol design, determinism controls, result
semantics, and future authorization/custody requirements.
It does **not** implement a production worker launch. No command in the `mlx` namespace imports
MLX or MLX-LM, initializes Metal, queries a device, loads a tokenizer or model, performs inference,
resolves/downloads a snapshot, starts a process, opens a socket, mutates a cache, consumes
authorization, or claims observed hardware evidence.

The built-in package is deliberately incomplete. No exact preexisting local MLX model was supplied
or discovered, and discovery would violate the explicit-path boundary. Wired/cache limits, active
runtime/backend evidence, applicable dependency closure, Python standard-library/native-loader
closure, production private-IPC/protocol/result-validation implementation, worker process birth,
output-root identity, and authorization are also absent. `observed_execution_reachable`,
`worker_process_may_start`, and `authorization_may_be_consumed` are therefore fixed `false`.

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

## Exact model closure

`mlx_model_manifest` 1.0 accepts one explicit, materialized, flat local directory. It requires:

- `config.json`, `tokenizer_config.json`, a tokenizer vocabulary artifact, and one or more
  `model*.safetensors` files;
- `model.safetensors.index.json` when more than one shard exists, with the exact present shard set;
- the exact weight-index path, digest, and normalized referenced-shard projection;
- the complete no-follow regular-file closure and physical root identity;
- exact config, tokenizer-config, tokenizer, weight, and chat-template digests.

Only the pinned loader's data extensions are admitted. Python/shared-library/custom-code files,
executables, symlinks, special files, nested path escapes, remote-code markers (`model_file`,
`auto_map`, or enabled `trust_remote_code`), missing/extra shards, and runtime snapshot resolution
are rejected. If neither `chat_template.jinja` nor a non-empty `tokenizer_config.json` template is
present, the manifest remains valid static custody but eligibility reports `exact_chat_template`
missing.

The repository does not search local caches or infer a snapshot from a model name. The built-in
study therefore has no real model identity.

## Private worker custody and protocol

The future parent, not the worker, owns lifecycle and authorization. The frozen design uses one
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

This PR records that finite state machine but intentionally provides no launch or transport object.
It also provides no production frame parser, state-machine enforcement, worker identity/result
validation, timeout/termination handling, or descriptor-passing implementation. That complete
private-IPC/protocol/result-validation implementation is an explicit eligibility blocker rather
than an inference from `worker_process_may_start=false`.
The public synthetic surface accepts only an output root and internally sealed immutable values;
it cannot receive custom dispatch, scripts, probes, transports, subclasses, or production objects.

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
