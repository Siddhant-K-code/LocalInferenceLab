# Ollama runner contract

## Scope and non-claims

The runner implements one frozen, preinstalled-resource Ollama study. It is not a general Ollama
client. A protocol file, environment variable, localhost service, `--allow-network`-style flag, or
possession of model artifacts cannot authorize execution. The repository's tests and recorded
accepted/invalid/refused bundles use a closed tuple of exact response/failure values. Public
synthetic entry points instantiate the private scripted transport internally; they cannot accept a
transport-capable object. The bundles make zero socket calls and zero model actions.

Implementation evidence is not an observed model benchmark. It establishes no determinism, speed,
memory, energy, backend quality, or model quality claim. Seed and temperature are controls, not
guarantees.

## Frozen package

`ollama_prospective_package` embeds and content-binds:

- a complete observed host, runtime, and Ollama model identity;
- the runtime executable digest and raw manifest/config/ordered layer digest closure;
- a numeric-loopback endpoint and the five exact API paths;
- process, model, cache, and serial concurrency identities;
- prompt bytes, raw/template decision, version-specific `think` choice, sampler, context/output
  bounds, `shift=false`, `truncate=false`, and `keep_alive=0`;
- exact `/api/show` projection digests and exact request-body bytes/digest;
- one exact run slot and nine ordered calls;
- output-root identity, eligibility, deadline, no-retry rule, and action/byte budgets.

Unknown keys and options fail. Request bytes are rebuilt in trusted code and compared byte-for-byte
during verification; a caller cannot inject JSON, a URL, another model, or another option after
authorization.

## Repeatability-study declaration

The runner package remains schema 1.0. A separate additive
`ollama_repeatability_study_declaration` schema 1.0 composes verified per-run packages into a
multi-repeat plan without broadening execution authority. It freezes the exact foundation commit,
contract versions, Qwen3 identity evidence, prompt/request catalog, five-run order, cache cohort,
authorization phases, action schedules, terminal policy, analysis policy, and custody/replay
requirements.

The declaration accepts no package path or mutable alias as identity. When all five canonical
packages are supplied, it embeds them and derives package, protocol, execution-declaration,
runtime, model, host, model-closure, output-root, and nonce identities. Partial coverage fails.
Mixed runtime, model, host, or output-root identities across repeats also fail. The metadata
preflight binds the first run's exact package and preflight nonce commitment while remaining
separately unauthorized. When the local manifest/config/layer bytes and runtime artifacts are
unavailable, construction records nulls and explicit missing package bindings; it does not query
Ollama or manufacture closure digests.

Declaration completeness, metadata-preflight authorization, and generation eligibility are
separate outputs. Metadata preflight always requires its own one-shot authorization. Observed
generation and observed replay remain ineligible regardless of declaration completeness until a
future reviewed schema content-binds both listener ownership and active internal runner/Metal
attestation.

The request model name must end in `:local`. Pinned Ollama source permits an unspecified model
reference backed by `RemoteHost`/`RemoteModel` metadata to proxy externally; `:local` turns such a
case into a refusal. The local config blob is also inspected and any non-empty `remote_host` or
`remote_model` field is rejected. The canonical local name is derived, not supplied independently:
the runner removes the final `:local` and adds `:latest` only when the remaining name has no tag.
`/api/tags`, `/api/ps`, and the generation response must bind that one derivation. Any loaded
`/api/ps` alias with the same manifest digest counts as the same loaded model.

## Endpoint and transport

Only `http`, an explicit port, and literal `127.0.0.1` or `::1` are accepted. DNS names,
credentials, fragments, alternate paths, Unix forwarding, TLS ambiguity, redirects, content
encoding, duplicate content lengths, and environment proxy discovery are unavailable by
construction. `HTTPConnection` connects directly to the numeric address. The connected peer is
checked against the exact declared loopback address before request bytes are sent.

Every call has one monotonic absolute deadline spanning connect, peer verification, request send,
response headers, and every body read; it is not a fresh timeout per socket operation. Each call
also has an accepted response limit and a one-byte overflow sentinel allowance committed in the
pre-action read budget. The full allowance is reserved before the call.
Bounded partial bytes, status, content type, and completeness are recorded on transport failure;
`IncompleteRead` and deadline failures retain every already returned bounded body byte, and a short
`Content-Length` body cannot appear complete. Content type must be exactly
`application/json` with at most a UTF-8 charset parameter. Status, malformed UTF-8/JSON, duplicate
keys, floats, unknown generate fields, missing terminal fields, and oversized bodies fail closed.
There are no retries.

## Identity and action schedule

The only execution schedule is:

| Sequence | Phase | Method and path | Purpose |
|---:|---|---|---|
| 1 | pre | `GET /api/version` | exact runtime version |
| 2 | pre | `GET /api/tags` | exact resolved-name manifest digest |
| 3 | pre | `POST /api/show` | exact model/template/details projection |
| 4 | pre | `GET /api/ps` | declared load state |
| 5 | generation | `POST /api/generate` | one exact request body |
| 6-9 | post | same four identity calls | immediate drift and lifecycle check |

Runtime executable bytes and the complete local model closure are checked before the first socket
and after generation. API projections before and after must be identical, including version,
manifest, show projection, selected runner/Metal facts, and declared load state.

Ollama's public API does not identify the selected inference engine, prove Metal execution, or
authenticate the process owning a loopback listener. The package binds separately reviewed
out-of-band runtime facts, but those facts do not attest the active TCP listener. Missing or
unreviewed runner/Metal evidence blocks package construction, and production generation currently
refuses before authorization consumption or socket access until a portable listener-process and
active-runner attestor is implemented. The synthetic path remains executable because it cannot
open a socket or perform model work.

## Authorization and pre-action accounting

An initialized production output root contains a canonical nonce-digest marker plus local
owner/device/inode binding. The declaration stores only the opaque digest of that complete marker.
Copying the marker to another directory or initializing another directory with the same nonce
produces no reusable identity. Three authorization phases exist:

- `preflight_only`: exactly four read-only identity calls and no generation;
- `identity_guard`: exactly eight pre/post identity calls for execution;
- `generation`: exactly one inference request.

The declaration first commits three distinct SHA-256 nonce digests, one per phase. The actual
owner-only nonce file is supplied later; `authorize` refuses any nonce whose digest is not already
committed. The authorization artifact carries the nonce preimage, so possession of the public
commitment alone cannot mint an artifact. Each artifact binds that proof, package, declaration,
output-root instance, phase, request count, request bytes, and response allowance. Execution
validates both artifacts and all static inputs before creating any consumption marker or socket.
One verified output-root directory descriptor is retained through artifact checks, authorization
consumption, stage creation, no-replace rename, receipt-last publication, and fsync; the path is
not reopened at any trust transition. Generation authorization is not consumed until all
pre-identity checks pass.

Network, identity, inference, request-byte, and complete bounded-read allowances are reserved
before each call. Actually received bounded bytes are then recorded separately. Model process
starts, downloads, mutations, and retries are fixed at zero. A transport timeout consumes the
request because the remote action may have occurred; post-identity checks still run after a
dispatched synthetic generation attempt.

## Cache lifecycle

The public API always enables internal prompt caching in the pinned source and exposes no control
that proves an empty or reusable prompt/KV state. Consequently:

| Requested state | Runner treatment |
|---|---|
| Cold process and model | Unsupported: this runner never starts or restarts Ollama |
| Warm model, cold prompt cache | Unsupported: the public API cannot prove an empty prompt/KV cache |
| Warm prompt/KV cache | Unsupported: exact reusable KV identity is not exposed |
| Cold model, warm process | Supported only when exact `/api/ps` projections show the model absent before and after, `keep_alive=0`, no warm-up requests, and no context shift/truncation |

The additional `cold_model_warm_process` label prevents a false cold-process claim. `keep_alive`,
context-shift policy, prompt-cache policy/evidence, warm-up set, selected runner, Metal state,
model/process instance, and post-request load evidence are content-bound. No runs are silently
pooled.

## Response and terminal custody

A valid response requires HTTP 200, JSON content type, exact response model identity, `done=true`,
non-empty `done_reason`, response text, and all six native count/duration fields. The exact response
envelope bytes and digest are retained. Text is the exact decoded JSON string and is separately
digested. Durations remain nanoseconds; counts remain tokens. `eval_count` must not exceed the
authorized `max_output_tokens`/exact request `num_predict`; the equal boundary is accepted. No
prompt/context token equivalence is invented.

The deprecated `context` field is not treated as generated token IDs. `token_ids` is always
unavailable.

If generation was dispatched but transport, parsing, required-field validation, cache lifecycle,
artifact recheck, or post-identity validation fails, the scheduled run closes as an invalid
digest-safe record. It retains the exact request and error digest but no partially trusted output,
text, tokens, finish reason, or envelope fields. Every dispatched action retains one exact bounded
body artifact under `responses/NNNN-operation.bin`, including empty and partial failures. The action
binds its path, digest, size, status, content type, and completeness. Pre-generation identity
failure publishes a refused terminal record with no run. All terminal outcomes include ordered
action accounting and are published through atomic no-replace, receipt-last custody.

## Synthetic boundary

The synthetic API accepts only an exact built-in tuple containing exact immutable
`TransportResponse`/`SyntheticTransportFailure` values; tuple/value subclasses, custom dispatch
objects, and production transports are rejected before output-root access or authorization
consumption. It creates the private finite scripted transport only after that validation. Synthetic
action timing is fixed to zero and physical network/model counters are zero. Synthetic execution
also requires the explicit `synthetic_fixture` output-root marker whose physical identity fields are
fixed to zero; observed preflight/execution rejects that marker mode. The fixture publishes:

- `accepted`: valid synthetic response custody;
- `invalid`: malformed response closed as a digest-safe invalid run;
- `refused`: runtime identity drift before generation.

Replay verifies closed-set publication, embedded one-shot authorizations and nonce commitments,
the exact accepted/invalid/refused state machine, schedule prefix, reserved/received byte totals,
the exact indexed response artifact set, strict identity snapshots reconstructed from all eight raw
pre/post identity envelopes, every run identity, regenerated valid response projections,
producer-reachable invalid analysis, non-claims, and synthetic side-effect/timing zeros. The same
command strictly replays four-call preflight bundles and proves they contain no generation action.
