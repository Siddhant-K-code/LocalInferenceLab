# Current backend source research

Retrieved 2026-10-04. Normative sources are official documentation and pinned upstream source.
Issue and pull request links are non-normative evidence of behavior or known limitations. They do
not define a guarantee.

## Pinned upstream revisions

| Project | Revision |
|---|---|
| MLX-LM | [`5cfec4cb39deba54210b3ff4d86f2337c7bc10b5`](https://github.com/ml-explore/mlx-lm/tree/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5) |
| MLX | [`0e3ff3643b1c3719f78814b98e0d222afbad867c`](https://github.com/ml-explore/mlx/tree/0e3ff3643b1c3719f78814b98e0d222afbad867c) |
| llama.cpp | [`0504396140d1c882f5f6ee34466a42db7ae90114`](https://github.com/ggml-org/llama.cpp/tree/0504396140d1c882f5f6ee34466a42db7ae90114) |
| GGML | [`353b63b439f27ab2cc19dac97ab1681ba6d2d084`](https://github.com/ggml-org/ggml/tree/353b63b439f27ab2cc19dac97ab1681ba6d2d084) |
| Ollama | [`42e911bc3d05798cad729cb474bf62f378cb2e26`](https://github.com/ollama/ollama/tree/42e911bc3d05798cad729cb474bf62f378cb2e26) |

On 2026-10-04, the pinned Ollama revision was verified as current `main` (commit date
2026-10-02). The latest tagged release was `v0.35.1`, two docs-only commits behind that revision.
The contract cites immutable source URLs; hosted docs are supplementary when their content can move.

## MLX-LM normative sources

- [`generate_step`](https://github.com/ml-explore/mlx-lm/blob/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5/mlx_lm/generate.py#L304-L330)
  accepts a sampler, prompt cache, KV size and quantization controls, and prefill size. Its response
  surfaces token, text, token counts, rates, peak memory, and finish reason through
  [`GenerationResponse`](https://github.com/ml-explore/mlx-lm/blob/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5/mlx_lm/generate.py#L266-L292).
- [`make_sampler`](https://github.com/ml-explore/mlx-lm/blob/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5/mlx_lm/sample_utils.py#L16-L31)
  defines temperature, top-p, min-p, top-k, and XTC controls. Temperature zero selects greedy
  sampling. The sampler does not accept a seed.
- The CLI
  [applies `mx.random.seed` only when a seed is supplied](https://github.com/ml-explore/mlx-lm/blob/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5/mlx_lm/generate.py#L2006-L2007).
  MLX documents an implicit global PRNG state in its
  [random API](https://ml-explore.github.io/mlx/build/html/python/random.html). This makes seed a
  recorded control, not proof that all backend operations are bit-exact.
- The MLX-LM server request fields
  [do not include a per-request seed](https://github.com/ml-explore/mlx-lm/blob/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5/mlx_lm/SERVER.md#L66-L133).
- Prompt caches can be created, saved, loaded, trimmed, rotated, quantized, and reused through
  [`models/cache.py`](https://github.com/ml-explore/mlx-lm/blob/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5/mlx_lm/models/cache.py#L15-L139).
  Cache class and cache configuration belong in provenance.
- Official benchmark instructions record both
  [`python -m mlx --version` and `python -m mlx_lm --version`](https://github.com/ml-explore/mlx-lm/blob/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5/mlx_lm/BENCHMARKS.md#L16-L19).
  Runtime identity must bind both packages.
- Model loading resolves a revision and allowed snapshot files through
  [`snapshot_download`](https://github.com/ml-explore/mlx-lm/blob/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5/mlx_lm/utils.py#L251-L291).
  The [Hugging Face cache guide](https://huggingface.co/docs/huggingface_hub/en/guides/manage-cache)
  documents revision snapshots and content-addressed blobs. An MLX model identity is therefore a
  file-manifest closure, not a GGUF-style single-file digest.

MLX-LM does not provide a normative claim that ordinary Metal generation is bit-exact across cache
state or chip families. The protocol measures that property rather than assuming it.

## llama.cpp normative sources

- [`llama-bench`](https://github.com/ggml-org/llama.cpp/blob/0504396140d1c882f5f6ee34466a42db7ae90114/tools/llama-bench/README.md#L21-L85)
  excludes tokenization and sampling time. Its token feed is benchmark machinery, not generated
  model output. `llama-bench` is useful for performance characterization, not content determinism.
- Its CSV and JSON output include
  [`build_commit` and `build_number`](https://github.com/ggml-org/llama.cpp/blob/0504396140d1c882f5f6ee34466a42db7ae90114/tools/llama-bench/README.md#L187-L208).
- `llama-server` documents seed as an RNG control and random `-1` default in its
  [CLI](https://github.com/ggml-org/llama.cpp/blob/0504396140d1c882f5f6ee34466a42db7ae90114/tools/server/README.md#L123)
  and [request schema](https://github.com/ggml-org/llama.cpp/blob/0504396140d1c882f5f6ee34466a42db7ae90114/tools/server/README.md#L573).
- The server explicitly warns that
  [`cache_prompt` can cause nondeterministic results](https://github.com/ggml-org/llama.cpp/blob/0504396140d1c882f5f6ee34466a42db7ae90114/tools/server/README.md#L587)
  because different batch sizes do not guarantee bit-identical logits.
- Server timing fields preserve prompt-cache reuse, prompt evaluation, and generation values in the
  [documented response](https://github.com/ggml-org/llama.cpp/blob/0504396140d1c882f5f6ee34466a42db7ae90114/tools/server/README.md#L1397-L1421).
- Metal is enabled by default on macOS, can be disabled at build time, and can be bypassed with
  zero GPU layers according to the
  [official build guide](https://github.com/ggml-org/llama.cpp/blob/0504396140d1c882f5f6ee34466a42db7ae90114/docs/build.md#L154-L159).
- Context shifting can discard and re-evaluate earlier tokens when the window fills. The
  [completion documentation](https://github.com/ggml-org/llama.cpp/blob/0504396140d1c882f5f6ee34466a42db7ae90114/tools/completion/README.md#L356-L375)
  defines this lifecycle.
- GGUF is a self-contained, mmap-oriented format according to the
  [GGUF specification](https://github.com/ggml-org/ggml/blob/353b63b439f27ab2cc19dac97ab1681ba6d2d084/docs/gguf.md#L1-L21).
  Its bytes and metadata are a representation identity distinct from an MLX snapshot.

### Non-normative llama.cpp evidence

- [Pull request `#16016`](https://github.com/ggml-org/llama.cpp/pull/16016) proposes deterministic
  CUDA kernels and explicitly leaves other GPU backends unchanged. It is open and CUDA-specific.
  It cannot support a Metal determinism claim.
- [Issue `#23212`](https://github.com/ggml-org/llama.cpp/issues/23212) reports different greedy
  output across Apple Silicon chip families. A maintainer scopes expected determinism to the same
  hardware with caveats. This is issue evidence, not a specification.
- [Issue `#7052`](https://github.com/ggml-org/llama.cpp/issues/7052) records multi-slot output
  instability. The normative `cache_prompt` warning above is the stronger basis for the protocol.

## Ollama normative sources

- The current [`/api/generate` documentation](https://docs.ollama.com/api/generate) reports total,
  load, prompt-evaluation, and evaluation durations plus token counts. Durations are nanoseconds.
  The project preserves these names and units.
- The pinned repository's
  [`docs/api.md`](https://github.com/ollama/ollama/blob/42e911bc3d05798cad729cb474bf62f378cb2e26/docs/api.md#L28-L134)
  includes the same duration convention, final response fields, and derived generation-rate
  formula.
- Ollama options document temperature and seed in the
  [Modelfile reference](https://github.com/ollama/ollama/blob/42e911bc3d05798cad729cb474bf62f378cb2e26/docs/modelfile.mdx#L144-L154).
  The published table says seed defaults to zero, while
  [`api.DefaultOptions`](https://github.com/ollama/ollama/blob/42e911bc3d05798cad729cb474bf62f378cb2e26/api/types.go#L1130-L1145)
  sets `Seed: -1`. The source is treated as the runtime truth and the discrepancy is recorded.
- Ollama manifests contain a config layer and content-addressed layers according to
  [`manifest.go`](https://github.com/ollama/ollama/blob/42e911bc3d05798cad729cb474bf62f378cb2e26/manifest/manifest.go#L16-L24)
  and [`layer.go`](https://github.com/ollama/ollama/blob/42e911bc3d05798cad729cb474bf62f378cb2e26/manifest/layer.go#L11-L51).
- Ollama's official
  [MLX announcement](https://ollama.com/blog/mlx) and
  [v0.40.0-rc0 release notes](https://github.com/ollama/ollama/releases/tag/v0.40.0-rc0)
  state that supported Apple Silicon models may run through MLX. "Ollama" is therefore not a
  sufficient internal runner identity.
- The pinned repository's
  [`GenerateRequest`](https://github.com/ollama/ollama/blob/42e911bc3d05798cad729cb474bf62f378cb2e26/api/types.go#L62-L127)
  and [OpenAPI schema](https://github.com/ollama/ollama/blob/42e911bc3d05798cad729cb474bf62f378cb2e26/docs/openapi.yaml#L68-L135)
  define `stream`, `raw`, `keep_alive`, `options`, pointer-valued `think`, `truncate`, and `shift`.
  The runner explicitly sets or version-pins every used field and rejects fields such as images,
  format, suffix, context, debug rendering, and logprobs.
- The full option source and
  [`DefaultOptions`](https://github.com/ollama/ollama/blob/42e911bc3d05798cad729cb474bf62f378cb2e26/api/types.go#L1127-L1157)
  are broader than the public OpenAPI table. Unknown option keys are warned about rather than
  rejected by upstream `FromMap`; therefore LocalInferenceLab applies its own closed allowlist.
- Pinned source distinguishes
  [`:local`, `:cloud`, and unspecified model sources`](https://github.com/ollama/ollama/blob/42e911bc3d05798cad729cb474bf62f378cb2e26/internal/modelref/modelref.go).
  `GenerateHandler` can proxy an unspecified name when its local config carries `RemoteHost` and
  `RemoteModel`; an explicit `:local` suffix hard-refuses that remote model. The contract requires
  `:local` and rejects those config fields.
- [`thinking.mdx`](https://github.com/ollama/ollama/blob/42e911bc3d05798cad729cb474bf62f378cb2e26/docs/capabilities/thinking.mdx)
  documents boolean or model-defined thinking values. Source comments confirm unset preserves
  pre-option behavior, but no official source found in this review identifies the introducing
  version or fully specifies that older behavior. Packages must pin `true`, `false`, or an
  explicitly version-supported omission and bind `/api/show` thinking metadata.
- Pinned scheduler/source behavior separates `shift` from `truncate`. `shift` controls internal
  context shifting and can force runner reload; `truncate` controls pre-subprocess prompt
  truncation. The runner fixes both false so an overlong prompt fails instead of changing input.
- Ollama sends `cache_prompt: true` to its internal llama-server and provides no public control to
  disable or identify exact prompt/KV contents. Sampling changes do not force a runner reload,
  while runner options such as context can. Cache cohorts that require empty or reused prompt/KV
  proof are therefore unsupported.
- `/api/ps` reports residency sizes and context length but no actual compute engine. Its CLI
  processor label is derived from a VRAM/size ratio. The API cannot prove Metal, CPU, MLX, or
  llama.cpp execution; selected runner/Metal evidence must be separately reviewed and bound.
- Model manifests and blobs are stored as plain manifest JSON plus content-addressed
  `sha256-*` files. The contract hashes the raw manifest and every ordered config/layer blob and
  rechecks the closure before and after generation.

## Ollama listener/runner attestation feasibility sources

Retrieved 2026-10-05. The assessment scope is the declared macOS 27.0.1 build 26A434/arm64 host,
non-root with no special entitlement, and same-effective-UID process inspection where Darwin
permits it. Apple's public XNU source revision
[`f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`](https://github.com/apple-oss-distributions/xnu/tree/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea)
and Security source revision
[`db15acbe6a7f257a859ad9a3bb86097bfe0679d9`](https://github.com/apple-oss-distributions/Security/tree/db15acbe6a7f257a859ad9a3bb86097bfe0679d9)
are pinned authoritative sources for the interfaces and fields they define. The assessment does
not claim that those public source revisions are byte-identical to the exact shipped OS build.

### Darwin normative source findings

- [`proc_bsdinfo`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/proc_info.h#L55-L82)
  includes effective/real owner fields and process start seconds/microseconds. These fields can
  reduce PID-reuse ambiguity but do not identify a request socket.
- [`in_sockinfo` and TCP state`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/proc_info.h#L377-L430)
  expose local/foreign address and port, a per-instance generation count, and TCP state.
  [`socket_info`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/proc_info.h#L541-L575)
  adds opaque socket/PCB handles and queue/state fields.
- The header defines separate
  [`PROC_PIDLISTFDS` and `PROC_PIDTBSDINFO` flavors](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/proc_info.h#L722-L730)
  and a separate
  [`PROC_PIDFDSOCKETINFO` lookup](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/proc_info.h#L781-L788).
  Kernel implementation performs process lookup and later FD lookup in distinct calls; it checks
  same-user policy for FD information at
  [`proc_pidfdinfo`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/proc_info.c#L2810-L2895).
- The same-user rule and privileged bypass are explicit in
  [`proc_security_policy`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/proc_info.c#L3160-L3203).
  A nonprivileged assessment cannot assume visibility into another user's process.
- TCP PCB records include local/foreign ports and socket/PCB generation counts in
  [`xinpcb_n` and `xinpgen`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/netinet/in_pcb.h#L537-L577).
  These support snapshot correlation, not a retained assertion that a particular process accepted
  and serviced one exact HTTP request.
- Apple's lsof source demonstrates the snapshot shape: it calls
  [`proc_pidfdinfo(..., PROC_PIDFDSOCKETINFO, ...)`](https://github.com/apple-oss-distributions/lsof/blob/7a8a1b2a3c0f35c30a5fcd0927f31d441c3e5255/lsof/dialects/darwin/libproc/dsock.c#L481-L506)
  for one PID and FD. lsof output is therefore evidence derived from those point-in-time lookups,
  not a new atomic ownership primitive.
- Security's dynamic-code API accepts PID and other guest selectors through
  [`SecCodeCopyGuestWithAttributes`](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/SecCode.h#L123-L190).
  [`SecCodeCheckValidity`](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/SecCode.h#L217-L227)
  validates the dynamic code and its filesystem source against a requirement, while
  [`SecCodeCopyDesignatedRequirement` and signing information](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/SecCode.h#L307-L347)
  expose signing identity. These APIs can strengthen executable identity; they do not bind code to
  the accepted socket or internal Ollama request.

### Pinned Ollama source findings

- `GenerateHandler` obtains a scheduler runner and later sends one
  [`CompletionRequest` to that exact in-process object](https://github.com/ollama/ollama/blob/42e911bc3d05798cad729cb474bf62f378cb2e26/server/routes.go#L693-L729).
- The scheduler's
  [`getRunner`](https://github.com/ollama/ollama/blob/42e911bc3d05798cad729cb474bf62f378cb2e26/server/sched.go#L174-L215)
  chooses a loaded runner or queues a load. `useLoadedRunner` increments an internal refcount and
  returns that `runnerRef` at
  [`sched.go` lines 477-496](https://github.com/ollama/ollama/blob/42e911bc3d05798cad729cb474bf62f378cb2e26/server/sched.go#L477-L496).
  New runner creation retains model, child PID, devices, options, and load state at
  [`sched.go` lines 701-756](https://github.com/ollama/ollama/blob/42e911bc3d05798cad729cb474bf62f378cb2e26/server/sched.go#L701-L756).
  The richer `runnerRef` state remains internal.
- The llama-server path retains the child PID at
  [`llama_server.go` lines 203-228](https://github.com/ollama/ollama/blob/42e911bc3d05798cad729cb474bf62f378cb2e26/llm/llama_server.go#L203-L228)
  and starts the subprocess at
  [`lines 426-442`](https://github.com/ollama/ollama/blob/42e911bc3d05798cad729cb474bf62f378cb2e26/llm/llama_server.go#L426-L442).
  PID, argv, environment, and logs are not proof that the child served one exact request.
- Completion builds a separate internal HTTP request and sends it to a runner loopback port at
  [`llama_server.go` lines 1623-1742](https://github.com/ollama/ollama/blob/42e911bc3d05798cad729cb474bf62f378cb2e26/llm/llama_server.go#L1623-L1742).
  The internal client
  [disables keep-alive](https://github.com/ollama/ollama/blob/42e911bc3d05798cad729cb474bf62f378cb2e26/llm/llama_server.go#L194-L208),
  so the completion uses a separate connection rather than a reusable content identity. No public
  correlation token binds the external accepted socket, canonical request, scheduler `runnerRef`,
  newly connected internal socket, and response.
- `/api/ps` copies a scheduler snapshot into the public response at
  [`routes.go` lines 2440-2462](https://github.com/ollama/ollama/blob/42e911bc3d05798cad729cb474bf62f378cb2e26/server/routes.go#L2440-L2462).
  Its exact public type contains model/name, size, digest, details, expiry, `size_vram`, and context
  length at
  [`api/types.go` lines 856-865](https://github.com/ollama/ollama/blob/42e911bc3d05798cad729cb474bf62f378cb2e26/api/types.go#L856-L865).
  It omits runner PID/process birth, backend/Metal state, load-instance identity, connection, and
  request dispatch.

### Candidate mechanism disposition

| Candidate | Canonical status | Exact reason |
|---|---|---|
| Darwin owner and process-birth fields | `insufficient_snapshot` | Reduces PID reuse ambiguity but is separate from socket/request ownership. |
| Darwin per-process FD/socket lookup | `insufficient_snapshot` | Endpoint, state, generation, and opaque handles are separate point-in-time calls with no retained request assertion. |
| Darwin TCP PCB snapshot | `insufficient_snapshot` | Supports endpoint correlation heuristics, not atomic accept/owner/request continuity. |
| Darwin dynamic code/signing identity | `insufficient_semantics` | Strengthens selected-process code identity but does not bind code to the accepted socket or internal dispatch. |
| Ollama `/api/ps` | `unsupported_public_api` | Omits runner process identity, backend/Metal state, model-load instance, connection, and request correlation. |
| Ollama internal scheduler state | `insufficient_semantics` | `runnerRef` and refcount are internal source behavior, not emitted signed runtime evidence. |
| Ollama internal completion transport | `insufficient_semantics` | No unforgeable token spans external socket, scheduler runner, internal socket, and response. |
| Ollama child-runner PID/launch data | `insufficient_semantics` | PID/argv/env/logs do not bind executable bytes, active backend, or exact request service. |
| Future privileged accepted-socket assertion | `required_future_primitive` | Must retain stable kernel socket and process/audit identity through response; not implemented. |
| Future Ollama cooperative assertion | `required_future_primitive` | Must bind request digest, runner/load/model closure, and actual Metal execution, then chain to socket evidence; not implemented. |

The canonical verdict is `insufficient`. This is not a claim that Apple or Ollama can never expose
the needed evidence. It is the narrower finding that the reviewed pinned public interfaces and
source do not provide a nonprivileged, request-scoped, content-bound chain today. A future positive
path requires both the privileged retained socket/process assertion and in-process Ollama
cooperation; either one alone leaves a trust gap.

### Non-normative Ollama evidence

- [Issue `#16860`](https://github.com/ollama/ollama/issues/16860) reports MLX prompt-cache restore
  changing fixed-seed, temperature-zero output. The linked fix disables unsafe restore. This
  supports measuring cache state rather than treating seed as proof.
- [Issues `#5321`](https://github.com/ollama/ollama/issues/5321) and
  [`#12559`](https://github.com/ollama/ollama/issues/12559) record reproducibility problems with
  fixed controls and structured output. They are observation history, not normative behavior.

## Design consequences

1. Primary analysis is within one backend, runtime identity, model representation, host identity,
   protocol, process/model instance, cache preparation, effective concurrency state, exact request,
   and cache cohort.
2. Exact hardware, runtime build, model bytes or manifest, prompt/template bytes, sampler controls,
   context, concurrency, and order are bound before execution.
3. Cache state and context shifting are explicit experimental variables.
4. Native counters retain backend names and units. Missing metrics remain unavailable.
5. Seed is a control. It is never the conclusion.
6. Cross-backend analysis is descriptive. V1 fixes representation equivalence to `unproven` until
   a future typed, indexed mapping-artifact record is defined.
7. CUDA deterministic-mode work is not generalized to Metal.
8. An unspecified Ollama model name is not a local-execution guarantee; explicit `:local` and local
   config inspection are required.
9. Ollama prompt-cache state and actual compute engine are not mechanically observable through the
   public API, so unsupported cohorts and absent runner evidence must refuse execution.
