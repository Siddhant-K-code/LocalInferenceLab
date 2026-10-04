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
