# Current backend source research

Retrieved 2026-10-04 and updated 2026-10-08. Normative sources are official documentation and
pinned upstream source.
Issue and pull request links are non-normative evidence of behavior or known limitations. They do
not define a guarantee.

## Pinned upstream revisions

| Project | Revision |
|---|---|
| MLX-LM candidate | [`v0.30.6` / `f18526f8d66f74728072e96d55acb6c451e92e88`](https://github.com/ml-explore/mlx-lm/tree/f18526f8d66f74728072e96d55acb6c451e92e88) |
| MLX candidate | [`v0.30.4` / `2f324cc3b200700b422db4811ae3ff8bd5bf48b4`](https://github.com/ml-explore/mlx/tree/2f324cc3b200700b422db4811ae3ff8bd5bf48b4) |
| CPython metadata mechanism | [`v3.13.0` / `60403a5409ff2c3f3b07dd2ca91a7a3e096839c7`](https://github.com/python/cpython/tree/60403a5409ff2c3f3b07dd2ca91a7a3e096839c7) |
| MLX-LM | [`5cfec4cb39deba54210b3ff4d86f2337c7bc10b5`](https://github.com/ml-explore/mlx-lm/tree/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5) |
| MLX | [`0e3ff3643b1c3719f78814b98e0d222afbad867c`](https://github.com/ml-explore/mlx/tree/0e3ff3643b1c3719f78814b98e0d222afbad867c) |
| llama.cpp | [`0504396140d1c882f5f6ee34466a42db7ae90114`](https://github.com/ggml-org/llama.cpp/tree/0504396140d1c882f5f6ee34466a42db7ae90114) |
| GGML | [`353b63b439f27ab2cc19dac97ab1681ba6d2d084`](https://github.com/ggml-org/ggml/tree/353b63b439f27ab2cc19dac97ab1681ba6d2d084) |
| Ollama | [`42e911bc3d05798cad729cb474bf62f378cb2e26`](https://github.com/ollama/ollama/tree/42e911bc3d05798cad729cb474bf62f378cb2e26) |

On 2026-10-04, the pinned Ollama revision was verified as current `main` (commit date
2026-10-02). The latest tagged release was `v0.35.1`, two docs-only commits behind that revision.
The contract cites immutable source URLs; hosted docs are supplementary when their content can move.

## Real MLX candidate evidence anchor

Retrieved 2026-10-07 using unauthenticated official PyPI JSON/files and immutable upstream GitHub
tags. The canonical evidence is committed at
`evidence/mlx-runtime-candidate-mlx-0.30.4-mlx-lm-0.30.6-v1.json`; offline verification requires no
network.

| Distribution | Source tag and revision | Wheel identity | Raw METADATA |
|---|---|---|---|
| MLX `0.30.4` | [`v0.30.4` / `2f324cc3b200700b422db4811ae3ff8bd5bf48b4`](https://github.com/ml-explore/mlx/tree/2f324cc3b200700b422db4811ae3ff8bd5bf48b4) | `mlx-0.30.4-cp313-cp313-macosx_15_0_arm64.whl`, 572,587 bytes, `sha256:1f367534078b10dcb660393a554f97732c194977ac8318bb389a76a6307757f8`, tag `cp313-cp313-macosx_15_0_arm64` | 5,860 bytes, `sha256:c3b3faaf1dd2bd14b33a62e3eb6297a51f8108f12f8d66d05e6c74f3d5fd6d46`, `Requires-Python: >=3.10` |
| MLX-LM `0.30.6` | [`v0.30.6` / `f18526f8d66f74728072e96d55acb6c451e92e88`](https://github.com/ml-explore/mlx-lm/tree/f18526f8d66f74728072e96d55acb6c451e92e88) | `mlx_lm-0.30.6-py3-none-any.whl`, 379,451 bytes, `sha256:a7405bd581eacc4bf8209d7a6b7f23629585a0d7c6740c2a97e51fee35b3b0e1`, tag `py3-none-any` | 9,483 bytes, `sha256:e5903a45bc0575fd6b8d68c67ba6cab13204995d103c1f1f32b52789f84bfb8f`, `Requires-Python: >=3.8` |

The validator confirms that each supplied raw METADATA byte stream equals the sole wheel-embedded
METADATA entry and that the filename tag occurs in the embedded WHEEL control record. MLX-LM's
Darwin requirement `mlx>=0.30.4` selects and accepts the pinned MLX `0.30.4`, correcting the
historical `0.29.3` / `0.30.6` incompatibility.

The package now binds exact prospective runtime target
`sha256:008f7c3ac60614bc6909822180a4bc0b9be17eaf0aa3abc23829eb2842c4fdc0`:
CPython 3.13.15 (`cpython-313`, `cp313`, `cpython-313-darwin`) on macOS 27.0.1 build 26A434
arm64, with interpreter deployment target 11.0 and runtime-wheel deployment target 15.0. The
already available interpreter's exact bytes and code-signature digests were collected using
bounded local OS commands and Python standard-library facts only. Its absolute private path is not
committed.

The previous 3.13.0 candidate value is superseded. The historical failed receipt's 3.13.15 value
is not accepted as target/runtime evidence and none of its IDs are rewritten. The target anchor's
development-host observation
`sha256:76ec73bb91e2436375de474be23458e61b4b6fba27de9b365112a0a31a42ff54`
is likewise not runtime evidence; it only establishes the prospective target was locally
available. `Requires-Python` is evaluated against exact full version 3.13.15, independently of
`cp313` wheel-tag compatibility.

The package ID is
`sha256:4f87b4678c31c0cd08534c58485e2b242c74936737b8f9c6c96319454ada358d`;
its target-derived pending review anchor is
`sha256:1382dfd5e9f5d19bfa74c8f3a7ad4db5b30d10caddfed3cd62c130242003f45f`.
The allowlist retains previously merged anchor
`sha256:e4bd7b6f5ce7656d1a490a6e4b39e23e1b9a6acaee55084744a8a267f0007f2c`.
The reconstructed, deliberately uncommitted qualification record is
`sha256:968f4bf20c15f97503ad5f7d3a95025bc40f0f787bf63b4c59d16e0d7d25ded3`
and remains `ineligible`. Exact blockers are the absent applicable distributions `mlx-metal`,
`numpy`, `transformers`, `sentencepiece`, `protobuf`, `pyyaml`, and `jinja2`, plus
`reviewed_candidate_not_committed_in_spec:sha256:1382dfd5e9f5d19bfa74c8f3a7ad4db5b30d10caddfed3cd62c130242003f45f`.

Caller-supplied observation claims are not independent evidence. Canonical identity and exact
target-field equality may be replayed offline, but claimed provenance remains self-asserted.
Authoritative observer identity and custody-bound executable/platform measurement are
unimplemented blockers, so no supplied envelope can satisfy qualification or preflight.

Only the two top-level wheels are embedded in the original candidate (952,038 bytes total). The
additive closure manifest at
`evidence/mlx-wheel-closure-mlx-0.30.4-mlx-lm-0.30.6-macos-arm64-py313-v1.json`
now binds 34 exact official wheels (70,700,189 bytes total) without adding any wheel files or
embedding the 32 transitive wheel binaries. The original candidate's two embedded roots remain
unchanged. The manifest ID is
`sha256:837deaf4265bf921e36712ee4ea7210eb7869b1487cc196e701689dd0fdd38be`;
its pack-spec ID is
`sha256:14b823fcf06c3107d76bbc41742353d6d2e57aa5683ab298533c9b7f84a714b7`.
Raw wheel-embedded METADATA and WHEEL control bytes are committed in the manifest, including the
38,255,657-byte macOS 15 MLX-Metal wheel's metadata, but no `.whl` files are committed.
A manifest is not proof of local byte presence: only verification of the exact separately supplied
pack can produce that proof.

The two root pins remain exact. The other versions and official wheel URLs are an externally
acquired exact selection; the manifest contains no bounded PyPI release inventory and does not
prove that any version is globally highest, non-yanked, or optimally ranked. Offline verification
proves target compatibility and internal closure coherence for the selected artifacts only. The
selection includes `transformers==5.19.0`; its
`tokenizers<0.24.0,>=0.23.1` edge constrains `huggingface-hub` to `1.33.0` instead of incompatible
2.x. Recursive discovery closes at 34 distributions:

`annotated-doc==0.0.5`, `anyio==4.15.1`, `certifi==2026.7.22`, `click==8.5.0`,
`filelock==4.0.12`, `fsspec==2026.9.0`, `h11==0.16.0`, `hf-xet==1.7.0`,
`httpcore==1.0.9`, `httpx==0.28.1`, `huggingface-hub==1.33.0`, `idna==3.20`,
`jinja2==3.1.6`, `markdown-it-py==4.2.0`, `markupsafe==3.0.4`, `mdurl==0.1.2`,
`mlx==0.30.4`, `mlx-lm==0.30.6`, `mlx-metal==0.30.4`, `numpy==2.5.3`,
`packaging==26.3`, `protobuf==7.36.2`, `pygments==2.21.0`, `pyyaml==6.0.3`,
`regex==2026.9.29`, `rich==15.0.0`, `safetensors==0.8.0`,
`sentencepiece==0.2.2`, `shellingham==1.5.4`, `tokenizers==0.23.2`,
`tqdm==4.70.1`, `transformers==5.19.0`, `typer==0.27.3`, and
`typing-extensions==4.16.0`.

Private inert verification produced receipt
`sha256:5401e65eb204b49318c044fd38ecaa48ac253b81bfbfc0f265dec9605431672e`.
The deliberately uncommitted reconstructed supplied-pack qualification record is
`sha256:fd56e61f90b63c24fa82ee70ddd55daf9ae3a2fb49817aa976096ba86b72cfba`
under the pre-independent-anchor mechanism. The fail-closed reviewed-manifest allowlist introduced
by this change is empty, so the final reconstruction instead retains
`wheel_evidence_manifest_anchor_not_independently_reviewed`. A later separate PR may review and
allowlist the unchanged manifest ID. No real record is committed, and these identities do not
authorize installation, import, execution, MLX/Metal access, or model action.

## Candidate worker API source evidence

Retrieved 2026-10-08 using only unauthenticated immutable GitHub tag/commit archives. No package
from the candidate closure was installed, no candidate module was imported, and no source was
executed or compiled. The worker-evidence spec is
`sha256:6c83f627032a2c3db38eee34f804469a42e227a3af0a84ed5c0052a192d29e97`;
the independently reviewed seven-record anchor is
`sha256:10ab50cbfb94890bae1dd8c57180645d5781e454b1a8171b158c4d932121d9dd`.

| Project/file | Full-file SHA-256 | Bound surfaces |
|---|---|---|
| MLX `setup.py` | `ef7f790742fbf7ec8f7760721c7684048d595f29503936021c7da3740f24c1ba` | `import_mlx` extension name `mlx.core` |
| MLX `python/src/mlx.cpp` | `e339e58d45f679b662bb06a96b42b015c59f1590a2af9b8fb12caac85f15097b` | `NB_MODULE(core, m)` and static initializer wiring |
| MLX `python/src/device.cpp` | `aea762cc90ced0d4d3274c2f3cdd48435de8219ff2b4d5e5b782982b05c362b9` | `default_device` binding |
| MLX `mlx/device.h` | `d00a0b67d10728666acf3b82838530471b29151a50212aec0cf960ea3d8fd814` | `const Device& default_device()` |
| MLX `python/src/stream.cpp` | `4d80cae66d2aa75c076ed9555e1439a41dbc2e4578d8faadefa957d567a97e63` | `default_stream(device)` and optional-stream `synchronize` bindings |
| MLX `mlx/stream.h` | `a9281c4a7301a3d1af7a817a19e95f5c1c22ce7f7f5a9e25e5113d314ed0b824` | `Stream default_stream(Device)`, `void synchronize()` overloads |
| MLX `python/src/metal.cpp` | `4e077805ef4db09e62479e3ff1d90b92c89caaca5d1af6245215169a4df4dce9` | `metal.is_available` binding |
| MLX `mlx/backend/metal/metal.h` | `d945d18236b8af528bc74161f72c067cc115d49026bd4ea71b84857c95c18870` | `bool is_available()` |
| MLX-LM `setup.py` | `68025286dfcf40efc18aa0ca42427d1d697ba631ca3fbe7e54e0f4bbe74a36e3` | literal `mlx_lm` package declaration |
| MLX-LM `mlx_lm/__init__.py` | `f9ffa88772d26e537a98aa39ab16488a7a0d13cc1fac5d665376132c94b49608` | intended package initializer |
| CPython `Lib/importlib/metadata/__init__.py` | `5476c7c22a65f9e8b5a07b799336d87fa70e792758fd95b161b53b530e3b2654` | `version(distribution_name: str) -> str` and `METADATA["Version"]` |

The committed evidence retains only minimal bounded excerpts, not whole upstream files or
repositories. Static AST/text replay rejects missing or renamed symbols, duplicate definitions,
dynamic module/package generation, wrong source/revision/path/tag/hash, signature drift,
boolean/integer confusion, overclaims, self-attestation, and coordinated excerpt rehashing.

All seven source/API-evidence blockers are removed. This establishes source-surface availability
only. It does not establish package installation, `mlx.core` or `mlx_lm` import success, native
loader success, runtime executability, backend/device availability, a positive Metal result,
synchronization completion, tensor/model behavior, or any authorization.

## MLX/MLX-LM normative sources

Retrieved and re-verified at the pinned commits on 2026-10-05. Links below are immutable source or
official documentation in those repositories. No issue/discussion evidence is used for the direct
runner contract.

### Local model, tokenizer, and remote-code boundary

- [`DEFAULT_ALLOW_PATTERNS`](https://github.com/ml-explore/mlx-lm/blob/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5/mlx_lm/utils.py#L251-L262)
  includes JSON, `model*.safetensors`, tokenizer formats, text/Jinja files, and Python. `_download`
  at
  [`utils.py` lines 264-292](https://github.com/ml-explore/mlx-lm/blob/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5/mlx_lm/utils.py#L264-L292)
  returns an existing local path as-is; any non-existing path/name enters
  `snapshot_download` without `local_files_only`. The direct contract therefore accepts only an
  explicitly supplied, already-existing local directory and never resolves a name or revision.
- [`load_config`](https://github.com/ml-explore/mlx-lm/blob/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5/mlx_lm/utils.py#L362-L378)
  requires `config.json` and merges only `eos_token_id` from optional `generation_config.json`.
  [`load_model`](https://github.com/ml-explore/mlx-lm/blob/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5/mlx_lm/utils.py#L408-L471)
  collects `model*.safetensors` and passes them to `model.load_weights` with its `strict` argument,
  whose normal default is `True`. A configured `model_file` requires `trust_remote_code=true` and
  is then imported/executed from the snapshot. Model Python is forbidden by the manifest contract.
  The static manifest can close obvious canonical shard-name/index gaps and rejects Safetensors
  outside this pinned `model*.safetensors` loader scope, but it cannot prove parameter key/shape
  completeness without this future strict load. The prospective study freezes the normal
  non-custom-code, non-distributed (`sharding=None`) `load` / `load_model` path with explicit
  `strict=True`; this PR does not call it.
- [`load`](https://github.com/ml-explore/mlx-lm/blob/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5/mlx_lm/utils.py#L610-L668)
  passes its `trust_remote_code` argument to model loading, but tokenizer loading separately
  delegates to
  [`AutoTokenizer.from_pretrained`](https://github.com/ml-explore/mlx-lm/blob/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5/mlx_lm/tokenizer_utils.py#L660-L697)
  with the caller's tokenizer-config dictionary. The CLI wires both gates from one option at
  [`generate.py` lines 2026-2049](https://github.com/ml-explore/mlx-lm/blob/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5/mlx_lm/generate.py#L2026-L2049),
  but a direct library caller cannot assume that convenience. The contract independently forbids
  model and tokenizer custom code.
- The import-time branch at
  [`utils.py` lines 29-35](https://github.com/ml-explore/mlx-lm/blob/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5/mlx_lm/utils.py#L29-L35)
  selects ModelScope when `MLXLM_USE_MODELSCOPE` lowercases to `true`. The closed worker
  environment fixes it to `False`; explicit local-path custody remains the primary control.

### Generation, token IDs, sampler, and cache lifecycle

- [`generate_step`](https://github.com/ml-explore/mlx-lm/blob/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5/mlx_lm/generate.py#L304-L475)
  binds max tokens, sampler, prompt cache, KV size/quantization and prefill step. Prefill processes
  bounded chunks, evaluates cache state, and clears the allocator cache. Decode pipelines one
  step ahead with `async_eval`; the first token is explicitly evaluated and every yielded token ID
  is converted through blocking scalar `.item()`. Output token IDs are therefore directly
  preservable Python integers.
- The generation stream is created at module import from the then-default device at
  [`generate.py` line 225](https://github.com/ml-explore/mlx-lm/blob/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5/mlx_lm/generate.py#L225).
  Changing the default device after import does not retarget that captured thread-local stream.
  Exact environment/device setup must precede import in a future worker.
- [`stream_generate`](https://github.com/ml-explore/mlx-lm/blob/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5/mlx_lm/generate.py#L658-L756)
  tokenizes strings, breaks on `tokenizer.eos_token_ids` before detokenizing/yielding the EOS token,
  and wraps the call in `wired_limit`. Prompt IDs originate from the tokenizer's `.encode`;
  generated IDs originate from `generate_step`.
- [`make_sampler`](https://github.com/ml-explore/mlx-lm/blob/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5/mlx_lm/sample_utils.py#L13-L75)
  applies temperature/top-p/min-p/top-k/XTC controls. Temperature zero selects
  [`greedy_sampler = mx.argmax`](https://github.com/ml-explore/mlx-lm/blob/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5/mlx_lm/sample_utils.py#L133-L135)
  and consumes no PRNG. Positive-temperature categorical sampling is compiled with implicit random
  state and calls `mx.random.categorical` at
  [`sample_utils.py` lines 271-285](https://github.com/ml-explore/mlx-lm/blob/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5/mlx_lm/sample_utils.py#L271-L285).
- [`make_prompt_cache`](https://github.com/ml-explore/mlx-lm/blob/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5/mlx_lm/models/cache.py#L15-L41)
  may delegate to a model-defined cache; otherwise it creates rotating caches when a maximum KV
  size is supplied and plain `KVCache` otherwise. Save/load/trim lifecycle appears at
  [`cache.py` lines 43-152](https://github.com/ml-explore/mlx-lm/blob/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5/mlx_lm/models/cache.py#L43-L152).
  `KVCache` and `QuantizedKVCache` grow in 256-token increments at
  [`cache.py` lines 251-421](https://github.com/ml-explore/mlx-lm/blob/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5/mlx_lm/models/cache.py#L251-L421).
  Rotating-cache quantization is not implemented at
  [`cache.py` lines 423-554](https://github.com/ml-explore/mlx-lm/blob/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5/mlx_lm/models/cache.py#L423-L554).
  The future worker must report exact runtime cache classes rather than trusting a generic label.

### PRNG, device/backend, synchronization, environment, and threads

- MLX's Python PRNG key is explicitly thread-local at
  [`python/src/random.cpp` lines 19-67](https://github.com/ml-explore/mlx/blob/0e3ff3643b1c3719f78814b98e0d222afbad867c/python/src/random.cpp#L19-L67);
  `mx.random.seed` at
  [`lines 122-131`](https://github.com/ml-explore/mlx/blob/0e3ff3643b1c3719f78814b98e0d222afbad867c/python/src/random.cpp#L122-L131)
  seeds only the calling thread's implicit key. Unseeded state is lazily time-seeded. MLX-LM's CLI
  seeds only when explicitly requested at
  [`generate.py` lines 2007-2008](https://github.com/ml-explore/mlx-lm/blob/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5/mlx_lm/generate.py#L2007-L2008).
  The direct design uses one generation thread and still treats seed as a control, not a guarantee.
- [`default_device`](https://github.com/ml-explore/mlx/blob/0e3ff3643b1c3719f78814b98e0d222afbad867c/mlx/device.cpp)
  selects GPU when the compiled GPU backend reports available, otherwise CPU. Metal-enabled and
  no-Metal builds return constant availability from alternative source files:
  [`metal.cpp`](https://github.com/ml-explore/mlx/blob/0e3ff3643b1c3719f78814b98e0d222afbad867c/mlx/backend/metal/metal.cpp)
  and
  [`no_metal.cpp`](https://github.com/ml-explore/mlx/blob/0e3ff3643b1c3719f78814b98e0d222afbad867c/mlx/backend/metal/no_metal.cpp).
  These facts identify build/default configuration, not actual per-kernel execution.
- Official
  [`environment_variables.rst`](https://github.com/ml-explore/mlx/blob/0e3ff3643b1c3719f78814b98e0d222afbad867c/docs/src/usage/environment_variables.rst)
  documents compile, TF32, distributed, Metal synchronization, command-buffer tuning, GPU
  architecture and SDPA controls. Many are read when a subsystem first initializes. It defines no
  runtime `MLX_DISABLE_METAL` or device-selection variable. The future environment is therefore a
  closed allowlist established before imports.
- [`mx.eval`](https://github.com/ml-explore/mlx/blob/0e3ff3643b1c3719f78814b98e0d222afbad867c/python/src/transforms.cpp#L1181-L1199)
  blocks for graph evaluation; `async_eval` is explicitly experimental at
  [`lines 1201-1230`](https://github.com/ml-explore/mlx/blob/0e3ff3643b1c3719f78814b98e0d222afbad867c/python/src/transforms.cpp#L1201-L1230).
  [`mx.synchronize`](https://github.com/ml-explore/mlx/blob/0e3ff3643b1c3719f78814b98e0d222afbad867c/python/src/stream.cpp#L211-L228)
  waits for the selected stream. `wired_limit` synchronizes supplied streams before restoring the
  limit at
  [`generate.py` lines 229-254](https://github.com/ml-explore/mlx-lm/blob/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5/mlx_lm/generate.py#L229-L254).
- No subprocess or thread creation occurs in the reviewed single-sequence
  load/generate/sample/cache path. `ThreadLocalStream` is a per-calling-thread stream abstraction,
  not a thread creator. MLX subprocess use is confined to build/docs/benchmark/test utilities and
  the opt-in distributed launcher
  [`launch.py`](https://github.com/ml-explore/mlx/blob/0e3ff3643b1c3719f78814b98e0d222afbad867c/python/mlx/_distributed_utils/launch.py),
  which the direct worker forbids.

### Native metric scope and unavailable proof

- At
  [`generate.py` lines 718-740](https://github.com/ml-explore/mlx-lm/blob/5cfec4cb39deba54210b3ff4d86f2337c7bc10b5/mlx_lm/generate.py#L718-L740),
  prompt TPS covers prefill plus the first decode step. Generation TPS is the cumulative average
  after that first token, not an instantaneous rate.
- `mx.get_peak_memory` is cumulative since process start or the last `reset_peak_memory` according
  to
  [`python/src/memory.cpp`](https://github.com/ml-explore/mlx/blob/0e3ff3643b1c3719f78814b98e0d222afbad867c/python/src/memory.cpp).
  MLX-LM does not reset it in the reviewed generation path. A future per-run use must explicitly
  reset and record that action; process RSS is not substituted.
- Official APIs expose default-device/build availability, stream synchronization, and memory
  counters. They do not programmatically attest individual Metal kernel dispatch, order, fusion,
  timing, or physical GPU identity. Metal trace capture requires external `MTL_CAPTURE_ENABLED=1`,
  MLX capture calls, optional compile-time debug labels, and manual Xcode interpretation per
  [`metal_debugger.rst`](https://github.com/ml-explore/mlx/blob/0e3ff3643b1c3719f78814b98e0d222afbad867c/docs/src/dev/metal_debugger.rst).
  The contract therefore scopes future evidence as direct synchronized MLX runtime execution, not
  proven per-kernel GPU execution.

MLX/MLX-LM provide no normative claim that ordinary Metal generation is bit-exact across cache
state, process lifetime, package versions, OS/driver versions, or chip families. The protocol
measures repeatability within an exact closure rather than assuming it.

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
not claim that those public source revisions are byte-identical to the exact shipped OS build. The
separate assessment binds the unchanged PR #3 built-in declaration identity
`sha256:ebf8c3758c83c353e6e0bd9ab0f12d4aeb30ed9d7c1ed8f20669f7948f30022e`;
it does not alter that strict declaration record.

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
