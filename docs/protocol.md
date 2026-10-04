# Experiment protocol

## Canonical form

Records use schema version `1.0` and canonical UTF-8 JSON:

- object keys are sorted;
- separators contain no insignificant whitespace;
- duplicate keys, unknown keys, floats, NaN, and infinity are rejected;
- exact bytes use unpadded URL-safe base64;
- identities use `sha256:<lowercase hex>` over canonical record bytes.
- identity allowlists are non-empty, unique, and sorted.

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
- backend flags;
- capability evidence.

Static artifact probes are always incomplete and never claim runtime capability. Observed MLX-LM
identity requires an immutable install manifest plus both MLX and MLX-LM versions. Observed
llama.cpp identity requires executable bytes, commit/build evidence, and an explicit Metal flag.
Observed Ollama identity requires immutable runtime bytes or manifest plus the selected internal
runner because Ollama can route Apple Silicon models through different engines.

### Model

Representations have distinct identity shapes:

- `mlx_snapshot`: snapshot file manifest plus config and tokenizer digests;
- `gguf`: full file bytes plus GGUF metadata and tokenizer metadata;
- `ollama_manifest`: manifest/config/layer digest closure.

`cross_representation_equivalence` defaults to `unproven`. `mapped` requires a content-addressed
mapping artifact. Labels and marketing names never create equivalence.

## Prospective protocol

The protocol binds exact prompt bytes and digest, chat-template digest, sampler controls, output
and context limits, allowed cache cohorts, repeat count, fixed ordering, backend order, concurrency,
timeout, retries, and exact runtime/model/host allowlists.

V1 accepts only backend-blocked ordering because it is the only schedule encoded and enforced by
the current record. New ordering modes require an explicit schedule schema.

Prompt bytes and template identity are separate because a backend can transform the same user text
into different tokenization inputs. A later observed runner must capture tokenization identity and
exact request bytes when observable.

## Cache cohorts

Runs are grouped into exactly one of:

| Cohort | Meaning |
|---|---|
| `cold_process_model` | New process or runtime and cold model state |
| `warm_model_cold_prompt_cache` | Model resident, prompt or KV reuse disabled or empty |
| `warm_prompt_kv_cache` | Prompt or KV state reused and identified |
| `unsupported` | Backend cannot establish a requested cache state |

Analysis keys include backend, runtime, model, protocol, and cohort. Cohorts are never pooled
silently. Run order remains part of custody even when it is not part of the grouping key.

## Run observations

A valid run binds exact request bytes and digest, raw response bytes, UTF-8 text, token IDs when observable, finish
reason, structured response envelope bytes, backend-native metrics, resource measurements, and all
identity references. Every byte-bearing field carries a matching digest. Observed runs also account
for one inference request and zero or one model process start.

An invalid run carries the request digest and an error digest, but no partially trusted output.
This permits custody without turning malformed backend output into a successful observation.

## Equality semantics

Within each backend, runtime, model, host, protocol, request, and cache cohort, replay independently
compares:

- raw response digest;
- text digest;
- token ID sequence digest when every run exposes token IDs;
- finish reason;
- structured envelope digest.

`equal` means exact equality for that projection only. A semantic projection is not defined in v1.
No LLM judge is used.

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

- two byte, text, token, finish, and envelope-identical MLX-LM records in
  `cold_process_model`;
- two llama.cpp records with text, token, raw, and envelope divergence in
  `warm_prompt_kv_cache`;
- synthetic native durations and counts, plus explicit unavailable TTFT, memory, and energy;
- MLX snapshot and GGUF identities with equivalence `unproven`;
- two forbidden declarations with zero process, inference, network, and download budgets.

Synthetic availability exercises arithmetic and schema behavior. It is never converted into an
observed or hardware benchmark claim.
