# Is Apple-Silicon AI Deterministic? Measuring MLX Before Loading a Model

> **Prospective study brief.** This article defines a question and a trustworthy way to measure it.
> It reports no physical MLX or Metal result.

**Thesis:** determinism is not a property we can infer from a package version, an Apple chip, a
hash, or one matching output. It has to be measured under predeclared conditions, with every
observation bound to the exact runtime, operation, process, authorization, and comparison rule that
produced it.

<picture>
  <source media="(max-width: 640px)" srcset="../assets/apple-silicon-determinism/locked-lab-mobile.svg" width="600">
  <img src="../assets/apple-silicon-determinism/locked-lab.svg" width="1200" alt="A sealed recipe identifies exact inputs, a locked laboratory represents missing permission, and an empty evidence tray represents zero accepted physical observations">
</picture>

> [!IMPORTANT]
> **Current state: 0 accepted physical MLX/Metal observations. No permission to run.**
> Static qualification has reached a reviewable decision, but no authorization, runtime import,
> device or Metal query, synchronization, tensor operation, benchmark, or model action is allowed.

## Three questions, not one

These terms are related, but they are not interchangeable:

| Question | What success would mean | What it would not mean |
|---|---|---|
| **Reproducibility** | Another reviewer can reconstruct the same declared bytes, identities, controls, and analysis. | The hardware will return the same bits. |
| **Numerical determinism** | Repeated evaluations under one exact condition satisfy a predeclared equality rule. | The result is authorized, authentic, or representative of another condition. |
| **Trustworthy evidence** | A parent validator accepts an observation whose authority, runtime, process, inputs, outputs, and custody all cross-bind. | The result is numerically equal or scientifically sufficient by itself. |

A SHA-256 digest answers **“which bytes?”** It does not answer **“who allowed this action?”** or
**“what did those bytes do on this machine?”** Hashes are essential identity links, but a
self-asserted chain of perfect hashes can still describe an unauthorized action or an event that
never occurred.

## ELI5: the recipe is checked; the laboratory is still locked

Imagine a school experiment:

1. A teacher seals the recipe and every ingredient. That is **identity**.
2. A safety reviewer checks that the recipe is internally coherent. That is **static
   qualification**.
3. The laboratory door remains locked until a responsible adult gives one-time permission. That is
   **authorization**.
4. A witnessed tray records what actually happened inside. That is **observed evidence**.

Checking the seal does not unlock the door. Unlocking the door does not prove the experiment ran
correctly. An empty tray cannot be described as a successful result.

## The trust progression

LocalInferenceLab deliberately separates four stages:

**1. Exact static qualification.** The canonical publication record
[`sha256:3d789c…711df`](../../evidence/mlx-runtime-qualification-mlx-0.30.4-mlx-lm-0.30.6-macos-arm64-py313-v1.json)
binds the reviewed MLX `0.30.4` / MLX-LM `0.30.6` candidate, target, source anchors, and a
34-artifact wheel closure. It derives `eligible_for_new_observed_authorization` with zero blockers.
That decision means only “eligible for human review toward a possible fresh authorization.”
Offline replay does not prove that the wheel pack is present now.

**2. Explicit authorization.** This does not exist. The current schema-1.1 layer is a
process-free contract and refusal surface: it has no authorization creator or consumer, installer,
worker, or execute entry point.

**3. Bounded execution.** A future implementation would need exact runtime custody, a one-shot
authority, fixed action budgets, no retries, a private worker protocol, strict parent validation,
and terminal process custody. Those requirements are design constraints, not current capability.

**4. Observed evidence.** Nothing physical has been accepted. There is no accepted proof of MLX
import success, native loading, backend or device availability, a positive Metal result, stream
synchronization, tensor behavior, model behavior, or per-kernel Metal dispatch.

The detailed boundaries live in the
[architecture](../architecture.md), [experiment protocol](../protocol.md), and
[direct MLX contract](../mlx-direct-runner-contract.md).

## The current atlas is a map, not a measurement

The [runtime-independent determinism canary](../mlx-determinism-canary.md) freezes a 48-cell
Cartesian product:

- eight operation forms: elementwise add, IEEE-edge identity, matrix multiplication, reduction
  sum, softmax, RMS normalization, fused multiply-add, and unfused multiply-add;
- three dtypes: `float32`, `float16`, and `bfloat16`;
- two evaluation styles: explicit and deferred.

All 48 cells remain `unverified_future_support`. Exactly eight cells contain synthetic byte
fixtures; the other 40 are prospective-only.

The eight fixtures **do** establish that the offline machinery can bind operation parameters,
validate tensor metadata, re-derive expected bytes with bounded standard-library arithmetic,
reconstruct comparison metrics, detect identity drift, and replay a closed synthetic bundle.

They **do not** establish MLX support, importability, Apple-silicon behavior, Metal availability,
device placement, execution order, fusion behavior, numerical determinism, performance, or any
physical observation. Schema 1.0 rejects physical and `authorized_observation` records by design.

## The proposed model-free study

The first physical study should stop below the model layer. No tokenizer, weights, prompt, cache,
sampling loop, or generated text is needed to ask whether transformer-shaped primitives repeat.
The successor protocol should predeclare each dimension rather than discovering convenient
settings after a run.

<picture>
  <source media="(max-width: 640px)" srcset="../assets/apple-silicon-determinism/experiment-flow-mobile.svg" width="600">
  <img src="../assets/apple-silicon-determinism/experiment-flow.svg" width="1200" alt="Prospective technical flow from a predeclared primitive matrix through a fresh human authorization gate, bounded future execution, strict parent validation, and an evidence atlas, with any mismatch routed to refusal">
</picture>

| Dimension | Prospective declaration |
|---|---|
| **Primitives** | Matrix multiplication, softmax, reduction sum, RMS normalization, and value-plus-index `top-k` / `argmax`, including declared tie cases. `top-k` / `argmax` would be a new operation contract; it is not in the current 48-cell atlas. |
| **Dtypes** | `float32`, `float16`, and `bfloat16`, but only for cells whose support is independently established. Unsupported combinations remain refusals, not missing data. |
| **Evaluation path** | Separate eager/uncompiled and compiled declarations. The current canary’s explicit/deferred styles are not evidence for either path and must not be relabeled. |
| **Process state** | A cold observation is the first declared evaluation in a fresh process. A warm observation is a numbered later evaluation in that same process. There are no discarded warmups. |
| **Repeats** | Five retained same-process evaluations and five retained cold-process observations per accepted condition, matching the canary’s prospective repeat intent. Retry count is zero; failures stay in the record. |
| **Synchronization** | Output-materialization-only and explicitly synchronized cohorts remain separately identified and report-only until a reviewed threshold exists. |
| **Comparison** | Exact dtype, shape, byte order, element count, payload length, bytes, and digest; bitwise equality; maximum absolute and relative error; maximum native-dtype ULP distance; and explicit NaN, infinity, signed-zero, and special-mismatch counts. |
| **Selection outputs** | `top-k` / `argmax` compare both values and indices. Tie construction and tie acceptance must be fixed before execution so an implementation-dependent tie cannot be explained away later. |

Same-condition repeatability should pass only when every retained output is bitwise equal. ULP,
absolute-error, and relative-error metrics remain diagnostic: they describe drift but do not turn a
non-bitwise repeat into a deterministic one. Cross-mode, cross-device, fusion, and synchronization
comparisons should remain descriptive unless a separately reviewed protocol defines an acceptance
threshold.

This is a determinism study, not a speed study. Timing is out of scope unless separately declared
and authorized. A future accepted device string or `metal.is_available()` value would still not
prove that each kernel used Metal; the strongest supportable claim would be scoped to the exact
worker-side backend facts that were actually accepted.

## The hard stop and the refusal rules

**Fresh human authorization is required after the static declaration and qualification are
reviewed, and before any authorization artifact may be created or any physical action begins.**
A future worker could consume that one-shot authority only after its exact identity and custody
bindings pass validation, and before its first allowed import, device query, synchronization, or
tensor operation. The repository cannot perform that transition today.

The future study must fail closed when any of these is true:

- the qualification, runtime, operation, case, process, output-root, nonce, or authorization
  identity is missing or drifts;
- authority is absent, stale, reused, caller-self-attested, or not independently custody-bound;
- a dtype, primitive, eager/compiled path, or device condition was not predeclared and proven
  eligible;
- a worker attempts an install, network action, model/tokenizer action, benchmark, retry, or other
  forbidden action;
- output dtype, shape, byte order, length, process identity, synchronization state, or retained
  repeat count does not match;
- a failed observation is dropped, replaced, or selectively rerun; or
- parent validation cannot distinguish attempted actions, completed actions, and accepted
  evidence.

Refusal is not a failed publication. It is the mechanism that keeps a prospective study from
quietly becoming a claim.

## What can be said today

The project has an exact static candidate, a zero-blocker qualification decision, a rigorous
comparison vocabulary, and synthetic fixtures that test that vocabulary. It has **zero accepted
physical MLX/Metal observations and no permission to run**.

That is enough to design the experiment honestly. It is not enough to answer the title.

For the canonical specifications rather than this narrative, read the
[canary contract](../mlx-determinism-canary.md), [schema-1.1 protocol](../protocol.md#prospective-schema-11-model-free-runtime-preflight-protocol),
[current source boundaries](current-sources.md), and
[static preparation runbook](../runbooks/mlx-prospective-study.md).
