# LocalInferenceLab

**Before local AI can run, prove exactly what would run -- and make refusal deterministic.**

<picture>
  <source media="(max-width: 600px)" srcset="docs/assets/readme/qualification-pipeline-mobile.svg">
  <img src="docs/assets/readme/qualification-pipeline.svg" width="1200" alt="System map showing the proposal, static qualification, human gate, bounded custody, and evidence path; the current project stops after static qualification and routes missing authority to refusal">
</picture>

> **Current state: static only.** The final qualification record is
> `eligible_for_new_observed_authorization`: eligible for human review toward a
> possible fresh explicit authorization. **No runtime action is authorized.**

## ELI5: checking ingredients is not cooking

<picture>
  <source media="(max-width: 600px)" srcset="docs/assets/readme/sealed-kitchen-mobile.svg">
  <img src="docs/assets/readme/sealed-kitchen.svg" width="1200" alt="Sealed ingredients and an offline checklist sit outside a locked kitchen, illustrating that verifying exact bytes and metadata does not execute them">
</picture>

- **Sealed ingredients** are exact candidate bytes, metadata, source anchors, and hashes.
- **The checklist** verifies their static coherence offline.
- **The locked kitchen** is runtime execution. It still needs a fresh human decision and authoritative custody.

The project proves what it can without quietly crossing that boundary.

## What is true now

| Current proof | Not proven |
|---|---|
| The canonical static qualification record derives `eligible_for_new_observed_authorization` with zero blockers. | That decision authorizes nothing and proves no install, import, runtime, device/Metal, synchronization, or model fact. |
| Pinned review binds the exact MLX `0.30.4` / MLX-LM `0.30.6` candidate, source evidence, target, 34-wheel closure, pack specification, and prior verified receipt. | Offline replay does not prove the wheel pack is present now, that native loading works, or that the candidate is runtime-executable. |
| MLX runtime-preflight schema 1.0 is permanently disabled. Schema 1.1 defines a prospective refusal contract. | Schema 1.1 has no worker, installer, authorization creator/consumer, or execute entrypoint. It remains unreachable until fresh explicit authorization and custody prerequisites exist. |
| One historical authorized preflight attempt failed closed and was not retried. | Its rejected worker frame was not retained, so it yielded no accepted runtime facts: no import, backend/device, synchronization, or exact forbidden-action fact. |
| The determinism canary freezes a 48-cell prospective matrix and exact comparison semantics. | Its eight committed positive cases are synthetic only. No physical MLX or Metal observation has been accepted. |

## A map, not a measurement

<picture>
  <source media="(max-width: 600px)" srcset="docs/assets/readme/determinism-atlas-mobile.svg">
  <img src="docs/assets/readme/determinism-atlas.svg" width="1200" alt="Determinism atlas preview with 48 prospective cells, eight synthetic represented cells, and zero accepted physical MLX or Metal observations">
</picture>

The canary makes future observations comparable. It does not manufacture them.

## How trust flows

**Declare exact inputs** -> **replay static checks** -> **stop at the human gate** ->
**require fresh one-shot authority and bounded custody** -> **accept only parent-validated evidence**.

Any mismatch, missing prerequisite, stale claim, or unsupported transition ends in refusal. A hash
binds bytes; it does not create authority.

## Inspect the evidence

| Start here | What it answers |
|---|---|
| [Architecture](docs/architecture.md) | What exists, what can act, and what stays process-free |
| [Protocol](docs/protocol.md) | Which records, gates, counters, and ledgers define trust |
| [Direct MLX contract](docs/mlx-direct-runner-contract.md) | The private-worker boundary and its explicit blockers |
| [Determinism canary](docs/mlx-determinism-canary.md) | The 48-cell matrix and exact comparison rules |
| [Final static qualification record](evidence/mlx-runtime-qualification-mlx-0.30.4-mlx-lm-0.30.6-macos-arm64-py313-v1.json) | The canonical zero-blocker static decision |
| [Historical failed-attempt projection](evidence/mlx-runtime-preflight-negative-v1.json) | What the failed preflight retained -- and did not retain |
| [Current sources](docs/research/current-sources.md) | Immutable upstream revisions and claim boundaries |
| [MLX static runbook](docs/runbooks/mlx-prospective-study.md) | Offline commands and refusal-only custody checks |

Explore the command surface without running a model:

```bash
uv run localinferencelab --help
```

For maintainers, CI's offline entry point is:

```bash
UV_NO_NETWORK=1 make validate
```

---

**The next gate is not "run it."** It is a fresh human decision backed by authoritative one-shot
authorization and custody that does not exist yet.

Apache-2.0.
