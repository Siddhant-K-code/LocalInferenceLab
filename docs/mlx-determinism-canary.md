# Runtime-independent MLX determinism canary

This framework compiles, verifies, inspects, and replays deterministic comparison records. It
never imports or executes MLX/MLX-LM, starts a worker, constructs or consumes authorization,
queries backend/device/Metal state, synchronizes hardware, discovers or loads a model/tokenizer,
performs an MLX tensor operation, benchmarks, uses a network, or spends cloud resources.

All committed positive records are synthetic. They copy exact embedded scalar/byte fixtures and
must not be described as observations of real MLX or Metal behavior.

## Offline commands

```bash
localinferencelab mlx determinism-canary-spec > canary-spec.json
localinferencelab mlx determinism-canary-verify canary-spec.json
localinferencelab mlx determinism-canary-inspect canary-spec.json

mkdir -p .artifacts/canary-a .artifacts/canary-b
localinferencelab mlx determinism-canary-fixture-compile .artifacts/canary-a
localinferencelab mlx determinism-canary-fixture-compile .artifacts/canary-b
diff -r .artifacts/canary-a .artifacts/canary-b
localinferencelab mlx determinism-canary-replay \
  .artifacts/canary-a/localinferencelab-mlx-determinism-canary-synthetic-v1-*
```

There is intentionally no execute, acquire, authorize, worker, probe, synchronize, model, or
benchmark command.

## Prospective matrix

| Dimension | Predeclared values | Current status |
|---|---|---|
| Operation | elementwise add, IEEE-edge identity, matmul, reduction sum, softmax, RMS normalization, fused multiply-add, unfused multiply-add | Every form unverified |
| Dtype | `float32`, `float16`, `bfloat16` | Every dtype unverified |
| Evaluation | explicit, deferred | Both modes unverified |
| Same-process repetition | 5 evaluations in one process | Future successor schema only |
| Cold-process repetition | 5 predeclared new-process observations | Future successor schema only |
| Device comparison | 5 CPU and 5 GPU observations | Report-only |
| Fusion comparison | 5 fused and 5 unfused observations | Report-only |
| Synchronization comparison | 5 output-materialization-only and 5 explicitly synchronized observations | Report-only |
| Retry count | 0 | Fixed |
| Timing | none | Forbidden unless separately authorized |

The operation/dtype/evaluation Cartesian product has 48 cells. Matrix inclusion never asserts MLX
support. Exactly eight cells have embedded synthetic fixtures; the other 40 are
`prospective_only_no_fixture`. Schema 1.0 cannot create a result for those cells. Its
machine-readable future registry contract is design-only and explicitly
`unavailable_and_rejected_in_schema_1_0`.

Every operation specification has a content identity over its mathematical contract and parameter
schema. Each represented case and result binds that identity, its matrix cell, and all concrete
parameters. RMS normalization binds axes/keepdims, exact epsilon and initial-accumulator bits,
square/accumulation/epsilon-add/output precision and rounding, reduction order, mean divisor, and
reciprocal-square-root contract. Verification re-derives expected output bytes from those bound
parameters with bounded standard-library scalar arithmetic.

## Comparison contract

Every tensor declares dtype, shape, endianness, exact lowercase hexadecimal bytes, payload digest,
and canonical descriptor digest. Shape rank, element count, byte count, case count, and atlas
result count are bounded. Booleans are not integers. Dtype, shape, endianness, element count, or
payload-length mismatch rejects the comparison.

Compatible outputs report:

- payload bitwise equality;
- canonical output digest equality;
- numerical equality under the declared edge policy;
- maximum absolute and relative error encoded as exact IEEE binary64 big-endian bytes;
- maximum native-dtype ULP distance;
- finite, NaN, infinity, signed-zero-difference, and special-mismatch counts.

NaN sign/payload mismatches and infinity sign mismatches are explicit failures. Positive and
negative zero have zero numerical and ULP error, but differing sign bits are counted. Non-finite
pairs do not silently enter finite error maxima. Both signed-zero encodings map to one ordered ULP
code, making either minimum subnormal one ULP from zero and opposite minimum subnormals two apart.

## Atlas path

The synthetic closed bundle proves canonicalization, validation, metric reconstruction, identity
cross-binding, and offline replay. The current verifier accepts no externally acquired,
authorized, or physical result. A future machine-readable physical atlas requires a new schema and
closed-bundle verifier that loads and independently validates each case registry, authorization,
runtime, device, process, and acquisition binding. Arbitrary digest strings cannot establish that
evidence.

Same-condition repeatability accepts only all-bitwise-equal observations. CPU/GPU,
fused/unfused, and synchronization-mode comparisons remain descriptive until a separately
reviewed protocol defines an acceptance threshold. Failed observations are retained; zero retries
means they cannot be replaced selectively.
