# Native Evidence Card: a path is not a pin

**12 matched / 2 unmet / 1 unknown. AFTER-STARTUP NATIVE HELPER, NOT AN MLX BENCHMARK.**

<picture>
  <source media="(max-width: 1279px)" srcset="native-evidence-card-mobile.svg" width="600">
  <img src="native-evidence-card.svg" width="1200" alt="After-startup C/libc helper, not an MLX benchmark: 12 matched / 2 unmet / 1 unknown. The same allowed path reads a new object; socket creation succeeds. Pre-exec calibration is unknown with 14 later checks untested. Startup confinement is unproven, the runtime gate is ungranted, and MLX determinism is NOT MEASURED.">
</picture>

Controlled synthetic files supplied inputs to actual retained C/libc native outcomes.
These are historical Darwin 27.0.0 arm64 observations, not newly acquired measurements.
Matching expectations include allowed reads/writes and parent hygiene, not just denials.
The same policy was applied after helper startup; startup confinement remains unproven.

**MLX determinism: NOT MEASURED. Runtime authority: false. Physical approval: false.
Production bindings: null.** No latency, cost savings, GPU, model, or MLX enforcement claim.

## Complete after-startup results

All unconfined baseline controls succeeded. The aggregate remains
`refused`.
Descriptor hygiene covers 3..255; supplied stdin/stdout/stderr are not absent.
Environment/descriptor hygiene is not inherited-resource revocation.

| Check (required) | Control | Candidate | Assessment |
|---|---|---|---|
| Allowed read (allow) | Succeeded; byte A | Succeeded; byte A | MATCHED |
| Allowed write (allow) | Succeeded | Succeeded | MATCHED |
| Outside-list read (deny) | Succeeded; byte A | Denied (errno 1, EPERM) | MATCHED |
| Outside-list write (deny) | Succeeded | Denied (errno 1, EPERM) | MATCHED |
| Prefix-sibling read (deny) | Succeeded; byte A | Denied (errno 1, EPERM) | MATCHED |
| Symlink read (deny) | Succeeded; byte A | Denied (errno 1, EPERM) | MATCHED |
| Symlink write (deny) | Succeeded | Denied (errno 1, EPERM) | MATCHED |
| Socket creation (deny) | Succeeded | Succeeded | UNMET |
| Loopback connection (deny) | Succeeded | Denied (errno 1, EPERM) | MATCHED |
| Fork (deny) | Succeeded | Denied (errno 1, EPERM) | MATCHED |
| Other executable (deny) | Succeeded | Denied (errno 1, EPERM) | MATCHED |
| Self-exec (deny) | Succeeded | SIGABRT; no result | UNKNOWN |
| Descriptor hygiene (allow) | Succeeded | Succeeded | MATCHED |
| Environment hygiene (allow) | Succeeded | Succeeded | MATCHED |
| Replacement read (deny) | Succeeded; byte B | Succeeded; byte B | UNMET |

Connection denial is not socket-creation denial. Reading replacement byte B from a changed
fixture inode is not object pinning, concurrent race exclusion, or executable lifetime custody.
Self-exec's signal is UNKNOWN, never a proven denial.

## Separate pre-exec calibration

**1 unknown / 14 untested.** The allowed-read control succeeded;
the candidate aborted without output. The remaining checks were never launched.
This is not proof that macOS cannot enforce controls and not proof of startup confinement.

| Check (required) | Candidate | Assessment |
|---|---|---|
| Allowed read (allow) | SIGABRT; no result | UNKNOWN |
| Allowed write (allow) | Not launched | UNTESTED |
| Outside-list read (deny) | Not launched | UNTESTED |
| Outside-list write (deny) | Not launched | UNTESTED |
| Prefix-sibling read (deny) | Not launched | UNTESTED |
| Symlink read (deny) | Not launched | UNTESTED |
| Symlink write (deny) | Not launched | UNTESTED |
| Socket creation (deny) | Not launched | UNTESTED |
| Loopback connection (deny) | Not launched | UNTESTED |
| Fork (deny) | Not launched | UNTESTED |
| Other executable (deny) | Not launched | UNTESTED |
| Self-exec (deny) | Not launched | UNTESTED |
| Descriptor hygiene (allow) | Not launched | UNTESTED |
| Environment hygiene (allow) | Not launched | UNTESTED |
| Replacement read (deny) | Not launched | UNTESTED |

## Scope and provenance

[Pre-exec receipt](https://github.com/Siddhant-K-code/LocalInferenceLab/blob/2accb11d14a56222e36c8b61957ce56031ff04f7/docs/evidence/native-confinement-darwin-27.0.0-arm64-v1.json) ·
[After-startup receipt](https://github.com/Siddhant-K-code/LocalInferenceLab/blob/2accb11d14a56222e36c8b61957ce56031ff04f7/docs/evidence/native-confinement-after-startup-darwin-27.0.0-arm64-v1.json) ·
[Historical versus corrected-source disclosure](https://github.com/Siddhant-K-code/LocalInferenceLab/blob/2accb11d14a56222e36c8b61957ce56031ff04f7/docs/native-confinement-feasibility.md) ·
[Machine-readable card](native-evidence-card.json) ·
[Hands-on case study and five share drafts](a-path-is-not-a-pin.md).

Full input identities and raw-byte digests are in the JSON, not substituted for evidence.
Acquired producer identities differ from the current corrected offline-derived source identities.
Historical bytes are unchanged; corrected source is not a reacquisition.
Current host observations do not amend the frozen historical runtime target.
Neither receipt is an independent kernel audit or trusted acquisition signature.

Unproven: deprecated Seatbelt support, hostile-parent isolation, exact loader/native closure,
final executable identity, immutable lifetime, inherited resource use, internal native
math/tensor/cache activity, and real MLX/Metal compatibility.
The physical atlas remains unobserved with no accepted physical records.
A separate historical model-free MLX attempt failed; this card does not erase that attempt.

## Reproduce the publication, not the OS experiment

```bash
# From the repository root, with Python 3.12+; no install or MLX needed.
PYTHONPATH=src python3 -m localinferencelab.native_evidence_card \
  --pre-exec docs/evidence/native-confinement-darwin-27.0.0-arm64-v1.json \
  --after-startup docs/evidence/native-confinement-after-startup-darwin-27.0.0-arm64-v1.json \
  --output-dir /tmp/localinferencelab-native-card
```

Use a fresh output directory; existing output filenames are refused, never overwritten.
The same command with an installed wheel needs no `PYTHONPATH`: use
`python -m localinferencelab.native_evidence_card` and provide explicit paths to the
two original receipts from the [pinned source tree](https://github.com/Siddhant-K-code/LocalInferenceLab/blob/2accb11d14a56222e36c8b61957ce56031ff04f7).
The wheel does not bundle these receipts. No repository-relative discovery is attempted.

Outputs, in fixed order: `native-evidence-card.json`, `native-evidence-card.md`,
`native-evidence-card.svg`, `native-evidence-card-mobile.svg`, `a-path-is-not-a-pin.md`.
Compare all five committed outputs from the repository root:

```bash
diff -r docs/research/native-evidence /tmp/localinferencelab-native-card
```

JSON uses canonical sorted keys and no trailing newline; text and SVG use UTF-8/LF
with one trailing newline. All outputs derive from the same revalidated receipts.
Missing, changed, rehashed, noncanonical, or invalid inputs fail with exit 2.
Success exits 0 and prints only those filenames.

Only explicit input reads and requested output writes occur. No probes, subprocesses,
network, clocks, runtime-root/key observation, or MLX activity occur.
Integrity-only replay cannot authenticate the original OS acquisition.
