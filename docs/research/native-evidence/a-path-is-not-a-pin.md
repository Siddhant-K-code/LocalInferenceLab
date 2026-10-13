# A path is not a pin: what my macOS probe actually measured

**12 matched / 2 unmet / 1 unknown. After-startup native helper, not an MLX benchmark.**

<picture>
  <source media="(max-width: 1279px)" srcset="native-evidence-card-mobile.svg" width="600">
  <img src="native-evidence-card.svg" width="1200" alt="After-startup C/libc helper, not an MLX benchmark: 12 matched / 2 unmet / 1 unknown. The same allowed path reads a new object; socket creation succeeds. Pre-exec calibration is unknown with 14 later checks untested. Startup confinement is unproven, the runtime gate is ungranted, and MLX determinism is NOT MEASURED.">
</picture>

Before measuring local AI determinism, I wanted to understand what a narrow macOS policy
actually constrained. The useful finding was smaller than a GPU result: an allowed filename
stayed the same while the object behind it changed.

## ELI5: the address stayed; the parcel changed

Imagine a guard who checks one locker address. Someone replaces the parcel inside.
The address still matches; the parcel does not.

The initial allowed read returned byte **A**.
The parent atomically replaced that owned fixture pathname with a different inode containing
byte **B**. Under the unchanged path policy, the native helper read **B**.
An inode identifies a filesystem object. Observing an inode does not make it an enforced pin.

This controlled replacement is not a hostile-parent attack or concurrent race test.
"Allow this path" and "read these exact bytes for the entire process lifetime" are different
requirements; this observation does not characterize every pathname policy.

## What actually ran

A hand-written C/libc helper exercised owned files, loopback sockets, fork/exec and hygiene
on Darwin 27.0.0 arm64. **Synthetic fixture** means deliberately chosen input bytes and paths.
**Retained native outcome** means actual helper results and parent-observed failures,
not invented success fixtures.

The pre-exec candidate used a deny-default Seatbelt profile. Its allowed-read control
succeeded, but the candidate exited on SIGABRT with empty output. That left
**1 unknown calibration and
14 later checks untested**. It is not proof that macOS
cannot enforce controls.

A separate diagnostic applied the same profile after helper startup, adding no grants.
It measures an already-running helper, not startup confinement or actual MLX enforcement.

## Every after-startup result

All baseline controls succeeded. "Matched" includes intended allowances, not just denied
actions. The aggregate remains `refused`.

| Check (required) | Candidate | Assessment |
|---|---|---|
| Allowed read (allow) | Succeeded; byte A | MATCHED |
| Allowed write (allow) | Succeeded | MATCHED |
| Outside-list read (deny) | Denied (errno 1, EPERM) | MATCHED |
| Outside-list write (deny) | Denied (errno 1, EPERM) | MATCHED |
| Prefix-sibling read (deny) | Denied (errno 1, EPERM) | MATCHED |
| Symlink read (deny) | Denied (errno 1, EPERM) | MATCHED |
| Symlink write (deny) | Denied (errno 1, EPERM) | MATCHED |
| Socket creation (deny) | Succeeded | UNMET |
| Loopback connection (deny) | Denied (errno 1, EPERM) | MATCHED |
| Fork (deny) | Denied (errno 1, EPERM) | MATCHED |
| Other executable (deny) | Denied (errno 1, EPERM) | MATCHED |
| Self-exec (deny) | SIGABRT; no result | UNKNOWN |
| Descriptor hygiene (allow) | Succeeded | MATCHED |
| Environment hygiene (allow) | Succeeded | MATCHED |
| Replacement read (deny) | Succeeded; byte B | UNMET |

**Socket creation succeeded; loopback connection was denied.** `connect()` is not `socket()`.
Self-exec's SIGABRT leaves effects unknown, not proven denied.
Descriptor hygiene covered 3..255, not supplied standard streams.
Empty environment/closed extra descriptors are parent hygiene, not resource revocation.

## What you can reuse now

Reuse this requirements checklist: paths versus objects, acquisition versus connection,
completed denials versus crashes. Keep the negative and unknown rows.

The exporter checks original receipt bytes and identities, reuses canonical/native validators,
and derives counts, tables and visuals together. Caller-rehashed mutations cannot publish.
Regenerate without MLX:

```bash
# From the repository root, with Python 3.12+; no install or MLX needed.
PYTHONPATH=src python3 -m localinferencelab.native_evidence_card \
  --pre-exec docs/evidence/native-confinement-darwin-27.0.0-arm64-v1.json \
  --after-startup docs/evidence/native-confinement-after-startup-darwin-27.0.0-arm64-v1.json \
  --output-dir /tmp/localinferencelab-native-card
```

Use a fresh output directory. Outputs: `native-evidence-card.json`, `native-evidence-card.md`,
desktop/mobile `native-evidence-card*.svg`, and this article.
Installed wheel: omit `PYTHONPATH=src`,
use its Python, and supply explicit original receipt paths; they are not bundled.
The [reproduction contract](native-evidence-card.md#reproduce-the-publication-not-the-os-experiment)
specifies byte comparison and errors.

## What this does not buy us

**MLX determinism: NOT MEASURED. Runtime authority and physical approval remain false;
production bindings remain null.** No model latency, lower inference cost or GPU performance
was measured. A historical model-free MLX attempt did occur and failed; these results
do not erase it or yield accepted MLX evidence. The atlas stays unobserved.

The helper cannot exclude internal native math/tensor/cache work. Loader grants are not an exact
native closure. Deprecated Seatbelt, unconfined startup, permitted sockets, re-exec uncertainty
and trusted-parent limits remain.
Integrity-only offline replay does not authenticate original OS acquisition.

[Pre-exec receipt](https://github.com/Siddhant-K-code/LocalInferenceLab/blob/2accb11d14a56222e36c8b61957ce56031ff04f7/docs/evidence/native-confinement-darwin-27.0.0-arm64-v1.json) and
[after-startup receipt](https://github.com/Siddhant-K-code/LocalInferenceLab/blob/2accb11d14a56222e36c8b61957ce56031ff04f7/docs/evidence/native-confinement-after-startup-darwin-27.0.0-arm64-v1.json) retain full
identities.
The [disclosure](https://github.com/Siddhant-K-code/LocalInferenceLab/blob/2accb11d14a56222e36c8b61957ce56031ff04f7/docs/native-confinement-feasibility.md) distinguishes historical acquired producers from current
corrected offline-derived sources: unchanged receipts, no reacquisition.
Host observations do not amend the frozen runtime target. No permission is added.

## Ready-to-share X drafts

Copy each draft without its numbering. No post has been sent.

1. A path is not a pin. My retained macOS C/libc helper read byte B from a new inode at the same allowed pathname. A path allowlist did not pin the object. After-startup diagnostic only; MLX determinism is not measured.

2. Actual native-helper results: 12 matched / 2 unmet / 1 unknown. Matched includes allowed reads/writes and hygiene, not just denials. After-startup policy, not startup confinement. Not an MLX benchmark.

3. Blocked connect() is not blocked socket(). The retained after-startup helper could create a socket but could not connect to loopback. Test the exact action your requirement names, not a nearby proxy.

4. An honest failure panel: pre-exec allowed-read control worked; candidate aborted with no result. 14 later checks were untested. That is not proof macOS cannot enforce controls. No MLX runtime permission is granted.

5. Reuse the analysis now: two pinned public receipts -> deterministic JSON, Markdown and SVG, with a Python standard-library command. No native probe or MLX needed. Offline replay checks integrity; it cannot authenticate the original OS acquisition.
