# Native confinement feasibility, schema 1.0

This is an explicitly invoked, bounded **harmless OS experiment**, not an MLX launcher,
authorization verifier, production sandbox, or positive runtime prerequisite. It builds a small
hand-written libc probe with an already installed compiler. No dependency is retrieved or installed.
It never imports MLX/MLX-LM, queries GPU/Metal, synchronizes, allocates tensors, loads models or
tokenizers, runs inference, creates trusted keys, consumes authority, or changes preflight gates.
The existing CLI, schema-1.2 worker/protocol, historical failure, qualification/target records,
ledger and frozen schema-1.1 evidence are unchanged. The atlas remains 18 unobserved cells and
**0 accepted physical records**.

## Explicit invocation

```bash
# Inert: static contract, import/help, or offline structural replay.
UV_NO_NETWORK=1 uv run python -m localinferencelab.native_confinement spec
UV_NO_NETWORK=1 uv run python -m localinferencelab.native_confinement --help
UV_NO_NETWORK=1 uv run python -m localinferencelab.native_confinement replay report.json

# Permission to run benign native probes only. Do not substitute a runtime or model.
# Captures can contain compiler diagnostics/private temporary paths: keep the report private.
umask 077
UV_NO_NETWORK=1 uv run python -m localinferencelab.native_confinement run > report.json

# Separate, bounded opt-in test. Default macOS/Ubuntu CI does NOT execute the experiment.
LOCALINFERENCELAB_NATIVE_PROBE=1 UV_NO_NETWORK=1 \
  uv run pytest tests/test_native_confinement.py -k explicit_native_probe -q
```

`run` exits 2 for any refused, unavailable, untested or unknown restriction. Exit 0 means only
that all **listed, finite syscall checks** matched their expectations; it never authorizes
MLX or establishes production readiness. Offline `replay` exits 0 for a structurally valid
record, including a record reporting failure; replay does not reproduce or authenticate it.
Outputs use canonical JSON without a trailing newline. Invalid replay/input emits a fixed
error type on stderr and exits 2.

The API is deliberately isolated: `native_confinement.run_probes()` takes **no arguments,
callback, runtime path, authorization object or bypass flag**. The companion contract exposes
`specification()`, `verify_report(value)` and `replay_bytes(data)`. There are no cross-branch APIs,
legacy entrypoint changes, default CI hooks, native binaries in the package, or import-time probes.

## Candidate and controls

The fixed custom Seatbelt profile starts with `(deny default)`. It permits initial execution
and executable mapping at the exact probe pathname, reading that executable and exact allowed
fixture paths, and writing the exact allowed fixture paths. The only nonfixture file grants are
the `/usr/lib/dyld` literal and `/System/Library/dyld` subtree for the native loader.
These path grants are **not a verified native dependency closure**. There is no allow-default
profile, network grant, fork grant, policy relaxation on failure, or unsandboxed candidate fallback.
Unconfined baseline controls are separate, explicitly labelled harmless measurements, not a
fallback enforcement mode.

Fifteen ordered probes compare baseline and candidate native `open/read/write`, `socket/connect`,
`fork/waitpid`, `execve`, descriptor enumeration and environment enumeration. All read/write
targets are controlled temporary fixtures; the denied files are outside the profile's exact
allowlist but still **inside the owned private temporary directory**. Symlinks point only to
those fixtures. Prefix siblings test literal rather than prefix grants. One permitted pathname
contains quotes, backslashes and parentheses; profile strings are escaped and nonprintable or
non-ASCII paths refuse rather than interpolate policy. Network probes use only IPv4 loopback and
one parent-owned ephemeral listener; there is no external traffic, accept/reconnect/watch loop,
or system-service interaction.

The initial allowed-read candidate calibrates whether the helper can start. A missing completion
halts the candidate experiment without retrying; its command exposure remains unknown and the
remaining probes are untested. Unsupported hosts/missing tools refuse before fixtures/processes/
sockets. Tool symlinks or unreadable/nonregular/oversized identities are unavailable, not followed
to a caller-selected executable. There is no provisioning, signing, entitlement change, privileged
action, global policy change or toolchain install.

The global measured interval is at most 30 seconds plus a 2-second cleanup allowance; compilation
has a 10-second subdeadline and each baseline/candidate command a 1-second subdeadline, all clipped
to the same global deadline. Collection retains at most 4,096 bytes **per stream per command**;
overflow stops collection. Deadline/overflow cleanup kills and waits on the exact owned subprocess
PID, closes its pipes, and removes the exact private temporary directory. There is no process-name
killing or retry. The probe itself limits CPU to 1 second, output file size to 1,024 bytes, open
descriptors to 256 and core size to zero. The installed compiler's own toolchain is not a
production-confined dependency/execution subtree; these bounds do not prove hostile descendants
or complete native lifetime exclusion.

## Exact evidence contract

`native_confinement_feasibility` / `schema_version="1.0"` is a deterministic encoding/schema,
not a promise that empirical observations or randomized fixture identities repeat byte-for-byte.
Unknown/extra fields, duplicate keys, floats, aliases such as Boolean PIDs, integer subclasses,
invalid enum values, noncanonical JSON, contradictory completion claims and excessive retained
bytes refuse. A report is at most 262,144 bytes and has exactly fifteen ordered observations.

| Field | Meaning |
|---|---|
| `specification_id` | Canonical identity of fixed operations, policy template, limits and limitations. |
| `identities` | Seven exact IDs: implementation (canonical source digest map), C source/source bundle, profile template, concrete escaped profile, compiled helper, installed sandbox-exec and installed compiler. Unobserved tool/profile/helper IDs are `null`. Tool hashes identify the invoked files, not their complete implementation/SDK/linker closure. |
| `host` | Observed Darwin system/release/machine, parent PID and monotonic start/finish; `null` before supported-host measurement. No trustworthy-time, signed host provenance or GPU claim. |
| `fixture` | Parent-observed device/inode/mode for the private root and initial allowed-read object, plus replacement object if exercised; otherwise replacement is `null`. Pins describe measurements, not OS object enforcement. |
| `compilation` | Bounded parent capture of the compiler command. |
| `observations` | Exact ordered operation/expectation, baseline/candidate captures and recomputed disposition. |
| Capture | `pid`, `exposure`, `terminal`, integer `elapsed_ns`, exit/signal `returncode`, canonical base64 `stdout`/`stderr`. `pid` is parent-observed, not independently verified final executable identity. |
| `disposition`, `reason` | Recomputed aggregate result and finite preparation/startup blocker code. |
| `untested` | Exact fixed limitations; these cannot be deleted or promoted by coordinated rehashing. |
| `runtime_authority`, `physical_launch_approved`, `production_bindings` | Always genuine `false`, genuine `false`, and `null`. |
| `record_id` | Canonical SHA-256 identity of all other fields; integrity only, not signature/authority. |

Capture terminals are `not_run`, `complete`, `deadline`, `output_limit`, `exit_error`, and
`spawn_failed`. After a launch call, `exposure="may_have_run"` is retained even for spawn failure.
A result delivered across a deadline is rejected as `deadline` **even if retained bytes contain
a successful syscall result**: native attempt/completion/effects remain UNKNOWN. Missing stdout,
signal/crash, malformed/duplicate native result, or stderr does not become a zero-action proof.
Unread bytes and actions outside the helper's measured syscall set remain unknown.

The compiler and every baseline/candidate command run serially. Their combined `elapsed_ns`
must fit within the recorded host start/finish span, including captures rejected for deadline
or output limits; exposed captures require that host interval. A spawned child PID cannot
equal the still-live parent PID. There is deliberately no global child-PID uniqueness claim
across serial commands: the OS may reuse a reaped PID. Every spawned terminal capture must
retain a reaped exit/signal `returncode`, including `deadline` and `output_limit`; only
`not_run` and `spawn_failed` have no child wait code. A wait code does not convert rejected
effects into accepted completion or authenticate host/process provenance.

Per-operation dispositions have deliberately narrow semantics:

| State | Meaning |
|---|---|
| `enforced` | A successful baseline and exact native result match the listed allow check, or the listed denial returns `EPERM`/`EACCES`. This proves only that particular finite observation. |
| `refused` | A measured operation contradicts the required expectation; this candidate is refused, not silently relaxed. |
| `unavailable` | The baseline cannot establish that the operation was available, or all candidate checks are untested because preparation was unavailable. |
| `untested` | That candidate operation was not launched. |
| `unknown` | Exposure occurred without acceptable completion/effect evidence, or the error does not establish policy denial. |

Aggregate precedence is refused, unknown, unavailable; any remaining untested check makes the
aggregate unavailable. There is no success-shaped skip. Offline verification recomputes every
disposition and the content identity; it cannot tell an invented/rehashed report from authentic
OS acquisition and must not be used as an authority verifier.

## Deliberate limits and the current blocker

Initial execution requires a path-based exec grant. The `exec_self` probe tests whether that same
grant also permits further `execve` of the helper; `exec_other` tests a different controlled
executable pathname. A successful self-exec is a **refused** no-further-exec restriction, even
when `fork` is denied. Network socket creation is distinct from connection initiation; successful
`socket()` is not relabelled denied merely because `connect()` fails.

The replacement probe atomically replaces the permitted read pathname with a new owned fixture
inode, then attempts to read its known replacement byte under the unchanged profile. Success is
**refused** object-pinning, not “still protected”. This is a deterministic replacement check,
not concurrent race exclusion, executable pinning, immutable closure/lifetime protection, a
hostile-parent boundary, or a complete snapshot. Descriptor checks cover 3..255; stdin/stdout/
stderr are intentionally supplied, not claimed absent. Empty child environment and close-fds
are parent hygiene, not Seatbelt authorization or an inherited-resource revocation proof.

**A native filesystem/network/process boundary cannot establish absence of mathematical,
tensor or cache work entirely inside a permitted native library. Real MLX/MLX-LM/Metal
compatibility has NOT been tested.** Neither this experiment nor more Python audit hooks
resolves that model-free import requirement.

On the available macOS 27.0.1 / Darwin 27.0.0 arm64 host, unconfined libc probes compiled and ran.
The deny-default candidate aborted with SIGABRT without a helper result, including bounded
startup experiments adding executable mapping and read-only sysctl access. No permissive
profile was tried. The final candidate retains the executable-mapping grant but **not** the
ineffective broad sysctl grant. Its measured startup is unavailable, exposed native effects
are unknown, and subsequent checks are untested. This is a concrete blocker, not readiness.

The retained [historical acquired observation](evidence/native-confinement-darwin-27.0.0-arm64-v1.json)
replays offline. Its allowed-read baseline returned the known fixture byte; the candidate's
parent-observed PID exited on signal 6 with no stdout/stderr. All fourteen subsequent operations
were not launched. Its serial capture sum is 601,133,042 ns, within the full measured interval
of 602,767,584 ns. Historical acquired record identity:
`sha256:94c12b835ac785f86a3b166837b67a5f7cf5a8457ce4ad4aa34f62afc7f873da`.
**Historical acquired pre-exec producer identity** (before diagnostic wiring):
`sha256:e53764779e3a61e239b1b4bbfd090ec89833ab0e062da3b5663640e146554b6b`.
The pre-correction shipped pre-exec source identity at commit `12c5674` was
`sha256:6bc75bf49671afb38a8c8a445911d6d44234ffe8dda78ccfdaa4a88e17bfcf6b`.
**Current corrected pre-exec source identity**, derived offline from the shipped sources:
`sha256:fa780e3e6a4cfd74abee4870ff63387f0e09865e2f182c3e6bab5489a7c1b3c4`.
Profile-template identity:
`sha256:65efe2ffd8c867fc5e31dbd9bda3d9095922bbf1f18f58f6675034b09fd43aa1`.
The historical receipt has NOT been rewritten or reacquired with either newer source. Source
identity drift is disclosed, not presented as new OS evidence. None of these identities is
trusted or production-approved.

### Distinct after-startup diagnostic

The pre-exec failure above is immutable and does **not** establish that macOS cannot enforce
native restrictions. A separate explicit diagnostic applies the **same profile**, with no added
filesystem/network/process grants, inside a tiny known native helper **after its own startup**:

```bash
umask 077
UV_NO_NETWORK=1 uv run python -m localinferencelab.native_confinement_after_startup run \
  > after-startup.json
UV_NO_NETWORK=1 uv run python -m localinferencelab.native_confinement_after_startup replay \
  after-startup.json
```

This diagnostic is never selected automatically, never retries the pre-exec candidate, and
always exits 2 when run: even matching checks cannot establish the required startup boundary.
It uses the same bounded private fixture engine, a fixed adapter C source including the original
probe source, and `sandbox_init(profile, 0, ...)`, **not a named profile**. Its implementation ID
binds all five Python/contract/C sources; its probe-source ID binds the two C source digests.
The sandbox-exec binary ID is the common installed-tool observation, not a claim that this
variant invoked sandbox-exec. Neither the adapter nor its libc initialization is confined
before the custom policy is applied.

The strict separate envelope is `native_confinement_after_startup_diagnostic` / schema 1.0,
with `application_stage="after_native_startup"`, genuine `startup_confinement_proven=false`,
genuine `runtime_authority=false`, a nested schema-1.0 `test_record`, and an outer canonical
`record_id`. Offline replay cannot authenticate application timing; rehashing cannot remove
the startup/non-authority limits.

The [retained separate diagnostic](evidence/native-confinement-after-startup-darwin-27.0.0-arm64-v1.json)
has a serial capture sum of 684,274,919 ns within a 687,192,458 ns host span. Its twelve
matching observations include
allowed read/write and descriptor/environment hygiene, plus EPERM for denied file read/write,
prefix siblings, symlinks, loopback connect, fork and the other controlled executable. **Socket
creation succeeded**, and the permitted read pathname accepted the replacement inode/byte B:
both required restrictions are **refused**. Self-exec terminated on signal 6 with empty output,
leaving its effects **unknown**, not proven denied. Every captured native stderr stream was
empty. This supplies actual native-effect evidence without claiming an approved launcher,
immutable objects, complete execution lifetime or MLX/Metal compatibility.

Outer diagnostic identity:
`sha256:be031b62bc65c7fe68e937e78a85f288d9ea871003aec3c4ce4a802ce0f29312`.
Nested observation identity:
`sha256:c308e83165b662d98d6d471e5d9d2640b3a3b68db6719855a06a1a96389af892`.
**Historical acquired diagnostic producer identity** (also the pre-correction source):
`sha256:af459854fedf83746e1317cf4e0643dba92ebb5e489baa6d23fe49e6be454e6a`.
**Current corrected diagnostic source identity**, derived offline:
`sha256:0507fd616e9383cf3a132c426b345b1dbd2a52a80d97cbaccd327ffb245aa7ed`.
The contract-only source correction changes both aggregate implementation identities, but
neither the profile nor C sources. The diagnostic receipt remains immutable historical
acquisition; there has been **no new native acquisition** with the corrected source.
Both receipts remain non-authority, and the historical exact runtime target/qualification is
unchanged; current Darwin 27 observations do not establish exact-target compatibility.

The narrow decision for independent review is to **keep launch closed**, unless a separately
scoped native startup-policy investigation or supported boundary redesign is approved. Even a
future successful finite experiment still needs independently reviewed enforcement, exact
provisioned Python/runtime/loader/framework closure and object custody, parent-observed child
executable identity, independent authority/time/host provenance and fresh separate provisioning
and physical-runtime approvals. This PR does not request, mint or consume any of them.

### Future trusted-code research-lab direction

The user subsequently chose a **trusted-code research lab with explicit isolation limits**,
not containment of malicious native libraries. That is a future policy decision, not an
authorization to provision/run MLX, reinterpret either receipt, or change this experiment's
expectations to manufacture a pass. The current measured failures and unknowns remain unchanged.

Under explicitly trusted OS/parent and independently reviewed, pinned-code assumptions, a narrow
usable safeguard stack would combine exact reviewed interpreter/wheel/native-loader manifests,
parent-observed private root/file custody and read-only runtime inputs, sanitized environment/
descriptors, finite process/resource/output budgets, and separately compatibility-tested
deny-connection/fork/outside-allowlist controls. Observed inode custody and trusted-parent
immutability discipline must be named as such, not advertised as Seatbelt inode enforcement.
Permitted socket creation, unconfined startup, re-exec uncertainty and unobservable internal
math/tensor/cache activity stay explicit exclusions. Real MLX/Metal compatibility, the exact
target, independently reviewed authority and separate fresh provisioning/runtime approvals
remain outstanding; no production implementation or gate change follows from this recommendation.

## Public sources and supported alternatives

Checked 2026-10-13; authoritative public Apple documentation and the installed Darwin manuals:

- [Apple App Sandbox](https://developer.apple.com/documentation/security/app-sandbox):
  supported app resource restrictions are entitlement-driven. This experiment does not adopt
  App Sandbox, sign an app, or claim equivalent supported deployment.
- [Protecting user data with App Sandbox](https://developer.apple.com/documentation/security/protecting-user-data-with-app-sandbox):
  supported embedded command-line tools inherit their app's sandbox configuration.
- [Outgoing network entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.network.client):
  TCP connection initiation and data flow are distinct. App Sandbox documentation does not
  establish this custom Seatbelt profile's behavior.
- Installed `man sandbox-exec` and `man sandbox_init` explicitly mark those interfaces deprecated
  and recommend App Sandbox. The installed macOS 27 SDK manual additionally warns that legacy
  named profiles must not be used when building against SDK >=27.0 and may kill the process.
  This experiment uses no named profile. The warning is not asserted as the cause of the
  custom candidate's SIGABRT.
- Installed `man sandbox` describes resource-acquisition-time restrictions. A profile/path
  allowlist is not an object pin or an inherited-resource revocation guarantee.

The unsupported SBPL candidate is empirical, not an Apple-supported cross-version policy API.
Tool presence, older examples, a package import, or a green offline test cannot establish it works
on another Darwin release.
