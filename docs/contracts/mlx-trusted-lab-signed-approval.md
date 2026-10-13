# Trusted-code lab retained signed-request evidence, version 2.0

**Candidate implementation/spec/policy: UNREVIEWED. Production execution remains closed.**
This is the user-selected trusted-code research-lab policy, not containment of malicious
native libraries. It trusts the host OS, current human user and parent process, and requires
independent review of exact-pinned Python/MLX/transitive/native code before future execution.
There is no hostile-parent/root/library containment, complete immutable native lifetime,
full-machine snapshot rollback resistance, external trusted time, or exhaustive proof that
libraries perform no internal tensor/cache work. “Model-free” describes scoped application
operations only.

## Separate version, not a downgrade of old approval meanings

`mlx_preflight_trusted_lab.py` exposes only a dedicated v2.0 request/spec and canonical signed
payload. It shares private structural validation/building with the
[v1.0 request machinery](mlx-preflight-authorization-request.md), not a generic public
policy plug-in or verification callback. v1.0 retains its exact published schema, spec
`sha256:8dde416f087e2b91b16cf32c02bb668129a9efc85f754bf0498bad4f337de7c8`,
policy `sha256:7a2b124f4f69ec7bc8107a6a341291587d782fad2bbaf528447c8dbfdfea27ea`,
13 unavailable prerequisites and always-blocked preparation/replay behavior. Old requests
and signatures cannot be interpreted as v2.0. Changes to shared validator bytes are new
candidate source identities, not retroactive changes to old record meanings.

The new request binds the same exact static target and 34-artifact closure, private `0700`
root declarations and nested `0555` execution-root declaration, full source/environment
claims, parent-process claim, nonce, one-attempt challenge/hello, and at-most-30-second validity.
The spec additionally content-binds the current shared validator, dedicated policy and
retained verifier source bytes. All new source/spec/policy identities are **UNREVIEWED**.
Matching source candidates, static eligibility, caller hashes/manifests/declared roots and
a matching hello are not authenticated installations, root/process observations or authority.
The target remains CPython 3.13.15 / MLX 0.30.4 / MLX-LM 0.30.6; nothing selects the current host.

`approval_payload_bytes` serializes the **full exact spec, policy and request**, with fixed
principal `localinferencelab-human`, scope `signed_request_evidence_only`, schema 2.0 and a
content ID. The signature covers every canonical payload byte, not a favorable subset or
aggregate receipt. Unknown fields, duplicate keys, floats, Boolean/integer aliases, old
versions, policy/source substitutions, noncanonical bytes and coherent self-rehashes that
violate pins refuse. Context changes that remain structurally valid require a new signature.
The request is bounded to 32,768 bytes; the full payload to 65,536 bytes.

## Explicit processful evidence verifier

`mlx_preflight_approval.verify_retained_approval` is an explicit library operation, not a CLI
entrypoint, import/discovery/replay side effect or production approval API. Its arguments
are three separately retained, non-nested absolute private directories and an independently
retained expected trust-content identity. The digest is an out-of-band content pin under
the trusted-human assumption, **not proof of an enrollment/review event**.

The trust directory contains `trust.json`. Its exact fields are:
`record_type`, `schema_version`, `trust_id`, `policy_id`, `spec_id`, `mechanism_id`,
`mechanism_approval`, `tool_sha256`, `principal`, `namespace`, `public_key`, `state`, `scope`.
The record type is `mlx_trusted_lab_retained_public_trust`, version 1.0; `trust_id` hashes
the canonical content without itself. It must match the independently retained expected ID,
the exact v2 spec/policy and fixed mechanism identity. State must be `enabled`, mechanism
approval `human_configured_approved_for_evidence_verification_only`, and scope
`signed_request_evidence_only_no_runtime_authority`. Namespace is
`localinferencelab-trusted-code-research-approval-v2`, principal is the literal principal above,
and the public key is a bounded exact `ssh-ed25519` wire key, without comments/options.
These configuration statements are human-controlled assumptions, not independently observed
review or live operator authority. No configuration writer, trust enrollment, issuer, signer,
key-generation, agent/keychain access or verification-tool installer is provided.

The approval directory contains `signed-request.json` and `signed-request.sig`.
Keys inside SSHSIG or extra artifact fields never become a trust anchor.
The human owns later enrollment/change/revocation decisions and the dedicated,
passphrase-protected signing key outside worker-accessible files. This verifier reads only
public configuration/signature bytes; it does not measure a private key's passphrase,
worker accessibility or its ceremony. Mode checks cannot isolate hostile same-user native
code; the separately retained architecture depends on the selected trusted-code policy.

All custody path components are opened no-follow, with trusted root/current-user ancestors
and only protected sticky-directory exceptions for shared temporary ancestors. Each final
root must be current-user `0700`, distinct and non-nested. Files must be current-user `0600`,
regular, singly linked and bounded (8,192-byte trust/signature bounds). Stable reads retain
device/inode/owner/mode/link/size/mtime/ctime pins and exact bytes, rechecked before/after
verification and publication. Replacement, revocation, drift, symlinks, hardlinks, FIFO,
ownership/mode errors or missing bytes refuse; no replacement identity is learned.
Non-nesting is checked against stable descriptor-relative `..` ancestor objects, not lexical
path spelling. Two bounded walks (at most 128 objects each) must agree; directory ancestry is
retained and rechecked with custody. Case, Unicode-normalization and volume aliases cannot
hide a nested root, while genuinely distinct objects are not conflated by casefolding.
Unsafe, unstable or over-bound ancestry refuses; unavailable output custody raises an explicit
retention failure.

Only absolute `/usr/bin/ssh-keygen -Y verify` is invoked. A no-follow, stable, root-owned,
non-group/world-writable executable read must match the independently retained tool digest.
Unapproved/missing/mismatched tooling refuses or records explicit unavailability. Exact tool
bytes are measured; the OS loader, libraries and complete tool lifetime are **not** made immutable.
The trusted-host scope covers the remaining measured-path-to-exec race.
Temporary verifier inputs are private pinned copies of the retained allowlist/signature.
Stdin receives the full payload; argv contains only fixed verify options and internal private
paths. There is no shell, caller command/executable, arbitrary verifier callback, inherited
environment, signing operation or inherited application descriptor.
The environment is exactly `LC_ALL=C`, `TZ=UTC`.

Input/output are bounded and multiplexed; combined output is limited to 8,192 bytes and
execution to two seconds, followed by bounded exact-child kill/wait handling. Arbitrary output,
raw child waits/PIDs, keys and paths are never projected publicly. Rejection is distinct from
deadline/output/signal/I/O/termination ambiguity; ambiguous exposure is **UNKNOWN**, not zero
or completed. There is no claim of malicious-tool containment.
Only an actual exact-child terminal status returned by `os.waitpid` can establish successful
exit or normal rejection. `Popen.wait`, `Popen.poll`, `returncode` and verifier stdout are never
status authority: CPython may synthesize zero after ECHILD. Ignored SIGCHLD, another legitimate
parent reaper, stolen/missing/malformed status or wait errors instead retain UNKNOWN status
and refuse, even for an otherwise valid signature. Cleanup uses bounded owned-PID status
observations; a lost status is not permission to kill a potentially recycled PID.
Private evidence retains the typed actual terminal wait status, or null when unavailable;
only its fixed disposition/termination projection is public.

## Time, retention and detached evidence

Each invocation creates a fresh parent-process-bound verification session and directly samples
trusted OS wall time inside a monotonic bracket. There is **no production clock/callback
injection API**. Sampling uncertainty and wall/monotonic elapsed disagreement are bounded
to five milliseconds; observed backward movement refuses and poisons that session.
Both signed wall and monotonic validity windows are checked before/after verification and
after retention, including agreement with the signed proposed clock pair. Restart/fork requires
a fresh session. Undetected pre-session clock rollback/full-machine snapshots are not excluded.
Later consumption would require fresh verification, custody and expiry rechecks; that adapter
is not implemented and consumption remains closed.

The private receipt-last bundle retains actual trust, complete payload, signature and observed
clock bytes, plus a privacy-safe outcome report. Return values hold detached immutable audit
bytes and a generated bundle basename, never a permit/ledger/executable object.
Malformed input/custody failures retain honest available bytes and explicit refusal outcomes.
The approval-only parser bounds each integer token to 20 digits before conversion, using the
canonical duplicate/float/constant/value validators. This narrow bounded-input parser refuses
integer-digit-limit payloads (including either retained trust or signed-request file), preserving
their exact available bytes; it does not catch arbitrary ValueError/programming failures globally
or change the repository's shared/historical JSON parser.
The narrow recursion guard also covers recursive canonical/value validation, including the
public v2 request-byte API. Deep bounded-byte inputs refuse with ContractError; no raw
RecursionError escapes that API, and unrelated ValueError/programming failures still propagate.
Verification followed by custody drift/expiry retains a subsequent refusal referring to the
prior observation ID; the earlier record describes only its observed interval, never ongoing
authority. Failure to retain either outcome raises `ApprovalRetentionError`, with no
success-shaped fallback. Public reports expose hashes, fixed status codes, bounded accounting
and candidate identities, not private paths, nonce/challenge, key bytes or arbitrary tool output.
Post-publication checks establish an additional observed interval, not permanent custody.
The final outcome bundle retains those postchecks and refers to the prior observation bundle;
its explicit postcheck scope covers that prior retention, never indefinite future custody.

Every outcome has `runtime_authorized`, `consumable`, `physical_launch_enabled`,
`accepted_physical_evidence` and `ledger_permit_created` **false**. A verified signature proves
only that the retained key verifies those exact signed bytes under the selected mechanism;
it does not prove human approval provenance, independently observed installations, physical
truth or live authority. JSON/copies/Booleans/callbacks cannot dispatch. No ledger file is opened,
no `consume_once`/`dispatch_synthetic_once` call is made, and no native worker or physical
acceptance gate is modified.

## Native limits and remaining blockers

The separate Darwin 27.0.0/macOS 27.0.1 arm64 benign probe's pre-exec candidate failed startup
with SIGABRT; historical failure receipt
`94c12b835ac785f86a3b166837b67a5f7cf5a8457ce4ad4aa34f62afc7f873da`
remains a failure. Its distinct after-startup diagnostic
`be031b62bc65c7fe68e937e78a85f288d9ea871003aec3c4ce4a802ce0f29312`
observed denied forbidden file read/write/prefix/symlink, loopback connection, fork/other-exec,
but **socket creation succeeded**, same-path new-inode replacement exposed byte B, and self-exec
produced SIGABRT/no result **UNKNOWN**. These are partial benign-helper measurements, not startup
confinement, actual MLX-process enforcement, exact-target MLX/Metal compatibility, authority or
readiness. No unmerged probe API is imported and no historical failure is reclassified.

Remaining closed prerequisites include independent review of this new policy/source/mechanism,
real human trust/approval custody, separate provisioning approval and fresh wheel bytes,
installation/exact environment/native-loader/framework custody, independent live root/host/process
observations, exact code review and measured trusted-lab isolation/child-identity limits,
production ledger binding/dispatch and an independent physical verifier. Code merge grants none
of them. Worker identity
`sha256:063f357df20b2b58be6b1b8b68c6321a33fdd15ba169e3c6173838524fee694a`
and protocol
`sha256:f7da6af4121dce3262230807f6faf73b83c1fd7d7bfe86ce98f9a634e6232881`
remain UNREVIEWED as runtime authority. Previous wheel bytes are deleted. Schema 1.0 historical
failure, frozen 1.1 evidence, qualification/registry/target/atlas and ledger-owned files are untouched.
The atlas remains 18 unobserved cells / 0 accepted physical records.

The [published non-secret regression vectors](../../tests/data/trusted-lab-openssh/README.md)
are isolated test-only data, never a default trust root or deployable approval. Their known key
is explicitly denied operator-authority promotion. Tests do not generate keys or sign; real
OpenSSH verification is exercised with precomputed signatures, and clock/custody fault
instrumentation remains outside the production API.
