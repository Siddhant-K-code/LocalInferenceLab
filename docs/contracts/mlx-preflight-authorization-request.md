# Staged MLX preflight authorization request, version 1.0

**This is an offline request/data-verification prerequisite, not production dispatch.**
`mlx_preflight_authorization.py` adds a content-bound proposal for the prospective schema-1.2
model-free worker. `prepare_authorization_acquisition` always raises
`AuthorizationAcquisitionError`, retaining canonical, privacy-safe refusal bytes.
There is no issuer, key generation, positive grant verifier, callback, approval/execute flag,
production ledger opener or physical acceptance path in this module.

The separate [trusted-code lab v2.0 signed-request evidence adapter](mlx-trusted-lab-signed-approval.md)
is a new candidate policy, not a reinterpretation of this version's stronger unresolved native
enforcement requirements. This v1.0 spec/policy/request meaning and always-blocked preparation
remain unchanged; its signatures cannot be migrated into the new trust scope.

The existing [model-free runbook](../runbooks/mlx-model-free-preflight.md), CLI, worker, parent,
ledger and historical records are unchanged. Schema 1.0 remains permanently disabled; frozen
schema-1.1 fixtures do not approve the current worker. The 18 atlas cells remain unobserved,
with 0 accepted/promotable physical records.

## Exact binding and offline meaning

`authorization_request_spec()` loads the established, independently reviewed **static**
qualification/registry/target/wheel-manifest records. Their established review mechanism is
reused only within its existing static scope. It supplies no production authority identity.

The spec binds static qualifying record
`sha256:3d789caf4e65581265dc686aed30df0d4612388710b20a2dabc36e2d906711df`,
target anchor `sha256:008f7c3ac60614bc6909822180a4bc0b9be17eaf0aa3abc23829eb2842c4fdc0`,
the exact 34-distribution metadata/closure and 70,700,189-byte wheel manifest. The target stays
CPython 3.13.15/cp313/arm64/Darwin, macOS 27.0.1 build 26A434, MLX 0.30.4 and MLX-LM 0.30.6.
It never selects the development host as the target or retrieves wheels.

The source map content-binds the eight merged preflight modules. These identities are
**candidates, not runtime source approvals**. In particular:

- Worker source: `sha256:063f357df20b2b58be6b1b8b68c6321a33fdd15ba169e3c6173838524fee694a`.
- Worker protocol: `sha256:f7da6af4121dce3262230807f6faf73b83c1fd7d7bfe86ce98f9a634e6232881`.

`build_authorization_request(context, requested_validity)` accepts only the exact versioned
prospective context. `verify_authorization_request_structure(value)` returns a detached,
structure-only copy; `verify_authorization_request_bytes(data)` additionally requires canonical
JSON of at most 32,768 bytes, rejecting duplicate keys, floating-point values, unknown fields
and unsupported versions.

Required context fields bind:

- Exact candidate/source/policy identities, a proposed parent PID and process-instance digest,
  plus an optional **unverified** host-provenance reference.
- Three distinct proposed private `0700` objects: `custody`, `output`, `runtime_container`.
  A fourth, distinct `0555` execution object must be declared as the fixed `preflight-runtime`
  child of that container, on the same device and under the same owner. An exact tree identity
  is required. This validates a declaration, **not actual nesting, ownership or observation**.
- Exact interpreter bytes and distribution metadata identities, runtime manifest identity and
  fixed `mlx/core.cpython-313-darwin.so` / `mlx_lm/__init__.py` import-file identities.
  Fresh wheel verification, installation custody, standard-library, native-loader and framework
  closure references are digest-or-null. Null remains unavailable; a digest remains unauthenticated.
- Proposed monotonic start/deadline and a 32-byte nonce; a requested Unix validity interval.
  Exact integer types, bounded object/PID/time ranges, ordered intervals and equal wall/monotonic
  lifetimes are required. The whole requested interval, including any not-before delay, is at
  most 30 seconds.

The attempt identity hashes the full context, validity and current spec identity. Its digest is
the prospective hello challenge; the session hashes that challenge and the nonce. The hello
uses the **existing shared schema-1.2 worker validator**. Neither a caller-matching hello nor a
coherently rehashed context/manifest creates independent provenance, freshness or approval.
There are no paths, commands or caller-defined action lists. The pinned action policy permits
one fixed sequence: distribution checks, the two imports, default device, default stream,
Metal availability and synchronization. No retries, warmups or parallel worker attempts.

Context evidence scope is only `caller_supplied_unverified` or `synthetic_non_promotable`.
Invented fixtures must use the latter. Copying, forking, replaying or relabeling claims cannot
produce a grant: **every valid request still refuses preparation**. A malformed request raises
a contract error instead of producing a success-shaped readiness object.

## Explicit refusal, not readiness

`assess_authorization_request(request, claimed_clock=None)` reports only content binding and
unavailable prerequisites. An optional coherent caller clock can label the *claimed* interval
as not-yet-valid, within-window or expired. It never verifies trusted current time or acquires
a clock. `prepare_authorization_acquisition` raises for all such outcomes.

The refusal states that authority/freshness/native enforcement are unavailable, wheel bytes
were not reverified and a live ledger was not opened or consumed. Proposed action outcomes
are **unknown, not executed or observed**, not fabricated zero physical-action evidence.
Its zero counters cover only operations performed by this offline preparation. The refusal
contains request/attempt digests, not private roots, PID, challenge, nonce or exception details.
Canonical request/refusal identities establish integrity only, never authenticity.

## Required separately reviewed decisions and evidence

All requests carry the same immutable **unavailable** prerequisites:

- Production authority/approval policy, independently retained trust root, authority-material
  custody and trustworthy time/freshness custody. No local signer, cryptography, key ownership,
  clock trust or issuer is chosen. The coordinator/user must select the direction for a later
  reviewed implementation; that decision is not a real runtime grant.
- Separate explicit provisioning approval, fresh actual-byte wheel reverification and recorded
  installation custody. The prior 34 wheel artifacts were deleted; static replay proves no
  current wheel-byte custody. Provisioning approval must exclude runtime authorization.
- Exact installed environment, native-loader/framework closure and independently authenticated
  host/process/root measurements. Caller hashes or a copied receipt cannot satisfy these.
- Runtime review of the **new** schema-1.2 source/protocol, and independently reviewed exact-target
  OS enforcement with parent-observed child-executable identity. Enforcement must establish the
  relevant native network/process/filesystem boundary and forbidden model/cache/tensor effects.
  Python audit hooks and offline environment variables are not a native sandbox.
- Fresh explicit user approval for this exact single attempt, after provisioning and all reviews.
- A narrowly reviewed schema-1.2 **production ledger binding/dispatch adapter** and an independent
  physical evidence verifier. The production ledger opener and physical acceptance remain closed.

The parallel benign native-confinement probe's candidate contract is not imported here.
Its feasibility receipt may identify helper/profile/host/probe observations, but leaves the
MLX target, interpreter, runtime/native closure and Metal compatibility unbound/untested. It is
not an approval or production enforcement proof. Integration requires an exact independently
reviewed provenance contract binding implementation/policy, exact target/source/closure,
parent/root identities and truthful per-operation outcomes, including unresolved self-exec
and executable-replacement limitations.

The unchanged merged ledger supports only `consume_once` and `dispatch_synthetic_once`.
Future adaptation must preserve object/issuer/process/store/inode/attempt bindings, terminal
claim before validation, durable fsync before callback, no retry/refund and no authority from
copied journal data. Parent-only retirement does not revoke a raw synthetic token. Unavailable
binding/authorization/callback-consumption evidence stays unavailable; missing retained evidence
must raise. This prerequisite neither adapts that API nor mutates any ledger-owned source,
tests or documentation.
