# Durable one-shot preflight consumption

`localinferencelab.mlx_preflight_ledger` implements actual private filesystem
storage, not another prospective contract or a process-local duplicate set.
Its only issuer and dispatch surface are explicitly **synthetic and
non-promotable**. `open_production_ledger()` unconditionally refuses. There is
no real authority/key enrollment, authorization creation/consumption, worker
launch, runtime provisioning, MLX import, or physical observation in this
change.

Storage proves an exclusive durable state transition within the stated local
filesystem assumptions. It does **not** establish human authority, independent
review, current-time trust, host provenance, interpreter bytes, or permission
to run. Static eligibility, caller hashes, freshness labels, and replayed
consumption records are never launch capabilities.

## Parent API

The worker/acquisition/report implementation is a separate change. This module
does not import it, alter its historical source bytes, or depend on an unmerged
branch. The deliberately small integration surface is:

```python
root_ids = synthetic_root_ids(root_descriptors)
bindings = synthetic_parent_bindings(
    fixture_authorization,
    session_id=synthetic_session_id,
    interpreter_sha256=synthetic_interpreter_digest,
    root_descriptors=root_descriptors,
)
issuer = SyntheticLedgerIssuer(fixture_authorization, synthetic_clock)
anchor = issuer.initialize(custody_descriptor, bindings, root_descriptors)
ledger = issuer.open(custody_descriptor, anchor, bindings, root_descriptors)
permit = ledger.consume_once(fixture_authorization, bindings)
ledger.dispatch_synthetic_once(permit, bindings, inert_parent_callback)
```

This illustrates an inert test, not a production launch recipe. The roots are
three already-open distinct private descriptors, in custody/output/runtime
order. Their synthetic IDs derive from observed device/inode/owner/mode and
role; the fixture authorization must already bind exactly those IDs.
`ParentBindings` is frozen and holds the exact canonical schema-1.1
authorization bytes, session ID, synthetic interpreter digest, and observed
root pins. The authorization includes all existing authority/review,
qualification, candidate, target, registry, worker, actions, nonce/challenge,
root, issuance, not-before, and expiry bindings. The allowlist must be exact
and nonempty. Unknown fields, downgrades, and ignored fields are rejected.

`LedgerAnchor` retains the parent/root/journal/initialization-marker object
pins and exact initial header bytes **outside** the journal. On restart a
parent must retain those original pins; reopening never learns a replacement
identity from the on-disk file. These pins are private bookkeeping, **not**
authority or an independently protected anti-rollback service.

The module enrolls only the existing synthetic authority/review/worker
identities. Even relabeling a fixture as externally reviewed is refused.
`SyntheticClock` is an explicit fake wall/monotonic pair, not an injectable
production clock. Consumption and dispatch separately check expiry and reject
backward movement or differing elapsed wall/monotonic time. Enrollment and
inspection can examine expired fixtures without making them consumable.
There is no production clock decision in this PR.

## On-disk state and ordering

One authorization has one derived name beneath its exact bound custody root:

```text
custody/
  authorization-<authorization-hash>.initialized   # private creation tombstone
  authorization-<authorization-hash>/
    authorization.journal
```

The initialization marker is created with exclusive no-replace semantics,
written and fsynced, then its parent directory is fsynced **before** journal
creation. Initialization then exclusively creates the directory/file, writes
the canonical header, and fsyncs the journal, its directory, and the custody
directory. No anchor is returned until all steps succeed. An interrupted
initialization leaves retained unusable state; there is no cleanup/recovery
that quietly makes it unused again. The marker prevents normal reinitialization
even if the entire journal directory is removed.

The bounded journal initially contains only a canonical header and newline.
Consumption opens the exact pinned inode, takes an exclusive `flock`, verifies
the closed directory and complete state, checks all exact bindings and the
synthetic clock, then appends:

```text
!<canonical durable-consumption record>\n
```

It fsyncs that inode and rereads/verifies the complete transition before
returning a permit. No callback occurs before durable consumption. The
append-only suffix contains the original schema-1.1 audit consumption record,
the exact parent-binding/header identities, and its synthetic clock pair.
Journal schema `1.0` is a **new ledger record type**, not the permanently
disabled runtime-preflight schema 1.0.

An intent marker with a missing/partial/invalid suffix is permanently
unusable. A complete valid suffix is consumed. A second process/invocation
refuses either `already consumed` or `busy`; locks are nonblocking, with no
hidden retry loop. Exactly one cooperating contender can commit and receive
a permit. A live parent also detects observed size rollback.

Write/short-write/fsync failures return no permit and poison the live handle.
On reopening, a complete suffix remains consumed and a partial suffix refuses;
there is no refund, reset, truncation repair, or retry after launch intent.
A process crash after fsync, after permit issuance, during callback, after
failed launch, on timeout, or on rejected-frame handling cannot undo
consumption. A crash **before any intent bytes** leaves the authorization
unconsumed and could not have dispatched anything.

## Permit origin and one dispatch

`SyntheticAttemptPermit` cannot be constructed normally or serialized. A
ledger retains its issued token by object identity, with the exact durable
record. Dispatch verifies the issuing ledger/issuer process, store pins,
authorization, session, interpreter digest, roots, and latest synthetic
expiry. Tokens inherited through `fork`, deserialized/lookalike objects,
booleans, caller receipts, or a token supplied to a reopened/foreign ledger
refuse. Threads serialize origin checking and token retirement; one token
can dispatch exactly once. The token is retired **before** a callback, even
when the callback fails. Restart never remints a token for a consumed record.

The callback receives audit JSON, not authority. `inspect()` only reads audit
state and never consumes or issues a token. Existing public verification and
offline replay remain non-consuming.

Python object-origin checking is an application invariant inside a trusted
parent, not a security boundary against hostile code in that process. An
inert callback is test code under the parent's control; this API does not
enforce what an arbitrary Python callback does. A synthetic permit must
**never** be accepted by a future production launcher.

## Filesystem guarantees and honest limitations

The implementation requires a POSIX local filesystem supporting advisory
`flock`, descriptor-relative no-follow opens, and file/directory `fsync`.
It requires effective-user ownership, exact `0700` directories, exact `0600`
regular files, and a single journal/marker hard link. Opens are close-on-exec
and nonblocking; paths are fixed single components under caller-pinned
descriptors, never worker-provided paths. Reads are bounded to 64 KiB; the
journal-directory scan examines at most two entries. Root/file/marker pins
and namespace entries are rechecked around the locked operation. Missing,
copied/replaced, symlinked, hardlinked, corrupt, truncated, or unexpected state
fails closed; it is not automatically recreated.

Other OS users without access to the private parent directories cannot use
the ordinary APIs to substitute state. Advisory locks coordinate cooperating
parents; they do not stop arbitrary writes by a same-user attacker.
**Same-user/root attackers, hostile Python in the parent, descriptor theft,
and power/storage systems that lie about fsync are not excluded.** An attacker
able to rewrite an old valid unused snapshot into the same inode and roll back
all local markers/retained pins can defeat local nonreuse across a restart.
Inode reuse and full filesystem/VM snapshot rollback likewise require an
independently protected external anchor to exclude. None is implemented here.
Detection of replaced objects or live-handle truncation is not a claim of
general rollback protection. The tests exercise process crashes and injected
I/O failures, not physical power-loss behavior or all filesystem types.

Production needs separately committed and independently reviewed authority
material, explicit fresh human approval, a trustworthy current-time/host
decision, exact reviewed new protocol/worker/interpreter/runtime bindings,
and a protected state/anti-rollback policy before any real consumption or
launch. Native no-network and forbidden-action enforcement remain separate
closed prerequisites. A Python audit hook is not a native sandbox.

## Preserved evidence and exercised boundaries

All committed candidate, qualification, target, registry, manifest, worker,
historical failure, and deterministic fixture bytes remain unchanged. The
qualification remains
`sha256:3d789caf4e65581265dc686aed30df0d4612388710b20a2dabc36e2d906711df`,
for MLX 0.30.4 / MLX-LM 0.30.6, exact CPython 3.13.15 arm64. Eligibility grants
no permission. The physical atlas remains an inert 18-cell study; the legacy
canary remains 48 prospective / 8 synthetic / 0 physical.

Tests use synthetic fixtures, ordinary filesystem primitives and independent
inert Python processes. They cover multi-process competing consumption,
restart, crash boundaries, initialization/fsync/partial-write failures,
missing/replaced/corrupt state, path races, permissions/hardlinks/symlinks/FIFO,
expiry/clock/binding drift, unknown fields, zero actions, fork/forgery/concurrent
token reuse, failed callback nonrefund, and historical deterministic replay.
They do not retrieve, install, import, query, synchronize, or run MLX.
