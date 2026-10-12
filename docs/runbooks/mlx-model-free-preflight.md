# Model-free MLX preflight: offline request and future execution boundary

Schema 1.2 implements worker operations, parent socket/process acquisition, byte-safe rejection
retention, and offline JSON/Markdown reports. **Physical launch is closed.** This is not permission
to retrieve wheels, provision an environment, import MLX/MLX-LM, observe a host/device, synchronize,
create keys, approve runtime execution, or acquire atlas tensors.

Schema 1.0 stays permanently disabled. Its historical rejected frame remains unavailable; no new
record repairs or rewrites that history. The frozen schema-1.1 refusal fixtures remain unchanged.
The atlas study `sha256:231214ab37eea562b70a52639e3bbfd92b6d3cc56a42a026b670c43db8a45d33`
still has 18 static unobserved cells and **0 accepted/promotable physical records**.

## Safe offline inspection

```bash
localinferencelab mlx runtime-preflight-1-2-capability-report
localinferencelab mlx runtime-preflight-1-2-protocol
localinferencelab mlx runtime-preflight-1-2-request
# request prints a canonical pre-acquisition refusal and exits 2, not success

mkdir -m 700 .artifacts/preflight-1-2
localinferencelab mlx runtime-preflight-1-2-fixture-compile .artifacts/preflight-1-2
localinferencelab mlx runtime-preflight-1-2-evidence-replay \
  .artifacts/preflight-1-2/localinferencelab-mlx-preflight-synthetic-v1-2-*
localinferencelab mlx runtime-preflight-1-2-report \
  .artifacts/preflight-1-2/localinferencelab-mlx-preflight-synthetic-v1-2-* --format markdown
```

These commands never launch even an inert child. Fixtures contain invented identities, timestamps,
frames and observations. Reports are irreversibly `synthetic_non_promotable`. Coordinated rehashing,
caller labels, a consumption receipt, or a Boolean cannot turn them into accepted physical evidence.
The source is packaged but has no console entrypoint; module loading/help/discovery/compilation
imports no MLX. Even direct worker invocation independently refuses before socket/import operations.

## Two separate future human requests

Do not execute these templates. Fill them only after the outstanding implementation reviews.

**Provisioning-only request**

- Candidate: MLX **0.30.4**, MLX-LM **0.30.6**, exact reviewed **34-wheel /
  70,700,189-byte** closure, no replacements or resolver-selected additions.
- Static qualifying record:
  `sha256:3d789caf4e65581265dc686aed30df0d4612388710b20a2dabc36e2d906711df`.
  This grants eligibility to request observed authorization, not runtime permission.
- Target: exact CPython **3.13.15**, `cp313`, macOS arm64 interpreter/target anchor:
  `sha256:008f7c3ac60614bc6909822180a4bc0b9be17eaf0aa3abc23829eb2842c4fdc0`.
- State: wheel files were deleted. No installed, provisioned or observed MLX environment exists by
  implication of this record. Separately approve wheel retrieval/verification and installation.
- Required output: independently observed exact provisioned interpreter/distributions/byte closure,
  standard-library/native-loader/framework closure and separately pinned runtime/custody/output
  root objects. Package-root manifests alone do not close the native environment.
- Scope excluded: imports, device/Metal queries, synchronization, model/tokenizer/cache/tensor
  operations, inference, downloads beyond the separately approved package closure, and runtime
  authorization. Installation approval must not authorize runtime execution.

**One-attempt model-free runtime request**

- Bind the provisioned environment above, actual schema-1.2 protocol and new worker-source digest
  emitted by the capability report. The old reviewed worker-API evidence is source-surface evidence,
  **not approval for this new worker**.
- Require independently reviewed authority and fresh explicit human approval for this exact action,
  identities, root instances, nonce/challenge and at-most-30-second session. Do not create or
  simulate approval here. Independently trustworthy current time and host provenance are required.
- Require the separately committed/reviewed durable-consumption implementation. The journal
  establishes exclusive consumption only, not human authority, host provenance or trustworthy time.
- Fixed order: exact installed-distribution/metadata identities; `import mlx.core`; `import mlx_lm`;
  `default_device()`; `default_stream(device)`; `metal.is_available()`; `synchronize()`.
  Each operation has a parent command, worker start event and completed/failed event. No optional
  operation, arbitrary command/path, retry, warmup, concurrency, model/tokenizer/prompt/cache/tensor/
  inference/generation/benchmark action is allowed.
- Risk: imports themselves can initialize native state; reviewed MLX-LM imports can initialize a
  generation stream. A returned device/stream representation does not prove per-kernel Metal
  execution. An exception does not prove that no side effect completed.
- Expected outputs: private receipt-last bundle containing exact source/protocol and parent
  acquisition frames, JSON report and concise Markdown report; a durable consumed-attempt reference
  only after integration. Accepted physical status requires authentic independently verified parent
  custody plus real observations. That acceptance verifier is not integrated in this PR.
- Failure policy: preserve bounded raw bytes, wait/terminate the exact owned PID, close owned
  sockets/descriptors and remove transient snapshots. Preserve private retention journals even if
  final publication fails. **Never retry or refund consumption automatically.**

## Concrete blockers, not a sandbox claim

Production request refuses before roots, snapshots, sockets, process start, consumption or imports.
The low-level native spawn helper and worker each retain independent unconditional refusal gates.
The implemented source shows descriptor isolation, no inherited environment, isolated Python flags,
bounded CPU/file/core limits, fixed operations and privacy-checked observations; those controls are
not authorization and not a native sandbox.

Before removal of any gate, a separate reviewed OS boundary must deny network, child processes and
filesystem mutation while allowing only the exact verified Python/MLX dylibs and required Metal
framework access. Darwin child executable identity needs independent parent observation. Review
must also establish how native model/cache/tensor side effects are excluded: Python audit hooks,
offline environment variables and absence of calls in Python source cannot guarantee that native
imports avoid them. If these guarantees cannot be established for the exact provisioned closure,
**keep launch closed**, even after the durable ledger lands.

## Durable ledger integration contract

The separate ledger workstream owns `mlx_preflight_ledger.py`, its tests and its documentation.
This implementation neither imports its unmerged code nor creates another ledger.

Settled synthetic API: `consume_once(authorization, ParentBindings) -> SyntheticAttemptPermit`,
then `dispatch_synthetic_once(permit, ParentBindings, inert_callback)`. Permits are issuer/process/
store/inode/attempt-bound, single-dispatch and fork-rejected. They are never production capability.
Future reviewed schema-1.2 integration must independently validate authority/approval/time/host
before consumption, extend exact bindings to the new worker/protocol/interpreter/closure, three
parent-observed root objects and nonce/challenge/session, and bind parent-owned action/rejection/
terminal evidence to that consumed attempt. Audit JSON is not a permit. Physical dispatch and
offline authenticity verification remain blocked until that integration is reviewed.
Integration regressions must prove poisoned, foreign, copied, forked and reused ledger handles
cannot invoke the parent dispatch callback; an unmerged draft ledger is not integration approval.

## Retention and claim scope

Wire frames are at most 16,384 payload bytes; the parent stores at most 32 captures. Oversized
frames retain the four-byte header and at most 4,096 already available prefix bytes, without
draining the claimed length. Partial headers, malformed/non-UTF8/duplicate-key JSON, unexpected
fields/actions, EOF and deadline failures retain exact received bytes before validation returns.
Private events are fsynced before semantic validation; rejection annotations are separately
persisted. Public reports expose only digests, sizes, completeness and fixed failure codes,
never raw bytes, private paths, challenge values or exception text.

`attempted=true` means a valid start event was retained; completion is worker-reported, not native
side-effect proof. A sent command without a start event has unknown attempt status; a start without
a valid terminal event has unknown completion. Actions not requested are refused, not secretly
claimed attempted. Unread/unretained events and forbidden native effects remain unknown.
Replaying a bundle verifies retained evidence only and performs zero process/socket/MLX actions.

Parent command exposure is recorded separately from deadline/protocol acceptance. A command
delivered across a deadline remains rejected, but absence of an accepted start/terminal event leaves
attempt/completion unknown, never zero. Offline compilation validates owned child-wait types,
PID and lifetime bindings and coherent exit/signal state before projecting public evidence.
The same strict hello validator is used by worker, parent acquisition and offline compilation/replay.
