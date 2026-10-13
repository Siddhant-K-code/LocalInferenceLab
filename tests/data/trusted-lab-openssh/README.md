# Published non-secret, non-authority OpenSSH regression fixture

`published-test-key.pub` is OpenSSH portable's ED25519 test key #1, without its comment:
[pinned public fixture](https://github.com/openssh/openssh-portable/blob/773771be4ae241380e5f2b65059c441f7eef2da7/regress/unittests/sshkey/testdata/ed25519_1.pub).
Its matching **publicly published, non-secret regression private key** is in the same
OpenSSH testdata directory. No key pair was generated and no user's private key was accessed.
That private fixture is not included in this repository.

`signed-request.json` contains invented roots, process, source/environment declarations,
nonce and wall/monotonic timestamps. Its evidence scope is `synthetic_non_promotable`.
`signed-request.sig` is a precomputed OpenSSH SSHSIG over those exact complete bytes, using
namespace `localinferencelab-trusted-code-research-approval-v2`; the signed payload also pins
principal `localinferencelab-human`. `wrong-namespace.sig` signs the same bytes with namespace
`file`. These vectors were prepared once using standard `/usr/bin/ssh-keygen -Y sign` with the
published regression key, solely for non-authority tests. There is no signing helper in
default tests, package imports, verifier, discovery, help or replay.

The fixture key's SSH wire identity is
`sha256:2f793fa09b9b6e5498d2507d525b25ede98332744f2a6ffcb9d7f671cc24e7ad`.
This is a **non-authority denylist identity**, never a production anchor/default.
The adapter refuses its use for non-synthetic request claims, even with a coherently rehashed
payload/configuration. A valid synthetic signature cannot attest approval provenance,
enroll an operator, grant execution, consume a ledger or enable physical acceptance.
No public test-mode or skip switch exists. Instrumented clocks and temporary configurations
live only in the test harness; they are not promotable APIs or deployment examples.

Default/offline tests perform only bounded signature **verification** against temporary
private fixture copies. Fixed historical times are observed through test-only monkeypatching.
These fixture files must be updated if the full signed candidate source/spec/policy changes;
rehashed subsets cannot preserve the old signature.
The source-bound vectors were refreshed after independent review corrections to owned OS
child-status custody, object ancestry and bounded parsing. That unavoidable refresh used only
the same pinned published non-secret regression key, not a generated or user-controlled key.
The public-request recursive-validation correction likewise requires only a source-bound vector
refresh with that same fixture; it does not change the signed policy's trust scope or authority.
