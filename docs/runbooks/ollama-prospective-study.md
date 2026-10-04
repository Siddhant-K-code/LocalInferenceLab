# Prospective Ollama study preparation

This runbook prepares records. Do not create authorization artifacts until an independent review
confirms the exact study and source evidence. Repository validation uses only the final synthetic
fixture command shown at the end.

## 1. Establish preinstalled identities

Prepare, without running Ollama:

- a privacy-reviewed `host_identity` from `localinferencelab host probe`;
- a complete observed `runtime_identity` whose executable digest matches the supplied preinstalled
  Ollama binary and whose selected runner/Metal/build facts come from reviewed evidence;
- the raw local manifest and its existing `blobs/sha256-*` config/layer files;
- a complete observed `model_identity` matching the manifest bytes, config blob digest, and
  canonical ordered closure produced by package construction.

Do not use a tag as model identity. Do not pull, copy, create, delete, or otherwise mutate a model.
Reject configs with remote model metadata.

## 2. Bind the output root

Create a private, existing, non-symlink directory and initialize it once:

```bash
localinferencelab ollama output-root-init ./ollama-output --nonce STUDY-ROOT-NONCE
```

Record the returned `output_root_id` in the canonical study specification. Paths are never written
into package or evidence records.

## 3. Construct and verify the prospective package

The canonical specification must explicitly provide every field documented in the
[runner contract](../ollama-runner-contract.md), including:

- `http`, numeric loopback host, exact port, and fixed API paths;
- request name ending in `:local`; the local canonical/response name is derived mechanically;
- prompt bytes/digest, `raw_mode=true`, template digest, explicit `think_mode`;
- all sampler millionths, context/output limits, `keep_alive_seconds=0`;
- `cold_model_warm_process`, mechanical cache evidence digest, expected `/api/show` projection;
- exact output-root identity, timeout, response bounds, and `authorized` or forbidden disposition;
- three distinct prospective authorization nonce commitments.

Create the owner-only nonce files before freezing the package, and copy only each printed
`nonce_sha256` into the matching `authorization_nonce_sha256` field:

```bash
localinferencelab ollama authorization-nonce-init preflight.nonce
localinferencelab ollama authorization-nonce-init identity.nonce
localinferencelab ollama authorization-nonce-init generation.nonce
```

Keep the nonce files out of source control. Their raw bytes are not package content and must not be
placed on a command line. The later one-shot authorization artifact intentionally carries the
preimage as proof of possession; it also stays out of source control and becomes safe to disclose
inside terminal evidence only after its exact output-root consumption marker is durable.

Create and re-verify without socket or model action:

```bash
localinferencelab ollama prospective-create study-spec.json prospective.json \
  --runtime-artifact /path/to/preinstalled/ollama \
  --model-manifest /path/to/local/manifest \
  --blob-root /path/to/local/blobs

localinferencelab ollama prospective-verify prospective.json
```

The command hashes local files only. A collision fails; it never replaces a package.

## 4. Optional read-only preflight

After review, create a one-shot artifact dedicated to four metadata calls:

```bash
localinferencelab ollama authorize prospective.json preflight_only preflight-auth.json \
  --nonce-file preflight.nonce
```

The following is the first command in this runbook that can open a socket. It permits only
`/api/version`, `/api/tags`, `/api/show`, and `/api/ps`; it cannot call generate/chat or start
Ollama:

```bash
localinferencelab ollama preflight prospective.json preflight-auth.json ./ollama-output \
  --runtime-artifact /path/to/preinstalled/ollama \
  --model-manifest /path/to/local/manifest \
  --blob-root /path/to/local/blobs
```

Review and offline-verify the resulting receipt-closed preflight bundle before proceeding:

```bash
localinferencelab ollama evidence-replay ./ollama-output/PREFLIGHT_BUNDLE
```

## 5. Prepare the two execution artifacts

Use distinct nonces and files:

```bash
localinferencelab ollama authorize prospective.json identity_guard identity-auth.json \
  --nonce-file identity.nonce
localinferencelab ollama authorize prospective.json generation generation-auth.json \
  --nonce-file generation.nonce
```

Do not place either artifact in source control. They are authorization, not configuration. A failed
or interrupted authorized phase remains consumed and must not be selectively rerun.

## 6. Execution gate

The command surface is present, but production generation intentionally refuses before consuming
either authorization or opening a socket. Ollama's public API cannot mechanically bind the
declared runtime, selected runner, and Metal state to the process that owns the loopback listener.
Do not attempt a real model run until a reviewed listener/runner attestor replaces this gate.

After that future gate is implemented and only after package, source, privacy, cache, and threat
review, the frozen command shape is:

```bash
localinferencelab ollama execute prospective.json identity-auth.json generation-auth.json \
  ./ollama-output \
  --runtime-artifact /path/to/preinstalled/ollama \
  --model-manifest /path/to/local/manifest \
  --blob-root /path/to/local/blobs
```

Today this command returns the attestation refusal without a socket or model action. There is no
generic environment-variable or network flag alternative. Missing, swapped, stale, or mismatched
artifacts also refuse before consumption markers or sockets. The runner does not auto-start Ollama
and performs no download or model mutation.

Replay a terminal bundle offline:

```bash
localinferencelab ollama evidence-replay ./ollama-output/BUNDLE
```

## 7. Repository-only synthetic validation

This command is always safe for CI and development. It uses no socket and no model:

```bash
localinferencelab ollama fixture-compile .artifacts
for bundle in .artifacts/localinferencelab-ollama-*-synthetic-v1-*; do
  localinferencelab ollama evidence-replay "$bundle"
done
```

The generated fake durations are schema fixtures only and must never be reported as performance.
