"""Fail-closed backend identity probes and non-executable plans."""

from __future__ import annotations

import errno
import hashlib
import os
import stat
from pathlib import Path
from typing import cast

from localinferencelab.canonical import ContractError, JsonValue
from localinferencelab.contracts import Backend, RuntimeFact, RuntimeIdentity

BACKENDS = {"mlx-lm", "llama.cpp", "ollama"}


def validate_backend(value: str) -> Backend:
    """Validate a backend name."""
    if value not in BACKENDS:
        raise ContractError(f"backend must be one of: {', '.join(sorted(BACKENDS))}")
    return cast("Backend", value)


def backend_plan(backend: Backend) -> dict[str, JsonValue]:
    """Return a plan that cannot start a process, call an API, or pull a model."""
    action = {
        "mlx-lm": "Python generation call",
        "llama.cpp": "local executable invocation",
        "ollama": "local API request",
    }[backend]
    return {
        "record_type": "backend_plan",
        "schema_version": "1.0",
        "backend": backend,
        "prospective_action": action,
        "execution_implemented": False,
        "allowed_to_execute": False,
        "authorization_requirement": "exact content-addressed execution declaration",
        "automatic_runtime_start": False,
        "automatic_model_download": False,
        "network_access": False,
        "reason": "v1 exposes identity and planning surfaces only",
    }


def probe_runtime_artifact(
    backend: Backend,
    artifact: Path,
    *,
    version: str,
    commit: str | None,
) -> RuntimeIdentity:
    """Hash a preinstalled artifact without executing or mutating it."""
    path = artifact.absolute()
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise ContractError("runtime artifact must not be a symlink") from error
        raise
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ContractError("runtime artifact must be a regular file")
        digest_state = hashlib.sha256()
        while block := os.read(descriptor, 1024 * 1024):
            digest_state.update(block)
        digest = f"sha256:{digest_state.hexdigest()}"
    finally:
        os.close(descriptor)
    record = RuntimeIdentity(
        "runtime_identity",
        "1.0",
        backend,
        "static_artifact_probe",
        path.name,
        None,
        version,
        commit,
        digest,
        None,
        (
            RuntimeFact("runner", "unobserved"),
            RuntimeFact("metal", "unobserved"),
        ),
        False,
    )
    return RuntimeIdentity.from_dict(record.to_dict())
