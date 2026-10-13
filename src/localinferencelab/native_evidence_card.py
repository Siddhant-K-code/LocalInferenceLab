"""Publish only the two pinned historical native receipts, entirely offline."""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from html import escape
from pathlib import Path
from typing import cast

from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    digest_bytes,
)
from localinferencelab.native_confinement import _read_regular
from localinferencelab.native_confinement_after_startup import replay_bytes as replay_diagnostic
from localinferencelab.native_confinement_contract import (
    COMMAND_TIMEOUT_NS,
    MAX_REPORT_BYTES,
    parse_capture,
    replay_bytes,
    syscall_observation,
)

SOURCE_COMMIT = "2accb11d14a56222e36c8b61957ce56031ff04f7"
SOURCE_ROOT = f"https://github.com/Siddhant-K-code/LocalInferenceLab/blob/{SOURCE_COMMIT}"
PRE_EXEC_FILENAME = "native-confinement-darwin-27.0.0-arm64-v1.json"
AFTER_STARTUP_FILENAME = "native-confinement-after-startup-darwin-27.0.0-arm64-v1.json"
PRE_EXEC_SHA256 = "sha256:0411c37c5e9f61e91fabb5ff4deb15e650f43e44200bff1f2095297d91ea421b"
AFTER_STARTUP_SHA256 = "sha256:de79bce056b671c87e4d8c199de1440380e0465ccdf5350338e0ed43b72bb4c0"
PRE_EXEC_ID = "sha256:94c12b835ac785f86a3b166837b67a5f7cf5a8457ce4ad4aa34f62afc7f873da"
AFTER_STARTUP_ID = "sha256:be031b62bc65c7fe68e937e78a85f288d9ea871003aec3c4ce4a802ce0f29312"
INNER_ID = "sha256:c308e83165b662d98d6d471e5d9d2640b3a3b68db6719855a06a1a96389af892"
_SIGABRT_RETURN_CODE = -6
_LABELS = {
    "enforced": "matched",
    "refused": "unmet",
    "unknown": "unknown",
    "untested": "untested",
    "unavailable": "unavailable",
}
_CHECKS = {
    "read_allowed": "Allowed read",
    "write_allowed": "Allowed write",
    "read_denied": "Outside-list read",
    "write_denied": "Outside-list write",
    "read_prefix_sibling": "Prefix-sibling read",
    "read_symlink": "Symlink read",
    "write_symlink": "Symlink write",
    "socket_loopback": "Socket creation",
    "connect_loopback": "Loopback connection",
    "fork": "Fork",
    "exec_other": "Other executable",
    "exec_self": "Self-exec",
    "descriptors": "Descriptor hygiene",
    "environment": "Environment hygiene",
    "read_replacement": "Replacement read",
}
_ALT = (
    "After-startup C/libc helper, not an MLX benchmark: {headline}. "
    "The same allowed path reads a new object; socket creation succeeds. "
    "Pre-exec calibration is unknown with {untested} later checks untested. "
    "Startup confinement is unproven, the runtime gate is ungranted, "
    "and MLX determinism is NOT MEASURED."
)
_DETAILS_URL = f"{SOURCE_ROOT}/docs/native-confinement-feasibility.md"


def _mapping(value: JsonValue) -> dict[str, JsonValue]:
    return cast("dict[str, JsonValue]", value)


def _rows(section: dict[str, JsonValue]) -> list[dict[str, JsonValue]]:
    return cast("list[dict[str, JsonValue]]", section["observations"])


def _result(value: JsonValue, operation: str) -> dict[str, JsonValue]:
    capture = parse_capture(value, COMMAND_TIMEOUT_NS)
    native = syscall_observation(capture, operation)
    return {
        "terminal": capture.terminal,
        "returncode": capture.returncode,
        "native_result": native,
    }


def _section(report: dict[str, JsonValue]) -> dict[str, JsonValue]:
    rows: list[JsonValue] = []
    for row in cast("list[dict[str, JsonValue]]", report["observations"]):
        operation = cast("str", row["operation"])
        rows.append(
            {
                "operation": operation,
                "expectation": row["expectation"],
                "disposition": row["disposition"],
                "assessment": _LABELS[cast("str", row["disposition"])],
                "baseline": _result(row["baseline"], operation),
                "candidate": _result(row["candidate"], operation),
            }
        )
    counts = Counter(_mapping(row)["assessment"] for row in rows)
    return {
        "aggregate_disposition": report["disposition"],
        "reason": report["reason"],
        "counts": {label: counts[label] for label in _LABELS.values()},
        "observations": rows,
    }


def build_card(pre_exec_bytes: bytes, after_startup_bytes: bytes) -> dict[str, JsonValue]:
    """Revalidate exact receipts; caller-rehashed or reformatted inputs cannot publish."""
    if digest_bytes(pre_exec_bytes) != PRE_EXEC_SHA256:
        raise ContractError("published pre-exec bytes do not match the pinned receipt")
    if digest_bytes(after_startup_bytes) != AFTER_STARTUP_SHA256:
        raise ContractError("published after-startup bytes do not match the pinned receipt")
    pre_exec = replay_bytes(pre_exec_bytes)
    envelope = replay_diagnostic(after_startup_bytes)
    after_startup = _mapping(envelope["test_record"])
    if (
        pre_exec["record_id"] != PRE_EXEC_ID
        or envelope["record_id"] != AFTER_STARTUP_ID
        or after_startup["record_id"] != INNER_ID
    ):
        raise ContractError("published native record identities do not match")
    sources: dict[str, JsonValue] = {}
    for name, filename, raw_digest, report, identity in (
        ("pre_exec", PRE_EXEC_FILENAME, PRE_EXEC_SHA256, pre_exec, PRE_EXEC_ID),
        (
            "after_startup",
            AFTER_STARTUP_FILENAME,
            AFTER_STARTUP_SHA256,
            after_startup,
            AFTER_STARTUP_ID,
        ),
    ):
        sources[name] = {
            "url": f"{SOURCE_ROOT}/docs/evidence/{filename}",
            "raw_sha256": raw_digest,
            "record_id": identity,
            "observation_record_id": report["record_id"],
            "historical_acquired_implementation_id": _mapping(report["identities"])[
                "implementation_id"
            ],
        }
    fixture = _mapping(after_startup["fixture"])
    initial, replacement = _mapping(fixture["read_initial"]), _mapping(fixture["read_replacement"])
    host = _mapping(after_startup["host"])
    card: dict[str, JsonValue] = {
        "record_type": "native_evidence_card",
        "schema_version": "1.0",
        "source_commit": SOURCE_COMMIT,
        "sources": sources,
        "scope": {
            "helper": "C/libc with controlled synthetic fixture inputs",
            "host": {field: host[field] for field in ("system", "release", "machine")},
            "application_stage": envelope["application_stage"],
            "startup_confinement_proven": envelope["startup_confinement_proven"],
            "runtime_authority": after_startup["runtime_authority"],
            "physical_launch_approved": after_startup["physical_launch_approved"],
            "production_bindings": after_startup["production_bindings"],
            "mlx_determinism": "not_measured",
            "model_latency_cost_gpu_performance": "not_measured",
            "offline_replay_authenticates_os_acquisition": False,
        },
        "pre_exec": _section(pre_exec),
        "after_startup": _section(after_startup),
        "replacement_object_changed": (initial["device"], initial["inode"])
        != (replacement["device"], replacement["inode"]),
        "limitations": after_startup["untested"],
        "historical_current_source_disclosure_url": _DETAILS_URL,
    }
    card["card_id"] = canonical_identity(card)
    return card


def _count(card: dict[str, JsonValue], stage: str, state: str) -> int:
    return cast("int", _mapping(_mapping(card[stage])["counts"])[state])


def _headline(card: dict[str, JsonValue]) -> str:
    return " / ".join(
        f"{_count(card, 'after_startup', state)} {state}"
        for state in ("matched", "unmet", "unknown")
    )


def _native_text(result: dict[str, JsonValue]) -> str:
    native = result["native_result"]
    if native is None:
        if result["terminal"] == "not_run":
            return "Not launched"
        if result["returncode"] == _SIGABRT_RETURN_CODE:
            return "SIGABRT; no result"
        return f"{result['terminal']}; no accepted result"
    item = _mapping(native)
    if item["ok"] is True:
        if cast("str", item["operation"]).startswith("read_"):
            return f"Succeeded; byte {chr(cast('int', item['detail']))}"
        return "Succeeded"
    return (
        f"Denied (errno {item['errno']}, EPERM)"
        if item["errno"] == 1
        else (f"Failed (errno {item['errno']})")
    )


def _row(card: dict[str, JsonValue], operation: str) -> dict[str, JsonValue]:
    return next(
        row for row in _rows(_mapping(card["after_startup"])) if row["operation"] == operation
    )


def _table(card: dict[str, JsonValue], stage: str) -> str:
    heading = "| Check (required) | Candidate result |\n|---|---|\n"
    lines = []
    for row in _rows(_mapping(card[stage])):
        operation = cast("str", row["operation"])
        lines.append(
            f"| {_CHECKS[operation]} ({row['expectation']}) | "
            f"**{str(row['assessment']).upper()}**<br>"
            f"{_native_text(_mapping(row['candidate']))} |"
        )
    return heading + "\n".join(lines)


def _picture(card: dict[str, JsonValue]) -> str:
    alt = escape(
        _ALT.format(
            headline=_headline(card),
            untested=_count(card, "pre_exec", "untested"),
        ),
        quote=True,
    )
    return (
        "<picture>\n"
        '  <source media="(max-width: 1279px)" '
        'srcset="native-evidence-card-mobile.svg" width="600">\n'
        f'  <img src="native-evidence-card.svg" width="1200" alt="{alt}">\n'
        "</picture>"
    )


def _command() -> str:
    return (
        "```bash\n"
        "# From the repository root, with Python 3.12+; no install or MLX needed.\n"
        "PYTHONPATH=src python3 -m localinferencelab.native_evidence_card \\\n"
        f"  --pre-exec docs/evidence/{PRE_EXEC_FILENAME} \\\n"
        f"  --after-startup docs/evidence/{AFTER_STARTUP_FILENAME} \\\n"
        "  --output-dir /tmp/localinferencelab-native-card\n"
        "```"
    )


def _reproduction() -> str:
    return f"""## Reproduce the publication, not the OS experiment

{_command()}

Use a fresh output directory; existing output filenames are refused, never overwritten.
The same command with an installed wheel needs no `PYTHONPATH`: use
`python -m localinferencelab.native_evidence_card` and provide explicit paths to the
two original receipts from the [pinned source tree]({SOURCE_ROOT}).
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
"""


def _markdown(card: dict[str, JsonValue]) -> str:
    pre_unknown = _count(card, "pre_exec", "unknown")
    pre_untested = _count(card, "pre_exec", "untested")
    return f"""# Native Evidence Card: a path is not a pin

**{_headline(card)}. AFTER-STARTUP NATIVE HELPER, NOT AN MLX BENCHMARK.**

{_picture(card)}

Controlled synthetic files supplied inputs to actual retained C/libc native outcomes.
These are historical Darwin 27.0.0 arm64 observations, not newly acquired measurements.
Matching expectations include allowed reads/writes and parent hygiene, not just denials.
The same policy was applied after helper startup; startup confinement remains unproven.

**MLX determinism: NOT MEASURED. Runtime authority: false. Physical approval: false.
Production bindings: null.** No latency, cost savings, GPU, model, or MLX enforcement claim.

## Complete after-startup results

All unconfined baseline controls succeeded. The aggregate remains
`{_mapping(card["after_startup"])["aggregate_disposition"]}`.
Descriptor hygiene covers 3..255; supplied stdin/stdout/stderr are not absent.
Environment/descriptor hygiene is not inherited-resource revocation.

{_table(card, "after_startup")}

Connection denial is not socket-creation denial. Reading replacement byte B from a changed
fixture inode is not object pinning, concurrent race exclusion, or executable lifetime custody.
Self-exec's signal is UNKNOWN, never a proven denial.

## Separate pre-exec calibration

**{pre_unknown} unknown / {pre_untested} untested.** The allowed-read control succeeded;
the candidate aborted without output. The remaining checks were never launched.
This is not proof that macOS cannot enforce controls and not proof of startup confinement.

{_table(card, "pre_exec")}

## Scope and provenance

[Pre-exec receipt]({SOURCE_ROOT}/docs/evidence/{PRE_EXEC_FILENAME}) ·
[After-startup receipt]({SOURCE_ROOT}/docs/evidence/{AFTER_STARTUP_FILENAME}) ·
[Historical versus corrected-source disclosure]({_DETAILS_URL}) ·
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

{_reproduction()}"""


def _posts(card: dict[str, JsonValue]) -> list[str]:
    return [
        "A path is not a pin. My after-startup macOS C/libc probe read byte B from a new "
        "inode at the same allowed pathname. Not an MLX determinism result.",
        f"Actual native-helper results: {_headline(card)}. Matched includes allowed "
        "actions and hygiene, not just denials. After-startup policy, not startup confinement "
        "or an MLX benchmark.",
        "Blocked connect() is not blocked socket(). My retained after-startup helper created "
        "a socket but could not connect to loopback. Test the exact action, not a proxy.",
        f"Pre-exec: allowed-read control worked; candidate aborted with no result. "
        f"{_count(card, 'pre_exec', 'untested')} later checks untested. Not proof macOS cannot "
        "enforce controls. MLX runtime permission stays absent.",
        "Reuse two pinned public receipts: deterministic JSON, Markdown and SVG with "
        "standard-library Python. No new probe or MLX. Offline replay checks integrity, "
        "not authenticity of the original OS acquisition.",
    ]


def _article(card: dict[str, JsonValue]) -> str:
    replacement = _row(card, "read_replacement")
    before = _mapping(_row(card, "read_allowed")["candidate"])["native_result"]
    after = _mapping(replacement["candidate"])["native_result"]
    byte_a, byte_b = (
        chr(cast("int", _mapping(before)["detail"])),
        chr(cast("int", _mapping(after)["detail"])),
    )
    return (
        f"""# A path is not a pin: what my macOS probe actually measured

**{_headline(card)}. After-startup native helper, not an MLX benchmark.**

{_picture(card)}

Before measuring local AI determinism, I tested a narrow macOS policy.
An allowed filename stayed the same while its underlying object changed.

## ELI5: the address stayed; the parcel changed

Imagine a guard checking a locker address, not the parcel inside. Replace the parcel:
the address still matches.

The initial allowed read returned byte **{byte_a}**.
The parent atomically replaced that owned fixture pathname with a different inode containing
byte **{byte_b}**. Under the unchanged path policy, the native helper read **{byte_b}**.
An inode identifies an object; observing it does not enforce a pin.

This is not a hostile-parent attack or race test. "Allow this path" and "read these exact bytes
for the entire process lifetime" differ; other pathname policies may behave differently.

## What actually ran

A hand-written C/libc helper exercised owned files, loopback sockets, fork/exec and hygiene
on Darwin 27.0.0 arm64. **Synthetic fixture** means deliberately chosen input bytes and paths.
**Retained native outcome** means actual helper results and parent-observed failures,
not invented success fixtures.

The pre-exec deny-default Seatbelt candidate aborted without output; its allowed-read control
succeeded. That left
**{_count(card, "pre_exec", "unknown")} unknown calibration and
{_count(card, "pre_exec", "untested")} later checks untested**. It is not proof that macOS
cannot enforce controls.

A separate diagnostic applied the same profile after helper startup, adding no grants.
It measures an already-running helper, not startup confinement or actual MLX enforcement.

## Every after-startup result

All baseline controls succeeded. "Matched" includes intended allowances, not just denied
actions. The aggregate remains `{_mapping(card["after_startup"])["aggregate_disposition"]}`.

{_table(card, "after_startup")}

**Socket creation succeeded; loopback connection was denied.** `connect()` is not `socket()`.
Self-exec's SIGABRT leaves effects unknown, not proven denied.
Descriptor hygiene covered 3..255, not supplied standard streams.
Empty environment/closed extra descriptors are parent hygiene, not resource revocation.

## What you can reuse now

Reuse this requirements checklist: paths versus objects, acquisition versus connection,
completed denials versus crashes. Keep the negative and unknown rows.

The exporter checks pinned bytes/identities, reuses canonical/native validators, and derives
counts/tables/visuals together. Caller-rehashed mutations cannot publish.
Regenerate without MLX:

{_command()}

Fresh-directory outputs: `native-evidence-card.json`, `native-evidence-card.md`,
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

[Pre-exec receipt]({SOURCE_ROOT}/docs/evidence/{PRE_EXEC_FILENAME}) and
[after-startup receipt]({SOURCE_ROOT}/docs/evidence/{AFTER_STARTUP_FILENAME}) retain full
identities.
The [disclosure]({_DETAILS_URL}) distinguishes historical acquired producers from current
corrected offline-derived sources: unchanged receipts, no reacquisition.
Host observations do not amend the frozen runtime target. No permission is added.

## Ready-to-share X drafts

Copy each draft without its numbering. No post has been sent.

"""
        + "\n\n".join(f"{index}. {post}" for index, post in enumerate(_posts(card), 1))
        + "\n"
    )


def _svg(card: dict[str, JsonValue], *, mobile: bool) -> str:
    headline = escape(_headline(card))
    matched = _count(card, "after_startup", "matched")
    unmet = _count(card, "after_startup", "unmet")
    unknown_count = _count(card, "after_startup", "unknown")
    untested = _count(card, "pre_exec", "untested")
    allowed = _mapping(_row(card, "read_allowed")["candidate"])["native_result"]
    replaced = _mapping(_row(card, "read_replacement")["candidate"])["native_result"]
    byte_a = chr(cast("int", _mapping(allowed)["detail"]))
    byte_b = chr(cast("int", _mapping(replaced)["detail"]))
    socket_status = str(_row(card, "socket_loopback")["assessment"]).upper()
    replacement_status = str(_row(card, "read_replacement")["assessment"]).upper()
    unknown = str(_row(card, "exec_self")["assessment"]).upper()
    description = escape(_ALT.format(headline=_headline(card), untested=untested))
    width, height = (600, 1560) if mobile else (1200, 900)
    opening = f"""<svg xmlns="http://www.w3.org/2000/svg" role="img"
     aria-labelledby="title desc" viewBox="0 0 {width} {height}">
  <title id="title">A path is not a pin: retained native evidence</title>
  <desc id="desc">{description}</desc>
  <!-- Read-mode extension of the incumbent dark research diagrams.
       One stable path, two objects; observed effects precede scope limits.
       No startup, MLX, authority or numerical-performance claim. -->
  <rect width="{width}" height="{height}" fill="#07111f"/>
  <g font-family="system-ui, -apple-system, Segoe UI, sans-serif">
"""
    if mobile:
        body = f"""    <text x="32" y="65" fill="#f8fbff"
          font-size="46" font-weight="700">A path is not a pin.</text>
    <text x="32" y="120" fill="#c2cee3" font-size="32">Actual outcomes. Controlled fixtures.</text>
    <text x="32" y="185" fill="#8cf4ff"
          font-size="50" font-weight="700">{matched} matched</text>
    <text x="32" y="245" fill="#ffd477"
          font-size="50" font-weight="700">{unmet} unmet / {unknown_count} unknown</text>
    <path d="M32 272H568" stroke="#263754" stroke-width="2"/>
    <text x="32" y="317" fill="#f8fbff"
          font-size="32" font-weight="700">AFTER-STARTUP NATIVE HELPER</text>
    <text x="32" y="362" fill="#ffd477" font-size="38" font-weight="700">NOT AN MLX BENCHMARK</text>
    <text x="32" y="406" fill="#c2cee3" font-size="32">C/libc on Darwin 27.0.0 arm64</text>
    <rect x="32" y="438" width="536" height="80" rx="12"
          fill="#12233b" stroke="#6ee7f5" stroke-width="2"/>
    <text x="300" y="488" text-anchor="middle" fill="#f8fbff"
          font-size="36" font-weight="700">One unchanged allowed path</text>
    <path d="M164 518V558M436 518V558" stroke="#6ee7f5" stroke-width="3"/>
    <path d="M76 560H252V710H76Z" fill="#12233b" stroke="#6ee7f5"
          stroke-width="3" stroke-dasharray="8 6"/>
    <path d="M348 560H524V710H348Z" fill="#113c49" stroke="#6ee7f5" stroke-width="3"/>
    <text x="164" y="610" text-anchor="middle" fill="#c2cee3" font-size="32">Old inode</text>
    <text x="164" y="678" text-anchor="middle" fill="#f8fbff"
          font-size="64" font-weight="700">{byte_a}</text>
    <text x="436" y="610" text-anchor="middle" fill="#8cf4ff" font-size="32">New inode</text>
    <text x="436" y="678" text-anchor="middle" fill="#f8fbff"
          font-size="64" font-weight="700">{byte_b}</text>
    <path d="M270 645H330M318 633L332 645L318 657" fill="none" stroke="#ffd477" stroke-width="4"/>
    <text x="32" y="760" fill="#f8fbff"
          font-size="34" font-weight="700">Replacement byte {byte_b} was read.</text>
    <text x="32" y="804" fill="#c2cee3" font-size="32">Path allowlist is not an object pin.</text>
    <path d="M32 836H568" stroke="#263754" stroke-width="2"/>
    <text x="32" y="882" fill="#ffd477"
          font-size="32" font-weight="700">{replacement_status}: replacement read allowed</text>
    <text x="32" y="930" fill="#ffd477"
          font-size="32" font-weight="700">{socket_status}: socket creation succeeded</text>
    <text x="32" y="974" fill="#c2cee3" font-size="32">Connection was denied, not creation.</text>
    <text x="32" y="1022" fill="#c2cee3" font-size="32">{unknown}: self-exec, no result</text>
    <rect x="32" y="1062" width="536" height="216" rx="14"
          fill="#251e22" stroke="#f2bd57" stroke-width="2"/>
    <text x="52" y="1108" fill="#ffd477"
          font-size="34" font-weight="700">SEPARATE PRE-EXEC FAILURE</text>
    <text x="52" y="1156" fill="#f8fbff" font-size="32">Allowed-read control succeeded.</text>
    <text x="52" y="1198" fill="#f8fbff" font-size="32">Candidate: SIGABRT, no result.</text>
    <text x="52" y="1248" fill="#ffd477"
          font-size="34" font-weight="700">UNKNOWN / {untested} later UNTESTED</text>
    <text x="32" y="1342" fill="#f8fbff" font-size="36" font-weight="700">MLX determinism:</text>
    <text x="32" y="1393" fill="#ffadb6" font-size="46" font-weight="700">NOT MEASURED</text>
    <text x="32" y="1444" fill="#c2cee3" font-size="32">Startup confinement: unproven.</text>
    <text x="32" y="1490" fill="#c2cee3" font-size="32">Runtime permission: NOT GRANTED.</text>
    <text x="32" y="1532" fill="#c2cee3"
          font-size="32">Offline replay is not acquisition proof.</text>
"""
    else:
        body = f"""    <text x="48" y="74" fill="#f8fbff"
          font-size="56" font-weight="700">A path is not a pin.</text>
    <text x="48" y="140" fill="#8cf4ff" font-size="48" font-weight="700">{headline}</text>
    <text x="48" y="195" fill="#f8fbff"
          font-size="32" font-weight="700">AFTER-STARTUP NATIVE HELPER</text>
    <text x="48" y="240" fill="#ffd477" font-size="36" font-weight="700">NOT AN MLX BENCHMARK</text>
    <text x="1152" y="195" text-anchor="end" fill="#c2cee3"
          font-size="26">C/libc, controlled fixtures</text>
    <text x="1152" y="235" text-anchor="end" fill="#c2cee3"
          font-size="26">Darwin 27.0.0 arm64</text>
    <path d="M48 272H1152" stroke="#263754" stroke-width="2"/>
    <rect x="48" y="306" width="600" height="68" rx="12"
          fill="#12233b" stroke="#6ee7f5" stroke-width="2"/>
    <text x="348" y="351" text-anchor="middle" fill="#f8fbff"
          font-size="32" font-weight="700">One unchanged allowed path</text>
    <path d="M195 374V410M501 374V410" stroke="#6ee7f5" stroke-width="3"/>
    <path d="M110 412H280V540H110Z" fill="#12233b" stroke="#6ee7f5"
          stroke-width="3" stroke-dasharray="8 6"/>
    <path d="M416 412H586V540H416Z" fill="#113c49" stroke="#6ee7f5" stroke-width="3"/>
    <text x="195" y="452" text-anchor="middle" fill="#c2cee3" font-size="26">Old inode</text>
    <text x="195" y="515" text-anchor="middle" fill="#f8fbff"
          font-size="60" font-weight="700">{byte_a}</text>
    <text x="501" y="452" text-anchor="middle" fill="#8cf4ff" font-size="26">New inode</text>
    <text x="501" y="515" text-anchor="middle" fill="#f8fbff"
          font-size="60" font-weight="700">{byte_b}</text>
    <path d="M306 479H390M375 464L392 479L375 494" fill="none" stroke="#ffd477" stroke-width="4"/>
    <text x="48" y="589" fill="#f8fbff"
          font-size="32" font-weight="700">Replacement byte {byte_b} was read.</text>
    <text x="48" y="630" fill="#c2cee3" font-size="28">Path allowlist is not an object pin.</text>
    <text x="706" y="347" fill="#ffd477"
          font-size="28" font-weight="700">{replacement_status}: replacement read allowed</text>
    <text x="706" y="403" fill="#ffd477"
          font-size="28" font-weight="700">{socket_status}: socket creation succeeded</text>
    <text x="706" y="448" fill="#c2cee3" font-size="26">Connection denied, not creation.</text>
    <text x="706" y="507" fill="#c2cee3" font-size="28">{unknown}: self-exec</text>
    <text x="706" y="548" fill="#c2cee3" font-size="26">SIGABRT, no accepted result.</text>
    <text x="706" y="615" fill="#c2cee3" font-size="26">Matches include allowed actions</text>
    <text x="706" y="650" fill="#c2cee3" font-size="26">and hygiene, not just denials.</text>
    <rect x="48" y="682" width="1104" height="92" rx="14"
          fill="#251e22" stroke="#f2bd57" stroke-width="2"/>
    <text x="70" y="718" fill="#ffd477"
          font-size="28" font-weight="700"
          >SEPARATE PRE-EXEC FAILURE: UNKNOWN / {untested} later UNTESTED</text>
    <text x="70" y="756" fill="#f8fbff"
          font-size="26"
          >Allowed-read control succeeded. Candidate: SIGABRT, no result. Startup unproven.</text>
    <text x="48" y="827" fill="#ffadb6"
          font-size="36" font-weight="700">MLX determinism: NOT MEASURED</text>
    <text x="48" y="873" fill="#c2cee3"
          font-size="26"
          >Runtime permission: NOT GRANTED. Offline replay is not acquisition proof.</text>
"""
    return opening + body + "  </g>\n</svg>\n"


def publication_artifacts(pre_exec_bytes: bytes, after_startup_bytes: bytes) -> dict[str, bytes]:
    """Derive all public formats from the same exact revalidated observations."""
    card = build_card(pre_exec_bytes, after_startup_bytes)
    return {
        "native-evidence-card.json": canonical_json(card),
        "native-evidence-card.md": _markdown(card).encode("utf-8"),
        "native-evidence-card.svg": _svg(card, mobile=False).encode("utf-8"),
        "native-evidence-card-mobile.svg": _svg(card, mobile=True).encode("utf-8"),
        "a-path-is-not-a-pin.md": _article(card).encode("utf-8"),
    }


def _write_outputs(output_dir: Path, outputs: dict[str, bytes]) -> None:
    if any((output_dir / name).exists() for name in outputs):
        raise ContractError("publication output already exists; choose a fresh directory")
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, data in outputs.items():
        with (output_dir / name).open("xb") as output:
            output.write(data)


def main(argv: list[str] | None = None) -> int:
    """Read explicit receipts and write a fresh card; no acquisition or authority path."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pre-exec", type=Path, required=True, help="Original pre-exec receipt")
    parser.add_argument(
        "--after-startup", type=Path, required=True, help="Original after-startup receipt"
    )
    parser.add_argument(
        "--output-dir", type=Path, required=True, help="Output directory; never overwrite files"
    )
    args = parser.parse_args(argv)
    try:
        outputs = publication_artifacts(
            _read_regular(args.pre_exec, MAX_REPORT_BYTES),
            _read_regular(args.after_startup, MAX_REPORT_BYTES),
        )
        _write_outputs(args.output_dir, outputs)
    except ContractError as error:
        print(f"native card error: {error}", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"native card I/O error: {error.strerror}", file=sys.stderr)
        return 2
    print("\n".join(outputs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
