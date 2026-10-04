"""Privacy-preserving, read-only host identity probing."""

from __future__ import annotations

import ctypes
import os
import platform
from pathlib import Path

from localinferencelab.contracts import Fact, HostIdentity


def _sysctl_string(name: str) -> str:
    libc = ctypes.CDLL(None, use_errno=True)
    function = libc.sysctlbyname
    function.argtypes = [
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    function.restype = ctypes.c_int
    size = ctypes.c_size_t()
    if function(name.encode(), None, ctypes.byref(size), None, 0) != 0:
        return "unavailable"
    buffer = ctypes.create_string_buffer(size.value)
    if function(name.encode(), buffer, ctypes.byref(size), None, 0) != 0:
        return "unavailable"
    return buffer.value.decode("utf-8", errors="replace")


def _sysctl_integer(name: str, default: int) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    function = libc.sysctlbyname
    function.argtypes = [
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    function.restype = ctypes.c_int
    value = ctypes.c_uint64()
    size = ctypes.c_size_t(ctypes.sizeof(value))
    if function(name.encode(), ctypes.byref(value), ctypes.byref(size), None, 0) != 0:
        return default
    return max(int(value.value), 1)


def _linux_chip() -> str:
    cpuinfo = Path("/proc/cpuinfo")
    if not cpuinfo.is_file():
        return platform.processor() or "unavailable"
    for line in cpuinfo.read_text(encoding="utf-8", errors="replace").splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip().lower() in {"model name", "hardware", "model"}:
            return value.strip() or "unavailable"
    return platform.processor() or "unavailable"


def _linux_memory() -> int:
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError):
        return 1
    return max(int(pages * page_size), 1)


def _linux_physical_cores() -> int | None:
    topology = Path("/sys/devices/system/cpu")
    core_pairs: set[tuple[str, str]] = set()
    if topology.is_dir():
        for cpu in topology.glob("cpu[0-9]*"):
            package_file = cpu / "topology" / "physical_package_id"
            core_file = cpu / "topology" / "core_id"
            if package_file.is_file() and core_file.is_file():
                package_value = package_file.read_text(
                    encoding="ascii",
                    errors="strict",
                ).strip()
                core_value = core_file.read_text(encoding="ascii", errors="strict").strip()
                core_pairs.add((package_value, core_value))
    if core_pairs:
        return len(core_pairs)
    cpuinfo = Path("/proc/cpuinfo")
    if not cpuinfo.is_file():
        return None
    package_id: str | None = None
    core_id: str | None = None
    for line in cpuinfo.read_text(encoding="utf-8", errors="replace").splitlines() + [""]:
        key, separator, value = line.partition(":")
        if separator and key.strip() == "physical id":
            package_id = value.strip()
        elif separator and key.strip() == "core id":
            core_id = value.strip()
        elif not line.strip():
            if package_id is not None and core_id is not None:
                core_pairs.add((package_id, core_id))
            package_id = None
            core_id = None
    return len(core_pairs) or None


def _linux_os_identity() -> tuple[str, str]:
    release = platform.release() or "unavailable"
    os_release = Path("/etc/os-release")
    if not os_release.is_file():
        return release, release
    values: dict[str, str] = {}
    for line in os_release.read_text(encoding="utf-8", errors="replace").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value.strip().strip("\"'")
    return (
        values.get("VERSION_ID") or release,
        values.get("BUILD_ID") or values.get("VERSION_CODENAME") or release,
    )


def probe_host() -> HostIdentity:
    """Collect only safe hardware and OS facts without subprocesses."""
    system = platform.system()
    architecture = platform.machine() or "unavailable"
    logical = os.cpu_count() or 1
    physical: int | None
    if system == "Darwin":
        chip = _sysctl_string("machdep.cpu.brand_string")
        if chip == "unavailable":
            chip = _sysctl_string("hw.model")
        physical = _sysctl_integer("hw.physicalcpu", logical)
        logical = _sysctl_integer("hw.logicalcpu", logical)
        memory = _sysctl_integer("hw.memsize", 1)
        os_version = platform.mac_ver()[0] or "unavailable"
        os_build = _sysctl_string("kern.osversion")
        is_apple_silicon = architecture in {"arm64", "aarch64"}
        facts = (
            Fact("probe_method", "libc.sysctlbyname"),
            Fact("apple_silicon_eligible", str(is_apple_silicon).lower()),
        )
    else:
        chip = _linux_chip()
        physical = _linux_physical_cores()
        memory = _linux_memory()
        os_version, os_build = _linux_os_identity()
        is_apple_silicon = False
        facts = (
            Fact("probe_method", "python-platform-and-procfs"),
            Fact("apple_silicon_eligible", "false"),
        )
    record = HostIdentity(
        "host_identity",
        "1.0",
        "safe_host_probe",
        "apple_silicon" if is_apple_silicon and system == "Darwin" else "non_apple_ci",
        architecture,
        chip,
        physical,
        max(logical, physical or 1, 1),
        memory,
        system or "unavailable",
        os_version,
        os_build,
        facts,
    )
    return HostIdentity.from_dict(record.to_dict())
