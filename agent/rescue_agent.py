#!/usr/bin/env python3
"""Rescue AI - one-day version.

A read-only MCP server that lets Claude (or any MCP client) examine a Windows
PC from a Linux live USB. Windows partitions are mounted read-only and no tool
can change anything on the PC.

Normally started by start.sh, which installs the dependencies first.
"""

import argparse
import collections
import datetime as dt
import fnmatch
import functools
import json
import logging
import os
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace

import anyio
import uvicorn
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

try:
    from mcp.server.transport_security import TransportSecuritySettings
except ImportError:  # older SDKs don't check the Host header at all
    TransportSecuritySettings = None

log = logging.getLogger("rescue")

MOUNT_BASE = Path("/mnt/rescue")
MAX_RESULT_CHARS = 90_000
EFI_GUID = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"

PARTS: dict[str, dict] = {}  # partition name -> info, filled in at start-up
ALLOW_PERSONAL = False
ACTIVITY: collections.deque = collections.deque(maxlen=200)
SCREEN = None  # the full-screen display, in --console mode
_LOCK = threading.Lock()  # tools run one at a time (hive/evtx readers aren't thread-safe)

PART_TYPES = {
    EFI_GUID: "EFI system",
    "e3c9e316-0b5c-4db8-817d-f92df00215ae": "Microsoft reserved",
    "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "Windows data",
    "de94bba4-06d1-4d40-a16a-bfd50179d6ac": "Windows recovery",
    "0fc63daf-8483-4772-8e79-3d69d8477de4": "Linux",
    "0x7": "NTFS/exFAT (MBR)",
    "0xef": "EFI system (MBR)",
}

STOP_CODES = {
    0x0A: "IRQL_NOT_LESS_OR_EQUAL",
    0x19: "BAD_POOL_HEADER",
    0x1A: "MEMORY_MANAGEMENT",
    0x1E: "KMODE_EXCEPTION_NOT_HANDLED",
    0x24: "NTFS_FILE_SYSTEM",
    0x3B: "SYSTEM_SERVICE_EXCEPTION",
    0x4E: "PFN_LIST_CORRUPT",
    0x50: "PAGE_FAULT_IN_NONPAGED_AREA",
    0x77: "KERNEL_STACK_INPAGE_ERROR",
    0x7A: "KERNEL_DATA_INPAGE_ERROR",
    0x7B: "INACCESSIBLE_BOOT_DEVICE",
    0x7E: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
    0x7F: "UNEXPECTED_KERNEL_MODE_TRAP",
    0x9C: "MACHINE_CHECK_EXCEPTION",
    0x9F: "DRIVER_POWER_STATE_FAILURE",
    0xA0: "INTERNAL_POWER_ERROR",
    0xBE: "ATTEMPTED_WRITE_TO_READONLY_MEMORY",
    0xC2: "BAD_POOL_CALLER",
    0xD1: "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
    0xD5: "DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL",
    0xED: "UNMOUNTABLE_BOOT_VOLUME",
    0xEF: "CRITICAL_PROCESS_DIED",
    0xF4: "CRITICAL_OBJECT_TERMINATION",
    0xFC: "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY",
    0x101: "CLOCK_WATCHDOG_TIMEOUT",
    0x109: "CRITICAL_STRUCTURE_CORRUPTION",
    0x116: "VIDEO_TDR_FAILURE",
    0x117: "VIDEO_TDR_TIMEOUT_DETECTED",
    0x124: "WHEA_UNCORRECTABLE_ERROR",
    0x133: "DPC_WATCHDOG_VIOLATION",
    0x139: "KERNEL_SECURITY_CHECK_FAILURE",
    0x154: "UNEXPECTED_STORE_EXCEPTION",
    0x1000007E: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M",
    0x1000008E: "KERNEL_MODE_EXCEPTION_NOT_HANDLED_M",
    0xC000021A: "STATUS_SYSTEM_PROCESS_TERMINATED",
}

# (provider substring, event id or None for any, meaning)
CRASH_EVENTS = [
    ("kernel-power", 41, "Unexpected restart or power loss (no clean shutdown)"),
    ("eventlog", 6008, "The previous shutdown was unexpected"),
    ("bugcheck", 1001, "Blue screen (stop code is in the data)"),
    ("wer-systemerrorreporting", 1001, "Blue screen (stop code is in the data)"),
    ("user32", 1074, "Planned shutdown or restart (who and why)"),
    ("whea-logger", None, "Hardware error reported by the CPU or firmware"),
]

CORE_FILES = [
    "Windows/System32/winload.efi",
    "Windows/System32/ntoskrnl.exe",
    "Windows/System32/hal.dll",
    "Windows/System32/ci.dll",
    "Windows/System32/config/SYSTEM",
    "Windows/System32/config/SOFTWARE",
]

# Files the AI may never read: passwords, keys, memory contents, raw hives.
DENY_PATTERNS = [
    r"^windows/system32/config/",
    r"^(hiberfil|pagefile|swapfile)\.sys$",
    r"/microsoft/(protect|credentials|crypto)/",
    r"^programdata/microsoft/wlansvc/",
    r"/(login data|cookies|logins\.json|key4\.db)$",
]

# name -> (command, keep the end of long output)
DIAGNOSTICS = {
    "kernel_errors": (["dmesg", "--level=emerg,alert,crit,err,warn"], True),
    "uefi_boot_entries": (["efibootmgr", "-v"], False),
    "secure_boot": (["mokutil", "--sb-state"], False),
    "pci_devices": (["lspci", "-nnk"], False),
    "usb_devices": (["lsusb"], False),
    "hardware_summary": (["lshw", "-short"], False),
    "bios_and_system": (["dmidecode", "-t", "bios", "-t", "system", "-t", "baseboard"], False),
    "memory_modules": (["dmidecode", "-t", "memory"], False),
    "cpu": (["lscpu"], False),
    "block_devices": (["lsblk", "-o", "NAME,SIZE,TYPE,FSTYPE,LABEL,MODEL,TRAN,RO,MOUNTPOINT"], False),
    "mounts": (["findmnt", "-l", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"], False),
    "network": (["ip", "-br", "addr"], False),
    "temperatures": (["sensors"], False),
    "battery": (None, False),  # read from /sys, see battery_info()
}

INSTRUCTIONS = r"""
You are connected to Rescue AI, running on a PC that was started from a Linux
live USB so its Windows installation can be examined from the outside.
Windows is NOT running. Everything is READ-ONLY: you can inspect, not change.

How to work:
1. Call get_overview first. Ask the person what they see when Windows starts
   (error message, stop code, boot loop, black screen, when it began).
2. Investigate with crash_history, boot_check, query_event_log, recent_updates,
   recent_drivers, disk_health, windows_info, read_registry and read_text_file.
   Useful files: Windows\System32\LogFiles\Srt\SrtTrail.txt (Automatic Repair),
   Windows\Logs\CBS\CBS.log, Windows\INF\setupapi.dev.log, Windows\Panther\.
3. Explain the most likely cause in plain language and show your evidence.
4. Give fix steps the person can do themselves (for example from the Windows
   Recovery Environment), one step at a time. Warn before anything that could
   lose data. If disk health is bad, tell them to copy important files first.

Notes:
- Event-log "days" count back from the newest event in that log, because the
  PC may have been broken for a while.
- Paths are relative to a partition (default: the Windows partition); drive
  letters such as C: are ignored.
- Personal files under \Users are private unless the owner allowed them.
- Never ask for passwords or BitLocker recovery keys in chat.
"""

security = {}
if TransportSecuritySettings is not None:
    # Requests arrive through the tunnel with its public Host header; the
    # secret token in the URL is what protects this server.
    security["transport_security"] = TransportSecuritySettings(enable_dns_rebinding_protection=False)

mcp = FastMCP(
    "rescue-ai",
    instructions=INSTRUCTIONS,
    stateless_http=True,
    json_response=True,  # plain JSON, no SSE: works through Cloudflare quick tunnels
    log_level="WARNING",
    **security,
)
READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False)


class UserError(Exception):
    """A problem the AI can act on; returned to it as {"error": ...}."""


def tool(fn):
    """Register fn as a read-only MCP tool, log each call, and catch errors."""

    def call(kwargs):
        with _LOCK:
            try:
                result = fn(**kwargs)
            except UserError as e:
                return {"error": str(e)}
            except Exception as e:
                log.exception("%s failed", fn.__name__)
                return {"error": f"{type(e).__name__}: {e}"}
        text = json.dumps(result, default=str, ensure_ascii=False)
        if len(text) > MAX_RESULT_CHARS:
            return {
                "truncated": True,
                "note": "Result too large; ask for less (smaller limit, more filters).",
                "partial_json": text[:MAX_RESULT_CHARS],
            }
        return json.loads(text)

    @functools.wraps(fn)
    async def wrapper(**kwargs):
        shown = ", ".join(f"{k}={v!r}" for k, v in kwargs.items())
        line = f"{dt.datetime.now():%H:%M:%S}  AI -> {fn.__name__}({shown})"
        ACTIVITY.append(line)
        if SCREEN:
            SCREEN.refresh()
        log.info("AI -> %s(%s)", fn.__name__, shown)
        return await anyio.to_thread.run_sync(call, kwargs)

    return mcp.tool(annotations=READ_ONLY)(wrapper)


# ---------------------------------------------------------------- helpers


def run(cmd: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)


def clip(text: str, limit: int, tail: bool = False) -> str:
    if len(text) <= limit:
        return text
    return "...[cut]...\n" + text[-limit:] if tail else text[:limit] + "\n...[cut]..."


def run_text(cmd: list[str], limit: int = 30_000, tail: bool = False) -> str:
    if not shutil.which(cmd[0]):
        return f"({cmd[0]} is not installed)"
    try:
        p = run(cmd)
    except subprocess.TimeoutExpired:
        return f"({cmd[0]} timed out)"
    out = p.stdout + (f"\n[stderr]\n{p.stderr}" if p.stderr.strip() else "")
    return clip(out, limit, tail)


def read_sys(path: str) -> str | None:
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def gb(size) -> float:
    try:
        return round(int(size or 0) / 1e9, 1)
    except (TypeError, ValueError):
        return 0.0


def mtime_str(path: Path) -> str:
    return dt.datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")


def filetime(ft: int) -> str | None:
    if not ft:
        return None
    try:
        return (dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=ft // 10)).strftime("%Y-%m-%d %H:%M:%S")
    except OverflowError:
        return None


def since(newest: str, days: int) -> str:
    """Timestamp `days` before `newest` (both "YYYY-MM-DD HH:MM:SS")."""
    try:
        return (dt.datetime.fromisoformat(newest) - dt.timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return ""


@functools.lru_cache(maxsize=4096)
def folder_names(folder: str) -> dict[str, str]:
    """Lower-case name -> real name for a folder (safe to cache: the disk is read-only)."""
    return {n.lower(): n for n in os.listdir(folder)}


def ci_path(root: Path, rel: str) -> Path | None:
    """Find rel under root, ignoring case like Windows does. None if missing."""
    cur = root
    for part in (p for p in re.split(r"[\\/]+", rel) if p and p != "."):
        if part == "..":
            raise UserError("'..' is not allowed in paths")
        candidate = cur / part
        if candidate.exists() or candidate.is_symlink():
            cur = candidate
            continue
        try:
            match = folder_names(str(cur)).get(part.lower())
        except OSError:
            return None
        if match is None:
            return None
        cur = cur / match
    return cur


def decode_text(raw: bytes) -> str | None:
    """Decode a text file's bytes; None if it looks binary."""
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", "replace")
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", "replace")
    sample = raw[:4000]
    if len(sample) > 8 and sample[1::2].count(0) > len(sample) // 4:  # UTF-16LE without BOM
        return raw.decode("utf-16-le", "replace")
    if b"\x00" in sample:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp1252", "replace")


def read_text(path: Path, max_bytes: int, from_end: bool = False) -> str | None:
    size = path.stat().st_size
    with open(path, "rb") as f:
        utf16 = f.read(2) == b"\xff\xfe"
        start = max(0, size - max_bytes) if from_end else 0
        if utf16 and start % 2:
            start += 1
        f.seek(start)
        raw = f.read(max_bytes)
    if utf16 and start > 0:
        return raw.decode("utf-16-le", "replace")
    return decode_text(raw)


# ---------------------------------------------------------------- disks and mounting


def lsblk() -> list[dict]:
    if not shutil.which("lsblk"):
        return []
    p = run(["lsblk", "-J", "-b", "-o",
             "NAME,PATH,SIZE,TYPE,FSTYPE,LABEL,PARTTYPE,PARTLABEL,MODEL,SERIAL,TRAN,RM,RO,MOUNTPOINT"])
    return json.loads(p.stdout or "{}").get("blockdevices", [])


def disks() -> list[dict]:
    return [d for d in lsblk() if d.get("type") == "disk"]


def mount_info(dev: str) -> tuple[str, bool] | None:
    """(mountpoint, is_read_only) if dev is already mounted."""
    p = run(["findmnt", "-J", "-o", "TARGET,OPTIONS", "--source", dev])
    if p.returncode != 0 or not p.stdout.strip():
        return None
    fs = json.loads(p.stdout)["filesystems"][0]
    return fs["target"], "ro" in fs["options"].split(",")


def mount_readonly(dev: str, name: str, kind: str) -> tuple[str | None, str]:
    """Mount a partition read-only. Returns (mountpoint, problem note)."""
    found = mount_info(dev)
    if found:
        target, ro = found
        if not ro and target.startswith("/media/"):  # opened from the Files app
            run(["mount", "-o", "remount,ro", target])
            found = mount_info(dev)
            ro = bool(found and found[1])
        return target, "" if ro else "mounted READ-WRITE by the system; unmount it in the Files app and restart"

    target = MOUNT_BASE / name
    target.mkdir(parents=True, exist_ok=True)
    run(["blockdev", "--setro", dev])  # block-level protection on top of the ro mount
    attempts = [["-t", "vfat", "-o", "ro"]] if kind == "efi" else [["-t", "ntfs3", "-o", "ro"], ["-t", "ntfs-3g", "-o", "ro"]]
    errors = []
    for opts in attempts:
        p = run(["mount", *opts, dev, str(target)])
        if p.returncode == 0:
            return str(target), ""
        errors.append(p.stderr.strip())
    return None, "could not mount: " + " | ".join(e for e in errors if e)


def discover() -> None:
    """Find Windows-related partitions on internal disks and mount them read-only."""
    for disk in disks():
        if disk.get("tran") == "usb":  # the live USB itself, or a backup stick
            continue
        for part in disk.get("children") or []:
            fstype = (part.get("fstype") or "").lower()
            ptype = (part.get("parttype") or "").lower()
            if ptype in (EFI_GUID, "0xef"):
                kind = "efi"
            elif fstype == "ntfs":
                kind = "ntfs"
            elif fstype == "bitlocker":
                kind = "bitlocker"
            else:
                continue
            info = {
                "name": part["name"], "device": part["path"], "disk": disk["name"], "kind": kind,
                "label": part.get("label") or part.get("partlabel"), "size_gb": gb(part.get("size")),
                "mountpoint": None, "note": "", "windows": False,
            }
            if kind == "bitlocker":
                info["note"] = "BitLocker-encrypted and locked (needs the recovery key to read)"
            else:
                info["mountpoint"], info["note"] = mount_readonly(part["path"], part["name"], kind)
                if info["mountpoint"] and kind == "ntfs":
                    info["windows"] = ci_path(Path(info["mountpoint"]), "Windows/System32/config/SYSTEM") is not None
            PARTS[part["name"]] = info


def add_test_root(path: str) -> None:
    root = Path(path).resolve()
    name = f"test{len(PARTS) + 1}"
    windows = ci_path(root, "Windows/System32/config/SYSTEM") is not None
    kind = "efi" if not windows and ci_path(root, "EFI") else "ntfs"
    PARTS[name] = {
        "name": name, "device": None, "disk": None, "kind": kind, "label": root.name,
        "size_gb": 0.0, "mountpoint": str(root), "note": "", "windows": windows,
    }


def unmount_ours() -> None:
    for p in PARTS.values():
        if p.get("device") and (p.get("mountpoint") or "").startswith(str(MOUNT_BASE)):
            run(["umount", p["mountpoint"]])


def get_part(name: str = "") -> dict:
    if name:
        part = PARTS.get(name.removeprefix("/dev/"))
        if not part:
            raise UserError(f"Unknown partition {name!r}. Known: {', '.join(PARTS) or 'none'}")
    else:
        part = next((p for p in PARTS.values() if p["windows"]), None)
        if not part:
            raise UserError("No readable Windows partition was found. Call get_overview: "
                            "the drive may be BitLocker-locked or failed to mount.")
    if not part.get("mountpoint"):
        raise UserError(f"{part['name']} is not readable: {part['note']}")
    return part


def resolve(path: str, partition: str = "") -> tuple[dict, Path]:
    part = get_part(partition)
    root = Path(part["mountpoint"])
    rel = re.sub(r"^[A-Za-z]:", "", path.strip())
    target = ci_path(root, rel)
    if target is None:
        raise UserError(f"Not found: {path} (on {part['name']})")
    real_root = os.path.realpath(root)
    if os.path.commonpath([os.path.realpath(target), real_root]) != real_root:
        raise UserError("That path is a link or junction pointing outside the partition; not followed.")
    return part, target


def check_readable(part: dict, target: Path) -> None:
    rel = os.path.relpath(target, part["mountpoint"]).replace("\\", "/").lower()
    if any(re.search(p, rel) for p in DENY_PATTERNS):
        raise UserError("This file is blocked: it can contain passwords, keys or memory contents. "
                        "Use read_registry for registry hives.")
    if rel.startswith("users/") and rel.count("/") >= 2 and not ALLOW_PERSONAL:
        raise UserError("Personal files are private. The owner can restart Rescue AI with "
                        "--allow-personal-files to share them.")


# ---------------------------------------------------------------- registry


_HIVES: dict[str, object] = {}


def open_hive(path: Path | None):
    if path is None:
        raise UserError("Hive file not found")
    from regipy.registry import RegistryHive

    key = str(path)
    if key not in _HIVES:
        _HIVES[key] = RegistryHive(key)
    return _HIVES[key]


def hive_root(hive):
    return getattr(hive, "root", None) or hive.get_key("\\")


def subkey(key, path: str):
    for part in (p for p in re.split(r"[\\/]+", path) if p):
        key = next((k for k in key.iter_subkeys() if k.name.lower() == part.lower()), None)
        if key is None:
            raise UserError(f"Registry key not found: {path}")
    return key


def reg_values(key) -> dict:
    return {v.name: v.value for v in key.iter_values()}


def reg_value(top, path: str, name: str, default=None):
    try:
        return reg_values(subkey(top, path)).get(name, default)
    except Exception:
        return default


def control_set(top) -> str:
    try:
        return f"ControlSet{int(reg_values(subkey(top, 'Select')).get('Current')):03d}"
    except Exception:
        return "ControlSet001"


def fmt_value(v):
    if isinstance(v, bytes):
        return v[:128].hex(" ") + (" ..." if len(v) > 128 else "")
    if isinstance(v, str) and len(v) > 2000:
        return v[:2000] + " ..."
    if isinstance(v, list):
        return [fmt_value(x) for x in v[:100]]
    return v


def key_time(key) -> str | None:
    try:
        return filetime(key.header.last_modified)
    except Exception:
        return None


# ---------------------------------------------------------------- event logs


_EVTX_CACHE: dict[str, tuple[float, list[dict]]] = {}
_EVTX_LOCKS: dict[str, threading.Lock] = {}
LEVELS = {0: "information", 1: "critical", 2: "error", 3: "warning", 4: "information", 5: "verbose"}
EVT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _record(created, eid, level, provider, data) -> dict:
    try:
        eid = int(eid)
    except (TypeError, ValueError):
        eid = None
    try:
        level = LEVELS.get(int(level), str(level))
    except (TypeError, ValueError):
        level = "information"
    if isinstance(data, dict):
        data = {k: v for k, v in data.items() if k != "#attributes"}
    return {"time": str(created or "")[:19].replace("T", " "), "id": eid, "level": level,
            "provider": provider or "", "data": data}


def _from_json(ev: dict) -> dict:
    s = ev.get("System", {})
    eid = s.get("EventID")
    if isinstance(eid, dict):
        eid = eid.get("#text")
    provider = (s.get("Provider") or {}).get("#attributes", {}).get("Name")
    created = (s.get("TimeCreated") or {}).get("#attributes", {}).get("SystemTime")
    return _record(created, eid, s.get("Level"), provider, ev.get("EventData") or ev.get("UserData") or {})


def _from_xml(text: str) -> dict:
    root = ET.fromstring(text)
    s = root.find(f"{EVT_NS}System")
    provider = s.find(f"{EVT_NS}Provider")
    created = s.find(f"{EVT_NS}TimeCreated")
    data = {}
    ed = root.find(f"{EVT_NS}EventData")
    if ed is not None:
        for i, d in enumerate(ed.findall(f"{EVT_NS}Data")):
            data[d.get("Name") or f"Data{i}"] = d.text
    return _record(created.get("SystemTime") if created is not None else "", s.findtext(f"{EVT_NS}EventID"),
                   s.findtext(f"{EVT_NS}Level"), provider.get("Name") if provider is not None else "", data)


def _parse_evtx(path: Path):
    try:
        from evtx import PyEvtxParser  # fast Rust parser, if it installed
    except ImportError:
        PyEvtxParser = None
    if PyEvtxParser:
        it = iter(PyEvtxParser(str(path)).records_json())
        bad = 0
        while bad < 1000:
            try:
                rec = next(it)
                yield _from_json(json.loads(rec["data"])["Event"])
            except StopIteration:
                return
            except Exception:
                bad += 1  # skip a damaged record
        return
    from Evtx.Evtx import Evtx

    with Evtx(str(path)) as f:
        for rec in f.records():
            try:
                yield _from_xml(rec.xml())
            except Exception:
                continue


def evtx_records(path: Path) -> list[dict]:
    """All records of an .evtx file, newest first (cached; parsed once even if asked twice at once)."""
    key = str(path)
    with _EVTX_LOCKS.setdefault(key, threading.Lock()):
        mtime = path.stat().st_mtime
        cached = _EVTX_CACHE.get(key)
        if cached and cached[0] == mtime:
            return cached[1]
        records = sorted(_parse_evtx(path), key=lambda r: r["time"], reverse=True)
        _EVTX_CACHE[key] = (mtime, records)
        return records


def evtx_path(part: dict, log_name: str) -> Path:
    fname = log_name.strip().replace("/", "%4")
    if not fname.lower().endswith(".evtx"):
        fname += ".evtx"
    found = ci_path(Path(part["mountpoint"]), f"Windows/System32/winevt/Logs/{fname}")
    if found is None:
        logs_dir = ci_path(Path(part["mountpoint"]), "Windows/System32/winevt/Logs")
        biggest = []
        if logs_dir:
            files = sorted(logs_dir.iterdir(), key=lambda f: f.stat().st_size, reverse=True)[:40]
            biggest = [f.name[:-5].replace("%4", "/") for f in files if f.suffix.lower() == ".evtx"]
        raise UserError(f"Log {log_name!r} not found. Largest logs on this PC: {', '.join(biggest)}")
    return found


def short_data(data, limit: int = 1500):
    text = json.dumps(data, default=str, ensure_ascii=False)
    return data if len(text) <= limit else text[:limit] + " ..."


def crash_label(r: dict) -> str | None:
    provider = r["provider"].lower()
    for name, eid, label in CRASH_EVENTS:
        if name in provider and (eid is None or r["id"] == eid):
            return label
    return None


def dump_header(path: Path) -> dict:
    """Stop code and parameters from a Windows kernel crash dump header."""
    try:
        with open(path, "rb") as f:
            h = f.read(0x60)
    except OSError as e:
        return {"header_error": str(e)}
    if h[:8] == b"PAGEDU64":
        code, params = struct.unpack_from("<I", h, 0x38)[0], struct.unpack_from("<4Q", h, 0x40)
    elif h[:8] == b"PAGEDUMP":
        code, params = struct.unpack_from("<I", h, 0x28)[0], struct.unpack_from("<4I", h, 0x2C)
    else:
        return {"header": "not a recognised kernel crash dump"}
    return {"stop_code": f"0x{code:08X}", "stop_name": STOP_CODES.get(code, "look up in Microsoft's bug check reference"),
            "parameters": [f"0x{p:X}" for p in params]}


def hibernated(root: Path) -> bool | None:
    f = ci_path(root, "hiberfil.sys")
    if f is None:
        return False
    try:
        with open(f, "rb") as fh:
            return fh.read(4).lower() == b"hibr"
    except OSError:
        return None


def windows_summary(part: dict) -> dict:
    root = Path(part["mountpoint"])
    info: dict = {"partition": part["name"]}
    try:
        cv = reg_values(subkey(hive_root(open_hive(ci_path(root, "Windows/System32/config/SOFTWARE"))),
                               "Microsoft/Windows NT/CurrentVersion"))
        build = int(str(cv.get("CurrentBuild") or cv.get("CurrentBuildNumber") or 0))
        product = str(cv.get("ProductName") or "Windows")
        if build >= 22000:  # Windows 11 still says "Windows 10" in ProductName
            product = product.replace("Windows 10", "Windows 11")
        info["windows"] = f"{product} {cv.get('DisplayVersion') or cv.get('ReleaseId') or ''}".strip()
        info["build"] = f"{build}.{cv.get('UBR', 0)}"
        if cv.get("InstallDate"):
            info["installed"] = dt.datetime.fromtimestamp(int(cv["InstallDate"]), dt.timezone.utc).strftime("%Y-%m-%d")
    except Exception as e:
        info["software_hive_error"] = str(e) or type(e).__name__
    try:
        top = hive_root(open_hive(ci_path(root, "Windows/System32/config/SYSTEM")))
        cs = control_set(top)
        info["computer_name"] = reg_value(top, f"{cs}/Control/ComputerName/ComputerName", "ComputerName")
        info["fast_startup_enabled"] = reg_value(top, f"{cs}/Control/Session Manager/Power", "HiberbootEnabled") == 1
        shut = reg_value(top, f"{cs}/Control/Windows", "ShutdownTime")
        if isinstance(shut, str):
            shut = bytes.fromhex(shut.replace(" ", ""))
        if isinstance(shut, bytes) and len(shut) >= 8:
            info["last_clean_shutdown_utc"] = filetime(struct.unpack_from("<Q", shut)[0])
    except Exception as e:
        info["system_hive_error"] = str(e) or type(e).__name__
    info["hibernated"] = hibernated(root)
    usage = shutil.disk_usage(root)
    info["free_gb"], info["size_gb"] = round(usage.free / 1e9, 1), round(usage.total / 1e9, 1)
    users = ci_path(root, "Users")
    skip = {"public", "default", "default user", "all users", "desktop.ini", "defaultapppool"}
    info["users"] = sorted(n for n in os.listdir(users) if n.lower() not in skip and (users / n).is_dir()) if users else []
    info["update_pending"] = ci_path(root, "Windows/WinSxS/pending.xml") is not None
    minidump = ci_path(root, "Windows/Minidump")
    info["crash_dumps"] = len([f for f in minidump.iterdir() if f.suffix.lower() == ".dmp"]) if minidump and minidump.is_dir() else 0
    info["automatic_repair_log"] = ci_path(root, "Windows/System32/LogFiles/Srt/SrtTrail.txt") is not None
    missing = []
    for rel in CORE_FILES:
        f = ci_path(root, rel)
        if f is None or f.stat().st_size == 0:
            missing.append(rel)
    info["missing_core_files"] = missing
    return info


def smart_quick(dev: str) -> str:
    if not shutil.which("smartctl"):
        return "unknown (smartctl not installed)"
    try:
        data = json.loads(run(["smartctl", "-H", "-j", dev], 30).stdout or "{}")
    except (ValueError, subprocess.TimeoutExpired):
        return "unknown"
    passed = (data.get("smart_status") or {}).get("passed")
    return "PASSED" if passed else "FAILED" if passed is False else "unknown"


def efi_partitions() -> list[dict]:
    return [p for p in PARTS.values() if p["kind"] == "efi" and p["mountpoint"]]


# ---------------------------------------------------------------- tools


@tool
def get_overview() -> dict:
    """START HERE. One-page summary of the PC: model, firmware, disks and their
    health, Windows installs, and red flags worth investigating."""
    meminfo = read_sys("/proc/meminfo") or ""
    m = re.search(r"MemTotal:\s+(\d+)", meminfo)
    efi_firmware = Path("/sys/firmware/efi").exists()
    disk_list = []
    for d in disks():
        if d.get("tran") == "usb":
            continue
        disk_list.append({"name": d["name"], "model": d.get("model"), "size_gb": gb(d.get("size")),
                          "transport": d.get("tran"), "smart": smart_quick(d["path"])})
    windows = [windows_summary(p) for p in PARTS.values() if p["windows"]]

    flags = []
    for d in disk_list:
        if d["smart"] == "FAILED":
            flags.append(f"Disk {d['name']} ({d['model']}) reports SMART health FAILED: copy important files first.")
    for p in PARTS.values():
        if p["note"]:
            flags.append(f"{p['name']}: {p['note']}")
    if efi_firmware and not any(p["kind"] == "efi" for p in PARTS.values()):
        flags.append("No EFI system partition on the internal disks: Windows can't boot in UEFI mode without one.")
    for p in efi_partitions():
        if ci_path(Path(p["mountpoint"]), "EFI/Microsoft/Boot/BCD") is None:
            flags.append(f"EFI partition {p['name']} has no Windows boot configuration (EFI/Microsoft/Boot/BCD).")
    for w in windows:
        where = f"Windows on {w['partition']}"
        if w.get("hibernated"):
            flags.append(f"{where} is hibernated (Fast Startup or hibernate): it was not fully shut down.")
        if w.get("free_gb", 99) < 5:
            flags.append(f"{where} has only {w['free_gb']} GB free.")
        if w.get("update_pending"):
            flags.append(f"{where} has an unfinished update (Windows\\WinSxS\\pending.xml exists).")
        if w.get("missing_core_files"):
            flags.append(f"{where} is missing or has empty core files: {', '.join(w['missing_core_files'])}")
        if w.get("crash_dumps"):
            flags.append(f"{where} has {w['crash_dumps']} crash dump(s): see crash_history.")
        if w.get("automatic_repair_log"):
            flags.append(f"{where}: Automatic Repair has run; read Windows\\System32\\LogFiles\\Srt\\SrtTrail.txt.")
        for k in ("software_hive_error", "system_hive_error"):
            if k in w:
                flags.append(f"{where}: registry problem ({k}): {w[k]}")
    if not windows and not any(p["kind"] == "bitlocker" for p in PARTS.values()):
        flags.append("No Windows installation was found on the internal disks.")

    return {
        "machine": {k: read_sys(f"/sys/class/dmi/id/{k}") for k in ("sys_vendor", "product_name", "bios_version", "bios_date")},
        "firmware": "UEFI" if efi_firmware else "Legacy BIOS / CSM",
        "secure_boot": run_text(["mokutil", "--sb-state"], 300).strip(),
        "ram_gb": round(int(m.group(1)) / 1e6, 1) if m else None,
        "disks": disk_list,
        "partitions": [{k: p[k] for k in ("name", "kind", "label", "size_gb", "windows", "note")} for p in PARTS.values()],
        "windows_installs": windows,
        "red_flags": flags or ["None found by the quick check."],
        "personal_files_shared": ALLOW_PERSONAL,
        "next_steps": "Ask what the person sees at start-up, then use crash_history, boot_check, "
                      "query_event_log (System, levels critical/error) and recent_updates.",
    }


@tool
def list_disks() -> dict:
    """List every disk and partition with model, size, type and read-only mount status."""
    out = []
    for d in disks():
        parts = []
        for c in d.get("children") or []:
            known = PARTS.get(c["name"], {})
            parts.append({
                "name": c["name"], "size_gb": gb(c.get("size")), "filesystem": c.get("fstype"),
                "label": c.get("label") or c.get("partlabel"),
                "type": PART_TYPES.get((c.get("parttype") or "").lower(), c.get("parttype")),
                "read_only_mount": known.get("mountpoint"), "windows_found": known.get("windows", False),
                "note": known.get("note") or None,
            })
        out.append({"name": d["name"], "model": d.get("model"), "size_gb": gb(d.get("size")),
                    "transport": d.get("tran"), "removable": str(d.get("rm")).lower() in ("1", "true"),
                    "partitions": parts})
    if not out:
        out = [{"note": "lsblk unavailable (test mode)", "partitions": list(PARTS.values())}]
    return {"disks": out}


@tool
def disk_health(disk: str) -> dict:
    """Full SMART / NVMe health report for one disk (e.g. "nvme0n1" or "sda"),
    with a list of problems found."""
    names = {d["name"]: d["path"] for d in disks()}
    name = disk.removeprefix("/dev/")
    if name not in names:
        raise UserError(f"Unknown disk {disk!r}. Disks: {', '.join(names) or 'none'}")
    if not shutil.which("smartctl"):
        raise UserError("smartctl is not installed")
    p = run(["smartctl", "-j", "-a", names[name]], 60)
    data = json.loads(p.stdout or "{}")
    problems = []
    passed = (data.get("smart_status") or {}).get("passed")
    if passed is False:
        problems.append("SMART overall health: FAILED")
    summary = {
        "model": data.get("model_name"), "smart_passed": passed,
        "temperature_c": (data.get("temperature") or {}).get("current"),
        "power_on_hours": (data.get("power_on_time") or {}).get("hours"),
        "smartctl_messages": [m.get("string") for m in (data.get("smartctl") or {}).get("messages", [])],
    }
    nvme = data.get("nvme_smart_health_information_log")
    if nvme:
        keys = ("critical_warning", "percentage_used", "available_spare", "available_spare_threshold",
                "media_errors", "num_err_log_entries", "unsafe_shutdowns", "power_cycles", "data_units_written")
        summary["nvme"] = {k: nvme.get(k) for k in keys}
        if nvme.get("critical_warning"):
            problems.append(f"NVMe critical warning flag: {nvme['critical_warning']}")
        if nvme.get("media_errors"):
            problems.append(f"NVMe media errors: {nvme['media_errors']}")
        if (nvme.get("percentage_used") or 0) >= 90:
            problems.append(f"NVMe wear: {nvme['percentage_used']}% of rated life used")
        if nvme.get("available_spare") is not None and nvme.get("available_spare_threshold") is not None \
                and nvme["available_spare"] < nvme["available_spare_threshold"]:
            problems.append("NVMe spare blocks below threshold")
    attrs = (data.get("ata_smart_attributes") or {}).get("table", [])
    if attrs:
        keep = {5, 9, 10, 184, 187, 188, 196, 197, 198, 199, 231, 233, 241}
        summary["ata_attributes"] = [
            {"id": a["id"], "name": a.get("name"), "value": a.get("value"), "worst": a.get("worst"),
             "threshold": a.get("thresh"), "raw": (a.get("raw") or {}).get("string"), "failed": a.get("when_failed") or None}
            for a in attrs if a.get("id") in keep
        ]
        for a in attrs:
            raw = (a.get("raw") or {}).get("value") or 0
            if a.get("id") in (5, 187, 197, 198) and raw > 0:
                problems.append(f"{a.get('name')}: {raw}")
            if a.get("when_failed"):
                problems.append(f"{a.get('name')} failed ({a['when_failed']})")
    summary["problems"] = problems or ["none"]
    return summary


@tool
def windows_info(partition: str = "") -> dict:
    """Details of a Windows install: version, build, computer name, users, free
    space, hibernation / Fast Startup, pending updates, crash dumps, missing core files."""
    return windows_summary(get_part(partition))


@tool
def query_event_log(log: str = "System", days: int = 14, event_ids: list[int] | None = None,
                    levels: list[str] | None = None, provider: str = "", contains: str = "",
                    limit: int = 50, partition: str = "") -> dict:
    """Search an offline Windows event log (.evtx).

    log: "System", "Application", "Setup", or a channel such as
         "Microsoft-Windows-WindowsUpdateClient/Operational".
    days: how far back from the NEWEST event in that log (not from today).
    levels: any of "critical", "error", "warning", "information".
    provider: case-insensitive part of the provider name.
    contains: case-insensitive text to find in the event data.
    Returns newest events first, plus the most common matching events."""
    part = get_part(partition)
    records = evtx_records(evtx_path(part, log))
    if not records:
        return {"log": log, "events": [], "note": "The log is empty."}
    cutoff = since(records[0]["time"], max(1, min(days, 3650)))
    limit = max(1, min(limit, 200))
    ids = set(event_ids or [])
    wanted_levels = {lv.lower() for lv in levels or []}
    counts: collections.Counter = collections.Counter()
    events = []
    for r in records:
        if r["time"] < cutoff:
            break
        if ids and r["id"] not in ids:
            continue
        if wanted_levels and r["level"] not in wanted_levels:
            continue
        if provider and provider.lower() not in r["provider"].lower():
            continue
        if contains and contains.lower() not in json.dumps(r["data"], default=str).lower():
            continue
        counts[(r["provider"], r["id"], r["level"])] += 1
        if len(events) < limit:
            events.append(dict(r, data=short_data(r["data"])))
    return {
        "log": log, "newest_event": records[0]["time"], "searched_from": cutoff,
        "matched": sum(counts.values()), "showing": len(events),
        "most_common": [{"provider": p, "id": i, "level": lv, "count": n} for (p, i, lv), n in counts.most_common(15)],
        "events": events,
    }


@tool
def crash_history(days: int = 60, partition: str = "") -> dict:
    """Blue screens and unexpected shutdowns: crash dump files with their stop
    codes, crash-related System events, and the Automatic Repair log (SrtTrail.txt)."""
    part = get_part(partition)
    root = Path(part["mountpoint"])
    dumps = []
    minidump = ci_path(root, "Windows/Minidump")
    if minidump and minidump.is_dir():
        files = sorted((f for f in minidump.iterdir() if f.suffix.lower() == ".dmp"),
                       key=lambda f: f.stat().st_mtime, reverse=True)
        for f in files[:30]:
            dumps.append({"file": f"Windows\\Minidump\\{f.name}", "time": mtime_str(f),
                          "size_kb": f.stat().st_size // 1024, **dump_header(f)})
    full = ci_path(root, "Windows/MEMORY.DMP")
    if full:
        dumps.append({"file": "Windows\\MEMORY.DMP", "time": mtime_str(full),
                      "size_mb": full.stat().st_size // 2**20, **dump_header(full)})

    events, boots = [], 0
    system_log = ci_path(root, "Windows/System32/winevt/Logs/System.evtx")
    if system_log:
        records = evtx_records(system_log)
        cutoff = since(records[0]["time"], days) if records else ""
        for r in records:
            if r["time"] < cutoff:
                break
            if r["id"] == 6005 and "eventlog" in r["provider"].lower():
                boots += 1
            label = crash_label(r)
            if label and len(events) < 80:
                events.append({"time": r["time"], "id": r["id"], "provider": r["provider"],
                               "meaning": label, "data": short_data(r["data"], 600)})

    srt = ci_path(root, "Windows/System32/LogFiles/Srt/SrtTrail.txt")
    return {
        "crash_dumps": dumps or "none",
        "crash_events": events or "none in this period",
        "boots_in_period": boots,
        "automatic_repair_log": clip(read_text(srt, 200_000) or "", 8000) if srt else "not present",
    }


def bcd_entries(path: Path) -> list[dict]:
    types = {0x10100001: "Firmware Boot Manager", 0x10100002: "Windows Boot Manager",
             0x101FFFFF: "Firmware boot entry", 0x10200003: "Windows Boot Loader",
             0x10200004: "Windows Resume (hibernate)", 0x10200005: "Windows Memory Diagnostic"}
    elements = {"12000002": "path", "12000004": "description", "22000002": "system_root",
                "23000003": "default_entry", "24000001": "display_order"}
    entries = []
    for obj in subkey(hive_root(open_hive(path)), "Objects").iter_subkeys():
        entry = {"id": obj.name}
        t = reg_value(obj, "Description", "Type")
        if isinstance(t, int):
            entry["type"] = types.get(t, f"0x{t:08X}")
        try:
            for el in subkey(obj, "Elements").iter_subkeys():
                label = elements.get(el.name.lower())
                if label:
                    entry[label] = fmt_value(reg_values(el).get("Element"))
        except UserError:
            pass
        if entry.get("type") == "Windows Boot Loader" and "default_entry" in entry:
            entry["resume_entry"] = entry.pop("default_entry")  # same element id, different meaning here
        entries.append(entry)
    return entries[:40]


@tool
def boot_check() -> dict:
    """Everything about booting: firmware mode, Secure Boot, EFI partition files,
    the Windows boot configuration (BCD) entries, core Windows boot files, and
    the UEFI boot menu entries."""
    efis = []
    for p in efi_partitions():
        root = Path(p["mountpoint"])
        efi_dir = ci_path(root, "EFI")
        entry = {
            "partition": p["name"],
            "files_present": {rel: ci_path(root, rel) is not None for rel in
                              ("EFI/Microsoft/Boot/bootmgfw.efi", "EFI/Microsoft/Boot/BCD", "EFI/Boot/bootx64.efi")},
            "efi_folders": sorted(os.listdir(efi_dir)) if efi_dir and efi_dir.is_dir() else [],
        }
        bcd = ci_path(root, "EFI/Microsoft/Boot/BCD")
        if bcd:
            try:
                entry["bcd_entries"] = bcd_entries(bcd)
            except Exception as e:
                entry["bcd_error"] = f"BCD could not be read: {e}"
        efis.append(entry)
    legacy = []
    for p in PARTS.values():
        bcd = ci_path(Path(p["mountpoint"]), "Boot/BCD") if p["kind"] == "ntfs" and p["mountpoint"] else None
        if bcd:
            try:
                legacy.append({"partition": p["name"], "bcd_entries": bcd_entries(bcd)})
            except Exception as e:
                legacy.append({"partition": p["name"], "bcd_error": str(e)})
    core = {}
    for p in PARTS.values():
        if p["windows"]:
            root = Path(p["mountpoint"])
            core[p["name"]] = {rel: (lambda f: f.stat().st_size if f else "MISSING")(ci_path(root, rel)) for rel in CORE_FILES}
    return {
        "firmware": "UEFI" if Path("/sys/firmware/efi").exists() else "Legacy BIOS / CSM",
        "secure_boot": run_text(["mokutil", "--sb-state"], 300).strip(),
        "efi_partitions": efis or "No mounted EFI system partition on the internal disks",
        "legacy_bios_bcd": legacy or None,
        "windows_core_files_bytes": core,
        "uefi_boot_menu": run_text(["efibootmgr", "-v"], 6000),
    }


@tool
def recent_updates(days: int = 60, partition: str = "") -> dict:
    """Windows Update activity: installs and failures from the System log,
    servicing events from Setup.evtx, unfinished updates (pending.xml), and
    recent error lines from CBS.log."""
    part = get_part(partition)
    root = Path(part["mountpoint"])
    out: dict = {}
    pending = ci_path(root, "Windows/WinSxS/pending.xml")
    out["pending_xml"] = ({"exists": True, "modified": mtime_str(pending), "size_kb": pending.stat().st_size // 1024,
                           "meaning": "Windows has unfinished update work; a common cause of boot loops after updates"}
                          if pending else {"exists": False})
    results = {19: "installed", 20: "FAILED", 43: "install started"}
    system_log = ci_path(root, "Windows/System32/winevt/Logs/System.evtx")
    if system_log:
        records = evtx_records(system_log)
        cutoff = since(records[0]["time"], days) if records else ""
        out["windows_update_events"] = [
            {"time": r["time"], "result": results[r["id"]], "data": short_data(r["data"], 400)}
            for r in records if r["time"] >= cutoff and r["id"] in results
            and "windowsupdateclient" in r["provider"].lower()
        ][:60]
    setup_log = ci_path(root, "Windows/System32/winevt/Logs/Setup.evtx")
    if setup_log:
        records = evtx_records(setup_log)
        cutoff = since(records[0]["time"], days) if records else ""
        out["setup_events"] = [dict(r, data=short_data(r["data"], 400)) for r in records if r["time"] >= cutoff][:40]
    cbs = ci_path(root, "Windows/Logs/CBS/CBS.log")
    if cbs:
        text = read_text(cbs, 2_000_000, from_end=True) or ""
        hits = [ln[:300] for ln in text.splitlines() if re.search(r"error|failed|corrupt|cannot repair", ln, re.I)]
        out["cbs_log_recent_errors"] = hits[-60:] or "none in the last 2 MB of CBS.log"
    return out


@tool
def recent_drivers(days: int = 30, partition: str = "") -> dict:
    """Driver changes: recent installs from setupapi.dev.log, boot-time drivers
    whose file is missing, and boot-time driver files changed recently."""
    part = get_part(partition)
    root = Path(part["mountpoint"])
    out: dict = {}

    sections, current = [], None
    log_file = ci_path(root, "Windows/INF/setupapi.dev.log")
    if log_file:
        for line in (read_text(log_file, 8_000_000, from_end=True) or "").splitlines():
            if m := re.match(r"^>>>\s+\[(.+)\]\s*$", line):
                current = {"title": m.group(1)}
            elif current is not None and (m := re.match(r"^>>>\s+Section start (\d{4}/\d\d/\d\d \d\d:\d\d:\d\d)", line)):
                current["time"] = m.group(1).replace("/", "-")
            elif current is not None and (m := re.match(r"^<<<\s+\[Exit status: (.+)\]", line)):
                current["result"] = m.group(1)
                sections.append(current)
                current = None
    sections.sort(key=lambda s: s.get("time", ""), reverse=True)
    reference = sections[0].get("time", "") if sections else dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cutoff = since(reference, days)
    out["driver_installs"] = [s for s in sections if s.get("time", "") >= cutoff][:80] or "none in this period"

    missing, changed = [], []
    try:
        top = hive_root(open_hive(ci_path(root, "Windows/System32/config/SYSTEM")))
        for svc in subkey(top, f"{control_set(top)}/Services").iter_subkeys():
            v = reg_values(svc)
            if v.get("Start") not in (0, 1) or v.get("Type") not in (1, 2):
                continue  # only kernel / file-system drivers that load at boot
            rel = image_rel(str(v.get("ImagePath") or ""), svc.name)
            f = ci_path(root, rel)
            item = {"driver": svc.name, "file": rel, "start": "boot" if v["Start"] == 0 else "system",
                    "error_control": v.get("ErrorControl")}
            if f is None:
                missing.append(item)
            elif mtime_str(f) >= cutoff:
                changed.append(dict(item, modified=mtime_str(f)))
    except Exception as e:
        out["registry_error"] = str(e)
    out["boot_drivers_missing_file"] = missing or "none"
    out["boot_drivers_changed_recently"] = changed or "none"
    return out


def image_rel(image_path: str, name: str) -> str:
    """Turn a service ImagePath into a path relative to the Windows partition."""
    p = image_path.strip().strip('"').replace("/", "\\") or f"System32\\drivers\\{name}.sys"
    if p.lower().startswith("\\??\\"):
        p = p[4:]
    low = p.lower()
    if re.match(r"^[a-z]:\\", low):
        p = p[3:]
    elif low.startswith("\\systemroot\\"):
        p = "Windows\\" + p[12:]
    elif low.startswith("system32\\"):
        p = "Windows\\" + p
    return p.lstrip("\\")


@tool
def read_registry(hive: str, key: str = "", partition: str = "", max_items: int = 200) -> dict:
    """Read a key from the offline Windows registry: its subkeys and values.

    hive: SYSTEM, SOFTWARE, DEFAULT, COMPONENTS, DRIVERS, BCD (boot configuration
          on the EFI partition) or NTUSER:<username>. SAM and SECURITY are blocked.
    key:  path inside the hive, e.g. "Microsoft\\Windows NT\\CurrentVersion" or
          "CurrentControlSet\\Services\\disk". "HKLM\\SYSTEM\\" prefixes are accepted."""
    name = hive.strip()
    upper = name.upper()
    if upper in ("SAM", "SECURITY"):
        raise UserError("SAM and SECURITY are blocked (they hold password data).")
    if upper == "BCD":
        path = next((ci_path(Path(p["mountpoint"]), "EFI/Microsoft/Boot/BCD") for p in efi_partitions()
                     if ci_path(Path(p["mountpoint"]), "EFI/Microsoft/Boot/BCD")), None)
    else:
        root = Path(get_part(partition)["mountpoint"])
        if upper.startswith("NTUSER:"):
            path = ci_path(root, f"Users/{name.split(':', 1)[1]}/NTUSER.DAT")
        elif upper in ("SYSTEM", "SOFTWARE", "DEFAULT", "COMPONENTS", "DRIVERS"):
            path = ci_path(root, f"Windows/System32/config/{upper}")
        else:
            raise UserError("hive must be SYSTEM, SOFTWARE, DEFAULT, COMPONENTS, DRIVERS, BCD or NTUSER:<username>")
    if path is None:
        raise UserError(f"Hive {hive} was not found on this PC.")
    top = hive_root(open_hive(path))

    key_path = re.sub(r"^(HKLM|HKEY_LOCAL_MACHINE)[\\/]+", "", key.strip(), flags=re.I)
    key_path = re.sub(rf"^{re.escape(upper.split(':')[0])}[\\/]+", "", key_path, flags=re.I)
    if upper == "SYSTEM":
        key_path = re.sub(r"(?i)^CurrentControlSet", control_set(top), key_path)
    k = subkey(top, key_path) if key_path else top
    max_items = max(1, min(max_items, 500))
    subkeys = [s.name for s in k.iter_subkeys()]
    values = [{"name": v.name, "type": v.value_type, "data": fmt_value(v.value)} for v in k.iter_values()]
    return {
        "hive": hive, "key": key_path or "\\", "last_written": key_time(k),
        "subkey_count": len(subkeys), "subkeys": subkeys[:max_items],
        "value_count": len(values), "values": values[:max_items],
    }


@tool
def list_directory(path: str = "\\", partition: str = "", name_filter: str = "",
                   offset: int = 0, limit: int = 200) -> dict:
    """List a folder on a Windows partition (names, sizes, dates).
    name_filter is a wildcard such as "*.log". Use offset to page through big folders."""
    part, target = resolve(path, partition)
    if not target.is_dir():
        raise UserError("Not a folder; use read_text_file for files.")
    entries = []
    for e in os.scandir(target):
        if name_filter and not fnmatch.fnmatch(e.name.lower(), name_filter.lower()):
            continue
        try:
            st = e.stat(follow_symlinks=False)
        except OSError:
            continue
        kind = "link" if e.is_symlink() else "folder" if e.is_dir(follow_symlinks=False) else "file"
        entries.append({"name": e.name, "type": kind, "size": st.st_size if kind == "file" else None,
                        "modified": dt.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")})
    entries.sort(key=lambda x: (x["type"] != "folder", x["name"].lower()))
    limit = max(1, min(limit, 500))
    return {"partition": part["name"], "path": path, "total": len(entries),
            "entries": entries[max(0, offset):max(0, offset) + limit]}


@tool
def read_text_file(path: str, partition: str = "", max_bytes: int = 60_000, from_end: bool = False) -> dict:
    """Read a text or log file from a Windows partition (UTF-8 and UTF-16 handled).
    Use from_end=True for big logs such as Windows\\Logs\\CBS\\CBS.log.
    Personal files under \\Users are private unless the owner allowed them, and
    files that can hold passwords or memory contents are always blocked."""
    part, target = resolve(path, partition)
    if target.is_dir():
        raise UserError("That is a folder; use list_directory.")
    check_readable(part, target)
    max_bytes = max(1_000, min(max_bytes, 200_000))
    size = target.stat().st_size
    text = read_text(target, max_bytes, from_end)
    if text is None:
        return {"path": path, "size": size, "note": "Binary file: contents not shown."}
    return {"path": path, "size": size, "modified": mtime_str(target),
            "partial": size > max_bytes, "from_end": from_end, "text": text}


@tool
def run_diagnostic(name: str) -> dict:
    """Run one safe, read-only Linux diagnostic on this PC's hardware. Names:
    kernel_errors (disk/hardware errors seen by Linux now), uefi_boot_entries,
    secure_boot, pci_devices, usb_devices, hardware_summary, bios_and_system,
    memory_modules, cpu, block_devices, mounts, network, temperatures, battery."""
    if name not in DIAGNOSTICS:
        raise UserError(f"Unknown diagnostic. Choose one of: {', '.join(DIAGNOSTICS)}")
    if name == "battery":
        return {"diagnostic": name, "output": battery_info()}
    cmd, tail = DIAGNOSTICS[name]
    return {"diagnostic": name, "command": " ".join(cmd), "output": run_text(cmd, 30_000, tail)}


def battery_info() -> str:
    found = []
    for d in sorted(Path("/sys/class/power_supply").glob("*")):
        text = read_sys(str(d / "uevent"))
        if text:
            found.append(f"[{d.name}]\n{text}")
    return "\n\n".join(found) or "No battery or power-supply information found."


# ---------------------------------------------------------------- server


def status_page() -> str:
    return ("Rescue AI is running (read-only).\n"
            "Connect an MCP client to this address followed by /mcp\n\n"
            "Recent AI activity (newest last):\n" + ("\n".join(ACTIVITY) or "(none yet)") + "\n")


class TokenGate:
    """Only requests under /<token>/ get through; everything else is a 404."""

    def __init__(self, app, token: str):
        self.app = app
        self.token = token

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":  # lifespan events
            return await self.app(scope, receive, send)
        parts = scope["path"].split("/", 2)
        token = parts[1] if len(parts) > 1 else ""
        if not secrets.compare_digest(token.encode(), self.token.encode()):
            return await self.reply(send, 404, "Not found")
        rest = "/" + parts[2].rstrip("/") if len(parts) > 2 and parts[2].strip("/") else "/"
        if rest == "/":
            return await self.reply(send, 200, status_page())
        await self.app(dict(scope, path=rest, raw_path=rest.encode()), receive, send)

    @staticmethod
    async def reply(send, status: int, text: str):
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"text/plain; charset=utf-8")]})
        await send({"type": "http.response.body", "body": text.encode()})


def qr_lines(text: str) -> list[str]:
    """QR code in half-block characters; light modules are drawn, for light-on-dark screens."""
    try:
        import qrcode

        qr = qrcode.QRCode(border=2)
        qr.add_data(text)
        qr.make(fit=True)
        m = qr.get_matrix()
    except Exception:
        return []
    lines = []
    for y in range(0, len(m), 2):
        top, bottom = m[y], m[y + 1] if y + 1 < len(m) else [True] * len(m[y])
        lines.append("".join(" " if t and b else "▄" if t else "▀" if b else "█" for t, b in zip(top, bottom)))
    return lines


def print_qr(text: str) -> None:
    try:
        print("\n".join("  " + line for line in qr_lines(text)), flush=True)
    except UnicodeEncodeError:
        pass


def announce(url: str) -> None:
    bar = "=" * 74
    print(f"\n{bar}\n  Rescue AI is ready (read-only). Give this link to Claude:\n\n    {url}\n", flush=True)
    print_qr(url)
    print("  claude.ai / Claude Desktop: Settings > Connectors > Add custom connector\n"
          f"  Claude Code: claude mcp add --transport http rescue {url}\n\n"
          "  Copy in this terminal with Ctrl+Shift+C. The link is also saved in /tmp/rescue-ai-link.txt\n"
          "  Anyone with this link can READ this PC's disk. Press Ctrl+C here to stop.\n"
          f"{bar}\n", flush=True)
    try:
        Path("/tmp/rescue-ai-link.txt").write_text(url + "\n")
        os.chmod("/tmp/rescue-ai-link.txt", 0o644)
    except OSError:
        pass


def online() -> bool:
    """True if Cloudflare's tunnel service is reachable (network, DNS and HTTPS port)."""
    try:
        socket.create_connection(("api.trycloudflare.com", 443), timeout=5).close()
        return True
    except OSError:
        return False


class Tunnel:
    """Keeps a Cloudflare quick tunnel open: waits for the network and reconnects if it drops.

    Every new link gets a new secret token, so old links stop working."""

    def __init__(self, binary: str, port: int, gate: TokenGate, on_change):
        self.binary, self.port, self.gate, self.on_change = binary, port, gate, on_change
        self.status, self.url = "Starting...", None
        self.sharing = True
        self.generation = 0
        self.proc: subprocess.Popen | None = None

    def start(self) -> None:
        threading.Thread(target=self._run, daemon=True).start()

    def _set(self, status: str, url: str | None = None) -> None:
        if (status, url) != (self.status, self.url):
            self.status, self.url = status, url
            self.on_change(self)

    def _run(self) -> None:
        while True:
            if not self.sharing:
                time.sleep(0.5)
                continue
            if not online():
                self._set("Waiting for the network: plug in the Ethernet cable.")
                time.sleep(3)
                continue
            generation = self.generation
            self.gate.token = secrets.token_urlsafe(24)
            self._set("Opening the secure link...")
            try:
                self.proc = subprocess.Popen(
                    [self.binary, "tunnel", "--no-autoupdate", "--url", f"http://127.0.0.1:{self.port}"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, errors="replace")
            except OSError as e:
                self._set(f"Could not start cloudflared: {e}")
                time.sleep(10)
                continue
            for line in self.proc.stderr:
                m = None if self.url else re.search(r"https://[-a-z0-9]+\.trycloudflare\.com", line)
                if m and m.group(0) != "https://api.trycloudflare.com":
                    self._set("Ready: Claude can connect now.", f"{m.group(0)}/{self.gate.token}/mcp")
            code = self.proc.wait()
            if self.sharing and generation == self.generation:
                log.warning("cloudflared exited (code %s); reconnecting", code)
                self._set("The link dropped; reconnecting...")
                time.sleep(5)

    def new_link(self) -> None:
        self.generation += 1
        self.sharing = True
        if self.proc:
            self.proc.terminate()

    def stop(self) -> None:
        self.close()
        self._set("Sharing stopped. Press N for a new link.")

    def close(self) -> None:
        self.generation += 1
        self.sharing = False
        self.gate.token = secrets.token_urlsafe(24)  # the old link stops working at once
        if self.proc:
            self.proc.terminate()


def found_lines() -> list[str]:
    if not PARTS:
        return ["(no Windows-related partitions on the internal disks)"]
    out = []
    for p in PARTS.values():
        status = "Windows found, " if p["windows"] else ""
        status += f"read-only at {p['mountpoint']}" if p["mountpoint"] else p["note"]
        out.append(f"{p['name']:<12} {p['kind']:<9} {p['size_gb']:>7} GB  {status}")
    return out


class Screen:
    """Full-screen status display on the PC's own monitor (Rescue USB, tty1), with keys N/S/P."""

    def __init__(self, link):
        self.link = link
        self.dirty = threading.Event()
        self.qr_for, self.qr = None, []

    def start(self) -> None:
        sys.stdout.write("\033[?25l")  # hide the cursor
        threading.Thread(target=self._draw_loop, daemon=True).start()
        threading.Thread(target=self._key_loop, daemon=True).start()
        self.refresh()

    def refresh(self) -> None:
        self.dirty.set()

    def _draw_loop(self) -> None:
        while True:
            self.dirty.wait(5)
            self.dirty.clear()
            try:
                self.draw()
            except Exception:
                log.exception("Screen update failed")

    def draw(self) -> None:
        cols, rows = shutil.get_terminal_size((80, 25))
        url = self.link.url
        if url != self.qr_for:
            self.qr_for, self.qr = url, qr_lines(url) if url else []
        lines = [" RESCUE AI - read-only PC check ".center(cols, "="), "", f" Status: {self.link.status}", ""]
        if url:
            lines.append(" Add this link to Claude (Settings > Connectors > Add custom connector):")
            lines += ["   " + url[i:i + cols - 4] for i in range(0, len(url), cols - 4)]
            lines.append("")
            if self.qr and len(lines) + len(self.qr) + 2 <= rows - 1 and len(self.qr[0]) + 3 <= cols:
                lines += ["   " + q for q in self.qr] + [""]
        lines += [" Found on this PC:"] + ["   " + f for f in found_lines()] + [""]
        free = rows - 2 - len(lines)
        if free > 1:
            lines += [" What Claude is doing:"] + ["   " + a for a in list(ACTIVITY)[-(free - 1):]]
        lines = lines[: rows - 1] + [""] * (rows - 1 - len(lines))
        footer = " [N] new link   [S] stop sharing   [P] power off"
        sys.stdout.write("\033[H\033[J" + "\n".join(l[:cols] for l in lines) + "\n" + footer[:cols])
        sys.stdout.flush()

    def _key_loop(self) -> None:
        try:
            import termios  # noqa: F401  (Linux only)
            import tty

            fd = sys.stdin.fileno()
            tty.setcbreak(fd)
        except Exception:
            return  # no keyboard attached to this process
        while True:
            data = os.read(fd, 1)
            if not data:
                return
            key = data.decode(errors="ignore").lower()
            if key == "n":
                self.link.new_link()
            elif key == "s":
                self.link.stop()
            elif key == "p":
                self.link.close()
                unmount_ours()
                subprocess.Popen(["systemctl", "poweroff"])
            self.refresh()


def link_changed(link) -> None:
    if SCREEN:
        SCREEN.refresh()
    elif link.url:
        announce(link.url)
    else:
        log.info(link.status)


def warm_up() -> None:
    """Index the System event log in the background so the first query is fast."""
    time.sleep(3)  # let the web server start first
    for p in PARTS.values():
        if p["windows"]:
            f = ci_path(Path(p["mountpoint"]), "Windows/System32/winevt/Logs/System.evtx")
            if f:
                try:
                    n = len(evtx_records(f))
                    log.info("Indexed the System event log on %s (%d events).", p["name"], n)
                except Exception as e:
                    log.warning("Could not read the System event log on %s: %s", p["name"], e)


def main() -> None:
    global ALLOW_PERSONAL, SCREEN
    ap = argparse.ArgumentParser(description="Rescue AI: read-only MCP server for examining a Windows PC.")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default="127.0.0.1",
                    help="use 0.0.0.0 together with --no-tunnel to serve a private network such as Tailscale")
    ap.add_argument("--no-tunnel", action="store_true", help="don't open a Cloudflare tunnel")
    ap.add_argument("--cloudflared", default="cloudflared", help="path to the cloudflared program")
    ap.add_argument("--allow-personal-files", action="store_true", help="let the AI read files under \\Users")
    ap.add_argument("--test-root", action="append", default=[], metavar="DIR",
                    help="treat DIR as a Windows partition instead of mounting disks (for testing)")
    ap.add_argument("--console", action="store_true",
                    help="full-screen display with keys N/S/P on the PC's monitor (used by the Rescue USB)")
    args = ap.parse_args()
    ALLOW_PERSONAL = args.allow_personal_files

    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    log_path = "/var/log/rescue-ai.log" if is_root else "rescue-ai.log"
    handlers: list[logging.Handler] = [logging.FileHandler(log_path)]
    if not args.console:  # in console mode the screen shows activity instead
        handlers.append(logging.StreamHandler(sys.stdout))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(message)s", datefmt="%H:%M:%S", force=True,
                        handlers=handlers)
    logging.getLogger("mcp").setLevel(logging.WARNING)

    if args.test_root:
        for path in args.test_root:
            add_test_root(path)
    elif not is_root:
        sys.exit("Please run with sudo (needed to read the disks): sudo bash start.sh")
    else:
        if args.console:
            run(["udevadm", "settle", "--timeout=15"])  # at boot, let the disks appear first
        discover()

    if not args.console:
        print("\nRescue AI - read-only mode. Found:")
        print("\n".join("  " + line for line in found_lines()))
    threading.Thread(target=warm_up, daemon=True).start()

    gate = TokenGate(mcp.streamable_http_app(), secrets.token_urlsafe(24))
    if args.no_tunnel:
        link = SimpleNamespace(status="Local network only (no tunnel).",
                               url=f"http://{args.host}:{args.port}/{gate.token}/mcp",
                               start=lambda: link_changed(link), new_link=lambda: None,
                               stop=lambda: None, close=lambda: None)
    else:
        link = Tunnel(args.cloudflared, args.port, gate, link_changed)
    if args.console:
        SCREEN = Screen(link)
        SCREEN.start()
    elif not args.no_tunnel:
        print("\nOpening the secure link (takes about 10 seconds)...", flush=True)
    link.start()

    try:
        uvicorn.run(gate, host=args.host, port=args.port, log_level="warning")
    finally:
        link.close()
        unmount_ours()
        log.info("Stopped. The link no longer works. Activity log: %s", log_path)


if __name__ == "__main__":
    main()
