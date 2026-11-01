#!/usr/bin/env python3
"""Rescue AI - one-day version.

A read-only MCP server that lets Claude (or any MCP client) examine a Windows
PC from a Linux live USB. Windows partitions are mounted read-only and no tool
can change anything on the PC.

Normally started by start.sh, which installs the dependencies first.
"""

import argparse
import collections
import contextlib
import datetime as dt
import fnmatch
import functools
import hashlib
import itertools
import json
import logging
import os
import queue
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import textwrap
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
Windows is NOT running.

How to work:
1. Call get_overview first. Ask the person what they see when Windows starts
   (error message, stop code, boot loop, black screen, when it began).
2. Investigate with crash_history, boot_check, query_event_log, recent_updates,
   recent_drivers, disk_health, windows_info, read_registry and read_text_file.
   Useful files: Windows\System32\LogFiles\Srt\SrtTrail.txt (Automatic Repair),
   Windows\Logs\CBS\CBS.log, Windows\INF\setupapi.dev.log, Windows\Panther\.
3. Explain the most likely cause in plain language and show your evidence.
4. Fix it:
   - Tools named request_* ask to change the PC. Nothing changes until the
     person at the PC presses Y on its screen. After a request, tell them what
     you asked for and why, then call get_job_status about every 20 seconds.
     Never send the same request twice.
   - Prefer the smallest change. Changes can be reverted with request_undo,
     except clearing hibernation and commands.
   - Repairs that need Windows' own tools (SFC, DISM, bcdboot, chkdsk) can't run
     here yet: give the person step-by-step instructions for the Windows
     Recovery Environment instead.
   - request_run_command only works after the person turns on Expert mode.
   - If disk health is bad, change nothing: tell them to copy their files first.

Notes:
- Event-log "days" count back from the newest event in that log, because the
  PC may have been broken for a while.
- Paths are relative to a partition (default: the Windows partition); drive
  letters such as C: are ignored.
- Personal files under \Users are private unless the owner allowed them.
- Never ask for passwords or BitLocker recovery keys in chat, and never try to
  reset or bypass Windows passwords.
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
CHANGES = ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False)


class UserError(Exception):
    """A problem the AI can act on; returned to it as {"error": ...}."""


def tool(fn=None, *, change: bool = False, locked: bool = True):
    """Register fn as an MCP tool, log each call, and catch errors.

    change=True marks request_* tools: they only create a job that the person
    at the PC must approve. locked=False lets a tool answer while a change runs."""
    if fn is None:
        return functools.partial(tool, change=change, locked=locked)

    def call(kwargs):
        with _LOCK if locked else contextlib.nullcontext():
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

    return mcp.tool(annotations=CHANGES if change else READ_ONLY)(wrapper)


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
        failing = None
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
            if failing is None:
                failing = smart_quick(disk["path"]) == "FAILED"
            info = {
                "name": part["name"], "device": part["path"], "disk": disk["name"], "kind": kind,
                "label": part.get("label") or part.get("partlabel"), "size_gb": gb(part.get("size")),
                "mountpoint": None, "note": "", "windows": False, "disk_failed": failing,
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
        "size_gb": 0.0, "mountpoint": str(root), "note": "", "windows": windows, "disk_failed": False,
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


HIVE_COPIES = Path(tempfile.gettempdir()) / "rescue-ai-hives"


def open_hive(path: Path | None):
    if path is None:
        raise UserError("Hive file not found")
    from regipy.registry import RegistryHive

    key = str(path)
    if key not in _HIVES:
        # Read a copy, so no file stays open on the Windows partition: it must be
        # possible to unmount it when a change is approved.
        HIVE_COPIES.mkdir(parents=True, exist_ok=True)
        copy = HIVE_COPIES / f"{hashlib.sha1(key.encode()).hexdigest()[:12]}-{path.name}"
        shutil.copyfile(path, copy)
        _HIVES[key] = RegistryHive(str(copy))
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
        "changes": "each request_* change needs Y on the PC's screen; expert mode (commands) is "
                   + ("ON" if EXPERT else "off"),
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

    key_path = normalize_key(upper, key, top)
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


# ---------------------------------------------------------------- changes (each one approved at the PC)


EXPERT = False  # the owner turns this on with E on the screen; it allows request_run_command
JOBS: dict[int, dict] = {}
_JOB_IDS = itertools.count(1)
_APPROVED: queue.Queue = queue.Queue()
JOB_EXPIRY_SECONDS = 15 * 60
WARMED = threading.Event()  # set when background event-log indexing is done
REG_TYPES = {"REG_SZ": 1, "REG_EXPAND_SZ": 2, "REG_BINARY": 3, "REG_DWORD": 4, "REG_MULTI_SZ": 7, "REG_QWORD": 11}
WRITABLE_HIVES = ("SYSTEM", "SOFTWARE", "DEFAULT")
# Drivers Windows can't start without: disabling one puts a warning on the approval card.
CRITICAL_DRIVERS = {
    "acpi", "pci", "disk", "partmgr", "volmgr", "volmgrx", "volume", "mountmgr", "ntfs", "refs", "fltmgr",
    "storahci", "stornvme", "storport", "iastorvd", "iastorav", "iastora", "vmd", "classpnp", "ksecdd",
    "cng", "wdf01000", "fvevol", "volsnap", "spaceport", "pdc", "msrpc", "tm", "clfs",
}


def job_view(job: dict) -> dict:
    return {k: v for k, v in job.items() if not k.startswith("_")}


def pending_jobs() -> list[dict]:
    """Jobs waiting for the person at the PC, oldest first (expired ones are marked on the way)."""
    waiting = []
    for job in JOBS.values():
        if job["state"] == "waiting_for_approval":
            if time.time() - job["_created"] > JOB_EXPIRY_SECONDS:
                job["state"] = "expired"
            else:
                waiting.append(job)
    return waiting


def print_card(job: dict) -> None:
    bar = "!" * 74
    lines = [bar, f"  CLAUDE ASKS TO CHANGE THIS PC  (job {job['id']}, risk: {job['risk']})", f"  {job['title']}"]
    lines += [f"    {d}" for d in job["details"]]
    lines += [f"  Reason given by the AI: {job['ai_reason']}",
              "  " + ("Can be undone later." if job["reversible"] else "This cannot be undone."),
              "  Press Y to approve or N to reject.", bar]
    print("\a\n" + "\n".join(lines), flush=True)


def new_job(kind: str, title: str, details: list[str], risk: str, reason: str, run_fn,
            reversible: bool = True) -> dict:
    """Queue a change for approval on the PC's screen. run_fn(job) does the work once approved."""
    job = {"id": next(_JOB_IDS), "kind": kind, "title": title, "details": details, "risk": risk,
           "reversible": reversible, "ai_reason": reason, "state": "waiting_for_approval",
           "requested_at": dt.datetime.now().strftime("%H:%M:%S"), "result": None,
           "_run": run_fn, "_created": time.time(), "_undo": None}
    JOBS[job["id"]] = job
    ACTIVITY.append(f"{job['requested_at']}  AI ASKS TO CHANGE: {title} (job {job['id']})")
    log.info("Job %d requested: %s | %s | reason: %s", job["id"], title, " | ".join(details), reason)
    if SCREEN:
        SCREEN.refresh()
    else:
        print_card(job)
    return {"job_id": job["id"], "state": job["state"],
            "note": "Nothing has changed yet. The person at the PC must press Y on its screen to approve. "
                    "Tell them what you asked for and why, then check get_job_status every ~20 seconds."}


def decide(approve: bool) -> None:
    """The person at the PC pressed Y or N: decide the oldest waiting job."""
    waiting = pending_jobs()
    if not waiting:
        return
    job = waiting[0]
    job["state"] = "approved" if approve else "rejected"
    job["decided_at"] = dt.datetime.now().strftime("%H:%M:%S")
    word = "APPROVED" if approve else "rejected"
    ACTIVITY.append(f"{job['decided_at']}  Owner {word} job {job['id']}: {job['title']}")
    log.info("Job %d %s at the PC", job["id"], word)
    if not SCREEN:
        print(f"  Job {job['id']} {word}.", flush=True)
    if approve:
        _APPROVED.put(job["id"])


def run_job(job: dict) -> None:
    job["state"] = "running"
    if SCREEN:
        SCREEN.refresh()
    with _LOCK:
        try:
            job["result"] = job["_run"](job) or {}
            job["state"] = "done"
        except UserError as e:
            job["state"], job["result"] = "failed", {"error": str(e)}
        except Exception as e:
            log.exception("Job %d failed", job["id"])
            job["state"], job["result"] = "failed", {"error": f"{type(e).__name__}: {e}"}
    line = f"{dt.datetime.now():%H:%M:%S}  Job {job['id']} {job['state'].upper()}: {job['title']}"
    ACTIVITY.append(line)
    log.info("%s | %s", line, job["result"])
    if SCREEN:
        SCREEN.refresh()
    else:
        print("  " + line, flush=True)


def job_worker() -> None:
    while True:
        run_job(JOBS[_APPROVED.get()])


def release_caches() -> None:
    """Forget everything read from the disks (before unmounting, and after a change)."""
    _HIVES.clear()
    _EVTX_CACHE.clear()
    folder_names.cache_clear()


def ntfs_hint(error: str) -> str:
    low = error.lower()
    if "hibernat" in low:
        return ("Windows is hibernated (Fast Startup or hibernate), so writing would damage it. "
                "Use request_clear_hibernation first.")
    if "unclean" in low or "metadata kept in windows cache" in low:
        return ("Windows was not shut down cleanly, so writing could damage it. If Fast Startup is on, "
                "request_clear_hibernation fixes this; otherwise chkdsk must run from Windows Recovery.")
    return "Could not open the partition for writing: " + error.strip()


@contextlib.contextmanager
def writable(part: dict, extra_options: str = ""):
    """Remount one partition read-write for a single approved change, then always back to read-only."""
    if not part.get("device"):  # --test-root folders are plain folders
        yield Path(part["mountpoint"])
        release_caches()
        return
    dev, name = part["device"], part["name"]
    WARMED.wait(120)  # don't unmount while the event log is still being indexed
    release_caches()
    if part.get("mountpoint") and run(["umount", part["mountpoint"]]).returncode != 0:
        raise UserError("The partition is in use (maybe a shell on screen 2 is inside it). Close it and try again.")
    part["mountpoint"] = None
    target = MOUNT_BASE / name
    try:
        run(["blockdev", "--setrw", dev])
        target.mkdir(parents=True, exist_ok=True)
        if part["kind"] == "efi":
            cmd = ["mount", "-t", "vfat", "-o", "rw", dev, str(target)]
        else:
            options = "rw,windows_names" + (f",{extra_options}" if extra_options else "")
            cmd = ["mount", "-t", "ntfs-3g", "-o", options, dev, str(target)]
        p = run(cmd)
        if p.returncode != 0:
            raise UserError(ntfs_hint(p.stderr or p.stdout))
        mounted = mount_info(dev)
        if not mounted or mounted[1]:
            # ntfs-3g quietly falls back to read-only on a hibernated or uncleanly shut-down volume
            run(["umount", str(target)])
            raise UserError(ntfs_hint((p.stderr or p.stdout).strip() or "Windows is hibernated or unclean"))
        try:
            yield target
        finally:
            run(["sync"])
            if run(["umount", str(target)]).returncode != 0:
                run(["umount", "-l", str(target)])
    finally:
        part["mountpoint"], part["note"] = mount_readonly(dev, name, part["kind"])
        release_caches()


def check_can_change(part: dict) -> None:
    if part.get("disk_failed"):
        raise UserError("This disk reports failing health (SMART). Changes are blocked: copy important files first.")
    if part["kind"] not in ("ntfs", "efi"):
        raise UserError(f"{part['name']} can't be changed.")


def check_write_path(rel: str) -> None:
    low = rel.replace("\\", "/").lstrip("/").lower()
    if any(re.search(p, low) for p in DENY_PATTERNS):
        raise UserError("That file can't be changed here (registry hives, passwords, keys or memory files). "
                        "Use the registry tools for registry changes.")
    if low.startswith("users/") and low.count("/") >= 2 and not ALLOW_PERSONAL:
        raise UserError("Personal files are off-limits unless the owner allowed them.")
    if low.startswith("rescueai/"):
        raise UserError("The RescueAI folder holds undo data; use request_undo instead.")


def rel_to(root, path) -> str:
    return os.path.relpath(path, root)


def undo_folder(root: Path, job: dict) -> Path:
    folder = root / "RescueAI" / "undo" / f"{dt.datetime.now():%Y%m%d-%H%M%S}-job{job['id']}"
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def record_undo(job: dict, root: Path, folder: Path | None, records: list[dict]) -> None:
    """Keep undo data on the job, plus undo.json on the partition as a record of what changed."""
    job["_undo"] = records
    folder = folder or undo_folder(root, job)
    (folder / "undo.json").write_text(json.dumps({"job": job_view(job), "undo": records}, indent=1, default=str))


def hive_file(hive: str) -> tuple[str, str]:
    """(path of a writable hive relative to the Windows partition, normalised hive name)."""
    upper = hive.strip().upper()
    if upper in WRITABLE_HIVES:
        return f"Windows/System32/config/{upper}", upper
    if upper.startswith("NTUSER:"):
        user = hive.strip().split(":", 1)[1]
        return f"Users/{user}/NTUSER.DAT", f"NTUSER:{user}"
    raise UserError("Changes are allowed in the SYSTEM, SOFTWARE, DEFAULT and NTUSER:<username> hives only.")


def normalize_key(hive_name: str, key: str, top) -> str:
    key_path = re.sub(r"^(HKLM|HKEY_LOCAL_MACHINE|HKCU|HKEY_CURRENT_USER)[\\/]+", "", key.strip(), flags=re.I)
    key_path = re.sub(rf"^{re.escape(hive_name.split(':')[0])}[\\/]+", "", key_path, flags=re.I)
    if hive_name == "SYSTEM":
        key_path = re.sub(r"(?i)^CurrentControlSet", control_set(top), key_path)
    return key_path.replace("/", "\\").strip("\\")


def encode_reg(type_name: str, data: str) -> tuple[int, bytes]:
    t = REG_TYPES.get(type_name.upper())
    if t is None:
        raise UserError(f"value_type must be one of {', '.join(REG_TYPES)}")
    try:
        if t in (1, 2):
            return t, (data + "\0").encode("utf-16-le")
        if t == 4:
            return t, struct.pack("<I", int(data, 0) & 0xFFFFFFFF)
        if t == 11:
            return t, struct.pack("<Q", int(data, 0) & 0xFFFFFFFFFFFFFFFF)
        if t == 7:
            return t, ("\0".join(data.splitlines()) + "\0\0").encode("utf-16-le")
        return t, bytes.fromhex(data.replace(" ", ""))
    except ValueError as e:
        raise UserError(f"data doesn't fit {type_name}: {e}")


def show_reg(t: int, raw: bytes) -> str:
    try:
        if t in (1, 2):
            return repr(raw.decode("utf-16-le").rstrip("\0"))
        if t == 4:
            return str(struct.unpack_from("<I", raw)[0])
        if t == 11:
            return str(struct.unpack_from("<Q", raw)[0])
        if t == 7:
            return repr([s for s in raw.decode("utf-16-le").split("\0") if s])
    except (UnicodeDecodeError, struct.error):
        pass
    return raw[:64].hex(" ")


def hive_dirty(path: Path) -> bool:
    """True if the hive still has changes waiting in its .LOG files (editing it would lose them)."""
    with open(path, "rb") as f:
        header = f.read(12)
    primary, secondary = struct.unpack_from("<II", header, 4)
    return header[:4] == b"regf" and primary != secondary


def hivex_apply(path: Path, changes: list[tuple]) -> list[tuple | None]:
    """Apply (key_path, value_name, type, data) changes to a hive file; data None deletes the value.

    Returns each value's old (type, data), or None where it didn't exist. Nothing is written
    unless every change succeeds."""
    try:
        import hivex
    except ImportError:
        raise UserError("Registry editing needs the hivex library (python3-hivex), which isn't installed.")
    if hive_dirty(path):
        raise UserError("This registry hive has unsaved changes in its log files (Windows didn't shut down "
                        "cleanly). Editing it now could lose them; Windows or Windows Recovery must open it first.")
    h = hivex.Hivex(str(path), write=True)
    olds = []
    for key_path, name, rtype, data in changes:
        node = h.root()
        for part in (p for p in re.split(r"[\\/]+", key_path) if p):
            node = next((c for c in h.node_children(node) if h.node_name(c).lower() == part.lower()), None)
            if node is None:
                raise UserError(f"Registry key not found: {key_path}")
        old, keep = None, []
        for v in h.node_values(node):
            t, raw = h.value_value(v)
            if h.value_key(v).lower() == name.lower():
                old = (t, raw)
            else:
                keep.append({"key": h.value_key(v), "t": t, "value": raw})
        if data is not None:
            keep.append({"key": name, "t": rtype, "value": data})
        h.node_set_values(node, keep)
        olds.append(old)
    h.commit(None)
    return olds


def registry_undo(part: dict, rel: str, names: list[tuple[str, str]], olds: list) -> dict:
    values = [{"key": key, "name": name, "old_type": old[0] if old else None, "old_hex": old[1].hex() if old else ""}
              for (key, name), old in zip(names, olds)]
    return {"type": "registry", "part": part["name"], "hive": rel, "values": values}


def apply_undo(record: dict) -> None:
    if record["type"] == "boot_order":
        p = run(["efibootmgr", "-o", ",".join(record["order"])])
        if p.returncode != 0:
            raise UserError("efibootmgr failed: " + p.stderr.strip())
        return
    with writable(PARTS[record["part"]]) as root:
        if record["type"] == "registry":
            hivex_apply(ci_path(root, record["hive"]), [
                (v["key"], v["name"], v["old_type"], bytes.fromhex(v["old_hex"]) if v["old_type"] is not None else None)
                for v in record["values"]])
        elif record["type"] == "rename":
            os.rename(ci_path(root, record["from"]), root / record["to"])
        elif record["type"] == "copy":
            target = ci_path(root, record["target"])
            if record["backup"]:
                shutil.copy2(ci_path(root, record["backup"]), root / record["target"])
            elif target:
                os.remove(target)


def uefi_boot_menu() -> tuple[list[str], dict[str, str]]:
    """(BootOrder, {entry number: label}) from efibootmgr."""
    if not shutil.which("efibootmgr") or not Path("/sys/firmware/efi").exists():
        raise UserError("This PC isn't booted in UEFI mode, or efibootmgr is missing.")
    p = run(["efibootmgr"])
    if p.returncode != 0:
        raise UserError("Can't read the UEFI boot menu: " + p.stderr.strip())
    order = re.search(r"^BootOrder:\s*(\S+)", p.stdout, re.M)
    entries = {n.upper(): re.split(r"\t|\s{2,}", rest)[0].strip()
               for n, rest in re.findall(r"^Boot([0-9A-Fa-f]{4})\*?\s+(.*)$", p.stdout, re.M)}
    return (order.group(1).upper().split(",") if order else []), entries


@tool(change=True)
def request_set_registry_value(hive: str, key: str, value_name: str, value_type: str, data: str,
                               reason: str, partition: str = "") -> dict:
    """Ask to set one value in the offline Windows registry (the person approves it on the PC's screen).

    hive: SYSTEM, SOFTWARE, DEFAULT or NTUSER:<username>.
    key: e.g. "CurrentControlSet\\Control\\Session Manager\\Power" (HKLM\\ prefixes are fine).
    value_type: REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, REG_MULTI_SZ (one item per line) or REG_BINARY (hex).
    data: the new value as text, e.g. "0" for a DWORD. The old value is kept for request_undo."""
    part = get_part(partition)
    check_can_change(part)
    rel, hive_name = hive_file(hive)
    path = ci_path(Path(part["mountpoint"]), rel)
    if path is None:
        raise UserError(f"Hive {hive} was not found on this PC.")
    top = hive_root(open_hive(path))
    key_path = normalize_key(hive_name, key, top)
    current = reg_values(subkey(top, key_path))  # also checks that the key exists
    name = "" if value_name in ("", "(default)") else value_name
    old = next((v for k, v in current.items() if k.lower() == (name or "(default)").lower()), None)
    rtype, raw = encode_reg(value_type, data)

    def run_fn(job):
        with writable(part) as root:
            olds = hivex_apply(ci_path(root, rel), [(key_path, name, rtype, raw)])
            record_undo(job, root, None, [registry_undo(part, rel, [(key_path, name)], olds)])
        return {"changed": f"{hive_name}\\{key_path}\\{name or '(default)'}", "new": show_reg(rtype, raw),
                "old": show_reg(*olds[0]) if olds[0] else "(did not exist)"}

    shown_old = fmt_value(old) if old is not None else "(does not exist)"
    return new_job("registry", f"Set registry value {name or '(default)'}",
                   [f"Key:   {hive_name}\\{key_path}", f"Value: {name or '(default)'} ({value_type.upper()})",
                    f"Now:   {shown_old}", f"New:   {show_reg(rtype, raw)}"],
                   "medium", reason, run_fn)


@tool(change=True)
def request_disable_driver(name: str, reason: str, partition: str = "") -> dict:
    """Ask to stop a driver or service from loading when Windows starts (Start=4 in every control set).
    Use it for a bad third-party driver that crashes Windows or blocks start-up. Reversible."""
    part = get_part(partition)
    check_can_change(part)
    rel = "Windows/System32/config/SYSTEM"
    top = hive_root(open_hive(ci_path(Path(part["mountpoint"]), rel)))
    found = []
    for cs in (k.name for k in top.iter_subkeys() if re.fullmatch(r"(?i)ControlSet\d{3}", k.name)):
        try:
            svc = subkey(top, f"{cs}/Services/{name}")
        except UserError:
            continue
        found.append((f"{cs}\\Services\\{svc.name}", reg_values(svc)))
    if not found:
        raise UserError(f"No driver or service named {name!r} in the SYSTEM hive.")
    values = found[0][1]
    starts = {0: "boot", 1: "system", 2: "automatic", 3: "manual", 4: "disabled"}
    control_sets = ", ".join(k.split("\\")[0] for k, _ in found)
    details = [f"Driver/service: {name}", f"File: {values.get('ImagePath', '(default location)')}",
               f"Now starts: {starts.get(values.get('Start'), values.get('Start'))}", "New: disabled (Start=4)",
               f"In: {control_sets}"]
    risk = "medium"
    if name.lower() in CRITICAL_DRIVERS:
        risk = "high"
        details.append("WARNING: Windows needs this driver to start. Disabling it will probably stop Windows booting.")
    keys = [k for k, _ in found]

    def run_fn(job):
        with writable(part) as root:
            olds = hivex_apply(ci_path(root, rel), [(k, "Start", 4, struct.pack("<I", 4)) for k in keys])
            record_undo(job, root, None, [registry_undo(part, rel, [(k, "Start") for k in keys], olds)])
        return {"disabled": name, "control_sets": len(keys)}

    return new_job("disable_driver", f"Disable driver/service {name}", details, risk, reason, run_fn)


@tool(change=True)
def request_rename_file(path: str, new_name: str, reason: str, partition: str = "") -> dict:
    """Ask to rename a file or folder on a Windows or EFI partition (nothing is deleted).
    Typical use: rename a corrupt driver so a good copy can be put in its place. Reversible."""
    part, target = resolve(path, partition)
    check_can_change(part)
    rel = rel_to(part["mountpoint"], target)
    check_write_path(rel)
    if not new_name or re.search(r'[\\/:*?"<>|]', new_name):
        raise UserError("new_name must be a plain name, without folders.")
    if ci_path(target.parent, new_name) is not None:
        raise UserError(f"{new_name} already exists in that folder.")
    check_write_path(str(Path(rel).parent / new_name))

    def run_fn(job):
        with writable(part) as root:
            src = ci_path(root, rel)
            if src is None:
                raise UserError("The file is no longer there.")
            dst = src.parent / new_name
            os.rename(src, dst)
            record_undo(job, root, None, [{"type": "rename", "part": part["name"],
                                           "from": rel_to(root, dst), "to": rel_to(root, src)}])
        return {"renamed": rel, "to": new_name}

    return new_job("rename", f"Rename {Path(rel).name} to {new_name}",
                   [f"Partition: {part['name']}", f"File: {rel}", f"New name: {new_name}"], "medium", reason, run_fn)


@tool(change=True)
def request_copy_file(source_path: str, target_path: str, reason: str, source_partition: str = "",
                      target_partition: str = "") -> dict:
    """Ask to copy one file onto a Windows or EFI partition, e.g. restore a damaged driver from
    Windows\\System32\\DriverStore\\FileRepository, or put back a missing EFI boot file from
    Windows\\Boot\\EFI. An existing target file is backed up first. Reversible."""
    src_part, src = resolve(source_path, source_partition)
    if src.is_dir():
        raise UserError("Only single files can be copied.")
    check_readable(src_part, src)
    dst_part = get_part(target_partition)
    check_can_change(dst_part)
    dst_rel = re.sub(r"^[A-Za-z]:", "", target_path.strip()).replace("\\", "/").strip("/")
    check_write_path(dst_rel)
    parent = ci_path(Path(dst_part["mountpoint"]), str(Path(dst_rel).parent))
    if parent is None or not parent.is_dir():
        raise UserError("The target folder does not exist.")
    exists = ci_path(Path(dst_part["mountpoint"]), dst_rel) is not None
    src_rel = rel_to(src_part["mountpoint"], src)
    size = src.stat().st_size

    def run_fn(job):
        with writable(dst_part) as root:
            # re-find the source: its partition may be the one that was just remounted
            source = ci_path(root if src_part is dst_part else Path(src_part["mountpoint"]), src_rel)
            target = ci_path(root, dst_rel) or ci_path(root, str(Path(dst_rel).parent)) / Path(dst_rel).name
            folder = undo_folder(root, job)
            backup = None
            if target.exists():
                saved = folder / "original" / target.name
                saved.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(target, saved)
                backup = rel_to(root, saved)
            shutil.copy2(source, target)
            record_undo(job, root, folder, [{"type": "copy", "part": dst_part["name"],
                                             "target": rel_to(root, target), "backup": backup}])
        return {"copied": src_rel, "to": dst_rel, "bytes": size, "replaced_existing_file": backup is not None}

    details = [f"From: {src_part['name']}: {src_rel} ({size:,} bytes)", f"To:   {dst_part['name']}: {dst_rel}",
               "The existing file is backed up first." if exists else "This creates a new file."]
    return new_job("copy", f"Copy {Path(src_rel).name} to {dst_part['name']}", details, "medium", reason, run_fn)


@tool(change=True)
def request_clear_hibernation(reason: str, disable_fast_startup: bool = True, partition: str = "") -> dict:
    """Ask to remove Windows' hibernation file so the partition can be changed safely, and by default
    turn off Fast Startup so it doesn't come back. NOT reversible: anything left open in Windows apps
    when it was hibernated is lost (a normal Fast Startup shutdown loses nothing)."""
    part = get_part(partition)
    check_can_change(part)
    root = Path(part["mountpoint"])
    cs = control_set(hive_root(open_hive(ci_path(root, "Windows/System32/config/SYSTEM"))))
    power_key = f"{cs}\\Control\\Session Manager\\Power"

    def run_fn(job):
        result = {}
        with writable(part, "remove_hiberfile") as root_w:
            result["hibernation_file_present"] = ci_path(root_w, "hiberfil.sys") is not None
            if disable_fast_startup:
                try:
                    hivex_apply(ci_path(root_w, "Windows/System32/config/SYSTEM"),
                                [(power_key, "HiberbootEnabled", 4, struct.pack("<I", 0))])
                    result["fast_startup_disabled"] = True
                except UserError as e:
                    result["fast_startup_disabled"], result["note"] = False, str(e)
        return result

    details = [f"Partition: {part['name']}", f"Hibernated now: {'yes' if hibernated(root) else 'no'}",
               "Removes hiberfil.sys: Windows starts fresh instead of resuming.",
               "Turns off Fast Startup (HiberbootEnabled=0)." if disable_fast_startup else "Leaves Fast Startup as it is.",
               "Anything left open in Windows apps when it hibernated is lost."]
    return new_job("clear_hibernation", "Clear Windows hibernation", details, "medium", reason, run_fn,
                   reversible=False)


@tool(change=True)
def request_boot_order(first_entry: str, reason: str) -> dict:
    """Ask to move one entry to the front of the PC's UEFI boot menu. first_entry is its number
    (e.g. "0001") or part of its name (e.g. "Windows Boot Manager"). Reversible."""
    order, entries = uefi_boot_menu()
    wanted = first_entry.strip().upper().removeprefix("BOOT")
    matches = [n for n in entries if n == wanted] or [n for n, label in entries.items()
                                                      if first_entry.strip().lower() in label.lower()]
    if len(matches) != 1:
        raise UserError(f"{len(matches)} entries match. Entries: " + "; ".join(f"{n} {l}" for n, l in entries.items()))
    first = matches[0]
    new_order = [first] + [n for n in order if n != first]

    def run_fn(job):
        p = run(["efibootmgr", "-o", ",".join(new_order)])
        if p.returncode != 0:
            raise UserError("efibootmgr failed: " + p.stderr.strip())
        job["_undo"] = [{"type": "boot_order", "order": order}]
        return {"boot_order": new_order}

    def names(o):
        return ", ".join(f"{n} {entries.get(n, '?')}" for n in o)

    return new_job("boot_order", f"Boot '{entries[first]}' first",
                   [f"Now: {names(order)}", f"New: {names(new_order)}"], "low", reason, run_fn)


@tool(change=True)
def request_run_command(command: str, reason: str, writable_partitions: list[str] | None = None) -> dict:
    """EXPERT MODE ONLY: ask to run one bash command as root on the rescue system. Partitions are
    mounted at /mnt/rescue/<name>; those listed in writable_partitions are read-write while the
    command runs, all others stay read-only. The person sees the exact command before approving.
    Times out after 10 minutes. Not reversible."""
    if not EXPERT:
        raise UserError("Expert mode is off. Ask the person to press E on the PC's screen if they want to allow commands.")
    parts = [get_part(n) for n in writable_partitions or []]
    for p in parts:
        check_can_change(p)

    def run_fn(job):
        if not EXPERT:
            raise UserError("Expert mode was turned off before the command ran.")
        with contextlib.ExitStack() as stack:
            for p in parts:
                stack.enter_context(writable(p))
            try:
                done = subprocess.run(["bash", "-c", command], capture_output=True, text=True, errors="replace",
                                      timeout=600)
            except subprocess.TimeoutExpired:
                raise UserError("The command timed out after 10 minutes.")
        out = done.stdout + (f"\n[stderr]\n{done.stderr}" if done.stderr.strip() else "")
        return {"exit_code": done.returncode, "output": clip(out, 30_000, tail=True)}

    details = [f"Command: {command}",
               "Writable while it runs: " + (", ".join(p["name"] for p in parts) or "nothing (all read-only)")]
    return new_job("command", "Run a command (expert mode)", details, "high", reason, run_fn, reversible=False)


@tool(change=True)
def request_undo(job_id: int, reason: str) -> dict:
    """Ask to revert a completed change from this session (registry values, disabled drivers,
    renamed or copied files, boot order). Needs approval like any change."""
    job = JOBS.get(job_id)
    if not job or job["state"] != "done" or not job.get("_undo"):
        raise UserError("Only completed, reversible changes from this session can be undone.")
    if job.get("undone_by"):
        raise UserError(f"Job {job_id} was already undone by job {job['undone_by']}.")
    records = job["_undo"]

    def run_fn(undo_job):
        for record in records:
            apply_undo(record)
        job["undone_by"] = undo_job["id"]
        return {"undone": job_id}

    return new_job("undo", f"Undo job {job_id}: {job['title']}", [f"Reverts: {job['title']}"] + job["details"],
                   "low", reason, run_fn, reversible=False)


@tool(locked=False)
def get_job_status(job_id: int) -> dict:
    """State of a change you requested: waiting_for_approval, approved, running, done, failed,
    rejected or expired, with its result."""
    pending_jobs()  # marks expired ones
    job = JOBS.get(job_id)
    if not job:
        raise UserError(f"No job {job_id} in this session.")
    return job_view(job)


@tool(locked=False)
def list_jobs() -> dict:
    """All changes requested in this session and their states."""
    pending_jobs()
    return {"expert_mode": EXPERT, "jobs": [job_view(j) for j in JOBS.values()]}


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
    print(f"\n{bar}\n  Rescue AI is ready. Give this link to Claude:\n\n    {url}\n", flush=True)
    print_qr(url)
    print("  claude.ai / Claude Desktop: Settings > Connectors > Add custom connector\n"
          f"  Claude Code: claude mcp add --transport http rescue {url}\n\n"
          "  Copy in this terminal with Ctrl+Shift+C. The link is also saved in /tmp/rescue-ai-link.txt\n"
          "  Anyone with this link can READ this PC's disk. Changes happen only when you press Y here.\n"
          "  Keys: Y/N approve or reject a change, L new link, S stop sharing, E expert mode. Ctrl+C stops.\n"
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
        self._set("Sharing stopped. Press L for a new link.")

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
    """Full-screen status display on the PC's own monitor (Rescue USB, tty1).

    A waiting change request takes over the top of the screen until Y or N is pressed."""

    def __init__(self, link):
        self.link = link
        self.dirty = threading.Event()
        self.qr_for, self.qr = None, []
        self.belled: set[int] = set()

    def start(self) -> None:
        sys.stdout.write("\033[?25l")  # hide the cursor
        threading.Thread(target=self._draw_loop, daemon=True).start()
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

        def wrapped(text: str, indent: int) -> list[str]:
            return textwrap.wrap(text, cols - indent, initial_indent=" " * indent, subsequent_indent=" " * indent) or [""]

        mode = "EXPERT MODE" if EXPERT else "PC check"
        lines = [f" RESCUE AI - {mode} ".center(cols, "="), "", f" Status: {self.link.status}", ""]
        waiting = pending_jobs()
        bell = ""
        if waiting:
            job = waiting[0]
            if job["id"] not in self.belled:
                self.belled.add(job["id"])
                bell = "\a"
            more = f"   (+{len(waiting) - 1} more waiting)" if len(waiting) > 1 else ""
            lines += ["!" * cols, f" CLAUDE ASKS TO CHANGE THIS PC  -  risk: {job['risk'].upper()}{more}", ""]
            lines += wrapped(job["title"], 3)
            for d in job["details"]:
                lines += wrapped(d, 5)
            lines += wrapped(f"Reason given by the AI: {job['ai_reason']}", 3)
            lines += ["   " + ("Can be undone later." if job["reversible"] else "This cannot be undone."), "",
                      "   Press Y to approve or N to reject.", "!" * cols, ""]
        elif url:
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
        if waiting:
            footer = " [Y] approve   [N] reject"
        else:
            footer = " [L] new link   [S] stop sharing   [E] expert mode   [P] power off"
        sys.stdout.write(bell + "\033[H\033[J" + "\n".join(l[:cols] for l in lines) + "\n" + footer[:cols])
        sys.stdout.flush()


_TTY_STATE = None  # (fd, settings) to restore when the agent exits


def key_loop(link) -> None:
    """Keys on the PC: Y/N decide the waiting change; L, S, E and P manage the link, expert mode and power."""
    global EXPERT, _TTY_STATE
    try:
        import termios
        import tty

        fd = sys.stdin.fileno()
        _TTY_STATE = (fd, termios.tcgetattr(fd))
        tty.setcbreak(fd)
    except Exception:
        return  # no keyboard attached to this process
    while True:
        data = os.read(fd, 1)
        if not data:
            return
        key = data.decode(errors="ignore").lower()
        if key in ("y", "n"):
            decide(key == "y")
        elif key == "l":
            link.new_link()
        elif key == "s":
            link.stop()
        elif key == "e":
            EXPERT = not EXPERT
            word = "ON: Claude may ask to run commands (each one still needs Y)" if EXPERT else "OFF"
            ACTIVITY.append(f"{dt.datetime.now():%H:%M:%S}  Expert mode {word}")
            log.info("Expert mode %s", word)
        elif key == "p" and SCREEN:
            link.close()
            unmount_ours()
            subprocess.Popen(["systemctl", "poweroff"])
        if SCREEN:
            SCREEN.refresh()


def restore_tty() -> None:
    if _TTY_STATE:
        import termios

        termios.tcsetattr(_TTY_STATE[0], termios.TCSADRAIN, _TTY_STATE[1])


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
    WARMED.set()


def main() -> None:
    global ALLOW_PERSONAL, SCREEN
    ap = argparse.ArgumentParser(description="Rescue AI: MCP server for examining and repairing a Windows PC.")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default="127.0.0.1",
                    help="use 0.0.0.0 together with --no-tunnel to serve a private network such as Tailscale")
    ap.add_argument("--no-tunnel", action="store_true", help="don't open a Cloudflare tunnel")
    ap.add_argument("--cloudflared", default="cloudflared", help="path to the cloudflared program")
    ap.add_argument("--allow-personal-files", action="store_true", help="let the AI read files under \\Users")
    ap.add_argument("--test-root", action="append", default=[], metavar="DIR",
                    help="treat DIR as a Windows partition instead of mounting disks (for testing)")
    ap.add_argument("--console", action="store_true",
                    help="full-screen display on the PC's monitor (used by the Rescue USB)")
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
        print("\nRescue AI - Windows is read-only until you approve a change. Found:")
        print("\n".join("  " + line for line in found_lines()))
    threading.Thread(target=warm_up, daemon=True).start()
    threading.Thread(target=job_worker, daemon=True).start()

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
    threading.Thread(target=key_loop, args=(link,), daemon=True).start()

    try:
        uvicorn.run(gate, host=args.host, port=args.port, log_level="warning")
    finally:
        link.close()
        unmount_ours()
        restore_tty()
        log.info("Stopped. The link no longer works. Activity log: %s", log_path)


if __name__ == "__main__":
    main()
