"""Integration test for approved changes on real Linux (run as root; CI runs it with sudo).

Builds an NTFS disk image with a real Windows SYSTEM hive and a hibernation file, then checks:
read-only protection, refusing to write while hibernated, clearing hibernation, registry edits
with hivex, disabling a driver, renaming a file, "partition busy" handling, and undo.
"""
import asyncio
import lzma
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rescue_agent as ra  # noqa: E402

SYSTEM_HIVE_URL = "https://raw.githubusercontent.com/mkorman90/regipy/master/regipy_tests/data/SYSTEM.xz"
POWER = "ControlSet001\\Control\\Session Manager\\Power"


def sh(*cmd, check=True):
    p = subprocess.run(cmd, capture_output=True, text=True)
    if check and p.returncode:
        sys.exit(f"{' '.join(cmd)} failed: {p.stderr}")
    return p


def check(label, cond):
    print(("PASS " if cond else "FAIL ") + label, flush=True)
    if not cond:
        sys.exit(1)


def call(tool, **kw):
    return asyncio.run(tool(**kw))


def approve(result):
    assert "job_id" in result, result
    ra.decide(True)
    job = ra.JOBS[result["job_id"]]
    ra.run_job(job)
    return ra.job_view(job)


def protected(part) -> bool:
    """Mounted read-only and blocked read-only at the device level."""
    opts = sh("findmnt", "-n", "-o", "OPTIONS", "--source", part["device"]).stdout.split(",")
    return "ro" in opts and sh("blockdev", "--getro", part["device"]).stdout.strip() == "1"


def system_value(part, key, name):
    ra.release_caches()
    top = ra.hive_root(ra.open_hive(ra.ci_path(Path(part["mountpoint"]), "Windows/System32/config/SYSTEM")))
    return ra.reg_values(ra.subkey(top, key)).get(name)


work = Path(tempfile.mkdtemp())
img = work / "win.img"
sh("truncate", "-s", "300M", str(img))
sh("mkntfs", "-F", "-Q", "-L", "TESTWIN", str(img))
dev = sh("losetup", "-f", "--show", str(img)).stdout.strip()
ra.MOUNT_BASE = work / "rescue"
try:
    staging = work / "staging"
    staging.mkdir()
    sh("mount", "-t", "ntfs-3g", dev, str(staging))
    for d in ("Windows/System32/config", "Windows/System32/drivers", "Users/alice"):
        (staging / d).mkdir(parents=True, exist_ok=True)
    hive = lzma.decompress(urllib.request.urlopen(SYSTEM_HIVE_URL).read())
    (staging / "Windows/System32/config/SYSTEM").write_bytes(hive)
    (staging / "Windows/System32/drivers/bad.sys").write_bytes(b"MZ bad driver")
    (staging / "hiberfil.sys").write_bytes(b"HIBR" + bytes(1024 * 1024))
    sh("umount", str(staging))

    name = Path(dev).name
    mp, note = ra.mount_readonly(dev, name, "ntfs")
    part = {"name": name, "device": dev, "disk": None, "kind": "ntfs", "label": "TESTWIN", "size_gb": 0.3,
            "mountpoint": mp, "note": note, "windows": True, "disk_failed": False}
    ra.PARTS[name] = part
    ra.WARMED.set()
    check("starts protected (ro mount + ro block device)", protected(part))
    try:
        (Path(mp) / "probe.txt").write_text("x")
        check("write through the read-only mount fails", False)
    except OSError:
        check("write through the read-only mount fails", True)

    j = approve(call(ra.request_rename_file, path="Windows/System32/drivers/bad.sys", new_name="bad.sys.off",
                     reason="test"))
    check("hibernated Windows: change refused with a hint", j["state"] == "failed" and
          "hibernat" in j["result"]["error"].lower())
    check("still protected after the refusal", protected(part))

    j = approve(call(ra.request_clear_hibernation, reason="test", partition=name))
    check("clear hibernation done", j["state"] == "done" and j["result"].get("fast_startup_disabled") is True)
    check("hiberfil.sys removed", ra.ci_path(Path(part["mountpoint"]), "hiberfil.sys") is None)
    check("Fast Startup off (HiberbootEnabled=0)", system_value(part, POWER, "HiberbootEnabled") == 0)
    check("protected again", protected(part))

    r = call(ra.request_set_registry_value, hive="SYSTEM", key=f"HKLM\\SYSTEM\\{POWER}", value_name="RescueTest",
             value_type="REG_SZ", data="hello", reason="test", partition=name)
    j = approve(r)
    check("registry value set", j["state"] == "done" and system_value(part, POWER, "RescueTest") == "hello")
    hive_path = ra.ci_path(Path(part["mountpoint"]), "Windows/System32/config/SYSTEM")
    check("hive still clean after hivex commit", not ra.hive_dirty(hive_path))
    check("protected again", protected(part))
    j = approve(call(ra.request_undo, job_id=r["job_id"], reason="test"))
    check("registry undo removes the new value", j["state"] == "done" and
          system_value(part, POWER, "RescueTest") is None)

    top = ra.hive_root(ra.open_hive(hive_path))
    services = {k.name.lower(): k.name for k in ra.subkey(top, "ControlSet001\\Services").iter_subkeys()}
    driver = next(services[n] for n in ("beep", "cdrom", "parport", "serial") if n in services)
    before = system_value(part, f"ControlSet001\\Services\\{driver}", "Start")
    r = call(ra.request_disable_driver, name=driver, reason="test", partition=name)
    j = approve(r)
    check(f"driver {driver} disabled", j["state"] == "done" and
          system_value(part, f"ControlSet001\\Services\\{driver}", "Start") == 4)
    approve(call(ra.request_undo, job_id=r["job_id"], reason="test"))
    check(f"driver {driver} restored to Start={before}",
          system_value(part, f"ControlSet001\\Services\\{driver}", "Start") == before)

    r = call(ra.request_rename_file, path="Windows/System32/drivers/bad.sys", new_name="bad.sys.off",
             reason="test", partition=name)
    j = approve(r)
    root = Path(part["mountpoint"])
    check("file renamed", j["state"] == "done" and (root / "Windows/System32/drivers/bad.sys.off").exists())
    check("undo record saved on the partition", any(root.glob("RescueAI/undo/*/undo.json")))

    holder = open(root / "Windows/System32/drivers/bad.sys.off", "rb")  # keeps the partition busy
    j = approve(call(ra.request_undo, job_id=r["job_id"], reason="test"))
    check("busy partition: change refused", j["state"] == "failed" and "in use" in j["result"]["error"])
    check("still mounted and protected", protected(part))
    holder.close()
    j = approve(call(ra.request_undo, job_id=r["job_id"], reason="test"))
    check("rename undone", j["state"] == "done" and (Path(part["mountpoint"]) / "Windows/System32/drivers/bad.sys").exists())
    check("ends protected", protected(part))
    print("ALL LINUX CHANGE TESTS PASSED")
finally:
    sh("umount", "-l", str(ra.MOUNT_BASE / Path(dev).name), check=False)
    sh("losetup", "-d", dev, check=False)
