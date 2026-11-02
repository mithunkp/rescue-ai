"""Fixes from the first real-PC session, on real Linux (run as root; CI runs it with a never-ending stdin,
like the PC's console, so any helper that waits for keyboard input hangs and fails the test).

- ntfs-3g.probe tells clean, hibernated and unclean partitions apart
- the NTFS journal reset (ntfsfix) needs the typed word RESET, and leaves the partition protected
- a SOFTWARE hive with Microsoft\\Windows NT\\CurrentVersion deleted (what the real PC had) is found by
  check_registry and put back from a restore point (a second NTFS image stands in for the shadow copy)
- drives held by device-mapper (how Ventoy keeps its stick busy) are recognised
"""
import asyncio
import lzma
import os
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rescue_agent as ra  # noqa: E402

SOFTWARE_URL = "https://raw.githubusercontent.com/mkorman90/regipy/master/regipy_tests/data/SOFTWARE.xz"
NO_LINK = SimpleNamespace(new_link=lambda: None, stop=lambda: None)


def sh(*cmd, check=True):
    p = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True)
    if check and p.returncode:
        sys.exit(f"{' '.join(cmd)} failed: {p.stderr}")
    return p


def check(label, cond):
    print(("PASS " if cond else "FAIL ") + label, flush=True)
    if not cond:
        sys.exit(1)


def call(tool, **kw):
    return asyncio.run(tool(**kw))


def approve(result, word=None):
    assert "job_id" in result, result
    if word:
        for key in word + "\r":
            ra.handle_key(key, NO_LINK)
    else:
        ra.decide(True)
    job = ra.JOBS[result["job_id"]]
    if job["state"] == "approved":
        ra.run_job(job)
    return ra.job_view(job)


def protected(part) -> bool:
    opts = sh("findmnt", "-n", "-o", "OPTIONS", "--source", part["device"]).stdout.split(",")
    return "ro" in opts and sh("blockdev", "--getro", part["device"]).stdout.strip() == "1"


def ntfs_disk(path: Path, size: str, label: str, files: dict[str, bytes]) -> str:
    sh("truncate", "-s", size, str(path))
    sh("mkntfs", "-F", "-Q", "-L", label, str(path))
    dev = sh("losetup", "-f", "--show", str(path)).stdout.strip()
    sh("blockdev", "--setrw", dev)
    staging = Path(tempfile.mkdtemp())
    sh("mount", "-t", "ntfs-3g", dev, str(staging))
    for rel, data in files.items():
        (staging / rel).parent.mkdir(parents=True, exist_ok=True)
        (staging / rel).write_bytes(data)
    sh("umount", str(staging))
    return dev


work = Path(tempfile.mkdtemp())
devices = []
try:
    software = lzma.decompress(urllib.request.urlopen(SOFTWARE_URL).read())
    files = {"Windows/System32/config/SOFTWARE": software, "Windows/System32/config/SOFTWARE.LOG1": b"old log",
             "Windows/System32/config/SYSTEM": b"regf" + bytes(4092), "Windows/System32/drivers/net.sys": b"good driver"}
    win_dev = ntfs_disk(work / "win.img", "300M", "WINDOWS", {**files, "hiberfil.sys": b"HIBR" + bytes(1 << 20)})
    snap_dev = ntfs_disk(work / "snap.img", "300M", "SNAPSHOT", files)
    devices += [win_dev, snap_dev]
    ra.MOUNT_BASE, ra.RESTORE_MOUNTS = work / "rescue", work / "restore"
    ra.WARMED.set()

    # --- ntfs-3g.probe: hibernated vs clean
    name = Path(win_dev).name
    check("hibernated partition detected by ntfs-3g.probe", ra.probe_ntfs(win_dev) == "hibernated")
    staging = Path(tempfile.mkdtemp())
    sh("mount", "-t", "ntfs-3g", "-o", "remove_hiberfile", win_dev, str(staging))
    sh("umount", str(staging))
    check("after removing hibernation: clean", ra.probe_ntfs(win_dev) == "clean")
    mp, note = ra.mount_readonly(win_dev, name, "ntfs")
    part = {"name": name, "device": win_dev, "disk": name, "kind": "ntfs", "label": "WINDOWS", "size_gb": 0.3,
            "mountpoint": mp, "note": note, "windows": True, "disk_failed": False}
    ra.PARTS[name] = part
    check("state recorded when mounted", ra.NTFS_STATES[win_dev] == "clean" and protected(part))

    # --- journal reset: refused when clean; needs RESET when unclean; partition protected afterwards
    check("journal reset refused on a clean partition",
          "doesn't need resetting" in call(ra.request_reset_ntfs_journal, reason="t", partition=name).get("error", ""))
    ra.NTFS_STATES[win_dev] = "unclean"  # a real unclean journal needs Windows to crash; ntfsfix works the same
    r = call(ra.request_reset_ntfs_journal, reason="t", partition=name)
    check("journal reset needs the typed word", ra.JOBS[r["job_id"]]["confirm"] == "RESET")
    j = approve(r, word="RESET")
    check("ntfsfix ran and the partition is clean again", j["state"] == "done" and ra.NTFS_STATES[win_dev] == "clean")
    check("partition protected after the journal reset", protected(part))

    # --- the real PC's problem: Microsoft\Windows NT\CurrentVersion still exists but is gutted
    #     (no values, almost no subkeys), which a "does the key exist" check reported as ok
    sh("umount", part["mountpoint"])
    sh("blockdev", "--setrw", win_dev)
    staging = Path(tempfile.mkdtemp())
    sh("mount", "-t", "ntfs-3g", win_dev, str(staging))
    import hivex
    h = hivex.Hivex(str(staging / "Windows/System32/config/SOFTWARE"), write=True)
    node = h.root()
    for key in ("Microsoft", "Windows NT", "CurrentVersion"):
        node = next(c for c in h.node_children(node) if h.node_name(c).lower() == key.lower())
    h.node_set_values(node, [])
    for child in h.node_children(node)[2:]:  # keep 2 subkeys, like the real PC
        h.node_delete_child(child)
    h.commit(None)
    sh("umount", str(staging))
    part["mountpoint"], part["note"] = ra.mount_readonly(win_dev, name, "ntfs")
    ra.release_caches()
    report = call(ra.check_registry, partition=name)
    status = report["hives"]["SOFTWARE"]["status"]
    print("   ", status)
    check("check_registry finds the gutted key: its values are missing",
          "SOFTWARE" in report["damaged"] and "has no ProductName, EditionID, CurrentBuild" in status)
    check("check_registry finds the gutted key: too few subkeys", "has only 2 subkeys" in status)
    check("without restore-point tools the comparison says why it was skipped",
          report["comparison"].startswith("not compared"))

    # the second image stands in for a restore point (vshadowmount isn't possible without Windows)
    rp_name = f"{name}@rp1"
    rp_mount = ra.RESTORE_MOUNTS / rp_name
    rp_mount.mkdir(parents=True)
    sh("blockdev", "--setro", snap_dev)
    sh("mount", "-t", "ntfs3", "-o", "ro", snap_dev, str(rp_mount), check=False).returncode == 0 or \
        sh("mount", "-t", "ntfs-3g", "-o", "ro", snap_dev, str(rp_mount))
    ra.PARTS[rp_name] = {"name": rp_name, "device": None, "disk": None, "base": name, "kind": "snapshot",
                         "label": "restore point 1", "size_gb": 0.3, "mountpoint": str(rp_mount), "note": "",
                         "windows": False, "disk_failed": False}
    check("restore point's SOFTWARE hive is healthy",
          call(ra.check_registry, partition=rp_name)["hives"]["SOFTWARE"]["status"] == "ok")
    report = call(ra.check_registry, partition=name, compare_with=rp_name)
    status = report["hives"]["SOFTWARE"]["status"]
    print("   ", status)
    check("comparison with the restore point flags the sudden drop in subkeys and values",
          report["comparison"] == f"compared with {rp_name}" and "much smaller than before" in status
          and f"has 2 subkeys" in status and f"in {rp_name}" in status)
    check("restore points are read-only", "error" in call(ra.request_rename_file, path="Windows/System32/drivers/net.sys",
                                                          new_name="x", reason="t", partition=rp_name))
    r = call(ra.request_restore_registry_hive, hive="SOFTWARE", restore_point_name=rp_name, reason="t")
    now_line = next(d for d in ra.JOBS[r["job_id"]]["details"] if d.startswith("Now:"))
    print("    card:", now_line)
    check("the restore card no longer says the damaged hive is ok", now_line.startswith("Now: DAMAGED"))
    check("hive restore needs the typed word RESTORE", ra.JOBS[r["job_id"]]["confirm"] == "RESTORE")
    j = approve(r, word="RESTORE")
    check("hive restored", j["state"] == "done" and "Windows/System32/config/SOFTWARE" in j["result"]["replaced"])
    ra.release_caches()
    check("check_registry: SOFTWARE healthy again", call(ra.check_registry, partition=name)["hives"]["SOFTWARE"]["status"] == "ok")
    check("restore point closed while the partition was written", rp_name not in ra.PARTS and not os.path.ismount(rp_mount))
    check("partition protected after the hive restore", protected(part))
    j = approve(call(ra.request_undo, job_id=r["job_id"], reason="t"))
    ra.release_caches()
    check("undo puts the damaged hive back (nothing is lost)",
          j["state"] == "done" and "SOFTWARE" in call(ra.check_registry, partition=name)["damaged"])

    # several files from a restore point in one approval
    sh("mount", "-t", "ntfs-3g", "-o", "ro", snap_dev, str(rp_mount))
    ra.PARTS[rp_name] = {"name": rp_name, "device": None, "disk": None, "base": name, "kind": "snapshot",
                         "label": "restore point 1", "size_gb": 0.3, "mountpoint": str(rp_mount), "note": "",
                         "windows": False, "disk_failed": False}
    j = approve(call(ra.request_restore_from_restore_point, restore_point_name=rp_name, reason="t",
                     paths=["Windows/System32/drivers/net.sys"]))
    check("file brought back from the restore point", j["state"] == "done"
          and (Path(part["mountpoint"]) / "Windows/System32/drivers/net.sys").read_bytes() == b"good driver")

    # --- device-mapper holds (how Ventoy keeps its stick busy)
    holder_img = work / "held.img"
    sh("truncate", "-s", "20M", str(holder_img))
    held_dev = sh("losetup", "-f", "--show", str(holder_img)).stdout.strip()
    devices.append(held_dev)
    held = Path(held_dev).name
    check("free drive not held", not ra.disk_held(held))
    sectors = int(sh("blockdev", "--getsz", held_dev).stdout)
    sh("dmsetup", "create", "rescue-held-test", "--table", f"0 {sectors} linear {held_dev} 0")
    check("drive held by device-mapper recognised", ra.disk_held(held))
    sh("dmsetup", "remove", "rescue-held-test")
    print("ALL LINUX FEEDBACK TESTS PASSED")
finally:
    ra.close_restore_points()
    for p in list(ra.PARTS.values()):
        if p.get("mountpoint"):
            sh("umount", "-l", p["mountpoint"], check=False)
    sh("dmsetup", "remove", "rescue-held-test", check=False)
    for dev in devices:
        sh("blockdev", "--setrw", dev, check=False)
        sh("losetup", "-d", dev, check=False)
