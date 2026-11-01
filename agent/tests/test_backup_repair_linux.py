"""Integration test for backups, disk images and the Windows repair pipeline on real Linux (run as root).

Uses loop-device disks: an NTFS "Windows" disk with real registry hives and a recovery image built with
wimlib, and a FAT32 "USB drive". The repair VM is replaced by a fake QEMU that checks what it was given
(the Windows disk unmounted and writable, the boot disk with Windows' boot files and the patched recovery
image, the job script) and writes a result, like Windows' recovery environment would.
"""
import asyncio
import hashlib
import json
import lzma
import os
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rescue_agent as ra  # noqa: E402

HIVES = "https://raw.githubusercontent.com/mkorman90/regipy/master/regipy_tests/data/{}.xz"

FAKE_QEMU = r'''#!/usr/bin/env python3
import json, os, re, subprocess, sys
args = sys.argv[1:]
files = {}
for i, a in enumerate(args):
    if i and args[i - 1] == "-drive":
        spec = dict(kv.split("=", 1) for kv in a.split(",") if "=" in kv)
        if "id" in spec:
            files[spec["id"]] = spec["file"]
win, boot, job = files["windows"], files["boot"], files["job"]
def out(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True).stdout
tmp = os.environ["FAKE_DIR"]
subprocess.run(["mcopy", "-n", "-i", boot + "@@1M", "::/sources/boot.wim", tmp + "/boot.wim"], check=True)
subprocess.run(["wimlib-imagex", "extract", tmp + "/boot.wim", "1", "/Windows/System32/winpeshl.ini",
                "/rescue/run.cmd", "--dest-dir=" + tmp + "/extract", "--no-acls"], check=True)
report = {
    "args": args,
    "win_ro": out("blockdev", "--getro", win).strip(),
    "win_mounted": out("findmnt", "-n", "--source", win).strip(),
    "boot_files": out("mdir", "-/", "-b", "-i", boot + "@@1M", "::/"),
    "winpeshl": open(tmp + "/extract/winpeshl.ini", "rb").read().decode(errors="replace"),
    "run_cmd": open(tmp + "/extract/run.cmd", "rb").read().decode(errors="replace"),
    "job_script": out("mtype", "-i", job + "@@1M", "::/rescue-job.cmd"),
}
json.dump(report, open(tmp + "/report.json", "w"))
if os.environ.get("FAKE_MODE") != "no-result":
    open(tmp + "/o.txt", "wb").write("Windows Resource Protection did not find any integrity violations.\r\n".encode("utf-16"))
    open(tmp + "/c.txt", "w").write("0\r\n")
    subprocess.run(["mcopy", "-o", "-i", job + "@@1M", tmp + "/o.txt", "::/output.txt"], check=True)
    subprocess.run(["mcopy", "-o", "-i", job + "@@1M", tmp + "/c.txt", "::/exitcode.txt"], check=True)
'''


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
    opts = sh("findmnt", "-n", "-o", "OPTIONS", "--source", part["device"]).stdout.split(",")
    return "ro" in opts and sh("blockdev", "--getro", part["device"]).stdout.strip() == "1"


def sha256_of(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


work = Path(tempfile.mkdtemp())
devices = []
try:
    # --- the "Windows" disk
    win_img, usb_img = work / "win.img", work / "usb.img"
    sh("truncate", "-s", "300M", str(win_img))
    sh("mkntfs", "-F", "-Q", "-L", "WINDOWS", str(win_img))
    win_dev = sh("losetup", "-f", "--show", str(win_img)).stdout.strip()
    devices.append(win_dev)
    sh("blockdev", "--setrw", win_dev)  # a reused loop device can keep an earlier test's read-only flag
    staging = work / "staging"
    staging.mkdir()
    sh("mount", "-t", "ntfs-3g", win_dev, str(staging))
    for d in ("Windows/System32/config", "Windows/INF", "Windows/Boot/EFI", "Windows/Boot/DVD/EFI",
              "Recovery/WindowsRE", "Users/alice/Documents", "Users/alice/Pictures"):
        (staging / d).mkdir(parents=True, exist_ok=True)
    for hive in ("SYSTEM", "SOFTWARE"):
        (staging / f"Windows/System32/config/{hive}").write_bytes(lzma.decompress(urllib.request.urlopen(HIVES.format(hive)).read()))
    (staging / "Users/alice/Documents/letter.txt").write_text("dear bob")
    (staging / "Users/alice/Pictures/photo.jpg").write_bytes(os.urandom(2_000_000))
    (staging / "Windows/INF/oem1.inf").write_text("[Version]\nClass=Display\nProvider=%P%\nDriverVer=09/01/2026,31.0.1\n[Strings]\nP=\"Contoso\"\n")
    for f in ("Windows/Boot/EFI/bootmgfw.efi", "Windows/Boot/DVD/EFI/BCD", "Windows/Boot/DVD/EFI/boot.sdi"):
        (staging / f).write_bytes(b"fake " + f.encode())
    re_dir = work / "winre"
    (re_dir / "Windows/System32").mkdir(parents=True)
    (re_dir / "Windows/System32/winpeshl.ini").write_text("[LaunchApp]\nAppPath=recenv.exe\n")
    sh("wimlib-imagex", "capture", str(re_dir), str(staging / "Recovery/WindowsRE/Winre.wim"), "WinRE")
    sh("umount", str(staging))

    # --- the "USB drive"
    sh("truncate", "-s", "450M", str(usb_img))
    sh("mkfs.vfat", "-F", "32", "-n", "RESCUEUSB", str(usb_img))
    usb_dev = sh("losetup", "-f", "--show", str(usb_img)).stdout.strip()
    devices.append(usb_dev)
    sh("blockdev", "--setrw", usb_dev)

    ra.MOUNT_BASE, ra.BACKUP_MOUNTS, ra.MEDIA_MOUNTS = work / "rescue", work / "backup", work / "media"
    name = Path(win_dev).name
    mp, note = ra.mount_readonly(win_dev, name, "ntfs")
    part = {"name": name, "device": win_dev, "disk": name, "kind": "ntfs", "label": "WINDOWS", "size_gb": 0.3,
            "mountpoint": mp, "note": note, "windows": True, "disk_failed": False}
    ra.PARTS[name] = part
    ra.WARMED.set()
    usb = {"name": Path(usb_dev).name, "device": usb_dev, "fstype": "vfat", "label": "RESCUEUSB", "size_gb": 0.45,
           "drive": "test stick"}
    ra.backup_candidates = lambda: [dict(usb)]
    ra.usb_partitions = lambda filesystems: []  # don't look at the runner's own disks
    check("Windows disk starts protected", protected(part))

    # --- backup
    d = call(ra.list_backup_drives)
    check("USB drive listed with free space", d["drives"][0]["free_gb"] > 0.3)
    j = approve(call(ra.request_backup, sources=["profile:alice"], destination=usb["name"], reason="test"))
    check("backup done", j["state"] == "done" and j["result"]["files_copied_now"] == 2)
    check("Windows disk still protected after backup", protected(part))
    check("USB unmounted after the backup", not ra.mount_info(usb_dev))
    view = work / "view"
    view.mkdir()
    sh("mount", "-o", "ro", usb_dev, str(view))
    dest = next(view.glob("RescueAI-Backup/*"))
    check("files on the USB match the originals",
          (dest / "alice/Documents/letter.txt").read_text() == "dear bob"
          and sha256_of(dest / "alice/Pictures/photo.jpg") == sha256_of(Path(part["mountpoint"]) / "Users/alice/Pictures/photo.jpg"))
    check("manifest written", len((dest / "manifest.csv").read_text().splitlines()) == 2)
    sh("umount", str(view))
    j = approve(call(ra.request_backup, sources=["profile:alice"], destination=usb["name"], reason="again"))
    check("second backup resumes (nothing copied again)", j["result"]["files_copied_now"] == 0)

    # --- disk image
    j = approve(call(ra.request_disk_image, partition=name, destination=usb["name"], reason="test"))
    check("disk image done, nothing unreadable", j["state"] == "done" and j["result"]["complete"] is True)
    sh("mount", "-o", "ro", usb_dev, str(view))
    check("image is an exact copy of the partition",
          sha256_of(view / f"RescueAI-Backup/images/{name}.img") == sha256_of(win_dev))
    sh("umount", str(view))

    # --- update and driver lists
    u = call(ra.list_installed_updates, limit=3)
    check("updates listed", len(u["recent"]) == 3)
    dr = call(ra.list_third_party_drivers)
    check("third-party driver listed", dr["drivers"][0]["provider"] == "Contoso")

    # --- Windows repair pipeline (fake VM)
    fake = work / "fake-qemu"
    fake.write_text(FAKE_QEMU)
    fake.chmod(0o755)
    ra.QEMU = str(fake)
    os.environ["FAKE_DIR"] = str(work)
    t = call(ra.check_repair_tools)
    check("repair tools ready (own recovery environment found)",
          t["missing_on_rescue_system"] == "nothing" and t["recovery_environment"].startswith("this PC's own"))
    check("bcdboot refused without an EFI partition on the disk",
          "EFI" in call(ra.request_windows_repair, repair="bcdboot", reason="x").get("error", ""))
    check("dism_remove_driver needs an existing oemNN.inf",
          "error" in call(ra.request_windows_repair, repair="dism_remove_driver", driver="oem9.inf", reason="x"))

    serial = ra.ntfs_serial(part)
    j = approve(call(ra.request_windows_repair, repair="sfc", reason="test"))
    report = json.loads((work / "report.json").read_text())
    check("repair finished with Windows' result", j["state"] == "done" and j["result"]["exit_code"] == 0
          and "did not find any integrity violations" in j["result"]["output"])
    check("VM got the Windows disk writable", report["win_ro"] == "0")
    check("Windows disk was unmounted while the VM had it", report["win_mounted"] == "")
    check("boot disk holds Windows' boot files and the recovery image",
          all(x in report["boot_files"] for x in ("/EFI/Boot/bootx64.efi", "/EFI/Microsoft/Boot/BCD",
                                                   "/boot/boot.sdi", "/sources/boot.wim")))
    check("recovery image patched to run our job", "rescue\\run.cmd" in report["winpeshl"] and "wpeutil shutdown" in report["run_cmd"])
    check("job finds Windows by its serial and runs sfc",
          serial in report["job_script"] and "sfc /scannow /offbootdir=%WIN%\\ /offwindir=%WIN%\\Windows" in report["job_script"])
    check("job script uses Windows line endings", "\r\n" in (lambda p: open(p, "rb").read().decode())(work / "extract/run.cmd"))
    check("Windows disk protected again after the repair", protected(part))

    os.environ["FAKE_MODE"] = "no-result"
    j = approve(call(ra.request_windows_repair, repair="chkdsk", reason="test"))
    check("missing result reported as a failure", j["state"] == "failed" and "didn't report a result" in j["result"]["error"])
    check("Windows disk protected after a failed repair", protected(part))
    print("ALL LINUX BACKUP AND REPAIR TESTS PASSED")
finally:
    for p in ra.PARTS.values():
        if p.get("mountpoint"):
            sh("umount", "-l", p["mountpoint"], check=False)
    for dev in devices:
        sh("blockdev", "--setrw", dev, check=False)
        sh("losetup", "-d", dev, check=False)
