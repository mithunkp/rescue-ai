#!/usr/bin/env python3
"""Preview the PC's screen page in your browser, with made-up data. Safe to run on any computer:
nothing touches a disk, nothing goes online, and the page is only reachable from this computer.

It is the real page from rescue_agent.py, walking through every state on its own; click Approve,
Reject, Details and the rest to try them (Power off is disabled here). The Rescue USB uses the
Inter font, so letters can look slightly different in your browser.

    python agent/preview_screen.py
"""

import sys
import tempfile
import threading
import time
import webbrowser
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rescue_agent as ra  # noqa: E402

DEMO_URL = "https://plain-river-quietly-seven.trycloudflare.com/preview-only-not-a-real-link/mcp"


class DemoLink:
    """Stands in for the Cloudflare link: the screen's New link and Stop sharing work on it."""

    def __init__(self):
        self.new_link()

    def new_link(self):
        self.sharing, self.url, self.status = True, DEMO_URL, "Ready: Claude can connect now."

    def stop(self):
        self.sharing, self.url, self.status = False, None, "Sharing stopped."

    def close(self):
        pass


def wait_for_decision(job_id: int) -> None:
    while ra.JOBS[job_id]["state"] == "waiting_for_approval":
        time.sleep(0.3)
    if ra.JOBS[job_id]["state"] == "approved":
        ra.run_job(ra.JOBS[job_id])


def demo(link: DemoLink) -> None:
    """Every state of the screen, in a loop; approvals wait for you."""
    while True:
        link.new_link()
        ra.LAST_ACTION["text"] = "Claude is checking the crash history."
        time.sleep(12)
        job = ra.new_job("rename", "Rename brokendrv.sys to brokendrv.sys.bad",
                         ["Partition: nvme0n1p3", "File: Windows\\System32\\drivers\\brokendrv.sys",
                          "New name: brokendrv.sys.bad"], "medium",
                         "Automatic Repair says this driver file is corrupt; moving it aside lets Windows start.",
                         lambda j: {"renamed": True})
        wait_for_decision(job["job_id"])
        time.sleep(5)
        job = ra.new_job("reset_journal", "Reset the NTFS journal (ntfsfix)",
                         ["Partition: nvme0n1p3",
                          "Now: not shut down cleanly (crash or power loss). This is not hibernation",
                          "Loses: changes Windows hadn't finished writing when it stopped",
                          "Safer alternative: Windows' own chkdsk"], "high",
                         "chkdsk can't run on this PC, and the drive must be writable to restore the registry.",
                         lambda j: {"ok": True}, reversible=False, confirm="RESET")
        wait_for_decision(job["job_id"])
        working = {"id": 10_000, "kind": "windows_repair", "title": "Check and fix the Windows file system (chkdsk /f)",
                   "state": "running", "_created": time.time(), "progress": ""}
        ra.JOBS[working["id"]] = working
        for minute in range(1, 6):
            working["progress"] = f"Windows' repair tool is running (started {minute} minute(s) ago)"
            time.sleep(2.5)
        working["state"] = "done"
        ra.LAST_ACTION["text"] = f"Done: {working['title']}."
        time.sleep(5)
        link.url, link.status = None, "Waiting for the network: plug in the Ethernet cable."
        time.sleep(8)
        link.stop()
        time.sleep(8)


def main() -> None:
    folder = tempfile.mkdtemp(prefix="rescue-preview-")
    ra.PARTS["nvme0n1p3"] = {"name": "nvme0n1p3", "device": None, "disk": None, "kind": "ntfs", "label": "Windows",
                             "size_gb": 475.1, "mountpoint": folder, "note": "", "windows": True, "disk_failed": False}
    ra.SUMMARY["text"] = "Windows 11 Pro was found. It stays read-only until you approve a change."
    ra.ACTIVITY.extend(["10:02:11  AI -> get_overview()", "10:02:19  AI -> crash_history(days=60)",
                        "10:02:31  AI -> check_registry()"])
    ra.SCREEN = SimpleNamespace(refresh=lambda: None)  # the page polls; nothing to redraw in a terminal
    link = DemoLink()
    ra.LINK = link
    url = ra.start_ui_server()
    if not url:
        sys.exit(f"Port {ra.UI_PORT} is in use; close whatever uses it (maybe another preview) and try again.")
    threading.Thread(target=demo, args=(link,), daemon=True).start()
    print(f"Preview of the PC's screen: {url}\nIt shows every state in turn. Press Ctrl+C here to stop.", flush=True)
    webbrowser.open(url)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
