# Rescue AI: one-day version (read-only)

Start a broken Windows PC from an Ubuntu USB stick, run one command, and get a link. Add that link to Claude, and Claude can look inside the PC (disks, crash records, event logs, registry, boot setup, update history) to find out what is wrong and tell you how to fix it.

**Read-only unless you approve.** Windows drives are mounted read-only and locked at the disk level. Claude can *ask* to change something, but a card appears on the PC and nothing happens until you press **Y**. The disk is writable only during that one change, then it's locked read-only again.

---

## What you need

- A USB stick (8 GB or bigger)
- The **Ubuntu 24.04 LTS Desktop** ISO (ubuntu.com/download/desktop)
- **Rufus** (rufus.ie) on any working Windows PC
- An **Ethernet cable**. Wi-Fi usually works on Ubuntu too, but a cable is simplest.
- A Claude plan that supports **custom connectors** (claude.ai or Claude Desktop), or **Claude Code**

## 1. Make the USB (only once)

1. Open Rufus, select the USB stick and the Ubuntu ISO, and click **Start**. If asked, choose **ISO Image mode**.
2. When Rufus finishes, copy this whole `agent` folder onto the USB stick.

> If you edit `start.sh` on Windows, keep **LF** line endings (VS Code shows "LF" at the bottom right). Windows-style line endings break the script.

## 2. Start the broken PC from the USB

1. Plug in the USB stick and the network cable.
2. Turn the PC on and press **F12** (on Dell) to open the boot menu. Choose the USB stick.
3. Choose **Try or Install Ubuntu**, then **Try Ubuntu**. Secure Boot can stay on.

## 3. Start Rescue AI

Open a terminal (**Ctrl+Alt+T**) and run:

```bash
sudo bash /cdrom/agent/start.sh
```

If it says "No such file", open the **Files** app, find the USB stick, right-click the `agent` folder, choose **Open in Terminal**, and run `sudo bash start.sh`.

The first run takes 1–2 minutes because it installs a few tools. Then it shows:

- what it found (for example `nvme0n1p3  ntfs  475 GB  Windows found, read-only at /mnt/rescue/nvme0n1p3`)
- **a link** and a QR code

**Leave the terminal open.** Closing it stops Rescue AI.

## 4. Connect Claude

Wait about 10 seconds after the link appears, then choose one option.

**claude.ai or Claude Desktop** (on any computer, or on this PC in Firefox)
1. Go to Settings → Connectors → **Add custom connector**.
2. Name it `Rescue` and paste the link.
3. Start a new chat and make sure the Rescue connector is turned on in the chat's tools menu.

**Claude Code**
```bash
claude mcp add --transport http rescue <the link>
claude
```

To get the link onto another device, scan the QR code with your phone, or select the link in the terminal and copy it with **Ctrl+Shift+C**. The link is also saved in `/tmp/rescue-ai-link.txt`.

Then describe the problem, for example:

> My PC won't start. It shows a blue screen saying INACCESSIBLE_BOOT_DEVICE and then goes into Automatic Repair. Use the Rescue tools to find out why, and tell me how to fix it step by step.

The terminal shows every tool Claude calls, so you can watch what it's looking at.

When Claude asks to change something, the terminal beeps and shows a card with what will change, the risk, and Claude's reason. Press **Y** to approve or **N** to reject.

Other keys:

| Key | Action |
|---|---|
| **L** | New link |
| **S** | Stop sharing |
| **E** | Expert mode on/off: lets Claude ask to run commands, each still needing Y |

## 5. Stop

Press **Ctrl+C** in the terminal. The link stops working immediately.

Each run creates a **new link**, so next time you'll need to update the connector's URL in Claude.

The activity log is in `/var/log/rescue-ai.log`. Ubuntu "Try" mode forgets everything at shutdown, so copy the log to another USB stick if you want to keep it.

---

## What Claude can use

| Tool | What it does |
|---|---|
| `get_overview` | One-page summary and red flags (Claude starts here) |
| `list_disks`, `disk_health` | Disks, partitions, SMART/NVMe health |
| `windows_info` | Version, computer name, users, free space, hibernation, pending updates |
| `crash_history` | Blue-screen stop codes from crash dumps, sudden shutdowns, the Automatic Repair log |
| `boot_check` | EFI partition, boot configuration (BCD), boot files, UEFI boot menu, Secure Boot |
| `query_event_log` | Searches any Windows event log |
| `recent_updates` | Windows Update installs and failures, stuck updates, CBS.log errors |
| `recent_drivers` | Recent driver installs, boot drivers with missing files |
| `read_registry` | Reads the offline registry (SAM/SECURITY blocked) |
| `list_directory`, `read_text_file` | Browses folders and reads log/text files |
| `run_diagnostic` | Safe Linux hardware checks (kernel disk errors, PCI devices, memory, temperatures and more) |

**Changes (each one needs Y on the PC):**

| Tool | What it does | Undo |
|---|---|---|
| `request_set_registry_value` | Sets one value in the SYSTEM, SOFTWARE, DEFAULT or a user's registry | ✅ |
| `request_disable_driver` | Stops a driver or service from loading at start-up | ✅ |
| `request_rename_file` | Renames a file (nothing is deleted) | ✅ |
| `request_copy_file` | Copies or restores a file; an existing file is backed up first | ✅ |
| `request_clear_hibernation` | Removes the hibernation file and turns off Fast Startup | ❌ |
| `request_boot_order` | Puts an entry first in the UEFI boot menu | ✅ |
| `request_run_command` | Runs a command (expert mode only) | ❌ |
| `request_undo`, `get_job_status`, `list_jobs` | Undo a change; check what happened | |

Changes are refused when:
- the disk reports failing health
- Windows is hibernated or wasn't shut down cleanly (until `request_clear_hibernation`)
- a registry hive has unsaved log data
- the target is a personal file, a password store, or a raw registry hive file

Undo records are saved in `RescueAI\undo\` on the changed partition.

**Privacy:**
- Files inside `C:\Users\...` are **hidden** unless you start with `--allow-personal-files`.
- Password stores, keys and memory files are **always blocked**.
- Anyone who has the link can read the disk while Rescue AI is running, so only give it to Claude.

## Options

```bash
sudo bash /cdrom/agent/start.sh --allow-personal-files       # let Claude read files in C:\Users
sudo bash /cdrom/agent/start.sh --no-tunnel --host 0.0.0.0   # no public link; use on your own network or Tailscale
```

## Problems?

| What you see | What to do |
|---|---|
| "No internet" | Plug in the cable, or join Wi-Fi from the top-right menu, then run the command again |
| "No Windows-related partitions" or "No readable Windows partition" | The drive may be **BitLocker-locked** (this version can't unlock it). On some Dell laptops the disk is hidden by "RAID On" storage mode. You can switch the BIOS to AHCI for this session, but **switch it back before starting Windows again** |
| A partition says "could not mount" | Windows may have crashed mid-write. Claude can still use the other tools; ask it to look at the partitions |
| Claude says it can't connect | Wait 20 seconds and try again. Make sure the terminal is still running. If it still fails, press Ctrl+C and run the command again for a new link |
| The link shows "Not found" in a browser | Use the full link. Opening it without the final `/mcp` shows a status page with Claude's recent activity |

## Try it without a broken PC

On any Linux machine, point it at a folder that looks like a Windows drive:

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt evtx
.venv/bin/python rescue_agent.py --test-root /path/to/windows-folder --no-tunnel
```

## Limits of this version

- Repairs that need Windows' own tools (SFC, DISM, bcdboot, chkdsk) can't run here yet. Claude gives you steps for the Windows Recovery Environment instead (running them automatically is milestone M3 in `../IMPLEMENTATION_PLAN.md`).
- It can't unlock BitLocker drives yet.
- You get a new link every run.
