# Rescue AI: Implementation Plan

Draft v0.1 · November 2026 · For the developers building Rescue AI
Companion to [PROPOSAL.md](PROPOSAL.md)

---

## 1. Principles

1. **Read-only by default.** Nothing writes to a Windows disk unless a job has been approved at the PC.
2. **Useful without AI.** Health Status, file browsing and backup all work offline.
3. **One agent, three front ends.** A single agent process serves the local screen, the MCP endpoint for AIs, and the technician dashboard. All three share the same tools, rules and audit log.
4. **No built-in AI.** All the intelligence comes from the connected AI. We ship tools, rules and guardrails.
5. **Long work runs as a job.** Anything slow or risky becomes a background job with an id. No AI request ever waits on a human or a long operation.

## 2. Architecture

```
        Person at the PC                              Outside
 ┌───────────────────────────┐          ┌──────────────────────────────┐
 │ Firefox app window        │          │ Claude (web / Desktop / Code)│
 │ Health · Files · Rescue   │          │ other MCP clients            │
 │ Approvals · Settings      │          │ technician's browser         │
 └─────────────┬─────────────┘          └──────────────┬───────────────┘
               │ 127.0.0.1:8766                         │ HTTPS
               │ (never tunnelled)                      ▼
               │                          cloudflared / frpc / Tailscale
               │                                        │ 127.0.0.1:8765
               ▼                                        ▼ (only while Rescue runs)
 ┌────────────────────────────────────────────────────────────────────┐
 │ rescue-agent  (Python, root, systemd)                              │
 │  web UI · MCP server · session + tunnel · policy · jobs + approvals│
 │  collectors → health engine · files · backup / imaging · audit log │
 └────────┬─────────────────────────────┬─────────────────────────────┘
          │ read-only mounts             │ approved jobs only
          ▼                              ▼
  Windows disk (block-level RO)    QEMU VM running the PC's own WinRE (M3)
                                   backup drive (USB / external / SMB)
```

### 2.1 Components

| Component | Responsibility |
|---|---|
| Live OS | Debian 13 "trixie" + Xfce built with live-build. Handles boot, networking, desktop apps, persistence and read-only protection |
| `disks` | Finds disks, keeps internal disks read-only, mounts Windows volumes read-only, handles BitLocker |
| `collectors` | Gather facts: SMART, partitions, registry, event logs, crashes, updates, drivers, boot, startup, hardware |
| `health` | Rules turn facts into findings and give each section a status |
| `files` | Browsing, reading and previewing, under the access rules |
| `jobs` | Queue, approval state machine, and workers for backup, imaging, unlock, repair and shell |
| `policy` | Decides what is allowed right now (permission level, disk health, hibernation, Expert mode) |
| `mcp_server` | MCP tools for AIs |
| `web` | Local UI and technician dashboard |
| `session` | Start/Stop Rescue, tokens, expiry and tunnel processes |
| `audit` | Append-only, hash-chained log of every request, decision and result |
| `repair` (M3) | Builds and runs the WinRE virtual machine |

### 2.2 Two listeners

| Listener | Bind | Exposed through tunnel | Serves |
|---|---|---|---|
| **local** | `127.0.0.1:8766` | **Never** | Local UI, approvals, BitLocker key entry, folder sharing, settings |
| **public** | `127.0.0.1:8765`, bound only while Rescue is running | Yes | `/s/<token>/mcp` (MCP), `/s/<token>/` (read-only dashboard), PIN approval endpoint |

The tunnel delivers traffic from `127.0.0.1` too, so the source address can't be used to tell local requests from remote ones. Approvals are kept safe by putting them on a **separate port that the tunnel never targets**. The local listener is also protected against malicious web pages open in Firefox:

- The desktop launcher opens the UI with a per-boot secret in the URL. That secret becomes an `HttpOnly; SameSite=Strict` cookie.
- The listener checks the `Host` and `Origin` headers, which blocks other sites and DNS rebinding.
- Every POST requires a CSRF token.

### 2.3 Processes

| Unit | Runs as | Starts |
|---|---|---|
| `rescue-agent.service` | root | At boot (Health Status needs it) |
| Tunnel (`cloudflared` / `frpc`) | Child of the agent | On **Start Rescue**; killed on **Stop** |
| `qemu-system-x86_64` | Child of a repair job | Once per approved repair (M3) |
| Firefox app window | user `rescue` | From the desktop launchers |

### 2.4 Paths on the live system

| Path | Purpose |
|---|---|
| `/opt/rescue-agent/` | Agent code and venv (inside the ISO, read-only) |
| `/etc/rescue-ai/config.toml` | Defaults |
| `/var/lib/rescue/` | **Persistent:** `settings.json`, `rescue.db` (SQLite), `sessions/<id>/` (audit log, reports) |
| `/run/rescue/mnt/<partuuid>/` | Read-only mounts of Windows volumes |
| `/run/rescue/work/` | Scratch space in RAM (temp files, VM workspace) |

Without persistence, `/var/lib/rescue` lives in RAM and the UI warns: "Logs will be lost at shutdown. Export them first."

## 3. Tech stack

| Area | Choice | Notes |
|---|---|---|
| Base OS | Debian 13 "trixie", amd64, `live-build` | Signed shim, GRUB and kernel for Secure Boot; firmware from `non-free-firmware` |
| Desktop | Xfce on X11, LightDM autologin user `rescue` | X11 so that RustDesk works |
| Agent | Python 3.13 (Debian's), venv in `/opt/rescue-agent` | Wheels pinned with hashes |
| MCP | Official `mcp` Python SDK, `FastMCP`, Streamable HTTP, `stateless_http=True`, `json_response=True` | Plain JSON responses, no SSE (works through quick tunnels) |
| Web | Starlette + Uvicorn, server-rendered HTML with small vanilla JS | No front-end build step |
| Storage | SQLite (jobs, settings, shares) and JSONL (audit) | |
| Registry | `regipy` (replays transaction logs, so it handles dirty hives) | Read-only |
| Event logs | `evtx` (Rust-based parser via pip), with `python-evtx` as fallback | |
| Disks | `lsblk -J`, `sfdisk -J`, `blkid`, `smartctl -j`, `nvme-cli` | |
| NTFS | Kernel `ntfs3`, read-only; `ntfs-3g` as fallback | |
| BitLocker | `cryptsetup` BITLK (`bitlkDump`, `open --type bitlk --readonly`); `dislocker` as fallback | |
| Backup / imaging | Own Python copier; `partclone.ntfs`; GNU `ddrescue` | |
| Repair VM | QEMU/KVM, OVMF, `wimlib-imagex` (`wimtools`), `mtools`, `dosfstools` | M3 |
| Tunnel | `cloudflared` (pinned .deb), `frpc`, `tailscale` | |
| Remote desktop | RustDesk client, pointed at our own server | M4 |
| QR code | `qrcode` (pip), rendered as SVG | |
| Quality | `pytest`, `ruff`, `mypy` | |

## 4. Repository layout

```
Rescue Ai/
├── PROPOSAL.md
├── IMPLEMENTATION_PLAN.md
├── liveos/                        # M0: Debian live-build config
│   ├── auto/                      # config, build, clean
│   ├── config/
│   │   ├── package-lists/         # desktop, apps, firmware, rescue-tools (.list.chroot)
│   │   ├── hooks/live/            # agent venv, cloudflared, trimming docs/locales
│   │   ├── includes.chroot/       # udev rule, udisks2 options, systemd units,
│   │   │                          # .desktop launchers, Firefox policies
│   │   └── bootloaders/           # boot menu entries
│   └── tools/make-usb.sh          # write ISO + create persistence partition
├── agent/                         # M1+: Python package
│   ├── pyproject.toml
│   ├── rescue_agent/
│   │   ├── __main__.py  config.py  audit.py  policy.py  session.py
│   │   ├── disks/                 # discovery, ro guard, mounts, bitlocker
│   │   ├── collectors/            # smart, partitions, registry, evtx, crashes,
│   │   │                          # servicing, drivers, boot, startup, hardware
│   │   ├── health/                # engine.py, rules/*.py, kb/*.yaml
│   │   ├── files/                 # browse, access rules, preview
│   │   ├── jobs/                  # queue, state machine, workers/
│   │   ├── mcp_server.py
│   │   ├── web/                   # routes, templates, static
│   │   ├── tunnel/                # cloudflared.py, frp.py, tailscale.py
│   │   └── repair/                # M3: vm.py, winre.py, jobdisk.py, scripts/*.cmd
│   └── tests/
│       └── fixtures/              # hives, evtx, smartctl JSON, minidump headers
├── lab/                           # breakage-lab scripts and notes
└── docs/                          # user guide, technician guide
```

## 5. Safety layers

Each layer works even if the one above it fails.

| # | Layer | How |
|---|---|---|
| 1 | **Block device** | A udev rule runs `blockdev --setro` on every protected disk **and each of its partitions** at boot. Only the job runner lifts this, for one approved job, and it always restores it afterwards (including after a crash or timeout) |
| 2 | **Mount** | The agent mounts Windows volumes with `ro`. `/etc/udisks2/mount_options.conf` forces `ro` for NTFS when the user mounts from the file manager |
| 3 | **Policy** | Every tool has a permission level. Policy also checks disk health, hibernation, BitLocker and Expert mode |
| 4 | **Approval** | Write jobs run only after approval on the local UI, or with a one-time PIN |
| 5 | **Path** | File-access rules: allowed roots, a deny list, no following symlinks or junctions outside a root, size limits |
| 6 | **Secrets** | BitLocker keys, SAM/SECURITY hives and credential stores are never returned. Keys, PINs and tokens are redacted from logs |
| 7 | **Audit** | Every request, decision and result is logged, hash-chained so tampering shows |
| 8 | **Network** | The MCP listener exists only during Rescue. It uses a random 256-bit token, an expiry, rate limits and an optional IP allowlist |

**Protected disks** are any non-USB internal disk, plus any disk that holds a Windows install or a BitLocker volume. The live USB itself and plain USB drives stay writable, so they can be backup destinations.

## 6. Data models

### 6.1 Health finding

```json
{
  "id": "BOOT-002",
  "section": "boot",
  "status": "problem",
  "title": "Boot configuration (BCD) is missing",
  "cause": "\\EFI\\Microsoft\\Boot\\BCD was not found on the EFI partition.",
  "fix": {
    "summary": "Rebuild the boot files with bcdboot",
    "tool": "request_repair",
    "args": { "kind": "bcdboot" },
    "level": "approval"
  },
  "evidence": [
    { "source": "EFI partition (disk 0, part 1)", "detail": "file not found: /EFI/Microsoft/Boot/BCD" }
  ],
  "confidence": "high"
}
```

The status values are `ok`, `warning`, `problem`, `unknown` (the collector could not run, with a reason) and `info` (does not affect the section's status).

### 6.2 Job

```
requested ─► pending_approval ─► approved ─► running ─► succeeded
                 │      │                       │
                 │      └─► rejected            └─► failed / cancelled
                 └─► expired (15 min)
```

```json
{
  "id": 12,
  "kind": "backup",
  "args": { "sources": ["profile:Priya/Documents"], "destination": null },
  "requested_by": "mcp:Claude",
  "ai_reason": "Back up documents before repairing the boot files.",
  "state": "pending_approval",
  "risk": "low",
  "decided_by": null,
  "progress": null,
  "result": null
}
```

`destination` is always chosen by the owner on the approval card. The AI never chooses where data is written.

### 6.3 Audit entry (JSONL)

```json
{"seq": 41, "ts": "2026-11-01T10:15:02Z", "session": "a1b2", "actor": "ai",
 "event": "tool_call", "tool": "query_event_log", "args": {"log": "System", "event_ids": [41]},
 "result": "ok, 7 events", "prev": "9f3c…", "hash": "c81a…"}
```

The actor is one of `ai`, `owner`, `technician` or `system`. Secrets are redacted before an entry is written.

## 7. MCP interface

### 7.1 Endpoint and setup

- URL: `https://<tunnel-host>/s/<token>/mcp`. MCP clients POST to it. A browser GET on `https://<tunnel-host>/s/<token>/` opens the dashboard.
- Requests with a wrong or expired token get **404** (not 401, so clients don't start an OAuth flow) and a small delay.
- The ASGI middleware checks the `/s/<token>` prefix and strips it before passing the request to the MCP app. The app lifespan runs `mcp.session_manager.run()`.

```python
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP(
    "rescue-ai",
    instructions=SERVER_INSTRUCTIONS,
    stateless_http=True,   # no server-side MCP sessions
    json_response=True,    # plain JSON, no SSE: works through quick tunnels
)

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_health_report(sections: list[str] | None = None) -> HealthReport:
    """Status of every section of the PC, with likely causes and suggested fixes."""
    ...
```

### 7.2 Server instructions (sent to the AI)

```
You are connected to Rescue AI on a PC that was started from a rescue USB.
Windows is NOT running; you are examining its disk from outside.

- Start with get_health_report, then use get_section for details.
- Read tools are free to use. Personal folders are hidden unless the owner shares them.
- Tools named request_* do not act immediately. They create a job that the person
  at the PC must approve on its screen. Tell the person what you requested and why,
  then check get_job_status about every 30 seconds. Do not submit duplicates.
- Never ask for a BitLocker recovery key in chat. Use request_bitlocker_unlock;
  the person types the key on the PC.
- Recommend a backup before any repair. If disk health is critical, only backup
  and imaging are allowed.
- Explain findings in plain language; the person may not be technical.
```

### 7.3 Conventions

- Keep each response small (aim for under 10k tokens). Use default limits and `cursor` paging for lists.
- Errors are sentences the AI can act on, for example: "Volume is BitLocker-locked. Call request_bitlocker_unlock."
- Paths use Windows style relative to an install, such as `C:\Windows\Minidump`. Drive letters come from the offline `SYSTEM\MountedDevices` key, and the agent maps them to mount points.
- Read tools set `readOnlyHint: true`. `request_*` tools set `destructiveHint` to match what the job can do.

### 7.4 Tool catalog

| Tool | Purpose | Level | Milestone |
|---|---|---|---|
| `get_session_info` | PC model, session expiry, mode, what is allowed | Read | M1 |
| `get_health_report(sections?)` | Status of every section and the top findings | Read | M1 |
| `get_section(section)` | All findings and evidence for one section | Read | M1 |
| `list_disks` | Model, serial, size, transport, health summary | Read | M1 |
| `list_partitions(disk_id)` | Type, size, file system, label, BitLocker, mount state | Read | M1 |
| `list_windows_installs` | Version, build, edition, computer name, users, drive letters, hibernation | Read | M1 |
| `get_disk_health(disk_id)` | SMART / NVMe details | Read | M1 |
| `get_bitlocker_status(volume_id?)` | Encrypted, locked, protector types | Read | M1 |
| `get_boot_config(install_id)` | EFI files, BCD entries, UEFI boot order, Secure Boot | Read | M1 |
| `query_event_log(...)` | Filter by log, time, level, ids, providers, text; paged | Read | M1 |
| `get_crash_history(install_id, days)` | Stop codes, minidumps, unexpected shutdowns | Read | M1 |
| `read_registry(install_id, hive, key, depth?)` | Offline registry values (SAM/SECURITY blocked) | Read | M1 |
| `list_recent_updates(install_id, days)` | Installed, failed and pending updates | Read | M1 |
| `list_recent_drivers(install_id, days)` | Driver installs and changes, failing drivers | Read | M1 |
| `list_startup_items(install_id)` | Run keys, services, scheduled tasks, Winlogon | Read | M1 |
| `get_live_system_log(filter?)` | Rescue OS kernel log (disk I/O errors this session) | Read | M1 |
| `list_dir(path, cursor?)` | Folder listing under the access rules | Read | M1 (system), M2 (shared) |
| `read_file(path, offset?, max_bytes?)` | Text files only, max 256 KB per call | Read | M1 (system), M2 (shared) |
| `find_files(root, pattern, modified_after?)` | Search under the access rules | Read | M2 |
| `list_user_profiles(install_id)` | Users and known-folder sizes (no file names) | Read | M2 |
| `request_bitlocker_unlock(volume_id, reason)` | Owner types the key on the PC | Approval | M2 |
| `request_backup(sources, reason)` | Owner approves and picks the destination | Approval | M2 |
| `request_disk_image(target, reason)` | partclone or ddrescue image | Approval | M2 |
| `get_job_status(job_id)` / `list_jobs()` / `cancel_job(job_id)` | Track or cancel the AI's own jobs | Read | M2 |
| `request_repair(install_id, kind, params, reason)` | See §12 | Approval | M3 |
| `request_boot_order(order, reason)` | `efibootmgr -o` | Approval | M3 |
| `request_shell_command(command, reason)` | Listed only in Expert mode | Approval | M4 |

**These are never exposed:** format, partition editing, deleting or writing files, approving anything, changing settings, or lifting read-only protection.

## 8. Health Status engine

### 8.1 Flow

`collectors → facts (cached, timestamped) → rules → findings → section status`

- A section's status is its worst finding: `problem` > `warning` > `ok`. It is `unknown` when a required collector failed, and the UI shows why (for example, "Unlock BitLocker to check this").
- **Timeline correlation:** "first trouble" is the earliest crash, unexpected shutdown or Automatic Repair entry in the last 30 days. Updates and drivers installed within 48 hours before it are marked as suspects.
- Output is JSON (for MCP and the report bundle) and HTML (for the local UI and the bundle).
- Target: a full scan in under 60 s on an SSD. Event logs are limited to 30 days and to the needed channels, parsed in parallel and cached.

### 8.2 Collectors

| Collector | Sources | Facts |
|---|---|---|
| disks | `lsblk -J -b`, `sfdisk -J`, `blkid`, `/sys/block` | Disks, partitions, GPT types, transport, removable |
| smart | `smartctl -j -a`, `nvme smart-log -o json` | Overall health, reallocated/pending/uncorrectable, media errors, wear %, temperature |
| bitlocker | `cryptsetup isBitlk`, `cryptsetup bitlkDump` | Encrypted volumes, protectors, locked/unlocked |
| volumes | ro mounts, `statvfs`, NTFS volume flags, `hiberfil.sys` signature | Free space, dirty flag, hibernated |
| windows | SOFTWARE and SYSTEM hives | Version/build/edition, computer name, ProfileList, MountedDevices, `HiberbootEnabled`, PendingFileRenameOperations, services and drivers |
| boot | EFI partition files, BCD hive, `efibootmgr -v`, `mokutil --sb-state` | Boot entries, missing boot files, Secure Boot state |
| eventlogs | `System.evtx`, `Application.evtx`, `Setup.evtx` | Normalised events from the last 30 days |
| crashes | `Minidump\*.dmp` headers, `MEMORY.DMP`, BugCheck 1001, Kernel-Power 41, EventLog 6008 | Crash list with stop code and parameters |
| servicing | `WinSxS\pending.xml`, `Logs\CBS\CBS.log` (tail), COMPONENTS hive | Pending operations, corruption lines |
| drivers | `INF\setupapi.dev.log`, Services keys, `System32\drivers` presence and mtimes | Recent driver installs, missing driver files |
| srt | `System32\LogFiles\Srt\SrtTrail.txt` | Automatic Repair's "root cause" |
| startup | Run/RunOnce (HKLM and each `NTUSER.DAT`), Winlogon, Services, `System32\Tasks` | Startup items with dates |
| hardware | `/sys/class/power_supply`, `sensors`, `dmidecode`, WHEA events | Battery wear, temperatures, model, BIOS version |
| livelog | `journalctl -k` | I/O errors seen during this session |

### 8.3 Rules v1

| ID | Condition | Status | Suggested fix |
|---|---|---|---|
| DISK-001 | SMART overall health FAILED | 🔴 | Back up now (backup-only mode) |
| DISK-002 | Reallocated, pending or uncorrectable sectors > 0 | 🟡 / 🔴 by count | Back up; replace the disk |
| DISK-003 | NVMe `critical_warning` ≠ 0 or `media_errors` > 0 | 🔴 | Back up now (backup-only mode) |
| DISK-004 | NVMe `percentage_used` ≥ 90 | 🟡 | Plan to replace the disk |
| DISK-005 | I/O errors in the live kernel log this session | 🔴 | Image the disk first (backup-only mode) |
| DISK-006 | Disk 7/51/153 or storport 129 events in the Windows System log | 🟡 | Check the cable/disk; back up |
| PART-001 | No EFI system partition on a UEFI install | 🔴 | Expert help (not auto-fixable in v1) |
| PART-002 | Windows volume free space < 2 GB (🔴) or < 10 GB (🟡) | 🔴 / 🟡 | Free space (owner), then retry updates |
| PART-003 | NTFS dirty flag set | 🟡 | `chkdsk_fix` |
| PART-004 | Ntfs corruption events (55, 98) | 🟡 | `chkdsk_fix` |
| PART-005 | WinRE / Recovery partition missing | 🟡 | Repairs need Windows install media |
| ENC-001 | BitLocker volume locked | ⚪ for dependent sections | `request_bitlocker_unlock` |
| ENC-002 | BitLocker suspended | ℹ️ | None |
| BOOT-001 | `\EFI\Microsoft\Boot\bootmgfw.efi` missing | 🔴 | `bcdboot` |
| BOOT-002 | BCD missing or unreadable | 🔴 | `bcdboot` |
| BOOT-003 | BCD has no Windows Boot Loader entry for this install | 🔴 | `bcdboot` |
| BOOT-004 | Windows Boot Manager missing from the UEFI boot order, or not first | 🟡 | `request_boot_order` |
| BOOT-005 | Secure Boot off | ℹ️ | None |
| WIN-001 | Windows hibernated (Fast Startup or hibernate) | 🟡 | Writes blocked until `discard_hibernation` |
| WIN-002 | Pending file renames / reboot pending | ℹ️ | None |
| WIN-003 | SYSTEM or SOFTWARE hive missing, zero-size or unreadable | 🔴 | Expert help / restore point |
| UPD-001 | `pending.xml` present (servicing stuck) | 🔴 if crashes or boot failure, otherwise 🟡 | `dism_revert_pending` |
| UPD-002 | Update installed ≤ 48 h before first trouble | 🟡 | `dism_remove_package` |
| UPD-003 | The same update fails repeatedly (WindowsUpdateClient 20) | 🟡 | Check free space; DISM |
| DRV-001 | Boot-start driver installed or changed ≤ 7 days before first trouble | 🟡 | `dism_remove_driver` |
| DRV-002 | Repeated service/driver start failures (7000, 7023, 7026) | 🟡 | Inspect; remove the driver |
| DRV-003 | Boot/system-start driver whose ImagePath file is missing | 🔴 | `dism_remove_driver` or `sfc_offline` |
| CRASH-001 | Stop codes in the last 30 days (≥ 3 → 🔴) | 🟡 / 🔴 | From the stop-code knowledge base |
| CRASH-002 | Unexpected shutdowns (Kernel-Power 41 with no bugcheck) | 🟡 | Power, overheating, hardware |
| SYS-001 | CBS.log reports corruption it couldn't repair | 🟡 | `sfc_offline`, then `dism_restore_health` |
| SYS-002 | Core file missing (`winload.efi`, `ntoskrnl.exe`, `hal.dll`, `ci.dll`) | 🔴 | `sfc_offline` / `bcdboot` |
| SRT-001 | SrtTrail.txt has a "Root cause found" entry | 🟡 / 🔴 | Mapped per cause |
| START-001 | Winlogon `Shell` or `Userinit` changed from default | 🔴 | Possible malware; expert help |
| START-002 | Service or Run key added in the last 7 days | ℹ️ | Review |
| HW-001 | WHEA errors (17, 18, 19, 47) | 🟡 / 🔴 | Hardware (CPU, RAM, PCIe) |
| HW-002 | Battery wear > 40 % | ℹ️ | None |
| HW-003 | CPU or disk temperature high | 🟡 | Cooling |

### 8.4 Knowledge base

- `kb/stopcodes.yaml` covers the 30 most common stop codes, starting with 0x7B, 0xEF, 0x50, 0xD1, 0x0A, 0x3B, 0x1E, 0x7E, 0x9F, 0x133, 0x124, 0x1A, 0xED, 0x24, 0x139, 0xC000021A and 0x116. Each entry has the name, a plain-language meaning, common causes, the sections to check and typical fixes.
- `kb/events.yaml` gives the meaning and severity of the event IDs the rules use.
- Both are data files, so they can grow without code changes.

## 9. Files and backup

### 9.1 Local file browser (owner)

- A tree of Windows volumes by drive letter and label, with badges: Locked / Read-only / Hibernated.
- Preview: text, images and PDF in the page; other files show metadata only. There is also an "Open in file manager" button (the mount is read-only).
- Search by name, type and date. Selected items go into a basket for **Back up**.

### 9.2 Rescue my files

- For each profile (from `ProfileList`), it selects Desktop, Documents, Pictures, Videos, Music and Downloads, plus browser bookmarks (Chrome/Edge `Bookmarks`, Firefox `places.sqlite`) and Outlook `.pst` files.
- Known folders are resolved through `NTUSER.DAT` → `User Shell Folders`, so folders moved into OneDrive are found.
- It shows sizes per folder and compares the total with the destination's free space **before** starting.
- AppData caches and temp folders are excluded. OneDrive files that exist only in the cloud are listed separately as "in the cloud, not on this PC".

### 9.3 Backup engine

- **Destinations:** a writable USB or external disk (exFAT, NTFS or ext4), or an SMB share. Never a protected disk.
- **Layout:** `<dest>/RescueAI-Backup/<ComputerName>_<YYYY-MM-DD_HHMM>/<User>/<Folder>/…`
- **Copy:** reads in 1 MiB chunks and computes SHA-256 while copying. On a read error it retries 3× with smaller chunks, then skips the file and records it. After copying, it re-reads the copy to verify it and preserves the modified time.
- **Manifest:** `manifest.csv` (path, size, mtime, sha256, status), `errors.csv` and `summary.html`.
- **Resume:** files already verified with the same size and mtime are skipped.
- **Special cases:**
  - EFS-encrypted files, cloud placeholders and offline files: skipped and listed. They are detected through the `system.ntfs_attrib` extended attribute.
  - Junctions and symlinks: not followed.
  - FAT32 destination: files over 4 GB are refused with a clear message.
- Progress, ETA, pause and cancel are shown live in the UI.
- Optional encrypted backup (7-Zip AES-256 per user) comes in M4.

### 9.4 Failing disk and imaging

- If DISK-001, DISK-003 or DISK-005 fires, **backup-only mode** turns on. Repairs are refused, heavy scans (`find_files`) are disabled, and the UI recommends imaging first.
- **Failing disk:** `ddrescue -d -n` (a fast pass that skips bad areas), then `ddrescue -d -r3` (retries), with a mapfile on the destination so it can resume. The image is then attached with `losetup -r` and mounted read-only (or opened with cryptsetup for BitLocker), and files are backed up from the image.
- **Healthy disk:** `partclone.ntfs` copies only used blocks. BitLocker volumes are imaged raw with ddrescue, so they stay encrypted.

### 9.5 What the AI can read

| Area | AI access |
|---|---|
| Everything outside `\Users\` | List and read (text only, size-capped), except the deny list |
| `\Users\<name>\…` | Hidden. `list_user_profiles` shows folder names and sizes only. The owner can share specific folders as **names only** or **names + contents**; shares end when the session stops |
| Deny list (never, even when shared) | `\Windows\System32\config\*` (use `read_registry`), SAM, SECURITY, `hiberfil.sys`, `pagefile.sys`, `swapfile.sys`, `…\Microsoft\Protect`, `…\Microsoft\Credentials`, `\ProgramData\Microsoft\Crypto`, `\ProgramData\Microsoft\Wlansvc\Profiles`, browser `Login Data`, `Cookies`, `logins.json`, `key4.db` |

- `read_file` detects the text encoding (UTF-8, UTF-16LE BOM, then CP-1252). For binary files it returns metadata only (size, type, sha256).
- Paths are normalised and resolved. `..`, NUL bytes, and symlinks or junctions that leave an allowed root are rejected.

## 10. Approvals

### 10.1 Approval card

The agent builds the card from the job's parameters, never from AI-written text:

- **What will happen**, a plain sentence from a template, plus the exact operation or command line.
- **Target**: disk model and serial, partition, size, drive letter.
- **Risk** (Low / Medium / High), **reversible?**, **estimated time**, and prerequisites (backup done? disk healthy?).
- **"Reason given by the AI"**, shown in a separate quoted box with a note: "Check that this makes sense."
- **Approve / Reject.** High-risk jobs require typing `APPROVE`.
- The destination picker appears here for backup and imaging jobs.
- A desktop notification and sound fire when a new request arrives. Requests expire after 15 minutes.

### 10.2 Who can approve

| Who | How |
|---|---|
| Person at the PC | Local UI on port 8766, with the session cookie |
| Technician | Only if the owner turned on "Remote approval with PIN" for this session. The PC shows a 6-digit PIN for each job; it is single-use and lasts 5 minutes. After 3 wrong PINs, remote approval turns off |
| AI | **Never.** No MCP tool approves anything, and MCP traffic can't reach the local listener |

### 10.3 Gating rules (`policy.py`)

| Condition | Effect |
|---|---|
| Disk health critical | Only backup and imaging; repairs are refused with the reason |
| Windows hibernated | Repairs are refused until `discard_hibernation` is approved (with a warning that unsaved work in open apps is lost) |
| No backup this session | The first repair requires the owner to tick "I have a backup" or "Skip backup" |
| BitLocker locked | Dependent tools answer "locked: request unlock" |
| Expert mode off | `request_shell_command` isn't listed |
| Session stopped or expired | Every public request gets 404 |

## 11. Rescue session and connectivity

### 11.1 Lifecycle

**Start Rescue:**

1. Check the internet connection. If it's down, show Wi-Fi help, phone USB tethering, or the offline report.
2. Create a session id and token (`secrets.token_urlsafe(32)`). The default expiry is 3 hours; the owner can add +1 hour, up to 12 hours.
3. Bind the public listener, start the tunnel, read the public URL, and **self-test it through the tunnel** (`GET /s/<token>/healthz`) before showing it.
4. Show the URL, the QR code, a copy button, the expiry, and short connection steps for claude.ai, Claude Desktop and Claude Code.
5. After the first `initialize`, show "Connected: \<clientInfo.name\>" and a live activity feed that describes each tool call in plain words.

**Stop:** revoke the token → stop the tunnel → close the listener → cancel pending jobs → ask what to do about running jobs → write the session bundle (audit log, jobs, before/after health).

### 11.2 Tunnel options

| Option | Use | Notes |
|---|---|---|
| Cloudflare quick tunnel | MVP default | `cloudflared tunnel --no-autoupdate --url http://127.0.0.1:8765`. No account and a random URL, but no uptime guarantee and request limits. We don't depend on SSE |
| frp to our own server | Production / self-hosted | `frpc` → `frps` on a VPS, giving `https://<session>.rescue.<domain>`, with wildcard TLS (e.g. Caddy). Same token scheme |
| Tailscale | Claude Code on a technician's machine | Nothing public; Claude Code connects to the tailnet IP |
| Fixed-URL relay | Avoid re-adding the connector every session | One permanent connector URL plus a pairing code shown on the PC. **Design spike in M4** |

### 11.3 Extra protection on the public listener

- Optional IP allowlist for `/mcp`, using Anthropic's published outbound IP ranges. The client IP comes from `CF-Connecting-IP`, which is trusted only when the request comes from the local cloudflared.
- Rate limit of 10 requests/s per client and a 1 MB body limit.
- Only the first 4 characters of the token are ever logged.

## 12. Windows repair runner (M3)

### 12.1 Steps

1. **Pre-checks** (policy): approved, disk not critical, not hibernated, backup acknowledged, `/dev/kvm` present. Without KVM, show "Turn on virtualisation (VT-x / AMD-V) in the BIOS"; a slow software fallback is allowed with a warning.
2. **Find WinRE:** read `\Windows\System32\Recovery\ReAgent.xml` and look for `\Recovery\WindowsRE\Winre.wim` on the Recovery partition, or `C:\Windows\System32\Recovery\Winre.wim`. If it's missing, ask the owner to plug in Windows install media (`sources\boot.wim` works the same way).
3. **Patch a copy** in `/run/rescue/work` with `wimlib-imagex update`: add `\rescue\` scripts and replace `Windows\System32\winpeshl.ini` so it launches `rescue\run.cmd` instead of the recovery menu. **The original on the disk is never touched.**
4. **Boot method**, decided in the spike:
   - (a) iPXE `wimboot` loading the WIM directly, or
   - (b) a small FAT EFI disk laid out like Windows install media: `bootmgfw.efi`, `BCD` and `boot.sdi` from the PC's own `C:\Windows\Boot\`, with the patched WIM as `\sources\boot.wim`.
5. **Job disk:** a 64 MB FAT image built with `mkfs.vfat -C` and `mcopy` (no mounting). It holds `job.json`, the script for this repair kind and, if needed, the BitLocker key, which is wiped as soon as the VM exits.
6. **Disk handoff:** unmount all volumes on the target disk → `blockdev --setrw` on the disk and its partitions → run the VM → `blockdev --setro` → remount read-only → re-run Health Status → show the before/after difference. The `setro` step runs in a `finally` block and on agent start-up.
7. **QEMU** (no network):

   ```
   qemu-system-x86_64 -machine q35,accel=kvm -cpu host -m 3072 -smp 2 \
     -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
     -drive if=pflash,format=raw,file=/run/rescue/work/vars.fd \
     -device ahci,id=ahci \
     -drive file=/dev/nvme0n1,format=raw,if=none,id=win,cache=none \
     -device ide-hd,drive=win,bus=ahci.0 \
     -drive file=/run/rescue/work/jobdisk.img,format=raw,if=none,id=job \
     -device ide-hd,drive=job,bus=ahci.1 \
     -drive file=/run/rescue/work/boot.img,format=raw,if=none,id=boot \
     -device ide-hd,drive=boot,bus=ahci.2,bootindex=0 \
     -serial file:/run/rescue/work/serial.log -display none -nic none
   ```

   AHCI is used so that WinRE's inbox driver sees the disk without extra drivers.
8. **Inside WinRE, `run.cmd`:**
   - Find the Windows volume by matching its volume serial (from Linux `blkid`) against `vol` output.
   - Assign the EFI partition a letter with `diskpart`.
   - Unlock BitLocker if needed (`manage-bde -unlock W: -RecoveryPassword …`).
   - Run the repair, copy `CBS.log`, `dism.log` and the tool output to the job disk, write `result.json`, then run `wpeutil shutdown`.
9. The Linux side reads the results and stores them on the job. A timeout per kind kills the VM; the disk handoff still restores read-only.

RAM needed: about 3 GB for the VM, about 1 GB for the boot image, and the live system on top. **Repairs need ≥ 8 GB of RAM.**

### 12.2 Repair kinds

| Kind | Runs (inside WinRE unless noted) | Risk |
|---|---|---|
| `bcdboot` | `bcdboot W:\Windows /s S: /f UEFI` | Medium |
| `sfc_offline` | `sfc /scannow /offbootdir=W:\ /offwindir=W:\Windows` | Low |
| `dism_revert_pending` | `dism /Image:W:\ /Cleanup-Image /RevertPendingActions` | Medium |
| `dism_remove_package` | `dism /Image:W:\ /Remove-Package /PackageName:<from /Get-Packages>` | Medium |
| `dism_remove_driver` | `dism /Image:W:\ /Remove-Driver /Driver:oemNN.inf` | Medium |
| `chkdsk_fix` | `chkdsk W: /f` (never on a failing disk) | Medium |
| `dism_restore_health` | `dism /Image:W:\ /Cleanup-Image /RestoreHealth /Source:wim:<src>:<idx> /LimitAccess`. Needs a matching Windows ISO from the owner | Medium |
| `discard_hibernation` (Linux) | `ntfs-3g` mount with `remove_hiberfile`, then unmount | Medium (unsaved work in open apps is lost) |
| boot order (Linux) | `efibootmgr -o …` | Low |

Note: a WinRE that is older than the installed Windows may refuse some DISM operations. When the owner provides a matching Windows ISO, prefer its `boot.wim`.

## 13. Milestones

### M0: Live OS (≈ 2 weeks)

- [ ] Set up the build host: a Debian 13 VM (4 vCPU, 8 GB RAM, 60 GB disk) with `live-build`. Avoid WSL2, because live-build needs loop devices and chroot mounts.
- [ ] `lb config`: trixie, amd64, archive areas `main contrib non-free-firmware`, `iso-hybrid`, UEFI + BIOS boot, `--uefi-secure-boot enable`, `--apt-recommends false`, no installer.
- [ ] Package lists:
  - **Desktop:** `xfce4 xfce4-terminal thunar lightdm network-manager-gnome firefox-esr atril ristretto mousepad file-roller gnome-disk-utility fonts-noto-core`
  - **Firmware:** `firmware-iwlwifi firmware-realtek firmware-atheros firmware-brcm80211 firmware-mediatek firmware-misc-nonfree firmware-sof-signed firmware-amd-graphics intel-microcode amd64-microcode`
  - **Rescue tools:** `smartmontools nvme-cli ntfs-3g cryptsetup dislocker efibootmgr mokutil gddrescue partclone wimtools qemu-system-x86 ovmf mtools dosfstools exfatprogs cifs-utils rsync rclone lm-sensors dmidecode pciutils usbutils python3 python3-venv`
- [ ] Autologin user `rescue`. Desktop icons: **Health Status**, **Files & Backup**, **Start Rescue**.
- [ ] Read-only protection: udev rule (`blockdev --setro` on protected disks and their partitions) and `udisks2` `mount_options.conf`.
- [ ] Persistence: `persistence` boot parameter. `make-usb.sh` writes the ISO, appends an ext4 partition labelled `persistence`, and writes a `persistence.conf` with:
  ```
  /home union
  /etc/NetworkManager/system-connections union
  /var/lib/rescue union
  ```
  Also check whether Rufus's persistence option works with Secure Boot, for Windows users.
- [ ] Boot menu: **Normal** · **Load to RAM** (`toram`, persistence off) · **Safe graphics** (`nomodeset`) · **Private** (no persistence).
- [ ] Trimming: dpkg `path-exclude` for docs, man pages and unused locales; xz squashfs.
- [ ] Firefox ESR policies: telemetry off; home page is the local UI.
- [ ] A stub `rescue-agent.service` to prove the systemd wiring.

**Acceptance**
- ISO ≤ 1.5 GB, or the actual size documented with a trimming plan.
- Boots with Secure Boot **on** in:
  - QEMU + OVMF (`OVMF_CODE_4M.secboot.fd` + `OVMF_VARS_4M.ms.fd`)
  - Hyper-V Gen 2 with the **"Microsoft UEFI Certificate Authority"** template
  - VirtualBox 7 (EFI + Secure Boot)
  - **the Dell**
- On the Dell: Wi-Fi and Ethernet work; a Wi-Fi password and a desktop file survive a reboot; the NVMe is visible even in "RAID On" (Intel VMD) mode.
- Load to RAM: the USB can be pulled after the desktop appears, and the apps keep working.
- Protected disk: `blockdev --getro` returns 1 for the disk and all its partitions. Mounting from Thunar is read-only, and `touch` fails.

### M1: Read-only agent, Health Status, tunnel (≈ 4 weeks)

- [ ] Agent skeleton: package, config, systemd unit, local listener with cookie/Host/Origin/CSRF protection, audit log.
- [ ] Disk discovery, read-only guard and mount manager. Windows install discovery, with drive letters from `MountedDevices`.
- [ ] All collectors in §8.2, each with fixtures and unit tests.
- [ ] Health engine, rules v1 (§8.3) and stop-code knowledge base.
- [ ] Local UI:
  - **Health** page: sections, statuses, evidence drawer, "Copy report"
  - **Rescue** page: start/stop, URL, QR, expiry, connected client, activity feed
- [ ] MCP server: the M1 tools from §7.4, server instructions, annotations, paging and size caps.
- [ ] Session and tunnel manager: cloudflared quick tunnel, with Tailscale as an option.
- [ ] Read-only technician dashboard: health and activity.
- [ ] **Dev mode:** run the agent on any Linux machine against a disk image (`--disk-image win11.img`, attached with `losetup -r`), for fast iteration without rebooting.
- [ ] Build breakage-lab scenarios 1–10 (§14.2).

**Acceptance**
- Health Status flags every planted lab problem with the right section and status.
- A full scan takes under 60 s on the Dell.
- Claude (claude.ai connector, Claude Desktop and Claude Code) connects, runs every read tool, and explains the planted problem in each lab scenario.
- **Read-only proof:** the SHA-256 of the lab disk image is identical before and after a full Rescue session.
- After Stop, the URL returns 404 within 5 s. Expiry works. No public listener exists while Rescue is off.

### M2: Approvals, Files and Backup, imaging (≈ 4 weeks)

- [ ] Job queue and state machine (SQLite), approval card UI, notifications, expiry, PIN remote approval.
- [ ] Gating rules (§10.3).
- [ ] BitLocker unlock flow: the AI requests → a local dialog for the key → `cryptsetup open --type bitlk --readonly` → read-only mount → Health Status runs again. The key is held only in memory.
- [ ] File browser UI with previews and search. **Rescue my files**. OneDrive placeholder and EFS handling.
- [ ] Backup engine (manifest, verify, resume, errors) and destinations (USB/external, SMB).
- [ ] Imaging: partclone for healthy disks, ddrescue with a mapfile for failing ones. Mount an image for file recovery.
- [ ] AI file tools (`list_dir`, `read_file`, `find_files`, `list_user_profiles`) and the folder-sharing UI.
- [ ] `request_*` tools for M2, plus `get_job_status`, `list_jobs` and `cancel_job`.

**Acceptance**
- A 20 GB mixed backup is 100 % verified. Unplugging and replugging the destination resumes where it stopped.
- With simulated bad sectors (QEMU `blkdebug` or `dm-error`):
  - the backup finishes and lists the unreadable files
  - the ddrescue image completes with its mapfile
  - backup-only mode blocks repairs
- An automated test shows every way of self-approval fails: via MCP, via the dashboard without a PIN, with a wrong PIN, and by POSTing to the local port through the tunnel.
- A BitLocker lab drive unlocks with its recovery key. The key string never appears in the audit log, the database or MCP responses (grep test).
- The AI can't read personal files until they are shared, and can't read deny-listed files even when shared.

### M3: Windows repair runner (≈ 5 weeks, including a 1-week spike)

- [ ] **Spike (week 1):** boot WinRE from `Winre.wim` in QEMU/OVMF, comparing `wimboot` with the EFI disk. Pass the disk through over AHCI, automate with `winpeshl.ini`, and stream logs over serial. **Go/no-go at the end of the week.**
- [ ] Repair runner: WIM patching, job disk, VM lifecycle, timeouts, disk handoff, result parsing.
- [ ] The repair kinds in §12.2, including the Linux-side `discard_hibernation` and boot order.
- [ ] Before/after Health Status diff in the UI and in the job result.
- [ ] Pre-repair guards.

**Acceptance**
- Lab results:
  - missing BCD → `bcdboot` → Windows boots
  - stuck update → revert → Windows boots
  - bad boot driver → removed → Windows boots
  - missing system file → `sfc_offline` restores it, or reports that a DISM source is needed
  - dirty volume → `chkdsk_fix` → clean
- The disk is read-only again after every job, including when QEMU is killed in the middle of a repair (tested).
- Works on the Dell with KVM. Shows a clear message when VT-x is disabled.

### M4: Expert mode, other connections, hardening (≈ 3 weeks)

- [ ] Expert mode: an owner toggle with typed confirmation. `request_shell_command` shows each command verbatim for approval, adds red warnings for dangerous patterns (`mkfs`, `dd of=`, `wipefs`, `parted`, `rm -rf`), and enforces timeouts and output caps.
- [ ] SSH: off by default and reachable only over Tailscale, with a one-time key or password.
- [ ] RustDesk client configured for our own server, started from the Rescue page. It shows the ID and a one-time password.
- [ ] Offline report bundle: a zip under 10 MB containing the health JSON and HTML, filtered event extracts, SrtTrail, CBS/setupapi excerpts, minidump headers (not full dumps), SMART data, partition table, a BCD dump, and `README_FOR_AI.md`. No personal files.
- [ ] Self-hosted frp tunnel, IP allowlist, rate limits. Fixed-URL relay spike.
- [ ] Optional encrypted backups.
- [ ] Security review against §15, dependency pinning, an SBOM, and signed `SHA256SUMS` for the ISO.
- [ ] User guide and technician guide.

**Acceptance**
- The security checklist review finds no critical issues.
- Uploading the offline bundle to a Claude chat gives the right diagnosis for the lab scenarios.
- RustDesk works through our own server. SSH is reachable only over the tailnet.

## 14. Testing

### 14.1 Unit tests

Fixtures come from the lab VMs, never from real users' data: hives, `.evtx` files, smartctl/NVMe JSON (healthy and failing), minidump headers, SrtTrail.txt, CBS.log and setupapi.dev.log samples. Every collector and every rule has tests.

### 14.2 Breakage lab

The lab is a Windows 11 VM on a Linux host using QEMU/KVM, with qcow2 snapshots and `swtpm` for a virtual TPM. For each scenario: snapshot → break it → shut down → boot the rescue ISO with the disk attached → check Health Status → (from M3) repair → confirm Windows boots → revert the snapshot.

| # | How to break it | Expected finding |
|---|---|---|
| 1 | Delete `\EFI\Microsoft\Boot\BCD` | BOOT-002 🔴 |
| 2 | Fill C: to < 1 GB | PART-002 🔴 |
| 3 | Fast Startup on, then a normal shutdown | WIN-001 🟡 |
| 4 | Turn on BitLocker (save the recovery key) | ENC-001 ⚪ until unlocked |
| 5 | Crash with Sysinternals NotMyFault (several crash types) | CRASH-001 with the correct stop codes |
| 6 | Boot-start driver pointing to a missing file | DRV-003 🔴 |
| 7 | Power off during "Working on updates" | UPD-001 🔴 |
| 8 | Delete `winload.efi` | SYS-002 🔴, SRT-001 |
| 9 | Change Winlogon `Userinit` | START-001 🔴 |
| 10 | Inject read errors (QEMU `blkdebug`) | DISK-005 🔴, backup-only mode |

M3 needs KVM, so use a spare physical PC or turn on nested virtualisation.

### 14.3 Hardware matrix

QEMU/OVMF, Hyper-V Gen 2, VirtualBox 7, **the Dell**, one HP and one Lenovo (including a "Secured-core" model), and one older BIOS/legacy PC. On each, test: boot with Secure Boot on, Wi-Fi, Ethernet, KVM availability and disk visibility.

### 14.4 Safety tests (automated, every release)

- Read-only proof: disk image hash before and after.
- Approval-bypass attempts (§13 M2).
- Path traversal and junction escape; deny-list reads.
- Secrets never in logs, the database or responses.
- Token expiry, and no listener while Rescue is off.
- Rate limits.
- Read-only restored after a killed VM.

## 15. Security checklist

- [ ] Web and MCP handlers never build shell strings. They call typed functions, which use `subprocess` with argument lists (no `shell=True`).
- [ ] All inputs are validated with pydantic. Paths are normalised and resolved.
- [ ] The token is 256-bit and compared in constant time; only 4 characters are ever logged.
- [ ] Local UI: per-boot secret cookie, Host/Origin checks and CSRF tokens.
- [ ] The only approval route on the public listener is the PIN route, which is rate-limited with 3 tries.
- [ ] Redaction of BitLocker keys, PINs and tokens in all logs.
- [ ] Prompt injection: file and log content is treated as data. Approval cards are built from job parameters, and the AI's reason is labelled as such.
- [ ] Supply chain: pinned Debian snapshot (snapshot.debian.org) for reproducible builds, pip wheels with hashes, and cloudflared/frp/RustDesk downloads pinned by SHA-256.
- [ ] ISO released with `SHA256SUMS` and a signature (GPG or minisign).
- [ ] Privacy: the session bundle lists everything shared with the AI, and an "Export & delete logs" button is available.

## 16. Open questions

1. Main user: PC owners or technicians? This affects UI wording and defaults.
2. Exact Dell model: Wi-Fi chip, and storage mode (AHCI or RAID On / Intel VMD).
3. Our own server and domain for frp, RustDesk and the fixed-URL relay: yes or no?
4. Support legacy BIOS/MBR repairs in v1, or report only? (Recommended: report only.)
5. Languages beyond English?
6. Open-source the agent? Under which licence?
