# Rescue AI

**A bootable USB that checks a broken Windows PC, rescues its files, and lets an AI fix it, with the owner approving every change.**

Proposal · Draft v0.1 · November 2026
Companion document: [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md)

---

## 1. Summary

Rescue AI is a USB stick that starts a PC into a small but complete Linux desktop, even when Windows is broken. Without any outside help, it:

- checks every part of the PC and explains in plain language what is wrong and what probably caused it, and
- lets the owner open, read and back up their files to another drive.

When more help is needed, the owner clicks **Start Rescue** and the screen shows a secure link. Claude, or any other AI tool that supports MCP (the open standard Claude uses for connectors), can use that link to examine the PC, explain the problem and propose fixes. **Nothing on the Windows disk changes until the person at the PC clicks Approve.**

**Is it possible? Yes.** Every part can be built from proven open-source tools. We estimate about 18 weeks of work for one experienced developer. The riskiest part is running Windows' own repair tools inside a small virtual machine. It is scheduled after the parts that are useful on their own, and it starts with a one-week test to confirm the approach works.

## 2. The problem

- When Windows will not start, every normal way to get help stops working. Remote-support apps, remote desktop and AI chat on that PC all need Windows to be running.
- The owner is left with poor options: pay for a repair visit, reinstall Windows and risk losing files, or follow generic online guides that may not fit their problem.
- The evidence that explains the failure is on the disk: crash records, event logs, update history, disk health and boot settings. It is hard to read from outside Windows.
- Files are most at risk exactly when the PC is failing. A dying disk may allow only one last good copy.

## 3. The solution at a glance

| Way to use it | Who | Needs internet | Needs an AI |
|---|---|---|---|
| **Health Status + file rescue** | Anyone at the PC | No | No |
| **Rescue mode with an AI** | The owner, plus Claude or another MCP-capable AI | Yes | Yes |
| **Technician help** | The owner, plus a remote technician using a browser dashboard or remote desktop | Yes | Optional |
| **Offline report** | When the PC can't get online | Another device does | Optional |

### What the owner does

1. Plug in the USB and start the PC from it. On a Dell, press F12 at power-on.
2. The **Health Status** page opens. It shows every part of the PC in green, yellow or red, with a plain explanation.
3. Optional: click **Rescue my files** to copy Desktop, Documents, Pictures and other folders to another USB drive.
4. Click **Start Rescue**. The screen shows a link and a QR code.
5. Add the link to Claude:
   - In claude.ai or Claude Desktop, go to Settings → Connectors → Add custom connector.
   - In Claude Code, run `claude mcp add --transport http rescue <URL>`.
6. Describe the problem. Claude reads the evidence and explains what it finds. When it wants to change something, a card appears **on the PC's screen** that says exactly what will happen. The owner approves or rejects it.
7. Click **Stop**. The link stops working immediately and a full log is saved on the USB.

## 4. Features

### 4.1 An everyday desktop

- Debian Linux with the lightweight Xfce desktop, in an ISO of about 1.5 GB.
- Starts with Secure Boot on. Wi-Fi and Ethernet work.
- Includes Firefox, a file manager, a terminal, a PDF viewer and a disk tool.
- Saves settings, Wi-Fi passwords and repair logs on the USB between uses.
- A "Load to RAM" start option means the USB can be removed after start-up.
- Windows drives always open read-only unless a change is approved.

### 4.2 Health Status: what's wrong, section by section

Each section gets one of four statuses:

- 🟢 OK
- 🟡 Warning
- 🔴 Problem
- ⚪ Can't check, with the reason (for example, "drive is locked by BitLocker")

Each status comes with the likely cause, a suggested fix, and whether that fix needs approval. Tapping a section shows the evidence behind it.

| Section | What it checks |
|---|---|
| Disk health | Wear, bad sectors, temperature, read errors |
| Partitions | Required partitions present, free space, file-system errors |
| Encryption | Whether BitLocker is on, off or locked |
| Boot | Boot files, boot configuration, boot order, Secure Boot |
| Windows state | Version, hibernation or Fast Startup, unfinished restarts |
| Updates | Recent updates, updates stuck half-installed |
| Drivers | Drivers changed recently, drivers that fail to load |
| Crashes | Blue-screen stop codes, sudden shutdowns |
| System files | Missing or damaged core Windows files, and the diagnosis from Windows' own Automatic Repair |
| Startup items | Programs and services that start with Windows, and recent changes to them |
| Hardware | Hardware errors logged by Windows, battery wear, temperatures |

The page also links events in time, for example: "a storage driver was updated 2 days before the crashes started". It works with no internet and no AI, and the AI sees exactly the same report.

### 4.3 Files: read and back up

- Browse the Windows drives safely (read-only), preview documents and photos, and search by name, type or date.
- **Rescue my files** selects each user's Desktop, Documents, Pictures, Videos, Music, Downloads and browser bookmarks in one click. This includes folders that were moved into OneDrive.
- Back up to a USB drive, an external disk or a network share. Every file is checked after copying, an interrupted backup resumes where it stopped, and unreadable files are listed rather than silently skipped.
- **Failing disk:** the whole drive is first copied to an image file with a tool built for damaged disks. Files are then recovered from that copy, so the failing disk is read as little as possible.
- The app clearly says what can't be copied: drives locked by BitLocker when there is no key, OneDrive files that exist only in the cloud, and files encrypted with Windows' file encryption.

### 4.4 Rescue mode: connect an AI

- One click creates a secure link (and QR code) that is random and expires.
- It works with Claude on the web, Claude Desktop and Claude Code, and with any other AI tool that supports MCP connectors.
- The PC's screen shows who is connected and a live list of everything the AI looks at.

### 4.5 Approved repairs

Repairs use Windows' own repair tools. They run inside a small virtual machine that starts from the PC's own recovery image. The repairs are:

- rebuild boot files
- repair system files (SFC, DISM)
- undo a stuck update, or uninstall a recent update
- remove a bad driver
- fix file-system errors (chkdsk)
- change the boot order

After each repair, Health Status runs again and shows the before and after.

### 4.6 Other ways to connect

- **Technician dashboard:** a person opens the same link in a browser.
- **Full remote desktop:** RustDesk, using a server we host ourselves.
- **Claude Code over SSH:** the most flexible option, with the fewest guardrails. It is for experts only and works over a private network only.
- **Offline:** save a report bundle to a USB stick, upload it to any AI chat, and follow its steps.

## 5. Safety and privacy

| Level | What's included |
|---|---|
| **Free to read** | Disks, partitions, Windows details, disk health, BitLocker state, event logs, crash records, registry settings, updates, drivers, boot settings, system log files |
| **Owner shares at the PC** | Personal folders. These are hidden from the AI unless the owner shares a folder, as file names only or as names and contents |
| **Needs approval at the PC** | BitLocker unlock (the key is typed on the PC), file backup, disk imaging, Windows repairs, boot order |
| **Blocked** | Formatting, changing partitions, deleting files, reading passwords and saved credentials, free-form commands (unless Expert mode is on) |

Safety rules:

- **Approvals happen only on the PC.** If the owner allows it, a technician can also approve by entering a one-time PIN shown on the PC's screen. The AI has no way to approve its own requests.
- **Rescue AI writes the approval card, not the AI.** The card shows exactly which disk and which operation are involved. The AI's stated reason is shown separately.
- **Read-only at three levels.** The disk itself is locked read-only, Windows drives are mounted read-only, and every action is checked against the permission list.
- **The link** is random. It stops working when Rescue stops or after a few hours, and it can be limited to Anthropic's network addresses.
- **Failing disk rule.** If disk health is critical, only backup and imaging are allowed.
- **Backup first.** Before the first repair, the owner either confirms that a backup exists or chooses to skip it.
- **BitLocker keys never leave the PC.** The key is typed on the PC and kept only in memory. It is never shown to the AI or written to logs.
- **Full log.** Every request, decision and result is recorded in a tamper-evident log saved on the USB.
- **Expert mode** can only be turned on by the owner at the PC. It gives the AI a command line, but every command is still shown and approved first.

Rescue AI deliberately does **not** reset or bypass Windows passwords, unlock BitLocker without the key, or hide its activity. Anyone with physical access can already start a PC from a Linux USB. BitLocker remains the real protection, and Rescue AI respects it.

## 6. Is it possible?

Yes. Each part relies on proven, widely used open-source tools.

| Part | Feasible | Difficulty | Built on |
|---|---|---|---|
| Live USB with Secure Boot, persistence and load-to-RAM | ✅ | Easy–Medium | Debian live-build, Microsoft-signed shim boot loader |
| Health Status page | ✅ | Medium | smartmontools, registry and event-log readers, cryptsetup |
| File browser and backup | ✅ | Easy–Medium | Linux NTFS driver (read-only), GNU ddrescue, partclone |
| AI connection (MCP and secure link) | ✅ | Medium | Official MCP Python SDK; Cloudflare Tunnel, frp or Tailscale |
| Approval screen | ✅ | Medium | Local web app |
| Windows repairs in a virtual machine | ✅ | **Hard** | QEMU/KVM, the PC's own Windows Recovery image, wimlib |
| Expert mode, remote desktop, offline report | ✅ | Easy–Medium | RustDesk, OpenSSH |

Known limits:

- Without the BitLocker recovery key, an encrypted drive can't be read or repaired. This is by design.
- Some PCs need a BIOS setting changed before they will start a Linux USB with Secure Boot on (see section 10).
- Windows repairs need virtualisation turned on in the BIOS (it usually is) and at least 8 GB of RAM.
- The free Cloudflare link is fine for testing but has no uptime guarantee. Production should use our own server.

## 7. Scope

**In the first version:** everything in section 4, for Windows 10 and 11 on 64-bit UEFI PCs, in English only.

**Not in the first version:**

- Repairing older BIOS/MBR Windows installs. They are detected and reported; repairs come later.
- Malware removal. Suspicious startup items are only flagged.
- Recovering deleted files. This is a candidate for a later version.
- Reinstalling Windows, password reset, Mac or Linux repair, and hardware repair.

## 8. Plan and timeline

| Milestone | What we can demo at the end | Estimate |
|---|---|---|
| **M0: Live USB** | Boots on the Dell and in VMs with Secure Boot on. Wi-Fi, persistence and load-to-RAM work. Windows drives are read-only | 2 weeks |
| **M1: Look, don't touch** | The Health Status page works. Claude connects through the link and diagnoses problems planted on test PCs | 4 weeks |
| **M2: Approvals and files** | Approval screen, file browser, Rescue my files, backup, disk imaging and BitLocker unlock | 4 weeks |
| **M3: Repairs** | Claude fixes planted problems end to end (boot files, stuck update, bad driver, system files) and Windows starts again | 5 weeks |
| **M4: Experts and hardening** | Expert mode, remote desktop, SSH, offline report, self-hosted link and a security review | 3 weeks |
| **Total** | | **About 18 weeks** for one experienced developer. Two developers can work on the OS and the agent in parallel and finish sooner |

Each milestone ends with a working demo. M0–M2 already make a useful product, even if M3 takes longer than planned.

## 9. Costs

| Item | Cost |
|---|---|
| Software | Free. All components are open source |
| Link for the first version | Free (Cloudflare quick tunnel) |
| Our own server, for the production link and the remote-desktop relay | A small virtual server at roughly $5–20 per month, plus a domain name |
| Test hardware | The Dell, plus 2–3 other laptops (borrowed or refurbished) |
| AI | Each user's own Claude plan, which must support custom connectors |
| Development | About 18 developer-weeks |

Distributing the USB image means publishing the source code and licence notices of its open-source parts. This is normal for Linux-based products. We don't distribute any Microsoft software, because repairs use the recovery image that is already on the PC.

## 10. Risks

| Risk | Impact | What we do about it |
|---|---|---|
| A PC won't start the USB with Secure Boot on. Some newer laptops disable the Microsoft third-party certificate by default, and Microsoft is replacing its 2011 Secure Boot certificates with 2023 ones during 2026 | The USB doesn't boot | Test on several brands from M0, write a short guide to the BIOS setting, and keep firmware updated |
| The Wi-Fi chip isn't supported | No connection for Rescue mode | Use Ethernet, phone USB tethering or the offline report |
| Running Windows repair tools in a VM proves harder than expected | M3 is delayed | Run a 1-week test first. M0–M2 deliver value regardless. Fallback: the AI guides a repair from Windows install media |
| The AI proposes a wrong fix | It could make things worse | Every change is approved on the PC, with a backup first, a before/after report and a full log |
| Hidden instructions inside files or logs try to mislead the AI | The AI asks for a harmful action | Rescue AI, not the AI, writes the approval card. Blocked actions can't be requested at all |
| Long operations time out on the AI's side | Sessions break | Actions run as background jobs that the AI checks on |
| Privacy concerns | Low trust | Personal files are hidden by default, keys never leave the PC, and the owner can export and delete logs |
| The free Cloudflare link is unreliable | Sessions drop | Use our own server (frp) in production |

## 11. How we'll measure success

- Starts with Secure Boot on for at least 9 out of 10 tested PCs.
- Health Status finds all 10 problems planted in our test lab.
- Zero changes to a Windows disk without approval, proven by comparing the disk's fingerprint (hash) before and after test sessions.
- Every backed-up file is verified.
- Claude repairs the four most common boot failures in the lab, and Windows starts afterwards.
- A non-technical tester rescues their files without help in under 15 minutes.

## 12. Decisions needed

1. **Main user:** everyday PC owners, or technicians? The answer changes the wording and the defaults.
2. **Target hardware:** the exact Dell model, and which other PCs to support first.
3. **Our own server:** do we approve a small server and a domain name for the production link and remote desktop?
4. **Open source:** do we publish the Rescue AI agent's code openly or keep it private?
5. **Name and languages:** do we keep the name "Rescue AI", and do we start in English only?
