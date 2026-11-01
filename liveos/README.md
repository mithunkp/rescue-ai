# Rescue USB (based on Debian 13)

A small bootable USB image (about 0.5–0.7 GB). Boot a broken Windows PC from it, plug in the Ethernet cable, and the screen shows a link and QR code for Claude. The Rescue AI agent is built in, so nothing is installed at the PC.

## What happens at boot

1. The boot menu starts **Rescue AI** automatically after 5 seconds. Secure Boot can stay on.
2. Linux starts, connects through the Ethernet cable on its own, and syncs the clock.
3. The agent mounts Windows **read-only** and opens the secure link.
4. Screen 1 shows the status, the link, a QR code, what was found, and what Claude is doing.
5. When Claude wants to change something, a card fills the top of the screen showing exactly what will change, the risk, and Claude's reason. Nothing happens until you press **Y**.

| Key | Action |
|---|---|
| **Y / N** | Approve or reject the change on screen |
| **L** | New link (the old one stops working) |
| **S** | Stop sharing |
| **E** | Expert mode on/off: lets Claude ask to run commands (each one still needs Y) |
| **P** | Power off |

For troubleshooting, press **Alt+F2** for a shell (`sudo journalctl -u rescue-agent`, log in `/var/log/rescue-ai.log`), then **Alt+F1** to go back.

## Get the image

**From GitHub (no Linux needed):** every push to `main` that changes `agent/`, `liveos/` or the workflow builds the image in about 20–30 minutes. Download it from **Actions → Build Rescue USB image → latest run → Artifacts → rescue-ai-iso**. You can also start a build by hand with **Run workflow**.

**On a Debian 13 machine** (as root):

```sh
apt install live-build
sh liveos/build.sh        # creates liveos/rescue-ai-amd64.iso
```

## Write the USB

Use Rufus: select the USB stick and `rescue-ai-amd64.iso`, click **Start**, and choose **DD Image mode** when asked. This erases the stick.

## What's inside

- Debian 13 base, no desktop: text screen only, Ethernet via NetworkManager
- The agent from `../agent`, with its Python packages pre-installed in `/opt/rescue-ai/.venv`
- `cloudflared` for the link
- Disk, boot and hardware tools: smartmontools, nvme-cli, ntfs-3g, cryptsetup, efibootmgr, mokutil, lshw and others
- Backups and repairs:
  - GNU ddrescue, for disk images
  - QEMU, OVMF, wimlib and mtools, for starting Windows' own recovery environment in a small virtual machine

Files:

- `auto/config`: build settings
- `config/package-lists/`: packages
- `config/hooks/live/`: installs the agent and cloudflared
- `config/includes.chroot/`: the auto-start service

## Licensing

Debian and the tools in this image are open source, and we only **add** packages, files and settings. Debian's signed boot loader and kernel are used unchanged, which keeps Secure Boot working.

If you give the image to others:

- Make the source of the GPL parts available (pointing to Debian's source archive for the exact package versions is the usual way).
- Keep the licence notices (they are inside the image under `/usr/share/doc`).
- Call it "Rescue AI, based on Debian", not "Debian", and don't use the Debian logo as your own.

`firmware-realtek` is not open source but may be redistributed. cloudflared is Apache-2.0, and using Cloudflare's tunnel service falls under Cloudflare's terms.
