# Rescue AI

Boot a broken Windows PC from a USB stick and let Claude (or any MCP client) diagnose and fix it through a secure link.

- Claude inspects disks, crash records, event logs, the registry, boot configuration, updates and drivers.
- It can **ask** to make fixes: registry values, drivers, files, hibernation, boot order, and commands in expert mode.
- It can run **Windows' own repair tools** (chkdsk, sfc, DISM, bcdboot) in a small virtual machine.
- It can **back up files** or a whole disk image to a USB drive.
- Each action shows on the PC's screen and only runs when the person there presses **Y**. Most fixes can be undone.

| Folder | What it is |
|---|---|
| [agent/](agent/) | The MCP server (`rescue_agent.py`). It can also run on an Ubuntu live USB with `start.sh` |
| [liveos/](liveos/) | Our own bootable USB image (Debian 13) with the agent built in: boot it and the link appears |
| [.github/workflows/](.github/workflows/) | Builds the USB image on GitHub |
| [PROPOSAL.md](PROPOSAL.md) | Proposal for the full product |
| [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) | Technical plan and milestones |
