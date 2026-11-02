# Rescue AI

Start a broken Windows PC from a USB stick, and let Claude (or any MCP client) diagnose and fix it through a secure link, while **the person at the PC stays in control**.

- Claude inspects disks, crash records, event logs, the registry, boot configuration, updates, drivers and restore points.
- It can **ask** to make fixes: registry values, drivers, files, registry hives from a restore point, hibernation, the NTFS journal, boot order, and commands in expert mode.
- It can run **Windows' own repair tools** (chkdsk, sfc, DISM, bcdboot) in a small virtual machine started from the PC's recovery image.
- It can **back up files** or a whole disk image to a USB drive.
- Windows stays **read-only** until the person at the PC approves a change on its screen. Most changes can be undone.

> **Status:** early. Tested with automated Linux tests, a virtual machine boot test, and the first real PCs. Expect rough edges and please report them.

## How it works

1. Boot the PC from the Rescue AI USB stick and plug in a network cable.
2. The screen shows a link and a QR code. Add the link to Claude as a custom connector.
3. Claude investigates, explains what's wrong, and asks for any change it wants to make. Each change appears on the PC's screen with exactly what it will do. Nothing happens until you approve it there.

| Folder | What it is |
|---|---|
| [agent/](agent/) | The MCP server (`rescue_agent.py`). It can also run on an Ubuntu live USB with `start.sh` |
| [liveos/](liveos/) | The bootable USB image (Debian 13) with the agent built in |
| [docs/](docs/) | Screenshots of the PC's screen |
| [.github/workflows/](.github/workflows/) | Tests, the USB image build and boot test, security scanning |
| [PROPOSAL.md](PROPOSAL.md), [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) | Where the project is heading |

## Responsible use

Use Rescue AI only on PCs you own, or where the owner asked you to help. It is built so that:
- the link is shown only on the PC's own screen
- every change needs approval **at that PC**
- personal files stay private unless the owner allows them

It doesn't bypass Windows passwords or BitLocker, and it never will.

## Contributing and security

- Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) first, especially the safety rules.
- Security problems: please report them privately. See [SECURITY.md](SECURITY.md).
- Everyone here follows the [code of conduct](CODE_OF_CONDUCT.md).

## Licence

[GNU General Public License v3.0](LICENSE). The USB image is built from Debian and other open-source software under their own licences.

Rescue AI is an independent project, not affiliated with or endorsed by Anthropic. Claude is a trademark of Anthropic.
