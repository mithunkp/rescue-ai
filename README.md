# Rescue AI

Boot a broken Windows PC from a USB stick and let Claude (or any MCP client) diagnose it through a secure link. The current version is **read-only**: Claude inspects disks, crash records, event logs, the registry, boot configuration, updates and drivers, then explains the problem and the fix steps.

| Folder | What it is |
|---|---|
| [agent/](agent/) | The MCP server (`rescue_agent.py`). It can also run on an Ubuntu live USB with `start.sh` |
| [liveos/](liveos/) | Our own bootable USB image (Debian 13) with the agent built in: boot it and the link appears |
| [.github/workflows/](.github/workflows/) | Builds the USB image on GitHub |
| [PROPOSAL.md](PROPOSAL.md) | Proposal for the full product |
| [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) | Technical plan and milestones |
