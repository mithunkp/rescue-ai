# Security

Rescue AI opens a remote link to a PC and can change its disk after approval, so security reports matter a lot to us.

## Reporting a vulnerability

Please report it **privately**: on this repository's **Security** tab, choose **Report a vulnerability**. Don't open a public issue, and don't include anyone's real Rescue AI link, BitLocker keys or personal files.

Useful details:
- what an attacker can do, and from where (over the link, from another machine on the network, or at the PC)
- the steps to reproduce it, and the version (commit or ISO build date)

We aim to reply within 7 days, and to fix serious problems before discussing them publicly. We'll credit you unless you'd rather not be named.

## In scope

- The agent (`agent/`): the MCP tools, approvals, the link and its token, the screen page, file and registry access rules
- The USB image (`liveos/`): services, the kiosk window, packages and downloads
- The GitHub workflows that build and publish the image

## How it is meant to work (not vulnerabilities)

- Anyone who has the link can **read** the PC's disk while sharing is on (except personal files, unless the owner allowed them, and password and credential stores, which are always blocked). Only the person at the PC gets the link, and it stops working with **Stop sharing**, **New link**, or power off.
- Changes happen only after approval **at the PC**, by keyboard or by clicking on its own screen.
- Physical access to a PC already allows starting it from any Linux USB. Rescue AI doesn't add a way around BitLocker or Windows passwords, and won't.

## Checking an ISO

Official ISOs are built only from `main` by GitHub Actions, and come with a signed build record. To check one:

```sh
gh attestation verify rescue-ai-amd64.iso --repo mithunkp/rescue-ai
```
