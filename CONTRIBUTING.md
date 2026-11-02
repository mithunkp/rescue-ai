# Contributing to Rescue AI

Thank you for helping. Rescue AI touches people's broken PCs and their files, so it has a few firm rules. They keep it trustworthy.

## How a change gets in

1. **Start with an issue.** Describe the problem on a broken PC and how you'd solve it (use the "Idea for a feature" form). A maintainer agrees or declines **before** you write code, so nobody wastes effort.
2. **Open a pull request** from your fork. Keep it small and focused on one thing.
3. **Automatic checks run on every pull request:**
   - the Linux integration tests (real NTFS disk images, registry edits, backups, the Windows repair pipeline)
   - the USB image build, plus a boot test with screenshots
   - CodeQL security scanning

   For first-time contributors, a maintainer approves the checks before they start.
4. **A maintainer reviews it.** The maintainer is the code owner for every file. Nothing reaches `main` without that review and green checks. Changes are squash-merged.

## Safety rules (pull requests that break these are declined)

1. **Read-only by default.** Nothing may write to a Windows disk except through a `request_*` tool. That tool creates a job, and the person **at the PC** must approve it on its screen. The only ways to write are `writable()`, `released()` and `disk_for_vm()`, and each must always return the disk to read-only.
2. **The approval card must say exactly what will change**: the target, the old and new value, the risk, and whether it can be undone. Card text comes from the tool's own parameters, never from the AI's wording. The riskiest changes need a typed confirmation word.
3. **Nobody can approve from outside the PC.** The screen page and keyboard are only on the PC itself. Don't add any way for the link, the AI or another machine to approve.
4. **No bypassing protection.** Nothing may reset Windows passwords, read password stores or credential files, break BitLocker without the recovery key, or turn off the read-only checks.
5. **Personal files stay private** unless the owner allows them. Backups copy files without showing their contents to the AI.
6. **No new network exposure.** Don't add new listeners, telemetry, or code downloaded at the PC. Anything the USB image downloads at build time is pinned to an exact version and checksum.
7. **Tests come with the change.** Add or update a test in test mode or in `agent/tests/*_linux.py`. A bug from a real PC gets a test that reproduces it.

## Running it while you work

You can run the agent against a folder that looks like a Windows drive, on Windows or Linux:

```sh
python -m venv .venv
.venv/bin/pip install -r agent/requirements.txt evtx      # Windows: .venv\Scripts\pip
.venv/bin/python agent/rescue_agent.py --test-root /path/to/windows-folder --no-tunnel
```

It prints a local MCP link, and the address of the PC's screen page.

The Linux integration tests need root and real loop devices; GitHub Actions runs them for every pull request. To run them yourself on Debian or Ubuntu, see `.github/workflows/test-agent.yml`. Each one runs as `sudo .venv/bin/python agent/tests/<test>.py`.

## Style

- Follow the code around your change: the same naming, comment density and idioms.
- Messages the PC owner sees use plain, short English: what happened, and what to do next.
- Errors that the AI sees name the check that failed and the way forward.

## Licence and sign-off

Rescue AI is licensed under the **GNU GPL v3** ([LICENSE](LICENSE)). By contributing, you agree that your contribution is licensed under it too.

Please sign off your commits (`git commit -s`). That adds a `Signed-off-by:` line confirming you wrote the change or have the right to submit it ([Developer Certificate of Origin](https://developercertificate.org/)).

## Security problems

Please **don't** open a public issue. See [SECURITY.md](SECURITY.md).
