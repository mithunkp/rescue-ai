## What this changes and why

<!-- Link the issue where this was agreed: "Closes #123" -->

## Safety checklist

- [ ] Windows stays read-only unless the person at the PC approves. There's no new write path outside `request_*` jobs and `writable()` / `released()` / `disk_for_vm()`
- [ ] A new `request_*` tool's card shows exactly what will change, the risk, and whether it can be undone
- [ ] Nothing lets the link, the AI or another machine approve a change
- [ ] Nothing reads passwords, credentials or BitLocker keys, or bypasses them
- [ ] No new network listener, telemetry, or code downloaded at the PC (build-time downloads are pinned to an exact version and checksum)
- [ ] Tests added or updated, and they pass
- [ ] Commits are signed off (`git commit -s`)

## How I tested it
