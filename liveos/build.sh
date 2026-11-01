#!/bin/sh
# Build the Rescue AI USB image. Run as root on Debian 13, or in a debian:trixie
# container started with --privileged (see .github/workflows/build-iso.yml).
set -e
cd "$(dirname "$0")"

# The agent comes from ../agent, so there is only one copy of the code.
mkdir -p config/includes.chroot/opt/rescue-ai
cp ../agent/rescue_agent.py ../agent/requirements.txt config/includes.chroot/opt/rescue-ai/
chmod +x auto/config config/hooks/live/*.hook.chroot

lb clean
lb config
lb build

mv live-image-amd64.hybrid.iso rescue-ai-amd64.iso
sha256sum rescue-ai-amd64.iso > rescue-ai-amd64.iso.sha256
ls -lh rescue-ai-amd64.iso
