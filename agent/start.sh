#!/usr/bin/env bash
# Rescue AI (one-day version). Run on an Ubuntu live USB:
#   sudo bash start.sh
# Extra options go to rescue_agent.py, e.g.  sudo bash start.sh --allow-personal-files
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
APP=/opt/rescue-ai

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run with sudo:  sudo bash $0"
  exit 1
fi

echo "== Rescue AI =="
echo "[1/4] Checking the internet connection..."
if ! python3 -c "import urllib.request; urllib.request.urlopen('https://pypi.org', timeout=10)" 2>/dev/null; then
  echo "No internet. Plug in the network cable (or join Wi-Fi from the top-right menu), then run this again."
  exit 1
fi

echo "[2/4] Installing system tools..."
if ! command -v smartctl >/dev/null || ! python3 -c "import ensurepip, hivex" 2>/dev/null; then
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    smartmontools python3-venv python3-hivex ntfs-3g gddrescue \
    qemu-system-x86 ovmf wimtools mtools dosfstools fdisk >/dev/null
fi

echo "[3/4] Setting up Python packages (the first run takes a minute)..."
mkdir -p "$APP"
if [ "$SRC" != "$APP" ]; then
  cp "$SRC/rescue_agent.py" "$SRC/requirements.txt" "$APP/"
fi
if [ ! -x "$APP/.venv/bin/python" ]; then
  python3 -m venv --system-site-packages "$APP/.venv"  # so the agent can use python3-hivex
fi
"$APP/.venv/bin/pip" install -q --disable-pip-version-check -r "$APP/requirements.txt"
if ! "$APP/.venv/bin/pip" install -q --disable-pip-version-check evtx 2>/dev/null; then
  echo "      (fast event-log reader unavailable; installing the slower one)"
  "$APP/.venv/bin/pip" install -q --disable-pip-version-check python-evtx
fi

echo "[4/4] Getting cloudflared (for the secure link)..."
CF="$(command -v cloudflared || true)"
if [ -z "$CF" ]; then
  case "$(uname -m)" in
    aarch64|arm64) ARCH=arm64 ;;
    *) ARCH=amd64 ;;
  esac
  CF="$APP/cloudflared"
  if [ ! -x "$CF" ]; then
    python3 -c "import urllib.request, sys; urllib.request.urlretrieve(sys.argv[1], sys.argv[2])" \
      "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-$ARCH" "$CF"
    chmod +x "$CF"
  fi
fi

exec "$APP/.venv/bin/python" "$APP/rescue_agent.py" --cloudflared "$CF" "$@"
