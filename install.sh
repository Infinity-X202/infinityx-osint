#!/usr/bin/env bash
# InfinityX OSINT Scanner installer for Kali Linux.
# Created by Infinity. Run this as a normal user. It asks before installing packages.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

echo "InfinityX OSINT Scanner installer"
echo "Created by Infinity"
echo
echo "This tool collects public information about a domain you are authorized to assess."
echo "The scanner itself should not be run as root."
echo

if [[ "${EUID}" -eq 0 ]]; then
  echo "Run ./install.sh as a normal user."
  echo "The script will use sudo only if you agree to install system packages."
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is not installed."
  exit 1
fi

PACKAGES=(python3 python3-venv python3-pip whois traceroute whatweb)
echo "System packages this installer can ask apt to install:"
for package in "${PACKAGES[@]}"; do
  echo "  - ${package}"
done
echo
echo "python3, python3-venv, and python3-pip are required for the virtual environment."
echo "whois is optional because InfinityX also speaks WHOIS itself."
echo "traceroute is optional and is used only with --enable-traceroute."
echo "whatweb is optional technology fingerprinting."
echo "DNS queries use dnspython and do not require the dnsutils package."
echo
read -r -p "Install these packages with apt if you confirm? [y/N] " reply
if [[ "${reply}" == "y" || "${reply}" == "Y" ]]; then
  sudo apt-get update
  sudo apt-get install -y "${PACKAGES[@]}"
else
  echo "Skipping system packages. Optional checks will be SKIPPED if their commands are missing."
fi

if ! python3 -m venv --help >/dev/null 2>&1; then
  echo "python3-venv is not available. Install it, then run ./install.sh again."
  exit 1
fi

python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt

echo
echo "Installation finished."
echo "Start the scanner with:"
echo "  source .venv/bin/activate"
echo "  python main.py"
echo "or:"
echo "  python main.py --domain example.com"
echo "You must type AGREE before a scan starts."
