#!/usr/bin/env bash
set -e

echo "[*] MCP-Kali Assistant setup (Kali Linux)"

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[!] Python3 not found. Please install Python 3 and re-run."
  exit 1
fi

if ! command -v pip3 >/dev/null 2>&1; then
  echo "[*] pip3 not found. Attempting to install via apt-get..."
  sudo apt-get update && sudo apt-get install -y python3-pip
fi

if [ ! -d ".venv" ]; then
  echo "[*] Creating Python virtual environment in .venv ..."
  python3 -m venv .venv
fi

echo "[*] Activating virtual environment..."
# shellcheck disable=SC1091
source .venv/bin/activate

if ! command -v nmap >/dev/null 2>&1; then
  echo "[*] nmap not found. Installing via apt-get (requires sudo)..."
  sudo apt-get update && sudo apt-get install -y nmap
else
  echo "[*] nmap is already installed."
fi

if [ ! -f "requirements.txt" ]; then
  echo "[!] requirements.txt not found in $SCRIPT_DIR"
  exit 1
fi

echo "[*] Installing Python dependencies from requirements.txt ..."
pip install --upgrade pip
pip install -r requirements.txt

echo "[*] Setup completed."
echo "    To use the virtualenv, run:"
echo "      source .venv/bin/activate"
echo "    Then run:"
echo "      python mcp_cli.py auto-analyse"
