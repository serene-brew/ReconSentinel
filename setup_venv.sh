#!/usr/bin/env bash
set -euo pipefail

# Run this from the project root (same folder as recon_sentinel/)
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

VENV_DIR="${VENV:-.venv}"

echo "▶ Checking python3..."
if ! command -v python3 >/dev/null 2>&1; then
  echo "❌ python3 not found. Install Python 3 first."
  exit 1
fi

echo "▶ Ensuring python3-venv is available..."
if ! python3 -c "import venv" >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    echo "⛏  Installing python3-venv via apt..."
    sudo apt-get update -y
    sudo apt-get install -y python3-venv
  else
    echo "❌ python3-venv not available and apt-get not found. Install a venv package manually."
    exit 1
  fi
fi

if [ ! -d "$VENV_DIR" ]; then
  echo "▶ Creating virtual environment at $VENV_DIR"
  python3 -m venv "$VENV_DIR"
else
  echo "✓ Virtual environment already exists: $VENV_DIR"
fi

echo "▶ Activating venv..."
# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"

echo "▶ Upgrading pip/wheel..."
python -m pip install -U pip wheel

if [ -f "requirements.txt" ]; then
  echo "▶ Installing requirements..."
  pip install -r requirements.txt
else
  echo "⚠ requirements.txt not found, installing core deps directly..."
  pip install "typer[all]" rich jinja2 pyyaml requests dnspython markdown
fi

echo ""
echo "✅ Setup complete."
echo "To use this environment later, run:"
echo "    source $VENV_DIR/bin/activate"

