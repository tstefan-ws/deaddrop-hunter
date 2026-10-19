#!/usr/bin/env bash
# Idempotent setup for WSL (Ubuntu) or any Debian/Ubuntu-like Linux.
#
#   scripts/bootstrap_wsl.sh [--no-run] [--dev]
#
# - installs python3, python3-venv and git via apt if they are missing (asks for sudo)
# - creates .venv and installs the package (with dev extras when --dev)
# - creates .env from .env.example if there is no .env yet
# - runs a first, short hunt + export + site build (skip with --no-run)
# Safe to re-run at any time.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

RUN=1
EXTRAS=""
for arg in "$@"; do
  case "$arg" in
    --no-run) RUN=0 ;;
    --dev) EXTRAS="[dev]" ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

say() { printf '\n==> %s\n' "$*"; }

case "$REPO_DIR" in
  /mnt/[a-z]/*)
    echo "WARNING: the repo is on the Windows filesystem ($REPO_DIR)."
    echo "         It works, but is much slower. Prefer cloning into your Linux home (~/)."
    ;;
esac

missing=()
command -v python3 >/dev/null 2>&1 || missing+=(python3)
python3 -c 'import venv, ensurepip' >/dev/null 2>&1 || missing+=(python3-venv)
command -v git >/dev/null 2>&1 || missing+=(git)
if [ ${#missing[@]} -gt 0 ]; then
  say "installing: ${missing[*]}"
  sudo apt-get update
  sudo apt-get install -y "${missing[@]}"
fi

python3 - <<'PY'
import sys
if sys.version_info < (3, 11):
    sys.exit(f"Python >= 3.11 required, found {sys.version.split()[0]}")
PY

if [ ! -x .venv/bin/python ]; then
  say "creating virtualenv .venv"
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
. .venv/bin/activate

say "installing deaddrop-hunter${EXTRAS}"
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -e ".${EXTRAS}"

if [ ! -f .env ] && [ -f .env.example ]; then
  say "creating .env from .env.example (all keys optional; edit to add yours)"
  cp .env.example .env
  chmod 600 .env
fi

mkdir -p data logs
chmod +x scripts/*.sh 2>/dev/null || true

if [ "$RUN" -eq 1 ]; then
  say "first run (polygon, last 3 days) - this can take a few minutes"
  scripts/run_hunt.sh --chains polygon --days 3
  say "serve the dashboard with:  python3 -m http.server -d site 8080"
  say "then open http://localhost:8080 in your Windows browser"
fi

say "bootstrap complete"
