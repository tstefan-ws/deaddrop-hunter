#!/usr/bin/env bash
# Run one full cycle: hunt -> export feeds/API -> build static site.
#
#   scripts/run_hunt.sh [--push] [--no-site] [-- <extra args for "deaddrop-hunter hunt">]
#
# --push     commit changed data/ and push it (for people who run the hunter from WSL or a
#            server but host the dashboard on GitHub Pages; the Pages workflow then deploys)
# --no-site  skip export + build_site (hunt only)
#
# Environment: optional API keys / RPC overrides are read from .env in the repo root
# (see .env.example). Logs: stdout/stderr; the cron/systemd examples in docs/deploy.md
# redirect them to logs/hunt.log.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

PUSH=0
SITE=1
HUNT_ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --push) PUSH=1 ;;
    --no-site) SITE=0 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    --) shift; HUNT_ARGS+=("$@"); break ;;
    *) HUNT_ARGS+=("$1") ;;
  esac
  shift
done

log() { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

# Load .env (KEY=value lines; comments and blank lines ignored). Values are exported.
if [ -f .env ]; then
  log "loading .env"
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

# Activate the virtualenv if present (bootstrap_wsl.sh creates .venv).
if [ -f .venv/bin/activate ]; then
  # shellcheck disable=SC1091
  . .venv/bin/activate
fi
PYTHON="${PYTHON:-python3}"
command -v deaddrop-hunter >/dev/null 2>&1 || {
  echo "deaddrop-hunter not found. Run scripts/bootstrap_wsl.sh or: pip install -e ." >&2
  exit 2
}

# Single-instance lock so overlapping cron runs never race on data/.
mkdir -p logs
exec 9>logs/.run_hunt.lock
if command -v flock >/dev/null 2>&1 && ! flock -n 9; then
  log "another run is in progress, exiting"
  exit 0
fi

log "hunt ${HUNT_ARGS[*]:-}"
deaddrop-hunter hunt --config config/hunts.toml --data data ${HUNT_ARGS[@]+"${HUNT_ARGS[@]}"}

if [ "$SITE" -eq 1 ]; then
  log "export"
  mkdir -p site/feeds
  deaddrop-hunter export --data data --out site/feeds --formats stix,misp,csv,txt,api
  log "build site"
  "$PYTHON" scripts/build_site.py --out site --web web --data data
fi

if [ "$PUSH" -eq 1 ]; then
  git add -A data/
  if git diff --cached --quiet; then
    log "no data changes to push"
  else
    # Cursors in meta.json move every cycle, so committing whatever changed would write a
    # commit every few minutes. Findings go out at once; a cursor-only heartbeat waits until
    # the last one is an hour old. Same rule as the hunt workflow.
    if git diff --cached --quiet -- data/ ':(exclude)data/meta.json'; then
      last=$(git log -1 --format=%ct -- data/meta.json 2>/dev/null || echo 0)
      if [ $(( $(date -u +%s) - ${last:-0} )) -lt 3300 ]; then
        log "cursors only, last heartbeat < 55 min ago: not committing"
        git reset -q
        log "done"
        exit 0
      fi
    fi
    git commit -m "data: hunt $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    branch="$(git rev-parse --abbrev-ref HEAD)"
    git pull --rebase origin "$branch"
    git push origin "HEAD:$branch"
    log "pushed data to $branch"
  fi
fi

log "done"
