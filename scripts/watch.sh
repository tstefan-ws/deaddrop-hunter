#!/usr/bin/env bash
# Continuous watcher: keep hunting, forever, on a machine that stays on.
#
#   scripts/watch.sh [--interval 300] [--push] [--no-site] [-- <extra args for "hunt">]
#
# --interval N  seconds between cycles (default 300). The block watcher reads max_blocks
#               blocks per cycle, so pick an interval the chain cannot outrun: Polygon
#               produces ~28 blocks a minute, so 600 blocks per cycle covers ~21 minutes.
# --push        commit and push changed data/ after each cycle (see run_hunt.sh)
# --no-site     skip the export + site build each cycle (faster; CI rebuilds the site)
#
# Why this exists: GitHub's scheduler queues cron jobs on a shared pool and drops them under
# load. Measured 2026-10-19: a workflow set to every 15 minutes ran once in six hours, which
# leaves roughly 6% of blocks read. A loop on a machine you control has no such problem.
#
# Stops cleanly on Ctrl-C or SIGTERM. One cycle at a time: run_hunt.sh holds a lock, so a
# slow cycle delays the next one rather than racing it.
set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

INTERVAL=300
ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --interval) INTERVAL="${2:?--interval needs a number of seconds}"; shift ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) ARGS+=("$1") ;;
  esac
  shift
done

log() { printf '[%s] watch: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

running=1
trap 'running=0; log "stopping after this cycle"' INT TERM

log "starting, one cycle every ${INTERVAL}s (Ctrl-C to stop)"
cycles=0
while [ "$running" -eq 1 ]; do
  start=$SECONDS
  if ! scripts/run_hunt.sh ${ARGS[@]+"${ARGS[@]}"}; then
    # A failed cycle is normal: endpoints rate-limit, nodes time out. The next cycle
    # resumes from the stored position, so nothing is lost by carrying on.
    log "cycle failed; continuing"
  fi
  cycles=$((cycles + 1))
  took=$((SECONDS - start))
  [ "$running" -eq 1 ] || break
  sleep_for=$((INTERVAL - took))
  if [ "$sleep_for" -gt 0 ]; then
    log "cycle $cycles took ${took}s, sleeping ${sleep_for}s"
    sleep "$sleep_for" &
    wait $! 2>/dev/null || true          # wake immediately on Ctrl-C
  else
    log "cycle $cycles took ${took}s, longer than the interval: starting the next one now"
  fi
done
log "stopped after $cycles cycle(s)"
