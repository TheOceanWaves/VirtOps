#!/usr/bin/env bash
# Install this user-facing wrapper as /home/vm_run/scripts/lib/vm.sh (0755).
# Privileged code remains only in root-owned /home/vm_run/scripts/lib/vmctl.py.
set -euo pipefail

backend=/home/vm_run/scripts/lib/vmctl.py

if [[ ! -f "$backend" || -L "$backend" ]]; then
  printf 'winvm01 root controller is missing or unsafe: %s\n' "$backend" >&2
  exit 2
fi

owner=$(stat -c '%u' "$backend")
mode=$(stat -c '%a' "$backend")
if [[ "$owner" != 0 ]] || (( (8#$mode & 8#022) != 0 )); then
  printf 'winvm01 root controller ownership/mode is unsafe: %s\n' "$backend" >&2
  exit 2
fi

case "${1:-}" in
  start|stop|status|logs|counters|delete|recreate)
    [[ $# -eq 1 ]] || { printf 'unexpected arguments for %s\n' "$1" >&2; exit 2; }
    ;;
  reset)
    [[ $# -eq 2 && "${2:-}" == --discard ]] || {
      printf 'usage: %s reset --discard\n' "$0" >&2
      exit 2
    }
    ;;
  *)
    cat >&2 <<'USAGE'
usage:
  vm.sh start|stop|status|logs|counters|delete|recreate
  winvm.sh reset --discard
USAGE
    exit 2
    ;;
esac

exec sudo -- "$backend" "$@"
