#!/usr/bin/env bash
# Install this user-facing wrapper as <instance-root>/scripts/lib/vm.sh (0755).
# Privileged code remains only in the root-owned sibling vmctl.py.
set -euo pipefail

script_path=$(readlink -f -- "$0") || {
  printf 'cannot resolve the vm wrapper path\n' >&2
  exit 2
}
lib_dir=$(dirname -- "$script_path")
instance_root=$(dirname -- "$(dirname -- "$lib_dir")")
backend="$lib_dir/vmctl.py"

# The wrapper is intentionally allowed to be user executable, but the path to
# the privileged controller must be root-owned and non-writable by group/other.
# Check every ancestor before sudo so a user cannot substitute a parent or the
# controller between validation and exec.
check_secure_dir() {
  local path=$1 owner mode
  [[ -d "$path" && ! -L "$path" ]] || {
    printf 'unsafe VM path component: %s\n' "$path" >&2
    exit 2
  }
  owner=$(stat -c '%u' -- "$path")
  mode=$(stat -c '%a' -- "$path")
  if [[ "$owner" != 0 ]] || (( (8#$mode & 8#022) != 0 )); then
    printf 'VM path component ownership/mode is unsafe: %s\n' "$path" >&2
    exit 2
  fi
}

path=$instance_root
while :; do
  check_secure_dir "$path"
  [[ "$path" == / ]] && break
  path=$(dirname -- "$path")
done
check_secure_dir "$instance_root/scripts"
check_secure_dir "$lib_dir"

if [[ ! -f "$backend" || -L "$backend" ]]; then
  printf 'root controller is missing or unsafe: %s\n' "$backend" >&2
  exit 2
fi

owner=$(stat -c '%u' "$backend")
mode=$(stat -c '%a' "$backend")
if [[ "$owner" != 0 ]] || (( (8#$mode & 8#022) != 0 )); then
  printf 'root controller ownership/mode is unsafe: %s\n' "$backend" >&2
  exit 2
fi

case "${1:-}" in
  status)
    [[ $# -eq 1 || ( $# -eq 2 && "$2" == --all ) ]] || { printf 'usage: status [--all]\n' >&2; exit 2; }
    ;;
  start|stop|logs|counters|delete|recreate)
    [[ $# -eq 1 ]] || { printf 'unexpected arguments for %s\n' "$1" >&2; exit 2; }
    ;;
  reset)
    [[ $# -ge 2 && "${2:-}" == --discard ]] || {
      printf 'usage: %s reset --discard [--owner-profile /absolute/root/profile.json] [--discard-data]\n' "$0" >&2
      exit 2
    }
    backend_args=(reset --discard)
    shift 2
    owner_profile=''
    discard_data=0
    while (($#)); do
      case "$1" in
        --owner-profile)
          [[ -z "$owner_profile" && $# -ge 2 ]] || { printf 'duplicate or incomplete --owner-profile\n' >&2; exit 2; }
          [[ "$2" == /* && "$2" != *$'\n'* && "$2" != *$'\r'* ]] || { printf '--owner-profile must be an absolute Linux path\n' >&2; exit 2; }
          owner_profile=$2
          backend_args+=(--owner-profile "$2")
          shift 2
          ;;
        --discard-data)
          (( discard_data == 0 )) || { printf 'duplicate --discard-data\n' >&2; exit 2; }
          discard_data=1
          backend_args+=(--discard-data)
          shift
          ;;
        *)
          printf 'unexpected reset argument: %s\n' "$1" >&2
          exit 2
          ;;
      esac
    done
    set -- "${backend_args[@]}"
    ;;
  *)
    cat >&2 <<'USAGE'
usage:
  vm.sh start|stop|status|logs|counters|delete|recreate
  vm.sh reset --discard [--owner-profile /absolute/root/profile.json] [--discard-data]
USAGE
    exit 2
    ;;
esac

exec sudo -- "$backend" "$@"
