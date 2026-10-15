#!/bin/sh
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$(readlink -f -- "$0")")" && pwd -P)
exec "$script_dir/lib/vm.sh" recreate "$@"
