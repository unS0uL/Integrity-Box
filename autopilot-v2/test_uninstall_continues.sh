#!/bin/sh
# uninstall.sh must reach its cleanup even when "autopilot.sh disable" fails (no engine, other ABI, stop timeout).
# Runs only the header of uninstall.sh (up to `set -x`) in a sandbox; the destructive part is never executed.
# Run: sh autopilot-v2/test_uninstall_continues.sh
set -eu
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT INT TERM
mkdir -p "$W/m/webroot/common_scripts"
printf '#!/bin/sh\nexit 1\n' > "$W/m/webroot/common_scripts/autopilot.sh"
sed -n '1,/^set -x/p' "$HERE/../uninstall.sh" | sed 's#/data/adb/Box-Brain/autopilot#'"$W"'/flag#' > "$W/m/uninstall.sh"
echo 1 > "$W/flag"
echo 'echo REACHED_CLEANUP' >> "$W/m/uninstall.sh"
out=$(sh "$W/m/uninstall.sh" 2>/dev/null) || { echo "FAIL: uninstall.sh exited early"; exit 1; }
case "$out" in *REACHED_CLEANUP*) ;; *) echo "FAIL: cleanup not reached"; exit 1 ;; esac
[ ! -e "$W/flag" ] || { echo "FAIL: the enable flag was not removed when disable failed"; exit 1; }
echo "PASS: uninstall.sh continues and drops the enable flag when disable fails"
