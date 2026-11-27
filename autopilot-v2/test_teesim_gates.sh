#!/bin/sh
# Host test of webroot/common_scripts/teesim.sh: it must honour the WebUI switches (sim-pixel, sim-target)
# and the module's own state. Beta-6 rewrote the whole TeeSim config on every run regardless.
# Run: sh autopilot-v2/test_teesim_gates.sh
set -eu
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT INT TERM
PASS=0
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

MODS=$W/mods; BRAIN=$W/brain; TS=$W/tricky; TD=$W/teesim
mkdir -p "$MODS/teesim" "$MODS/playintegrityfix" "$BRAIN" "$TS" "$TD" "$W/tmp"
printf 'BRAND=google\nDEVICE=newdev\nPRODUCT=newprod\nMANUFACTURER=Google\nMODEL=Pixel Z\nSECURITY_PATCH=2026-11-05\n' > "$MODS/playintegrityfix/custom.pif.prop"
printf 'all=2026-11-05\n' > "$TS/security_patch.txt"
printf 'com.new.app\n' > "$TS/target.txt"

reset() {
    cat > "$TD/config.json" <<'JSON'
{
    "keybox": "keep.xml",
    "mode": "patch",
    "osVersion": "14",
    "brand": "old",
    "device": "olddev",
    "product": "oldprod",
    "manufacturer": "oldmf",
    "model": "oldmodel",
    "patchLevel": { "system": "2025-01-05", "vendor": "2025-01-05", "boot": "2025-01-05" },
    "apps": [
        "com.old.app"
    ]
}
JSON
    rm -f "$BRAIN"/sim-pixel "$BRAIN"/sim-target "$MODS/teesim/disable"
    cp "$TD/config.json" "$W/orig.json"
}
run() { TEESIM_MODS=$MODS TEESIM_BRAIN=$BRAIN TEESIM_DIR=$TD TEESIM_TRICKY=$TS TEESIM_TMP=$W/tmp sh "$HERE/../webroot/common_scripts/teesim.sh"; }
same() { cmp -s "$TD/config.json" "$W/orig.json"; }
has() { grep -q -- "$1" "$TD/config.json" || fail "$CASE: expected '$1' in config"; PASS=$((PASS + 1)); }
lacks() { grep -q -- "$1" "$TD/config.json" && fail "$CASE: unexpected '$1' in config"; PASS=$((PASS + 1)); return 0; }
ok() { "$@" || fail "$CASE"; PASS=$((PASS + 1)); }

CASE=no-switch-no-change;   reset; run; ok same
CASE=disabled-module;       reset; : > "$BRAIN/sim-pixel"; : > "$MODS/teesim/disable"; run; ok same
CASE=pixel-only;            reset; : > "$BRAIN/sim-pixel"; run; has newdev; has '2026-11-05'; has com.old.app; lacks com.new.app
CASE=target-only;           reset; : > "$BRAIN/sim-target"; run; has com.new.app; lacks com.old.app; has olddev; has '2025-01-05'
CASE=both;                  reset; : > "$BRAIN/sim-pixel"; : > "$BRAIN/sim-target"; run; has newdev; has com.new.app; lacks com.old.app; has keep.xml
CASE=target-without-file;   reset; : > "$BRAIN/sim-target"; rm "$TS/target.txt"; run; ok same; printf 'com.new.app\n' > "$TS/target.txt"

printf 'test_teesim_gates.sh: %d checks passed\n' "$PASS"
