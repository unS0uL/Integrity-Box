#!/bin/sh
# deploy_files.sh: the ONLY sanctioned way to replace files on a phone.
#
#   sh autopilot-v2/deploy_files.sh ADDR:PORT [--serial SERIAL] [--restart-autopilot] [--dry-run] SRC=DST[=MODE[=REF]] ...
#
# Why: on 2026-11-16 a hand-typed `cat /data/local/tmp/x > custom.pif.prop` with a missing source emptied the
# production fingerprint file for two minutes (the shell truncates the target before `cat` fails).
# What it does: checks the device serial, refuses an empty/missing local source, pushes to a unique temp name,
# verifies the sha256 ON THE DEVICE, copies owner / mode / SELinux context from the file it replaces (or from REF
# for a new file; MODE overrides), optionally stops AutoPilot, swaps with an atomic mv, restarts AutoPilot,
# removes every temp file it created. Nothing is replaced unless EVERY file staged and verified.
set -eu

SERIAL=${DEVICE_SERIAL:-}
RESTART=0
DRY=0
ADDR=${1:?usage: deploy_files.sh ADDR:PORT [--serial S] [--restart-autopilot] [--dry-run] SRC=DST[=MODE[=REF]] ...}
shift
while [ $# -gt 0 ]; do
    case "$1" in
        --serial) SERIAL=$2; shift 2 ;;
        --restart-autopilot) RESTART=1; shift ;;
        --dry-run) DRY=1; shift ;;
        --) shift; break ;;
        -*) echo "unknown option $1" >&2; exit 2 ;;
        *) break ;;
    esac
done
[ $# -gt 0 ] || { echo "no files given" >&2; exit 2; }

[ -n "$SERIAL" ] || { echo "ABORT: name the device you mean: --serial S or DEVICE_SERIAL=S (the serial is checked before anything is touched)" >&2; exit 2; }
got=$(adb -s "$ADDR" shell getprop ro.serialno 2>/dev/null | tr -d '\r')
[ "$got" = "$SERIAL" ] || { echo "ABORT: $ADDR is serial '$got', expected '$SERIAL' (never deploy to a device you did not identify)" >&2; exit 1; }

# validate EVERY local source before anything is pushed (a late failure must not leave temp files on the phone)
for spec in "$@"; do
    case "$spec" in *=/*) ;; *) echo "bad spec '$spec' (SRC=DST[=MODE[=REF]], DST absolute)" >&2; exit 2 ;; esac
    chk=${spec%%=*}
    [ -s "$chk" ] || { echo "ABORT: local source '$chk' is missing or empty" >&2; exit 1; }
done

TAG=dput.$$
LIST=""
n=0
for spec in "$@"; do
    src=${spec%%=*}; rest=${spec#*=}
    [ "$rest" != "$spec" ] || { echo "bad spec '$spec' (SRC=DST[=MODE[=REF]])" >&2; exit 2; }
    dst=${rest%%=*}; rest2=${rest#*=}
    mode=-; ref=-
    if [ "$rest2" != "$rest" ]; then
        mode=${rest2%%=*}; rest3=${rest2#*=}
        [ "$rest3" = "$rest2" ] || ref=$rest3
    fi
    [ -s "$src" ] || { echo "ABORT: local source '$src' is missing or empty" >&2; exit 1; }
    case "$dst" in /*) ;; *) echo "ABORT: destination '$dst' must be absolute" >&2; exit 2 ;; esac
    sha=$(shasum -a 256 "$src" | cut -d' ' -f1)
    n=$((n + 1))
    tmp=/data/local/tmp/$TAG.$n
    LIST="$LIST$tmp $dst $sha $ref $mode
"
    printf 'plan: %s -> %s (sha %s, mode %s, ref %s)\n' "$src" "$dst" "$(printf %s "$sha" | cut -c1-12)" "$mode" "$ref"
    [ "$DRY" = 1 ] || adb -s "$ADDR" push "$src" "$tmp" >/dev/null
done
[ "$DRY" = 0 ] || { echo "dry run: nothing pushed"; exit 0; }

SCRIPT=$(mktemp)
# Whatever fails on the host side (syntax check, push), no pushed temp file stays on the phone's flash.
trap 'rm -f "$SCRIPT"; adb -s "$ADDR" shell "rm -f /data/local/tmp/$TAG.*" >/dev/null 2>&1' EXIT INT TERM
cat > "$SCRIPT" <<DEVEOF
#!/system/bin/sh
RESTART=$RESTART
CS=/data/adb/modules/playintegrityfix/webroot/common_scripts
FILES="
$LIST"
cleanup() {
    while read -r tmp dst sha ref mode; do
        [ -n "\$tmp" ] || continue
        rm -f "\$tmp" "\$dst.rvnew"
    done <<EOF
\$FILES
EOF
    rm -f "/data/local/tmp/$TAG.sh"
}
# A failure after AutoPilot was stopped must not leave it stopped.
fail() { echo "ABORT: \$*"; cleanup; [ "\${OFF:-0}" = 1 ] && sh \$CS/autopilot.sh enable; exit 1; }
stage() {
    [ -s "\$1" ] || return 1
    cp "\$1" "\$2.rvnew" || return 1
    got=\$(sha256sum "\$2.rvnew" | cut -d' ' -f1)
    [ "\$got" = "\$3" ] || { echo "hash mismatch for \$2 (\$got)"; return 1; }
    meta="\$2"; [ "\$4" = "-" ] || meta="\$4"
    [ -e "\$meta" ] || meta=\$(dirname "\$2")
    ctx=\$(ls -Zd "\$meta" | tr ' ' '\\n' | grep '^u:object_r' | head -n 1)
    own=\$(stat -c %u:%g "\$meta")
    mode=\$(stat -c %a "\$meta"); [ "\$5" = "-" ] || mode="\$5"
    [ -n "\$ctx" ] && [ -n "\$mode" ] && [ -n "\$own" ] || { echo "cannot read metadata of \$meta"; return 1; }
    chown "\$own" "\$2.rvnew" && chmod "\$mode" "\$2.rvnew" && chcon "\$ctx" "\$2.rvnew" || return 1
    echo "staged \$2 (\$own \$mode \$ctx)"
}
while read -r tmp dst sha ref mode; do
    [ -n "\$tmp" ] || continue
    stage "\$tmp" "\$dst" "\$sha" "\$ref" "\$mode" || fail "staging \$dst"
done <<EOF
\$FILES
EOF
if [ "\$RESTART" = 1 ]; then
    echo "--- stopping AutoPilot"
    sh \$CS/autopilot.sh disable
    OFF=1
    sleep 3
    if ps -A | grep -q '[b]ox-autopilot'; then fail "an engine process is still running; nothing was replaced"; fi
fi
echo "--- swapping"
while read -r tmp dst sha ref mode; do
    [ -n "\$tmp" ] || continue
    mv "\$dst.rvnew" "\$dst" || fail "swap \$dst"
done <<EOF
\$FILES
EOF
if [ "\$RESTART" = 1 ]; then
    echo "--- starting AutoPilot"
    sh \$CS/autopilot.sh enable
    OFF=0
    sleep 8
    sh \$CS/autopilot.sh status | tr -d ' \\n' | grep -oE '"(phase|running|desired_enabled)":[^,]*' | tr '\\n' ' '; echo
fi
cleanup
echo "deploy ok"
DEVEOF
sh -n "$SCRIPT" || { echo "internal error: generated device script has a syntax error" >&2; exit 3; }
adb -s "$ADDR" push "$SCRIPT" "/data/local/tmp/$TAG.sh" >/dev/null
adb -s "$ADDR" shell "su -c 'sh /data/local/tmp/$TAG.sh 2>&1'"
