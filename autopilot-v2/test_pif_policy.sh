#!/bin/sh
# Host tests for the two scripts that write Tricky Store's security_patch.txt:
#   - the BOOT script service.d/prop.sh (extracted verbatim from the heredoc in customize.sh, so that
#     what is tested is what is installed), run in a sandbox with stubbed resetprop/getprop;
#   - pif_policy.sh (pif_conf_get, pif_may_write_patch).
# The incident of 2026-11-16 was a boot script that re-wrote the patch with an old literal; the user's
# own choices (stock-patch flag, pif_mode, pif_sync_patch) must also survive every boot.
# Run: sh autopilot-v2/test_pif_policy.sh   (TEST_SH=dash|bash|ksh to choose the shell)
set -eu
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT="$HERE/.."
SH=${TEST_SH:-sh}
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT INT TERM
PASS=0
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
ok() { PASS=$((PASS + 1)); }

# ---- the boot script, verbatim, with every /data/adb path moved into the sandbox
awk '/cat <<.EOF. > "\$boot\/prop.sh"/ {f = 1; next} f && /^EOF$/ {exit} f {print}' "$ROOT/customize.sh" > "$W/prop.orig"
[ -s "$W/prop.orig" ] || fail "prop.sh heredoc not found in customize.sh"
grep -q 'PATCH_DATE' "$W/prop.orig" || fail "extracted script looks wrong"

mkdir -p "$W/bin"
cat > "$W/bin/resetprop" <<'STUB'
#!/bin/sh
echo "$@" >> "$SANDBOX/resetprop.log"
STUB
cat > "$W/bin/getprop" <<'STUB'
#!/bin/sh
echo "${FAKE_PATCH_PROP:-2026-10-05}"
STUB
chmod 755 "$W/bin/resetprop" "$W/bin/getprop"

# sandbox NAME PIF_PATCH(or "-" none) TS_FILE_CONTENT(or "-" none) [setup-command...]
make_box() {
    d="$W/$1"
    rm -rf "$d"
    mkdir -p "$d/data/adb/modules/playintegrityfix" "$d/data/adb/tricky_store" "$d/data/adb/Box-Brain"
    [ "$2" = - ] || printf 'MODEL=Pixel 6a\nSECURITY_PATCH=%s\n\n# Configuration\nspoofBuild=1\n' "$2" > "$d/data/adb/modules/playintegrityfix/custom.pif.prop"
    [ "$3" = - ] || printf '%s' "$3" > "$d/data/adb/tricky_store/security_patch.txt"
    cp "$ROOT/pif_policy.sh" "$d/data/adb/modules/playintegrityfix/pif_policy.sh"
    sed "s#/data/adb/#$d/data/adb/#g" "$W/prop.orig" > "$d/prop.sh"
    : > "$d/resetprop.log"
}
boot() { # NAME  -> runs the boot script
    d="$W/$1"
    ( SANDBOX="$d" PIF_BOX="$d/data/adb/Box-Brain" PATH="$W/bin:$PATH" "$SH" "$d/prop.sh" ) >/dev/null 2>&1 || true
}
patch_of() { cat "$W/$1/data/adb/tricky_store/security_patch.txt" 2>/dev/null || echo "<absent>"; }
resets() { wc -l < "$W/$1/resetprop.log" | tr -d ' '; }
expect_patch() { [ "$(patch_of "$1")" = "$2" ] || fail "$1: security_patch.txt is '$(patch_of "$1")', expected '$2'"; ok; }

# 1. the incident: old patch in Tricky Store, new one in the fingerprint -> fixed at boot, props set
make_box normal 2026-11-05 "all=2026-10-05
"
boot normal
expect_patch normal "all=2026-11-05"
[ "$(resets normal)" = 2 ] || fail "normal: both patch properties must be set, got $(resets normal) resetprop calls"; ok

# 2. already right: the file is not rewritten (other lines survive)
make_box current 2026-11-05 "all=2026-11-05
boot=2026-01-01
"
boot current
[ "$(patch_of current)" = "all=2026-11-05
boot=2026-01-01" ] || fail "current: a matching file must be left untouched"; ok

# 3. the user's stock-patch flag: neither the file nor the properties are touched at boot
make_box stock 2026-11-05 "system=prop
"
: > "$W/stock/data/adb/Box-Brain/patch"
boot stock
expect_patch stock "system=prop"
[ "$(resets stock)" = 0 ] || fail "stock: no property may be changed when the stock patch flag is set"; ok

# 4. pif_mode=manual / off and pif_sync_patch=off: the file is not rewritten (the properties still follow)
for conf in "pif_mode = manual" "PIF_MODE=Off" "pif_sync_patch = off" "pif_sync_patch=no"; do
    make_box policy 2026-11-05 "all=2026-10-05
"
    printf '# a comment\n%s\n' "$conf" > "$W/policy/data/adb/Box-Brain/autopilot.conf"
    boot policy
    expect_patch policy "all=2026-10-05"
done
# ... but a policy that does not forbid it changes nothing
make_box policy_ok 2026-11-05 "all=2026-10-05
"
printf 'pif_mode = auto\npif_sync_patch = on\ncandidate_budget = 3\n' > "$W/policy_ok/data/adb/Box-Brain/autopilot.conf"
boot policy_ok
expect_patch policy_ok "all=2026-11-05"

# 5. NO LITERAL FALLBACK: an unusable fingerprint patch leaves everything as it is
for pifpatch in - garbage 2026-13-45x 2026-11; do
    make_box nopatch "$pifpatch" "all=2026-09-09
"
    boot nopatch
    expect_patch nopatch "all=2026-09-09"   # a value no literal in any script could equal
    [ "$(resets nopatch)" = 0 ] || fail "nopatch($pifpatch): no property may be set without a valid patch"; ok
done

# 6. a missing security_patch.txt is created (the module always had one)
make_box missing 2026-11-05 -
boot missing
expect_patch missing "all=2026-11-05"

# 7. upstream behaviours that must stay: disabled module -> nothing; skip file -> file written, properties untouched
make_box disabled 2026-11-05 "all=2026-10-05
"
: > "$W/disabled/data/adb/modules/playintegrityfix/disable"
boot disabled
expect_patch disabled "all=2026-10-05"
make_box skipfile 2026-11-05 "all=2026-10-05
"
: > "$W/skipfile/data/adb/Box-Brain/skip"
boot skipfile
expect_patch skipfile "all=2026-11-05"
[ "$(resets skipfile)" = 0 ] || fail "skipfile: sensitive devices must not get property overrides"; ok

# 8. the policy helpers on their own
( PIF_BOX="$W/pol"; mkdir -p "$PIF_BOX"; . "$ROOT/pif_policy.sh"
  pif_may_write_patch || exit 1                                   # nothing configured: allowed
  printf 'pif_mode = MANUAL  \r\n' > "$PIF_BOX/autopilot.conf"
  [ "$(pif_conf_get pif_mode)" = manual ] || exit 2               # lowercased, CR and spaces trimmed
  ! pif_may_write_patch || exit 3
  printf 'pif_mode = banana\n' > "$PIF_BOX/autopilot.conf"
  pif_may_write_patch || exit 4                                   # an invalid value does not forbid (the engine keeps auto)
  printf 'pif_sync_patch = off\npif_sync_patch = on\n' > "$PIF_BOX/autopilot.conf"
  pif_may_write_patch || exit 5                                   # the LAST line of a key wins, like the engine
  printf 'pif_mode = off\n' > "$PIF_BOX/autopilot.conf"
  ! pif_may_write_patch || exit 6
  rm -f "$PIF_BOX/autopilot.conf"; : > "$PIF_BOX/patch"                   # the stock-patch flag ALONE forbids
  ! pif_may_write_patch || exit 7 ) || fail "pif_policy.sh helper failed with status $?"
ok

printf 'pif boot-script and policy tests PASS (%s assertions)\n' "$PASS"
