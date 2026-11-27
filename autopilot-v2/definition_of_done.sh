#!/bin/sh
# definition_of_done.sh: "done" is a command, not a feeling.
#
#   sh autopilot-v2/definition_of_done.sh [--device ADDR:PORT] [--mutate] [--quick]
#
# Runs everything that CAN be run mechanically and lists what cannot (independent review, live scenario).
# --device  also runs the whole suite ON the phone (device_test.sh): a host test is not proof
# --mutate  also runs the mutation harness (slow; needs a committed tree)
# --quick   skips the month-long simulations of the Go suite and -race
# Exit status 0 only when every mechanical check passed.
set -u
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT="$HERE/.."
LINT=${ANDROID_LINT:-$ROOT/../tools/android-lint/android_lint.py} # workspace tool, optional
DEVICE=""
MUTATE=0
QUICK=0
while [ $# -gt 0 ]; do
    case "$1" in
        --device) DEVICE=${2:?--device needs ADDR:PORT}; shift 2 ;;
        --mutate) MUTATE=1; shift ;;
        --quick) QUICK=1; shift ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
    esac
done

FAILS=0
step() { # NAME COMMAND...   (output is shown only when the step fails)
    name=$1; shift
    if out=$("$@" 2>&1); then
        printf 'PASS  %s\n' "$name"
    else
        printf 'FAIL  %s\n' "$name"
        printf '%s\n' "$out" | tail -15 | sed 's/^/        /'
        FAILS=$((FAILS + 1))
    fi
}
note() { printf 'NOTE  %s\n' "$1"; }

cd "$ROOT" || exit 1
echo "== repository"
dirty=$(git status --porcelain 2>/dev/null | head -5)
if [ -n "$dirty" ]; then
    printf 'FAIL  uncommitted changes (commit before you claim "done"):\n%s\n' "$dirty" | sed '2,$s/^/        /'
    FAILS=$((FAILS + 1))
else
    echo "PASS  working tree is committed"
fi
hook="$(git rev-parse --git-common-dir 2>/dev/null)/hooks/pre-commit"
case "$hook" in /*) ;; *) hook="$ROOT/$hook" ;; esac
if [ -x "$hook" ] && grep -q precommit_guard "$hook" 2>/dev/null; then echo "PASS  git-guard pre-commit hook installed"; else note "git-guard is not installed: sh tools/git-guard/install.sh $ROOT"; fi

echo "== Go"
step "gofmt clean" sh -c "cd '$HERE' && test -z \"\$(gofmt -l .)\""
step "go vet" sh -c "cd '$HERE' && go vet ./..."
if [ "$QUICK" = 1 ]; then
    step "go test (quick, no simulations)" sh -c "cd '$HERE' && go test -count=1 -skip 'Lifecycle|DaemonCycleRate' ./..."
else
    step "go test -race (with the month-long simulations)" sh -c "cd '$HERE' && go test -count=1 -race ./..."
fi

echo "== the shipped binary"
vbout=$(mktemp); env -u VERIFY_BINARY_ALLOW_INCONCLUSIVE sh "$HERE/verify_binary.sh" >"$vbout" 2>&1; vb=$?
case $vb in
    0) printf 'PASS  %s\n' "tracked box-autopilot is a reproducible build of the committed source" ;;
    3) printf 'FAIL  %s\n' "tracked box-autopilot is NOT verified on this machine (different Go toolchain): run it where the recorded toolchain is installed"; tail -n 2 "$vbout" | sed 's/^/        /'; FAILS=$((FAILS + 1)) ;;
    *) printf 'FAIL  %s\n' "tracked box-autopilot is a reproducible build of the committed source"; tail -n 8 "$vbout" | sed 's/^/        /'; FAILS=$((FAILS + 1)) ;;
esac
rm -f "$vbout"
# A stand-in for the upstream release: only the file names that matter, to prove the completeness rule on any machine.
pkgtmp=$(mktemp -d)
python3 - "$pkgtmp/base.zip" <<'PYEOF'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], 'w') as z:
    for n in ('classes.dex', 'zygisk/arm64-v8a.so', 'resetprop-rs/resetprop-arm64-v8a'):
        z.writestr(n, 'x')
PYEOF
step "package.py builds a package that verify.sh accepts (META-INF outside the manifest, no dot-files)" python3 "$HERE/package.py" --base "$pkgtmp/base.zip" --output "$pkgtmp/package.zip"
step "the built package carries the upstream binaries (classes.dex, zygisk, resetprop)" sh -c "unzip -l '$pkgtmp/package.zip' | grep -q ' classes.dex\$' && unzip -l '$pkgtmp/package.zip' | grep -q 'zygisk/arm64-v8a.so'"
step "package.py REFUSES to build without the upstream binaries" sh -c "! python3 '$HERE/package.py' --output '$pkgtmp/refused.zip' >/dev/null 2>&1 && [ ! -e '$pkgtmp/refused.zip' ]"
if [ -n "${PACKAGE_BASE_ZIP:-}" ]; then
    step "a package from the real release ($PACKAGE_BASE_ZIP) builds and is complete" python3 "$HERE/package.py" --base "$PACKAGE_BASE_ZIP" --output "$pkgtmp/real.zip"
else
    note "PACKAGE_BASE_ZIP not set: the real upstream release was not used to build a package (the stand-in proved the rule only)"
fi

echo "== shell"
step "module scripts parse under ash-compatible dash, no bash-only redirections" sh "$HERE/test_portable_syntax.sh"
for sh_ in sh dash bash; do
    command -v "$sh_" >/dev/null 2>&1 || continue
    step "test_doctor.sh under $sh_" env TEST_SH="$sh_" sh "$HERE/test_doctor.sh"
    step "test_pif_policy.sh under $sh_" env TEST_SH="$sh_" sh "$HERE/test_pif_policy.sh"
    step "test_action_pif.sh under $sh_" "$sh_" "$HERE/test_action_pif.sh"
    step "test_key_shim.sh under $sh_" "$sh_" "$HERE/test_key_shim.sh"
    step "test_boot_wait.sh under $sh_" "$sh_" "$HERE/test_boot_wait.sh"
    step "test_teesim_gates.sh under $sh_" "$sh_" "$HERE/test_teesim_gates.sh"
    step "test_trim_logs.sh under $sh_" "$sh_" "$HERE/test_trim_logs.sh"
    step "test_uninstall_continues.sh under $sh_" "$sh_" "$HERE/test_uninstall_continues.sh"
done
if command -v shellcheck >/dev/null 2>&1; then
    step "shellcheck" shellcheck -s sh webroot/common_scripts/doctor.sh webroot/common_scripts/autopilot.sh pif_policy.sh autopilot-v2/deploy_files.sh autopilot-v2/device_test.sh autopilot-v2/definition_of_done.sh autopilot-v2/build.sh autopilot-v2/verify_binary.sh autopilot-v2/test_uninstall_continues.sh
else
    note "shellcheck not installed"
fi
if command -v node >/dev/null 2>&1 && [ -f "$HERE/test_webui.cjs" ]; then step "WebUI bridge test" node "$HERE/test_webui.cjs"; fi

echo "== lint (the self-learning barrier)"
if [ -f "$LINT" ]; then step "android_lint over the repository" python3 "$LINT" "$ROOT"; else note "android_lint.py not found at $LINT"; fi

CHECKDOCS=${CHECK_DOCS:-$ROOT/../tools/android-lint/check_docs.py}
DOCSDIR=${DOCS_DIR:-$ROOT/../docs/integrity-box}
if [ -f "$CHECKDOCS" ] && [ -d "$DOCSDIR" ]; then
    step "documents promise nothing that does not exist (tests, files, policy keys, exit codes, stale counts)" \
        python3 "$CHECKDOCS" "$ROOT" "$DOCSDIR/AUTOPILOT_GUIDE.md" "$DOCSDIR/AUTOPILOT_V4_PIF_DESIGN.md" "$DOCSDIR/AUTOPILOT_V3_DESIGN.md" "$DOCSDIR/README.md" "$ROOT/../DEVELOPMENT_RULES.md"
else
    note "check_docs.py or the documents directory not found: document claims were NOT checked"
fi

if [ -n "$DEVICE" ]; then
    [ -n "${DEVICE_SERIAL:-}" ] || { echo "--device needs DEVICE_SERIAL=<the phone's ro.serialno>: the tools refuse to touch a device they were not told to expect" >&2; exit 2; }
    echo "== on the phone"
    step "device tests (Go suite + boot-script test under the phone's shell)" sh "$HERE/device_test.sh" "$DEVICE"
else
    note "no --device given: the suite was NOT run on the phone (a host test is not proof)"
fi
if [ "$MUTATE" = 1 ]; then
    echo "== mutation harness (do the tests really fail when the code is broken?)"
    step "mutate_pif.py" python3 "$HERE/mutate_pif.py" "$HERE"
else
    note "mutation harness not run (--mutate)"
fi

echo "== gates that cannot be automated"
note "independent fresh-eyes review of any automation that writes files as root: done? attach the findings"
note "live scenario on the phone with a measured verdict (checker via uiautomator dump), and doctor afterwards"
note "claims about what else touches an artifact: tools/android-lint/who_writes.sh output attached"
echo
if [ "$FAILS" = 0 ]; then echo "MECHANICAL CHECKS PASS"; else echo "$FAILS MECHANICAL CHECK(S) FAILED"; fi
[ "$FAILS" = 0 ]
