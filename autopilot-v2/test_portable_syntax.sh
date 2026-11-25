#!/bin/sh
# The installer and the module scripts run under whatever busybox/sh the root manager ships (Magisk, KernelSU,
# APatch). Magisk's busybox accepts some bash-isms (verified: `sh -n` of `read < <(...)` passes there), other
# shells do not, and a parse error aborts the whole script. Parse every module script with dash (strict POSIX)
# and refuse process substitution / here-strings. hello.sh is exempt from the parse: dash trips over its
# ASCII art in a $(...) heredoc.
# Run: sh autopilot-v2/test_portable_syntax.sh
set -eu
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE/.."
PASS=0
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
PARSER=sh
if command -v dash >/dev/null 2>&1; then PARSER=dash; fi

FILES=$(find . \( -name '*.sh' -o -name update-binary \) -not -path './autopilot-v2/*' -not -path './.git/*' | sort)
for f in $FILES; do
    case "$f" in ./hello.sh) ;; *) "$PARSER" -n "$f" 2>/dev/null || fail "$f does not parse under $PARSER (bash-only syntax?)" ;; esac
    if grep -nE '<\(|>\(|<<<' "$f" | grep -vE '^[0-9]+:[[:space:]]*#' | grep -q .; then
        fail "$f uses process substitution or a here-string (not supported by busybox ash)"
    fi
    PASS=$((PASS + 1))
done
printf 'test_portable_syntax.sh: %d scripts checked\n' "$PASS"
