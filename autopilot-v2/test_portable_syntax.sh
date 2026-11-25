#!/bin/sh
# Magisk runs the installer and the module scripts with busybox ash, not bash. Anything bash-only is a syntax
# error there that aborts the whole script (Beta-6's volume-key safemode prompt used `read < <(...)`).
# Parse every module shell script with the strictest shell on hand and refuse bash-only redirections.
# hello.sh is exempt from the parse: dash trips over its ASCII art in a $(...) heredoc, ash does not.
# Run: sh autopilot-v2/test_portable_syntax.sh
set -eu
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE/.."
PASS=0
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
PARSER=sh; command -v dash >/dev/null 2>&1 && PARSER=dash

FILES=$(find . -name '*.sh' -not -path './autopilot-v2/*' -not -path './.git/*' | sort)
for f in $FILES; do
    case "$f" in ./hello.sh) ;; *) "$PARSER" -n "$f" 2>/dev/null || fail "$f does not parse under $PARSER (bash-only syntax?)" ;; esac
    if grep -nE '<\(|>\(|<<<' "$f" | grep -vE '^[0-9]+:[[:space:]]*#' | grep -vE "<<<?[[:space:]]*['\"]?[A-Z_]+['\"]?" | grep -q .; then
        fail "$f uses process substitution or a here-string (not supported by busybox ash)"
    fi
    PASS=$((PASS + 1))
done
printf 'test_portable_syntax.sh: %d scripts checked\n' "$PASS"
