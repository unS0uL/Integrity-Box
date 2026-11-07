#!/system/bin/sh
# Verify the extracted package, whether staged for update or freshly installed.
VERIFY_ROOT=${MODPATH:-${0%/*}}
HASHFILE="$VERIFY_ROOT/hash"
[ -s "$HASHFILE" ] || { printf '%s\n' 'Missing package hash manifest' >&2; exit 1; }
count=0
while IFS='|' read -r RELPATH EXPECT_SHA256 || [ -n "$RELPATH" ]; do
    case "$RELPATH" in
        ''|/*|..|../*|*/../*|*/..|*'|'*) printf '%s\n' 'Invalid manifest path' >&2; exit 1 ;;
    esac
    case "$EXPECT_SHA256" in ''|*[!0-9a-f]*) exit 1 ;; esac
    [ "${#EXPECT_SHA256}" -eq 64 ] || exit 1
    FILE="$VERIFY_ROOT/$RELPATH"
    [ -f "$FILE" ] && [ ! -L "$FILE" ] || { printf '%s\n' 'Missing package file' >&2; exit 1; }
    ACTUAL_SHA256=$(sha256sum "$FILE") || exit 1
    ACTUAL_SHA256=${ACTUAL_SHA256%% *}
    [ "$ACTUAL_SHA256" = "$EXPECT_SHA256" ] || { printf 'Package checksum mismatch: %s\n' "$RELPATH" >&2; exit 1; }
    count=$((count + 1))
done < "$HASHFILE"
[ "$count" -gt 0 ] || exit 1
exit 0
