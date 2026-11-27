#!/system/bin/sh
# Policy helpers for the scripts that touch Tricky Store's security_patch.txt (the boot script
# service.d/prop.sh and the Action button). The AutoPilot engine honours the same rules
# (autopilot-v2/pif*.go): a script must never undo a choice the engine respects.
# PIF_BOX overrides the data directory (tests only).

# pif_patch_from_prop [FILE]: the SECURITY_PATCH of a fingerprint file as YYYY-MM-DD (default: the module's
# custom.pif.prop). Fails when the file or the value is missing or malformed: callers never invent a date.
# The single reader of that field for the installer, the boot script and the Action button.
pif_patch_from_prop() {
    _pif_f="${1:-${MODPATH:-/data/adb/modules/playintegrityfix}/custom.pif.prop}"
    [ -f "$_pif_f" ] || return 1
    _pif_v="$(sed -n 's/^SECURITY_PATCH=//p' "$_pif_f" | head -n 1 | tr -d ' \t\r')"
    case "$_pif_v" in
        [0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]) echo "$_pif_v" ;;
        *) return 1 ;;
    esac
}

# pif_conf_get KEY: the last value of KEY in autopilot.conf, lowercased ("" when absent).
pif_conf_get() {
    _pif_conf="${PIF_BOX:-/data/adb/Box-Brain}/autopilot.conf"
    [ -r "$_pif_conf" ] || return 0
    awk -v want="$1" '
        {
            line = $0; sub(/\r$/, "", line); sub(/^[ \t]+/, "", line)
            if (line == "" || substr(line, 1, 1) == "#") next
            eq = index(line, "="); if (eq == 0) next
            k = substr(line, 1, eq - 1); gsub(/[ \t]+$/, "", k)
            v = substr(line, eq + 1); sub(/^[ \t]+/, "", v); sub(/[ \t]+$/, "", v)
            if (tolower(k) == want) last = tolower(v)
        }
        END { print last }' "$_pif_conf"
}

# pif_may_write_patch: succeeds when a script may (re)write security_patch.txt.
# It must not when the stock-patch flag is set, the user set a custom patch date in the WebUI, the fingerprint
# contour is in report-only/off mode, or the user switched the patch synchronisation off.
pif_may_write_patch() {
    [ -f "${PIF_BOX:-/data/adb/Box-Brain}/patch" ] && return 1
    # a date the user pinned on purpose: any file in Custom-Patch/ (the Patch page that wrote it was removed in v48, so it is now created by hand)
    [ -n "$(ls -A "${PIF_BOX:-/data/adb/Box-Brain}/Custom-Patch" 2>/dev/null)" ] && return 1
    case "$(pif_conf_get pif_mode)" in manual | off) return 1 ;; esac
    case "$(pif_conf_get pif_sync_patch)" in off | false | 0 | no) return 1 ;; esac
    return 0
}
