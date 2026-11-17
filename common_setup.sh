OPTIMISE="$MODPATH/webroot/common_scripts/hehe.sh"

check_ksun() {
    KSUN_FLAG="/data/adb/Box-Brain/ksun"
    KSUD="/data/adb/ksud"

    rm -f "$KSUN_FLAG"

    [ -x "$KSUD" ] || return 0

    HELP="$("$KSUD" --help 2>/dev/null)"
    case "$HELP" in
        *"KernelSU Next userspace cli"*) ;;
        *) return 0 ;;
    esac

    VERSION_OUTPUT="$("$KSUD" -V 2>/dev/null)"
    VERSION="$(printf '%s\n' "$VERSION_OUTPUT" |
        sed -n 's/^ksud \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' |
        head -n 1)"

    [ -n "$VERSION" ] || return 0

    MAJOR="${VERSION%%.*}"
    REST="${VERSION#*.}"
    MINOR="${REST%%.*}"
    PATCH="${REST#*.}"

    if [ "$MAJOR" -gt 3 ] ||
        { [ "$MAJOR" -eq 3 ] && [ "$MINOR" -gt 4 ]; } ||
        { [ "$MAJOR" -eq 3 ] && [ "$MINOR" -eq 4 ] && [ "$PATCH" -ge 0 ]; }; then
        if [ "$MAJOR" -gt 3 ] ||
            [ "$MINOR" -gt 4 ] ||
            [ "$PATCH" -ge 0 ]; then
            mkdir -p /data/adb/Box-Brain
            : > "$KSUN_FLAG"
        fi
    fi

    return 0
}

check_ksun >/dev/null 2>&1 || true

if [ -f "/data/adb/Box-Brain/ksun" ]; then
    "$OPTIMISE" >/dev/null 2>&1 || true
fi

# Skip on pixel mode
if [ -e "/sdcard/zygisk" ] || [ -e "/data/adb/Box-Brain/zygisk" ]; then
    return 0
fi

if ! $SKIPPERSISTPROP; then
    # Work around custom ROM PropImitationHooks conflict when their persist props don't exist
    if [ -n "$(resetprop ro.aospa.version)" -o -n "$(resetprop net.pixelos.version)" -o -n "$(resetprop ro.afterlife.version)" -o -f /data/system/gms_certified_props.json ]; then
        for PROP in persist.sys.pihooks.first_api_level persist.sys.pihooks.security_patch; do
            resetprop | grep -q "\[$PROP\]" || persistprop "$PROP" ""
        done
    fi

    # Work around supported custom ROM PropImitationHooks/PixelPropsUtils (and hybrids) conflict when spoofProvider is disabled
    if resetprop | grep -qE "persist.sys.pihooks|persist.sys.entryhooks|persist.sys.spoof|persist.sys.pixelprops|persist.sys.pp" || [ -f /data/system/gms_certified_props.json ]; then
        persistprop persist.sys.pihooks.disable.gms_props true
        persistprop persist.sys.pihooks.disable.gms_key_attestation_block true
        persistprop persist.sys.entryhooks_enabled false
        persistprop persist.sys.spoof.gms false
        persistprop persist.sys.pixelprops.gms false
        persistprop persist.sys.pixelprops.gapps false
        persistprop persist.sys.pixelprops.google false
        persistprop persist.sys.pixelprops.pi false
        persistprop persist.sys.pp.gms false
        persistprop persist.sys.pp.finsky false
    fi
fi
