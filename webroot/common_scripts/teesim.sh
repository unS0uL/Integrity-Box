#!/system/bin/sh

# Do not run when TeeSim is absent or disabled.
[ -d "/data/adb/modules/teesim" ] || exit 0
[ ! -f "/data/adb/modules/teesim/disable" ] || exit 0

SIM_PIXEL="/data/adb/Box-Brain/sim-pixel"
SIM_TARGET="/data/adb/Box-Brain/sim-target"

# No enabled update targets: leave config.json untouched.
[ -f "$SIM_PIXEL" ] || [ -f "$SIM_TARGET" ] || exit 0

TSIM_DIR="/data/adb/teesim"
CONFIG_JSON="$TSIM_DIR/config.json"
PIF_PROP="/data/adb/modules/playintegrityfix/custom.pif.prop"
SEC_PATCH="/data/adb/tricky_store/security_patch.txt"
TARGET_TXT="/data/adb/tricky_store/target.txt"

[ -f "$CONFIG_JSON" ] || exit 0

if [ -f "$SIM_PIXEL" ]; then
    [ -f "$PIF_PROP" ] || exit 0
    [ -f "$SEC_PATCH" ] || exit 0
fi

if [ -f "$SIM_TARGET" ]; then
    [ -f "$TARGET_TXT" ] || exit 0
fi

TMP="${CONFIG_JSON}.tmp.$$"
APPS_TMP="/data/local/tmp/.teesim_apps_$$"
cp "$CONFIG_JSON" "$TMP" || exit 0

get_pif() {
    grep -m1 -i "^$1=" "$PIF_PROP" 2>/dev/null | cut -d '=' -f2- | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

esc_json() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# Update Pixel/build identity fields only when sim-pixel is enabled.
if [ -f "$SIM_PIXEL" ]; then
    BRAND=$(esc_json "$(get_pif "BRAND")")
    DEVICE=$(esc_json "$(get_pif "DEVICE")")
    PRODUCT=$(esc_json "$(get_pif "PRODUCT")")
    MANUFACTURER=$(esc_json "$(get_pif "MANUFACTURER")")
    MODEL=$(esc_json "$(get_pif "MODEL")")

    VENDOR_PATCH=$(grep -m1 -i "^all=" "$SEC_PATCH" 2>/dev/null | cut -d '=' -f2 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    [ -n "$VENDOR_PATCH" ] || VENDOR_PATCH=$(head -n1 "$SEC_PATCH" 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

    sed -i "s|^\([[:space:]]*\"osVersion\"[[:space:]]*:[[:space:]]*\)\"[^\"]*\"|\1\"17\"|" "$TMP"
    sed -i "s|^\([[:space:]]*\"brand\"[[:space:]]*:[[:space:]]*\)\"[^\"]*\"|\1\"$BRAND\"|" "$TMP"
    sed -i "s|^\([[:space:]]*\"device\"[[:space:]]*:[[:space:]]*\)\"[^\"]*\"|\1\"$DEVICE\"|" "$TMP"
    sed -i "s|^\([[:space:]]*\"product\"[[:space:]]*:[[:space:]]*\)\"[^\"]*\"|\1\"$PRODUCT\"|" "$TMP"
    sed -i "s|^\([[:space:]]*\"manufacturer\"[[:space:]]*:[[:space:]]*\)\"[^\"]*\"|\1\"$MANUFACTURER\"|" "$TMP"
    sed -i "s|^\([[:space:]]*\"model\"[[:space:]]*:[[:space:]]*\)\"[^\"]*\"|\1\"$MODEL\"|" "$TMP"
    sed -i "s|^\([[:space:]]*\"mode\"[[:space:]]*:[[:space:]]*\)\"[^\"]*\"|\1\"generation\"|" "$TMP"
    sed -i "s|\(\"patchLevel\"[[:space:]]*:[[:space:]]*\){[^}]*}|\1{ \"system\": \"system_property\", \"vendor\": \"$VENDOR_PATCH\", \"boot\": \"$VENDOR_PATCH\" }|" "$TMP"
fi

# Update the apps array only when sim-target is enabled.
if [ -f "$SIM_TARGET" ]; then
    : > "$APPS_TMP"
    first=1
    while IFS= read -r line || [ -n "$line" ]; do
        [ -z "$line" ] && continue
        pkg=$(printf '%s' "$line" | tr -d '\r' | sed 's/[!?]$//')
        [ -z "$pkg" ] && continue
        pkg=$(esc_json "$pkg")
        if [ "$first" -eq 1 ]; then
            printf '        "%s"' "$pkg" >> "$APPS_TMP"
            first=0
        else
            printf ',\n        "%s"' "$pkg" >> "$APPS_TMP"
        fi
    done < "$TARGET_TXT"
    printf '\n' >> "$APPS_TMP"

    APPS_START=$(grep -n '"apps"' "$TMP" | head -n1 | cut -d: -f1)
    [ -n "$APPS_START" ] || { rm -f "$TMP" "$APPS_TMP"; exit 0; }
    APPS_END=$(tail -n +"$APPS_START" "$TMP" | grep -n '^[[:space:]]*\]' | head -n1 | cut -d: -f1)
    [ -n "$APPS_END" ] || { rm -f "$TMP" "$APPS_TMP"; exit 0; }
    APPS_END=$((APPS_START + APPS_END - 1))

    REBUILD="${TMP}.apps"
    head -n "$APPS_START" "$TMP" > "$REBUILD"
    cat "$APPS_TMP" >> "$REBUILD"
    tail -n +"$APPS_END" "$TMP" >> "$REBUILD"
    mv -f "$REBUILD" "$TMP"
    rm -f "$APPS_TMP"
fi

mv -f "$TMP" "$CONFIG_JSON"
exit 0
