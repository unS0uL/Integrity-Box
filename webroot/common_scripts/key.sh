#!/system/bin/sh
# shellcheck disable=SC3043,SC1091

MODPATH="/data/adb/modules/playintegrityfix"
UPDATEPATH="/data/adb/modules_update/playintegrityfix"

# Load common functions
if [ -f "$MODPATH/common_func.sh" ]; then
    . "$MODPATH/common_func.sh"
elif [ -f "$UPDATEPATH/common_func.sh" ]; then
    . "$UPDATEPATH/common_func.sh"
else
    echo "ERROR: common_func.sh not found"
    exit 1
fi

# Paths
RECORD="/data/adb/Box-Brain"
TRICKY_STORE="/data/adb/tricky_store"
KEYBOX="$TRICKY_STORE/keybox.xml"
LOG_DIR="$RECORD/Integrity-Box-Logs"
LOG_FILE="$LOG_DIR/keybox.log"
TEMP_FILE="$(mktemp -p /data/local/tmp 2>/dev/null || echo "/data/local/tmp/keybox_dl_$$")"
CLEANUP="$MODPATH/webroot/common_scripts/cleanup.sh"
UCLEANUP="$UPDATEPATH/webroot/common_scripts/cleanup.sh"
BACKUP_DIR="$RECORD/KeyBackup"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
KEYBOX_BACKUP="$BACKUP_DIR/keybox_$TIMESTAMP.xml"
FILE="$MODPATH/module.prop"
NOW=$(date '+%d %B %I:%M %p')
SIM_KEY="/data/adb/teesim/keybox.xml"
SIM_KEYBACKUP="$BACKUP_DIR/spectre_teesim_keybox_$TIMESTAMP.xml"
DISABLE_DEFAULT="$RECORD/disable-default-source"
BANNED_FILE="$RECORD/banned_serials.txt"

# Spectre API endpoints
SPECTRE_BASE_URL="https://rawbin.dpejoh.com/key"
SPECTRE_CATALOG_URL="https://rawbin.dpejoh.com/catalog"

# Default source URL
KEYBOX_URL="https://raw.githubusercontent.com/MeowDump/MeowDump/refs/heads/main/Megatron"

log() {
    echo "$*" | tee -a "$LOG_FILE"
}

# Cleanup temp files on exit
trap 'rm -f "$TEMP_FILE" "${TEMP_FILE}".* 2>/dev/null' EXIT HUP INT TERM

# Create directories
mkdir -p "$TRICKY_STORE" "$RECORD" "$LOG_DIR" "$BACKUP_DIR" 2>/dev/null
touch "$LOG_FILE" "$BANNED_FILE" 2>/dev/null

# Backup existing keybox with timestamp if valid
if [ -s "$KEYBOX" ] && grep -q '<Keybox' "$KEYBOX" 2>/dev/null; then
    cp -f "$KEYBOX" "$KEYBOX_BACKUP" 2>/dev/null
    log " 𒀭 Backed up current keybox to $KEYBOX_BACKUP"
fi

# Universal downloader
download_url() {
    local url="$1"
    local out="$2"
    local timeout="${3:-15}"
    rm -f "$out" 2>/dev/null

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --connect-timeout 8 --max-time "$timeout" --insecure "$url" -o "$out" 2>/dev/null
        [ -s "$out" ] && return 0
    fi

    if command -v wget >/dev/null 2>&1; then
        wget -q --no-check-certificate --timeout="$timeout" --tries=2 -O "$out" "$url" 2>/dev/null
        [ -s "$out" ] && return 0
    fi

    return 1
}

# Validate if an XML file is a genuine Keybox
validate_keybox_xml() {
    local file="$1"
    [ -s "$file" ] || return 1
    local size
    size=$(wc -c < "$file" 2>/dev/null | tr -d ' ')
    [ "${size:-0}" -ge 1024 ] || return 1
    grep -q '<Keybox' "$file" 2>/dev/null && grep -q '<CertificateChain' "$file" 2>/dev/null
}

# Attempt download and decoding from Default source (Megatron)
try_default_source() {
    log " 𒀭 Checking Default Keybox source..."
    local dl_target="${TEMP_FILE}.default"

    if ! download_url "$KEYBOX_URL" "$dl_target" 20; then
        log " ✦ Default source download failed or returned 404"
        rm -f "$dl_target" 2>/dev/null
        return 1
    fi

    # Check if download is an HTML 404 error
    if grep -qi "404" "$dl_target" 2>/dev/null && [ "$(wc -c < "$dl_target" 2>/dev/null | tr -d ' ')" -lt 200 ]; then
        log " ✦ Default source returned 404 Not Found"
        rm -f "$dl_target" 2>/dev/null
        return 1
    fi

    # Decode Megatron: 10x Base64 > Hex > ROT13
    local cur="$dl_target"
    local iter=0
    while [ "$iter" -lt 10 ]; do
        iter=$((iter + 1))
        local nxt="${TEMP_FILE}.b64.$iter"
        if ! base64 -d "$cur" > "$nxt" 2>/dev/null; then
            rm -f "$nxt" "$cur" 2>/dev/null
            log " ✦ Default source decode failed at iteration $iter"
            return 1
        fi
        rm -f "$cur" 2>/dev/null
        cur="$nxt"
    done

    local hex_out="${TEMP_FILE}.hex"
    if ! command -v xxd >/dev/null 2>&1 || ! xxd -r -p "$cur" > "$hex_out" 2>/dev/null; then
        rm -f "$cur" "$hex_out" 2>/dev/null
        log " ✦ Default source hex decode failed"
        return 1
    fi
    rm -f "$cur" 2>/dev/null

    local decoded_xml="${TEMP_FILE}.xml"
    if ! tr 'A-Za-z' 'N-ZA-Mn-za-m' < "$hex_out" > "$decoded_xml" 2>/dev/null; then
        rm -f "$hex_out" "$decoded_xml" 2>/dev/null
        log " ✦ Default source ROT13 decode failed"
        return 1
    fi
    rm -f "$hex_out" 2>/dev/null

    if validate_keybox_xml "$decoded_xml"; then
        mv -f "$decoded_xml" "$KEYBOX" 2>/dev/null
        chmod 600 "$KEYBOX" 2>/dev/null
        log " ✦ Default source successfully decoded and installed"
        return 0
    fi

    rm -f "$decoded_xml" 2>/dev/null
    return 1
}

# Attempt download and decoding from Spectre Catalog
try_spectre_source() {
    log " ✦ Querying Spectre catalog for healthy keybox..."
    local cat_tmp="${TEMP_FILE}.catalog"
    local entries_tmp="${TEMP_FILE}.entries"

    if ! download_url "$SPECTRE_CATALOG_URL" "$cat_tmp" 15; then
        log " ✦ Failed to acquire Spectre catalog"
        rm -f "$cat_tmp" 2>/dev/null
        return 1
    fi

    # Parse JSON entries
    if ! tr -d '\r\n' < "$cat_tmp" 2>/dev/null |
        sed -n 's/.*"entries":\[\(.*\)\],"latest".*/\1/p' |
        sed 's/},{/}\n{/g' > "$entries_tmp" 2>/dev/null || [ ! -s "$entries_tmp" ]; then
        log " ✦ Failed to parse Spectre catalog entries"
        rm -f "$cat_tmp" "$entries_tmp" 2>/dev/null
        return 1
    fi
    rm -f "$cat_tmp" 2>/dev/null

    # Filter entries: revoked=false and softbanned=false
    local eligible_list="${TEMP_FILE}.eligible"
    awk '/"revoked":false/ && /"softbanned":false/ { print }' "$entries_tmp" > "$eligible_list" 2>/dev/null

    # If no strict clean entries, allow softbanned=true as secondary fallback
    if [ ! -s "$eligible_list" ]; then
        awk '/"revoked":false/ { print }' "$entries_tmp" > "$eligible_list" 2>/dev/null
    fi
    rm -f "$entries_tmp" 2>/dev/null

    if [ ! -s "$eligible_list" ]; then
        log " ✦ Spectre catalog contains no eligible (unrevoked) entries"
        rm -f "$eligible_list" 2>/dev/null
        return 1
    fi

    # Iterate through candidates and find the first working key not in local blacklist
    local std_alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    local shuffled_alphabet='1dgWnocayqxU3r6vA5lCIPYfHmkV08b4tz+KMsp2NQ9LRXihODwSj7BEFJ/ZuGTe'
    local found_key=0

    while IFS= read -r entry || [ -n "$entry" ]; do
        [ -z "$entry" ] && continue

        local src ver ser
        src=$(printf '%s\n' "$entry" | sed -n 's/.*"source":"\([^"]*\)".*/\1/p')
        ver=$(printf '%s\n' "$entry" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')
        ser=$(printf '%s\n' "$entry" | sed -n 's/.*"serial":"\([^"]*\)".*/\1/p')

        [ -z "$src" ] || [ -z "$ver" ] && continue

        # Check local blacklist
        if [ -n "$ser" ] && grep -Fxq "$ser" "$BANNED_FILE" 2>/dev/null; then
            log " ✦ Skipping locally banned serial: $ser ($src v$ver)"
            continue
        fi

        log " ✦ Trying Spectre key: $src v$ver (serial: ${ser:-unknown})..."
        local payload_url="${SPECTRE_BASE_URL}/${src}/${ver}"
        local enc_tmp="${TEMP_FILE}.enc"
        local b64_tmp="${TEMP_FILE}.b64"
        local dec_tmp="${TEMP_FILE}.dec"

        if ! download_url "$payload_url" "$enc_tmp" 15; then
            log " ✦ Download failed for $src v$ver"
            rm -f "$enc_tmp" 2>/dev/null
            continue
        fi

        # Alphabet conversion and Base64 decode
        if ! tr "$shuffled_alphabet" "$std_alphabet" < "$enc_tmp" > "$b64_tmp" 2>/dev/null; then
            rm -f "$enc_tmp" "$b64_tmp" 2>/dev/null
            continue
        fi
        rm -f "$enc_tmp" 2>/dev/null

        if ! base64 -d "$b64_tmp" > "$dec_tmp" 2>/dev/null; then
            rm -f "$b64_tmp" "$dec_tmp" 2>/dev/null
            continue
        fi
        rm -f "$b64_tmp" 2>/dev/null

        if validate_keybox_xml "$dec_tmp"; then
            mv -f "$dec_tmp" "$KEYBOX" 2>/dev/null
            chmod 600 "$KEYBOX" 2>/dev/null
            local ksize
            ksize=$(wc -c < "$KEYBOX" 2>/dev/null | tr -d ' ')
            log " ✦ Successfully installed keybox from Spectre ($src v$ver, $ksize bytes)"
            found_key=1
            break
        fi

        rm -f "$dec_tmp" 2>/dev/null
    done < "$eligible_list"

    if [ "$found_key" -eq 1 ]; then
        return 0
    fi

    log " ✦ All Spectre candidates exhausted"
    return 1
}

# Main Execution Flow
success=0

# Step 1: If default source is NOT disabled, attempt it first
if [ ! -f "$DISABLE_DEFAULT" ]; then
    if try_default_source; then
        success=1
    fi
else
    log " ✦ Default source disabled by user configuration, using Spectre directly"
fi

# Step 2: Fallback to Spectre if Default source failed or was disabled
if [ "$success" -eq 0 ]; then
    if try_spectre_source; then
        success=1
    fi
fi

# Step 3: Zero-Key Protection (Survival Mode)
if [ "$success" -eq 0 ]; then
    log " ✦ [ALERT] All remote key sources failed or returned revoked keys"

    # Check if the existing keybox on device is valid
    if validate_keybox_xml "$KEYBOX"; then
        log " ✦ [ZERO-KEY PROTECTION] Preserving current working keybox (Freeze Mode). Keybox NOT wiped."
        success=1
    elif [ -s "$KEYBOX_BACKUP" ] && validate_keybox_xml "$KEYBOX_BACKUP"; then
        cp -f "$KEYBOX_BACKUP" "$KEYBOX" 2>/dev/null
        chmod 600 "$KEYBOX" 2>/dev/null
        log " ✦ [ZERO-KEY PROTECTION] Restored known valid backup keybox from $KEYBOX_BACKUP"
        success=1
    else
        # Search for any valid backup in KeyBackup directory
        found_bak=""
        for b in "$BACKUP_DIR"/keybox_*.xml "$BACKUP_DIR"/spectre_*.xml; do
            [ -f "$b" ] || continue
            if validate_keybox_xml "$b"; then
                found_bak="$b"
                break
            fi
        done

        if [ -n "$found_bak" ]; then
            cp -f "$found_bak" "$KEYBOX" 2>/dev/null
            chmod 600 "$KEYBOX" 2>/dev/null
            log " ✦ [ZERO-KEY PROTECTION] Restored valid archive from $found_bak"
            success=1
        else
            log " ✦ [FATAL] No valid keybox found and all sources exhausted"
            touch "$RECORD/emergency_no_keys" 2>/dev/null
            exit 1
        fi
    fi
fi

# Step 4: Mirror keybox to other modules if present
chmod 600 "$KEYBOX" 2>/dev/null

# OMK
OMK_DIR="/data/misc/keystore/omk"
if [ -d "$OMK_DIR" ]; then
    cp -f "$KEYBOX" "$OMK_DIR/keybox.xml" 2>/dev/null
    chmod 600 "$OMK_DIR/keybox.xml" 2>/dev/null
    log " ✪ Keybox synchronized to OMK"
fi

# TEESimulator (legacy mirror if directory exists)
if [ -d "/data/adb/teesim" ]; then
    [ -s "$SIM_KEY" ] && cp -f "$SIM_KEY" "$SIM_KEYBACKUP" 2>/dev/null
    cp -f "$KEYBOX" "$SIM_KEY" 2>/dev/null
    chmod 600 "$SIM_KEY" 2>/dev/null
    log " ✪ Keybox synchronized to TEESimulator"
fi

# Step 5: Clean temporary files
if [ -f "$CLEANUP" ]; then
    sh "$CLEANUP" >/dev/null 2>&1
elif [ -f "$UCLEANUP" ]; then
    sh "$UCLEANUP" >/dev/null 2>&1
fi

# Step 6: Restart Google Services so changes take effect immediately
for proc in com.google.android.gms.unstable com.google.android.gms com.android.vending; do
    if type kill_process >/dev/null 2>&1; then
        kill_process "$proc" >/dev/null 2>&1
    elif command -v killall >/dev/null 2>&1; then
        killall "$proc" 2>/dev/null
    fi
done

# Step 7: Update description in module.prop
if [ -f "$FILE" ]; then
    DESC=$(grep '^description=' "$FILE" 2>/dev/null | sed 's| ✦ Synced on .*||' | cut -d= -f2-)
    [ -n "$DESC" ] && sed -i "s|^description=.*|description=$DESC ✦ Synced on $NOW|" "$FILE" 2>/dev/null
fi

log " 𒀭 Keybox operation completed successfully at $NOW"
exit 0
