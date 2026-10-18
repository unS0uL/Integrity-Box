#!/system/bin/sh
# shellcheck disable=SC1091,SC2181,SC3012

CHECK_INTERVAL=900
GITHUB="https://raw.githubusercontent.com/MeowDump/Integrity-Box/main/auto-pilot"
BOX_BRAIN="/data/adb/Box-Brain"
MODPATH="/data/adb/modules/playintegrityfix"

mkdir -p "$BOX_BRAIN/Integrity-Box-Logs" 2>/dev/null
LOG_FILE="$BOX_BRAIN/Integrity-Box-Logs/autorun.log"

log() {
    echo "[$(date '+%H:%M:%S')] $1" >> "$LOG_FILE"
    if type writelog >/dev/null 2>&1; then
        writelog "$1" 2>/dev/null
    fi
}

log "••••••• AUTORUN START PID: $$ •••••••"

if [ -f "$MODPATH/common_func.sh" ]; then
    . "$MODPATH/common_func.sh"
    log "common_func.sh loaded"
else
    log "FATAL: common_func.sh missing"
    exit 1
fi

if [ ! -f "$BOX_BRAIN/autopilot" ]; then
    log "autopilot disabled, exit"
    exit 0
fi

LOCK_DIR="$BOX_BRAIN/autorun.lockdir"

claim_lock() {
    rm -rf "$LOCK_DIR" 2>/dev/null
    mkdir "$LOCK_DIR" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo $$ > "$LOCK_DIR/pid"
        return 0
    fi
    return 1
}

if mkdir "$LOCK_DIR" 2>/dev/null; then
    echo $$ > "$LOCK_DIR/pid"
    log "Lock acquired (fresh)"
else
    log "Lock exists, checking stale..."
    if [ -f "$LOCK_DIR/pid" ]; then
        old_pid=$(cat "$LOCK_DIR/pid" 2>/dev/null | tr -dc '0-9')
        if [ -n "$old_pid" ] && [ -d "/proc/$old_pid" ]; then
            if [ -r "/proc/$old_pid/cmdline" ] && grep -q "autorun" "/proc/$old_pid/cmdline" 2>/dev/null; then
                last_beat=$(cat "$BOX_BRAIN/daemon_heartbeat" 2>/dev/null | tr -dc '0-9')
                now=$(date +%s)
                diff=$((now - ${last_beat:-0}))
                if [ "$diff" -lt 180 ]; then
                    log "Already running (PID $old_pid, ${diff}s ago)"
                    exit 0
                else
                    log "Killing stale PID $old_pid"
                    kill -9 "$old_pid" 2>/dev/null
                    sleep 1
                    claim_lock || { log "Cannot claim lock"; exit 1; }
                    log "Lock acquired (stale reclaimed)"
                fi
            else
                claim_lock || { log "Cannot claim lock"; exit 1; }
                log "Lock acquired (foreign process)"
            fi
        else
            claim_lock || { log "Cannot claim lock"; exit 1; }
            log "Lock acquired (dead process)"
        fi
    else
        claim_lock || { log "Cannot claim lock"; exit 1; }
        log "Lock acquired (no pid file)"
    fi
fi

cleanup() {
    log "Stopping daemon"
    rm -rf "$LOCK_DIR" "$BOX_BRAIN/.executing" 2>/dev/null
    exit 0
}

trap cleanup 15 2 1 0 2>/dev/null || true

wakelock_acquire() {
    [ -w "/sys/power/wake_lock" ] && printf "integrity_autorun" > /sys/power/wake_lock 2>/dev/null
}

wakelock_release() {
    [ -w "/sys/power/wake_unlock" ] && printf "integrity_autorun" > /sys/power/wake_unlock 2>/dev/null
}

get_local_highest() {
    highest=""
    for f in "$BOX_BRAIN"/emergency_[A-Z]*; do
        [ -f "$f" ] || continue
        name=$(basename "$f")
        letter=${name#emergency_}
        case "$letter" in
            [A-Z]|[A-Z][A-Z])
                if [ -z "$highest" ]; then
                    highest="$letter"
                else
                    if [ "$letter" \> "$highest" ]; then
                        highest="$letter"
                    fi
                fi
                ;;
        esac
    done
    printf '%s' "$highest"
}

get_script() {
    if [ -f "$BOX_BRAIN/run_action" ] && [ -f "$MODPATH/action.sh" ]; then
        printf '%s' "$MODPATH/action.sh"
    elif [ -f "$MODPATH/webroot/common_scripts/key.sh" ]; then
        printf '%s' "$MODPATH/webroot/common_scripts/key.sh"
    else
        printf ''
    fi
}

check_github() {
    letter="$1"
    if ! type detect_downloader >/dev/null 2>&1; then
        log "WARNING: detect_downloader not found"
        return 1
    fi
    detect_downloader
    if [ "$DL_MODE" = "curl" ]; then
        code=$(curl -s -I --max-time 15 -o /dev/null -w "%{http_code}" "$GITHUB/emergency_$letter" 2>/dev/null)
        [ "$code" = "200" ]
    elif [ "$DL_MODE" = "wget" ]; then
        wget -q --spider --timeout=15 --tries=1 "$GITHUB/emergency_$letter" 2>/dev/null
    else
        false
    fi
}

get_remote_highest() {
    highest=""
    for letter in A B C D E F G H I J K L M N O P Q R S T U V W X Y Z; do
        if check_github "$letter"; then
            highest="$letter"
        fi
    done
    if [ "$highest" = "Z" ]; then
        for letter in AA AB AC AD AE AF AG AH AI AJ AK AL AM AN AO AP AQ AR AS AT AU AV AW AX AY AZ; do
            if check_github "$letter"; then
                highest="$letter"
            fi
        done
    fi
    if [ "$highest" = "AZ" ]; then
        for letter in BA BB BC BD BE BF BG BH BI BJ BK BL BM BN BO BP BQ BR BS BT BU BV BW BX BY BZ; do
            if check_github "$letter"; then
                highest="$letter"
            fi
        done
    fi
    printf '%s' "$highest"
}

execute() {
    letter="$1"
    if [ -f "$BOX_BRAIN/.executing" ]; then
        log "Skip: already executing"
        return 1
    fi
    touch "$BOX_BRAIN/.executing"
    script=$(get_script)
    if [ -z "$script" ]; then
        log "ERROR: no script found"
        rm -f "$BOX_BRAIN/.executing"
        return 1
    fi
    log "EXECUTE: emergency_$letter -> $script"
    wakelock_acquire
    [ -x "$script" ] || chmod +x "$script" 2>/dev/null
    if type timeout >/dev/null 2>&1; then
        timeout 120 "$script" >> "$LOG_FILE" 2>&1
        code=$?
    else
        "$script" >> "$LOG_FILE" 2>&1 &
        pid=$!
        ( sleep 120; kill "$pid" 2>/dev/null ) &
        wait "$pid" 2>/dev/null
        code=$?
    fi
    wakelock_release
    log "EXIT: $code"
    if [ "$code" -eq 0 ]; then
        touch "$BOX_BRAIN/emergency_$letter"
        log "MARKED: $letter done"
    fi
    rm -f "$BOX_BRAIN/.executing"
    return "$code"
}

log "Entering loop (interval: ${CHECK_INTERVAL}s)"

iteration=0
while true; do
    iteration=$((iteration + 1))
    now=$(date +%s)
    printf '%s' "$now" > "$BOX_BRAIN/daemon_heartbeat"
    if [ -f "$LOCK_DIR/pid" ]; then
        owner=$(cat "$LOCK_DIR/pid" 2>/dev/null | tr -dc '0-9')
        if [ "$owner" != "$$" ]; then
            log "Lost lock (owner: $owner), exit"
            exit 1
        fi
    else
        log "Lock lost, exit"
        exit 1
    fi
    log "--- Cycle #$iteration ---"
    if type wait_for_network >/dev/null 2>&1; then
        if wait_for_network 15; then
            local_max=$(get_local_highest)
            remote_max=$(get_remote_highest)
            printf '%s' "$now" > "$BOX_BRAIN/last_github_check"
            log "Local: ${local_max:-none}, Remote: ${remote_max:-none}"
            if [ -n "$remote_max" ]; then
                if [ "$remote_max" = "$local_max" ]; then
                    log "Remote = Local, no action"
                elif [ -f "$BOX_BRAIN/emergency_$remote_max" ]; then
                    log "Remote $remote_max already done"
                else
                    execute "$remote_max"
                fi
            else
                log "No remote emergency"
            fi

            # Check 2: Upstream Default source monitoring (if current key came from DEFAULT)
            current_src=$(cat "$BOX_BRAIN/current_key_source" 2>/dev/null || echo "UNKNOWN")
            current_ser=$(cat "$BOX_BRAIN/current_key_serial" 2>/dev/null | tr -dc '0-9a-fA-F')

            if [ "$current_src" = "DEFAULT" ]; then
                # Check for silent key update by author via auto-pilot/key-hash
                remote_hash=$(curl -fsSL --connect-timeout 8 --max-time 10 "https://raw.githubusercontent.com/MeowDump/Integrity-Box/main/auto-pilot/key-hash" 2>/dev/null | tr -dc '0-9a-fA-F')
                stored_hash=$(cat "$BOX_BRAIN/upstream_default_hash" 2>/dev/null | tr -dc '0-9a-fA-F')
                if [ "${#remote_hash}" -eq 64 ] && [ "${#stored_hash}" -eq 64 ] && [ "$remote_hash" != "$stored_hash" ]; then
                    log "UPSTREAM ROTATION: Author updated default key-hash on GitHub ($stored_hash -> $remote_hash)!"
                    echo "$remote_hash" > "$BOX_BRAIN/upstream_default_hash" 2>/dev/null
                    execute "DEFAULT_HASH_UPDATED"
                fi

                # Check if author flagged key status as revoked (Status: 🔴🔴🔴)
                status_text=$(curl -fsSL --connect-timeout 8 --max-time 10 "https://raw.githubusercontent.com/MeowDump/Integrity-Box/refs/heads/main/keybox/key-status" 2>/dev/null)
                if printf '%s' "$status_text" | grep -q '🔴🔴🔴'; then
                    log "UPSTREAM REVOCATION: Author flagged default key as revoked (🔴🔴🔴)!"
                    if [ -n "$current_ser" ] && ! grep -Fxq "$current_ser" "$BOX_BRAIN/banned_serials.txt" 2>/dev/null; then
                        echo "$current_ser" >> "$BOX_BRAIN/banned_serials.txt" 2>/dev/null
                    fi
                    execute "DEFAULT_REVOKED"
                fi
            fi

            # Check 3: Community Catalog Proactive Health Audit
            # Applies to ANY key (Spectre, Default, or Custom) if serial exists in catalog
            if [ -n "$current_ser" ]; then
                cat_tmp="$BOX_BRAIN/catalog_check.json"
                if curl -fsSL --connect-timeout 8 --max-time 15 "https://rawbin.dpejoh.com/catalog" -o "$cat_tmp" 2>/dev/null; then
                    entry=$(sed 's/},{/}\n{/g' "$cat_tmp" 2>/dev/null | grep "\"serial\":\"$current_ser\"" | head -n 1)
                    if [ -n "$entry" ]; then
                        if grep -Fxq "$current_ser" "$BOX_BRAIN/banned_serials.txt" 2>/dev/null; then
                            log "CATALOG AUDIT: Serial $current_ser is already in banned list (freeze/survival mode active). Skipping redundant rotation."
                        elif printf '%s\n' "$entry" | grep -q '"revoked":true'; then
                            log "PROACTIVE ROTATION: Current serial $current_ser revoked in catalog!"
                            echo "$current_ser" >> "$BOX_BRAIN/banned_serials.txt" 2>/dev/null
                            execute "PROACTIVE_REVOKED"
                        elif printf '%s\n' "$entry" | grep -q '"softbanned":true'; then
                            log "CATALOG AUDIT: Current serial $current_ser is softbanned in catalog."
                        else
                            log "CATALOG AUDIT: Current serial $current_ser is healthy in catalog."
                        fi
                    else
                        log "CATALOG AUDIT: Serial $current_ser not indexed in catalog (source: $current_src). Upstream monitoring active."
                    fi
                    rm -f "$cat_tmp" 2>/dev/null
                fi
            fi
        else
            log "Network unavailable"
        fi
    else
        log "WARNING: wait_for_network not found"
    fi
    remaining=$CHECK_INTERVAL
    while [ "$remaining" -gt 0 ]; do
        chunk=60
        [ "$remaining" -lt "$chunk" ] && chunk=$remaining
        sleep "$chunk"
        remaining=$((remaining - chunk))
        date +%s > "$BOX_BRAIN/daemon_heartbeat"
        if [ ! -f "$BOX_BRAIN/autopilot" ]; then
            log "Autopilot disabled, stop"
            cleanup
        fi
    done
done
