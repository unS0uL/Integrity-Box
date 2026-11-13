#!/system/bin/sh
# AutoPilot doctor: independent, read-only diagnostics that do not need the compiled engine.
# It never prints key material. The only touch on the keybox is the same no-op "reload"
# the engine uses (open an existing file for append, close without writing).
# Prints "LEVEL name detail" lines (OK/WARN/FAIL) and exits 1 if any check FAILed.
# Test overrides: AP_KEYBOX AP_MODULES AP_BRAIN AP_CONF AP_ENGINE AP_LOGCAT AP_LOG
#                 AP_NOW AP_NO_PROBE AP_SETTLE
set -u

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd) || exit 1
KEYBOX=${AP_KEYBOX:-/data/adb/tricky_store/keybox.xml}
MODULES=${AP_MODULES:-/data/adb/modules}
BRAIN=${AP_BRAIN:-/data/adb/Box-Brain}
CONF=${AP_CONF:-$BRAIN/autopilot.conf}
ENGINE=${AP_ENGINE:-$SCRIPT_DIR/bin/box-autopilot}
LOGCAT=${AP_LOGCAT:-logcat}
LOGBIN=${AP_LOG:-log}
KDIR=$(dirname -- "$KEYBOX")
CONSUMER=0
FAILS=0
WARNS=0

report() {
    case "$1" in
        FAIL) FAILS=$((FAILS + 1)) ;;
        WARN) WARNS=$((WARNS + 1)) ;;
    esac
    printf '%-4s %-12s %s\n' "$1" "$2" "$3"
}

have() { command -v "$1" >/dev/null 2>&1; }

# All values of a configuration key (key match is case-insensitive, like the engine).
conf_values() {
    [ -r "$CONF" ] || return 0
    AP_KEY="$1" awk '
        {
            line = $0
            sub(/^[ \t]+/, "", line)
            if (line == "" || substr(line, 1, 1) == "#") next
            eq = index(line, "=")
            if (eq == 0) next
            k = substr(line, 1, eq - 1); gsub(/[ \t]+$/, "", k)
            v = substr(line, eq + 1); sub(/^[ \t]+/, "", v); sub(/[ \t\r]+$/, "", v)
            if (tolower(k) == ENVIRON["AP_KEY"]) print v
        }' "$CONF"
}

conf_last() { conf_values "$1" | tail -n 1; }

# conf_int KEY LOW HIGH DEFAULT: a number clamped like the engine does.
conf_int() {
    v=$(conf_last "$1")
    case "$v" in
        ''|*[!0-9]*) printf '%s' "$4"; return 0 ;;
    esac
    if [ "$v" -lt "$2" ]; then v=$2; fi
    if [ "$v" -gt "$3" ]; then v=$3; fi
    printf '%s' "$v"
}

# A usable rejection pattern: valid ERE, 4..200 characters, must not match the empty string.
valid_pattern() {
    AP_P="$1" awk 'BEGIN { p = ENVIRON["AP_P"]; if (length(p) < 4 || length(p) > 200) exit 2; if ("" ~ p) exit 3 }' </dev/null >/dev/null 2>&1
}

# Up to 8 valid rejection patterns joined with '|' (an ERE alternation).
conf_alternation() {
    out=""
    n=0
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        valid_pattern "$p" || continue
        n=$((n + 1))
        [ "$n" -le 8 ] || break
        if [ -z "$out" ]; then out=$p; else out="$out|$p"; fi
    done <<EOF
$(conf_values consumer.tricky_store.rejection)
EOF
    printf '%s' "$out"
}

check_tools() {
    missing=""
    for t in awk sed grep base64 xxd date tr wc; do
        have "$t" || missing="$missing $t"
    done
    if [ -n "$missing" ]; then
        report FAIL tools "missing:$missing (certificates cannot be read)"
        return 1
    fi
    optional=""
    for t in curl flock; do
        have "$t" || optional="$optional $t"
    done
    have "$LOGCAT" || optional="$optional logcat"
    have "$LOGBIN" || optional="$optional log"
    if [ -n "$optional" ]; then
        report WARN tools "optional missing:$optional (acceptance probe will be unverified)"
    else
        report OK tools "all present"
    fi
}

check_consumer() {
    mods=$(conf_last consumer.tricky_store.modules)
    [ -n "$mods" ] || mods=tricky_store
    found=""
    declared=""
    oldifs=$IFS
    IFS=,
    for m in $mods; do
        m=$(printf '%s' "$m" | tr -d ' ')
        case "$m" in
            ''|.|..|*[!A-Za-z0-9._-]*) continue ;;
        esac
        if [ -d "$MODULES/$m" ]; then
            declared=$m
            if [ ! -e "$MODULES/$m/disable" ] && [ ! -e "$MODULES/$m/remove" ]; then
                found=$m
            fi
        fi
    done
    IFS=$oldifs
    if [ -n "$found" ]; then
        report OK consumer "module $found is enabled"
        CONSUMER=1
    elif [ -n "$declared" ]; then
        # A disabled module leaves target.txt behind; that is not a live consumer.
        report FAIL consumer "module $declared is disabled or marked for removal"
    elif [ -e "$KDIR/target.txt" ]; then
        report OK consumer "directory contract (target.txt)"
        CONSUMER=1
    else
        report FAIL consumer "required keybox consumer is not installed"
    fi
}

# Reads one DER certificate as a hex string on stdin and prints
# "<serial-hex> <not-before ISO> <not-after ISO> <not-after epoch> <not-before epoch>".
# Anything that is not a well-formed X.509 certificate with sane validity prints nothing.
der_info() {
    awk '
    function h2d(s,   i, v) { v = 0; for (i = 1; i <= length(s); i++) v = v * 16 + index("0123456789abcdef", substr(s, i, 1)) - 1; return v }
    function tlv(p,   b, n) {
        if (p + 3 > length($0)) bad = 1
        T = substr($0, p, 2); b = h2d(substr($0, p + 2, 2))
        if (b < 128) { L = b; V = p + 4 } else { n = b - 128; if (n < 1 || n > 4) bad = 1; L = h2d(substr($0, p + 4, 2 * n)); V = p + 4 + 2 * n }
        N = V + 2 * L
        if (N - 1 > length($0)) bad = 1
    }
    # ASCII digits are bytes 0x30-0x39: the second hex character of each byte is the digit.
    function digits(p, len,   i, s) { s = ""; for (i = 0; i < len; i++) s = s substr($0, p + 2 * i + 1, 1); return s }
    function ascii_time(p, len,   i, c) {
        for (i = 0; i < len - 1; i++) { c = substr($0, p + 2 * i, 2); if (substr(c, 1, 1) != "3" || index("0123456789", substr(c, 2, 1)) == 0) return 0 }
        return substr($0, p + 2 * (len - 1), 2) == "5a"
    }
    function epoch(y, mo, d, h, mi, s,   era, yoe, doy, doe) {
        if (mo <= 2) y -= 1
        era = int(y / 400); yoe = y - era * 400
        doy = int((153 * (mo + (mo > 2 ? -3 : 9)) + 2) / 5) + d - 1
        doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy
        return (era * 146097 + doe - 719468) * 86400 + h * 3600 + mi * 60 + s
    }
    function when(tag, p, len,   t, y, mo, d, h, mi, s) {
        if (!((tag == "17" && len == 13) || (tag == "18" && len == 15)) || !ascii_time(p, len)) return 0
        t = digits(p, len - 1)
        if (tag == "17") { y = substr(t, 1, 2) + 0; y += (y < 50 ? 2000 : 1900); t = y substr(t, 3) }
        mo = substr(t, 5, 2) + 0; d = substr(t, 7, 2) + 0; h = substr(t, 9, 2) + 0; mi = substr(t, 11, 2) + 0; s = substr(t, 13, 2) + 0
        if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 60) return 0
        W_ISO = substr(t, 1, 4) "-" substr(t, 5, 2) "-" substr(t, 7, 2) "T" substr(t, 9, 2) ":" substr(t, 11, 2) ":" substr(t, 13, 2) "Z"
        W_EPOCH = epoch(substr(t, 1, 4) + 0, mo, d, h, mi, s)
        return 1
    }
    {
        tlv(1); if (bad || T != "30") exit 1          # Certificate
        tlv(V); if (bad || T != "30") exit 1          # TBSCertificate
        q = V; tlv(q)
        if (T == "a0") { q = N; tlv(q) }              # optional [0] version
        if (bad || T != "02") exit 1                  # serialNumber
        ser = substr($0, V, 2 * L); q = N
        if (length(ser) > 2 && substr(ser, 1, 2) == "00" && index("89abcdef", substr(ser, 3, 1)) > 0) ser = substr(ser, 3)
        tlv(q); q = N                                 # signature algorithm
        tlv(q); q = N                                 # issuer
        tlv(q); if (bad || T != "30") exit 1; vv = V  # validity
        tlv(vv); if (bad || !when(T, V, L)) exit 1; nbIso = W_ISO; nbEpoch = W_EPOCH; q = N
        tlv(q); if (bad || !when(T, V, L)) exit 1
        printf "%s %s %s %.0f %.0f\n", ser, nbIso, W_ISO, W_EPOCH, nbEpoch
    }'
}

# The n-th certificate body (base64 without whitespace); works for pretty-printed and
# single-line XML.
cert_body() {
    tr -d '\r' < "$KEYBOX" | AP_N="$1" awk '
        BEGIN { RS = "\001" }
        {
            s = $0; n = ENVIRON["AP_N"] + 0; c = 0
            while (match(s, /-----BEGIN CERTIFICATE-----[^-]*-----END CERTIFICATE-----/)) {
                c++
                if (c == n) {
                    body = substr(s, RSTART + 27, RLENGTH - 27 - 25)
                    gsub(/[ \t\n]/, "", body)
                    print body
                    exit
                }
                s = substr(s, RSTART + RLENGTH)
            }
        }'
}

check_key_format() {
    algos=$(grep -o 'algorithm="[a-z0-9]*"' "$KEYBOX" | sed 's/^algorithm="//; s/"$//')
    types=$(grep -o 'BEGIN [A-Z ]*PRIVATE KEY' "$KEYBOX" | sed 's/^BEGIN //')
    verdict=$(AP_A="$algos" AP_T="$types" awk '
        BEGIN {
            na = split(ENVIRON["AP_A"], a, "\n"); nt = split(ENVIRON["AP_T"], t, "\n")
            if (ENVIRON["AP_T"] == "") { print "NONE"; exit }
            for (i = 1; i <= nt; i++) if (t[i] == "PRIVATE KEY") { print "PKCS8"; exit }
            if (na != nt) { print "MISMATCH"; exit }
            for (i = 1; i <= nt; i++) {
                want = (a[i] == "ecdsa") ? "EC PRIVATE KEY" : (a[i] == "rsa") ? "RSA PRIVATE KEY" : ""
                if (t[i] != want) { print "MISMATCH"; exit }
            }
            print "OK " nt
        }')
    case "$verdict" in
        NONE) report FAIL key-format "no private key found" ;;
        PKCS8) report FAIL key-format "PKCS#8 key (BEGIN PRIVATE KEY): Tricky Store 1.4.1 cannot load it" ;;
        MISMATCH) report FAIL key-format "private key type does not match the declared algorithm, or is not SEC1/PKCS#1" ;;
        OK*) report OK key-format "SEC1/PKCS#1 (${verdict#OK } key)" ;;
        *) report WARN key-format "could not be evaluated" ;;
    esac
}

check_keybox() {
    if [ ! -f "$KEYBOX" ]; then
        report FAIL keybox "missing: $KEYBOX"
        return 1
    fi
    meta=$(stat -c '%a %U' "$KEYBOX" 2>/dev/null || stat -f '%Lp %Su' "$KEYBOX" 2>/dev/null || echo '? ?')
    size=$(wc -c < "$KEYBOX" | tr -d ' ')
    report OK keybox "$size bytes, mode/owner $meta"
    check_key_format

    declared=$(grep -o '<NumberOfCertificates>[[:space:]]*[0-9][0-9]*' "$KEYBOX" | sed 's/.*>[[:space:]]*//' | awk '{ s += $1 } END { print s + 0 }')
    actual=$(grep -o 'BEGIN CERTIFICATE' "$KEYBOX" | wc -l | tr -d ' ')
    if [ "$actual" -eq 0 ]; then
        report FAIL cert-count "no certificate found"
        return 1
    elif [ "$declared" -ne "$actual" ]; then
        report FAIL cert-count "declared $declared but file holds $actual"
    else
        report OK cert-count "$actual certificates"
    fi

    now=${AP_NOW:-$(date +%s)}
    window=$(conf_int renew_before_hours 6 168 24)
    i=1
    while [ "$i" -le "$actual" ]; do
        hex=$(cert_body "$i" | base64 -d 2>/dev/null | xxd -p | tr -d '\n')
        info=$(printf '%s\n' "$hex" | der_info 2>/dev/null)
        if [ -z "$info" ]; then
            report FAIL "cert-$i" "cannot be parsed as an X.509 certificate"
            i=$((i + 1))
            continue
        fi
        IFS=' ' read -r ser nbiso naiso naepoch nbepoch <<EOF
$info
EOF
        left=$(( (naepoch - now) / 3600 ))
        if [ "$nbepoch" -gt "$now" ]; then
            report FAIL "cert-$i" "serial $ser is not valid before $nbiso"
        elif [ "$naepoch" -le "$now" ]; then
            report FAIL "cert-$i" "serial $ser expired $naiso"
        elif [ "$left" -lt "$window" ]; then
            report WARN "cert-$i" "serial $ser expires $naiso (in ${left}h, inside the ${window}h renewal window)"
        else
            report OK "cert-$i" "serial $ser valid until $naiso (in ${left}h)"
        fi
        i=$((i + 1))
    done
}

check_probe() {
    if [ "${AP_NO_PROBE:-0}" = 1 ]; then
        report WARN probe "skipped (AP_NO_PROBE=1)"
        return 0
    fi
    if [ "$CONSUMER" -ne 1 ] || [ ! -f "$KEYBOX" ]; then
        report WARN probe "skipped: no consumer or keybox"
        return 0
    fi
    if ! have "$LOGCAT" || ! have "$LOGBIN"; then
        report WARN probe "unverified: no log channel on this device"
        return 0
    fi
    nonce="$(date +%s)-$$"
    if ! "$LOGBIN" -p i -t BoxAutoPilot "probe=$nonce" >/dev/null 2>&1; then
        report WARN probe "unverified: cannot write the log"
        return 0
    fi
    # ':' is a special builtin: a failed redirection would end a POSIX shell, so isolate it.
    if ! ( : >> "$KEYBOX" ) 2>/dev/null; then
        report WARN probe "unverified: cannot open the keybox for a reload"
        return 0
    fi
    settle=${AP_SETTLE:-$(conf_int probe_settle_seconds 1 15 5)}
    sleep "$settle"
    tag=$(conf_last consumer.tricky_store.tag)
    case "$tag" in
        ''|*[!A-Za-z0-9._-]*) tag=TrickyStore ;;
    esac
    pat=$(conf_alternation)
    [ -n "$pat" ] || pat='Load Keybox failed|valid keybox\.xml was not present'
    verdict=$("$LOGCAT" -d -t 3000 2>/dev/null | AP_TAG="$tag" AP_PAT="$pat" AP_MARK="probe=$nonce" awk '
        index($0, ENVIRON["AP_MARK"]) { seen = 1; next }
        seen && index($0, ENVIRON["AP_TAG"]) && $0 ~ ENVIRON["AP_PAT"] { bad = 1 }
        END { if (!seen) print "NOMARKER"; else if (bad) print "REJECTED"; else print "CLEAR" }')
    case "$verdict" in
        REJECTED) report FAIL probe "$tag refused the keybox (rejection logged after reload)" ;;
        CLEAR) report OK probe "no refusal logged after reload (negative evidence only)" ;;
        *) report WARN probe "unverified: the log marker was not visible" ;;
    esac
}

check_engine() {
    if [ ! -x "$ENGINE" ]; then
        report WARN engine "binary missing or not executable"
        return 0
    fi
    # The engine prints compact single-line JSON; strip whitespace so either layout parses.
    st=$("$ENGINE" status 2>/dev/null | tr -d ' \t\r\n')
    if [ -z "$st" ]; then
        report WARN engine "status unavailable"
        return 0
    fi
    summary=""
    for f in phase desired_enabled running time_state revocation_state; do
        v=$(printf '%s' "$st" | grep -oE "\"$f\":(\"[^\"]*\"|true|false)" | head -n 1 | sed "s/^\"$f\"://; s/\"//g")
        [ -n "$v" ] && summary="$summary$f=$v "
    done
    cons=$(printf '%s' "$st" | sed -n 's/.*"consumer":{\([^}]*\)}.*/\1/p')
    cstate=$(printf '%s' "$cons" | grep -o '"state":"[^"]*"' | head -n 1 | sed 's/^"state":"//; s/"$//')
    [ -n "$cstate" ] || cstate=unknown
    summary="${summary}consumer.state=$cstate"
    case "$cstate" in
        rejected) report FAIL engine "$summary" ;;
        *) report OK engine "$summary" ;;
    esac
}

if check_tools; then
    check_consumer
    check_keybox
    check_probe
fi
check_engine
printf 'SUMMARY fail=%s warn=%s\n' "$FAILS" "$WARNS"
[ "$FAILS" -eq 0 ]
