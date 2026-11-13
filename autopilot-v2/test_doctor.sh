#!/bin/sh
# Host-side tests for webroot/common_scripts/doctor.sh. Uses synthetic keys generated here
# with openssl; no real keybox is ever read. python3 is used only as an independent oracle
# for dates (those assertions are skipped when it is missing).
# Run: sh autopilot-v2/test_doctor.sh
set -eu

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
DOCTOR="$HERE/../webroot/common_scripts/doctor.sh"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT INT TERM
PASS=0

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
ok() { PASS=$((PASS + 1)); }
contains() { case "$1" in *"$2"*) ok ;; *) printf '%s\n' "$1" >&2; fail "expected output to contain: $2" ;; esac; }
lacks() { case "$1" in *"$2"*) printf '%s\n' "$1" >&2; fail "output must not contain: $2" ;; *) ok ;; esac; }

# Real compact status line printed by the engine (before its first cycle).
STATUS_SAMPLE='{"installed_source":"","ready":false,"next_search_due":"0001-01-01T00:00:00Z","next_crl_due":"0001-01-01T00:00:00Z","time_state":"unknown","time_source":"","crl_checked":"0001-01-01T00:00:00Z","crl_valid_until":"0001-01-01T00:00:00Z","desired_enabled":false,"running":false,"phase":"not_started","local":{"keybox_identity":"","root_public_key_hashes":null,"state":"missing","fingerprint":"","serials":null,"expires":"0001-01-01T00:00:00Z","anchor":false},"consumer":{"id":"","required":false,"present":false,"state":"","evidence":"","checked":"0001-01-01T00:00:00Z"},"revocation_state":"unknown","integrity_verdict":"not_measured","reason":"","next_due":"0001-01-01T00:00:00Z","source":"","pid":0,"heartbeat":"0001-01-01T00:00:00Z"}'

# make_keybox NAME KEYFORMAT(sec1|pkcs8) VALID_DAYS SERIAL_HEX [DECLARED_COUNT] [LAYOUT(pretty|oneline)] [ALGO]
make_keybox() {
    d="$W/$1"
    mkdir -p "$d/tricky_store" "$d/modules/tricky_store" "$d/brain"
    openssl ecparam -name prime256v1 -genkey -noout -out "$d/root.key" 2>/dev/null
    openssl ecparam -name prime256v1 -genkey -noout -out "$d/leaf.key" 2>/dev/null
    openssl req -x509 -new -key "$d/root.key" -subj "/CN=test root" -days 20000 -out "$d/root.pem" 2>/dev/null
    openssl req -new -key "$d/leaf.key" -subj "/CN=test leaf" -out "$d/leaf.csr" 2>/dev/null
    printf 'basicConstraints=CA:TRUE\nkeyUsage=keyCertSign,digitalSignature\n' > "$d/ext"
    openssl x509 -req -in "$d/leaf.csr" -CA "$d/root.pem" -CAkey "$d/root.key" -set_serial "0x$4" -days "$3" -extfile "$d/ext" -out "$d/leaf.pem" 2>/dev/null
    if [ "$2" = pkcs8 ]; then
        openssl pkcs8 -topk8 -nocrypt -in "$d/leaf.key" -out "$d/leaf.priv" 2>/dev/null
    else
        cp "$d/leaf.key" "$d/leaf.priv"
    fi
    {
        printf '<?xml version="1.0" encoding="UTF-8"?>\n<AndroidAttestation>\n<NumberOfKeyboxes>1</NumberOfKeyboxes>\n'
        printf '<Keybox DeviceID="test">\n<Key algorithm="%s">\n<PrivateKey format="pem">\n' "${7:-ecdsa}"
        cat "$d/leaf.priv"
        printf '</PrivateKey>\n<CertificateChain>\n<NumberOfCertificates>%s</NumberOfCertificates>\n' "${5:-2}"
        printf '<Certificate format="pem">\n'; cat "$d/leaf.pem"; printf '</Certificate>\n'
        printf '<Certificate format="pem">\n'; cat "$d/root.pem"; printf '</Certificate>\n'
        printf '</CertificateChain>\n</Key>\n</Keybox>\n</AndroidAttestation>\n'
    } > "$d/tricky_store/keybox.xml"
    if [ "${6:-pretty}" = oneline ]; then
        tr -d '\n' < "$d/tricky_store/keybox.xml" > "$d/one.xml"
        mv "$d/one.xml" "$d/tricky_store/keybox.xml"
    fi
}

# Fake platform log: "log" appends the marker (and optionally a rejection), "logcat" prints it.
make_log() {
    mkdir -p "$W/bin"
    : > "$W/log.txt"
    cat > "$W/bin/log" <<'LOGEOF'
#!/bin/sh
[ "${FAKE_MUTE:-0}" = 1 ] && exit 0
echo "11-13 15:00:00.000  1  1 I BoxAutoPilot: $5" >> "$FAKE_LOG"
if [ "${FAKE_REJECT:-0}" = 1 ]; then
    echo "11-13 15:00:01.000  2  2 E TrickyStore: ${FAKE_REJECT_TEXT:-Load Keybox failed with exception}" >> "$FAKE_LOG"
fi
exit 0
LOGEOF
    cat > "$W/bin/logcat" <<'LOGEOF'
#!/bin/sh
cat "$FAKE_LOG"
LOGEOF
    chmod 755 "$W/bin/log" "$W/bin/logcat"
}

# make_engine NAME CONSUMER_STATE: a fake engine printing the real compact status layout.
make_engine() {
    mkdir -p "$W/engines"
    body=$(printf '%s\n' "$STATUS_SAMPLE" | sed "s/\"phase\":\"not_started\"/\"phase\":\"waiting\"/; s/\"running\":false/\"running\":true/; s/\"id\":\"\",\"required\":false,\"present\":false,\"state\":\"\"/\"id\":\"tricky_store\",\"required\":true,\"present\":true,\"state\":\"$2\"/")
    cat > "$W/engines/$1" <<'ENGHEAD'
#!/bin/sh
[ "$1" = status ] || exit 2
ENGHEAD
    printf "cat <<'ENGEOF'\n%s\nENGEOF\n" "$body" >> "$W/engines/$1"
    chmod 755 "$W/engines/$1"
}

# run_doctor NAME [VAR=value ...] -> sets OUT and RC
run_doctor() {
    n=$1
    shift
    d="$W/$n"
    set +e
    OUT=$(env AP_KEYBOX="$d/tricky_store/keybox.xml" AP_MODULES="$d/modules" AP_BRAIN="$d/brain" \
        AP_ENGINE="$d/none" AP_SETTLE=0 AP_LOGCAT="$W/bin/logcat" AP_LOG="$W/bin/log" FAKE_LOG="$W/log.txt" "$@" "${TEST_SH:-sh}" "$DOCTOR" 2>&1)
    RC=$?
    set -e
}

have_python=0
command -v python3 >/dev/null 2>&1 && have_python=1
oracle_end() { # leaf.pem -> ISO end date
    python3 -I -c '
import subprocess,sys,datetime
o=subprocess.run(["openssl","x509","-noout","-enddate","-in",sys.argv[1]],capture_output=True,text=True).stdout.strip().split("=")[1]
print(datetime.datetime.strptime(o,"%b %d %H:%M:%S %Y %Z").strftime("%Y-%m-%dT%H:%M:%SZ"))' "$1"
}
oracle_epoch() {
    python3 -I -c '
import subprocess,sys,datetime
o=subprocess.run(["openssl","x509","-noout","-enddate","-in",sys.argv[1]],capture_output=True,text=True).stdout.strip().split("=")[1]
print(int(datetime.datetime.strptime(o,"%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc).timestamp()))' "$1"
}

make_log
SERIAL=7a24f50d9090cb23cf6497654c9aee33

# 1. A healthy SEC1 keybox: exit 0, DER fields agree with openssl.
make_keybox good sec1 30 "$SERIAL"
run_doctor good
[ "$RC" -eq 0 ] || { printf '%s\n' "$OUT" >&2; fail "healthy keybox exited $RC"; }
contains "$OUT" "OK   key-format"
contains "$OUT" "OK   cert-count"
contains "$OUT" "serial $SERIAL valid until"
contains "$OUT" "OK   probe"
if [ "$have_python" -eq 1 ]; then
    contains "$OUT" "valid until $(oracle_end "$W/good/leaf.pem")"
else
    printf 'SKIP: python3 oracle\n'
fi

# 1b. The same file as a single line (no line breaks anywhere) parses identically.
make_keybox oneline sec1 30 "$SERIAL" 2 oneline
run_doctor oneline
[ "$RC" -eq 0 ] || { printf '%s\n' "$OUT" >&2; fail "single-line keybox exited $RC"; }
contains "$OUT" "OK   cert-count   2 certificates"
contains "$OUT" "serial $SERIAL valid until"

# 2. PKCS#8 is the incident format: FAIL with a specific explanation.
make_keybox pkcs8 pkcs8 30 "$SERIAL"
run_doctor pkcs8
[ "$RC" -eq 1 ] || fail "PKCS#8 keybox must exit 1"
contains "$OUT" "FAIL key-format"
contains "$OUT" "PKCS#8"

# 3. Validity comes from the certificate: expired, near expiry, and not yet valid.
run_doctor good AP_NOW=4102444800
[ "$RC" -eq 1 ] || fail "expired keybox must exit 1"
contains "$OUT" "FAIL cert-1"
contains "$OUT" "expired"
run_doctor good AP_NOW=1000000000
[ "$RC" -eq 1 ] || fail "not-yet-valid keybox must exit 1"
contains "$OUT" "is not valid before"
if [ "$have_python" -eq 1 ]; then
    leaf_end=$(oracle_epoch "$W/good/leaf.pem")
    run_doctor good AP_NOW=$((leaf_end - 7200))
    contains "$OUT" "WARN cert-1"
    contains "$OUT" "renewal window"
fi

# 3b. A serial with the high bit set carries a leading 00 in DER; it is shown like openssl does.
make_keybox highbit sec1 30 f1a2b3c4d5e6f70809a1b2c3d4e5f607
run_doctor highbit
contains "$OUT" "serial f1a2b3c4d5e6f70809a1b2c3d4e5f607 valid until"
# 3c. Dates from 2050 on are GeneralizedTime.
make_keybox far sec1 9500 "$SERIAL"
run_doctor far
contains "$OUT" "valid until 20"
if [ "$have_python" -eq 1 ]; then
    contains "$OUT" "valid until $(oracle_end "$W/far/leaf.pem")"
fi

# 4. Declared and actual certificate counts must agree.
make_keybox count sec1 30 "$SERIAL" 3
run_doctor count
[ "$RC" -eq 1 ] || fail "count mismatch must exit 1"
contains "$OUT" "FAIL cert-count"

# 4b. The key type must match the declared algorithm.
make_keybox mismatch sec1 30 "$SERIAL" 2 pretty rsa
run_doctor mismatch
[ "$RC" -eq 1 ] || fail "algorithm/key type mismatch must exit 1"
contains "$OUT" "FAIL key-format"

# 5. The required consumer must be installed and enabled; a stale target.txt does not count.
make_keybox noconsumer sec1 30 "$SERIAL"
rmdir "$W/noconsumer/modules/tricky_store"
run_doctor noconsumer
[ "$RC" -eq 1 ] || fail "missing consumer must exit 1"
contains "$OUT" "FAIL consumer"
make_keybox disabled sec1 30 "$SERIAL"
: > "$W/disabled/modules/tricky_store/disable"
: > "$W/disabled/tricky_store/target.txt"
run_doctor disabled
[ "$RC" -eq 1 ] || fail "a disabled module with a stale target.txt must exit 1"
contains "$OUT" "disabled or marked for removal"

# 6. Acceptance probe: rejection, silence without a marker, and a device without logcat.
: > "$W/log.txt"
run_doctor good FAKE_REJECT=1
[ "$RC" -eq 1 ] || fail "rejected keybox must exit 1"
contains "$OUT" "FAIL probe"
: > "$W/log.txt"
run_doctor good FAKE_MUTE=1
[ "$RC" -eq 0 ] || fail "an unobservable probe must not fail"
contains "$OUT" "WARN probe"
contains "$OUT" "marker was not visible"
run_doctor good AP_LOGCAT=/nonexistent/logcat
[ "$RC" -eq 0 ] || fail "missing logcat must not fail"
contains "$OUT" "no log channel"

# 6b. A keybox that cannot be opened for writing degrades the probe; the doctor still finishes.
make_keybox readonly sec1 30 "$SERIAL"
chmod 444 "$W/readonly/tricky_store/keybox.xml"
run_doctor readonly
contains "$OUT" "SUMMARY"
contains "$OUT" "cannot open the keybox"
[ ! -e "$W/absent.xml" ] && ok

# 7. Rejection patterns come from autopilot.conf (no rebuild for new log wording).
conf="$W/good/brain/autopilot.conf"
printf 'consumer.tricky_store.rejection = brand new failure text\n' > "$conf"
: > "$W/log.txt"
run_doctor good FAKE_REJECT=1 AP_CONF="$conf"
[ "$RC" -eq 0 ] || fail "the default pattern must not match once the config replaces it"
: > "$W/log.txt"
run_doctor good FAKE_REJECT=1 FAKE_REJECT_TEXT="brand new failure text" AP_CONF="$conf"
[ "$RC" -eq 1 ] || fail "a configured pattern must match"
contains "$OUT" "FAIL probe"
# 7b. Invalid, empty-matching and too-short patterns are ignored; a valid one still works.
printf 'consumer.tricky_store.rejection = [\nconsumer.tricky_store.rejection = .*\nconsumer.tricky_store.rejection = ab\nCONSUMER.TRICKY_STORE.REJECTION = Load Keybox failed\n' > "$conf"
: > "$W/log.txt"
run_doctor good FAKE_REJECT=1 AP_CONF="$conf"
[ "$RC" -eq 1 ] || { printf '%s\n' "$OUT" >&2; fail "valid pattern must survive invalid neighbours"; }
contains "$OUT" "FAIL probe"

# 8. The renewal window is clamped to 6..168 hours and the key is case-insensitive, like the engine.
make_keybox ten sec1 10 "$SERIAL"
printf 'Renew_Before_Hours = 300\n' > "$conf"
run_doctor ten AP_CONF="$conf"
lacks "$OUT" "WARN cert-1"
printf 'renew_before_hours = 5\n' > "$conf"
run_doctor ten AP_CONF="$conf"
lacks "$OUT" "WARN cert-1"

# 9. The engine line is read from the real compact JSON layout.
make_engine accepted accepted
make_engine rejected rejected
run_doctor good AP_ENGINE="$W/engines/accepted"
contains "$OUT" "OK   engine"
contains "$OUT" "phase=waiting"
contains "$OUT" "consumer.state=accepted"
run_doctor good AP_ENGINE="$W/engines/rejected"
[ "$RC" -eq 1 ] || fail "an engine reporting a refusal must exit 1"
contains "$OUT" "FAIL engine"
contains "$OUT" "consumer.state=rejected"
mkdir -p "$W/engines"
cat > "$W/engines/fresh" <<'ENGHEAD'
#!/bin/sh
[ "$1" = status ] || exit 2
ENGHEAD
printf "cat <<'ENGEOF'\n%s\nENGEOF\n" "$STATUS_SAMPLE" >> "$W/engines/fresh"
chmod 755 "$W/engines/fresh"
run_doctor good AP_ENGINE="$W/engines/fresh"
contains "$OUT" "consumer.state=unknown"

# 10. The probe must not modify the keybox, and a missing keybox is never created.
before=$(cksum < "$W/good/tricky_store/keybox.xml")
run_doctor good
after=$(cksum < "$W/good/tricky_store/keybox.xml")
[ "$before" = "$after" ] || fail "doctor changed the keybox"
ok
mkdir -p "$W/none/tricky_store" "$W/none/modules/tricky_store"
run_doctor none
[ ! -e "$W/none/tricky_store/keybox.xml" ] || fail "doctor created a keybox"
ok

# 11. No key material in any output: no base64 line of the private key may appear.
run_doctor good
while IFS= read -r line; do
    case "$line" in
        -----*) ;;
        *) lacks "$OUT" "$line" ;;
    esac
done < "$W/good/leaf.priv"

printf 'doctor tests PASS (%s assertions)\n' "$PASS"
