#!/system/bin/sh
# All official and fallback updates share the v2 transaction and validation path.
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd) || exit 1

# The author's hint (v48.1): a keybox target whose module is installed and enabled, but which the user did not
# switch on, is skipped by the engine. Tell the user how to enable it (same wording and conditions as before).
BOX=/data/adb/Box-Brain
hint_disabled() { # MODULE FLAG TITLE
    [ -d "/data/adb/modules/$1" ] && [ ! -f "/data/adb/modules/$1/disable" ] && [ ! -f "$BOX/$2" ] || return 0
    echo "----------------------------------------"
    echo " ✦ $3 keybox update is disabled by user"
    echo "    DO THIS TO ENABLE :"
    echo "    WebUI -> Customise Scope -> Keybox"
    echo "----------------------------------------"
}

case "${1:-}" in
    '')
        hint_disabled oh_my_keymint omk-key OhMyKeyMint
        hint_disabled teesim sim-key TEE-SIM
        exec "$SCRIPT_DIR/bin/box-autopilot" run-once ;;
    Megatron|Megatron2) exec "$SCRIPT_DIR/bin/box-autopilot" fetch "$1" ;;
    *) printf '%s\n' 'Unsupported key variant' >&2; exit 2 ;;
esac
