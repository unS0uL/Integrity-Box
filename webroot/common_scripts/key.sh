#!/system/bin/sh
# All official and fallback updates share the v2 transaction and validation path.
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd) || exit 1
case "${1:-}" in
    '') exec "$SCRIPT_DIR/bin/box-autopilot" run-once ;;
    Megatron|Megatron2) exec "$SCRIPT_DIR/bin/box-autopilot" fetch "$1" ;;
    *) printf '%s\n' 'Unsupported key variant' >&2; exit 2 ;;
esac
