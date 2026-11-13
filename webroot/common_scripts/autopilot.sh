#!/system/bin/sh
# AutoPilot v2 controller. No network work is performed by this shell.
set -u
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd) || exit 1
ENGINE="$SCRIPT_DIR/bin/box-autopilot"
BRAIN=/data/adb/Box-Brain
# The doctor is independent of the compiled engine and must work without it.
if [ "${1:-}" = doctor ]; then
    exec sh "$SCRIPT_DIR/doctor.sh"
fi
[ -x "$ENGINE" ] || { printf '%s\n' 'AutoPilot ARM64 engine missing' >&2; exit 1; }
case "${1:-start}" in
    status|inspect|probe|run-once|import|configure|clock-status)
        exec "$ENGINE" "$@"
        ;;
    enable)
        mkdir -p "$BRAIN" || exit 1
        "$ENGINE" configure autopilot on || exit 1
        ;;
    disable)
        exec "$ENGINE" disable
        ;;
    start) ;;
    *) printf '%s\n' 'Usage: autopilot.sh enable|disable|start|status|doctor|probe|inspect PATH|import PATH [SLOT]|run-once' >&2; exit 2 ;;
esac
[ -f "$BRAIN/autopilot" ] || exit 0
# Detach standard descriptors so WebUI/boot callers cannot wait on the daemon.
nohup "$ENGINE" supervise </dev/null >/dev/null 2>&1 &
exit 0
