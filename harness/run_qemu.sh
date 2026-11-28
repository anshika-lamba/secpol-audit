#!/usr/bin/env bash
# Boot a QNX Neutrino 8.0 x86_64 IFS image in QEMU TCG (`-accel tcg -nographic`)
# with full-stream serial capture, post-marker validation, and fail-closed exit semantics.
#
# Usage:
#   harness/run_qemu.sh [--require-post-marker <pattern>] <ifs_image> <output_log> [timeout_seconds]
#
# Why timeout exit 124 can be legitimate:
#   QNX does not power off QEMU after printing `=== SECPOL_AUDIT_DONE ===`, so QEMU
#   may remain idle until `timeout` exits with 124. Exit 124 is accepted ONLY when:
#     1. The logging pipeline (`tee`) succeeded (`rc == 0`),
#     2. `=== SECPOL_AUDIT_DONE ===` is present in the captured serial log, AND
#     3. Any required post-marker record (e.g. `SECPOLEV_STATS:` for sentry/blast
#        boots) appears AFTER `=== SECPOL_AUDIT_DONE ===`.
#   Any other nonzero QEMU exit status (crash/signal) or missing marker fails closed.

set -euo pipefail

REQUIRE_POST_MARKER=""
POSITIONAL=()

while [ "$#" -gt 0 ]; do
    case "$1" in
        --require-post-marker)
            if [ "$#" -lt 2 ]; then
                echo "ERROR: --require-post-marker requires an argument" >&2
                exit 2
            fi
            REQUIRE_POST_MARKER="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--require-post-marker <pattern>] <ifs_image> <output_log> [timeout_seconds]"
            exit 0
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done

if [ "${#POSITIONAL[@]}" -lt 2 ]; then
    echo "Usage: $0 [--require-post-marker <pattern>] <ifs_image> <output_log> [timeout_seconds]" >&2
    exit 2
fi

IFS_IMAGE="${POSITIONAL[0]}"
OUTPUT_LOG="${POSITIONAL[1]}"
TIMEOUT_SEC="${POSITIONAL[2]:-45}"

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "ERROR: qemu-system-x86_64 not found on PATH. Install QEMU to run live QNX 8.0 target verification." >&2
    exit 2
fi

if [ ! -f "$IFS_IMAGE" ]; then
    echo "ERROR: IFS boot image not found: $IFS_IMAGE" >&2
    echo "Build QNX 8.0 mutant images first with: make -C qnx_demo images" >&2
    exit 2
fi

mkdir -p "$(dirname "$OUTPUT_LOG")"

echo "[run_qemu.sh] Booting $IFS_IMAGE under QEMU x86_64 TCG (timeout=${TIMEOUT_SEC}s)..."
echo "[run_qemu.sh] Capturing full serial console to $OUTPUT_LOG"

# Capture the complete QEMU serial stream without early-exit consumer truncation.
# Use a tiny wrapper with a TERM trap + sentinel file so we can distinguish a
# genuine `timeout` termination from QEMU naturally exiting with status 124.
TIMEOUT_SENTINEL="$(mktemp)"
trap 'rm -f "$TIMEOUT_SENTINEL"' EXIT

set +e
timeout --foreground "${TIMEOUT_SEC}" \
    bash -c '
        sentinel="$1"; shift
        child=""
        trap '\''[ -n "$child" ] && kill -TERM "$child" 2>/dev/null; wait "$child" 2>/dev/null; echo 1 > "$sentinel"; exit 143'\'' TERM
        "$@" &
        child=$!
        wait "$child"
        exit $?
    ' _ "$TIMEOUT_SENTINEL" \
    qemu-system-x86_64 \
        -accel tcg \
        -cpu max \
        -m 512M \
        -smp 2 \
        -nographic \
        -no-reboot \
        -serial mon:stdio \
        -kernel "$IFS_IMAGE" \
    | tee "$OUTPUT_LOG"
PIPE_RCS=("${PIPESTATUS[@]}")
set -e

QEMU_RC="${PIPE_RCS[0]:-1}"
TEE_RC="${PIPE_RCS[1]:-1}"
TIMED_OUT=0
if [ "$QEMU_RC" -eq 124 ] && [ -s "$TIMEOUT_SENTINEL" ]; then
    TIMED_OUT=1
fi
rm -f "$TIMEOUT_SENTINEL"

if [ "$TEE_RC" -ne 0 ]; then
    echo "[run_qemu.sh] ERROR: Serial logging pipeline (tee) failed with exit $TEE_RC" >&2
    exit "$TEE_RC"
fi

if [ "$QEMU_RC" -ne 0 ] && [ "$TIMED_OUT" -ne 1 ]; then
    echo "[run_qemu.sh] ERROR: QEMU exited unexpectedly with status $QEMU_RC; log saved to $OUTPUT_LOG" >&2
    exit "$QEMU_RC"
fi

HAS_DONE=0
if grep -q "=== SECPOL_AUDIT_DONE ===" "$OUTPUT_LOG"; then
    HAS_DONE=1
fi

if [ "$HAS_DONE" -ne 1 ]; then
    if [ "$TIMED_OUT" -eq 1 ]; then
        echo "[run_qemu.sh] ERROR: Reached timeout (${TIMEOUT_SEC}s) before completion marker; partial serial log saved to $OUTPUT_LOG" >&2
        exit 124
    fi
    echo "[run_qemu.sh] ERROR: Completion marker '=== SECPOL_AUDIT_DONE ===' missing from $OUTPUT_LOG (QEMU rc=$QEMU_RC)" >&2
    exit 1
fi

if [ -n "$REQUIRE_POST_MARKER" ]; then
    HAS_POST=0
    if [ "$REQUIRE_POST_MARKER" = "SECPOLEV_STATS:" ]; then
        if awk '
            { gsub(/\r/, "") }
            /=== SECPOL_AUDIT_DONE ===/ { seen_done=1; next }
            seen_done && $0 ~ /^SECPOLEV_STATS:[[:space:]]*ok=[0-9]+[[:space:]]+denied=[0-9]+[[:space:]]+dropped=[0-9]+[[:space:]]*$/ { found=1; exit 0 }
            END { exit (found ? 0 : 1) }
        ' "$OUTPUT_LOG"; then
            HAS_POST=1
        fi
    elif awk -v pat="$REQUIRE_POST_MARKER" '
        { gsub(/\r/, "") }
        /=== SECPOL_AUDIT_DONE ===/ { seen_done=1; next }
        seen_done && index($0, pat) > 0 { found=1; exit 0 }
        END { exit (found ? 0 : 1) }
    ' "$OUTPUT_LOG"; then
        HAS_POST=1
    fi
    if [ "$HAS_POST" -ne 1 ]; then
        echo "[run_qemu.sh] ERROR: Required post-marker record '$REQUIRE_POST_MARKER' missing or malformed after '=== SECPOL_AUDIT_DONE ===' in $OUTPUT_LOG" >&2
        exit 1
    fi
fi

if [ "$TIMED_OUT" -eq 1 ]; then
    echo "[run_qemu.sh] Done (post-completion idle timeout). Log written to $OUTPUT_LOG"
else
    echo "[run_qemu.sh] Done. Log written to $OUTPUT_LOG"
fi
exit 0
