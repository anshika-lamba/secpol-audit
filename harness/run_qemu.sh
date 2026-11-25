#!/usr/bin/env bash
# Boot a QNX Neutrino 8.0 x86_64 IFS image in QEMU TCG (`-accel tcg -nographic`)
# with timeout and serial log capture.
#
# Usage:
#   harness/run_qemu.sh <ifs_image> <output_log> [timeout_seconds]
#
# Requires:
#   - qemu-system-x86_64 on PATH
#   - A compiled QNX 8.0 x86_64 boot image built via `make -C qnx_demo images`

set -euo pipefail

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <ifs_image> <output_log> [timeout_seconds]" >&2
    exit 2
fi

IFS_IMAGE="$1"
OUTPUT_LOG="$2"
TIMEOUT_SEC="${3:-45}"

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
echo "[run_qemu.sh] Capturing serial console to $OUTPUT_LOG"

# Note: QEMU TCG (`-accel tcg`) is used intentionally for portable, KVM-free CI/judge execution.
# Stop once the guest emits `=== SECPOL_AUDIT_DONE ===` or timeout expires.
set +e
timeout --foreground "${TIMEOUT_SEC}" \
    qemu-system-x86_64 \
        -accel tcg \
        -cpu max \
        -m 512M \
        -smp 2 \
        -nographic \
        -no-reboot \
        -serial mon:stdio \
        -kernel "$IFS_IMAGE" \
    | tee "$OUTPUT_LOG" \
    | awk '/=== SECPOL_AUDIT_DONE ===/ { print; fflush(); exit 0 } { print; fflush() }'
RC=$?
set -e

if [ "$RC" -eq 124 ]; then
    echo "[run_qemu.sh] Reached timeout (${TIMEOUT_SEC}s); partial serial log saved to $OUTPUT_LOG" >&2
fi

echo "[run_qemu.sh] Done. Log written to $OUTPUT_LOG"
