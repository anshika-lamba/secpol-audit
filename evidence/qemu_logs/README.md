# Real QNX Neutrino 8.0 QEMU Target Logs (`evidence/qemu_logs/`)

This directory contains **5 real QNX Neutrino 8.0 x86_64 QEMU TCG serial captures** booted from the compiled `qnx_demo/` mutant IFS images (`M0_clean.log` through `M3_fixed.log`), verified **`5/5 MATCH`** against `secpol-audit`'s static predictions via `make verify-offline`:

- `evidence/qemu_logs/M0_clean.log` — Hardened baseline (`DIRECT_RESULT=DENIED errno=1`, `HOP1_SPAWN=DENIED errno=1`, `can_server` typed as `can_hal_t`)
- `evidence/qemu_logs/M1_no_connect.log` — Single hop only (`DIRECT_RESULT=DENIED errno=1`, `HOP1_SPAWN=OK child_pid=16388`, `HOP2_SPAWN=DENIED errno=1`)
- `evidence/qemu_logs/M2_untyped_server.log` — Untyped IFS server (`pidin -f a_n` shows `4098 - proc/boot/can_server`, caught by `RUNTIME_UNTYPED_PROCESS`)
- `evidence/qemu_logs/M3_2hop_escalate.log` — Live 2-hop escalation (`DIRECT_RESULT=DENIED errno=1`, `HOP1_SPAWN=OK child_pid=16388`, `HOP2_SPAWN=OK child_pid=16389`, `HOP2_PROBE_START pid=16389`, `HOP2_RESULT=GRANTED coid=1073741825`)
- `evidence/qemu_logs/M3_fixed.log` — Hardened remediation (`DIRECT_RESULT=DENIED errno=1`, `HOP1_SPAWN=DENIED errno=1`)

Synthetic unit-test fixtures remain strictly separated in `tests/fixtures/sample_qemu_logs/` and are verified independently via `make verify-fixtures`.

## Reproducing the Real QNX 8.0 QEMU x86_64 TCG Captures

On a host with **QNX Software Development Platform (SDP) 8.0** (`qcc`, `secpolcompile`, `mkifs`) and **QEMU** (`qemu-system-x86_64`) installed:

```bash
# 1. Source QNX SDP 8.0 toolchain environment
source ~/qnx800/qnxsdp-env.sh

# 2. Cross-compile can_server, diag_helper, ivi_exploit, build all 5 mutant IFS images,
#    and boot each mutant under QEMU x86_64 TCG (`-accel tcg -nographic`)
make qemu-mutants

# 3. Replay and verify static predictions vs. real observed QNX 8.0 kernel logs (5/5 MATCH)
make verify-offline
```

> **QEMU TCG Disclosure:** `harness/run_qemu.sh` explicitly uses QEMU software emulation (`-accel tcg -nographic`) rather than KVM so the harness reproduces identically across WSL2, CI runners, containers, and judge laptops without host virtualization prerequisites.
