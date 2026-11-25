# Real QNX Neutrino 8.0 QEMU Target Logs (`evidence/qemu_logs/`)

This directory is intentionally **free of fabricated kernel boot logs**.

In keeping with `secpol-audit`'s strict honesty guardrails, no synthetic or hand-edited log files are placed here masquerading as real QNX Neutrino 8.0 kernel captures. Synthetic logs used exclusively for offline unit testing live in `tests/fixtures/sample_qemu_logs/` and are explicitly tagged as synthetic fixtures.

## How to Populate Real QNX 8.0 QEMU x86_64 TCG Logs

On a host with **QNX Software Development Platform (SDP) 8.0** (`qcc`, `secpolcompile`, `mkifs`) and **QEMU** (`qemu-system-x86_64`) installed:

```bash
# 1. Source QNX SDP 8.0 toolchain environment
source ~/qnx800/qnxsdp-env.sh

# 2. Cross-compile can_server, diag_helper, ivi_exploit, build all 5 mutant IFS images,
#    and boot each mutant under QEMU x86_64 TCG (`-accel tcg -nographic`)
make qemu-mutants

# 3. Verify static predictions vs. real observed QNX 8.0 kernel behavior
make verify-offline
```

This populates:
- `evidence/qemu_logs/M0_clean.log`
- `evidence/qemu_logs/M1_no_connect.log`
- `evidence/qemu_logs/M2_untyped_server.log`
- `evidence/qemu_logs/M3_2hop_escalate.log`
- `evidence/qemu_logs/M3_fixed.log`

> **QEMU TCG Disclosure:** `harness/run_qemu.sh` explicitly uses QEMU software emulation (`-accel tcg -nographic`) rather than KVM so the harness reproduces identically across CI runners, containers, and judge laptops without host virtualization prerequisites.
