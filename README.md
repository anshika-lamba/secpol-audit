# secpol-audit

[![CI](https://github.com/anshika-lamba/secpol-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/anshika-lamba/secpol-audit/actions/workflows/ci.yml)

A deterministic QNX 8.0 security-policy auditor that connects static privilege-escalation analysis with native security-event telemetry and reproducible before/after verification.

- **Interactive Before/After Blast Explorer (GitHub Pages):** https://anshika-lamba.github.io/secpol-audit/
- **Hands-On QNX 8.0 Codelab:** https://anshika-lamba.github.io/secpol-audit/codelab/ (Markdown: [`codelab/README.md`](codelab/README.md))

---

## 1. What security problem does this solve?

QNX Neutrino 8.0 enforces least privilege through security policies (`.secpol`), IFS boot scripts (`.ifs`), and resource-manager attachment rules (`allow_attach`). In multi-service embedded systems, individual rules can look harmless in isolation while composing into multi-hop privilege-escalation chains—for example, an untrusted UI type (`ivi_ui_t`) spawning an intermediate helper (`diag_helper_t`) that transitions into a privileged hardware-access type (`can_hal_t`).

`secpol-audit` models these transitive paths statically and pairs them with on-target QNX 8.0 kernel telemetry (`libsecpolev`) and independent syscall probes (`kprobe.c`) so every finding is backed by reproducible evidence.

---

## 2. What does the tool actually detect?

`secpol-audit` strictly separates three evidence layers and never conflates them:

1. **Static reachability (`STATIC_ONLY`):**
   - Multi-hop `settypeid` / `derive_type` / `default_spawn_type` escalation chains toward privileged abilities (`mem_phys`, `io`, `pathspace`, `public_channel`, `trace`, etc.).
   - IFS boot-script wiring defects (`UNTYPED_IFS_SERVICE`, `PRE_SECPOLPUSH_LAUNCH`, `UNDEFINED_IFS_TYPE`) and `allow_attach` / `mount_point` / `PATHSPACE_HIJACK_OVERLAP` checks.
2. **Syscall probe outcomes (`SYSCALL_ONLY_UNOBSERVABLE`):**
   - Independent on-target `kprobe.c` results (`KPROBE_JSON:`) for `settypeid`, `channel_connect`, and fresh-path `secpol_resmgr_attach()` (`allow_attach`) with strict 5-way errno classification (`ALLOW`, `DENY_POLICY` `errno=13`, `DENY_ABILITY` `errno=1`, `INCONCLUSIVE` `errno=17`, `SETUP_FAILURE`).
3. **PID-correlated `libsecpolev` telemetry (`OBSERVED_AND_CORRELATED`):**
   - Native microkernel security events captured by `secpol_sentry.c` via `secpolev_wait_event()` and `secpolev_get_pid()`, matched 1-to-1 by PID (`ev.pid == probe.pid` or `LINEAGE_HOP1`/`LINEAGE_HOP2` `parent_pid` -> `child_pid` causal linkage).

---

## 3. Which parts run on QNX 8.0 and which run on the host?

- **On QNX 8.0 (QEMU x86_64 TCG):**
  - **Nested two-hop exploit boot (`qnx_demo/build_sentry.ifs.in`):** Runs `secpol_sentry` alongside `ivi_exploit` -> `diag_helper` -> `can_hal_t`:
    - Under vulnerable `M3_sentry_escalate.secpol`: `ivi_exploit` (`pid=16388`) transitions to `diag_helper` (`pid=20485`), which transitions to `can_hal_t` (`pid=20486`) and opens `can_ctrl` (`HOP2_RESULT=GRANTED`).
    - Under hardened `M0_sentry_clean.secpol`: `HOP1_SPAWN=DENIED` blocks the chain at the first hop.
  - **Independent per-edge probe boot (`qnx_demo/build_blast.ifs.in` + `qnx_demo/kprobe.c`):** Exercises each `(origin, op, target)` edge independently—including fresh-path `secpol_resmgr_attach()` (`ALLOW` `errno=0` on `/dev/secpol_probe_allow` and `EACCES` `errno=13` on `/dev/secpol_probe_deny_<origin>`)—while `secpol_sentry` records PID-tagged `SECPOLEV_JSON:` events and live kernel policy provenance via `secpol_get_policy_id()` (`SECPOLEV_POLICY_ID:`).
  - **12-service ADAS channel-override verification (`qnx_demo/build_adas_blast.ifs.in` + `ADAS_12svc_blast.secpol` / `ADAS_12svc_fixed_blast.secpol`):** Verifies 16/16 probes (`COMPLETE`) across 4 origins with an explicit QNX 8.0 channel-type override (`allow_attach can_hal_t /dev/name/local/can_ctrl can_chan_t;`) and distinct live kernel policy IDs (`2418320052` vulnerable vs. `3119197131` remediated).
- **On the host (Python 3.10+, stdlib-only):**
  - `secpol_audit` parses `.secpol` and `.ifs` files, auto-generates expected-probe manifests and IFS snippets for any policy (`secpol-audit generate-probes`), builds the static escalation graph, correlates `KPROBE_JSON:` + `LINEAGE_HOP*` + `SECPOLEV_JSON:` telemetry against live `SECPOLEV_POLICY_ID` provenance, computes `EvidenceCompleteness`, and renders SARIF 2.1.0 (`docs/ci-integration.yml`), JSON, and offline HTML reports (`docs/index.html`).

---

## 4. How to reproduce the evidence

### Offline replay (5 minutes, no QNX SDP required)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

pytest -q
python3 harness/verify_offline.py
make verify-fixtures
```

### Live QNX SDP 8.0 + QEMU execution

Live QNX 8.0 x86_64 TCG images are built and booted via `.github/workflows/qemu-sentry.yml` (`make -C qnx_demo sentry-images blast-images secpolgen-image`, `make qemu-blast`, and `harness/run_qemu.sh`), which enforces fail-closed exit-code and `completeness.json` (`result == "COMPLETE"`, `mismatches == 0`, `dropped_events == 0`) checks.

---

## 5. Known limitations

- **QEMU x86_64 TCG only:** All live captures were executed under QEMU x86_64 TCG; no production-readiness or formal security certification claims are made.
- **`secpolgenerate -N -u` capture scope:** `qnx_demo/secpolgen_capture.ifs` is a dev-time capture on a minimal custom IFS (`slogger2`, `pipe`, `can_server`) where `random` exits under QEMU TCG without hardware RNG.
- **`dropped=0` scope:** `dropped=0` is only meaningful in independent verification boots without `secpolgenerate` active.
- **`/dev/secpol_sentry` snapshot semantics:** `/dev/secpol_sentry` provides a per-client frozen snapshot with independent OCB read offsets, not a continuous live event stream.
- **Policy reachability vs. exploitability:** Static and probed blast-radius edges prove worst-case post-compromise **policy-permitted reachability** (what the QNX microkernel allows a compromised type to do), not that a specific application binary contains a remote exploit.
- **`libsecpolev` single-consumer constraint:** Per QNX 8.0 architecture, `libsecpolev` consumes system trace events exclusively and cannot run simultaneously with `tracelogger` / System Profiler unless `secpolgenerate` is forwarding events.

---

## Evidence Map

| Claim | Repo Implementation & Committed Raw Evidence |
| :--- | :--- |
| **Static privilege analysis** | `secpol_audit/parser_secpol.py`, `secpol_audit/blast.py`, `evidence/blast/` |
| **Native QNX telemetry** | `qnx_demo/secpol_sentry.c` (`secpolev_wait_event()`, `secpolev_get_pid()`) |
| **Process-level transition evidence** | `evidence/qemu_logs/M3_sentry_escalate.log` (329 events: 327 OK, 2 DENIED, 0 dropped); `evidence/qemu_logs/M0_sentry_clean.log` (281 events: 278 OK, 3 DENIED, 0 dropped) |
| **Resource-manager security enforcement** | `qnx_demo/kprobe.c` (`secpol_resmgr_attach()`), `evidence/blast/M0_blast_completeness.json`, `evidence/blast/M3_blast_completeness.json` (12/12 1-to-1 PID correlated, 1 `ALLOW`, 2 `EACCES`, 0 `EEXIST`, 0 mismatches, `COMPLETE`) |
| **Remediation** | `qnx_demo/mutants/M3_sentry_escalate.secpol` vs. `qnx_demo/mutants/M0_sentry_clean.secpol` + raw QEMU logs |
| **12-service ADAS & channel-type override** | `qnx_demo/mutants/ADAS_12svc_blast.secpol` vs. `ADAS_12svc_fixed_blast.secpol`, `evidence/adas_blast/` (16/16 `COMPLETE`, `can_chan_t` override, `kernel_policy_id` `2418320052` vs. `3119197131`) |
| **CI & Developer Adoption** | `secpol-audit generate-probes`, `docs/ci-integration.yml` (SARIF 2.1.0 GitHub Code Scanning), `tests/test_kprobe_host.c` (`gcc -Werror`) |
| **Reproducibility** | `harness/verify_offline.py`, `harness/run_qemu.sh`, `.github/workflows/ci.yml`, `.github/workflows/qemu-sentry.yml`, `evidence/MANIFEST.json` |
