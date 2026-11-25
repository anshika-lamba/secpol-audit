# `secpol-audit` — QNX Neutrino 8.0 Security Policy Auditor & Privilege-Escalation Graph Analyzer

> **QNX Global Hackathon 2026** — *Developer Tooling & Host Tools* + *Best Use of QNX-Specific Technologies*

`secpol-audit` is a **100% deterministic, fail-closed, zero-dependency** static & runtime security policy auditor and BloodHound-style `settypeid` privilege-escalation graph analyzer for **QNX Neutrino 8.0** (`.secpol` + `build.ifs` + `pidin -f a_n`).

![secpol-audit ADAS 12-service privilege-escalation graph](docs/adas_graph_preview.svg)

*Generated directly from `examples/adas_12svc.secpol` + `examples/adas_12svc.ifs` via `secpol-audit paths ... --svg docs/adas_graph_preview.svg`. Solid crimson arrows denote real `ESCALATION` transitions (`settypeid`); dashed slate arrows denote `REVIEW-ONLY` IPC edges (`channel_connect` / `allow_link`).*

---

## Screen-1: Predicted vs. Observed Verification Matrix

`secpol-audit` catches transitive multi-hop `settypeid` privilege escalations and `build.ifs` wiring flaws **before flashing a single QNX image**—and pairs static analysis with a real 3-binary QNX 8.0 C proof-of-concept (`qnx_demo/`) and runtime `pidin -f a_n` drift checker.

| Mutant | Policy / IFS Flaw | `secpol-audit` Static Prediction | Expected QNX 8.0 Target Behavior (`qnx_demo/`) | Live QEMU x86_64 TCG Log Status |
| :--- | :--- | :--- | :--- | :--- |
| **`M0_clean`** | Hardened baseline | **PASS** (0 chains, 0 wiring errors) | `DIRECT_RESULT=DENIED`, `HOP1_SPAWN=DENIED`, all typed in `pidin` | Run `make qemu-mutants` on SDP 8.0 |
| **`M1_no_connect`** | `ivi_ui_t -> diag_helper_t` only (no hop-2 escalation or CAN connect) | **PASS** (0 escalation chains; `diag_helper_t` is not a sink) | `DIRECT_RESULT=DENIED`, `HOP1_SPAWN=OK`, `HOP2_RESULT=DENIED` | Run `make qemu-mutants` on SDP 8.0 |
| **`M2_untyped_server`** | `can_server` launched without `on -T can_hal_t` | **FAIL**: `UNTYPED_IFS_SERVICE` (`HIGH`) | `pidin -f a_n` shows `can_server` untyped -> `RUNTIME_UNTYPED_PROCESS` (`CRITICAL`) | Run `make qemu-mutants` on SDP 8.0 |
| **`M3_2hop_escalate`** | `ivi_ui_t -> diag_helper_t -> can_hal_t` (`mem_phys`, `io`, `/dev/name/local/can_ctrl`) | **FAIL**: `ESCALATION_CHAIN` (`CRITICAL`, 2-hop) | `DIRECT_RESULT=DENIED`, `HOP1_SPAWN=OK`, `HOP2_TRANSITION=OK`, **`HOP2_RESULT=GRANTED`** | Run `make qemu-mutants` on SDP 8.0 |
| **`M3_fixed`** | Removes `settypeid` chain from M3 | **PASS** (`diff`: `-1 escalation chain (0 remaining)`) | `DIRECT_RESULT=DENIED`, `HOP1_SPAWN=DENIED` | Run `make qemu-mutants` on SDP 8.0 |

> **Honesty & QEMU TCG Disclosure:**
> - No fabricated QNX kernel logs are committed in `evidence/qemu_logs/`. All static checks, parsers, graph algorithms, SARIF 2.1.0 output, HTML workbench, and runtime `pidin` diff logic are verified locally via `pytest -v`. Synthetic unit-test fixtures live exclusively in `tests/fixtures/sample_qemu_logs/` and are explicitly labeled as synthetic fixtures.
> - When run on a host with **QNX SDP 8.0** (`qcc`, `secpolcompile`, `mkifs`) and **QEMU** (`qemu-system-x86_64`), `harness/run_qemu.sh` uses **QEMU software emulation (`-accel tcg -nographic`)** intentionally so verification is reproducible across CI runners and judge machines without requiring KVM hardware virtualization.
> - When `secpolcompile` is absent on the host, `secpol-audit` explicitly reports **`skipped`**—never `pass`.

---

## Core Design Principles

1. **100% Deterministic & Fail-Closed:** Zero LLM calls in core analysis. Any unsupported QNX `.secpol` or `build.ifs` construct or syntax error emits a structured `UNSUPPORTED_CONSTRUCT` / `PARSE_ERROR` diagnostic with exact `file:line:col` and exits with **code `2`**.
2. **Strict Exit Codes:**
   - `0` — Clean pass (no critical/high/error/medium findings and no privilege expansion)
   - `1` — Policy, IFS wiring, escalation chain, runtime drift finding, or privilege expansion in `diff`
   - `2` — Parser error, `UNSUPPORTED_CONSTRUCT`, unreadable input, or invalid CLI usage
3. **Strict Graph Edge Separation:**
   - **`ESCALATION` (solid crimson):** `settypeid`, `derive_type` (with matching `settypeid`), and `default_spawn_type` transitions.
   - **`REVIEW_ONLY` (dashed slate):** `channel connect` and `allow_link` IPC/namespace edges—explicitly tagged `review-only` and **never** traversed as privilege-escalation hops.
4. **Zero Runtime Dependencies & 100% Offline HTML:** Core `secpol_audit/` uses Python 3.10+ standard library only. Generated `--html` reports are single-file, zero-CDN interactive SVG workbenches.

---

## Quickstart

```bash
# Install editable (Python 3.10+, zero runtime deps)
pip install -e ".[dev]"

# 1. Run static policy + IFS wiring checks with SARIF 2.1.0 output
secpol-audit check examples/adas_12svc.secpol \
  --ifs examples/adas_12svc.ifs \
  --format sarif

# 2. Generate self-contained BloodHound-style HTML workbench (and optional static SVG preview)
secpol-audit paths examples/adas_12svc.secpol \
  --ifs examples/adas_12svc.ifs \
  --html /tmp/adas_report.html \
  --svg docs/adas_graph_preview.svg

# 3. CI privilege-expansion gate (diff vulnerable -> hardened policy)
secpol-audit diff examples/adas_12svc.secpol examples/adas_12svc_fixed.secpol
# -> Escalation chains: -1 escalation chain (0 remaining) (exits 0)

# 4. Verify runtime `pidin -f a_n` snapshot against static policy & IFS
secpol-audit verify-runtime tests/fixtures/sample_qemu_logs/pidin_drift.log \
  --policy examples/adas_12svc_fixed.secpol \
  --ifs examples/adas_12svc_fixed.ifs

# 5. Run the full automated test suite
make test
```

---

## 12-Service ADAS Demo (`examples/adas_12svc.*`)

Includes 12 realistic automotive QNX 8.0 services (`slogger2_t`, `secpol_mgr_t`, `io_sock_t`, `can_hal_t`, `lidar_drv_t`, `cam_drv_t`, `perception_t`, `planner_t`, `ota_agent_t`, `diag_helper_t`, `telemetry_t`, `ivi_ui_t`) with 4 planted flaws caught immediately by `secpol-audit`:

1. **`ESCALATION_CHAIN` (CRITICAL):** 2-hop transitive escalation `ivi_ui_t -> diag_helper_t -> can_hal_t` (gains `mem_phys`, `io`, `/dev/can_ctrl`).
2. **`PRE_SECPOLPUSH_LAUNCH` (HIGH):** `telemetry_svc` started before `secpolpush` in `adas_12svc.ifs`.
3. **`UNTYPED_IFS_SERVICE` (HIGH):** `ota_agent` launched after `secpolpush` without `on -T <type>`.
4. **`UNDEFINED_IFS_TYPE` (ERROR):** Typo `on -T diag_hlpr_t diag_helper` (undeclared in `.secpol`).

All 4 flaws are cleanly resolved in `examples/adas_12svc_fixed.secpol` + `examples/adas_12svc_fixed.ifs` (exit `0`, 0 findings).

---

## Live QNX 8.0 C Demo & QEMU Harness (`qnx_demo/`, `harness/`)

On a machine with QNX SDP 8.0 (`qcc`, `secpolcompile`, `mkifs`) and `qemu-system-x86_64`:

```bash
source ~/qnx800/qnxsdp-env.sh
make qemu-mutants
```

- `qnx_demo/can_server.c`: `on -T can_hal_t` resource manager calling `name_attach(NULL, "can_ctrl", 0)` and replying `"CAN_CTRL_GRANTED"`.
- `qnx_demo/diag_helper.c`: calls `secpol_transition_type(NULL, "can_hal_t", 0)` then `name_open("can_ctrl", 0)`.
- `qnx_demo/ivi_exploit.c`: proves direct `name_open("can_ctrl", 0)` is denied, then executes Hop 1 via `secpol_posix_spawnattr_settypeid(..., "diag_helper_t", 0)` + `posix_spawn("/proc/boot/diag_helper")`.
- `harness/verify_offline.py`: compares static predictions against real `evidence/qemu_logs/*.log` captures (or synthetic fixtures with `--fixtures`).
