# From QNX Security Policy to Runtime Proof: Locking Down and Auditing a Resource Manager

**Estimated time:** 30–45 minutes  
**Learning outcome:** Build a minimal QNX 8.0 resource manager, lock down its mount point with `secpol_resmgr_attach()`, prove both permitted (`ALLOW`, `errno=0`) and policy-denied (`EACCES`, `errno=13`) attachment, capture PID-attributed `libsecpolev` kernel telemetry (`dropped=0`), audit a two-hop privilege-escalation chain (`ivi_ui_t -> diag_helper_t -> can_hal_t`), remove one rule, reboot, and verify the attack is blocked.

---

## Step 0 — Preflight

Check that QNX SDP 8.0 (`qcc`, `secpolcompile`, `mkifs`) and QEMU `x86_64` are available:

```bash
source ~/qnx800/qnxsdp-env.sh
command -v qcc secpolcompile mkifs qemu-system-x86_64
```

You can also run a 5-minute offline replay on committed QNX 8.0 logs:

```bash
python3 harness/verify_offline.py
```

> **Note:** Offline replay verifies committed artifacts in `evidence/qemu_logs/` and does **not** replace running QNX 8.0 yourself.

---

## Step 1 — Build

Compile `codelab/starter/minimal_resmgr.c` with `qcc`:

```bash
make -C codelab/starter minimal_resmgr
```

On a host without QNX SDP 8.0, you can syntax-check with:

```bash
gcc -Wall -Wextra -Werror -O2 codelab/starter/minimal_resmgr.c -o /tmp/minimal_resmgr && /tmp/minimal_resmgr
```

---

## Step 2 — Policy

Inspect and compile `codelab/starter/vulnerable.secpol` into `secpol.bin`:

```bash
secpolcompile -o codelab/starter/vulnerable.secpol.bin codelab/starter/vulnerable.secpol
```

Key primitives:
- `type`: declares a security domain (e.g., `ivi_ui_t`, `diag_helper_t`, `can_hal_t`).
- `allow_attach`: authorizes a type to attach a pathname (e.g., `/dev/secpol_probe_allow`).
- `pathspace`: ability required to register paths in the QNX pathname space.
- `settypeid`: allows a process to spawn a child in another security type.
- `channel_connect`: allows IPC message passing between types.

---

## Step 3 — Enforce

`qnx_demo/kprobe.c` exercises `secpol_resmgr_attach()` on isolated, previously unused paths:
- **Positive (`audit_reader_t` -> `/dev/secpol_probe_allow`):** has `pathspace` + `allow_attach`.
- **Negative (`ivi_ui_t` -> `/dev/secpol_probe_deny_ivi_ui_t`):** has `noinherit pathspace` but NO `allow_attach`.

Verbatim output from `evidence/blast/M3_blast_escalate.log`:

```text
KPROBE_JSON:{"origin":"audit_reader_t","op":"allow_attach","target":"/dev/secpol_probe_allow","path":"/dev/secpol_probe_allow","pid":40964,"ret":0,"outcome":"ALLOW","errno":0,"errno_name":"OK"}
KPROBE_JSON:{"origin":"ivi_ui_t","op":"allow_attach","target":"/dev/secpol_probe_deny_ivi_ui_t","path":"/dev/secpol_probe_deny_ivi_ui_t","pid":16388,"ret":-1,"outcome":"DENY","errno":13,"errno_name":"EACCES"}
```

**Knowledge check:** Why does `errno=13` (`EACCES`) differ from `errno=1` (`EPERM`) and `errno=17` (`EEXIST`)?
- `EACCES` (`13`): Security policy denied `allow_attach` (`DENY_POLICY`).
- `EPERM` (`1`): Missing `pathspace` ability (`DENY_ABILITY`).
- `EEXIST` (`17`): Pathname already occupied (`INCONCLUSIVE` / `PATH_COLLISION`, never `DENY`).

---

## Step 4 — Observe

Run `secpol_sentry` (`libsecpolev` via `secpolev_wait_event()` + `secpolev_get_pid()`) in an independent verification boot (no `secpolgenerate` active, so `dropped=0` is meaningful):

```bash
make -C qnx_demo blast-images
make qemu-blast
```

Verbatim stats from `evidence/qemu_logs/M3_sentry_escalate.log`:

```text
SECPOLEV_STATS: ok=327 denied=2 dropped=0
```

---

## Step 5 — Audit

Run `secpol-audit check` and `secpol-audit blast` on the vulnerable policy + serial log:

```bash
secpol-audit check codelab/starter/vulnerable.secpol
secpol-audit blast qnx_demo/mutants/M3_blast_escalate.secpol \
  --ifs qnx_demo/build_blast.ifs.in \
  --log evidence/blast/M3_blast_escalate.log
```

`secpol-audit` separates three evidence states:
- `STATIC_ONLY`: predicted from `.secpol`, not probed on target.
- `SYSCALL_ONLY_UNOBSERVABLE`: probed by `kprobe.c`, no `libsecpolev` witness.
- `OBSERVED_AND_CORRELATED`: matched 1-to-1 by PID to `SECPOLEV_JSON:`.

Verbatim two-hop lineage from `evidence/qemu_logs/M3_sentry_escalate.log`:

```text
HOP1_SPAWN=OK child_pid=20485
LINEAGE_HOP1:{"parent_pid":16388,"child_pid":20485,"origin_type":"ivi_ui_t","requested_target_type":"diag_helper_t","outcome":"OK","errno":0}
HOP2_SPAWN=OK child_pid=20486
LINEAGE_HOP2:{"parent_pid":20485,"child_pid":20486,"origin_type":"diag_helper_t","requested_target_type":"can_hal_t","outcome":"OK","errno":0}
HOP2_RESULT=GRANTED coid=1073741825
```

Explore the interactive Before/After Blast Explorer at [../index.html](../index.html).

---

## Step 6 — Remediate

Remove the unsafe `settypeid:diag_helper_t` rule (as in `codelab/starter/fixed.secpol`), recompile `secpol.bin` + IFS, and reboot QEMU:

```bash
secpolcompile -o codelab/starter/fixed.secpol.bin codelab/starter/fixed.secpol
```

---

## Step 7 — Verify & Hands-On Challenge

Under the fixed policy (`M0`), the identical attack is blocked at Hop 1 (`evidence/qemu_logs/M0_sentry_clean.log`):

```text
DIRECT_RESULT=DENIED errno=1 (Operation not permitted)
HOP1_SPAWN=DENIED errno=1 (Operation not permitted)
LINEAGE_HOP1:{"parent_pid":16388,"child_pid":-1,"origin_type":"ivi_ui_t","requested_target_type":"diag_helper_t","outcome":"DENIED","errno":1}
SECPOLEV_STATS: ok=278 denied=3 dropped=0
```

| State | `ivi_ui_t -> diag_helper_t` | `diag_helper_t -> can_hal_t` | `HOP2_RESULT` |
| :--- | :--- | :--- | :--- |
| **Before (`M3`)** | `OK` (`pid=16388 -> 20485`) | `OK` (`pid=20485 -> 20486`) | `GRANTED` |
| **After (`M0`)** | `DENIED` (`errno=1`, `child_pid=-1`) | Not reached | Blocked |

### Hands-On Challenge
1. Run `secpol-audit check codelab/starter/challenge.secpol` to find the indirect escalation chain.
2. Fix `codelab/starter/challenge.secpol` and re-run `secpol-audit check` until it exits `0`.
3. Compare your fix against `codelab/starter/challenge_solution.secpol`.

---

## Troubleshooting

- **`EACCES` vs. `EPERM` vs. `EEXIST`:** `EACCES` (`13`) = policy denied `allow_attach`; `EPERM` (`1`) = missing `pathspace`; `EEXIST` (`17`) = path already occupied (`INCONCLUSIVE`).
- **Missing `SECPOL_TYPE_NAME` flag:** `secpol_posix_spawnattr_settypeid()` requires `SECPOL_TYPE_NAME` when passing a string type name.
- **`dropped=0` with `secpolgenerate`:** `secpolgenerate` saturates trace buffers; `dropped=0` is only meaningful in independent verification boots without `secpolgenerate` active.
- **`libsecpolev` single-consumer limit:** Only one `secpol_sentry` instance can consume `/dev/name/local/_tracelog` at a time.
- **QEMU TCG idle shutdown:** QNX does not power off QEMU after `=== SECPOL_AUDIT_DONE ===`; `harness/run_qemu.sh` treats `timeout` exit `124` as clean completion when `=== SECPOL_AUDIT_DONE ===` is present in the log.
