PYTHON ?= python3
PYTEST ?= pytest
MUTANTS := M0_clean M1_no_connect M2_untyped_server M3_2hop_escalate M3_fixed

.PHONY: test demo-report verify-offline verify-fixtures qemu-mutants clean

test:
	$(PYTEST) -v

demo-report:
	@mkdir -p /tmp/secpol-audit-demo
	$(PYTHON) -m secpol_audit paths examples/adas_12svc.secpol \
		--ifs examples/adas_12svc.ifs \
		--html /tmp/secpol-audit-demo/adas_report.html || true
	@echo "Demo HTML workbench generated at /tmp/secpol-audit-demo/adas_report.html"

verify-offline:
	$(PYTHON) harness/verify_offline.py

verify-fixtures:
	$(PYTHON) harness/verify_offline.py --fixtures

qemu-mutants:
	$(MAKE) -C qnx_demo all
	@mkdir -p evidence/qemu_logs
	@for m in $(MUTANTS); do \
		echo "=== Running QEMU x86_64 TCG for mutant $$m ==="; \
		bash harness/run_qemu.sh qnx_demo/build/$$m.ifs evidence/qemu_logs/$$m.log 45; \
	done
	$(PYTHON) harness/verify_offline.py

clean:
	$(MAKE) -C qnx_demo clean
	rm -rf /tmp/secpol-audit-demo
