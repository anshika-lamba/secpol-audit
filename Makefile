PYTHON ?= python3
PYTEST ?= pytest
MUTANTS := M0_clean M1_no_connect M2_untyped_server M3_2hop_escalate M3_fixed
SENTRY_MUTANTS := M0_sentry_clean M3_sentry_escalate
BLAST_MUTANTS := M0_blast_clean M3_blast_escalate

.PHONY: test demo-report verify-offline verify-fixtures qemu-mutants sentry-binaries sentry-images qemu-sentry blast-binaries blast-images qemu-blast secpolgen-image qemu-secpolgen clean

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
		bash harness/run_qemu.sh qnx_demo/build/$$m.ifs evidence/qemu_logs/$$m.log 45 || exit $$?; \
	done
	$(PYTHON) harness/verify_offline.py

sentry-binaries:
	$(MAKE) -C qnx_demo sentry-binaries

sentry-images:
	$(MAKE) -C qnx_demo sentry-images

qemu-sentry:
	$(MAKE) -C qnx_demo sentry-binaries sentry-images
	@mkdir -p evidence/qemu_logs
	@for m in $(SENTRY_MUTANTS); do \
		echo "=== Running QEMU x86_64 TCG for sentry mutant $$m ==="; \
		bash harness/run_qemu.sh --require-post-marker "SECPOLEV_STATS:" qnx_demo/build/$$m.ifs evidence/qemu_logs/$$m.log 60 || exit $$?; \
	done

blast-binaries:
	$(MAKE) -C qnx_demo blast-binaries

blast-images:
	$(MAKE) -C qnx_demo blast-images

qemu-blast:
	$(MAKE) -C qnx_demo blast-binaries blast-images
	@mkdir -p qnx_demo/build/blast
	@for m in $(BLAST_MUTANTS); do \
		echo "=== Running QEMU x86_64 TCG for blast verification $$m ==="; \
		bash harness/run_qemu.sh --require-post-marker "SECPOLEV_STATS:" qnx_demo/build/$$m.ifs qnx_demo/build/blast/$$m.log 60 || exit $$?; \
	done

secpolgen-image:
	$(MAKE) -C qnx_demo secpolgen-image

qemu-secpolgen:
	$(MAKE) -C qnx_demo secpolgen-image
	@mkdir -p qnx_demo/build/secpolgen
	bash harness/run_qemu.sh qnx_demo/build/secpolgen_capture.ifs qnx_demo/build/secpolgen/secpolgen_capture.log 60
	$(PYTHON) harness/extract_secpolgen.py qnx_demo/build/secpolgen/secpolgen_capture.log --out-dir qnx_demo/build/secpolgen

clean:
	$(MAKE) -C qnx_demo clean
	rm -rf /tmp/secpol-audit-demo
