# QNX Neutrino 8.0 Cross-Compilation & Mutant Image Build Makefile
# Requires QNX SDP 8.0 environment sourced (`source ~/qnx800/qnxsdp-env.sh`).

CC            := qcc
TARGET_FLAGS  ?= -Vgcc_ntox86_64
CFLAGS        ?= -Wall -Wextra -O2
LDFLAGS       ?= -lsecpol
SECPOLCOMPILE ?= secpolcompile
MKIFS         ?= mkifs

BUILD_DIR     := build
BINARIES      := $(BUILD_DIR)/can_server $(BUILD_DIR)/diag_helper $(BUILD_DIR)/ivi_exploit
SENTRY_BINS   := $(BINARIES) $(BUILD_DIR)/secpol_sentry
BLAST_BINS    := $(BUILD_DIR)/can_server $(BUILD_DIR)/secpol_sentry $(BUILD_DIR)/kprobe
MUTANTS       := M0_clean M1_no_connect M2_untyped_server M3_2hop_escalate M3_fixed
SENTRY_MUTANTS := M0_sentry_clean M3_sentry_escalate
BLAST_MUTANTS  := M0_blast_clean M3_blast_escalate

.PHONY: all binaries images sentry-binaries sentry-images blast-binaries blast-images secpolgen-image clean check-sdp

all: binaries images

check-sdp:
	@command -v $(CC) >/dev/null 2>&1 || { echo "ERROR: '$(CC)' not found. Source your QNX SDP 8.0 qnxsdp-env.sh first."; exit 1; }
	@command -v $(SECPOLCOMPILE) >/dev/null 2>&1 || { echo "ERROR: '$(SECPOLCOMPILE)' not found on PATH."; exit 1; }
	@command -v $(MKIFS) >/dev/null 2>&1 || { echo "ERROR: '$(MKIFS)' not found on PATH."; exit 1; }

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

binaries: check-sdp $(BINARIES)

$(BUILD_DIR)/can_server: can_server.c | $(BUILD_DIR)
	$(CC) $(TARGET_FLAGS) $(CFLAGS) -o $@ $<

$(BUILD_DIR)/diag_helper: diag_helper.c | $(BUILD_DIR)
	$(CC) $(TARGET_FLAGS) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BUILD_DIR)/ivi_exploit: ivi_exploit.c | $(BUILD_DIR)
	$(CC) $(TARGET_FLAGS) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BUILD_DIR)/secpol_sentry: secpol_sentry.c | $(BUILD_DIR)
	$(CC) $(TARGET_FLAGS) $(CFLAGS) -o $@ $< -lsecpolev $(LDFLAGS)

$(BUILD_DIR)/dump_file: dump_file.c | $(BUILD_DIR)
	$(CC) $(TARGET_FLAGS) $(CFLAGS) -o $@ $<

$(BUILD_DIR)/kprobe: kprobe.c | $(BUILD_DIR)
	$(CC) $(TARGET_FLAGS) $(CFLAGS) -o $@ $< $(LDFLAGS)

sentry-binaries: check-sdp $(SENTRY_BINS)

blast-binaries: check-sdp $(BLAST_BINS)

# Compile mutant policies
$(BUILD_DIR)/M0_clean.secpol.bin: mutants/M0_clean.secpol | $(BUILD_DIR)
	$(SECPOLCOMPILE) -o $@ $<

$(BUILD_DIR)/M1_no_connect.secpol.bin: mutants/M1_no_connect.secpol | $(BUILD_DIR)
	$(SECPOLCOMPILE) -o $@ $<

$(BUILD_DIR)/M3_2hop_escalate.secpol.bin: mutants/M3_2hop_escalate.secpol | $(BUILD_DIR)
	$(SECPOLCOMPILE) -o $@ $<

$(BUILD_DIR)/M3_fixed.secpol.bin: mutants/M3_fixed.secpol | $(BUILD_DIR)
	$(SECPOLCOMPILE) -o $@ $<

$(BUILD_DIR)/M0_sentry_clean.secpol.bin: mutants/M0_sentry_clean.secpol | $(BUILD_DIR)
	$(SECPOLCOMPILE) -o $@ $<

$(BUILD_DIR)/M3_sentry_escalate.secpol.bin: mutants/M3_sentry_escalate.secpol | $(BUILD_DIR)
	$(SECPOLCOMPILE) -o $@ $<

# Generate parameterized IFS images for QEMU x86_64 TCG
$(BUILD_DIR)/M0_clean.ifs: build.ifs.in $(BUILD_DIR)/M0_clean.secpol.bin $(BINARIES)
	sed -e 's|@SECPOL_BIN@|$(BUILD_DIR)/M0_clean.secpol.bin|g' \
	    -e 's|@CAN_SERVER_CMD@|on -T can_hal_t -u 23:23 /proc/boot/can_server \&|g' \
	    -e 's|@MUTANT_NAME@|M0_clean|g' $< > $(BUILD_DIR)/M0_clean.build
	$(MKIFS) $(BUILD_DIR)/M0_clean.build $@

$(BUILD_DIR)/M1_no_connect.ifs: build.ifs.in $(BUILD_DIR)/M1_no_connect.secpol.bin $(BINARIES)
	sed -e 's|@SECPOL_BIN@|$(BUILD_DIR)/M1_no_connect.secpol.bin|g' \
	    -e 's|@CAN_SERVER_CMD@|on -T can_hal_t -u 23:23 /proc/boot/can_server \&|g' \
	    -e 's|@MUTANT_NAME@|M1_no_connect|g' $< > $(BUILD_DIR)/M1_no_connect.build
	$(MKIFS) $(BUILD_DIR)/M1_no_connect.build $@

$(BUILD_DIR)/M2_untyped_server.ifs: mutants/M2_untyped_server.ifs $(BUILD_DIR)/M0_clean.secpol.bin $(BINARIES)
	cp mutants/M2_untyped_server.ifs $(BUILD_DIR)/M2_untyped_server.build
	$(MKIFS) $(BUILD_DIR)/M2_untyped_server.build $@

$(BUILD_DIR)/M3_2hop_escalate.ifs: build.ifs.in $(BUILD_DIR)/M3_2hop_escalate.secpol.bin $(BINARIES)
	sed -e 's|@SECPOL_BIN@|$(BUILD_DIR)/M3_2hop_escalate.secpol.bin|g' \
	    -e 's|@CAN_SERVER_CMD@|on -T can_hal_t -u 23:23 /proc/boot/can_server \&|g' \
	    -e 's|@MUTANT_NAME@|M3_2hop_escalate|g' $< > $(BUILD_DIR)/M3_2hop_escalate.build
	$(MKIFS) $(BUILD_DIR)/M3_2hop_escalate.build $@

$(BUILD_DIR)/M3_fixed.ifs: build.ifs.in $(BUILD_DIR)/M3_fixed.secpol.bin $(BINARIES)
	sed -e 's|@SECPOL_BIN@|$(BUILD_DIR)/M3_fixed.secpol.bin|g' \
	    -e 's|@CAN_SERVER_CMD@|on -T can_hal_t -u 23:23 /proc/boot/can_server \&|g' \
	    -e 's|@MUTANT_NAME@|M3_fixed|g' $< > $(BUILD_DIR)/M3_fixed.build
	$(MKIFS) $(BUILD_DIR)/M3_fixed.build $@

$(BUILD_DIR)/M0_sentry_clean.ifs: build_sentry.ifs.in $(BUILD_DIR)/M0_sentry_clean.secpol.bin $(SENTRY_BINS)
	sed -e 's|@SECPOL_BIN@|$(BUILD_DIR)/M0_sentry_clean.secpol.bin|g' \
	    -e 's|@MUTANT_NAME@|M0_sentry_clean|g' $< > $(BUILD_DIR)/M0_sentry_clean.build
	$(MKIFS) $(BUILD_DIR)/M0_sentry_clean.build $@

$(BUILD_DIR)/M3_sentry_escalate.ifs: build_sentry.ifs.in $(BUILD_DIR)/M3_sentry_escalate.secpol.bin $(SENTRY_BINS)
	sed -e 's|@SECPOL_BIN@|$(BUILD_DIR)/M3_sentry_escalate.secpol.bin|g' \
	    -e 's|@MUTANT_NAME@|M3_sentry_escalate|g' $< > $(BUILD_DIR)/M3_sentry_escalate.build
	$(MKIFS) $(BUILD_DIR)/M3_sentry_escalate.build $@

$(BUILD_DIR)/M0_blast_clean.secpol.bin: mutants/M0_blast_clean.secpol | $(BUILD_DIR)
	$(SECPOLCOMPILE) -o $@ $<

$(BUILD_DIR)/M3_blast_escalate.secpol.bin: mutants/M3_blast_escalate.secpol | $(BUILD_DIR)
	$(SECPOLCOMPILE) -o $@ $<

$(BUILD_DIR)/M0_blast_clean.ifs: build_blast.ifs.in $(BUILD_DIR)/M0_blast_clean.secpol.bin $(BLAST_BINS)
	sed -e 's|@SECPOL_BIN@|$(BUILD_DIR)/M0_blast_clean.secpol.bin|g' \
	    -e 's|@MUTANT_NAME@|M0_blast_clean|g' $< > $(BUILD_DIR)/M0_blast_clean.build
	$(MKIFS) $(BUILD_DIR)/M0_blast_clean.build $@

$(BUILD_DIR)/M3_blast_escalate.ifs: build_blast.ifs.in $(BUILD_DIR)/M3_blast_escalate.secpol.bin $(BLAST_BINS)
	sed -e 's|@SECPOL_BIN@|$(BUILD_DIR)/M3_blast_escalate.secpol.bin|g' \
	    -e 's|@MUTANT_NAME@|M3_blast_escalate|g' $< > $(BUILD_DIR)/M3_blast_escalate.build
	$(MKIFS) $(BUILD_DIR)/M3_blast_escalate.build $@

images: check-sdp $(addprefix $(BUILD_DIR)/,$(addsuffix .ifs,$(MUTANTS)))

sentry-images: check-sdp $(addprefix $(BUILD_DIR)/,$(addsuffix .ifs,$(SENTRY_MUTANTS)))

blast-images: check-sdp $(addprefix $(BUILD_DIR)/,$(addsuffix .ifs,$(BLAST_MUTANTS)))

$(BUILD_DIR)/secpolgen_capture.ifs: secpolgen_capture.ifs $(BUILD_DIR)/can_server $(BUILD_DIR)/dump_file
	$(MKIFS) $< $@

secpolgen-image: check-sdp $(BUILD_DIR)/secpolgen_capture.ifs

clean:
	rm -rf $(BUILD_DIR)
