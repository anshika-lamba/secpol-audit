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
MUTANTS       := M0_clean M1_no_connect M2_untyped_server M3_2hop_escalate M3_fixed

.PHONY: all binaries images clean check-sdp

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

# Compile mutant policies
$(BUILD_DIR)/M0_clean.secpol.bin: mutants/M0_clean.secpol | $(BUILD_DIR)
	$(SECPOLCOMPILE) -o $@ $<

$(BUILD_DIR)/M1_no_connect.secpol.bin: mutants/M1_no_connect.secpol | $(BUILD_DIR)
	$(SECPOLCOMPILE) -o $@ $<

$(BUILD_DIR)/M3_2hop_escalate.secpol.bin: mutants/M3_2hop_escalate.secpol | $(BUILD_DIR)
	$(SECPOLCOMPILE) -o $@ $<

$(BUILD_DIR)/M3_fixed.secpol.bin: mutants/M3_fixed.secpol | $(BUILD_DIR)
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

images: check-sdp $(addprefix $(BUILD_DIR)/,$(addsuffix .ifs,$(MUTANTS)))

clean:
	rm -rf $(BUILD_DIR)
