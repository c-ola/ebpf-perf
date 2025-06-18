CC := clang
BUILD_DIR := build
SRC_DIR := src
TESTS_DIR := tests
SKEL_DIR := $(BUILD_DIR)/skel
CFLAGS := -g -Wall

_dummy := $(shell mkdir -p $(BUILD_DIR) $(SKEL_DIR))

all: uprobe test

clean:
	rm -r $(BUILD_DIR)

INCLUDES := -I$(SKEL_DIR) -I$(SRC_DIR)

test: $(TESTS_DIR)/test_program.c
	@ mkdir -p $(BUILD_DIR)/$(notdir $(basename $<))
	gcc $(CFLAGS) -Wl,-Map="$(BUILD_DIR)/$(notdir $(basename $<))/output.map" -Wl,--strip-debug $< -o $(BUILD_DIR)/$(notdir $(basename $<))/$@
	nm -U -v -S $(BUILD_DIR)/$(notdir $(basename $<))/$@ > $(BUILD_DIR)/$(notdir $(basename $<))/$@.syms
	strip $(BUILD_DIR)/$(notdir $(basename $<))/$@
	python3 $(SRC_DIR)/ebpf_perf.py $(BUILD_DIR)/$(notdir $(basename $<))/output.map $(BUILD_DIR)/$(notdir $(basename $<))/$@ $(BUILD_DIR)/$(notdir $(basename $<))/symbols.json

uprobe: $(SRC_DIR)/uprobe.c $(SKEL_DIR)/uprobe.skel.h
	gcc $(CFLAGS) $(SRC_DIR)/uprobe.c $(SRC_DIR)/symbols.c $(INCLUDES) -ljson-c -lbpf -lelf -lz -o $(BUILD_DIR)/$@

$(BUILD_DIR)/uprobe.bpf.o: $(SRC_DIR)/uprobe.bpf.c
	$(CC) -g -O2 -target bpf -D__TARGET_ARCH_x86 -c $< -o $(BUILD_DIR)/uprobe.bpf.o

$(SKEL_DIR)/uprobe.skel.h: $(BUILD_DIR)/uprobe.bpf.o
	bpftool gen skeleton $< > $@
