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
	gcc $(CFLAGS) -Wl,-Map="$(BUILD_DIR)/output.map" $< -o $(BUILD_DIR)/$@
	strip $(BUILD_DIR)/$@
	python3 $(SRC_DIR)/ebpf_perf.py $(BUILD_DIR)/output.map $(BUILD_DIR)/$@ $(BUILD_DIR)/symbols.json

uprobe: $(SRC_DIR)/uprobe.c $(SKEL_DIR)/uprobe.skel.h
	gcc $(CFLAGS) $(SRC_DIR)/uprobe.c $(SRC_DIR)/symbols.c $(INCLUDES) -ljson-c -lbpf -lelf -lz -o $(BUILD_DIR)/$@

$(BUILD_DIR)/uprobe.bpf.o: $(SRC_DIR)/uprobe.bpf.c
	$(CC) -g -O2 -target bpf -D__TARGET_ARCH_x86 -c $< -o $(BUILD_DIR)/uprobe.bpf.o

$(SKEL_DIR)/uprobe.skel.h: $(BUILD_DIR)/uprobe.bpf.o
	bpftool gen skeleton $< > $@
