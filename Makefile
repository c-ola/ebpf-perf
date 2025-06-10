CC := clang
BUILD_DIR := build
CFLAGS := -g -Wall

all: uprobe test
	mkdir -p $(BUILD_DIR)

clean:
	rm -r $(BUILD_DIR)

INCLUDES := -I$(BUILD_DIR)

test: test_program.c
	gcc $(CFLAGS) -Wl,-Map="$(BUILD_DIR)/output.map" test_program.c -o $(BUILD_DIR)/$@
	python3 ebpf_perf.py $(BUILD_DIR)/output.map $(BUILD_DIR)/$@ $(BUILD_DIR)/symbols.json

uprobe: $(BUILD_DIR)/uprobe.bpf.o uprobe.c $(BUILD_DIR)/uprobe.skel.h
	gcc $(CFLAGS) uprobe.c symbols.c $(INCLUDES) -ljson-c -lbpf -lelf -lz -o $(BUILD_DIR)/$@

$(BUILD_DIR)/uprobe.bpf.o: uprobe.bpf.c
	$(CC) -g -O2 -target bpf -D__TARGET_ARCH_x86 -c uprobe.bpf.c -o $(BUILD_DIR)/uprobe.bpf.o

$(BUILD_DIR)/uprobe.skel.h: $(BUILD_DIR)/uprobe.bpf.o
	bpftool gen skeleton $< > $@
