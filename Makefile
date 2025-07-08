CC := clang
BUILD_DIR := build
SRC_DIR := src
SCRIPTS_DIR := scripts
TESTS_DIR := tests
SKEL_DIR := $(BUILD_DIR)/skel
CFLAGS := -g -Wall -Wextra

STRIP ?= 1

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
             | sed 's/arm./arm/' \
             | sed 's/aarch64/arm64/' \
             | sed 's/ppc64le/powerpc/' \
             | sed 's/mips./mips/' \
             | sed 's/riscv64/riscv/' \
             | sed 's/loongarch64/loongarch/')

_dummy := $(shell mkdir -p $(BUILD_DIR) $(SKEL_DIR))

all: uprobe test

clean:
	rm -r $(BUILD_DIR)

INCLUDES := -I$(SKEL_DIR) -I$(SRC_DIR)


bname = $(notdir $(basename $<))

test: $(TESTS_DIR)/test_program.c
	@ mkdir -p $(BUILD_DIR)/$(bname)
	gcc $(CFLAGS) -Wl,-Map="$(BUILD_DIR)/$(bname)/output.map" -Wl,--strip-debug $< -o $(BUILD_DIR)/$(bname)/$@
	nm -U -v -S --demangle $(BUILD_DIR)/$(bname)/$@ > $(BUILD_DIR)/$(bname)/$@.syms
	@if [ $(STRIP) = "1" ]; then strip $(BUILD_DIR)/$(bname)/$@; fi
	python3 $(SCRIPTS_DIR)/symbols.py $(BUILD_DIR)/$(bname)/$@.syms $(BUILD_DIR)/$(bname)/$@ $(BUILD_DIR)/$(bname)/symbols.json

uprobe: $(SRC_DIR)/uprobe.c $(SKEL_DIR)/uprobe.skel.h
	gcc $(CFLAGS) $(SRC_DIR)/uprobe.c $(SRC_DIR)/symbols.c $(INCLUDES) -ljson-c -lbpf -lelf -lz -o $(BUILD_DIR)/$@

$(BUILD_DIR)/uprobe.bpf.o: $(SRC_DIR)/uprobe.bpf.c
	$(CC) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -c $< -o $(BUILD_DIR)/uprobe.bpf.o

$(SKEL_DIR)/uprobe.skel.h: $(BUILD_DIR)/uprobe.bpf.o
	bpftool gen skeleton $< > $@
