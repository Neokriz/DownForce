# Makefile
BPF_CLANG ?= clang-15
BPF_LLVM_STRIP ?= llvm-strip
CC ?= gcc

VMLINUX_H = vmlinux.h
BPF_OBJ = io_lat.bpf.o
SKEL_H = io_lat.skel.h
USER_BIN = io_lat

CFLAGS_USER = -O2 -g -Wall
CFLAGS_BPF  = -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86

LIBBPF_CFLAGS = $(shell pkg-config --cflags libbpf)
LIBBPF_LDLIBS = $(shell pkg-config --libs libbpf)

.PHONY: all clean

all: $(USER_BIN)

$(VMLINUX_H):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

$(BPF_OBJ): io_lat.bpf.c $(VMLINUX_H)
	$(BPF_CLANG) $(CFLAGS_BPF) -c $< -o $@
	$(BPF_LLVM_STRIP) -g $@

$(SKEL_H): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

$(USER_BIN): io_lat.c $(SKEL_H)
	$(CC) $(CFLAGS_USER) $(LIBBPF_CFLAGS) -I. $< -o $@ $(LIBBPF_LDLIBS)

clean:
	rm -f $(VMLINUX_H) $(BPF_OBJ) $(SKEL_H) $(USER_BIN)

