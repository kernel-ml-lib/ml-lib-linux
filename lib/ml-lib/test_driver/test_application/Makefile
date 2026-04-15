# SPDX-License-Identifier: GPL-2.0
#
# Makefile for ML library test application with BPF programs
#

CLANG		?= clang
BPFTOOL		?= bpftool
CC		?= gcc

# Kernel source tree (for vmlinux.h generation)
KERNEL_SRC	?= $(abspath ../../../..)

# Architecture for BPF target
ARCH		:= $(shell uname -m | sed 's/x86_64/x86/' \
			| sed 's/aarch64/arm64/')

# libbpf headers and library
LIBBPF_CFLAGS	:= $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LDFLAGS	:= $(shell pkg-config --libs libbpf 2>/dev/null || echo "-lbpf -lelf -lz")

CFLAGS		:= -g -Wall -O2 $(LIBBPF_CFLAGS) -idirafter $(KERNEL_SRC)/include/uapi
LDFLAGS		:= $(LIBBPF_LDFLAGS)

BPF_CFLAGS	:= -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		   -I$(KERNEL_SRC)/include/uapi

APP		:= test_ml_lib_misc_dev
BPF_PROGS	:= ml_lib_monitor.bpf.o ml_lib_control.bpf.o
BPF_SKELS	:= ml_lib_monitor.skel.h ml_lib_control.skel.h

.PHONY: all clean

all: $(APP)

# Generate vmlinux.h from the running kernel's BTF
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Compile BPF programs
# Detect whether vmlinux.h already contains ml_lib trace structs (happens when
# the running kernel has ml_lib compiled in).  If so, pass -DML_LIB_TYPES_IN_VMLINUX
# so ml_lib_trace_types.h skips its struct definitions and avoids a redefinition error.
%.bpf.o: %.bpf.c vmlinux.h
	$(eval _ML_LIB_IN_VMLINUX := $(shell grep -c 'trace_event_raw_ml_lib_model_registered' vmlinux.h 2>/dev/null || echo 0))
	$(CLANG) $(BPF_CFLAGS) $(if $(filter-out 0,$(_ML_LIB_IN_VMLINUX)),-DML_LIB_TYPES_IN_VMLINUX) -I. -c $< -o $@

# Generate BPF skeletons
%.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# Compile and link userspace application
$(APP): test_ml_lib_misc_dev.c $(BPF_SKELS) ml_lib_misc_dev_ioctl.h
	$(CC) $(CFLAGS) -I. $< -o $@ $(LDFLAGS)

clean:
	rm -f $(APP) $(BPF_PROGS) $(BPF_SKELS) vmlinux.h
