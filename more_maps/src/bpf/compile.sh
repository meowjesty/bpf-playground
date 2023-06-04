#!/bin/bash

clang -target bpf -D__TARGET_ARCH_x86 -I/usr/include/$(uname -m)-linux-gnu -Wall -O2 -g -c more_maps.bpf.c -o more_maps.o

readelf -S more_maps.o | grep BTF

bpftool btf dump file more_maps.o