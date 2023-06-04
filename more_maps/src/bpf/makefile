more_maps_config.bpf.o: %o: %.c
	clang \
		-target bpf \
		-D__TARGET_ARCH_$(ARCH) \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-Wall \
		-O2 -g \
		-c $< -o $@
	llvm-strip -g $@
