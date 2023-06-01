/// Generated with:
///
/// `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/// `SEC` applies to global items.
SEC("license")
char LICENSE[] = "Dual BSD/GPL";

typedef struct {
  /// The example uses `BPF_MAP_TYPE_PERF_EVENT_ARRAY`, which is the older (and
  /// worse) equivalent to `BPF_MAP_TYPE_RINGBUF`.
  ///
  /// See [here](https://docs.kernel.org/bpf/ringbuf.html#id2) for reasons to
  /// avoid it.
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} Buffer;

typedef struct {
  int pid;
  int uid;
  char command[16];
  char message[16];
  char path[16];
} Data;

typedef struct {
  char value[16];
} UserMessage;

typedef struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256 * 1024);
  __type(key, u32);
  __type(value, UserMessage);
} UserMessages;

/// `SEC` are the sections in the ELF object.
///
/// These can also be used to auto-attach via `libbpf`, instead of us having to
/// do so in user code (like we did in the `hello_xdp` sample).
///
/// `SEC(kprobe/__arm64_sys_excve)` would auto-attach a `kprobe` to `execve` for
/// arm64 arch, but `libbpf` can make our lives easier (as it's been doing so
/// far) with the `k(ret)syscall` section, such as:
///
/// `SEC("ksyscall/excve")`, which does the same thing, but is arch independent.
///
/// You can look at all the possible attach points for the user arch by checking
/// `/proc/kallsyms`, which lists all the kernel symbols.
SEC(".maps")
Buffer global_buffer;

SEC(".maps")
UserMessages user_messages;
