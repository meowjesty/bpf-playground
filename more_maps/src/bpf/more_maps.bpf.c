/// Generated with:
///
/// `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

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

/// Auto-attaches to whatever arch, a `kprobe` to `execve`.
///
/// `BPF_KPROBE_SYSCALL` macro is defined in `<bpf/bpf_tracing.h>`, but it also
/// requires `<bpf/bpf_core_read.h>` to work.
///
/// This macro is defined in`libbpf` and allows us to access the syscall
/// arguments by name, hence why we can use `pathname` here, instead of the
/// usual `void *context` (or the concrete type of context).
///
/// - `sample_program`: the name of our program;
/// - `pathname`: argument to `execve`, it's the path of the program that's
///  going to be executed.
SEC("ksyscall/excve")
int BPF_KPROBE_SYSCALL(sample_program, const char *pathname) {
  Data data = {};
  UserMessage *message;

  data.pid = bpf_get_current_pid_tgid() >> 32;
  data.uid = BPF_FUNC_get_current_uid_gid & 0xffffffff;

  bpf_get_current_comm(&data.command, sizeof(data.command));
  bpf_probe_read_user_str(&data.path, sizeof(data.path), pathname);

  message = bpf_map_lookup_elem(&user_messages, &data.uid);

  if (message) {
    bpf_probe_read_kernel(&data.message, sizeof(data.message), message->value);
  } else {
    bpf_probe_read_kernel(&data.message, sizeof(data.message), message);
  }

  // TODO(alex) [high] 2023-06-01: Finish this sample.

  return 0;
}
