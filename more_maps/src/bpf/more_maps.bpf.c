//! When compiling with clang, you must use `-O2`, otherwise the bpf bytecode
//! won't pass the verifier, as lesser levels of optmization will use
//! `callx <register>` to call helper functions, and bpf doesn't support calling
//! addresses from registers!
//!
//! Generated with:
//!
//! `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`
//!
//! **Warning**:
//!
//! Be very careful when updating the system, as I just got an
//! "Error (-22) - invalid argument" that failed to create `global_buffer` due
//! to `vmlinux` version mismatch with updated kernel.
//!
//! Solving this is just a matter of re-running the `bpftool` like what's above.
//!
//! More on this here:
//! https://nakryiko.com/posts/bpf-core-reference-guide/#handling-incompatible-field-and-type-changes
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
} Buffer;

typedef struct {
  __u64 pid;
  __u64 uid;
  char command[32];
  char message[32];
  char path[32];
} Data;

typedef struct {
  char value[32];
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

const char DEFAULT_MESSAGE[32] = "Default message";

/// Auto-attaches to whatever arch, a `kprobe` to `execve`.
///
/// `BPF_KPROBE_SYSCALL` macro is defined in `<bpf/bpf_tracing.h>`, but it
/// also requires `<bpf/bpf_core_read.h>` to work.
///
/// This macro is defined in`libbpf` and allows us to access the syscall
/// arguments by name, hence why we can use `pathname` here, instead of the
/// usual `void *context` (or the concrete type of context).
///
/// - `sample_program`: the name of our program;
/// - `pathname`: argument to `execve`, it's the path of the program that's
///  going to be executed.
///
/// We're not seeing the `void *ctx` argument here, but it is accessible
/// from within the macro-ed function.
SEC("ksyscall/execve")
int BPF_KPROBE_SYSCALL(sample_program, const char *pathname) {
  Data data = {};
  UserMessage *message;

  // Some helper functions are not allowed in certain program types, an example
  // would be `bpf_get_current_pid_tgid()` that is not allowed in XDP programs,
  // but is fine here.
  //
  // The explanation for this particular case is that there is no user space
  // process/thread involved when a packet is received and the XDP hook is
  // triggered, so it makes no sense to try and get the PID of ... nothing.
  data.pid = bpf_get_current_pid_tgid() >> 32;
  data.uid = bpf_get_current_uid_gid() & 0xffffffff;

  bpf_get_current_comm(&data.command, sizeof(data.command));

  // Copies `pathname` string to `data.path`.
  //
  // bpf_core_read_user_str(&data.path, sizeof(data.path), pathname);
  bpf_probe_read_user_str(&data.path, sizeof(data.path), pathname);

  message = bpf_map_lookup_elem(&user_messages, &data.uid);

  if (message) {
    // Tracing programs have a somewhat restricted access to memory, and these
    // `bpf_probe_read_*` (and `bpf_probe_write_*`) are how we do pointer memory
    // access (`x = p->y`);
    //
    // libbpf provides a helper macro `bpf_core_read(dst, size, src)` that uses
    // the special clang instruction `__builtin_presever_access_index`.
    //
    // It also provides another macro `BPF_CORE_READ` which allows putting
    // multiple reads into a single line, such as:
    //
    // ```c
    // bpf_core_read(&b, 8, a->b);
    // bpf_core_read(&c, 8, b->c);
    // bpf_core_read(&d, 8, c->d);
    // ```
    //
    // becomes:
    //
    // ```c
    // d = BPF_CORE_READ(a, b, c, d);
    // ```
    //
    // bpf_core_read(&data.message, sizeof(data.message), message->value);
    bpf_probe_read_kernel(&data.message, sizeof(data.message), message->value);
  } else {
    // bpf_core_read(&data.message, sizeof(data.message), message);
    bpf_probe_read_kernel(&data.message, sizeof(data.message), message);
  }

  bpf_ringbuf_output(&global_buffer, &data, sizeof(data), 0);

  return 0;
}
