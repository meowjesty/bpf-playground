/// Instead of this `lix/bpf.h` include, we could use a `vmlinux.h`, which is a
/// file that contains the BTF of the current (running) kernel.
///
/// If you run `bpftool btf list` (might require `sudo`) the first resutl should
/// be `vmlinux`:
/// ```sh
/// 1: name [vmlinux]  size 5081050B
/// ...
/// 182: name [snd_hrtimer]  size 2373B
/// 183: name [snd_seq_dummy]  size 3388B
/// ```
///
/// You can inspect the BTF information with `btf dump id {id}`.
///
/// To generate the `vmlinux.h` header:
///
/// `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`
///
/// Check out https://github.com/aquasecurity/btfhub-archive/ for various BTF
/// files.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/// Need a GPL compatible license, otherwise we get an error:
/// `cannot call GPL-restricted function from non-GPL compatible program`
///
/// I expect this is required for some functions, but not others.
SEC("license")
char LICENSE[] = "Dual BSD/GPL";

/// You must include the "linux/bpf.h" header, which contains a bunch of the
/// functions plus type declarations.
///
/// Without this file, you get a bunch of errors of
/// `unknown type name __u32 static long (*bpf_tail_call) (...)` and other
/// missing type definitions like these.
SEC("tracepoint/syscalls/sys_enter_execve")
int hello(void *ctx) {
  char msg[] = "Hello, World!";

  // To see these logs:
  // `sudo cat /sys/kernel/debug/tracing/trace_pipe`
  bpf_printk("hello(): %s\n", msg);
  return 0;
}
