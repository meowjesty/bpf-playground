#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/// Need a GPL compatible license, otherwise we get an error:
/// `cannot call GPL-restricted function from non-GPL compatible program`
///
/// I expect this is required for some functions, but not others.
SEC("license") 
char LICENSE[] = "Dual BSD/GPL";

/// You must include the "linux/bpf.h" header, which contains a bunch of the functions plus type 
/// declarations.
///
/// Without this file, you get a bunch of errors of 
/// `unknown type name __u32 static long (*bpf_tail_call) (...)` and other missing type definitions
/// like these.
SEC("tracepoint/syscalls/sys_enter_execve")
int hello(void *ctx) {
  char msg[] = "Hello, World!";

  // To see these logs:
  // `sudo cat /sys/kernel/debug/tracing/trace_pipe`
  bpf_printk("hello(): %s\n", msg);
  return 0;
}
