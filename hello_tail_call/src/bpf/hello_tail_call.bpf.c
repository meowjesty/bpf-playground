/// Helpeful links:
/**
https://blog.cloudflare.com/assembly-within-bpf-tail-calls-on-x86-and-arm/

https://kernel.googlesource.com/pub/scm/network/iproute2/iproute2-next/+/refs/tags/v5.9.0/examples/bpf/bpf_tailcall.c
*/
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/// `SEC` applies to global items.
SEC("license")
char LICENSE[] = "Dual BSD/GPL";

typedef struct {
  /// Special type of array whose values contain only fds referring to other bpf
  /// programs.
  ///
  /// Both they `key_size` and `value_size` must be exactly 4 bytes (`u32`).
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 256 * 1024);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));

} ProgramArray;

SEC(".maps")
ProgramArray syscalls;

SEC("tracepoint/syscalls/sys_enter_execve")
int run(struct bpf_raw_tracepoint_args *tracepoint_args) {
  int opcode = tracepoint_args->args[1];

  // TODO(alex) [high] 2023-05-08: Is this enough to move the tail call
  // forwards? Are we accessing a valid index?
  bpf_tail_call(tracepoint_args, &syscalls, opcode);

  bpf_trace_printk("syscall: {%d}", opcode);

  return 0;
}

SEC("tc")
int enter_execve(void *ctx) {
  bpf_trace_printk("enter_execve %d", 0);
  return 0;
}

SEC("tc")
int timer(struct bpf_raw_tracepoint_args *tracepoint_args) {
  if (tracepoint_args->args[1] == 222) {
    bpf_trace_printk("create timer %d", 222);
  } else if (tracepoint_args->args[1] == 226) {
    bpf_trace_printk("deleting timer %d", 226);
  } else {
    bpf_trace_printk("timer operation %d", tracepoint_args->args[1]);
  }

  return 0;
}

SEC("tc")
int ignore_opcode(void *ctx) { return 0; }
