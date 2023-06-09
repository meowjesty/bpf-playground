/// Helpful links:
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

  // It did not like when I set this to `__u64`, maybe related how this is a
  // `__uint()`, but there doesn't seem to exist an `__uint64()` though?
  __uint(key_size, sizeof(__u32));

  /// These will be our syscall opcodes.
  __uint(value_size, sizeof(__u32));
} ProgramArray;

/// Link with syscall opcodes:
///
/// https://filippo.io/linux-syscall-table/
SEC(".maps")
ProgramArray syscalls;

/// Helpful links:
///
/// https://mozillazg.com/2022/05/ebpf-libbpf-raw-tracepoint-common-questions-en.html#hidformat-of-sec-content
///
/// The more general syscall entry point. Represents any of the `sys_enter_*`
/// calls, such as `sys_enter_excve` that we were using.
///
/// For the full list of the events that raw tracepoints can monitor:
///
///```sh
/// sudo cat /sys/kernel/debug/tracing/available_events
///```
SEC("raw_tracepoint/sys_enter")
int run(struct bpf_raw_tracepoint_args *tracepoint_args) {
  // We access the `bpf_raw_tracepoint_args[1]` which contains the syscall id.
  //
  // `bpf_raw_tracepoints[0]` contains the regs (see `pt_regs`), which are the
  // arguments to the corresponding syscall (for example the
  // `const char *pathname, char *const argv[], char *const envp[]`, from
  // `execve`).
  int opcode = tracepoint_args->args[1];

  // You cannot call `bpf_map_lookup_elem` for a `BPF_MAP_TYPE_PROG_ARRAY`, it
  // errors out at load time with:
  // "cannot pass map_type 3 into func bpf_map_lookup_elem#1"
  //
  // The same is true for `bpf_map_update_elem`.
  //
  //  void *sys_fd = bpf_map_lookup_elem(&syscalls, &key);

  // Jumps into another bpf program (indexed here by `opcode`) preserving
  // the stack frame. Sort of like a loop, it should never come back from
  // this (doesn't go back to a previous program).
  //
  // On failure it's basically skipped, and we move on to the
  // `bpf_trace_printk` line (continues execution of the current program).
  bpf_tail_call(tracepoint_args, &syscalls, opcode);

  // We only display something here if the `bpf_tail_call` fails, due to
  // `opcode` not being a valid index for the `syscalls` map.
  bpf_printk("syscall bypassed our tail call: {%d}", opcode);
  return 0;
}

/// Loaded into the `syscalls` program array map, and is executed when the
/// `bpf_tail_call` `opcode` is `execve`.
SEC("raw_tracepoint")
int enter_execve(void *ctx) {
  bpf_printk("excve was called");
  return 0;
}

/// Loaded into the `syscalls` program array map.
SEC("raw_tracepoint")
int timer(struct bpf_raw_tracepoint_args *tracepoint_args) {
  if (tracepoint_args->args[1] == 222) {
    bpf_printk("create timer %s", "timer");
  } else if (tracepoint_args->args[1] == 226) {
    bpf_printk("deleting timer");
  } else {
    bpf_printk("timer operation");
  }

  return 0;
}

/// Used for syscalls that we want to do nothing (it's a `bpf_tail_call`
/// program).
SEC("raw_tracepoint")
int ignore_opcode(void *ctx) { return 0; }

/// Loaded into the `syscalls` program array map, and is executed for some
/// syscalls.
SEC("raw_tracepoint")
int random_syscall(struct bpf_raw_tracepoint_args *tracepoint_args) {
  bpf_printk("random syscall [%d]", tracepoint_args->args[1]);
  return 0;
}
