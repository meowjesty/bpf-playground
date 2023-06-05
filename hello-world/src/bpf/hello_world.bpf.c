//! Instead of this `lix/bpf.h` include, we could use a `vmlinux.h`, which is a
//! file that contains the BTF of the current (running) kernel.
//!
//! If you run `bpftool btf list` (might require `sudo`) the first resutl should
//! be `vmlinux`:
//! ```sh
//! 1: name [vmlinux]  size 5081050B
//! ...
//! 182: name [snd_hrtimer]  size 2373B
//! 183: name [snd_seq_dummy]  size 3388B
//! ```
//!
//! You can inspect the BTF information with `btf dump id {id}`.
//!
//! To generate the `vmlinux.h` header:
//!
//! `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`
//!
//! Check out https://github.com/aquasecurity/btfhub-archive/ for various BTF
//! files.
//!
//! You must include the "linux/bpf.h" header, which contains a bunch of the
//! functions plus type declarations.
//!
//! Without this file, you get a bunch of errors of
//! `unknown type name __u32 static long (*bpf_tail_call) (...)` and other
//! missing type definitions like these.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/// Need a GPL compatible license, otherwise we get an error:
/// `cannot call GPL-restricted function from non-GPL compatible program`
///
/// Some functions require GPL compatibility.
///
/// The bpf verifier checks the `bpf_func_proto` structure of the function,
/// which can be something like this:
///
/// ```c
/// const struct bpf_func_proto bpf_map_lookup_elem_proto = {
///   .func       = bpf_map_lookup_elem,
///   .gpl_only   = false,
///   .pkt_access = true,
///   .ret_type   = RET_PTR_TO_MAP_VALUE_OR_NULL,
///   .arg1_type  = ARG_CONST_MAP_PTR,
///   .arg2_type  = ARG_PTR_TO_MAP_KEY,
/// };
///
/// ```
///
/// For a list of functions and their licenses, check:
/// https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#helpers
SEC("license")
char LICENSE[] = "Dual BSD/GPL";

/// Programs can contain at most 1 million instructions, thus requiring that
/// loops be bounded.
///
/// Normal `for` loops are fine, but there is the smarter `bpf_loop` helper that
/// takes the maximum number of iterations, and a function that is called for
/// each iteration. `bpf_loop` is more efficient when interacting with the bpf
/// verifier (it'll only check the inner function once).
///
/// For collections, there is also the `bpf_for_each_map_elem` helper, which is
/// a nicer iterator than a dumb `for` loop.
SEC("tracepoint/syscalls/sys_enter_execve")
int hello(void *ctx) {
  char msg[] = "Hello, World!";

  // To see these logs:
  // `sudo cat /sys/kernel/debug/tracing/trace_pipe`
  bpf_printk("hello(): %s\n", msg);

  // We have to return something here, which is stored in register 0 (`R0`).
  //
  // Keep in mind though, that helper functions return values are also stored in
  // `R0`, thus we could remove this explicit `return 0` statement, as
  // `bpf_printk` will set `R0` for us (which would be a very clunky thing to
  // do, just know that it's possible, not that you should do it).
  //
  // P.S.: To not lose return values, bpf will copy the value from `R0` to other
  // registers (after `R5`, so `R6` to `R9`, while `R10` holds the stack
  // pointer).
  return 0;
}
