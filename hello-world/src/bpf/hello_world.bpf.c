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
//!
//! Useful links:
//!
//! - Page with a list of eBPF helper functions (you can check what is available
//! with the `bpftool feature` command):
//! https://man7.org/linux/man-pages/man7/bpf-helpers.7.html
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
///
/// The `ctx` argument here is a context that depends on the type of event. If
/// you look into the `hello_xdp` sample, you'll see that we have `xdp_md *`.
/// You must use the correct pointer type / event type pair, otherwise the
/// verifier will get angry.
///
/// ## Kfuncs
///
/// You can't use internal kernel stuff, only what's available in the UAPI, but
/// Kfuncs allows you to register kernel functions with the BPF subsystem,
/// thus you can call these kernel functions from within BPF programs.
///
/// They don't provide compatibility guarantees, meaning they can change between
/// kernel versions!
///
/// https://docs.kernel.org/bpf/kfuncs.html#core-kfuncs
///
/// ## Types of programs:
///
/// ### Tracing
///
/// Programs that attach to kprobes, tracepoints, raw tracepoints, fentry/fexit,
/// and perf events.
///
/// They provide, well... tracing capabilities, and you're not supposed to use
/// them to change how the kernel behaves when one of these events is triggered
/// (but you can do it, somewhat).
///
/// #### Kprobes and Kretprobes
///
/// Can be used almost anywhere, except in what's listed at:
/// `/sys/kernel/debug/kprobes/blacklist`
///
/// Funny note: looking into this file we can see some of the memory functions
/// listed, such as `memset`, `memcpy`, etc, so looks like we can't mess around
/// with those, which would be a big security risk (if we could).
///
/// Kprobes are usually attached to the entry of a function, while Kretprobes
/// are attached to the exit. This is not a rule because you can change the
/// offset of a instruction, so you could attach a Kprobe to the exit (why would
/// you do this though, as you basically lose compatibility guarantee between
/// kernels, again).
///
/// If the compiler inlined a kernel function that you wanted to attach a Kprobe
/// to, you're out of luck, there won't be an entry point to attach to.
///
/// You're **NOT** limited to attaching this to only syscalls, you can do it for
/// any non-inlined kernel function! An example would be attaching to
/// `do_execve`, which is not a syscall.
///
/// #### Fentry and Fexit
///
/// More efficient than the Kprobes/Kretprobes (kernel 5.5+, arm only on
/// kernel 6.0+).
///
/// The big difference here is that `fexit` has access to the function's input,
/// while `kretprobe` can only see the output.
///
/// #### Tracepoints
///
/// Marked locations in the kernel code. You can see the available events you
/// can trace with: `cat /sys/kernel/tracing/available_events`.
///
/// You use it just like we're doing here for the `hello` program:
///
/// `tp/syscalls/sys_enter_execve`, where `/syscalls` is the tracing subsystem,
/// and `sys_enter_execve` is the tracepoint name.
///
/// The file `/sys/kernel/tracing/events/syscalls/{syscall}/format` contains
/// information about the fields of `{syscall}` (e.g.
/// `sys_enter_execve/format`), so you could build your own struct and not rely
/// on BTF for the function arguments.
///
/// If you have access to BTF, you can use `SEC(tp_btf/{tracepoint name})`, and
/// get access to the BTF struct (instead of `void *`). You can see the list of
/// `{tracepoint name}` in `/sys/kernel/tracing/available_events`.
///
/// #### User space attachments
///
/// There are user space equivalents for attaching to, well, user space
/// functions. Uprobes, Uretprobes, and USDTs (user statically defined
/// tracepoints), they use the `BPF_PROG_TYPE_KPROBE` program type.
///
/// Attaching an Uprobe for `SSL_write()` from OpenSSL:
///
/// `SEC(uprobe/usr/lib/aarch64-linux-gnu/libssl.so.3/SSL_write)`: the path
/// depends on system arch, lib version (if the lib is even installed), and the
/// path might differ in general (especially for containers).
///
/// An example attaching uprobe and uretprob to OpenSSL can be found at
/// [ebpf-openssl-tracing](https://blog.px.dev/ebpf-openssl-tracing/).
///
/// #### LSM
///
/// You can attach programs to the _Linux Security Module_ API with
/// `BPF_PROG_TYPE_LSM`.
///
/// Keep in mind that, different from the other tracing stuff, the return code
/// from LSM attached programs may change kernel behavior, where a non-0 return
/// value indicates that the security check wasn't passed, so the kernel won't
/// proceed with the operation it was running.
///
/// ### Network
///
/// Requires `CAP_NET_ADMIN` + `CAP_BPF`, or `CAP_SYS_ADMIN` capabilities to be
/// permitted.
///
/// BPF here can do more than just trace stuff, now we're talking about being
/// able to modify a packet, socket configuration, or even what should happen
/// with a packet (proceed as usual, drop it, redirect).
///
/// #### Sockets (top of the stack for BPF network)
///
/// Here you have `BPF_PROG_TYPE_SOCKET_FILTER`, which can filter a _copy_ of
/// socket data, and **NOT** filtering data being sent/received from an
/// application.
///
/// There is also `BPF_PROG_TYPE_SOCK_OPS`, that intercepts operations and
/// actions that take place on a socket. Here we can set, for example, a timeout
/// value for TCP.
///
/// Finally, we have `BPF_PROG_TYPE_SK_SKB` paired with a special map that holds
/// references to sockets, providing `sockmap operations` (redirecting traffic
/// at the socket layer).
///
/// #### Traffic Control (TC)
///
/// https://man7.org/linux/man-pages/man8/tc.8.html
///
/// You attach a program here to provide custom filters and classifiers for
/// network packets (ingress and egress traffic).
///
/// #### eXpress Data Path (XDP) (lowest level of the stack)
///
/// Attached to a network interface (`eth0` for example), and can be offloaded
/// to run on network cards.
///
/// #### Flow Dissector
///
/// https://lwn.net/Articles/764200/
///
/// Used at various points in the stack to get details from a packet's headers.
/// With `BPF_PROG_TYPE_FLOW_DISSECTOR` you can have custom packet dissection.
///
/// #### Ligthweight Tunnels (LWT)
///
/// `BPF_PROG_TYPE_LWT_*` are used for network encapsulation.
///
/// #### Control Groups (Cgroups)
///
/// _Crgoups_ are a sort of _sandbox_ for the resources that a process (or group
/// of processes) can access. They're used in kubernetes to isolate a pod's
/// resources from another.
///
/// Most BPF hooks here are related to networking, except for a few (notably
/// `BPF_CGROUP_SYSCTL`).
///
/// You can use this to check if a given cgroup has permission to do a socket
/// operation, or data transmission.
///
/// ### Infrared Controllers
///
/// `BPF_PROG_TYPE_LIRC_MODE2` are attached to the file descriptor for infrared
/// controller devices.
///
/// This type is here to show that BPF is more than just tracing and network.
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
