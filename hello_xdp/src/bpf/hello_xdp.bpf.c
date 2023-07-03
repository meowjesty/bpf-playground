//! Helpful links:
/**
<Spec documentation for instructions, bpf opcodes and more>
https://github.com/iovisor/bpf-docs/blob/master/eBPF.md

https://docs.kernel.org/bpf/instruction-set.html

https://github.com/ebpffoundation/ebpf-docs

A tutorial to dive deeper into xdp:

https://github.com/xdp-project/xdp-tutorial
 */
//!
//! You can check if the BPF program is JIT with
//! `sysctl net.core.bpf_jit_enable`.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/// `SEC` applies to global items.
SEC("license")
char LICENSE[] = "Dual BSD/GPL";

__u32 counter = 0;

/// `eXpress Data Path` bypasses most of the networking stack, thus it allows us
/// to handle packets at a very low (and fast) level.
///
/// We're hooking the `NIC` (network interface controller) driver, but some
/// network cards allow handling this stuff there (so the program is ran on the
/// network card itself).
///
/// XDP allows not only inspection, but also modification of the network
/// packets.
///
/// Other network related events (that you can attach to) are `tc` and
/// `flow_dissector`. Use `bpftool net list` to see a list of network attached
/// events.
///
/// This program just prints the value of `counter` whenever a new packet
/// arrives.
///
/// Unlike the previous `sys_enter` examples, this program has to be attached to
/// something (a network interface in this case), it doesn't run on its own on
/// some event (again, unless it's attached).
///
/// Use `ip link` to see the attached program + it's id on the network interface
/// we selected.
///
/// XDP return codes are:
///
/// - `XDP_PASS`: packet continues as normal in the network stack;
/// - `XDP_DROP`: packet is discarded;
/// - `XDP_TX`: sends the packet back out of the same interface it arrived;
/// - `XDP_REDIRECT`: sends the packet to a different network iface;
/// - `XDP_ABORTED`: discarded, with the semantics of this being an _error_;
SEC("xdp")
int sample(struct xdp_md *context) {
  bpf_printk("counter [%d]", counter);

  counter += 1;

  // Let the packet continue to the networking stack.
  //
  // We could use `XDP_REDIRECT` to redirect the packet to another userspace
  // socket.
  return XDP_PASS;
}
