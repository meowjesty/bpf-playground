#include "../../../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("license")
char LICENSE[] = "Dual BSD/GPL";

const u16 ETH_PROTOCOL_IP = 0x0800;
const u8 ICMP = 1;

/// Returns the protocol byte for an IP packet, or `0` for anything else.
///
/// Quick and dirty way of doing parsing the whole `context` to extract what we
/// want.
u8 lookup_protocol(struct xdp_md *context) {
  // These are just the positions of where the packet data is, so we convert
  // them to pointers here to convert them later on the types we want (checking
  // that data could actually be of said type).
  void *data = (void *)(uintptr_t)context->data;
  void *data_end = (void *)(uintptr_t)context->data_end;

  // Let's check if this packet has an eth header.
  struct ethhdr *eth = data;

  // The data of this packet starts at `contex->data`, and can't surpass
  // `context->data_end`.
  //
  // We can't just assume that the packet is big enough to hold the type we want
  // (verifier checks this).
  if (data + sizeof(struct ethhdr) > data_end) {
    // Out-of-bounds, this can't be an eth header.
    return 0;
  }

  // `h_proto` is of type `__be16` (big endian), so we use this helper
  // (`bpf_ntohs`) to normalize the endianess (remember that network protocols
  // are big-endian, but CPUs are usually little-endian, so always use these
  // helpers!).
  //
  // Then we check if it's an IP packet.
  if (bpf_ntohs(eth->h_proto) == ETH_PROTOCOL_IP) {
    // Pay attention here that to get the ip header, we start from position
    // `data`, advance the eth header, and that's where we have the ip header
    // struct.
    struct iphdr *iph = data + sizeof(struct ethhdr);

    // Let's check to see if this can be an ip header.
    //
    // Extracting information from what's held in `data` is finnicky, as
    // `context->data` basically just marks the start of a `void *` containing
    // the actual stuff.
    //
    // So we have to check here that whatever position `data` is, it can hold an
    // eth header, and an ip header, going over `context->data_end` would mean
    // that this is not an ip header.
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end) {
      // Protocol of this packet:
      // 1  = ICMP
      // 6  = TCP
      // 17 = UDP
      return iph->protocol;

      // We could do more here than just read/analyze whatever is inside the
      // packet.
      //
      // It's totally fine to modify stuff, so we could change the destination
      // of this packet by messing with `iph->daddr` and `eth->h_dest` fields.
      //
      // Warning: If you change values of an ip header, remember to also update
      // the ip header checksum with `iph->check = iph_csum(iph)`.
    }
  }

  return 0;
}

/// Prints `"PING"` after a `ping {address}` command is started on the attached
/// network interface (`enp5s0` in my case).
SEC("xdp") int sample_program(struct xdp_md *context) {
  u8 protocol = lookup_protocol(context);

  if (ICMP == protocol) {
    bpf_printk("PING");
  }

  return XDP_PASS;
}
