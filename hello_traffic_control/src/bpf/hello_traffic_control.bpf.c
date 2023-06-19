//! The main differences between XDP and TC are:
//!
//! 1. XDP can only process ingress (inbound from the network interface)
//! traffic, while TC can do both ingress and egress (outbound toward the
//! network interface);
//!
//! 2. XDP doesn't have access to [`sk_buff`];
//!
//! For more info on this, see the program type
//! [reference](https://docs.cilium.io/en/latest/bpf/#program-types)
#include "../../../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Some of the stuff defined here conflicts with `vmlinux.h`, so if we want the
// constants for return values of a TC program, we have to define them
// ourselves.
// #include <linux/pkt_cls.h>

SEC("license")
char LICENSE[] = "Dual BSD/GPL";

const u16 ETH_PROTOCOL_IP = 0x0800;
const u8 ICMP = 1;

/// It's as if the BPF program didn't run on this packet, passing it to the next
/// classifier in the sequence.
const int TC_ACT_UNSPEC = -1;

/// Passes the packet to the next layer in the stack.
const int TC_ACT_OK = 0;

/// Sends the packet to the ingress or egress path of a different network
/// device.
const int TC_ACT_REDIRECT = 7;

/// Drop the packet.
const int TC_ACT_SHOT = 2;

bool is_icmp_ping_request(const void *const data, const void *const data_end) {
  struct ethhdr const *const eth_header = data;
  if (data + sizeof(struct ethhdr) > data_end) {
    return false;
  }

  if (bpf_ntohs(eth_header->h_proto) != ETH_PROTOCOL_IP) {
    return false;
  }

  struct iphdr const *const ip_header = data + sizeof(struct ethhdr);
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
    return false;
  }

  if (ip_header->protocol != ICMP) {
    return false;
  }

  struct icmphdr const *const icmp_header =
      data + sizeof(struct ethhdr) + sizeof(struct iphdr);
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
          sizeof(struct icmphdr) >
      data_end) {
    return false;
  }

  return (icmp_header->type == 0);
}

/// Prints that we're dropping the packet, then drop it with [`TC_ACT_SHOT`].
///
/// [`__sk_buff`] is a simplified version of [`sk_buff`], which contains a lot
/// of stuff we don't need in BPF (at least that's what I'm getting). Also,
/// [`sk_buff`] is not a "Linux exposed user-space API", so it can change,
/// meanwhile `__sk_buff` seems to be stable-ish, there is even a comment saying
/// that new fields must be added at the end.
///
/// [`__sk_buff`] is a metadata struct about a packet, it doesn't contain the
/// packet data itself. We have our familiar `data` and `data_end` pointer
/// offsets here.
SEC("tc")
int tc_drop(struct __sk_buff *skb) {
  bpf_printk("[tc] dropping packet\n");
  return TC_ACT_SHOT;
}

/// Prints that we're dropping the packet, then drop it with [`TC_ACT_SHOT`] if
/// it's an ICMP packet.
///
/// Could also be `SEC("classifier")`, not sure if there is a difference (yet).
// SEC("classifier")
SEC("tc")
int tc_drop_ping(struct __sk_buff *skb) {
  void *data = (void *)(uintptr_t)skb->data;
  void *data_end = (void *)(uintptr_t)skb->data_end;

  if (is_icmp_ping_request(data, data_end)) {
    struct iphdr const *const ip_header = data + sizeof(struct ethhdr);
    struct icmphdr const *const icmp_header =
        data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    bpf_printk("[tc] ICMP request for %x type %x\n", ip_header->daddr,
               icmp_header->type);
    return TC_ACT_SHOT;
  }

  return TC_ACT_OK;
}
