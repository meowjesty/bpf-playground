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
//
// #include <linux/pkt_cls.h>

// Contains the definition for ETH_HLEN, but conflicts with `vmlinux.h` on some
// stuff.
//
// #include <linux/if_ether.h>

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

/// Total octets in header.
const u32 ETH_HLEN = 14;

const u32 ip_source_offset() {
  return ETH_HLEN + offsetof(struct iphdr, saddr);
}

const u32 ip_destination_offset() {
  return ETH_HLEN + offsetof(struct iphdr, daddr);
}

const u32 icmp_checksum_offset() {
  return ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, checksum);
}

const u32 icmp_type_offset() {
  return ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, type);
}

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

void swap_mac_addresses(struct __sk_buff *skb) {
  u8 source_mac[6];
  u8 destination_mac[6];

  bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_source), source_mac, 6);
  bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_dest), destination_mac, 6);

  bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source), destination_mac,
                      6, 0);
  bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), source_mac, 6, 0);
}

void swap_ip_addresses(struct __sk_buff *skb) {
  u8 source_ip[4];
  u8 destination_ip[6];

  bpf_skb_load_bytes(skb, ip_source_offset(), source_ip, 4);
  bpf_skb_load_bytes(skb, ip_destination_offset(), destination_ip, 4);

  bpf_skb_store_bytes(skb, ip_source_offset(), destination_ip, 4, 0);
  bpf_skb_store_bytes(skb, ip_destination_offset(), source_ip, 4, 0);
}

void update_icmp_type(struct __sk_buff *skb, u8 old_type, u8 new_type) {
  bpf_l4_csum_replace(skb, icmp_checksum_offset(), old_type, new_type, 2);
  bpf_skb_store_bytes(skb, icmp_type_offset(), &new_type, sizeof(new_type), 0);
}

/// Captures ICMP ping requests and sends back an ICMP ping reply.
///
/// We modify `skb` here, so we can't forget to update the packet's checksum.
///
/// It replies by first swapping the source with the destination addresses, then
/// we change the type field for the ICMP header ([`icmphdr`]) to be an echo
/// reply (`8`).
///
/// [`bpf_clone_redirect`] sends the cloned packet back through the interface
/// `skb->ifindex` on which it was received.
///
/// Finally, we drop the original packet, as we sent back a response and don't
/// need the original to reach anyone anymore.
///
/// Here we're avoiding the normal flow of a ping request, which would be
/// handled by the kernel network stack. Instead we capture and respond without
/// this ever taking place.
SEC("tc")
int tc_ping_reply(struct __sk_buff *skb) {
  void *data = (void *)(uintptr_t)skb->data;
  void *data_end = (void *)(uintptr_t)skb->data_end;

  if (!is_icmp_ping_request(data, data_end)) {
    return TC_ACT_OK;
  }

  struct iphdr const *const ip_header = data + sizeof(struct ethhdr);
  struct icmphdr const *const icmp_header =
      data + sizeof(struct ethhdr) + sizeof(struct iphdr);

  swap_mac_addresses(skb);
  swap_ip_addresses(skb);

  // Change the type of the ICMP packet to 0 (ICMP echo reply) from 8 (ICMP echo
  // request).
  update_icmp_type(skb, 8, 0);

  // Redirect a clone of the modified `skb` back to the interface it arrived on.
  bpf_clone_redirect(skb, skb->ifindex, 0);

  return TC_ACT_SHOT;
}
