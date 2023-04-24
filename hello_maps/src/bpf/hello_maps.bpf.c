#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/// `SEC` applies to global items.
SEC("license")
char LICENSE[] = "Dual BSD/GPL";

typedef struct {
  __u64 counter;

  /// We could use this `bpf_spin_lock` to properly access the element directly.
  // struct bpf_spin_lock lock;
} HashElement;

/// `SEC` applies to global values, and not for type definitions, it's a macro for putting things
/// in a place, like we have a `.DATA` section in asm. 
typedef struct {
  /// `__uint` is actually a macro for defining a named field for our type.
  ///
  /// #define __uint(name, val) int (*name)[val]
  ///
  /// Specify the type of BPF map, see the `bpf_map_type` enum in `linux/bpf.h`.
  __uint(type, BPF_MAP_TYPE_HASH);

  /// We must specify the max number of elements, otherwise it errors at checking-time.
  /**
[2023-04-24T03:47:37Z WARN  hello_maps] libbpf: Error in bpf_create_map_xattr(global_hash_map):Invalid argument(-22). Retrying without BTF.

[2023-04-24T03:47:37Z WARN  hello_maps] libbpf: map 'global_hash_map': failed to create: Invalid argument(-22)

[2023-04-24T03:47:37Z WARN  hello_maps] libbpf: failed to load object 'hello_maps_bpf'

[2023-04-24T03:47:37Z WARN  hello_maps] libbpf: failed to load BPF skeleton 'hello_maps_bpf': -22
  **/
  __uint(max_entries, 256 * 1024);

  /// Another macro to define a type named `key` with value `__u64`.
  ///
  /// Key of the hash map.
  ///
  /// I think this is equivalent to `key: u64`.
  __type(key, __u64);

  /// I think this is equivalent to `value: HashElement`.
  __type(value, HashElement);
} HashMap;


/// Section for `Map` types (arrays, ring buffers, queues, and a bunch more).
SEC(".maps")
HashMap global_hash_map;

SEC("tracepoint/syscalls/sys_enter_execve")
int hello(void *ctx) {
  __u64 counter = 0;
  __u64 uid = bpf_get_current_uid_gid();

  // Performs the lookup on `Map` by `Key`.
  //
  // Must be careful as every pointer here is just `void *`.
  HashElement *element = bpf_map_lookup_elem(&global_hash_map, &uid);
  if (element != NULL) {
    counter = element->counter;
  }

  counter += 1;

  HashElement updated = { .counter = counter };
  // Upserts the `Map` by checking `Key`
  bpf_map_update_elem(&global_hash_map, &uid, &updated, BPF_ANY);

  return 0;
}
