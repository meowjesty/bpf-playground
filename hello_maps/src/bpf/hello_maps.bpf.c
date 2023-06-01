#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/// `SEC` applies to global items.
SEC("license")
char LICENSE[] = "Dual BSD/GPL";

typedef struct {
  __u64 counter;

  /// We could use this `bpf_spin_lock` to properly access the element directly.
  ///
  /// Required when dealing with multiple CPU cores trying to access the same
  /// resource.
  ///
  /// It comes with a few restrictions:
  ///
  /// 1. Can only be used for maps of type hash and arrays;
  /// 2. **Cannot** be used in tracing or socket filter bpf programs;
  ///
  /// Read more here: https://lwn.net/Articles/779120/
  ///
  // struct bpf_spin_lock lock;
} HashElement;

/// `SEC` applies to global values, and not for type definitions, it's a macro
/// for putting things in a place, like we have a `.DATA` section in asm.
typedef struct {
  /// `__uint` is actually a macro for defining a named field for our type.
  ///
  /// #define __uint(name, val) int (*name)[val]
  ///
  /// Specify the type of BPF map, see the `bpf_map_type` enum in `linux/bpf.h`.
  __uint(type, BPF_MAP_TYPE_HASH);

  /// We must specify the max number of elements, otherwise it errors at
  /// checking-time.
  /**
[2023-04-24T03:47:37Z WARN  hello_maps] libbpf: Error in
bpf_create_map_xattr(global_hash_map):Invalid argument(-22). Retrying without
BTF.

[2023-04-24T03:47:37Z WARN  hello_maps] libbpf: map 'global_hash_map': failed to
create: Invalid argument(-22)

[2023-04-24T03:47:37Z WARN  hello_maps] libbpf: failed to load object
'hello_maps_bpf'

[2023-04-24T03:47:37Z WARN  hello_maps] libbpf: failed to load BPF skeleton
'hello_maps_bpf': -22
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

/// With this struct we can pass data from the `iterator_fn` by accessing
/// `CallbackContext` fields.
///
/// In this case we use the `output` field to return the current key.
typedef struct {
  void *context;
  __u64 output;
} CallbackContext;

/// Iterator callback function called in each iteration of
/// `bpf_for_each_map_elem`.
///
/// Can be used to act as a filter (not just straight on iteration of each
/// element), as we can decide when iteration stops by return `1` (indicates end
/// of map).
static __u64 iterator_fn(HashMap *map, __u64 *key, HashElement *element,
                         CallbackContext *context) {
  if (element) {
    bpf_printk("key: %llu | value: %llu", *key, element->counter);
    context->output = *key;
    return 0; // Continues to the next element.
  } else {
    return 1; // Skips the rest of the elements.
  }
}

/// Section for `Map` types (arrays, ring buffers, queues, and a bunch more).
SEC(".maps")
HashMap global_hash_map;

SEC("tracepoint/syscalls/sys_enter_execve")
int hello(void *ctx) {
  __u64 counter = 0;

  // Returns the `uid` (lower half) and `gid` (higher half) as a single u64.
  __u64 uid_gid = bpf_get_current_uid_gid();

  // Only `uid` (lower half).
  __u64 uid = uid_gid & 0xffffffff;

  // Only `gid` (higher half).
  // __u64 gid = uid_gid >> 32;

  // Performs the lookup on `Map` by `Key`.
  //
  // Must be careful as every pointer here is just `void *`.
  HashElement *element = bpf_map_lookup_elem(&global_hash_map, &uid);
  if (element != NULL) {
    counter = element->counter;
  }

  counter += 1;

  HashElement updated = {.counter = counter};
  // Upserts the `Map` by checking `Key`
  bpf_map_update_elem(&global_hash_map, &uid, &updated, BPF_ANY);

  // You'll see many things like these (commands) for basically every function
  // you can use in bpf. We don't have to deal with these commands, due to using
  // `libbpf`, but if we were to use the `bpf(...)` syscall, then these would be
  // the first argument, which is the command we want to execute in bpf-land.
  //
  // An equivalent way of updating an element from the Rust side (userspace)
  // would be:
  //
  // `bpf(BPF_MAP_UPDATE_ELEM, bpf_attr: { map_fd, key, value, flags }, size);`
  //
  // BPF_MAP_UPDATE_ELEM

  CallbackContext data = {.context = ctx, .output = 0};

  // `flags` must be set to `0`.
  long total_iterations =
      bpf_for_each_map_elem(&global_hash_map, iterator_fn, &data, 0);

  bpf_printk("output of each map %llu | total_iterations %ld", data.output,
             total_iterations);

  return 0;
}
