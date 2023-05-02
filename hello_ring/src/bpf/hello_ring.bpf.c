/// Useful tutorial at https://nakryiko.com/posts/bpf-ringbuf/
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/// `SEC` applies to global items.
SEC("license")
char LICENSE[] = "Dual BSD/GPL";

/// MPSC queue, with variable-length data records.
///
/// The ring buffer allows us to read data from user-space, this is "just" a memory-mapped region,
/// so no memory copying is neccessary (we just read from a cursor).
///
/// Supports `epoll` and busy-loop (for low latency).
///
/// Writing to it occurs in 2 separate steps:
/// 
/// 1. *reservation*, where you just reserve the space for data, which can fail;
/// 2. *submiting*, which cannot fail, as we have checked for space during reservation;
typedef struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} RingBuffer;

/// The data we're storing in the `RingBuffer`.
typedef struct {
  __u64 pid;
  __u64 uid;
  char command[32];
  char message[32];
} ProgramData;

SEC(".maps")
RingBuffer output;

SEC("tracepoint/syscalls/sys_enter_execve")
int hello(void *ctx) {
  ProgramData program_data = {
    .pid = bpf_get_current_pid_tgid() >> 32,
    .uid = bpf_get_current_uid_gid() & 0xffffffff,
  };

  char message[32] = "Hello";
  bpf_get_current_comm(&program_data.command, sizeof(program_data.command));
  bpf_probe_read_kernel(&program_data.message, sizeof(program_data.message), message);

  // Copies `data` into the `ringbuf`.
  bpf_ringbuf_output(&output, &program_data, sizeof(program_data), 0);

  // This crashes during program load, with an error of:
  /*
    ; bpf_ringbuf_submit(&output, 0);
    39: (18) r1 = 0xffff8b78357b8400      ; R1_w=map_ptr(off=0,ks=0,vs=0,imm=0)
    41: (b7) r2 = 0                       ; R2_w=0
    42: (85) call bpf_ringbuf_submit#132
    R1 type=map_ptr expected=ringbuf_mem
  */
  // bpf_ringbuf_submit(&output, 0);

  return 0;
}
