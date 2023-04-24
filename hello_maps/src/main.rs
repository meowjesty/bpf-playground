//! Map types are available in `linux/bpf.h::
//!
//! ```
//! enum bpf_map_type {
//! 	BPF_MAP_TYPE_UNSPEC,
//! 	BPF_MAP_TYPE_HASH,
//! 	BPF_MAP_TYPE_ARRAY,
//! 	BPF_MAP_TYPE_PROG_ARRAY,
//! 	BPF_MAP_TYPE_PERF_EVENT_ARRAY,
//! 	BPF_MAP_TYPE_PERCPU_HASH,
//! 	BPF_MAP_TYPE_PERCPU_ARRAY,
//! 	BPF_MAP_TYPE_STACK_TRACE,
//! 	BPF_MAP_TYPE_CGROUP_ARRAY,
//! 	BPF_MAP_TYPE_LRU_HASH,
//! 	BPF_MAP_TYPE_LRU_PERCPU_HASH,
//! 	BPF_MAP_TYPE_LPM_TRIE,
//! 	BPF_MAP_TYPE_ARRAY_OF_MAPS,
//! 	BPF_MAP_TYPE_HASH_OF_MAPS,
//! 	BPF_MAP_TYPE_DEVMAP,
//! 	BPF_MAP_TYPE_SOCKMAP,
//! 	BPF_MAP_TYPE_CPUMAP,
//! 	BPF_MAP_TYPE_XSKMAP,
//! 	BPF_MAP_TYPE_SOCKHASH,
//! 	BPF_MAP_TYPE_CGROUP_STORAGE,
//! 	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
//! 	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
//! 	BPF_MAP_TYPE_QUEUE,
//! 	BPF_MAP_TYPE_STACK,
//! 	BPF_MAP_TYPE_SK_STORAGE,
//! 	BPF_MAP_TYPE_DEVMAP_HASH,
//! 	BPF_MAP_TYPE_STRUCT_OPS,
//!     BPF_MAP_TYPE_RINGBUF,
//! 	BPF_MAP_TYPE_INODE_STORAGE,
//! 	BPF_MAP_TYPE_TASK_STORAGE,
//! 	BPF_MAP_TYPE_BLOOM_FILTER,
//! 	BPF_MAP_TYPE_USER_RINGBUF,
//! };
//!```
///
/// Details can also be seen in the [kernel maps page](https://docs.kernel.org/bpf/maps.html).
use std::{process::exit, thread::sleep, time::Duration};

use libbpf_rs::PrintLevel;
use nix::unistd::Uid;

mod hello_maps {
    include!(concat!(env!("OUT_DIR"), "/hello_maps.skel.rs"));
}

use hello_maps::*;

fn print_based_on_log(level: PrintLevel, msg: String) {
    match level {
        PrintLevel::Debug => log::debug!("{}", msg),
        PrintLevel::Info => log::info!("{}", msg),
        PrintLevel::Warn => log::warn!("{}", msg),
    }
}

fn main() {
    env_logger::init();

    log::info!("Starting hello_maps");

    if !Uid::effective().is_root() {
        log::error!("Must run as root!");
        exit(1);
    }

    libbpf_rs::set_print(Some((PrintLevel::Debug, print_based_on_log)));

    let builder = HelloMapsSkelBuilder::default();

    let open = builder.open().unwrap();
    let mut skel = open.load().unwrap();
    let _attached = skel.attach().unwrap();

    loop {
        log::info!("...");

        for key in skel.maps().global_hash_map().keys() {
            log::info!("key: {key:#?}");
        }
        sleep(Duration::from_secs(1));
    }
}
