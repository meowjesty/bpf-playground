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
use plain::Plain;
///
/// Details can also be seen in the [kernel maps page](https://docs.kernel.org/bpf/maps.html).
use std::{process::exit, ptr, thread::sleep, time::Duration};

use libbpf_rs::{MapFlags, PrintLevel};
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

#[repr(C)]
#[derive(Default, Debug)]
struct HashElement {
    counter: u64,
}

unsafe impl Plain for HashElement {}

impl HashElement {
    fn from_bytes(bytes: &[u8]) -> &Self {
        plain::from_bytes(bytes).expect("Invalid buffer!")
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

    let key_size = skel.maps().global_hash_map().key_size();
    let map_info = skel.maps().global_hash_map().info();
    log::debug!("key size {key_size:#?} | map info {map_info:#?}");

    loop {
        log::info!("...");

        // {
        //     // The `libbpf-sys` crate also outputs the double `1000`.
        //     let fd = skel.maps().global_hash_map().fd();
        //     let mut next_key = vec![0; 8];
        //     unsafe {
        //         while libbpf_sys::bpf_map_get_next_key(fd, ptr::null(), next_key.as_mut_ptr() as _)
        //             == 0
        //         {
        //             let raw_key: u64 = *plain::from_bytes(&next_key).expect("Invalid buffer!");

        //             log::info!("next_key is {next_key:?} raw_key {raw_key:#?}");
        //             next_key = vec![0; 8];
        //         }
        //     }
        // }

        for key_bytes in skel.maps().global_hash_map().keys() {
            // TODO(alex) [high] 2023-04-30: For some reason, we get `1000, 1000`, instead of only
            // `1000`, which turns our key value into a huge number.
            let key: u64 = *plain::from_bytes(&key_bytes).expect("Invalid buffer!");

            let value_bytes = skel
                .maps()
                .global_hash_map()
                .lookup(&key_bytes, MapFlags::ANY)
                .expect("Failed lookup!");

            let value: Option<&HashElement> = value_bytes
                .as_ref()
                .map(|bytes| HashElement::from_bytes(bytes));

            log::info!("raw key: {key_bytes:04x?} | value_bytes: {value_bytes:?}");
            log::info!("ID (key): {key:#?} | value: {value:#?}");
        }
        sleep(Duration::from_secs(1));
    }
}
