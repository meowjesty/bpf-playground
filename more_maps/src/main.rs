#![feature(result_option_inspect)]

use core::mem::size_of;

use libbpf_rs::{PrintLevel, RingBufferBuilder};
use log::{debug, error, info, warn};
use nix::unistd::Uid;

mod more_maps {
    include!(concat!(env!("OUT_DIR"), "/more_maps.skel.rs"));
}
use more_maps::*;
use plain::Plain;

#[repr(C)]
#[derive(Default)]
struct Data {
    pid: u64,
    uid: u64,
    command: [u8; 32],
    message: [u8; 32],
    path: [u8; 32],
}

fn sample() {
    let builder = MoreMapsSkelBuilder::default();

    // `open` phase reads the ELF data and converts its sections into structures that represent bpf
    // programs and maps.
    let open = builder.open().unwrap();

    // `open` and `load` phases being handled separately allow us to configure a program before
    // loading, e.g. initializing a global variable.
    //
    // `open.maps_mut().user_messages()` ...
    //
    // If you tried to do this after the `load` phase, it would have no effect.

    // `load` phase loads the maps and programs into the kernel, doing CO-RE changes.
    let mut skel = open
        .load()
        .inspect_err(|fail| error!("Failed loading with {fail:#?}"))
        .unwrap();

    // Auto-attach programs (see our definition for `sample_program` in the C file).
    let _ = skel.attach().unwrap();

    let mut buffer_builder = RingBufferBuilder::new();
    buffer_builder
        .add(skel.maps().global_buffer(), |bytes| {
            if bytes.len() >= size_of::<Data>() {
                let data = Data::from_bytes(bytes);
                log::debug!("Data arrived {data:#?}");

                CONTINUE
            } else {
                STOP
            }
        })
        .unwrap();

    // Maps can be shared with multiple programs by _pinning_.
    //
    // So we could:
    //
    // skel.maps_mut()
    //     .global_buffer()
    //     .pin("/sys/fs/bpf/mymap")
    //     .unwrap();
    //
    // And access it from another program with (C example):
    //
    // int fd = bpf_obj_get("sys/fs/bpf/mymap");
    // bpf_obj_get_info_by_fd(fd, ...);
    //
    // Equivalent Rust code:
    //
    // let my_map = libbpf_rs::Map::from_pinned_path("/sys/fs/bpf/mymap");
    //
    // We can start using `my_map` here, even though it's not part of this program's `skel`.
    let data_buffer = buffer_builder.build().unwrap();

    loop {
        print!(".");

        // We keep polling the ring buffer to check for new data.
        data_buffer
            .poll(std::time::Duration::from_millis(250))
            .unwrap();

        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

fn main() {
    setup();
    sample();
}

const STOP: i32 = 1;
const CONTINUE: i32 = 0;

unsafe impl Plain for Data {}

impl Data {
    fn from_bytes(bytes: &[u8]) -> &Self {
        plain::from_bytes(bytes).expect("Invalid buffer!")
    }
}

impl core::fmt::Debug for Data {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Data")
            .field("PID", &self.pid)
            .field("UID", &self.uid)
            .field(
                "command",
                &String::from_utf8_lossy(&self.command[..]).trim_end_matches('\0'),
            )
            .field(
                "message",
                &String::from_utf8_lossy(&self.message[..]).trim_end_matches('\0'),
            )
            .field(
                "path",
                &String::from_utf8_lossy(&self.path[..]).trim_end_matches('\0'),
            )
            .finish()
    }
}

fn print_based_on_log(level: PrintLevel, msg: String) {
    match level {
        PrintLevel::Debug => debug!("{}", msg),
        PrintLevel::Info => info!("{}", msg),
        PrintLevel::Warn => warn!("{}", msg),
    }
}

fn setup() {
    std::env::set_var("RUST_LOG", "trace");
    env_logger::Builder::from_default_env()
        .target(env_logger::Target::Stdout)
        .init();

    info!("Starting more_maps");

    if !Uid::effective().is_root() {
        log::error!("Must run as root!");
        std::process::exit(1);
    }

    libbpf_rs::set_print(Some((PrintLevel::Debug, print_based_on_log)));
}
