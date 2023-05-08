use std::{fmt::Debug, mem::size_of, process::exit, thread::sleep, time::Duration};

use libbpf_rs::{PrintLevel, RingBufferBuilder};
use nix::unistd::Uid;

mod hello_ring {
    include!(concat!(env!("OUT_DIR"), "/hello_ring.skel.rs"));
}

use hello_ring::*;
use plain::Plain;

fn print_based_on_log(level: PrintLevel, msg: String) {
    match level {
        PrintLevel::Debug => log::debug!("{}", msg),
        PrintLevel::Info => log::info!("{}", msg),
        PrintLevel::Warn => log::warn!("{}", msg),
    }
}

/// Contains the data we're storing in the ring buffer.
///
/// This is the same type we have on the `C` side (in `hello_ring.bpf.c`).
#[repr(C)]
#[derive(Default)]
struct ProgramData {
    pid: u64,
    uid: u64,
    command: [u8; 32],
    message: [u8; 32],
}

unsafe impl Plain for ProgramData {}

impl ProgramData {
    fn from_bytes(bytes: &[u8]) -> &Self {
        plain::from_bytes(bytes).expect("Invalid buffer!")
    }
}

impl Debug for ProgramData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgramData")
            .field("PID", &self.pid)
            .field("UID", &self.uid)
            .field("command", &String::from_utf8_lossy(&self.command[..]))
            .field("message", &String::from_utf8_lossy(&self.message[..]))
            .finish()
    }
}

fn main() {
    env_logger::init();

    log::info!("Starting hello_ring");

    if !Uid::effective().is_root() {
        log::error!("Must run as root!");
        exit(1);
    }

    libbpf_rs::set_print(Some((PrintLevel::Debug, print_based_on_log)));

    let builder = HelloRingSkelBuilder::default();

    let open = builder.open().unwrap();
    let mut skel = open.load().unwrap();
    let _attached = skel.attach().unwrap();

    log::debug!("Map info: {:#?}", skel.maps().output().info());

    let mut ring_buffer_builder = RingBufferBuilder::new();
    ring_buffer_builder
        .add(
            skel.maps().output(),
            // Callback that is called on `RingBuffer::poll`.
            |bytes| {
                if bytes.len() >= size_of::<ProgramData>() {
                    let data = ProgramData::from_bytes(bytes);
                    log::debug!("Have data {data:#?}");
                    0
                } else {
                    // Stop ring buffer consumption early.
                    1
                }
            },
        )
        .unwrap();

    let ring_buffer = ring_buffer_builder.build().unwrap();

    loop {
        log::info!("...");

        ring_buffer.poll(Duration::from_secs(30)).unwrap();

        sleep(Duration::from_secs(1));
    }
}
