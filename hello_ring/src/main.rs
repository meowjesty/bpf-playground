use std::{fmt::Debug, mem::size_of, process::exit, thread::sleep, time::Duration};

use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    PrintLevel, RingBufferBuilder,
};
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
            .field(
                "command",
                &String::from_utf8_lossy(&self.command[..]).trim_end_matches('\0'),
            )
            .field(
                "message",
                &String::from_utf8_lossy(&self.message[..]).trim_end_matches('\0'),
            )
            .finish()
    }
}

/// Used for stop/continuing to receive data in a ring buffer. Any non-zero value means **stop**.
const STOP: i32 = 1;
const CONTINUE: i32 = 0;

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
    skel.attach().unwrap();

    log::debug!("Map info: {:#?}", skel.maps().output().info());

    let mut ring_buffer_builder = RingBufferBuilder::new();

    // Adds the `output` (global C variable in `hello_ring.bpf.c`) ring buffer.
    //
    // We're registering the `output` ring buffer `fd` with a callback, that'll be setup with
    // `libbfps_sys::ring_buffer__new` later on, actually connecting the buffer we have here with
    // the one on the bpf program.
    //
    // I think that this is similar to how you initialize and interact with GPU buffers.
    let maps = skel.maps();
    ring_buffer_builder
        .add(
            maps.output(),
            // Callback that is called on `RingBuffer::poll`, which is our way of querying the
            // buffer for changes.
            //
            // This is async done with callbacks, which means that if we want to interact with the
            // things inside, we would need Rust channels.
            |bytes| {
                // The callback gets called when new data arrives.
                if bytes.len() >= size_of::<ProgramData>() {
                    let data = ProgramData::from_bytes(bytes);
                    log::debug!("Have data {data:#?}");

                    CONTINUE
                } else {
                    // Stop ring buffer consumption early.
                    STOP
                }
            },
        )
        .unwrap();

    let ring_buffer = ring_buffer_builder.build().unwrap();

    loop {
        log::info!("...");

        // Queries the ring buffer, and triggers our callback.
        //
        // Reminds me of Cpp's ASIO async stuff.
        ring_buffer.poll(Duration::from_secs(30)).unwrap();

        sleep(Duration::from_secs(1));
    }
}
