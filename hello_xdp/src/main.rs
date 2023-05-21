#![feature(result_option_inspect)]
use std::{process::exit, ptr};

use libbpf_rs::PrintLevel;
use libbpf_sys::{bpf_xdp_set_link_opts, XDP_FLAGS_UPDATE_IF_NOEXIST};
use log::{debug, error, info, warn};
use nix::unistd::Uid;

mod hello_xdp {
    include!(concat!(env!("OUT_DIR"), "/hello_xdp.skel.rs"));
}
use hello_xdp::*;

fn print_based_on_log(level: PrintLevel, msg: String) {
    match level {
        PrintLevel::Debug => debug!("{}", msg),
        PrintLevel::Info => info!("{}", msg),
        PrintLevel::Warn => warn!("{}", msg),
    }
}

fn sample() {
    let builder = HelloXdpSkelBuilder::default();

    let open = builder.open().unwrap();
    let mut skel = open
        .load()
        .inspect_err(|fail| error!("Failed loading with {fail:#?}"))
        .unwrap();

    let mut opts = bpf_xdp_set_link_opts::default();

    let run_fd = skel.progs_mut().run().fd();
    debug!("run_fd {run_fd:#?}");

    // TODO(alex) [high] 2023-05-21: Why is this crashing with `-19` (`ENODEV`)?
    let attached = unsafe {
        libbpf_sys::bpf_xdp_attach(
            540,
            run_fd,
            XDP_FLAGS_UPDATE_IF_NOEXIST | libbpf_sys::XDP_FLAGS_SKB_MODE,
            ptr::null(),
        )
    };
    if attached < 0 {
        panic!("Failed attaching with {attached:#?}");
    }

    // debug!("{:#?}", skel.progs_mut().run().autoload());

    // let program_path = "/sys/fs/bpf/hello_xdp";
    // We can pin a program to some file path (optional for most use-cases, include this one).
    //
    // Has to be unique (bpf-ID and pinned path are always unique).
    //
    // If you don't attach to the file system like this, then the "attachment" lives only while
    // the program is running (the Rust program).
    // skel.progs_mut().run().pin(program_path).unwrap();

    // debug!("{:#?}", program.attach_type());
    // debug!("{:#?}", program.prog_type());

    let attached = skel.attach().unwrap();

    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    // Remember to `unpin`, otherwise the file in `program_path` will stay created there.
    // program.unpin(program_path).unwrap();
}

fn main() {
    setup();
    sample();
}

fn setup() {
    std::env::set_var("RUST_LOG", "trace");
    env_logger::Builder::from_default_env()
        .target(env_logger::Target::Stdout)
        .init();

    info!("Starting hello_xdp");

    if !Uid::effective().is_root() {
        log::error!("Must run as root!");
        exit(1);
    }

    libbpf_rs::set_print(Some((PrintLevel::Debug, print_based_on_log)));
}
