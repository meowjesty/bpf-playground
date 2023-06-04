#![feature(result_option_inspect)]
use std::process::exit;

use libbpf_rs::PrintLevel;
use log::{debug, error, info, warn};
use nix::{net::if_::if_nametoindex, unistd::Uid};

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

    // You MUST attach to the CORRECT `ifindex` (Interface Index).
    //
    // An easy way to retrieve this index value is to use linux's `if_nametoindex` if you know
    // the name of the interface (e.g. `eth0`). Or use the `ip link` which shows the index as:
    //
    // 2: enp5s0: (...)
    // ^
    // |
    // the `ifindex`
    //
    // If you use an invalid value here, meaning that the value doesn't correspond to any interface,
    // you'll be met with a very unhelpful error message of:
    //
    // > libbpf: prog 'sample': failed to attach to xdp: Invalid argument
    //
    // Some types can be auto-attached thanks to `SEC` (see `more_maps` sample), but for xpd we have
    // to manually do it.
    let _link = skel
        .progs_mut()
        .sample()
        .attach_xdp(if_nametoindex("enp5s0").unwrap() as i32)
        .unwrap();

    // There is an example which manually updates the `skel.links`, but we don't need this.
    // skel.links = HelloXdpLinks { sample: Some(link) };

    // let program_path = "/sys/fs/bpf/hello_xdp";
    //
    // We can pin a program to some file path (optional for most use-cases, including this one).
    //
    // Has to be unique (bpf-ID and pinned path are always unique).
    //
    // If you don't attach to the file system like this, then the "attachment" lives only while
    // the program is running (the Rust program / userspace program).
    //
    // This happens due to programs in bpf being reference counted, so if the count decrements to
    // `0` (no userspace thing is holding a reference), then it gets "dropped" (deleted). Note that
    // bpf maps are also reference counted (and they can also be pinned).
    //
    // Read more about lifetimes of bpf things in:
    //
    // https://facebookmicrosites.github.io/bpf/blog/2018/08/31/object-lifetime.html
    //
    // The "pin" happens in the filesystem, but it actually only lives in memory (reboot clears it,
    // or you can `rm {file-path}`).
    //
    // skel.progs_mut().run().pin(program_path).unwrap();

    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        print!(".");
    }

    // Remember to `unpin`, otherwise the file in `program_path` will stay created there (until
    // reboot).
    //
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
