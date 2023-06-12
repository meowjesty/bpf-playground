#![feature(result_option_inspect)]

use libbpf_rs::PrintLevel;
use log::{debug, error, info, warn};
use nix::{net::if_::if_nametoindex, unistd::Uid};

mod xdp_ping {
    include!(concat!(env!("OUT_DIR"), "/xdp_ping.skel.rs"));
}
use xdp_ping::*;

fn sample() {
    let builder = XdpPingSkelBuilder::default();
    let open = builder.open().unwrap();
    let mut skel = open
        .load()
        .inspect_err(|fail| error!("Failed loading with {fail:#?}"))
        .unwrap();

    let _link = skel
        .progs_mut()
        .sample_program()
        .attach_xdp(if_nametoindex("enp5s0").unwrap() as i32)
        .unwrap();

    loop {
        print!(".");
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

fn main() {
    setup();
    sample();
}

#[allow(dead_code)]
const STOP: i32 = 1;

#[allow(dead_code)]
const CONTINUE: i32 = 0;

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
