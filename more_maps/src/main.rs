#![feature(result_option_inspect)]
use std::process::exit;

use libbpf_rs::PrintLevel;
use log::{debug, error, info, warn};
use nix::unistd::Uid;

mod more_maps {
    include!(concat!(env!("OUT_DIR"), "/more_maps.skel.rs"));
}
use more_maps::*;

fn sample() {
    let builder = MoreMapsSkelBuilder::default();

    let open = builder.open().unwrap();
    let skel = open
        .load()
        .inspect_err(|fail| error!("Failed loading with {fail:#?}"))
        .unwrap();

    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        print!(".");
    }
}

fn main() {
    setup();
    sample();
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
        exit(1);
    }

    libbpf_rs::set_print(Some((PrintLevel::Debug, print_based_on_log)));
}
