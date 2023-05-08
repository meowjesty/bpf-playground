use libbpf_rs::PrintLevel;
use nix::unistd::Uid;
use std::{process::exit, thread::sleep, time::Duration};

mod hello_tail_call {
    include!(concat!(env!("OUT_DIR"), "/hello_tail_call.skel.rs"));
}
use hello_tail_call::*;

fn print_based_on_log(level: PrintLevel, msg: String) {
    match level {
        PrintLevel::Debug => log::debug!("{}", msg),
        PrintLevel::Info => log::info!("{}", msg),
        PrintLevel::Warn => log::warn!("{}", msg),
    }
}

fn main() {
    env_logger::init();

    log::info!("Starting hello_tail_call");

    if !Uid::effective().is_root() {
        log::error!("Must run as root!");
        exit(1);
    }

    libbpf_rs::set_print(Some((PrintLevel::Debug, print_based_on_log)));

    let builder = HelloTailCallSkelBuilder::default();

    let open = builder.open().unwrap();
    let mut skel = open.load().unwrap();
    let _attached = skel.attach().unwrap();

    // TODO(alex) [high] 2023-05-08: Interact with the `run` program.
    loop {
        log::info!("...");

        sleep(Duration::from_secs(1));
    }
}
