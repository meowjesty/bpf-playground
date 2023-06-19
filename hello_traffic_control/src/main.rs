#![feature(result_option_inspect)]

use libbpf_rs::{PrintLevel, TcHookBuilder, TC_INGRESS};
use log::{debug, error, info, warn};
use nix::{net::if_::if_nametoindex, unistd::Uid};

mod hello_traffic_control {
    include!(concat!(env!("OUT_DIR"), "/hello_traffic_control.skel.rs"));
}
use hello_traffic_control::*;

fn sample() {
    let builder = HelloTrafficControlSkelBuilder::default();
    let open = builder.open().unwrap();
    let skel = open
        .load()
        .inspect_err(|fail| error!("Failed loading with {fail:#?}"))
        .unwrap();

    let programs = skel.progs();
    let interface_index = if_nametoindex("enp5s0").unwrap() as i32;

    // If we try to hook multiple TCs (with the same config), we get a warning after the second
    // hook:
    //
    // > libbpf: Kernel error message: Exclusivity flag on, cannot modify
    //
    // let mut _tc_drop = TcHookBuilder::new()
    //     .fd(programs.tc_drop().fd())
    //     .ifindex(interface_index)
    //     .replace(true)
    //     .handle(1)
    //     .priority(1)
    //     .hook(TC_INGRESS);
    // let mut tc_drop = tc_drop.create().unwrap();
    // let _ = tc_drop.attach().unwrap();

    let mut tc_drop_ping = TcHookBuilder::new()
        .fd(programs.tc_drop_ping().fd())
        .ifindex(interface_index)
        .replace(true)
        .handle(1)
        .priority(1)
        .hook(TC_INGRESS);

    // We must call `create` here to create a `qdisc`, otherwise we fail with:
    //
    // > libbpf: Kernel error message: Parent Qdisc doesn't exists
    // > `Result::unwrap()` on an `Err` value: System(22)'
    //
    // The `qdisc` is a scheduler, and every output interface NEEDS a scheduler of some kind
    // (default is FIFO).
    //
    // `qdisc` is short for "queueing discipline".
    //
    // Every interface contains both a `root` qdisc (egress), and an ingress `qdisc`.
    let mut tc_drop_ping = tc_drop_ping.create().unwrap();
    let _ = tc_drop_ping.attach().unwrap();

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
