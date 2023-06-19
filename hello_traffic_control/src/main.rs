#![feature(result_option_inspect)]

use std::io;

use libbpf_rs::{PrintLevel, TcHookBuilder, TC_INGRESS};
use log::{debug, error, info, warn};
use nix::{net::if_::if_nametoindex, unistd::Uid};

mod hello_traffic_control {
    include!(concat!(env!("OUT_DIR"), "/hello_traffic_control.skel.rs"));
}
use hello_traffic_control::*;

#[allow(dead_code)]
fn tc_drop() {
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
    // let mut tc_drop = _tc_drop.create().unwrap();
    // let _ = tc_drop.attach().unwrap();
}

#[allow(dead_code)]
fn tc_drop_ping(
    programs: &HelloTrafficControlProgs<'_>,
    interface_index: i32,
) -> libbpf_rs::TcHook {
    let mut tc_drop_ping = TcHookBuilder::new()
        .fd(programs.tc_drop_ping().fd())
        .ifindex(interface_index)
        .replace(true)
        .handle(2)
        .priority(2)
        .hook(TC_INGRESS);

    // We must call `create` here to create a `qdisc`, otherwise we fail with:
    //
    // > libbpf: Kernel error message: Parent Qdisc doesn't exists
    // > `Result::unwrap()` on an `Err` value: System(22)'
    //
    // The `qdisc` is a scheduler, and every output interface NEEDS a scheduler of some kind
    // (default is FIFO). It acts as a buffer between the kernel and the network interface.
    //
    // `qdisc` is short for "queueing discipline".
    //
    // Every interface contains both a `root` qdisc (egress), and an ingress `qdisc`.
    //
    // https://man7.org/linux/man-pages/man8/tc.8.html
    let mut tc_drop_ping = tc_drop_ping.create().unwrap();
    tc_drop_ping.attach().unwrap()
}

#[allow(dead_code)]
fn tc_ping_reply(
    programs: &HelloTrafficControlProgs<'_>,
    interface_index: i32,
) -> libbpf_rs::TcHook {
    let mut tc_ping_reply = TcHookBuilder::new()
        .fd(programs.tc_ping_reply().fd())
        .ifindex(interface_index)
        .replace(true)
        .handle(3)
        .priority(3)
        .hook(TC_INGRESS);

    let mut tc_ping_reply = tc_ping_reply.create().unwrap();
    tc_ping_reply.attach().unwrap()
}

/// We are attaching to the host network here, and messing with ingress packets, which means that if
/// you run this, your internet is probably going to be messed up (especially if running the
/// `tc_drop` program)!
///
/// To get back a working network interface:
///
/// 1. Check if the TC program(s) are running with `bpftool net list`, then;
/// 2. Run `tc filter del dev {iface} {direction}`, where `iface` for me is `enp5s0`, and flow is
/// `ingress`.
///
/// p.s.: don't ask me why I know this.
fn sample() {
    let builder = HelloTrafficControlSkelBuilder::default();
    let open = builder.open().unwrap();
    let skel = open
        .load()
        .inspect_err(|fail| error!("Failed loading with {fail:#?}"))
        .unwrap();

    let programs = skel.progs();
    let interface_index = if_nametoindex("enp5s0").unwrap() as i32;

    // let mut tc_drop_ping = tc_drop_ping(&programs, interface_index);
    let mut tc_ping_reply = tc_ping_reply(&programs, interface_index);

    let mut quit_buffer = String::new();
    loop {
        print!(".");

        std::thread::sleep(std::time::Duration::from_secs(1));
        match io::stdin().read_line(&mut quit_buffer) {
            Ok(read) => {
                if read > 0 {
                    break;
                } else {
                    continue;
                }
            }
            Err(fail) => {
                println!("Reading stdin failed with {fail:#?}");
                break;
            }
        }
    }

    // tc_drop_ping.destroy().unwrap();
    tc_ping_reply.destroy().unwrap();
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
