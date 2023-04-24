use std::{process::exit, thread::sleep, time::Duration};

use libbpf_rs::PrintLevel;
use nix::unistd::Uid;

mod hello_world {
    include!(concat!(env!("OUT_DIR"), "/hello_world.skel.rs"));
}

/// Auto-completion doesn't play very nice with this generated module.
///
/// The generator will create a `[First][Second][Third]SkelBuilder` struct, where it removes the
/// `_` char, and uses a PascalCase convention for the builder.
///
/// In this case, it generates `HelloWorldSkelBuilder`
use hello_world::*;

fn print_based_on_log(level: PrintLevel, msg: String) {
    match level {
        PrintLevel::Debug => log::debug!("{}", msg),
        PrintLevel::Info => log::info!("{}", msg),
        PrintLevel::Warn => log::warn!("{}", msg),
    }
}

fn main() {
    env_logger::init();

    log::info!("Starting hello_world");

    if !Uid::effective().is_root() {
        log::error!("Must run as root!");
        exit(1);
    }

    libbpf_rs::set_print(Some((PrintLevel::Debug, print_based_on_log)));

    let builder = HelloWorldSkelBuilder::default();

    // Opens the bpf application.
    //
    // `OpenObject`
    let open = builder.open().unwrap();

    // Loads and verifies the bpf programs, returning an `Object`.
    //
    // https://docs.rs/libbpf-rs/latest/libbpf_rs/struct.Object.html
    let mut skel = open.load().unwrap();

    // `progs()` gets the programs.
    //
    // `hello()` is the program we have in `hello_world.bpf.c`.
    // let hello_program = skel.progs_mut().hello().fd();
    // println!("fd {fd:#?}");

    // Auto attaches based on program section (`SEC(...)`).
    // https://docs.rs/libbpf-rs/latest/libbpf_rs/struct.Link.html
    //
    // We get a `Link` back, which is an attached `Program`.
    // https://docs.rs/libbpf-rs/latest/libbpf_rs/struct.Link.html
    let attached = skel.attach();
    println!("{:#?}", attached);

    // Keep running the program, as the bpf will only run while it's alive.
    //
    // To see the logs, run:
    //
    // `sudo cat /sys/kernel/debug/tracing/trace_pipe`
    //
    // This is the simplest solution to communicating what's going on the bpf program, it's not a
    // good thing though, as if you have multiple bpf programs logging stuff, they'll all be using
    // the same file as output.
    loop {
        log::info!("...");
        sleep(Duration::from_secs(1));
    }
}
