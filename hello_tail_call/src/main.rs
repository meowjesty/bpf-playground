use libbpf_rs::{MapFlags, PrintLevel};
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
    // TODO(alex) [high] 2023-05-11: Debug in lldb why we crash here!
    let mut skel = open.load().unwrap();
    let _attached = skel.attach().unwrap();

    let enter_execve_fd = skel.progs().enter_execve().fd().to_be_bytes();
    let ignore_fn_fd = skel.progs().ignore_opcode().fd().to_be_bytes();
    let timer_fn_fd = skel.progs().timer().fd().to_be_bytes();

    let mut maps = skel.maps_mut();
    let syscalls = maps.syscalls();

    // execve
    syscalls
        .update(&59_u64.to_be_bytes(), &enter_execve_fd, MapFlags::empty())
        .unwrap();

    // calls we care about
    syscalls
        .update(&222_u64.to_be_bytes(), &timer_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&223_u64.to_be_bytes(), &timer_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&224_u64.to_be_bytes(), &timer_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&225_u64.to_be_bytes(), &timer_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&226_u64.to_be_bytes(), &timer_fn_fd, MapFlags::empty())
        .unwrap();

    // ignore these that come up a lot
    syscalls
        .update(&21_u64.to_be_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&22_u64.to_be_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&25_u64.to_be_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&29_u64.to_be_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&56_u64.to_be_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&57_u64.to_be_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&63_u64.to_be_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&64_u64.to_be_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&66_u64.to_be_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&72_u64.to_be_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&73_u64.to_be_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&79_u64.to_be_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&98_u64.to_be_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&101_u64.to_be_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&115_u64.to_be_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&131_u64.to_be_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&134_u64.to_be_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&135_u64.to_be_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&139_u64.to_be_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&172_u64.to_be_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&233_u64.to_be_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&280_u64.to_be_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&291_u64.to_be_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();

    loop {
        log::info!("...");

        sleep(Duration::from_secs(1));
    }
}
