#![feature(result_option_inspect)]
use libbpf_rs::{MapFlags, PrintLevel};
use nix::unistd::Uid;
use std::{process::exit, thread::sleep, time::Duration};

mod hello_tail_call {
    include!(concat!(env!("OUT_DIR"), "/hello_tail_call.skel.rs"));
}
use hello_tail_call::*;

fn print_based_on_log(level: PrintLevel, msg: String) {
    match level {
        PrintLevel::Debug => println!("[Debug] {}", msg),
        PrintLevel::Info => println!("[Info] {}", msg),
        PrintLevel::Warn => println!("[Warn] {}", msg),
    }
}

fn main() {
    env_logger::Builder::from_default_env()
        .target(env_logger::Target::Stdout)
        .init();

    println!("Starting hello_tail_call");

    if !Uid::effective().is_root() {
        log::error!("Must run as root!");
        exit(1);
    }

    libbpf_rs::set_print(Some((PrintLevel::Debug, print_based_on_log)));

    let builder = HelloTailCallSkelBuilder::default();

    let open = builder.open().unwrap();
    let mut skel = open
        .load()
        .inspect_err(|fail| println!("Failed loading with {fail:#?}"))
        .unwrap();
    let _attached = skel.attach().unwrap();

    let enter_execve_fd = skel.progs().enter_execve().fd().to_le_bytes();
    let ignore_fn_fd = skel.progs().ignore_opcode().fd().to_le_bytes();
    let timer_fn_fd = skel.progs().timer().fd().to_le_bytes();

    let mut maps = skel.maps_mut();
    let syscalls = maps.syscalls();

    // Key size must match what's on the bpf side.
    //
    // And `BPF_MAP_TYPE_PROG_ARRAY` did not like `key_size` being set to `__u64`, so we use `u32`.
    //
    // - `to_be_bytes` gave me an errno of `7` (E2BIG - argument list too long);
    // - `to_le_bytes` errno was `9` (EBADF - bad file descriptor);
    //
    // See errno values here:
    //
    // https://chromium.googlesource.com/chromiumos/docs/+/master/constants/errnos.md
    //
    // execve
    syscalls
        .update(&59_u32.to_le_bytes(), &enter_execve_fd, MapFlags::empty())
        .unwrap();

    // calls we care about
    syscalls
        .update(&222_u32.to_le_bytes(), &timer_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&223_u32.to_le_bytes(), &timer_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&224_u32.to_le_bytes(), &timer_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&225_u32.to_le_bytes(), &timer_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&226_u32.to_le_bytes(), &timer_fn_fd, MapFlags::empty())
        .unwrap();

    // ignore these that come up a lot
    syscalls
        .update(&21_u32.to_le_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&22_u32.to_le_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&25_u32.to_le_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&29_u32.to_le_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&56_u32.to_le_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&57_u32.to_le_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&63_u32.to_le_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&64_u32.to_le_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&66_u32.to_le_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&72_u32.to_le_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&73_u32.to_le_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&79_u32.to_le_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&98_u32.to_le_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&101_u32.to_le_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&115_u32.to_le_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&131_u32.to_le_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&134_u32.to_le_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&135_u32.to_le_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&139_u32.to_le_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&172_u32.to_le_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&233_u32.to_le_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&280_u32.to_le_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();
    syscalls
        .update(&291_u32.to_le_bytes(), &ignore_fn_fd, MapFlags::empty())
        .unwrap();

    loop {
        log::info!("...");

        sleep(Duration::from_secs(1));
    }
}
