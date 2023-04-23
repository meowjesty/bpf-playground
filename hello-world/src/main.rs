use std::process::exit;

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

fn main() {
    if !Uid::effective().is_root() {
        eprintln!("Must run as root!");
        exit(1);
    }

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
    // To see the logs
    loop {}
}