use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

/// The file has to be named with something that can become a valid Rust identifier, it doesn't
/// convert things like `hello-world` into `hello_world`, as is usual for cargo projects.
///
/// If you don't follow this rule, the error you get is due to something like:
/// `pub struct Hello-worldSkelBuilder` being generated in `cargo build`.
///
/// This will generate a Rust module named `hello_world`.
const SRC: &str = "src/bpf/hello_world.bpf.c";

fn main() {
    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("hello_world.skel.rs");
    SkeletonBuilder::new()
        .source(SRC)
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
}
