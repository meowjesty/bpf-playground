use const_format::formatcp;
use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

const PROGRAM_NAME: &str = "hello_tail_call";
const BPF_FILE: &str = formatcp!("src/bpf/{PROGRAM_NAME}.bpf.c");
const RUST_FILE: &str = formatcp!("{PROGRAM_NAME}.skel.rs");

fn main() {
    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push(RUST_FILE);

    SkeletonBuilder::new()
        .source(BPF_FILE)
        .build_and_generate(&out)
        .unwrap();

    println!("cargo:rerun-if-changed={BPF_FILE}");
}
