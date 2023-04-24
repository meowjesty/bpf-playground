use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::{self, Path, PathBuf},
    process::exit,
    sync::mpsc::{self, Receiver, Sender},
    time::Duration,
};

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
use notify::{PollWatcher, Watcher};

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
    let path = Path::new("/sys/kernel/debug/tracing/trace_pipe");
    watch_file(&path);
}

struct TracePipeFileEvent {
    file_path: PathBuf,
    tx: Sender<String>,
}

impl notify::EventHandler for TracePipeFileEvent {
    fn handle_event(&mut self, event: notify::Result<notify::Event>) {
        if let Ok(event) = event {
            log::trace!("Event: {:?}", event);

            if let notify::EventKind::Modify(_) = event.kind {
                let contents = fs::read_to_string(&self.file_path).unwrap();
                self.tx.send(contents).unwrap();
            }
        }
    }
}

fn watch_file(path: &Path) {
    let (tx, rx) = mpsc::channel();

    let mut watcher = PollWatcher::new(
        TracePipeFileEvent {
            tx,
            file_path: PathBuf::from(path),
        },
        notify::Config::default()
            .with_poll_interval(Duration::from_secs(2))
            .with_compare_contents(true),
    )
    .unwrap();

    watcher
        .watch(path, notify::RecursiveMode::NonRecursive)
        .unwrap();

    loop {
        log::info!("Trace: {:?}", rx.recv().unwrap());
    }
}
