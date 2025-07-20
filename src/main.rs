use libc::{self, mkfifo};
use nix::{libc::getuid, unistd, sys::stat};
use signal_hook::{
    consts::{SIGINT, SIGKILL, SIGTERM},
    iterator::{exfiltrator::raw, Signals},
};
use std::{
    any::Any, error::Error, io::{BufRead, BufReader, Read}, iter::Enumerate, os::fd::{self, AsFd, AsRawFd, FromRawFd, RawFd}, process::{Child, ChildStdout, Command, Stdio}, thread::{JoinHandle, Thread}
};

use structopt::StructOpt;
use std::fs::File;
use std::mem;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool};
use signal_hook::flag;
use std::thread;

use crossbeam_channel::unbounded;

fn main() -> Result<(), Box<dyn Error>> {
    let opt = Opt::from_args();
    let is_root = unsafe { getuid() == 0 };


    if (opt.files || opt.network) && !is_root {
        return Err("To track the network and/or file system you must run as root with sudo, use -h for help".into());
    }
    if !(opt.files || opt.network || opt.system) {
        return Err("You must at least pass one flag to output logs, use -h for help".into());
    }

    //create the subprocess
    let mut sys = if opt.system {
        let mut temp = spawn_process("log", &vec!["stream", "--style", "ndjson", "--info"]);
        Some(temp)
    } else {
        None
    };

    let mut fs = if opt.files {
        let mut temp = (spawn_process("fs_usage", &vec!["-w", "-f", "filesys"]));
        // temp.wait();
        Some(temp)
    } else {
        None
    };

    let mut net = if opt.network {
        let mut temp = (spawn_process("tcpdump", &vec!["-i", "en0", "-l", "-n"]));
        // temp.wait();
        Some(temp)
    } else {
        None
    };

    let (s, r) = unbounded();

    let child_ps = vec![("log",sys), ("fs_usage", fs), ("tcpdump", net)];

    let term = Arc::new(AtomicBool::new(false));

    flag::register(SIGINT, Arc::clone(&term))?;
    flag::register(SIGTERM, Arc::clone(&term))?;

    let mut polling_threads: Vec<JoinHandle<()>> = Vec::new();

    for (cmd, child) in child_ps {

        let Some(kid) = child else {
            continue;
        };

        let kid = kid.stdout.unwrap();
        let mut reader = BufReader::new(kid);
        let term_ref = Arc::clone(&term);
        let send = s.clone();
        let t = thread::spawn(move || {
            while !term_ref.load(std::sync::atomic::Ordering::Relaxed) {
                let mut line = String::new();
                if let Ok(n) = reader.read_line(&mut line) {
                    send.send(cmd);
                }
            }
        });
        polling_threads.push(t);
    };

    for message in r.into_iter() {
        println!("{message}");
    }

    for (i, t) in polling_threads.into_iter().enumerate() {
        println!("{i}");
        t.join();
    }

    Ok(())
}

fn spawn_process(command: &str, args: &Vec<&str>) -> Child {
    let mut res: Child = Command::new(command)
        .args(args)
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to run the command");
    return res;
}
#[derive(Debug, StructOpt)]
#[structopt(
    name = "logger",
    help = "Specify what part of the mac to log, -s for the system and apps, -f for file based system calls, and -n for network packets"
)]
struct Opt {
    #[structopt(short = "s", long = "system")]
    system: bool,

    #[structopt(short = "f", long = "filesystem")]
    files: bool,

    #[structopt(short = "n", long = "network")]
    network: bool,
}
