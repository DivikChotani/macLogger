use libc;
use nix::{libc::getuid, unistd};
use signal_hook::{
    consts::{SIGINT, SIGKILL, SIGTERM},
    iterator::{exfiltrator::raw, Signals},
};
use std::{
    any::Any,
    error::Error,
    os::{fd::{self, AsFd, AsRawFd, FromRawFd, RawFd}, unix::process::CommandExt},
    process::{Child, Command, Stdio},
};

use interprocess::unnamed_pipe::pipe;
use interprocess::unnamed_pipe::Sender;
use structopt::StructOpt;
use std::fs::File;

fn main() -> Result<(), Box<dyn Error>> {
    let opt = Opt::from_args();
    let isRoot = unsafe { getuid() == 0 };

    let mut signals = (Signals::new([SIGINT, SIGKILL, SIGTERM]))?;

    if (opt.files || opt.network) && !isRoot {
        return Err("To track the network and/or file system you must run as root with sudo, use -h for help".into());
    }
    if !(opt.files || opt.network || opt.system) {
        return Err("You must at least pass one flag to output logs, use -h for help".into());
    }

    //create the subprocess
    let (sender, receiver) = pipe()?;
    let senderfd = sender.as_fd().try_clone_to_owned()?.as_raw_fd();

    let mut sys = if opt.system {
        let mut temp = spawn_process("log", &vec!["stream", "--style", "json", "--info"], senderfd);
        // temp.wait();
        Some(temp)
    } else {
        None
    };

    let mut fs = if opt.files {
        let mut temp = (spawn_process("fs_usage", &vec!["-w", "-f", "filesys"], senderfd));
        // temp.wait();
        Some(temp)
    } else {
        None
    };

    let mut net = if opt.network {
        let mut temp = (spawn_process("tcpdump", &vec!["-i", "en0", "-l", "-n"], senderfd));
        // temp.wait();
        Some(temp)
    } else {
        None
    };

    Ok(())
}

fn spawn_process(command: &str, args: &Vec<&str>, f: RawFd) -> Child {
    
    let file = unsafe {File::from_raw_fd(f)};
    let mut res: Child = Command::new(command)
        .args(args)
        .stdout(file)
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
