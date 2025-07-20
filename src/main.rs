use libc::{self, mkfifo};
use nix::{libc::getuid, unistd, sys::stat};
use signal_hook::{
    consts::{SIGINT, SIGKILL, SIGTERM},
    iterator::{exfiltrator::raw, Signals},
};
use std::{
    any::Any, error::Error, io::{BufRead, Read, BufReader}, os::{fd::{self, AsFd, AsRawFd, FromRawFd, RawFd}}, process::{Child, Command, Stdio}
};

use structopt::StructOpt;
use std::fs::File;
use std::mem;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool};
use signal_hook::flag;
use tempdir::TempDir;

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
    let tmp_dir = TempDir::new("test_fifo").unwrap();
    let fifo_path = tmp_dir.path().join("foo.pipe");

    unistd::mkfifo(&fifo_path, stat::Mode::S_IRWXU)?;

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
    let term = Arc::new(AtomicBool::new(false));
    let mut sys = sys.unwrap();
    let sys_stdout = sys.stdout.take().unwrap();
    let mut reader = BufReader::new(sys_stdout);
    unsafe {
        flag::register(SIGINT, Arc::clone(&term))?;
        flag::register(SIGTERM, Arc::clone(&term))?;
    };

    while !term.load(std::sync::atomic::Ordering::Relaxed) {
        let mut line = String::new();
        if let Ok(n) = reader.read_line(&mut line) {
            if n == 0 {
                println!("GY");
            }
            println!("{line}");
        }
    }
    sys.kill();
    sys.wait();



    

  

   
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
