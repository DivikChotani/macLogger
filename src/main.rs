use libc;
use nix::{libc::getuid, unistd};
use signal_hook::{
    consts::{SIGINT, SIGKILL, SIGTERM},
    iterator::{exfiltrator::raw, Signals},
};
use std::{
    any::Any, error::Error, io::{BufRead, Read}, os::{fd::{self, AsFd, AsRawFd, FromRawFd, RawFd}}, process::{Child, Command, Stdio}
};

use structopt::StructOpt;
use std::fs::File;
use std::io::BufReader;
use std::mem;

fn main() -> Result<(), Box<dyn Error>> {
    let opt = Opt::from_args();
    let isRoot = unsafe { getuid() == 0 };


    if (opt.files || opt.network) && !isRoot {
        return Err("To track the network and/or file system you must run as root with sudo, use -h for help".into());
    }
    if !(opt.files || opt.network || opt.system) {
        return Err("You must at least pass one flag to output logs, use -h for help".into());
    }

    //create the subprocess

    let mut sys = if opt.system {
        let mut temp = spawn_process("log", &vec!["stream", "--style", "json", "--info"]);
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
    let mut signals = (Signals::new([SIGINT, SIGTERM]))?;

    let mut sys = sys.unwrap();
    let mut last_few = String::with_capacity(10);
    let k = last_few.len();
    println!("{k}");
    let mut stay = true;
    while stay {
        for sig in signals.forever() {
            match sig {
                SIGINT |
                SIGTERM => {
                    sys.kill();
                    sys.wait();
                    stay = false;
                    break;
                },
                _ => {},
            }
            println!("HERE");

        }
        sys.stdout.take().unwrap().read_to_string(&mut last_few);

    }
    println!("{last_few}");

   
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
