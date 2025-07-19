use structopt::StructOpt;
use nix::{libc::getuid, unistd};
use libc;
use std::{os::unix::process::CommandExt, process::{Command, Child}};

fn main() {
    let opt = Opt::from_args();
    let isRoot = unsafe {
        getuid() == 0
    };
    
    if (opt.files || opt.network) && !isRoot {
        println!("To track the network and/or file system you must run as root with sudo, use -h for help");
        return;
    }
    if !(opt.files || opt.network || opt.system) {
        println!("You must at least pass one flag to output logs, use -h for help");
        return;
    }

    //create the subprocess

    let mut sys = if opt.system {
        Some(spawnProcess("log", &vec!["stream", "--style", "json", "--info"]))
    } else {
        None
    };

    let mut fs = if opt.files {
        Some(spawnProcess("sudo", &vec!["fs_usage", "-w", "-f", "filesys"]))
    } else {
        None
    };

    let mut net = if opt.network {
        Some(spawnProcess("log", &vec!["stream", "--style", "json", "--info"]))
    } else {
        None
    };

   


    
}

fn spawnProcess(command: &str, args: &Vec<&str>) -> Child{
    let pid: i32;

    
    let res = Command::new(command).args(args).spawn().expect("Failed to run the command");
    return res
}
#[derive(Debug, StructOpt)]
#[structopt(name = "logger", help = "Specify what part of the mac to log, -s for the system and apps, -f for file based system calls, and -n for network packets")]
struct Opt {

    #[structopt(short = "s", long = "system")]
    system:bool,

    #[structopt(short = "f", long = "filesystem")]
    files:bool,

    #[structopt(short = "n", long = "network")]
    network:bool,

}
