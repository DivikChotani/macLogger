use nix::libc::getuid;
use signal_hook::consts::{SIGINT, SIGTERM};
use std::{
    any::type_name, error::Error, io::{BufRead, BufReader}, process::{Child, Command, Stdio}, thread::JoinHandle
};

use signal_hook::flag;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::thread;
use structopt::StructOpt;
use serde_json::{from_str, Result as JsonResult, Value};
use serde_json::json;
use crossbeam_channel::unbounded;
use regex::Regex;
use serde::{Deserialize, Serialize};


#[derive(Debug, Clone, Copy)]
enum LogType {
    Sys,
    Fs,
    Net,
}
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
    let sys = if opt.system {
        let temp = spawn_process("log", &vec!["stream", "--style", "ndjson", "--info"]);
        Some(temp)
    } else {
        None
    };

    let fs = if opt.files {
        let temp = spawn_process("fs_usage", &vec!["-w", "-f", "filesys"]);
        // temp.wait();
        Some(temp)
    } else {
        None
    };

    let net = if opt.network {
        let temp = spawn_process("tcpdump", &vec!["-i", "en0", "-l", "-n"]);
        // temp.wait();
        Some(temp)
    } else {
        None
    };

    let (s, r) = unbounded();

    let child_ps = vec![(LogType::Sys, sys), (LogType::Fs, fs), (LogType::Net, net)];

    let term = Arc::new(AtomicBool::new(false));

    flag::register(SIGINT, Arc::clone(&term))?;
    flag::register(SIGTERM, Arc::clone(&term))?;

    let mut polling_threads: Vec<JoinHandle<()>> = Vec::new();

    for (cmd, child) in child_ps {
        let Some(mut kid) = child else {
            continue;
        };

        let term_ref = Arc::clone(&term);
        let send = s.clone();
        let t = thread::spawn(move || {
            let kid_stdout = kid.stdout.take().unwrap();
            let mut reader = BufReader::new(kid_stdout);
            while !term_ref.load(std::sync::atomic::Ordering::Relaxed) {
                let mut line = String::new();
                if let Ok(_) = reader.read_line(&mut line) {
                    match send.send((cmd, line)) {
                        Ok(_) => {}
                        Err(_) => {
                            println!("Failed to send message");
                            return;
                        }
                    }
                }
            }
            let err = kid.kill();
            let Ok(_) = err else {
                println!("Failed to kill child process");
                return;
            };
            let _ = kid.wait();
        });
        polling_threads.push(t);
    }
    drop(s);
    while !term.load(std::sync::atomic::Ordering::Relaxed) {
        match r.recv() {
            Ok((cmd, mes)) => {
                let mes = mes.trim();
                handle_fs(&mes);
                // handle_sys(&mes);

                // let json_out = match cmd {
                //     LogType::Sys => handle_sys(&mes),
                    
                // }
                //println!("{mes}");
            },
            Err(_) => {break}
        }
    }
    for (_i, t) in polling_threads.into_iter().enumerate() {
        let _ = t.join();
    }
    Ok(())
}

fn handle_sys(log: &str) -> Value{
    from_str::<serde_json::Value>(log).expect("could not jsonize")
}

fn handle_fs(log: &str){

    //get time
    let raw_time = Regex::new(r"^([\.:0-9]+)").unwrap();
    let Some(time) = raw_time.captures(log) else {
        return
    };
    let time = &time[0];
    
    let name_id = Regex::new(r"[\w\.]+$").unwrap();
    let Some(nameid) = name_id.captures(log) else {
        return
    };
    let nameid = &nameid[0];
    let list: Vec<&str> = nameid.split(".").collect();
    let p_name = list[0].to_string();
    let pid = list[list.len()-1].to_string();
    println!("{nameid}");

}

fn spawn_process(command: &str, args: &Vec<&str>) -> Child {
    let res: Child = Command::new(command)
        .args(args)
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to run the command");
    res
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

#[derive(Serialize, Deserialize)]
struct FsHandler {
    time: String,
    event_type: String,
    file_path: String,
    duration: f64,
    p_name: String,
    pid: i32
}
