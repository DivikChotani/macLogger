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
use serde::{de::value, Deserialize, Serialize};


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
    let mut networkHandler = NetParsing::new();

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
        let temp = spawn_process("tcpdump", &vec!["-i", "en0", "-n", "-l", "-tttt", "-vvv", "-q"]);
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
                println!("{mes}");

                let log = match cmd {
                    LogType::Fs => handle_fs(&mes),
                    LogType::Sys => handle_sys(&mes),
                    LogType::Net => networkHandler.handle_net(&mes),
                };
                match log {
                    Some(val) => println!("{val:#?}"),
                    _ =>{}
                }
                
            },
            Err(_) => {break}
        }
    }
    for (_i, t) in polling_threads.into_iter().enumerate() {
        let _ = t.join();
    }
    Ok(())
}

fn handle_sys(log: &str) -> Option<Value>{
    (from_str::<serde_json::Value>(log)).ok()
}
struct NetParsing {
    prev: Option<Network>
}

impl NetParsing  {
    fn new() -> NetParsing{
        NetParsing {
            prev: None
        }
    }

    fn handle_net(&mut self, log: &str) -> Option<Value>{
        if let Some(ref mut prev) = self.prev.take() {
            let re = Regex::new(
                r"^\s*(?P<src>(?:\d{1,3}\.){4}\d+)\s*>\s*(?P<dst>(?:\d{1,3}\.){4}\d+):.+?(?P<len>\d+)\s*$"
            ).unwrap();

            let line = log.trim();

            if let Some(caps) = re.captures(line) {
                if let ArpIp::Ip(ref mut ip) = prev.req_type {
                    ip.source      = caps["src"].to_string();
                    ip.dest        = caps["dst"].to_string();
                    ip.payload_len = caps["len"].parse().unwrap();
                }
            }

            return Some(serde_json::to_value(prev).unwrap());
        }
        let mut network = Network::default();

        let re = Regex::new("(ARP|IP)").unwrap();
        let get_len = Regex::new(r"\blength[: ]+(\d+)\b").unwrap();
        if let Some(len) = get_len.captures(log) {
            let temp = &len[1];
            network.len = temp.trim().parse().unwrap();
        }

        let time_stamp = Regex::new(r"^([0-9\.\-\/]+)\s+([0-9\.\-:]+)").unwrap();
        if let Some(times) = time_stamp.captures(log) {
            let a = &times[1];
            let b = &times[2];
            network.time = a.to_owned()+" "+b;
        }
        if let Some(caps) = re.captures(log) {
            match &caps[1] {
                "IP" => {
                    network.req_type = ArpIp::Ip(IP::default());
                    network.req_type_str = "Ip".to_string();
                    

                    let re = Regex::new(r"\bproto\s+(?<proto>\w+)").unwrap();
                    if let Some(caps) = re.captures(log) {
                        match network.req_type {
                            ArpIp::Ip(ref mut ip) => {ip.proto = (&caps["proto"]).to_owned()},
                            _ => {},
                        }
                    }
                    self.prev = Some(network);
                    return None;
                },
                "ARP" => {

                    network.req_type = ArpIp::Arp(ARP::default());
                    network.req_type_str = "Arp".to_string();
                    
                    let re = Regex::new(r"\bARP,\s+(?P<type>\w+)").unwrap();
                    let has_re = Regex::new(r"\bwho-has\s+(?P<who_has>[\w\.:]+)").unwrap();
                    let tell_re = Regex::new(r"\btell\s+(?P<tell>[\w\.:]+)").unwrap();

                    let caps = re.captures(log);
                    let has_caps = has_re.captures(log);
                    let tell_caps = tell_re.captures(log);

                    if let (Some(caps), Some(has), Some(tell)) = (caps, has_caps, tell_caps)
                    {
                        match network.req_type {
                            ArpIp::Arp(ref mut arp) => {
                                arp.connect_type = (&caps["type"]).to_owned();
                                arp.tell = (&tell["tell"]).to_owned();
                                arp.who_has = (&has["who_has"]).to_owned()
                            },
                            _ => {},
                        }
                        
                    }
                    return Some(serde_json::to_value(network).unwrap())

                },
                &_ => {}
            }
        }
        
        None
    }
}
fn handle_fs(log: &str) -> Option<Value>{
    //get time
    let mut fs = FsHandler::default();
    let re = Regex::new(
        r"(?m)^\s*(\S+)\s+(\S+)\s+.*?\s+(\d+\.\d+)\s+(.+)$"
    ).unwrap();
    if let Some(caps) = re.captures(log) {
        fs.time  = (&caps[1]).to_string();  // 1st word
        fs.event_type = (&caps[2]).to_string();  // 2nd word
        fs.duration = (&caps[3]).to_string().parse().unwrap();  // 2nd‑to‑last word
        let  nameid = &caps[4];  // last word
        let a: Vec<&str> = nameid.split(".").collect();
        fs.p_name = a[0].to_string();
        fs.pid = a[1].to_string().parse().unwrap();
        
    } else{
        return None
    }

    let re = Regex::new(r"(\S+/\S+)").unwrap();

    let f = re
                    .find_iter(log)
                    .map(|m| m.as_str())
                    .collect::<Vec<&str>>()
                    .join(" ");
    fs.file_path = f;
    Some(serde_json::to_value(&fs).unwrap())
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

#[derive(Debug, Serialize, Deserialize, Default)]
struct FsHandler {
    time: String,
    event_type: String,
    file_path: String,
    duration: f64,
    p_name: String,
    pid: i32
}

#[derive(Default, Debug, Serialize, Deserialize,)]
enum ArpIp {
    Arp(ARP),
    Ip(IP),
    #[default]
    None,
}

#[derive(Default, Debug, Serialize, Deserialize,)]
struct Network {
    time: String,
    len: i32,
    req_type: ArpIp,
    req_type_str: String
}

#[derive(Default, Debug, Serialize, Deserialize,)]
struct ARP {
    connect_type: String,
    who_has: String,
    tell: String
}

#[derive(Default, Debug, Serialize, Deserialize,)]
struct IP {
    proto: String,
    payload_len: i32,
    source: String,
    dest: String,
}