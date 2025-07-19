use structopt::StructOpt;
use nix::{libc::getuid, unistd};
fn main() {
    let opt = Opt::from_args();
    let isRoot = unsafe {
        getuid() == 0
    };
    
    if (opt.files || opt.network) && !isRoot {
        println!("To track the network and/or file system you must run as root with sudo");
        return;
    }
    if !(opt.files || opt.network || opt.system) {
        println!("You must at least pass one flag to output logs, use -h for help");
        return;
    }
}

#[derive(Debug, StructOpt)]
#[structopt(name = "logger", help = "Specify what part of the mac to log,
                                    -s for the system and apps,
                                    -f for file based system calls
                                    and -n for network packets")]
struct Opt {

    #[structopt(short = "s", long = "system")]
    system:bool,

    #[structopt(short = "f", long = "filesystem")]
    files:bool,

    #[structopt(short = "n", long = "network")]
    network:bool,

}
