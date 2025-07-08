use std::{collections::HashMap, fmt::Display, path::{Path, PathBuf}, sync::{atomic::{AtomicBool, Ordering}, Arc}, time::Duration};

use anyhow::anyhow;
use aya::{maps::{Map, RingBuf}, programs::{links::{FdLink, PinnedLink}, Program, UProbe}};
use clap::{Parser, Subcommand};
#[rustfmt::skip]
use log::{debug, warn};
use serde::Deserialize;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[derive(Parser, Debug)]
#[command(name = "ebpf perf commands")]
#[command(about, long_about = None)]
struct Cli {
    #[command(flatten)]
    core_args: CoreArgs,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Parser, Debug)]
struct CoreArgs {
    #[arg(short, long, default_value="../build/test_program/test")]
    elf: PathBuf,

    #[arg(short, long, default_value="symbols.json")]
    symbols: PathBuf,

    #[arg(short, long)]
    description: Option<PathBuf>,
}
/// Loader for an ebpf monitor
#[derive(Subcommand, Debug)]
#[command(name = "uprobe", version, about, author)]
enum Commands {
    Load {
        #[arg(short, long)]
        monitor_after: bool,
        #[arg(short, long)]
        pin: bool
    },
    Unload,
    Monitor
}

/*#[repr(C)]
#[derive(Debug)]
struct PerfData {
    pid: i32,
    call_time: u64,
    ip: u64,
    base_code_addr: u64,
    params: [u64; 6],
    ret: u64
    // rdi, rsi, rdx, rcx, r8, r9
    // rax for returns (x86_64)
    // other args are passed on the stack
}*/

type PerfData = perf_data;

impl PerfData {
    pub fn addr(&self, symbols: &Symbols) -> u64 {
        self.ip - self.base_code_addr + symbols.offset
    }

    pub fn get_symbol<'a>(&self, symbols: &'a Symbols) -> Option<&'a FuncSymbol> {
        let addr = self.addr(symbols);
        symbols.functions.iter().find(|s| { addr == s.addr || s.returns.contains(&addr) })
    }

    pub fn get_label<'a>(&self, symbols: &'a Symbols) -> Option<&'a str> {
        let sym = self.get_symbol(symbols);
        sym.map(|sym| sym.label.as_str())
    }

    fn log(&self, symbols: &Symbols, desc: &Option<Description>) -> anyhow::Result<()>{
        let sym = self.get_symbol(symbols);
        println!("\nt={} name={} pid={} ip={:x} params={:?} ret={:?}", self.call_time, if let Some(sym) = sym {&sym.label} else { "" }, self.pid, self.ip, self.params, self.ret);
        let sym = sym.ok_or(anyhow!("Could not find symbol at addr {}", self.addr(symbols)))?;
        let is_entry = sym.addr == self.addr(symbols);
        if let Some(desc) = desc {
            let desc = desc.functions.get(&sym.label);
            if let Some(desc) = desc {
                if is_entry {
                    for (i, arg) in desc.args.iter().enumerate() {
                        let val = self.params[i];
                        // this has to be changed
                        let arg_val = format!("{} {}={}", arg.0, arg.1, val);
                        println!("{}", arg_val);
                    }
                } else {
                    let arg_val = format!("{} {}={}", desc.ret, "ret", self.ret);
                    println!("{}", arg_val);
                }
            }
        }

        // print the values of the globals
        // This doesn't do anything right now, but i think it might make sense to write the globals
        // into a seperate hashmap that where addr => value, these will have to be generated with
        // the ebpf program

        //for global in &symbols.globals {
        //    println!("\tglobal: {}=", global.label);
        //}

        Ok(())
    }
}

fn handle_data(data: &[u8], symbols: &Symbols, desc: &Option<Description>) -> anyhow::Result<()> {
    let data: &PerfData = unsafe { &*(data.as_ptr() as *const PerfData)};
    match data.log(symbols, desc) {
        Ok(()) => (),
        Err(e) => log::error!("Error occurred while logging: {e}")
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct FuncSymbol {
    pub addr: u64,
    pub label: String,
    pub returns: Vec<u64>
}

#[derive(Debug, Deserialize)]
struct VarSymbol {
    pub addr: u64,
    pub label: String,
    pub size: u64
}

#[derive(Debug, Deserialize)]
struct Symbols {
    pub offset: u64,
    pub functions: Vec<FuncSymbol>,
    pub globals: Vec<VarSymbol>,
}

#[derive(Debug, Deserialize)]
struct TypeIdentifier(String, String);

#[derive(Debug, Deserialize)]
struct FuncDesc {
    pub args: Vec<TypeIdentifier>,
    pub ret: String,
}

#[derive(Debug, Deserialize)]
struct Description {
    pub structs: HashMap<String, Vec<TypeIdentifier>>,
    pub functions: HashMap<String, FuncDesc>,
    pub type_map: HashMap<String, String>,
    pub vars: HashMap<String, String>,
}

pub struct Context {
    elf: PathBuf,
    symbols: Symbols,
    description: Option<Description>
}

pub fn load(ebpf: &mut aya::Ebpf, pin: bool, ctx: &Context) -> anyhow::Result<()> {
    let elf = std::fs::canonicalize(&ctx.elf)?;

    // dart around the borrow checker like this
    let entry: &mut UProbe = ebpf.program_mut("uprobe_entry").expect("uprobe_entry is not a uprobe").try_into()?;
    entry.load()?;
    if pin {
        entry.pin("/sys/fs/bpf/uprobe_entry")?;
    }
    log::info!("Loaded uprobe_entry");

    // attach the ebpf to each symbol
    for symbol in &ctx.symbols.functions {
        let link_id = entry.attach(None, symbol.addr, &elf, None)?;
        if pin {
            let link = entry.take_link(link_id).expect("couldnt take the link");
            let fd_link: FdLink = link.try_into().unwrap();
            let pin_path = format!("/sys/fs/bpf/{}_{}_entry", symbol.label, symbol.addr);
            fd_link.pin(pin_path).unwrap();
        }
    }

    let ret: &mut UProbe = ebpf.program_mut("uprobe_ret").expect("uprobe_entry is not a uprobe").try_into()?;
    ret.load()?;
    if pin {
        ret.pin("/sys/fs/bpf/uprobe_ret")?;
    }
    log::info!("Loaded uprobe_ret");
    for symbol in &ctx.symbols.functions {
        for ret_addr in &symbol.returns {
            let link_id = ret.attach(None, *ret_addr, &elf, None)?;
            if pin {
                let link = ret.take_link(link_id).expect("couldnt take the link");
                let fd_link: FdLink = link.try_into().unwrap();
                let pin_path = format!("/sys/fs/bpf/{}_{}_ret", symbol.label, symbol.addr);
                fd_link.pin(pin_path).unwrap();
            }
        }
    }
    let map = ebpf.map_mut("rb").expect("Could not find map");
    if pin {
        //    map.pin("/sys/fs/bpf/rb")?;
    }
    log::info!("Loaded and Attach uprobe ebpf and maps");
    Ok(())
}

pub fn monitor(ebpf: &mut aya::Ebpf, is_pinned: bool, ctx: &Context) -> anyhow::Result<()> {
    // cant get a MapRefMut
    if is_pinned {
        // This doesn't work
        // If the map is pinned, we cant just get it 
        let map_data = aya::maps::MapData::from_pin("/sys/fs/bpf/rb").unwrap();
        let mut map = Map::RingBuf(map_data);
        let mut ring_buf = RingBuf::try_from(&mut map).unwrap();
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.expect("Failed Ctrl C Listen");
            println!("Ctrl-C Received");
            r.store(false, Ordering::SeqCst);
        });

        while running.load(Ordering::SeqCst) {
            // read the item from the ringbuf if it has it, then handle it
            while let Some(item) = ring_buf.next() {
                handle_data(&item, &ctx.symbols, &ctx.description)?;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    else {
        let mut ring_buf = RingBuf::try_from(ebpf.map_mut("rb").expect("Could not find map to monitor"))?;
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.expect("Failed Ctrl C Listen");
            println!("Ctrl-C Received");
            r.store(false, Ordering::SeqCst);
        });

        while running.load(Ordering::SeqCst) {
            // read the item from the ringbuf if it has it, then handle it
            while let Some(item) = ring_buf.next() {
                handle_data(&item, &ctx.symbols, &ctx.description)?;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }


    Ok(())
}

fn unpin_program(path: &str) -> anyhow::Result<()> {
    match aya::programs::UProbe::from_pin(path, aya::programs::ProbeKind::UProbe) {
        Ok(prog) => prog.unpin()?,
        Err(e) => log::error!("Program {path} does not exist in bpffs {e}")
    };
    Ok(())
}

fn unpin_link(path: &str) -> anyhow::Result<()> {
    match PinnedLink::from_pin(path) {
        Ok(link) => {let _ = link.unpin()?;},
        Err(e) => {log::error!("Link {path} does not exist in bpffs {e}");}
    };
    Ok(())
}

pub fn unload(_ebpf: &mut aya::Ebpf, ctx: &Context) -> anyhow::Result<()> {

    unpin_program("/sys/fs/bpf/uprobe_entry")?;
    unpin_program("/sys/fs/bpf/uprobe_ret")?;

    // attach the ebpf to each symbol
    for symbol in &ctx.symbols.functions {
        let pin_path = format!("/sys/fs/bpf/{}_{}_entry", symbol.label, symbol.addr);
        unpin_link(&pin_path)?;
    }

    for symbol in &ctx.symbols.functions {
        for ret_addr in &symbol.returns {
            let pin_path = format!("/sys/fs/bpf/{}_{}_ret", symbol.label, ret_addr);
            unpin_link(&pin_path)?;
        }
    }
    // cant really unpin maps, have to remove with e.g. rm /sys/fs/bpf/rb
    /*let path = "/sys/fs/bpf/rb";
      match aya::maps::MapInfo::from_pin(path) {
      Ok(map) => prog..unpin(),
      Err(e) => log::error!("Map {path} does not exist in bpffs {e}")
      };*/

    log::info!("Unloaded ebpf");
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();
    env_logger::init();
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // get the symbols into a hashmap
    let symbols = std::fs::read_to_string(&args.core_args.symbols).expect(&format!("No symbols file at {:?}", args.core_args.symbols));
    let symbols: Symbols = serde_json::from_str(&symbols)?;
    log::info!("Loaded symbols");
    println!("{:#?}", symbols);

    // read the description of the types
    let description: Option<Description> = args.core_args.description
        .map(|d| {
            std::fs::read_to_string(d).expect("Provided description file does not exist")
        }).map(|s| serde_json::from_str(&s).expect("Error reading description file"));

    log::info!("Loading uprobe");
    let mut ebpf = aya::Ebpf::load_file("../build/uprobe.bpf.o")?;

    let elf = std::fs::canonicalize(&args.core_args.elf)?;
    let ctx: Context = Context { elf: elf, symbols, description };

    log::info!("Running Command");
    match &args.command {
        Commands::Load{ monitor_after, pin } => {
            let res = load(&mut ebpf, *pin, &ctx);
            if res.is_ok() && *monitor_after {
                return monitor(&mut ebpf, *pin, &ctx)
            }
            res
        },
        Commands::Unload => {
            unload(&mut ebpf, &ctx)
        },
        Commands::Monitor => {
            monitor(&mut ebpf, false, &ctx)
        }
    }?;

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    //let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
    //    env!("OUT_DIR"),
    //   "/rust"
    //)));


    // this is used if using a rust-compiled ebpf
    /*if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
    // This can happen if you remove all log statements from your eBPF program.
    warn!("failed to initialize eBPF logger: {e}");
    }*/

    Ok(())
}
