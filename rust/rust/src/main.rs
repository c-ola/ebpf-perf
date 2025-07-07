use std::{collections::HashMap, fmt::Display, path::{Path, PathBuf}, sync::{atomic::{AtomicBool, Ordering}, Arc}, time::Duration};

use anyhow::anyhow;
use aya::{maps::RingBuf, programs::UProbe};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use serde::Deserialize;

#[derive(Debug, Parser)]
struct Opt {
    #[arg(short, long)]
    pid: Option<i32>,
    
    #[arg(short, long)]
    elf: Option<PathBuf>,

    #[arg(short, long, default_value="symbols.json")]
    symbols: PathBuf,

    #[arg(short, long, default_value="desc.json")]
    description: PathBuf,
}

#[repr(C)]
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
}

impl PerfData {
    pub fn addr(&self, symbols: &Symbols) -> u64 {
        self.ip - self.base_code_addr + symbols.offset
    }

    pub fn get_symbol<'a>(&self, symbols: &'a Symbols) -> Option<&'a FuncSymbol> {
        symbols.functions.iter().find(|s| { self.addr(symbols) == s.addr || s.returns.contains(&self.ip) })
    }

    pub fn get_label<'a>(&self, symbols: &'a Symbols) -> Option<&'a str> {
        let sym = symbols.functions.iter().find(|s| { self.addr(symbols) == s.addr || s.returns.contains(&self.ip) });
        sym.map(|sym| sym.label.as_str())
    }
}

impl PerfData {
    fn log(&self, symbols: &Symbols, desc: &Description) {
        let sym = self.get_symbol(symbols);
        if let Some(sym) = sym {
            let label = self.get_label(symbols);
            let is_entry = sym.addr == self.addr(symbols);
            let desc = label.map(|label| desc.functions.get(label));
            if let Some(desc) = desc {
                if let Some(desc) = desc {
                    let get_arg_str = |arg: &TypeIdentifier, val: u64| {
                        match arg.0.as_str() {
                            "int" => format!("{} {}={}", arg.0, arg.1, val),
                            "unsigned_long" => format!("{} {}={}", arg.0, arg.1, val),
                            "long" => format!("{} {}={}", arg.0, arg.1, val),
                            "float" => format!("{} {}={}", arg.0, arg.1, "not implemented for floats"),
                            _ => format!(""),
                        }
                    };
                    if is_entry {
                        for (i, arg) in desc.args.iter().enumerate() {
                            let val = self.params[i];
                            let arg_val = get_arg_str(arg, val);
                            println!("{}", arg_val);
                        }
                    } else {
                        let arg_val = get_arg_str(&TypeIdentifier(desc.ret.clone(), "ret".to_string()), self.ret);
                        println!("{}", arg_val);
                    }
                }
            }
        }
        println!("name={} pid={} ip={:x} params={:?} ret={:?}", if let Some(sym) = sym {&sym.label} else { "" }, self.pid, self.ip, self.params, self.ret)
    }
}

fn handle_data(data: &[u8], symbols: &Symbols, desc: &Description) {
    let data: &PerfData= unsafe { &*(data.as_ptr() as *const PerfData)};
    data.log(symbols, desc);
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    let elf = if let Some(elf) = &opt.elf {
        elf
    } else {Path::new("./build/test_program/test")};

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

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    //let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
    //    env!("OUT_DIR"),
    //   "/rust"
    //)));
    let mut ebpf = aya::Ebpf::load_file("../build/uprobe.bpf.o")?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }
    let program: &mut UProbe = ebpf.program_mut("uprobe_entry").unwrap().try_into()?;
    program.load()?;

    // get the symbols into a hashmap
    let symbols = std::fs::read_to_string(opt.symbols).unwrap();
    let symbols: Symbols = serde_json::from_str(&symbols)?;

    // attach the ebpf to each symbol
    for symbol in &symbols.functions {
        program.attach(None, symbol.addr, elf, opt.pid)?;
        for ret_addr in &symbol.returns {
            program.attach(None, *ret_addr, elf, opt.pid)?;
        }
    }

    // read the description of the types
    let desc = std::fs::read_to_string(opt.description).unwrap();
    let desc: Description = serde_json::from_str(&desc)?;
    println!("{:#?}", desc);

    // get the ringbuf
    let mut ring_buf = RingBuf::try_from(ebpf.map_mut("rb").expect("Could not find map"))?;

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
            handle_data(&item, &symbols, &desc);
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}
