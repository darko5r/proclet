use proclet::{cstrings, run_pid_mount};
use std::env;

fn usage() -> ! {
    eprintln!("Usage: proclet -- <command> [args...]");
    std::process::exit(2);
}

fn main() {
    let args = env::args().collect::<Vec<_>>();
    let dashdash = args.iter().position(|a| a == "--").unwrap_or_else(|| usage());

    let cmd = &args[dashdash + 1..];
    if cmd.is_empty() {
        usage();
    }

    // use cstrings so the import isn't unused
    let cargs = cstrings(&cmd.iter().map(|s| s.as_str()).collect::<Vec<_>>());

    match run_pid_mount(&cargs) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("proclet: failed to start: {e}");
            std::process::exit(1);
        }
    }
}

