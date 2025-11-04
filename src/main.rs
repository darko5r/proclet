mod cli;

use clap::Parser;
use cli::{Cli, Ns};
use proclet::{cstrings, run_pid_mount, ProcletOpts};
use std::ffi::CString;

fn main() {
    let cli = Cli::parse();

    if cli.ns.iter().any(|n| matches!(n, Ns::Net)) {
        eprintln!("proclet: --ns net is not implemented yet (placeholder)");
        std::process::exit(64); // EX_USAGE
    }

    // Build argv
    let cargs: Vec<CString> = cstrings(
        &cli.cmd.iter().map(|s| s.as_str()).collect::<Vec<_>>()
    );

    // For now, require pid + mnt
    let use_pid = cli.ns.iter().any(|n| matches!(n, Ns::Pid));
    let use_mnt = cli.ns.iter().any(|n| matches!(n, Ns::Mnt));
    if !use_pid || !use_mnt {
        eprintln!("proclet: currently requires ns=pid,mnt (others coming soon)");
        std::process::exit(64);
    }

    // Build Proclet options
    let opts = ProcletOpts {
        mount_proc: !cli.no_proc,
        hostname: cli.hostname.clone(),
        chdir: cli.workdir.as_deref().map(Into::into), // -> Option<PathBuf>
    };

    match run_pid_mount(&cargs, &opts) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("proclet: failed to start: {e}");
            std::process::exit(1);
        }
    }
}
