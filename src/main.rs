mod ffi;

use clap::Parser;

/// Minimal PID-namespace runner (MVP). Requires root unless using user namespaces.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Command to run inside the new PID namespace (e.g., /bin/bash)
    cmd: String,
    /// Arguments for the command
    #[arg(trailing_var_arg = true)]
    cmd_args: Vec<String>,
}

fn main() {
    let args = Args::parse();

    let mut items: Vec<&str> = Vec::with_capacity(1 + args.cmd_args.len());
    items.push(&args.cmd);
    for s in &args.cmd_args {
        items.push(s);
    }

    let code = ffi::run_pid_ns_safe(&items);
    std::process::exit(code);
}
