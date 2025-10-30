use clap::Parser;
use std::ffi::CString;
use std::os::raw::c_char;
use std::process::exit;

#[derive(Parser, Debug)]
#[command(
    name = "proclet",
    about = "Tiny Linux process sandbox using PID + mount namespaces with a fresh /proc.",
    version
)]
struct Cli {
    /// Command to run inside the sandbox (use `--` before the command)
    #[arg(trailing_var_arg = true, required = true)]
    cmd: Vec<String>,
}

mod ffi;
fn main() {
    let cli = Cli::parse();

    // Build argv as C strings + trailing null
    let cstrings: Vec<CString> = cli
        .cmd
        .iter()
        .map(|s| CString::new(s.as_str()).expect("nul in arg"))
        .collect();

    // Build **argv (null-terminated)
    let mut argv_ptrs: Vec<*const c_char> = cstrings.iter().map(|s| s.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());

    let code = ffi::run_pid_mount(argv_ptrs.as_ptr()) as i32;
    exit(code);
}
