use clap::{Parser, ValueEnum};

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum Ns {
    /// New PID namespace (child becomes PID 1)
    Pid,
    /// New mount namespace (private mounts + fresh /proc)
    Mnt,
    /// Placeholder for future net namespace
    Net,
}

#[derive(Parser, Debug)]
#[command(name = "proclet", about = "Tiny Linux sandbox using namespaces")]
pub struct Cli {
    /// Namespace(s) to enable
    #[arg(long = "ns", value_enum, num_args=1.., value_delimiter=',', default_values_t = [Ns::Pid, Ns::Mnt])]
    pub ns: Vec<Ns>,

    /// Do NOT mount a fresh /proc (only valid if Mnt is enabled)
    #[arg(long)]
    pub no_proc: bool,

    /// Set working directory inside the sandbox (after namespaces)
    #[arg(long)]
    pub workdir: Option<String>,

    /// Set hostname inside PID/MNT ns (cosmetic; requires MNT ns)
    #[arg(long)]
    pub hostname: Option<String>,

    /// Command to run (use `--` before it)
    #[arg(last = true, required = true)]
    pub cmd: Vec<String>,
}
