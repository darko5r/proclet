/*
 * Copyright 2025 darko5r
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use clap::{ArgAction, Parser, ValueEnum};

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum Ns {
    /// New USER namespace (map real uid/gid -> root inside)
    User,
    /// New PID namespace (child becomes PID 1)
    Pid,
    /// New mount namespace (private mounts + fresh /proc)
    Mnt,

    /// Placeholder for future NET namespace (requires building with `--features net`)
    ///
    /// Note: currently parsed and validated, but not yet wired into the engine.
    Net,

    #[cfg(feature = "uts")]
    /// Placeholder for UTS namespace (hostname isolation).
    ///
    /// Currently the actual UTS unshare is triggered by `--hostname`
    /// when built with `--features uts`. This variant is reserved for
    /// future explicit control.
    Uts,
}

#[derive(Parser, Debug)]
#[command(
    name = "proclet",
    about = "Proclet — tiny open-source Linux sandbox using namespaces"
)]
pub struct Cli {
    /// Namespace(s) to enable (comma-separated).
    ///
    /// Defaults to: user,pid,mnt
    ///
    /// Notes:
    ///   • `net` requires building with the `net` feature (otherwise you get a
    ///     clear error at runtime).
    ///   • `uts` is only available when built with `--features uts` and is
    ///     currently mostly a placeholder — hostname isolation is driven by
    ///     the `--hostname` flag.
    #[arg(
        long = "ns",
        value_enum,
        num_args = 1..,
        value_delimiter = ',',
        default_values_t = [Ns::User, Ns::Pid, Ns::Mnt]
    )]
    pub ns: Vec<Ns>,

    /// Increase verbosity (-v, -vv, -vvv)
    ///
    ///   -v   : show sandbox configuration summary only
    ///   -vv  : add runtime events (namespace setup, /proc mount, exit codes)
    ///   -vvv : full deep trace (PID1, TTY, signalfd, signal forwarding, etc.)
    #[arg(short, long, action = ArgAction::Count)]
    pub verbose: u8,

    /// Do NOT mount a fresh /proc (only valid if Mnt is enabled)
    #[arg(long)]
    pub no_proc: bool,

    /// Set working directory inside the sandbox (after namespaces)
    #[arg(long)]
    pub workdir: Option<String>,

    /// Set hostname inside the sandbox.
    ///
    /// Build note: requires compiling with `--features uts`. Without that
    /// feature, proclet will exit with EX_USAGE if this flag is used.
    ///
    /// When enabled, Proclet will unshare the UTS namespace and call
    /// sethostname() inside the sandbox.
    #[arg(long)]
    pub hostname: Option<String>,

    /// Bind-mounts: --bind /host:/inside[:ro]
    ///
    /// You can repeat this flag, or pass comma-separated specs:
    ///   --bind /etc/resolv.conf:/etc/resolv.conf,~/src:/src:ro
    #[arg(long, value_delimiter = ',')]
    pub bind: Vec<String>,

    /// Make root filesystem read-only (remount / or new-root as MS_RDONLY)
    #[arg(long)]
    pub readonly: bool,

    /// New root directory inside the sandbox (bind-mount to /).
    ///
    /// Rough analogue of:
    ///   bubblewrap: --ro-bind /my/root / --chdir /
    ///
    /// Example:
    ///   proclet --ns user,pid,mnt --new-root /tmp/proclet-root -- /bin/bash
    #[arg(long = "new-root")]
    pub new_root: Option<String>,

    /// Automatically create a temporary new-root under /tmp
    /// (e.g. /tmp/proclet-XXXXXX) and use it as the sandbox root.
    ///
    /// If combined with --new-root, Proclet will:
    ///   • ensure the directory exists, and
    ///   • optionally auto-populate it with core dirs when used
    ///     together with --new-root-auto in the engine.
    ///
    /// If used alone (no --new-root), Proclet creates a throwaway
    /// directory under /tmp and uses that as the rootfs for this run.
    #[arg(long = "new-root-auto")]
    pub new_root_auto: bool,

    /// Command to run inside the sandbox (use `--` before it).
    ///
    /// Example:
    ///   proclet --ns user,pid,mnt -- /usr/bin/id
    ///
    /// Common mistake (extra `--`):
    ///   proclet --ns user,pid,mnt -- -- id   # WRONG
    ///
    /// Proclet detects `cmd[0] == "--"` and prints a helpful error.
    #[arg(last = true, required = true)]
    pub cmd: Vec<String>,
}
