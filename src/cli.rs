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

use clap::{Parser, ValueEnum};

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum Ns {
    /// New USER namespace (map real uid/gid -> root inside)
    User,
    /// New PID namespace (child becomes PID 1)
    Pid,
    /// New mount namespace (private mounts + fresh /proc)
    Mnt,

    /// Placeholder for future net namespace (requires building with `--features net`)
    Net,

    #[cfg(feature = "uts")]
    /// New UTS namespace (hostname/domain isolation) — requires building with `--features uts`
    Uts,
}

#[derive(Parser, Debug)]
#[command(name = "proclet", about = "Tiny Linux sandbox using namespaces")]
pub struct Cli {
    /// Namespace(s) to enable (comma-separated). Note: `net` requires build feature `net`,
    /// and `uts` is only available when built with `--features uts`.
    #[arg(
        long = "ns",
        value_enum,
        num_args = 1..,
        value_delimiter = ',',
        default_values_t = [Ns::User, Ns::Pid, Ns::Mnt]
    )]
    pub ns: Vec<Ns>,

    /// Do NOT mount a fresh /proc (only valid if Mnt is enabled)
    #[arg(long)]
    pub no_proc: bool,

    /// Set working directory inside the sandbox (after namespaces)
    #[arg(long)]
    pub workdir: Option<String>,

    /// Set hostname inside the sandbox.
    ///
    /// Build note: requires compiling with `--features uts`. Without that feature,
    /// proclet will exit with EX_USAGE if this flag is used.
    #[arg(long)]
    pub hostname: Option<String>,

    /// Bind-mounts: --bind /host:/inside[:ro] (repeatable; comma-separated also supported)
    #[arg(long, value_delimiter = ',')]
    pub bind: Vec<String>,

    /// Make root filesystem read-only (remount / as MS_RDONLY, or new-root if specified)
    #[arg(long)]
    pub readonly: bool,

    /// Use an existing directory as the sandbox root (like bwrap --ro-bind /root /).
    ///
    /// Example:
    ///   proclet --ns user,pid,mnt --new-root /tmp/proclet-root -- /bin/bash
    ///
    /// By itself, proclet expects you to populate this root (or combine with --new-root-auto).
    #[arg(long = "new-root")]
    pub new_root: Option<String>,

    /// Automatically populate the new root with core system directories using bind mounts.
    ///
    /// Behaviour:
    ///   - If used together with --new-root, that directory is used and auto-populated.
    ///   - If used alone, proclet creates a temporary dir under /tmp and uses that.
    ///
    /// Core dirs currently bound (if they exist on the host):
    ///   /usr, /bin, /sbin, /lib, /lib64
    #[arg(long = "new-root-auto")]
    pub new_root_auto: bool,

    /// Command to run (use `--` before it)
    #[arg(last = true, required = true)]
    pub cmd: Vec<String>,
}
