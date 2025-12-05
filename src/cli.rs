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
    /// Reserved for future net namespace wiring
    Net,
}

#[derive(Parser, Debug)]
#[command(name = "proclet", about = "Tiny Linux sandbox using namespaces")]
pub struct Cli {
    /// Namespace(s) to enable (comma-separated).
    ///
    /// Default: user,pid,mnt
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
    /// -v   : show a one-line summary of the sandbox
    /// -vv  : + runtime events
    /// -vvv : + deep trace
    #[arg(short, long, action = ArgAction::Count)]
    pub verbose: u8,

    /// Enable HyperRoot lab mode (max power inside sandbox, host-safe).
    #[arg(long = "cursed")]
    pub cursed: bool,

    /// Ultra-dangerous: operate directly as host root (no user namespace).
    ///
    /// Requires real root; changes may affect the host kernel/filesystem.
    #[arg(long = "cursed-host")]
    pub cursed_host: bool,

    /// Create a minimal rootfs skeleton instead of auto-binding /usr, /bin, etc.
    #[arg(long = "minimal-rootfs")]
    pub minimal_rootfs: bool,

    /// Do NOT mount a fresh /proc (only valid if Mnt is enabled)
    #[arg(long)]
    pub no_proc: bool,

    /// Set working directory inside the sandbox (after namespaces)
    #[arg(long)]
    pub workdir: Option<String>,

    /// Set hostname inside the sandbox (requires `uts` feature at build time)
    #[arg(long)]
    pub hostname: Option<String>,

    /// Bind-mounts: --bind /host:/inside[:ro] (repeatable; comma-separated also supported)
    #[arg(long, value_delimiter = ',')]
    pub bind: Vec<String>,

    /// Make root filesystem read-only (remount / as MS_RDONLY)
    #[arg(long)]
    pub readonly: bool,

    /// New root directory inside the sandbox (bind-mount to /).
    #[arg(long = "new-root")]
    pub new_root: Option<String>,

    /// Automatically create a temporary new-root under /tmp (e.g. /tmp/proclet-XXXXXX).
    #[arg(long = "new-root-auto")]
    pub new_root_auto: bool,

    /// Automatically delete the auto-created new-root directory after the sandbox exits.
    ///
    /// Only applies when using --new-root-auto without an explicit --new-root.
    #[arg(long = "auto-clean-new-root")]
    pub auto_clean_new_root: bool,

    /// Copy host files into the new-root (comma-separated).
    ///
    /// Example:
    ///   --new-root-copy /etc/resolv.conf,/etc/hosts
    #[arg(long = "new-root-copy", value_delimiter = ',')]
    pub new_root_copy: Vec<String>,

    /// Mount a private tmpfs on /tmp inside the sandbox (or inside new-root if set).
    #[arg(long = "tmpfs-tmp")]
    pub tmpfs_tmp: bool,

    /// Copy a binary and its shared libraries into the new-root (repeatable; comma-separated).
    ///
    /// Example:
    ///   --copy-bin /bin/ls --copy-bin /usr/bin/env
    #[arg(long = "copy-bin", value_delimiter = ',')]
    pub copy_bin: Vec<String>,

    /// Environment variables to set inside the sandbox (KEY=VALUE).
    ///
    /// Repeatable and comma-separated.
    ///
    /// Examples:
    ///   --env PATH=/bin:/usr/bin
    ///   --env LANG=C,LC_ALL=C
    #[arg(long = "env", value_delimiter = ',')]
    pub env: Vec<String>,

    /// Use overlayfs with this lowerdir as the read-only base.
    ///
    /// Requires --new-root or --new-root-auto.
    #[arg(long = "overlay-lower")]
    pub overlay_lower: Option<String>,

    /// Clear the environment inside the sandbox before applying --env.
    ///
    /// Default: inherit host environment.
    #[arg(long = "clear-env")]
    pub clear_env: bool,

    /// Command to run (use `--` before it)
    #[arg(last = true, required = true)]
    pub cmd: Vec<String>,
}
