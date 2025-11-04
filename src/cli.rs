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
    /// Placeholder for future net namespace
    Net,
}

#[derive(Parser, Debug)]
#[command(name = "proclet", about = "Tiny Linux sandbox using namespaces")]
pub struct Cli {
    /// Namespace(s) to enable
    #[arg(long = "ns", value_enum, num_args=1.., value_delimiter=',',
        default_values_t = [Ns::User, Ns::Pid, Ns::Mnt])]
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

    /// Bind-mounts: --bind /host:/inside[:ro] (repeatable)
    #[arg(long, value_delimiter=',')]
    pub bind: Vec<String>,

    /// Make root filesystem read-only (remount / as MS_RDONLY)
    #[arg(long)]
    pub readonly: bool,

    /// Command to run (use `--` before it)
    #[arg(last = true, required = true)]
    pub cmd: Vec<String>,
}
