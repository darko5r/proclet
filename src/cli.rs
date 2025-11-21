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
pub enum Ns { User, Pid, Mnt, Net, #[cfg(feature = "uts")] Uts }

#[derive(Parser, Debug)]
#[command(name = "proclet", about = "Tiny Linux sandbox using namespaces")]
pub struct Cli {
    #[arg(
        long = "ns",
        value_enum,
        num_args = 1..,
        value_delimiter = ',',
        default_values_t = [Ns::User, Ns::Pid, Ns::Mnt]
    )]
    pub ns: Vec<Ns>,

    #[arg(long)]
    pub no_proc: bool,

    #[arg(long)]
    pub workdir: Option<String>,

    #[arg(long)]
    pub hostname: Option<String>,

    /// Generic binds: /host:/inside[:ro]
    #[arg(long, value_delimiter = ',')]
    pub bind: Vec<String>,

    /// Convenience: read-only binds (format: /host:/inside)
    #[arg(long = "bind-ro", value_delimiter = ',')]
    pub bind_ro: Vec<String>,

    /// Convenience: read-write binds (format: /host:/inside)
    #[arg(long = "bind-rw", value_delimiter = ',')]
    pub bind_rw: Vec<String>,

    #[arg(long)]
    pub readonly: bool,

    /// Command to run (use `--` before it)
    #[arg(last = true, required = true)]
    pub cmd: Vec<String>,
}
