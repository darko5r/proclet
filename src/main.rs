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

mod cli;

use clap::Parser;
use cli::{Cli, Ns};
use proclet::{cstrings, run_pid_mount, ProcletOpts};
use std::ffi::CString;

fn parse_binds(b: &[String]) -> Vec<(std::path::PathBuf, std::path::PathBuf, bool)> {
    // Syntax: /host:/inside[:ro]
    b.iter().filter_map(|spec| {
        let parts = spec.split(':').collect::<Vec<_>>();
        if parts.len() < 2 { return None; }
        let ro = parts.len() >= 3 && parts[2].eq_ignore_ascii_case("ro");
        Some((parts[0].into(), parts[1].into(), ro))
    }).collect()
}

fn main() {
    let cli = Cli::parse();

    if cli.ns.iter().any(|n| matches!(n, Ns::Net)) {
        eprintln!("proclet: --ns net is not implemented yet (placeholder)");
        std::process::exit(64); // EX_USAGE
    }

    let cargs: Vec<CString> = cstrings(
        &cli.cmd.iter().map(|s| s.as_str()).collect::<Vec<_>>()
    );

    let use_user = cli.ns.iter().any(|n| matches!(n, Ns::User));
    let use_pid  = cli.ns.iter().any(|n| matches!(n, Ns::Pid));
    let use_mnt  = cli.ns.iter().any(|n| matches!(n, Ns::Mnt));

    if !use_pid || !use_mnt {
        eprintln!("proclet: currently requires ns=pid,mnt (others coming soon)");
        std::process::exit(64);
    }

    let opts = ProcletOpts {
        mount_proc: !cli.no_proc,
        hostname: cli.hostname.clone(),
        chdir: cli.workdir.as_deref().map(Into::into),

        // new:
        use_user,
        use_pid,
        use_mnt,
        readonly_root: cli.readonly,
        binds: parse_binds(&cli.bind),
    };

    match run_pid_mount(&cargs, &opts) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("proclet: failed to start: {e}");
            std::process::exit(1);
        }
    }
}