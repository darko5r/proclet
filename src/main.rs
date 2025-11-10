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

#![allow(clippy::needless_return)]
#[cfg(not(feature = "core"))]
compile_error!("proclet currently requires the `core` feature. Build with default features or enable `--features core`."); 

mod cli;

use clap::Parser;
use cli::{Cli, Ns};
use proclet::{cstrings, run_pid_mount, ProcletOpts};
use std::ffi::CString;

// ---------- feature gates as booleans ----------
#[cfg(feature = "net")]
const FEATURE_NET: bool = true;
#[cfg(not(feature = "net"))]
const FEATURE_NET: bool = false;

#[cfg(feature = "uts")]
const FEATURE_UTS: bool = true;
#[cfg(not(feature = "uts"))]
const FEATURE_UTS: bool = false;

// Only define FEATURE_REACTOR in debug builds (it’s only printed in dbg output)
#[cfg(all(feature = "debug", feature = "reactor"))]
const FEATURE_REACTOR: bool = true;
#[cfg(all(feature = "debug", not(feature = "reactor")))]
const FEATURE_REACTOR: bool = false;

#[cfg(feature = "debug")]
macro_rules! dbgln {
    ($($t:tt)*) => { eprintln!($($t)*); }
}
#[cfg(not(feature = "debug"))]
macro_rules! dbgln {
    ($($t:tt)*) => {};
}

// ---------- helpers ----------
fn parse_binds(b: &[String]) -> Vec<(std::path::PathBuf, std::path::PathBuf, bool)> {
    // Syntax: /host:/inside[:ro]
    b.iter()
        .filter_map(|spec| {
            let parts = spec.split(':').collect::<Vec<_>>();
            if parts.len() < 2 {
                return None;
            }
            let ro = parts.len() >= 3 && parts[2].eq_ignore_ascii_case("ro");
            Some((parts[0].into(), parts[1].into(), ro))
        })
        .collect()
}

fn main() {
    let cli = Cli::parse();

    // --- Validate feature-dependent flags up front ---
    if cli.ns.iter().any(|n| matches!(n, Ns::Net)) && !FEATURE_NET {
        eprintln!(
            "proclet: this binary was built without the `net` feature.\n\
             Rebuild with: cargo build --features net\n\
             (requested: --ns net)"
        );
        std::process::exit(64); // EX_USAGE
    }

    if cli.hostname.is_some() && !FEATURE_UTS {
        eprintln!(
            "proclet: setting hostname requires the `uts` feature.\n\
             Rebuild with: cargo build --features uts\n\
             (requested: --hostname ...)"
        );
        std::process::exit(64); // EX_USAGE
    }

    let cargs: Vec<CString> = cstrings(&cli.cmd.iter().map(|s| s.as_str()).collect::<Vec<_>>());

    let use_user = cli.ns.iter().any(|n| matches!(n, Ns::User));
    let use_pid  = cli.ns.iter().any(|n| matches!(n, Ns::Pid));
    let use_mnt  = cli.ns.iter().any(|n| matches!(n, Ns::Mnt));
    let _use_net = cli.ns.iter().any(|n| matches!(n, Ns::Net)); // reserved for future wiring

    if !use_pid || !use_mnt {
        eprintln!("proclet: currently requires ns=pid,mnt (others coming soon)");
        std::process::exit(64);
    }

    // Optional debug dump (only if built with --features debug)
    dbgln!(
        "proclet(debug): ns={{ user:{}, pid:{}, mnt:{}, net:{} }}, readonly_root={}, no_proc={}, workdir={:?}, hostname={:?}, binds={:?}{}",
        use_user,
        use_pid,
        use_mnt,
        _use_net,
        cli.readonly,
        cli.no_proc,
        cli.workdir,
        cli.hostname,
        cli.bind,
        // append reactor flag only when it's defined (i.e., in debug builds)
        {
            #[cfg(feature = "debug")]
            {
                format!(", reactor={}", FEATURE_REACTOR)
            }
            #[cfg(not(feature = "debug"))]
            {
                String::new()
            }
        }
    );

    let opts = ProcletOpts {
        mount_proc: !cli.no_proc,
        hostname: cli.hostname.clone(),
        chdir: cli.workdir.as_deref().map(Into::into),

        // existing toggles
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
