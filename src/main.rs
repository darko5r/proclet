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
compile_error!(
    "proclet currently requires the `core` feature. \
     Build with default features or enable `--features core`."
);

mod cli;

use clap::Parser;
use cli::{Cli, Ns};
use proclet::{cstrings, run_pid_mount, ProcletOpts};
use std::ffi::CString;
use std::io::{self, IsTerminal};

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

fn stderr_is_terminal() -> bool {
    io::stderr().is_terminal()
}

fn print_error(msg: &str) {
    if stderr_is_terminal() {
        eprintln!("\x1b[31mproclet: {msg}\x1b[0m");
    } else {
        eprintln!("proclet: {msg}");
    }
}

fn print_info(msg: &str) {
    if stderr_is_terminal() {
        eprintln!("\x1b[36m{msg}\x1b[0m");
    } else {
        eprintln!("{msg}");
    }
}

fn print_summary(cli: &Cli, use_user: bool, use_pid: bool, use_mnt: bool, use_net: bool) {
    let use_color = stderr_is_terminal();

    // Colorize labels, but don't pad them or add extra spaces.
    let label = |s: &str| {
        if use_color {
            format!("\x1b[36m{}:\x1b[0m", s) // cyan "ns:" / "root:" / "new-root:" ...
        } else {
            format!("{}:", s)
        }
    };

    print_info("proclet: sandbox configuration");

    // Namespaces
    eprintln!(
        "  {} {}",
        label("ns"),
        format!(
            "user={} pid={} mnt={} net={}",
            use_user, use_pid, use_mnt, use_net
        )
    );

    // Root section
    eprintln!(
        "  {} {}",
        label("root"),
        format!(
            "mount_proc={} readonly_root={}",
            !cli.no_proc,
            cli.readonly
        )
    );

    // new-root section
    let root_desc = match (&cli.new_root, cli.new_root_auto) {
        (Some(path), true) => format!("{} (explicit) + auto-core-dirs", path),
        (Some(path), false) => path.clone(),
        (None, true) => String::from("auto-temp under /tmp"),
        (None, false) => String::from("<host />"),
    };
    eprintln!("  {} {}", label("new-root"), root_desc);

    // workdir / hostname
    eprintln!("  {} {:?}", label("workdir"), cli.workdir.as_deref());
    eprintln!("  {} {:?}", label("hostname"), cli.hostname);

    // binds
    if cli.bind.is_empty() {
        eprintln!("  {} []", label("binds"));
    } else {
        eprintln!("  {} [", label("binds"));
        for b in &cli.bind {
            eprintln!("    {b}");
        }
        eprintln!("  ]");
    }
}

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

fn main() {
    let cli = Cli::parse();

    // --- Validate feature-dependent flags up front ---
    if cli.ns.iter().any(|n| matches!(n, Ns::Net)) && !FEATURE_NET {
        print_error(
            "this binary was built without the `net` feature (requested --ns net).\n\
             Rebuild with: cargo build --features net",
        );
        std::process::exit(64); // EX_USAGE
    }

    if cli.hostname.is_some() && !FEATURE_UTS {
        print_error(
            "setting hostname requires the `uts` feature (requested --hostname ...).\n\
             Rebuild with: cargo build --features uts",
        );
        std::process::exit(64); // EX_USAGE
    }

    // Validate command vector (common mistake: extra `--` inside cmd)
    if let Some(first) = cli.cmd.first() {
        if first == "--" {
            print_error("invalid command vector (starts with `--`).");
            eprintln!("Hint: do NOT pass an extra `--` *inside* the command.");
            eprintln!();
            eprintln!("\t# bad");
            eprintln!("\tproclet --ns user,pid,mnt -- -- id");
            eprintln!();
            eprintln!("\t# good");
            eprintln!("\tproclet --ns user,pid,mnt -- id");
            std::process::exit(64);
        }
    }

    let cargs: Vec<CString> = cstrings(&cli.cmd.iter().map(|s| s.as_str()).collect::<Vec<_>>());

    let use_user = cli.ns.iter().any(|n| matches!(n, Ns::User));
    let use_pid = cli.ns.iter().any(|n| matches!(n, Ns::Pid));
    let use_mnt = cli.ns.iter().any(|n| matches!(n, Ns::Mnt));
    let use_net = cli.ns.iter().any(|n| matches!(n, Ns::Net)); // reserved for future wiring

    if !use_pid || !use_mnt {
        print_error("currently requires ns=pid,mnt (others coming soon).");
        std::process::exit(64);
    }

    // Optional debug dump (only if built with --features debug)
    dbgln!(
        "proclet(debug): ns={{ user:{}, pid:{}, mnt:{}, net:{} }}, readonly_root={}, no_proc={}, workdir={:?}, hostname={:?}, binds={:?}{}",
        use_user,
        use_pid,
        use_mnt,
        use_net,
        cli.readonly,
        cli.no_proc,
        cli.workdir,
        cli.hostname,
        cli.bind,
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

    // Verbose summary (Phase 2 feature, level 1)
    if cli.verbose >= 1 {
        print_summary(&cli, use_user, use_pid, use_mnt, use_net);
    }

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

        // new-root knobs
        new_root: cli.new_root.as_ref().map(Into::into),
        new_root_auto: cli.new_root_auto,

        // verbosity for runtime trace
        verbose: cli.verbose,
    };

    match run_pid_mount(&cargs, &opts) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            print_error(&format!("failed to start: {e}"));
            std::process::exit(1);
        }
    }
}
