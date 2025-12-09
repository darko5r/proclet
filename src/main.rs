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

mod cli;

use clap::Parser;
use cli::{Cli, Ns};
use nix::unistd::pipe;
use proclet::{cstrings, run_pid_mount, set_log_fd, set_verbosity, ProcletOpts, cursed};
use std::{
    ffi::CStr,
    fs::File,
    io::{self, IsTerminal, Read, Write},
    os::fd::{FromRawFd, IntoRawFd, RawFd},
    path::PathBuf,
    thread,
};

// ---------- feature gates as booleans ----------
#[cfg(feature = "net")]
const FEATURE_NET: bool = true;
#[cfg(not(feature = "net"))]
const FEATURE_NET: bool = false;

#[cfg(feature = "uts")]
const FEATURE_UTS: bool = true;
#[cfg(not(feature = "uts"))]
const FEATURE_UTS: bool = false;

// Only exposed in debug builds; tells us whether the `reactor` feature is compiled in.
#[cfg(feature = "debug")]
const FEATURE_REACTOR: bool = cfg!(feature = "reactor");
#[cfg(not(feature = "debug"))]
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

fn parse_env_vars(vars: &[String]) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for spec in vars {
        if let Some((k, v)) = spec.split_once('=') {
            if k.is_empty() {
                return Err(format!("invalid --env '{}': empty key", spec));
            }
            // Very basic check; NULs are impossible in Rust strings anyway.
            out.push((k.to_string(), v.to_string()));
        } else {
            return Err(format!("invalid --env '{}': expected KEY=VALUE", spec));
        }
    }
    Ok(out)
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

    // Modes
    eprintln!(
        "  {} cursed={} cursed_host={}",
        label("modes"),
        cli.cursed,
        cli.cursed_host
    );

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
        format!("mount_proc={} readonly_root={}", !cli.no_proc, cli.readonly)
    );

    // new-root section
    let mut root_desc = match (&cli.new_root, cli.new_root_auto) {
        (Some(path), true) => format!("{} (explicit) + auto-temp", path),
        (Some(path), false) => path.clone(),
        (None, true) => String::from("auto-temp under /tmp"),
        (None, false) => String::from("<host />"),
    };

    if cli.minimal_rootfs {
        root_desc.push_str(" [minimal-rootfs]");
    }

    eprintln!("  {} {}", label("new-root"), root_desc);

    // overlay summary
    if let Some(ref lower) = cli.overlay_lower {
        eprintln!("  {} lower={}", label("overlay"), lower);
    } else {
        eprintln!("  {} disabled", label("overlay"));
    }

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

    // Env summary (just a hint, not full dump)
    if cli.env.is_empty() && !cli.clear_env {
        eprintln!("  {} inherit (default)", label("env"));
    } else {
        eprintln!(
            "  {} clear_env={} overrides={}",
            label("env"),
            cli.clear_env,
            cli.env.len()
        );
    }
}

/// Background thread that reads from the logging pipe and writes lines to stderr.
fn spawn_logger_thread(read_fd: RawFd) {
    // Safety: we take ownership of read_fd inside this thread.
    let mut file = unsafe { File::from_raw_fd(read_fd) };

    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut line_buf = Vec::new();
        let mut stderr = io::stderr();

        loop {
            match file.read(&mut buf) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    for &b in &buf[..n] {
                        if b == b'\n' {
                            let _ = stderr.write_all(&line_buf);
                            let _ = stderr.write_all(b"\n");
                            line_buf.clear();
                        } else {
                            line_buf.push(b);
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });
}

fn main() {
    let cli = Cli::parse();

    // --- Global cursed mode validation ---
    if cli.cursed && cli.cursed_host {
        print_error("--cursed and --cursed-host cannot be used together");
        std::process::exit(64); // EX_USAGE
    }

    // --- Resolve new-root path (explicit or auto) ---
    let (new_root_path, auto_root_for_cleanup): (Option<PathBuf>, Option<PathBuf>) =
        if let Some(explicit) = &cli.new_root {
            (Some(PathBuf::from(explicit)), None)
        } else if cli.new_root_auto {
            // mkdtemp expects a mut char* buffer ending with "XXXXXX\0"
            let mut template = b"/tmp/proclet-XXXXXX\0".to_vec();
            let ptr = template.as_mut_ptr() as *mut libc::c_char;

            let res = unsafe { libc::mkdtemp(ptr) };
            if res.is_null() {
                print_error("failed to create auto new-root under /tmp (mkdtemp failed)");
                std::process::exit(1);
            }

            let path_str = unsafe { CStr::from_ptr(res) }
                .to_string_lossy()
                .into_owned();

            let root = PathBuf::from(path_str);
            (Some(root.clone()), Some(root))
        } else {
            (None, None)
        };

    // Safety: these flags require a private rootfs.
    if (cli.tmpfs_tmp
        || !cli.new_root_copy.is_empty()
        || !cli.copy_bin.is_empty()
        || cli.minimal_rootfs
        || cli.overlay_lower.is_some())
        && new_root_path.is_none()
    {
        print_error(
            "--tmpfs-tmp, --new-root-copy, --copy-bin, --minimal-rootfs and --overlay-lower require a new root \
             (use --new-root or --new-root-auto)",
        );
        std::process::exit(64); // EX_USAGE
    }

    // Parse env vars early so we can fail with a clear message.
    let env_pairs = match parse_env_vars(&cli.env) {
        Ok(p) => p,
        Err(msg) => {
            print_error(&msg);
            std::process::exit(64);
        }
    };

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

    // Install global verbosity in the library
    let verbosity = cli.verbose;
    set_verbosity(verbosity as u8);

    // If we are in v2+ mode, set up the logging pipe & thread.
    if verbosity >= 2 {
        let (read_fd, write_fd) = pipe().expect("proclet: pipe() failed for logger");

        // nix 0.29 pipe() returns (OwnedFd, OwnedFd); convert to RawFd.
        set_log_fd(write_fd.into_raw_fd());
        spawn_logger_thread(read_fd.into_raw_fd());
    }

    // Build CString argv
    let cmd_slices: Vec<&str> = cli.cmd.iter().map(|s| s.as_str()).collect();
    let cargs = cstrings(&cmd_slices);

    // Base namespace selection from --ns
    let mut use_user = cli.ns.iter().any(|n| matches!(n, Ns::User));
    let mut use_pid = cli.ns.iter().any(|n| matches!(n, Ns::Pid));
    let mut use_mnt = cli.ns.iter().any(|n| matches!(n, Ns::Mnt));
    let use_net = cli.ns.iter().any(|n| matches!(n, Ns::Net));

    // --- Cursed semantics ---

    // HyperRoot lab: fully sandboxed, max power inside userns.
    if cli.cursed {
        use_user = true;
        use_pid = true;
        use_mnt = true;
        // when net namespace is wired, we can also enable it here if desired
        // use_net = true;
    }

    // Host-cursed: no user namespace, but still use PID+MNT isolation.
    if cli.cursed_host {
        use_user = false;
        use_pid = true;
        use_mnt = true;

        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            print_error("--cursed-host requires real root on the host");
            std::process::exit(1);
        }

        // Only show the scary banner for interactive use.
        if io::stderr().is_terminal() {
            eprintln!(
                "\x1b[31mproclet: WARNING: --cursed-host will run with real host root powers.\x1b[0m"
            );
            eprintln!("proclet: Changes may permanently affect the host kernel and filesystem.");
            eprintln!("proclet: Press Ctrl+C now to abort, or wait 5 seconds to continue...");
            std::thread::sleep(std::time::Duration::from_secs(5));
        }
    }

    if !use_pid || !use_mnt {
        print_error("currently requires ns=pid,mnt (others coming soon).");
        std::process::exit(64);
    }

    // Optional debug dump (only if built with --features debug)
    dbgln!(
        "proclet(debug): ns={{ user:{}, pid:{}, mnt:{}, net:{} }}, cursed={}, cursed_host={}, readonly_root={}, no_proc={}, workdir={:?}, hostname={:?}, binds={:?}, clear_env={}, env_overrides={}, overlay_lower={:?}, minimal_rootfs={}, tmpfs_tmp={}, reactor={}",
        use_user,
        use_pid,
        use_mnt,
        use_net,
        cli.cursed,
        cli.cursed_host,
        cli.readonly,
        cli.no_proc,
        cli.workdir,
        cli.hostname,
        cli.bind,
        cli.clear_env,
        env_pairs.len(),
        cli.overlay_lower,
        cli.minimal_rootfs,
        cli.tmpfs_tmp,
        FEATURE_REACTOR,
    );

    // v1: human summary
    if verbosity > 0 {
        print_summary(&cli, use_user, use_pid, use_mnt, use_net);
    }

    // ---------- overlayfs wiring ----------
    let (overlay_lower, overlay_upper, overlay_work) =
        if let Some(lower_str) = &cli.overlay_lower {
            let root = new_root_path
                .as_ref()
                .expect("overlay-lower requires new-root/new-root-auto (validated earlier)");
            let lower = PathBuf::from(lower_str);
            let upper = root.join(".upper");
            let work = root.join(".work");
            (Some(lower), Some(upper), Some(work))
        } else {
            (None, None, None)
        };

    // Decide whether we will auto-clean the auto-created new-root directory.
    let cleanup_root: Option<PathBuf> = if cli.auto_clean_new_root {
        if cli.new_root.is_some() {
            print_error(
                "--auto-clean-new-root only applies with --new-root-auto (no explicit --new-root).",
            );
            std::process::exit(64); // EX_USAGE
        }
        auto_root_for_cleanup.clone()
    } else {
        None
    };

    // Build ProcletOpts, now with drop_uid/drop_gid wired from --as-user
    let mut opts = ProcletOpts {
        mount_proc: !cli.no_proc,
        hostname: cli.hostname.clone(),
        chdir: cli.workdir.as_deref().map(Into::into),

        // namespace / FS toggles
        use_user,
        use_pid,
        use_mnt,
        use_net,
        readonly_root: cli.readonly,
        binds: parse_binds(&cli.bind),

        // new-root knobs
        new_root: new_root_path,
        new_root_auto: cli.new_root_auto,

        // minimal rootfs flag
        minimal_rootfs: cli.minimal_rootfs,

        // overlayfs knobs
        overlay_lower,
        overlay_upper,
        overlay_work,

        // env control
        clear_env: cli.clear_env,
        env: env_pairs,

        // new-root extras
        new_root_copy: cli.new_root_copy.iter().map(PathBuf::from).collect(),
        tmpfs_tmp: cli.tmpfs_tmp,

        // copy-bin: binaries + deps into new-root
        copy_bin: cli.copy_bin.iter().map(PathBuf::from).collect(),

        // cursed modes
        cursed: cli.cursed,
        cursed_host: cli.cursed_host,

        // NEW: privilege drop inside sandbox
        drop_uid: cli.as_user,
        drop_gid: cli.as_user, // same UID/GID for now
    };

    // ── Apply cursed profiles (mutually exclusive already checked above) ───────
    if cli.cursed {
        cursed::apply_lab_mode(&mut opts);
    } else if cli.cursed_host {
        cursed::apply_host_mode(&mut opts);
    }

    let exit_code = match run_pid_mount(&cargs, &opts) {
        Ok(code) => code,
        Err(e) => {
            print_error(&format!("failed to start: {e}"));
            1
        }
    };

    if let Some(root) = cleanup_root {
        // Best-effort; log only in debug builds.
        match std::fs::remove_dir_all(&root) {
            Ok(_) => {
                dbgln!("auto-clean-new-root: removed {:?}", root);
            }
            Err(e) => {
                dbgln!("auto-clean-new-root: failed to remove {:?}: {}", root, e);
            }
        }
    }

    std::process::exit(exit_code);
}
