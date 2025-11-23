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

//! Core sandbox engine
/// _______________________________________________________________________________________________________________________
/// Compile-time safeguard: this library requires the `core` feature to function.
/// Acts as a safety net — `core` is mandatory for now. Abort early if someone forgets to enable it.
/// _______________________________________________________________________________________________________________________
#[cfg(not(feature = "core"))]
compile_error!(
    "proclet currently requires the `core` feature. \
     Build with default features or enable `--features core`."
);

use nix::{
    errno::Errno,
    mount::{mount, umount2, MntFlags, MsFlags},
    sched::{unshare, CloneFlags},
    sys::{
        signal::{SaFlags, SigAction, SigHandler, SigSet, SigmaskHow, Signal},
        signalfd::{SfdFlags, SignalFd},
        wait::{waitpid, WaitPidFlag, WaitStatus},
    },
    unistd::{chdir, execvp, fork, ForkResult},
};
use std::{
    ffi::CString,
    fs::OpenOptions,
    io::Write,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};

// ---- debug helper (enabled only with `--features debug`) ----
#[cfg(feature = "debug")]
macro_rules! dbgln {
    ($($t:tt)*) => { eprintln!($($t)*); }
}
#[cfg(not(feature = "debug"))]
macro_rules! dbgln {
    ($($t:tt)*) => {};
}

#[inline]
fn to_errno(e: std::io::Error) -> Errno {
    Errno::from_raw(e.raw_os_error().unwrap_or(libc::EIO))
}

fn write_file(path: &str, s: &str) -> Result<(), Errno> {
    let mut f = OpenOptions::new().write(true).open(path).map_err(to_errno)?;
    f.write_all(s.as_bytes()).map_err(to_errno)
}

/// _________________________________________________________________________________
/// Enter a new user namespace and map the real UID/GID to root (0) inside it.
/// This gives the process root-like privileges *within* the sandbox, without
/// needing real root permissions on the host.
///
/// Acts as a safety net: if we’re already real root outside, skip userns entirely,
/// since there’s no need to remap anything for mounts or capabilities.
/// _________________________________________________________________________________
fn enter_userns_map_root() -> Result<(), Errno> {
    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };

    // If running as real root, just don't use a user namespace.
    if euid == 0 {
        dbgln!("proclet(debug): skipping userns (already root)");
        return Ok(());
    }

    dbgln!("proclet(debug): unshare(CLONE_NEWUSER)");
    unshare(CloneFlags::CLONE_NEWUSER)?;

    // On unprivileged paths, kernel requires setgroups=deny before gid_map
    // Ignore ENOENT/EINVAL here (some kernels/filesystems differ)
    let _ = write_file("/proc/self/setgroups", "deny\n");

    let uid = euid as u32;
    let gid = egid as u32;

    write_file("/proc/self/uid_map", &format!("0 {uid} 1\n"))?;
    write_file("/proc/self/gid_map", &format!("0 {gid} 1\n"))?;

    Ok(())
}

// ---- UTS helpers (only compiled when `--features uts`) ----
#[cfg(feature = "uts")]
fn maybe_enter_uts_ns_if_needed(hostname: &Option<String>) -> Result<(), Errno> {
    if hostname.is_some() {
        dbgln!("proclet(debug): unshare(CLONE_NEWUTS) for hostname");
        unshare(CloneFlags::CLONE_NEWUTS)?;
    }
    Ok(())
}

#[cfg(not(feature = "uts"))]
fn maybe_enter_uts_ns_if_needed(_hostname: &Option<String>) -> Result<(), Errno> {
    Ok(())
}

/// Preflight: if `--hostname` is requested, ensure we can call sethostname().
/// Rule of thumb:
/// - with `--ns user`, non-root callers gain in-ns caps and can set hostname;
/// - without userns, you must be real root on the host.
#[cfg(feature = "uts")]
fn ensure_hostname_possible(use_user: bool) -> Result<(), Errno> {
    if !use_user {
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            return Err(Errno::EPERM);
        }
    }
    Ok(())
}

/// Runtime options for Proclet.
#[derive(Debug, Default, Clone)]
pub struct ProcletOpts {
    /// Remount a fresh `/proc` inside the sandbox. Disable for debugging.
    pub mount_proc: bool,
    /// Optional hostname to set inside the (isolated) UTS context (requires feature `uts`).
    pub hostname: Option<String>,
    /// Optional working directory to `chdir` into before exec.
    pub chdir: Option<PathBuf>,

    /// Optional new root (like a light chroot). If set, proclet will:
    ///   - bind-mount this path on itself,
    ///   - move-mount it to `/`,
    ///   - and chdir("/") inside the private mount namespace.
    pub new_root: Option<PathBuf>,

    // Namespace/FS toggles populated by main.rs
    pub use_user: bool,
    pub use_pid: bool,
    pub use_mnt: bool,
    pub readonly_root: bool,
    pub binds: Vec<(PathBuf, PathBuf, bool)>, // (host, inside, ro?)
}

/// Exhaustively reap all available children. If `direct_pid` (the payload leader)
/// has exited, returns its exit code (or 128+signal).
fn reap_all(direct_pid: libc::pid_t) -> Result<Option<i32>, Errno> {
    let mut direct_exit: Option<i32> = None;
    loop {
        match waitpid(
            None,
            Some(WaitPidFlag::WNOHANG | WaitPidFlag::WUNTRACED | WaitPidFlag::WCONTINUED),
        ) {
            Ok(WaitStatus::Exited(pid, code)) => {
                if pid.as_raw() == direct_pid {
                    direct_exit = Some(code);
                }
            }
            Ok(WaitStatus::Signaled(pid, sig, _)) => {
                if pid.as_raw() == direct_pid {
                    direct_exit = Some(128 + sig as i32);
                }
            }
            Ok(WaitStatus::Stopped(_, _))
            | Ok(WaitStatus::Continued(_))
            | Ok(WaitStatus::PtraceEvent(_, _, _))
            | Ok(WaitStatus::PtraceSyscall(_)) => {
                // ignore; not relevant for regular supervision
            }
            Ok(WaitStatus::StillAlive) => break,
            Err(Errno::ECHILD) => break,   // nothing left to reap
            Err(Errno::EINTR) => continue, // interrupted, try again
            Err(e) => return Err(e),       // propagate any other error
        }
    }
    Ok(direct_exit)
}

// === TTY foreground control helpers (fix interactive shells) ======================

struct TtyGuard {
    fd: i32,
    had_tty: bool,
    prev_fg: Option<libc::pid_t>,
}

impl TtyGuard {
    fn take_for(payload_pgid: libc::pid_t) -> Self {
        let fd = std::io::stdin().as_raw_fd();
        let mut guard = TtyGuard { fd, had_tty: false, prev_fg: None };

        // Only attempt if stdin is a TTY
        if unsafe { libc::isatty(fd) } != 1 {
            return guard;
        }

        // Temporarily ignore TTY stop signals so tcsetpgrp won't stop us
        let ignore = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty());
        unsafe {
            let _ = nix::sys::signal::sigaction(Signal::SIGTTOU, &ignore);
            let _ = nix::sys::signal::sigaction(Signal::SIGTTIN, &ignore);
        }

        // Save previous foreground pgid
        let pg = unsafe { libc::tcgetpgrp(fd) };
        if pg > 0 {
            guard.prev_fg = Some(pg);
        }

        // Hand TTY to the payload's process group
        if unsafe { libc::tcsetpgrp(fd, payload_pgid) } == 0 {
            guard.had_tty = true;
            dbgln!("proclet(debug): tty foreground -> pgid {}", payload_pgid);
        }

        // Restore default handlers
        let dfl = SigAction::new(SigHandler::SigDfl, SaFlags::empty(), SigSet::empty());
        unsafe {
            let _ = nix::sys::signal::sigaction(Signal::SIGTTOU, &dfl);
            let _ = nix::sys::signal::sigaction(Signal::SIGTTIN, &dfl);
        }

        guard
    }

    fn restore(&self) {
        if self.had_tty {
            if let Some(pg) = self.prev_fg {
                let _ = unsafe { libc::tcsetpgrp(self.fd, pg) };
                dbgln!("proclet(debug): tty foreground restored -> pgid {}", pg);
            }
        }
    }
}

/// Run `argv` inside namespaces. Child acts as PID 1 if PID ns is used.
///
/// Order: USER → (UTS?) → MNT (+optional new_root) → PID
pub fn run_pid_mount(argv: &[CString], opts: &ProcletOpts) -> Result<i32, Errno> {
    if argv.is_empty() {
        return Err(Errno::EINVAL);
    }

    // 0) User namespace first (enables unprivileged mounts inside)
    if opts.use_user {
        enter_userns_map_root()?;
    }

    // 0.5) UTS namespace if hostname requested (only when built with `uts`)
    #[cfg(feature = "uts")]
    if opts.hostname.is_some() {
        ensure_hostname_possible(opts.use_user)?;
    }
    maybe_enter_uts_ns_if_needed(&opts.hostname)?;

    // 1) Isolate mount namespace so our mounts don't leak out.
    if opts.use_mnt {
        dbgln!("proclet(debug): unshare(CLONE_NEWNS)");
        unshare(CloneFlags::CLONE_NEWNS)?;

        dbgln!("proclet(debug): remount / as MS_PRIVATE|MS_REC");
        mount::<str, str, str, str>(
            None,
            "/",
            None,
            MsFlags::MS_REC | MsFlags::MS_PRIVATE,
            None,
        )?;

        // Optional: switch to a new filesystem root
        if let Some(ref root) = opts.new_root {
            dbgln!("proclet(debug): switching new root to {:?}", root);

            // Best-effort ensure the directory exists
            let _ = std::fs::create_dir_all(root);

            // Make it a mount point (bind-mount on itself)
            mount(
                Some(root.as_path()),
                root.as_path(),
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                None::<&str>,
            )?;

            // Move that mount tree to /
            chdir(root)?;
            mount(
                Some(Path::new(".")),
                Path::new("/"),
                None::<&str>,
                MsFlags::MS_MOVE,
                None::<&str>,
            )?;
            chdir(Path::new("/"))?;

            dbgln!("proclet(debug): new root is now /");
        }

        // Apply bind mounts before readonly root.
        //
        // NOTE: when new_root is set, both host and inside paths are interpreted
        // inside that tree; for now we keep it simple: the caller is expected to
        // prepare the root filesystem layout in advance.
        for (host, inside, ro) in &opts.binds {
            // Ensure the target exists (best-effort for dirs)
            let _ = std::fs::create_dir_all(inside);
            dbgln!(
                "proclet(debug): bind {:?} -> {:?} (ro={})",
                host,
                inside,
                ro
            );
            mount(
                Some(host.as_path()),
                inside,
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                None::<&str>,
            )?;
            if *ro {
                // Remount bind as read-only
                mount::<str, Path, str, str>(
                    None,
                    inside,
                    None,
                    MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
                    None,
                )?;
            }
        }

        if opts.readonly_root {
            // Best-effort remount / read-only (may fail on some hosts)
            dbgln!("proclet(debug): remount / read-only (best-effort)");
            let _ = mount::<str, str, str, str>(
                None,
                "/",
                None,
                MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
                None,
            );
        }
    }

    // 2) Create a new PID namespace (affects future children)
    if opts.use_pid {
        dbgln!("proclet(debug): unshare(CLONE_NEWPID)");
        unshare(CloneFlags::CLONE_NEWPID)?;
    }

    // 3) Fork so the child becomes PID 1 in the new PID namespace (if any).
    match unsafe { fork()? } {
        ForkResult::Child => {
            // --- Child == PID 1 ---
            #[cfg(feature = "uts")]
            if let Some(h) = &opts.hostname {
                dbgln!("proclet(debug): sethostname({})", h);
                set_hostname(h)?; // requires UTS ns; userns grants caps in-ns
            }

            if opts.mount_proc && opts.use_mnt {
                setup_proc()?;
            }
            if let Some(dir) = &opts.chdir {
                chdir(dir)?;
            }

            // Put ourselves in a new process group so we can forward signals to the group.
            let _ = unsafe { libc::setpgid(0, 0) };

            // Spawn the actual payload so PID 1 can reap it.
            match unsafe { fork()? } {
                ForkResult::Child => {
                    // --- Inner child: actual payload ---------------------------------

                    // Debug: show final argv we’re about to exec
                    #[cfg(feature = "debug")]
                    {
                        let pretty: Vec<String> = argv
                            .iter()
                            .map(|c| c.to_string_lossy().into_owned())
                            .collect();
                        dbgln!("proclet(debug): execvp argv={:?}", pretty);
                    }

                    // Exec the target (on success, never returns)
                    let e = execvp(&argv[0], argv).unwrap_err();
                    eprintln!("proclet: exec failed: {e}");
                    std::process::exit(127);
                }
                ForkResult::Parent { child } => {
                    // === subreaper + signalfd + full forward + exhaustive reap ===

                    // 1) Become a subreaper: orphans in our subtree get reparented to us.
                    unsafe {
                        libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
                    }

                    // 2) Ensure the payload is its own process group; store its PGID
                    unsafe {
                        libc::setpgid(child.as_raw(), child.as_raw());
                    }
                    let payload_pgid: libc::pid_t = child.as_raw();

                    // 2.5) Hand the controlling TTY to the payload's process group
                    let tty_guard = TtyGuard::take_for(payload_pgid);

                    // 3) Block signals we want to manage and route them via signalfd
                    let mut mask = SigSet::empty();
                    for s in [
                        Signal::SIGINT,
                        Signal::SIGTERM,
                        Signal::SIGHUP,
                        Signal::SIGQUIT,
                        Signal::SIGUSR1,
                        Signal::SIGUSR2,
                        Signal::SIGTSTP,
                        Signal::SIGCONT,
                        Signal::SIGWINCH,
                        Signal::SIGCHLD,
                    ] {
                        mask.add(s);
                    }
                    // Block so default handlers won't run; we will read from signalfd.
                    nix::sys::signal::sigprocmask(SigmaskHow::SIG_BLOCK, Some(&mask), None)?;

                    // 4) signalfd to consume the blocked signals synchronously
                    let sfd = SignalFd::with_flags(&mask, SfdFlags::SFD_CLOEXEC)?;

                    // 5) Main supervision loop: read signals → forward or reap
                    let mut exit_code: Option<i32> = None;

                    loop {
                        match sfd.read_signal() {
                            Ok(Some(si)) => {
                                let signo = si.ssi_signo as i32;
                                let sig = Signal::try_from(signo).ok();

                                if matches!(sig, Some(Signal::SIGCHLD)) {
                                    // Reap everything available; capture direct child's exit if any.
                                    if let Some(code) = reap_all(child.as_raw())? {
                                        exit_code = Some(code);
                                    }
                                } else if let Some(sig) = sig {
                                    // Forward almost everything else to the entire payload process group.
                                    // Negative PGID means: deliver to the process group.
                                    unsafe {
                                        libc::kill(-payload_pgid, sig as i32);
                                    }
                                }

                                // If our direct child is done: graceful shutdown of the group
                                if let Some(code) = exit_code {
                                    // Best-effort TERM then KILL after a short grace
                                    unsafe { libc::kill(-payload_pgid, libc::SIGTERM) };
                                    // ~200ms grace
                                    let ts = libc::timespec {
                                        tv_sec: 0,
                                        tv_nsec: 200_000_000,
                                    };
                                    unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
                                    unsafe { libc::kill(-payload_pgid, libc::SIGKILL) };

                                    // Drain any stragglers before exiting
                                    let _ = reap_all(child.as_raw());

                                    // Restore TTY before exit
                                    tty_guard.restore();

                                    return Ok(code);
                                }
                            }
                            Ok(None) => continue, // nothing to read (blocking fd, so unlikely)
                            Err(e) if e == Errno::EINTR => continue,
                            Err(e) => {
                                eprintln!("proclet: signalfd error: {e}");
                                // Fallback: try reaping; if direct child is gone, exit with its code
                                if let Some(code) = reap_all(child.as_raw())? {
                                    tty_guard.restore();
                                    return Ok(code);
                                }
                            }
                        }
                    }
                }
            }
        }
        ForkResult::Parent { child } => {
            // --- Original process: wait for namespace init (PID1) to finish ---
            match waitpid(child, None)? {
                WaitStatus::Exited(_, code) => Ok(code),
                WaitStatus::Signaled(_, sig, _) => Ok(128 + sig as i32),
                _ => Ok(1),
            }
        }
    }
}

/// Mount a fresh `/proc` inside the current mount namespace.
fn setup_proc() -> Result<(), Errno> {
    let proc_path = Path::new("/proc");
    let _ = umount2(proc_path, MntFlags::MNT_DETACH);
    let _ = std::fs::create_dir_all(proc_path);
    mount::<str, str, str, str>(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        None,
    )?;
    Ok(())
}

/// Set the hostname using libc (keeps `nix` features minimal).
#[cfg(feature = "uts")]
fn set_hostname(name: &str) -> Result<(), Errno> {
    let c = CString::new(name).map_err(|_| Errno::EINVAL)?;
    let rc = unsafe { libc::sethostname(c.as_ptr(), name.len()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(Errno::last())
    }
}

/// Convert `&str` slices to `CString`s for `execvp`.
pub fn cstrings(args: &[&str]) -> Vec<CString> {
    let mut out = Vec::with_capacity(args.len());
    for s in args {
        match CString::new((*s).as_bytes()) {
            Ok(c) => out.push(c),
            Err(_) => {
                eprintln!("proclet: argument contains interior NUL byte: {:?}", s);
                std::process::exit(64);
            }
        }
    }
    out
}
