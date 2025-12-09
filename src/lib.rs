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

/// _____________________________________________________________________________
/// Compile-time safeguard: this library requires the `core` feature to function.
/// Acts as a safety net — `core` is mandatory for now. Abort early if someone
/// forgets to enable it.
/// _____________________________________________________________________________
#[cfg(not(feature = "core"))]
compile_error!(
    "proclet currently requires the `core` feature. \
     Build with default features or enable `--features core`."
);

#[macro_use]
mod log;
mod fs;
mod env;
mod supervisor;
pub mod cursed;

use nix::{
    errno::Errno,
    mount::{mount, umount2, MntFlags, MsFlags},
    sched::{unshare, CloneFlags},
    sys::{
        signal::{SigSet, SigmaskHow, Signal},
        signalfd::{SfdFlags, SignalFd},
        wait::{waitpid, WaitStatus},
    },
    unistd::{chdir, chroot, execvp, fork, ForkResult},
};

use std::{
    ffi::CString,
    fs::OpenOptions,
    io,
    process::Command,
    path::{Path, PathBuf},
};

use crate::env::apply_env;
use crate::fs::{
    build_minimal_rootfs, copy_bins_with_deps, copy_into_new_root, mount_overlay, prepare_new_root,
};
use crate::supervisor::{reap_all, TtyGuard};

pub use log::{log_error, set_log_fd, set_verbosity};

#[inline]
fn to_errno(e: io::Error) -> Errno {
    Errno::from_raw(e.raw_os_error().unwrap_or(libc::EIO))
}

fn write_file(path: &str, s: &str) -> Result<(), Errno> {
    let mut f = OpenOptions::new().write(true).open(path).map_err(to_errno)?;
    use std::io::Write;
    f.write_all(s.as_bytes()).map_err(to_errno)
}

/// _____________________________________________________________________________
/// Enter a new user namespace and map the real UID/GID to root (0) inside it.
/// This gives the process root-like privileges *within* the sandbox, without
/// needing real root permissions on the host.
///
/// Safety rule:
/// - If we’re already real root on the host, we skip userns completely.
/// _____________________________________________________________________________
fn enter_userns_map_root() -> Result<(), Errno> {
    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };

    // If running as real root, just don't use a user namespace.
    if euid == 0 {
        v3!("skipping user namespace (already real root)");
        return Ok(());
    }

    v3!("unshare(CLONE_NEWUSER) — enter user namespace");
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
        v3!("unshare(CLONE_NEWUTS) for hostname");
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
///
/// Populated by `main.rs` before calling `run_pid_mount`.
#[derive(Debug, Default, Clone)]
pub struct ProcletOpts {
    /// Remount a fresh `/proc` inside the sandbox. Disable for debugging.
    pub mount_proc: bool,

    /// Optional hostname to set inside the (isolated) UTS context (requires feature `uts`).
    pub hostname: Option<String>,

    /// Optional working directory to `chdir` into before exec.
    pub chdir: Option<PathBuf>,

    // Namespace/FS toggles populated by main.rs
    pub use_user: bool,
    pub use_pid: bool,
    pub use_mnt: bool,
    pub use_net: bool,
    pub readonly_root: bool,

    /// Bind mounts: (host_path, inside_path, read_only)
    pub binds: Vec<(PathBuf, PathBuf, bool)>,

    /// Optional new root directory for chroot-like isolation.
    /// If set, proclet will chroot into this path inside the mount namespace.
    pub new_root: Option<PathBuf>,

    /// If true, automatically bind core system dirs into new_root:
    /// /usr, /bin, /sbin, /lib, /lib64 (only ones that exist).
    pub new_root_auto: bool,

    /// If true, build a minimal rootfs skeleton instead of auto-binding core dirs.
    /// Mutually exclusive *conceptually* with "fat" auto-root semantics.
    pub minimal_rootfs: bool,

    /// Overlayfs lowerdir (read-only base). If set, new_root becomes
    /// the overlay mountpoint, with a writable upperdir/workdir.
    pub overlay_lower: Option<PathBuf>,
    pub overlay_upper: Option<PathBuf>,
    pub overlay_work: Option<PathBuf>,

    /// Clear the environment inside the sandbox before applying `env`.
    pub clear_env: bool,

    /// Environment variables to set/override inside the sandbox.
    /// If `clear_env` is false, these overlay the inherited env.
    pub env: Vec<(String, String)>,

    /// Host files to copy into `new_root` (paths like `/etc/resolv.conf`).
    /// These are copied to `<new-root>/<relative-path>`.
    pub new_root_copy: Vec<PathBuf>,

    /// Whether to mount a private tmpfs on `/tmp` inside the sandbox.
    pub tmpfs_tmp: bool,

    /// Binaries to copy into new-root (plus their shared library dependencies).
    pub copy_bin: Vec<PathBuf>,

    /// HyperRoot lab mode (host-safe, userns+pid+mnt).
    pub cursed: bool,

    /// Host-cursed mode (no userns, real host root).
    pub cursed_host: bool,

    /// Drop privileges inside the sandbox to this UID/GID before exec.
    /// Useful for running GUI apps from root while keeping Chrome's own sandbox.
    pub drop_uid: Option<u32>,
    pub drop_gid: Option<u32>,
}

/// Run `argv` inside namespaces. Child acts as PID 1 if PID ns is used.
///
/// Order: USER → (UTS?) → MNT (+new-root/overlay) → PID
pub fn run_pid_mount(argv: &[CString], opts: &ProcletOpts) -> Result<i32, Errno> {
    if argv.is_empty() {
        return Err(Errno::EINVAL);
    }

    v2!(
    "starting sandbox: user={} pid={} mnt={} net={} new_root={:?} minimal_rootfs={} cursed={} cursed_host={}",
    opts.use_user,
    opts.use_pid,
    opts.use_mnt,
    opts.use_net,
    opts.new_root,
    opts.minimal_rootfs,
    opts.cursed,
    opts.cursed_host,
);

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

        // 0.75) Optional network namespace
    if opts.use_net {
        v2!("unshare(CLONE_NEWNET) — new network namespace");
        unshare(CloneFlags::CLONE_NEWNET)?;

        // Best-effort: bring up loopback so 127.0.0.1 works.
        // We don't fail the whole sandbox if this doesn't work.
        match Command::new("ip").args(["link", "set", "lo", "up"]).status() {
            Ok(status) => {
                if !status.success() {
                    v2!(
                        "warning: `ip link set lo up` exited with status {:?} in netns",
                        status.code()
                    );
                }
            }
            Err(e) => {
                v2!("warning: failed to run `ip link set lo up` in netns: {e}");
            }
        }
    }

    // (later we can call cursed::apply_cursed_policies(opts) here if desired)

    // 1) Isolate mount namespace so our mounts don't leak out.
    if opts.use_mnt {
        v2!("unshare(CLONE_NEWNS) — new mount namespace");
        unshare(CloneFlags::CLONE_NEWNS)?;

        v2!("remount / as MS_PRIVATE|MS_REC (best-effort)");
        if let Err(e) = mount::<str, str, str, str>(
            None,
            "/",
            None,
            MsFlags::MS_REC | MsFlags::MS_PRIVATE,
            None,
        ) {
            v2!("remount / as MS_PRIVATE|MS_REC failed: {e}, continuing");
            // We continue anyway; worst case: mounts may be shared with the host.
        }

        // If a new_root is requested, prepare it:
        //   - if overlay_lower is set: mount overlayfs on new_root
        //   - else: minimal_rootfs OR auto-populated root
        if let Some(ref root) = opts.new_root {
            if let (Some(lower), Some(upper), Some(work)) = (
                opts.overlay_lower.as_ref(),
                opts.overlay_upper.as_ref(),
                opts.overlay_work.as_ref(),
            ) {
                v3!(
                    "overlay mode: lower={:?}, upper={:?}, work={:?}, mountpoint={:?}",
                    lower,
                    upper,
                    work,
                    root
                );
                mount_overlay(root, lower, upper, work)?;
            } else {
                if opts.minimal_rootfs {
                    build_minimal_rootfs(root)?;
                } else {
                    prepare_new_root(root, opts.new_root_auto)?;
                }
            }

            // Copy extra files into the (possibly overlay-backed) root
            if !opts.new_root_copy.is_empty() {
                copy_into_new_root(root, &opts.new_root_copy)?;
            }

            // copy-bin behaviour:
            // - minimal_rootfs or overlay: really copy binaries + deps into root
            // - new-root-auto (fat root with /bin,/usr bind-mounted): skip to avoid clobber
            if !opts.copy_bin.is_empty() {
                if opts.minimal_rootfs || opts.overlay_lower.is_some() {
                    copy_bins_with_deps(root, &opts.copy_bin)?;
                } else {
                    v2!(
                        "copy-bin: new-root-auto already exposes /bin and /usr; \
                         skipping extra copies to avoid clobbering host binaries"
                    );
                }
            }
        }

        // Apply user-specified bind mounts before readonly root.
        for (host, inside, ro) in &opts.binds {
            // Ensure the target exists (best-effort for dirs)
            let _ = std::fs::create_dir_all(inside);
            v3!("bind {:?} -> {:?} (ro={})", host, inside, ro);
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

        // Optional tmpfs on /tmp (inside new_root if present)
        if opts.tmpfs_tmp {
            use std::fs;
            use std::path::PathBuf;

            let target: PathBuf = if let Some(ref root) = opts.new_root {
                root.join("tmp")
            } else {
                PathBuf::from("/tmp")
            };

            let _ = fs::create_dir_all(&target);

            v2!("mounting tmpfs on {:?}", target);
            mount::<str, Path, str, str>(
                Some("tmpfs"),
                &target,
                Some("tmpfs"),
                MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
                Some("size=512M"),
            )?;
        }

        // Apply readonly_root: if we have a new_root, remount that; otherwise `/`.
        if opts.readonly_root {
            if let Some(ref root) = opts.new_root {
                v3!("remount new_root {:?} read-only (best-effort)", root);
                let _ = mount::<str, Path, str, str>(
                    None,
                    root,
                    None,
                    MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
                    None,
                );
            } else {
                v3!("remount / read-only (best-effort)");
                let _ = mount::<str, str, str, str>(
                    None,
                    "/",
                    None,
                    MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
                    None,
                );
            }
        }
    }

    // 2) Create a new PID namespace (affects future children)
    if opts.use_pid {
        v2!("unshare(CLONE_NEWPID) — new PID namespace");
        unshare(CloneFlags::CLONE_NEWPID)?;
    }

    // 3) Fork so the child becomes PID 1 in the new PID namespace (if any).
    match unsafe { fork()? } {
        ForkResult::Child => {
            // --- Child == PID 1 ---
            #[cfg(feature = "uts")]
            if let Some(h) = &opts.hostname {
                v3!("sethostname({})", h);
                set_hostname(h)?; // requires UTS ns; userns grants caps in-ns
            }

            // If new_root is specified, chroot into it and cd to "/".
            if let Some(ref root) = opts.new_root {
                v3!("chroot into {:?}", root);
                chroot(root)?;
                chdir(Path::new("/"))?;
            }

            if opts.mount_proc && opts.use_mnt {
                v2!("mounting fresh /proc");
                setup_proc()?;
            }
            if let Some(dir) = &opts.chdir {
                chdir(dir)?;
            }

            // Put ourselves in a new process group so we can forward signals to the group.
            unsafe {
                libc::setpgid(0, 0);
            }
            v3!("setpgid(0,0) in PID1 child");

            // Spawn the actual payload so PID 1 can reap it.
            match unsafe { fork()? } {
    ForkResult::Child => {
        // --- Innermost payload child (will exec the target) ---

        // Optional privilege drop: root → unprivileged uid/gid inside the sandbox.
        if let Some(uid) = opts.drop_uid {
            let gid = opts.drop_gid.unwrap_or(uid);
            v3!("dropping privileges to uid={}, gid={}", uid, gid);

            // Clear supplementary groups first.
            unsafe {
                libc::setgroups(0, std::ptr::null());
            }

            if unsafe { libc::setgid(gid) } != 0 {
                log_error(&format!(
                    "setgid({}) failed: {}",
                    gid,
                    Errno::last()
                ));
                std::process::exit(127);
            }
            if unsafe { libc::setuid(uid) } != 0 {
                log_error(&format!(
                    "setuid({}) failed: {}",
                    uid,
                    Errno::last()
                ));
                std::process::exit(127);
            }

            v3!("privilege drop complete");
        }

        // Apply env rules in the innermost child before exec.
        if let Err(e) = apply_env(opts) {
            log_error(&format!("failed to apply env: {e}"));
            std::process::exit(127);
        }

        v3!("execvp({:?}, ...)", argv[0]);
        // Exec the target (on success, never returns)
        let e = execvp(&argv[0], argv).unwrap_err();
        log_error(&format!("exec failed: {e}"));
        std::process::exit(127);
    }
                ForkResult::Parent { child } => {
                    // === subreaper + signalfd + full forward + exhaustive reap ===

                    // 1) Become a subreaper: orphans in our subtree get reparented to us.
                    unsafe {
                        libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
                    }
                    v3!("set PR_SET_CHILD_SUBREAPER = 1");

                    // 2) Ensure the payload is its own process group; store its PGID
                    unsafe {
                        libc::setpgid(child.as_raw(), child.as_raw());
                    }
                    let payload_pgid: libc::pid_t = child.as_raw();
                    v3!("payload process group set to {}", payload_pgid);

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
                    v3!("blocked signals and installed signalfd mask");

                    // 4) signalfd to consume the blocked signals synchronously
                    let sfd = SignalFd::with_flags(&mask, SfdFlags::SFD_CLOEXEC)?;
                    v3!("created signalfd for supervised signals");

                    // 5) Main supervision loop: read signals → forward or reap
                    let mut exit_code: Option<i32> = None;

                    loop {
                        match sfd.read_signal() {
                            Ok(Some(si)) => {
                                let signo = si.ssi_signo as i32;
                                let sig = Signal::try_from(signo).ok();

                                if matches!(sig, Some(Signal::SIGCHLD)) {
                                    v3!("signalfd: received SIGCHLD (pid={})", si.ssi_pid);
                                    // Reap everything available; capture direct child's exit if any.
                                    if let Some(code) = reap_all(child.as_raw())? {
                                        v3!(
                                            "waitpid: pid {} exited with code {}",
                                            child,
                                            code
                                        );
                                        exit_code = Some(code);
                                    }
                                } else if let Some(sig) = sig {
                                    v3!(
                                        "forwarding signal {:?} to pgid {}",
                                        sig,
                                        payload_pgid
                                    );
                                    // Negative PGID means: deliver to the process group.
                                    unsafe {
                                        libc::kill(-payload_pgid, sig as i32);
                                    }
                                }

                                // If our direct child is done: graceful shutdown of the group
                                if let Some(code) = exit_code {
                                    v2!("direct child exited with code {}", code);
                                    // Best-effort TERM then KILL after a short grace
                                    unsafe { libc::kill(-payload_pgid, libc::SIGTERM) };
                                    // ~200ms grace
                                    let ts = libc::timespec {
                                        tv_sec: 0,
                                        tv_nsec: 200_000_000,
                                    };
                                    unsafe {
                                        libc::nanosleep(&ts, std::ptr::null_mut());
                                    }
                                    unsafe { libc::kill(-payload_pgid, libc::SIGKILL) };

                                    v2!(
                                        "payload exited; shutting down process group {}",
                                        payload_pgid
                                    );

                                    // Drain any stragglers before exiting
                                    let _ = reap_all(child.as_raw());

                                    // Restore TTY before exit
                                    tty_guard.restore();

                                    return Ok(code);
                                }
                            }
                            Ok(None) => continue,
                            Err(e) if e == Errno::EINTR => continue,
                            Err(e) => {
                                log_error(&format!("signalfd error: {e}"));
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
            v3!("outer parent waiting for init pid {}", child);
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
                log_error(&format!("argument contains interior NUL byte: {:?}", s));
                std::process::exit(64);
            }
        }
    }
    out
}
