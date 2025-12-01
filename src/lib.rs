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
    unistd::{chdir, chroot, execvp, fork, ForkResult},
};

use std::{
    ffi::CString,
    fs::OpenOptions,
    io::{self, IsTerminal, Write},
    os::fd::{AsRawFd, RawFd},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicU8, Ordering},
        OnceLock,
    },
};

// ===== runtime verbosity + logger pipe =========================================

static VERBOSITY: AtomicU8 = AtomicU8::new(0);
static LOG_FD: OnceLock<RawFd> = OnceLock::new();

/// Set global verbosity (0–3) from main.rs (`-v/-vv/-vvv`).
pub fn set_verbosity(level: u8) {
    VERBOSITY.store(level, Ordering::Relaxed);
}

/// Install the logging write-end fd for v2/v3 logs.
pub fn set_log_fd(fd: RawFd) {
    let _ = LOG_FD.set(fd);
}

fn stderr_is_terminal() -> bool {
    io::stderr().is_terminal()
}

/// Internal logging helper for v2/v3.
///
/// - Respects global VERBOSITY
/// - Writes either to the logging pipe (if installed) or directly to stderr.
/// - Each log line is a single write(2) so it does not interleave.
pub(crate) fn vlog_impl(level: u8, msg: &str) {
    if VERBOSITY.load(Ordering::Relaxed) < level {
        return;
    }

    let pid = unsafe { libc::getpid() };
    let line = format!("[v{level}] pid={pid} {msg}\n");

    if let Some(fd) = LOG_FD.get().copied() {
        let bytes = line.as_bytes();
        let mut written = 0usize;
        unsafe {
            while written < bytes.len() {
                let ptr = bytes.as_ptr().add(written) as *const libc::c_void;
                let len = (bytes.len() - written) as libc::size_t;
                let ret = libc::write(fd, ptr, len);
                if ret <= 0 {
                    break;
                }
                written += ret as usize;
            }
        }
    } else {
        let _ = io::stderr().write_all(line.as_bytes());
    }
}

macro_rules! v2 {
    ($($arg:tt)*) => {{
        crate::vlog_impl(2, &format!($($arg)*));
    }};
}

macro_rules! v3 {
    ($($arg:tt)*) => {{
        crate::vlog_impl(3, &format!($($arg)*));
    }};
}

fn log_error(msg: &str) {
    if stderr_is_terminal() {
        eprintln!("\x1b[31mproclet: {msg}\x1b[0m");
    } else {
        eprintln!("proclet: {msg}");
    }
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
    pub readonly_root: bool,
    pub binds: Vec<(PathBuf, PathBuf, bool)>, // (host, inside, ro?)

    /// Optional new root directory for chroot-like isolation.
    /// If set, proclet will chroot into this path inside the mount namespace.
    pub new_root: Option<PathBuf>,

    /// If true, automatically bind core system dirs into new_root:
    /// /usr, /bin, /sbin, /lib, /lib64 (only ones that exist).
    pub new_root_auto: bool,

    /// If true, build a minimal rootfs skeleton instead of auto-binding core dirs.
    /// Mutually exclusive *conceptually* with "fat" auto-root semantics.
    pub minimal_rootfs: bool,

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
        let mut guard = TtyGuard {
            fd,
            had_tty: false,
            prev_fg: None,
        };

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

        // Save previous foreground pgid (libc versions; no nix term feature needed)
        let pg = unsafe { libc::tcgetpgrp(fd) };
        if pg > 0 {
            guard.prev_fg = Some(pg);
        }

        // Hand TTY to the payload's process group
        if unsafe { libc::tcsetpgrp(fd, payload_pgid) } == 0 {
            guard.had_tty = true;
            v3!("tty: foreground -> payload pgid {}", payload_pgid);
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
                v3!("tty: foreground restored -> pgid {}", pg);
            }
        }
    }
}

// === new-root helpers ==============================================================

fn prepare_new_root(root: &Path, auto_populate: bool) -> Result<(), Errno> {
    // Ensure the root directory exists.
    std::fs::create_dir_all(root).map_err(to_errno)?;

    if !auto_populate {
        return Ok(());
    }

    const CORE_DIRS: &[&str] = &["/usr", "/bin", "/sbin", "/lib", "/lib64"];

    for host in CORE_DIRS {
        let host_path = Path::new(host);
        if !host_path.exists() {
            continue;
        }

        // Map "/usr" -> root/"usr", "/bin" -> root/"bin", etc.
        let rel = host.trim_start_matches('/');
        let inside = root.join(rel);

        if host_path.is_dir() {
            let _ = std::fs::create_dir_all(&inside);
        } else if let Some(parent) = inside.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        v3!("auto bind core {:?} -> {:?}", host_path, inside);

        mount(
            Some(host_path),
            &inside,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )?;
    }

    Ok(())
}

/// Build a "thin" / minimal rootfs skeleton at `root`:
/// - Ensures root exists
/// - Creates basic dirs: /bin, /usr/bin, /dev, /tmp, /etc
/// - Binds a minimal set of device nodes from host: /dev/null, /dev/zero, /dev/tty
fn build_minimal_rootfs(root: &Path) -> Result<(), Errno> {
    use std::fs::{self, File};

    v3!("building minimal rootfs skeleton at {:?}", root);

    fs::create_dir_all(root).map_err(to_errno)?;

    // Basic directory skeleton
    const DIRS: &[&str] = &["bin", "usr/bin", "dev", "tmp", "etc"];
    for d in DIRS {
        let path = root.join(d);
        fs::create_dir_all(&path).map_err(to_errno)?;
    }

    // Bind minimal /dev nodes from the host
    const DEV_NODES: &[&str] = &["null", "zero", "tty"];
    for dev in DEV_NODES {
        let host = Path::new("/dev").join(dev);
        if !host.exists() {
            v3!(
                "minimal-rootfs: host device {:?} does not exist, skipping",
                host
            );
            continue;
        }

        let inside = root.join("dev").join(dev);

        if let Some(parent) = inside.parent() {
            fs::create_dir_all(parent).map_err(to_errno)?;
        }

        // For a bind mount of a *file*, the target must already exist.
        if !inside.exists() {
            v3!("minimal-rootfs: creating placeholder device file {:?}", inside);
            File::create(&inside).map_err(to_errno)?;
        }

        v3!("minimal-rootfs: bind {:?} -> {:?}", host, inside);
        mount(
            Some(&host),
            &inside,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )?;
    }

    Ok(())
}

fn copy_into_new_root(root: &Path, sources: &[PathBuf]) -> Result<(), Errno> {
    use std::fs;

    for src in sources {
        if !src.is_absolute() {
            // Keep it strict for now; we can relax later if we add custom dest paths.
            v2!("new-root-copy: path {:?} is not absolute, rejecting", src);
            return Err(Errno::EINVAL);
        }

        if !src.exists() {
            // Best-effort: skip missing files, but log at v2.
            v2!("new-root-copy: source {:?} does not exist, skipping", src);
            continue;
        }

        // Strip leading "/" so "/etc/resolv.conf" -> "etc/resolv.conf"
        let rel = match src.strip_prefix("/") {
            Ok(r) => r,
            Err(_) => src.as_path(),
        };
        let dest = root.join(rel);

        if let Some(parent) = dest.parent() {
            let _ = fs::create_dir_all(parent);
        }

        v2!("new-root-copy: {:?} -> {:?}", src, dest);
        fs::copy(src, &dest).map_err(to_errno)?;
    }

    Ok(())
}

/// Copy one absolute path into `root`, preserving its absolute layout.
/// Example: src=/usr/bin/ls, root=/tmp/proclet-XXXXXX →
/// dest=/tmp/proclet-XXXXXX/usr/bin/ls
fn copy_path_into_root(root: &Path, src: &Path) -> Result<(), Errno> {
    use std::fs;

    if !src.is_absolute() {
        return Err(Errno::EINVAL);
    }
    if !src.exists() {
        v2!("copy-bin: source {:?} does not exist, skipping", src);
        return Ok(());
    }

    let rel = src.strip_prefix("/").unwrap_or(src);
    let dest = root.join(rel);

    if let Some(parent) = dest.parent() {
        let _ = fs::create_dir_all(parent);
    }

    v2!("copy-bin: {:?} -> {:?}", src, dest);
    fs::copy(src, &dest).map_err(to_errno)?;
    Ok(())
}

/// Use `ldd` to discover shared libs for each binary and copy them into new-root.
fn copy_bins_with_deps(root: &Path, bins: &[PathBuf]) -> Result<(), Errno> {
    for bin in bins {
        if !bin.is_absolute() {
            v2!("copy-bin: path {:?} is not absolute, rejecting", bin);
            return Err(Errno::EINVAL);
        }

        if !bin.exists() {
            v2!("copy-bin: {:?} does not exist, skipping", bin);
            continue;
        }

        // 1) Copy the binary itself.
        copy_path_into_root(root, bin)?;

        // 2) Ask ldd about its dependencies.
        let output = match Command::new("ldd").arg(bin).output() {
            Ok(o) => o,
            Err(e) => {
                v2!("copy-bin: failed to run ldd on {:?}: {}", bin, e);
                continue;
            }
        };

        if !output.status.success() {
            v2!("copy-bin: ldd {:?} returned non-zero, skipping libs", bin);
            continue;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            // Typical patterns:
            //   linux-vdso.so.1 (0x0000...)
            //   libm.so.6 => /usr/lib/libm.so.6 (0x0000...)
            //   /lib64/ld-linux-x86-64.so.2 (0x0000...)
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            // Look for the first token that looks like an absolute path.
            let mut candidate: Option<&str> = None;
            for &p in &parts {
                if p.starts_with('/') {
                    // Strip trailing ':' if any.
                    let cleaned = p.trim_end_matches(':');
                    candidate = Some(cleaned);
                    break;
                }
            }

            if let Some(path_str) = candidate {
                let lib_path = PathBuf::from(path_str);
                if lib_path.exists() {
                    copy_path_into_root(root, &lib_path)?;
                } else {
                    v3!(
                        "copy-bin: ldd reported {:?} but it does not exist, skipping",
                        lib_path
                    );
                }
            }
        }

        // Also ensure the dynamic linker itself is present if ldd reported it
        // (usually handled by the parsing above).
        let ld_candidates = ["/lib64/ld-linux-x86-64.so.2", "/lib/ld-linux.so.2"];
        for ld in ld_candidates {
            let p = Path::new(ld);
            if p.exists() {
                let _ = copy_path_into_root(root, p);
            }
        }
    }

    Ok(())
}

/// Apply environment policy from ProcletOpts:
/// - If `clear_env` is true, call clearenv()
/// - Then set each (key, value) pair via setenv()
fn apply_env(opts: &ProcletOpts) -> Result<(), Errno> {
    unsafe {
        if opts.clear_env {
            v3!("apply_env: clearenv()");
            if libc::clearenv() != 0 {
                return Err(Errno::last());
            }
        }

        if !opts.env.is_empty() {
            v3!(
                "apply_env: setting {} variable(s) (clear_env={})",
                opts.env.len(),
                opts.clear_env
            );
        }

        for (key, val) in &opts.env {
            let k_c = CString::new(key.as_str()).map_err(|_| Errno::EINVAL)?;
            let v_c = CString::new(val.as_str()).map_err(|_| Errno::EINVAL)?;
            if libc::setenv(k_c.as_ptr(), v_c.as_ptr(), 1) != 0 {
                return Err(Errno::last());
            }
        }
    }
    Ok(())
}

/// Run `argv` inside namespaces. Child acts as PID 1 if PID ns is used.
///
/// Order: USER → (UTS?) → MNT (+new-root) → PID
pub fn run_pid_mount(argv: &[CString], opts: &ProcletOpts) -> Result<i32, Errno> {
    if argv.is_empty() {
        return Err(Errno::EINVAL);
    }

    v2!(
        "starting sandbox: user={} pid={} mnt={} new_root={:?} minimal_rootfs={}",
        opts.use_user,
        opts.use_pid,
        opts.use_mnt,
        opts.new_root,
        opts.minimal_rootfs
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
        //   - minimal_rootfs: build skeleton + /dev binds
        //   - otherwise: optional auto-populate (/usr, /bin, ...)
        if let Some(ref root) = opts.new_root {
            if opts.minimal_rootfs {
                build_minimal_rootfs(root)?;
            } else {
                prepare_new_root(root, opts.new_root_auto)?;
            }

            if !opts.new_root_copy.is_empty() {
                copy_into_new_root(root, &opts.new_root_copy)?;
            }

            if !opts.copy_bin.is_empty() {
                copy_bins_with_deps(root, &opts.copy_bin)?;
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
                                    // Forward almost everything else to the entire payload process group.
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
                            Ok(None) => continue, // nothing to read (blocking fd, so unlikely)
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
