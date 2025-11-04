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

use nix::{
    errno::Errno,
    mount::{mount, umount2, MntFlags, MsFlags},
    sched::{unshare, CloneFlags},
    sys::wait::{waitpid, WaitPidFlag, WaitStatus},
    unistd::{chdir, execvp, fork, ForkResult},
};
use std::{
    ffi::CString,
    path::{Path, PathBuf},
};

use std::fs::OpenOptions;
use std::io::Write;

fn write_file(path: &str, s: &str) -> Result<(), Errno> {
    let to_errno = |e: std::io::Error| Errno::from_raw(e.raw_os_error().unwrap_or(libc::EIO));
    let mut f = OpenOptions::new().write(true).open(path).map_err(to_errno)?;
    f.write_all(s.as_bytes()).map_err(to_errno)
}

/// Enter a user namespace and map real uid/gid → root (0) inside.
/// If we're already real root outside, skip userns entirely (not needed for mounts).
fn enter_userns_map_root() -> Result<(), Errno> {
    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };

    // If running as real root, just don't use a user namespace.
    if euid == 0 {
        return Ok(());
    }

    // Create the user namespace
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

/// Runtime options for Proclet.
#[derive(Debug, Default, Clone)]
pub struct ProcletOpts {
    /// Remount a fresh `/proc` inside the sandbox. Disable for debugging.
    pub mount_proc: bool,
    /// Optional hostname to set inside the (shared) UTS context.
    pub hostname: Option<String>,
    /// Optional working directory to `chdir` into before exec.
    pub chdir: Option<PathBuf>,

    // Namespace/FS toggles populated by main.rs
    pub use_user: bool,
    pub use_pid: bool,
    pub use_mnt: bool,
    pub readonly_root: bool,
    pub binds: Vec<(PathBuf, PathBuf, bool)>, // (host, inside, ro?)
}

/// Run `argv` inside namespaces. Child acts as PID 1 if PID ns is used.
///
/// Order: USER → MNT → PID
pub fn run_pid_mount(argv: &[CString], opts: &ProcletOpts) -> Result<i32, Errno> {
    if argv.is_empty() {
        return Err(Errno::EINVAL);
    }

    // 0) User namespace first (enables unprivileged mounts inside)
    if opts.use_user {
        enter_userns_map_root()?;
    }

    // 1) Isolate mount namespace so our mounts don't leak out.
    if opts.use_mnt {
        unshare(CloneFlags::CLONE_NEWNS)?;
        mount::<str, str, str, str>(
            None,
            "/",
            None,
            MsFlags::MS_REC | MsFlags::MS_PRIVATE,
            None,
        )?;

        // Apply bind mounts before readonly root
        for (host, inside, ro) in &opts.binds {
            // Ensure the target exists (best-effort for dirs)
            let _ = std::fs::create_dir_all(inside);
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
        unshare(CloneFlags::CLONE_NEWPID)?;
    }

    // 3) Fork so the child becomes PID 1 in the new PID namespace (if any).
    match unsafe { fork()? } {
        ForkResult::Child => {
            // --- Child == PID 1 ---
            if let Some(h) = &opts.hostname {
                set_hostname(h)?; // works after userns mapping if CAP_SYS_ADMIN in-ns
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
                    // Exec the target (on success, never returns)
                    let e = execvp(&argv[0], argv).unwrap_err();
                    eprintln!("proclet: exec failed: {e}");
                    std::process::exit(127);
                }
                ForkResult::Parent { child } => {
                    // Ignore ctrl-c/term in PID1; we will forward to child group instead.
                    unsafe {
                        libc::signal(libc::SIGINT, libc::SIG_IGN);
                        libc::signal(libc::SIGTERM, libc::SIG_IGN);
                    }

                    // Forward SIGINT/SIGTERM that PID1 receives to the child’s process group.
                    extern "C" fn fwd_sig(sig: libc::c_int) {
                        unsafe {
                            let pg = libc::getpgrp();
                            if pg > 0 {
                                // Negative PGID targets the whole process group
                                let _ = libc::kill(-pg, sig);
                            }
                        }
                    }
                    unsafe {
                        let mut sa: libc::sigaction = std::mem::zeroed();
                        // Use sa_handler to avoid union casting gymnastics
                        sa.sa_sigaction = fwd_sig as usize;
                        sa.sa_flags = 0;
                        libc::sigemptyset(&mut sa.sa_mask);
                        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
                        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
                    }

                    // Reap until direct child exits; propagate exit code.
                    let exit_code = loop {
                        match waitpid(
                            None,
                            Some(WaitPidFlag::WUNTRACED | WaitPidFlag::WCONTINUED),
                        )? {
                            WaitStatus::Exited(pid, code) if pid == child => break code,
                            WaitStatus::Signaled(pid, sig, _) if pid == child => {
                                break 128 + sig as i32
                            }
                            // Reap strays/zombies; continue waiting for our direct child.
                            WaitStatus::Exited(_, _)
                            | WaitStatus::Signaled(_, _, _)
                            | WaitStatus::StillAlive => {}
                            _ => {}
                        }
                    };

                    // Best-effort termination for leftovers in our group.
                    unsafe {
                        let pg = libc::getpgrp();
                        if pg > 0 {
                            let _ = libc::kill(-pg, libc::SIGTERM);
                        }
                    }

                    Ok(exit_code)
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
