use nix::{
    errno::Errno,
    mount::{mount, umount2, MntFlags, MsFlags},
    sched::{unshare, CloneFlags},
    sys::{
        signal::{kill, Signal},
        wait::{waitpid, WaitPidFlag, WaitStatus},
    },
    unistd::{chdir, execvp, fork, ForkResult},
};
use std::{
    ffi::CString,
    path::{Path, PathBuf},
};

/// Runtime options for Proclet.
#[derive(Debug, Default, Clone)]
pub struct ProcletOpts {
    /// Remount a fresh `/proc` inside the sandbox. Disable for debugging.
    pub mount_proc: bool,
    /// Optional hostname to set inside the (shared) UTS context.
    pub hostname: Option<String>,
    /// Optional working directory to `chdir` into before exec.
    pub chdir: Option<PathBuf>,
}

/// Run `argv` inside **new PID + mount** namespaces (child acts as PID 1).
/// Steps:
/// 1) New mount namespace with private propagation
/// 2) New PID namespace
/// 3) PID 1 optionally sets hostname, mounts fresh `/proc`, chdir()
/// 4) PID 1 forks payload, reaps it, returns its exit code
pub fn run_pid_mount(argv: &[CString], opts: &ProcletOpts) -> Result<i32, Errno> {
    // 1) Isolate mount namespace so our mounts don't leak out.
    unshare(CloneFlags::CLONE_NEWNS)?;
    mount::<str, str, str, str>(
        None,
        "/",
        None,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None,
    )?;

    // 2) Create a new PID namespace. This affects *future* children only.
    unshare(CloneFlags::CLONE_NEWPID)?;

    // 3) Fork so the child becomes PID 1 in the new PID namespace.
    match unsafe { fork()? } {
        ForkResult::Child => {
            // --- Child == PID 1 ---
            if let Some(h) = &opts.hostname {
                set_hostname(h)?;
            }
            if opts.mount_proc {
                setup_proc()?;
            }
            if let Some(dir) = &opts.chdir {
                chdir(dir)?;
            }

            // Spawn the actual payload so PID 1 can reap it.
            match unsafe { fork()? } {
                ForkResult::Child => {
                    // Exec the target
                    let e = execvp(&argv[0], argv).unwrap_err();
                    eprintln!("proclet: exec failed: {e}");
                    std::process::exit(127);
                }
                ForkResult::Parent { child } => {
                    // Minimal “init” loop: reap child; best-effort signal handling.
                    unsafe {
                        // Ignore these so PID 1 doesn’t die early.
                        libc::signal(libc::SIGINT, libc::SIG_IGN);
                        libc::signal(libc::SIGTERM, libc::SIG_IGN);
                    }

                    // Reap until our direct child exits; collect its status.
                    let exit_code = loop {
                        match waitpid(
                            None,
                            Some(WaitPidFlag::WUNTRACED | WaitPidFlag::WCONTINUED),
                        )? {
                            WaitStatus::Exited(pid, code) if pid == child => break code,
                            WaitStatus::Signaled(pid, sig, _) if pid == child => break 128 + sig as i32,
                            // Reap strays/zombies; continue waiting for our direct child.
                            WaitStatus::Exited(_, _)
                            | WaitStatus::Signaled(_, _, _)
                            | WaitStatus::StillAlive => {}
                            _ => {}
                        }
                    };

                    // Best-effort propagation of termination to leftover children.
                    let _ = kill(child, Signal::SIGTERM);
                    Ok(exit_code)
                }
            }
        }
        ForkResult::Parent { child } => {
            // --- Original process: wait for PID 1 (namespace init) to finish ---
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
    args.iter().map(|s| CString::new(*s).unwrap()).collect()
}
