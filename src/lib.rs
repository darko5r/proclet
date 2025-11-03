use nix::{
    errno::Errno,
    mount::{mount, umount2, MntFlags, MsFlags},
    sched::{unshare, CloneFlags},
    sys::{
        signal::{kill, Signal},
        wait::{waitpid, WaitPidFlag, WaitStatus},
    },
    unistd::{chdir, execvp, fork, ForkResult},
    libc,
};
use std::{ffi::CString, path::{Path, PathBuf}};

/// Runtime options for Proclet.
#[derive(Debug, Default, Clone)]
pub struct ProcletOpts {
    /// Remount a fresh `/proc` inside the sandbox. Disable with `--no-proc` for debugging.
    pub mount_proc: bool,
    /// Optional hostname to set inside the UTS namespace.
    pub hostname: Option<String>,
    /// Optional working directory to `chdir` into before exec.
    pub chdir: Option<PathBuf>,
}

/// Run `argv` inside **new PID + mount** namespaces (child is PID 1).
/// - Private mount propagation
/// - Optional fresh `/proc`
/// - Minimal PID 1 reaper that forwards signals and reaps children
pub fn run_pid_mount(argv: &[CString], opts: &ProcletOpts) -> Result<i32, Errno> {
    // 1) Isolate mount ns first (so our mount ops don’t leak)
    unshare(CloneFlags::CLONE_NEWNS)?;
    mount::<str, str, str, str>(
        None, "/", None,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None,
    )?;

    // 2) Create a new PID ns; affects *future* children.
    unshare(CloneFlags::CLONE_NEWPID)?;

    // 3) Fork: child becomes PID 1 inside new PID ns.
    match unsafe { fork()? } {
        ForkResult::Child => {
            // Child == PID 1
            if let Some(h) = &opts.hostname {
                set_hostname(h)?;
            }
            if opts.mount_proc {
                setup_proc()?;
            }
            if let Some(dir) = &opts.chdir {
                chdir(dir)?;
            }

            // Spawn the actual payload as a subprocess so we can reap it.
            match unsafe { fork()? } {
                ForkResult::Child => {
                    let e = execvp(&argv[0], argv).unwrap_err();
                    eprintln!("proclet: exec failed: {e}");
                    std::process::exit(127);
                }
                ForkResult::Parent { child } => {
                    // PID 1: minimal “init” loop – reap & (best-effort) forward signals
                    unsafe {
                        let _ = libc::signal(libc::SIGINT, libc::SIG_IGN);
                        let _ = libc::signal(libc::SIGTERM, libc::SIG_IGN);
                    }

                    let exit_code = loop {
                        match waitpid(None, Some(WaitPidFlag::WUNTRACED | WaitPidFlag::WCONTINUED))? {
                            WaitStatus::Exited(pid, code) if pid == child => break code,
                            WaitStatus::Signaled(pid, sig, _) if pid == child => break 128 + sig as i32,
                            // Reap any other zombies
                            WaitStatus::Exited(_, _)
                            | WaitStatus::Signaled(_, _, _)
                            | WaitStatus::StillAlive => {}
                            _ => {}
                        }
                    };

                    let _ = kill(child, Signal::SIGTERM);
                    Ok(exit_code)
                }
            }
        }
        ForkResult::Parent { child } => {
            // Original process: wait for the namespace’s PID 1 to finish
            match waitpid(child, None)? {
                WaitStatus::Exited(_, code) => Ok(code),
                WaitStatus::Signaled(_, sig, _) => Ok(128 + sig as i32),
                _ => Ok(1),
            }
        }
    }
}

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

fn set_hostname(name: &str) -> Result<(), Errno> {
    // Use libc directly to avoid needing extra nix features.
    let c = CString::new(name).map_err(|_| Errno::EINVAL)?;
    let rc = unsafe { libc::sethostname(c.as_ptr(), name.len()) };
    if rc == 0 { Ok(()) } else { Err(Errno::last()) }
}

/// Convert &str slices to CStrings for execvp
pub fn cstrings(args: &[&str]) -> Vec<CString> {
    args.iter().map(|s| CString::new(*s).unwrap()).collect()
}
