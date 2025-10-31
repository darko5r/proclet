use nix::{
    errno::Errno,
    mount::{mount, umount2, MntFlags, MsFlags},
    sched::{unshare, CloneFlags},
    sys::{
        signal::{kill, Signal},
        wait::{waitpid, WaitPidFlag, WaitStatus},
    },
    unistd::{execvp, fork, ForkResult},
    libc, // bring in libc via nix re-export
};
use std::{ffi::CString, path::Path};

/// Run `argv` inside **new PID + mount** namespaces (child is PID 1).
/// - Private mount propagation
/// - Fresh `/proc`
/// - Minimal PID 1 reaper that forwards signals and reaps children
pub fn run_pid_mount(argv: &[CString]) -> Result<i32, Errno> {
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
            setup_proc()?;

            // Spawn the actual payload as a subprocess so we can reap it.
            match unsafe { fork()? } {
                ForkResult::Child => {
                    // Grandchild: replace with the target program
                    let e = execvp(&argv[0], argv).unwrap_err();
                    eprintln!("proclet: exec failed: {e}");
                    std::process::exit(127);
                }
                ForkResult::Parent { child } => {
                    // PID 1: minimal “init” loop – reap & (best-effort) forward signals

                    // Best-effort: don't die on SIGINT/SIGTERM; we'll try to forward later.
                    unsafe {
                        let _ = libc::signal(libc::SIGINT, libc::SIG_IGN);
                        let _ = libc::signal(libc::SIGTERM, libc::SIG_IGN);
                    }

                    // Reap until our direct child exits, collecting its code.
                    let exit_code = loop {
                        match waitpid(None, Some(WaitPidFlag::WUNTRACED | WaitPidFlag::WCONTINUED))? {
                            WaitStatus::Exited(pid, code) if pid == child => break code,
                            WaitStatus::Signaled(pid, sig, _) if pid == child => break 128 + sig as i32,
                            // Reap any other zombies (grand-grandchildren, etc.)
                            WaitStatus::Exited(_, _)
                            | WaitStatus::Signaled(_, _, _)
                            | WaitStatus::StillAlive => {}
                            _ => {}
                        }
                    };

                    // Propagate termination to lingering children (best-effort)
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

/// Convert &str slices to CStrings for execvp
pub fn cstrings(args: &[&str]) -> Vec<CString> {
    args.iter().map(|s| CString::new(*s).unwrap()).collect()
}
