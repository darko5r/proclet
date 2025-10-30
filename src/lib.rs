use nix::{
    errno::Errno,
    mount::{mount, umount2, MntFlags, MsFlags},
    sched::{clone, unshare, CloneFlags},
    sys::signal::Signal,
    sys::wait::{waitpid, WaitStatus},
    unistd::execvp,
};
use std::{ffi::CString, path::Path};

/// Run `argv` inside **new PID + mount** namespaces.
/// 
/// - The child becomes **PID 1** in the new PID namespace.
/// - The mount namespace is made **private**, so mount changes don’t affect the host.
/// - A fresh `/proc` filesystem is mounted inside the sandbox.
///
/// # Returns
/// * `Ok(exit_code)` — exit code of the child process.
/// * `Err(Errno)` — setup or clone failure before execution.
///
/// # Example
/// ```no_run
/// use proclet::{cstrings, run_pid_mount};
/// let args = cstrings(&["/bin/sh", "-c", "echo Hello from sandbox"]);
/// let code = run_pid_mount(&args).unwrap();
/// println!("child exited with code {}", code);
/// ```
pub fn run_pid_mount(argv: &[CString]) -> Result<i32, Errno> {
    // 1) Unshare the mount namespace so mount operations are isolated
    unshare(CloneFlags::CLONE_NEWNS)?;

    // Make existing mounts private so they don’t propagate
    mount::<str, str, str, str>(
        None,
        "/",
        None,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None,
    )?;

    // 2) Create new PID namespace; child will become PID 1
    // nix 0.29 clone() requires a child stack buffer.
    let mut stack = vec![0u8; 1024 * 1024]; // 1 MiB stack

    let child = unsafe {
        clone(
            Box::new(|| -> isize {
                // --- Inside child process (PID 1 in the new PID namespace) ---

                // Fresh /proc inside the new namespace
                let proc_path = Path::new("/proc");
                let _ = umount2(proc_path, MntFlags::MNT_DETACH);
                let _ = std::fs::create_dir_all(proc_path);

                if let Err(e) = mount::<str, str, str, str>(
                    Some("proc"),
                    "/proc",
                    Some("proc"),
                    MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
                    None,
                ) {
                    eprintln!("proclet: mount /proc failed: {e}");
                    return 127;
                }

                // Exec target program — never returns on success
                let e = execvp(&argv[0], argv).unwrap_err();
                eprintln!("proclet: exec failed: {e}");
                127
            }),
            &mut stack,
            CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNS,
            Some(Signal::SIGCHLD as i32),
        )
    }?;

    // 3) Reap child and return its exit status
    match waitpid(child, None)? {
        WaitStatus::Exited(_, code) => Ok(code),
        WaitStatus::Signaled(_, sig, _) => Ok(128 + sig as i32),
        _ => Ok(1),
    }
}

/// Convert string slices to C-compatible strings for execvp.
///
/// Example:
/// ```
/// let args = cstrings(&["/bin/sh", "-c", "echo Hello"]);
/// ```
pub fn cstrings(args: &[&str]) -> Vec<CString> {
    args.iter().map(|s| CString::new(*s).unwrap()).collect()
}
