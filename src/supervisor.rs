use nix::{
    errno::Errno,
    sys::{
        signal::{SaFlags, SigAction, SigHandler, SigSet, Signal},
        wait::{waitpid, WaitPidFlag, WaitStatus},
    },
};

use std::os::fd::AsRawFd;

/// Exhaustively reap all available children. If `direct_pid` (the payload leader)
/// has exited, returns its exit code (or 128+signal).
pub fn reap_all(direct_pid: libc::pid_t) -> Result<Option<i32>, Errno> {
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

pub struct TtyGuard {
    fd: i32,
    had_tty: bool,
    prev_fg: Option<libc::pid_t>,
}

impl TtyGuard {
    pub fn take_for(payload_pgid: libc::pid_t) -> Self {
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

    pub fn restore(&self) {
        if self.had_tty {
            if let Some(pg) = self.prev_fg {
                let _ = unsafe { libc::tcsetpgrp(self.fd, pg) };
                v3!("tty: foreground restored -> pgid {}", pg);
            }
        }
    }
}
