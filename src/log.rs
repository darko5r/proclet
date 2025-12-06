use std::{
    io::{self, IsTerminal, Write},
    os::fd::RawFd,
    sync::{
        atomic::{AtomicU8, Ordering},
        OnceLock,
    },
};

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

pub fn log_error(msg: &str) {
    if stderr_is_terminal() {
        eprintln!("\x1b[31mproclet: {msg}\x1b[0m");
    } else {
        eprintln!("proclet: {msg}");
    }
}

// ===== macros, exported crate-wide via #[macro_use] in lib.rs =====================

macro_rules! v2 {
    ($($arg:tt)*) => {{
        $crate::log::vlog_impl(2, &format!($($arg)*));
    }};
}

macro_rules! v3 {
    ($($arg:tt)*) => {{
        $crate::log::vlog_impl(3, &format!($($arg)*));
    }};
}

