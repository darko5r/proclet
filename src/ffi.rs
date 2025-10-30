use std::os::raw::{c_char, c_int};

unsafe extern "C" {
    fn proclet_run_pid_mount(argv: *const *const c_char) -> c_int;
}

// Safe wrapper: we uphold argv’s invariants in main.rs
pub fn run_pid_mount(argv: *const *const c_char) -> c_int {
    unsafe { proclet_run_pid_mount(argv) }
}
