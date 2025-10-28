use std::os::raw::c_char;

unsafe extern "C" {
    pub fn run_pid_ns(argv: *const *const c_char) -> i32;
}

pub fn run_pid_ns_safe(args: &[&str]) -> i32 {
    use std::ffi::CString;
    let cstrings: Vec<CString> = args.iter().map(|s| CString::new(*s).unwrap()).collect();
    let mut ptrs: Vec<*const c_char> = cstrings.iter().map(|s| s.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    unsafe { run_pid_ns(ptrs.as_ptr()) }
}

