use nix::errno::Errno;
use std::ffi::CString;

use crate::ProcletOpts;

/// Apply environment policy from ProcletOpts:
/// - If `clear_env` is true, call clearenv()
/// - Then set each (key, value) pair via setenv()
pub fn apply_env(opts: &ProcletOpts) -> Result<(), Errno> {
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
