use crate::log_error;
use nix::errno::Errno;
use std::{
    ffi::CStr,
    os::unix::{fs::FileTypeExt, net::UnixStream},
    path::{Path, PathBuf},
    process::Command,
};

/// Result of probing a parent compositor socket we can connect to.
#[derive(Debug, Clone)]
pub struct ParentWayland {
    pub runtime_dir: PathBuf,  // e.g. /run/user/0
    pub socket_name: String,   // e.g. wayland-0
    pub socket_path: PathBuf,  // e.g. /run/user/0/wayland-0
}

/// Try to connect to a unix socket path to ensure it is live.
/// This avoids false positives where a stale socket file exists but compositor is gone.
fn socket_is_live(p: &Path) -> bool {
    UnixStream::connect(p).is_ok()
}

/// Return username for uid using getpwuid (no external `getent` dependency).
fn username_for_uid(uid: u32) -> Option<String> {
    unsafe {
        let pw = libc::getpwuid(uid as libc::uid_t);
        if pw.is_null() {
            return None;
        }
        let pw = *pw;
        if pw.pw_name.is_null() {
            return None;
        }
        Some(CStr::from_ptr(pw.pw_name).to_string_lossy().into_owned())
    }
}

/// Find a live parent Wayland compositor socket owned by root session.
///
/// Strategy:
/// 1) Prefer $XDG_RUNTIME_DIR/$WAYLAND_DISPLAY if it points to a live socket.
/// 2) Else scan /run/user/0/wayland-* and pick the first live one.
pub fn find_parent_wayland_socket() -> Option<ParentWayland> {
    // Prefer environment if present.
    if let (Some(rt), Some(disp)) = (std::env::var_os("XDG_RUNTIME_DIR"), std::env::var("WAYLAND_DISPLAY").ok()) {
        let p = PathBuf::from(rt).join(&disp);
        if p.starts_with("/run/user/0/") && socket_is_live(&p) {
            return Some(ParentWayland {
                runtime_dir: PathBuf::from("/run/user/0"),
                socket_name: disp,
                socket_path: p,
            });
        }
    }

    // Fallback: scan /run/user/0/wayland-*
    let rt = PathBuf::from("/run/user/0");
    let entries = std::fs::read_dir(&rt).ok()?;
    for ent in entries.flatten() {
        let name = ent.file_name().to_string_lossy().into_owned();
        if !name.starts_with("wayland-") {
            continue;
        }
        let p = rt.join(&name);
        // Must be a socket file and live.
        if ent.file_type().ok().map(|t| t.is_socket()).unwrap_or(false) && socket_is_live(&p) {
            return Some(ParentWayland {
                runtime_dir: rt.clone(),
                socket_name: name,
                socket_path: p,
            });
        }
    }

    None
}

/// Best-effort ACL grant for connecting to root compositor socket.
/// This mirrors:
///   setfacl -m u:USER:rw /run/user/0/wayland-0
///   setfacl -m u:USER:rx /run/user/0
///
/// Notes:
/// - We run this as root, before dropping privileges.
/// - We intentionally do NOT fail the sandbox if ACL tooling is missing.
/// - If it fails, caller can decide whether to continue.
pub fn grant_wayland_acl_best_effort(target_uid: u32, parent: &ParentWayland) -> Result<(), Errno> {
    if target_uid == 0 {
        return Ok(()); // nothing to do
    }

    let user = match username_for_uid(target_uid) {
        Some(u) => u,
        None => {
            log_error(&format!("wayland: cannot resolve username for uid={}", target_uid));
            return Err(Errno::EINVAL);
        }
    };

    // Use setfacl if available.
    // We do two calls to keep it simple and readable.
    let sock = parent.socket_path.to_string_lossy().to_string();
    let dir = parent.runtime_dir.to_string_lossy().to_string();

    let st1 = Command::new("setfacl")
        .args(["-m", &format!("u:{}:rw", user), &sock])
        .status();

    match st1 {
        Ok(s) if s.success() => {}
        Ok(s) => {
            log_error(&format!("wayland: setfacl on socket failed (exit={:?})", s.code()));
            return Err(Errno::EPERM);
        }
        Err(e) => {
            log_error(&format!("wayland: failed to execute setfacl (socket): {}", e));
            return Err(Errno::ENOENT);
        }
    }

    let st2 = Command::new("setfacl")
        .args(["-m", &format!("u:{}:rx", user), &dir])
        .status();

    match st2 {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => {
            log_error(&format!("wayland: setfacl on runtime dir failed (exit={:?})", s.code()));
            Err(Errno::EPERM)
        }
        Err(e) => {
            log_error(&format!("wayland: failed to execute setfacl (dir): {}", e));
            Err(Errno::ENOENT)
        }
    }
}

/// Ensure opts.env contains env needed to talk to root compositor.
/// This is the other half of your manual workflow: point the payload to /run/user/0.
pub fn ensure_env_points_to_parent_socket(
    env_pairs: &mut Vec<(String, String)>,
    parent: &ParentWayland,
) {
    let set_if_missing = |env: &mut Vec<(String, String)>, k: &str, v: String| {
        if !env.iter().any(|(ek, _)| ek == k) {
            env.push((k.to_string(), v));
        }
    };

    set_if_missing(env_pairs, "XDG_RUNTIME_DIR", parent.runtime_dir.to_string_lossy().to_string());
    set_if_missing(env_pairs, "WAYLAND_DISPLAY", parent.socket_name.clone());
    set_if_missing(env_pairs, "XDG_SESSION_TYPE", "wayland".to_string());
}
