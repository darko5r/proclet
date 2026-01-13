use crate::log_error;
use nix::errno::Errno;
use std::{
    ffi::CStr,
    os::unix::{fs::FileTypeExt, net::UnixStream},
    path::{Path, PathBuf},
    process::Command,
};

/// Result of probing a compositor socket we can connect to.
#[derive(Debug, Clone)]
pub struct ParentWayland {
    pub runtime_dir: PathBuf, // e.g. /run/user/1000 or /run/user/0
    pub socket_name: String,  // e.g. wayland-0
    pub socket_path: PathBuf, // e.g. /run/user/1000/wayland-0
}

/// Try to connect to a unix socket path to ensure it is live.
/// This avoids false positives where a stale socket file exists but compositor is gone.
fn socket_is_live(p: &Path) -> bool {
    UnixStream::connect(p).is_ok()
}

/// Check whether a path is a unix socket.
fn path_is_socket(p: &Path) -> bool {
    std::fs::metadata(p)
        .ok()
        .map(|m| m.file_type().is_socket())
        .unwrap_or(false)
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

/// Try to find a live Wayland compositor socket inside `runtime_dir`.
///
/// Preference order:
/// 1) `wayland-0` if present and live (common case)
/// 2) first live `wayland-*` socket found
pub fn probe_wayland_runtime(runtime_dir: &Path) -> Option<ParentWayland> {
    // Prefer wayland-0 first (common case)
    let preferred = runtime_dir.join("wayland-0");
    if path_is_socket(&preferred) && socket_is_live(&preferred) {
        return Some(ParentWayland {
            runtime_dir: runtime_dir.to_path_buf(),
            socket_name: "wayland-0".to_string(),
            socket_path: preferred,
        });
    }

    let entries = std::fs::read_dir(runtime_dir).ok()?;
    for ent in entries.flatten() {
        let name = ent.file_name().to_string_lossy().into_owned();
        if !name.starts_with("wayland-") {
            continue;
        }
        let p = runtime_dir.join(&name);
        let is_sock = ent
            .file_type()
            .ok()
            .map(|t| t.is_socket())
            .unwrap_or(false);

        if is_sock && socket_is_live(&p) {
            return Some(ParentWayland {
                runtime_dir: runtime_dir.to_path_buf(),
                socket_name: name,
                socket_path: p,
            });
        }
    }

    None
}

/// Find a live Wayland socket based on the current environment.
///
/// Strategy:
/// 1) If $XDG_RUNTIME_DIR and $WAYLAND_DISPLAY are set and point to a live socket, use that.
/// 2) Else scan $XDG_RUNTIME_DIR for wayland-*.
/// 3) Else (best-effort) if running as root, try /run/user/0.
/// 4) Else give up.
///
/// Note: policy about *which* runtime dirs should be trusted belongs in the caller.
/// This function is intentionally just a probe.
pub fn find_parent_wayland_socket() -> Option<ParentWayland> {
    // 1) Prefer environment if it looks valid.
    if let (Some(rt_os), Some(disp)) = (
        std::env::var_os("XDG_RUNTIME_DIR"),
        std::env::var("WAYLAND_DISPLAY").ok(),
    ) {
        let rt = PathBuf::from(rt_os);
        let p = rt.join(&disp);
        if path_is_socket(&p) && socket_is_live(&p) {
            return Some(ParentWayland {
                runtime_dir: rt,
                socket_name: disp,
                socket_path: p,
            });
        }
    }

    // 2) Scan $XDG_RUNTIME_DIR if present.
    if let Some(rt_os) = std::env::var_os("XDG_RUNTIME_DIR") {
        let rt = PathBuf::from(rt_os);
        if let Some(found) = probe_wayland_runtime(&rt) {
            return Some(found);
        }
    }

    // 3) Best-effort fallback: root session runtime (only if we are root).
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        let rt0 = PathBuf::from("/run/user/0");
        if let Some(found) = probe_wayland_runtime(&rt0) {
            return Some(found);
        }
    }

    None
}

/// Best-effort ACL grant for connecting to a compositor socket owned by another user.
/// This mirrors:
///   setfacl -m u:USER:rx /run/user/<owner>
///   setfacl -m u:USER:rw /run/user/<owner>/wayland-0
///
/// Notes:
/// - We run this as root, before dropping privileges.
/// - We intentionally do NOT fail the sandbox if ACL tooling is missing.
/// - This grant is *persistent* unless you implement revocation in the caller.
pub fn grant_wayland_acl_best_effort(
    target_uid: u32,
    parent: &ParentWayland,
) -> Result<(), Errno> {
    if target_uid == 0 {
        return Ok(()); // nothing to do
    }

    // Prefer username, but fall back to numeric uid if lookup fails.
    let user_spec = match username_for_uid(target_uid) {
        Some(name) => name,
        None => {
            log_error(&format!(
                "wayland: cannot resolve username for uid={}, falling back to numeric ACL",
                target_uid
            ));
            target_uid.to_string()
        }
    };

    // Use setfacl if available. Two calls to keep it readable.
    let sock = parent.socket_path.to_string_lossy().to_string();
    let dir = parent.runtime_dir.to_string_lossy().to_string();

    // 1) Grant rw on the socket
    let st1 = Command::new("setfacl")
        .args(["-m", &format!("u:{}:rw", user_spec), &sock])
        .status();

    match st1 {
        Ok(s) if s.success() => {}
        Ok(s) => {
            log_error(&format!(
                "wayland: setfacl on socket failed (exit={:?})",
                s.code()
            ));
            return Err(Errno::EPERM);
        }
        Err(e) => {
            log_error(&format!("wayland: failed to execute setfacl (socket): {}", e));
            return Err(Errno::ENOENT);
        }
    }

    // 2) Grant rx on the runtime dir (needed to reach the socket path)
    let st2 = Command::new("setfacl")
        .args(["-m", &format!("u:{}:rx", user_spec), &dir])
        .status();

    match st2 {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => {
            log_error(&format!(
                "wayland: setfacl on runtime dir failed (exit={:?})",
                s.code()
            ));
            Err(Errno::EPERM)
        }
        Err(e) => {
            log_error(&format!("wayland: failed to execute setfacl (dir): {}", e));
            Err(Errno::ENOENT)
        }
    }
}

/// Ensure env contains what is needed to talk to the compositor socket.
/// We only set values if they are missing, so explicit --env overrides win.
pub fn ensure_env_points_to_parent_socket(env_pairs: &mut Vec<(String, String)>, parent: &ParentWayland) {
    fn set_if_missing(env: &mut Vec<(String, String)>, k: &str, v: String) {
        if !env.iter().any(|(ek, _)| ek == k) {
            env.push((k.to_string(), v));
        }
    }

    set_if_missing(
        env_pairs,
        "XDG_RUNTIME_DIR",
        parent.runtime_dir.to_string_lossy().to_string(),
    );
    set_if_missing(env_pairs, "WAYLAND_DISPLAY", parent.socket_name.clone());
    set_if_missing(env_pairs, "XDG_SESSION_TYPE", "wayland".to_string());
}
