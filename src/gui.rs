// src/gui.rs
use crate::{log_error, wayland};
use std::path::{PathBuf};
use std::process::Command;

/// Prepare a “desktop-like” environment when running as root but dropping to a
/// real user (Chrome/Firefox etc).
///
/// Returns extra bind mounts to be applied by the mount namespace code:
///   (host_path, inside_path, read_only)
///
/// Policy:
/// - Keep XDG_RUNTIME_DIR as /run/user/<uid> for sane DBus + per-user runtime.
/// - If parent compositor socket is elsewhere (often /run/user/0), bind-mount the
///   socket inode into /run/user/<uid>/<socket_name>.
/// - Best-effort ACL grant so uid can connect.
/// - Avoid breaking explicit user overrides passed via --env.
pub fn prepare_desktop(
    env_pairs: &mut Vec<(String, String)>,
    cmd_vec: &mut Vec<String>,
    target_uid: u32,
    verbosity: u8,
) -> Vec<(PathBuf, PathBuf, bool)> {
    let mut extra_binds: Vec<(PathBuf, PathBuf, bool)> = Vec::new();

    // Respect explicit user intent.
    if env_has(env_pairs, "WAYLAND_DISPLAY") || env_has(env_pairs, "DISPLAY") {
        return extra_binds;
    }

    // We always want a sane runtime for the target user.
    let target_runtime = PathBuf::from(format!("/run/user/{target_uid}"));
    set_if_missing(env_pairs, "XDG_RUNTIME_DIR", target_runtime.to_string_lossy().to_string());

    // Remove root session DBus if user did not explicitly pass it via --env.
    // (Keeping root's DBUS_SESSION_BUS_ADDRESS while dropping to uid=1000 is a common source of weirdness.)
    if !env_has(env_pairs, "DBUS_SESSION_BUS_ADDRESS") {
        // remove inherited one by overwriting to empty only if clear_env was used in main;
        // since we can’t see clear_env here, we do the safer thing: do nothing.
        // Instead we’ll prefer wrapping with dbus-run-session below.
    }

    // Try to find a live parent Wayland socket (based on current env + fallback probes).
    let parent = match wayland::find_parent_wayland_socket() {
        Some(p) => p,
        None => {
            if verbosity > 0 {
                log_error("gui: no live Wayland socket detected; leaving GUI env untouched");
            }
            maybe_wrap_dbus_run_session(cmd_vec, verbosity);
            return extra_binds;
        }
    };

    // If the parent socket already lives under the target runtime dir, just point env there.
    if parent.runtime_dir == target_runtime {
        wayland::ensure_env_points_to_parent_socket(env_pairs, &parent);
        maybe_wrap_dbus_run_session(cmd_vec, verbosity);
        return extra_binds;
    }

    // Otherwise: bridge the socket inode into the target runtime dir.
    // Example:
    //   /run/user/0/wayland-0  ->  /run/user/1000/wayland-0
    let inside_socket_path = target_runtime.join(&parent.socket_name);

    // Best-effort ACL grant so uid can connect to the socket inode.
    // (ACL is on the inode; binding it into another path still uses the same inode ACL.)
    if let Err(e) = wayland::grant_wayland_acl_best_effort(target_uid, &parent) {
        if verbosity > 0 {
            log_error(&format!("gui: wayland ACL grant failed (best-effort): {e}"));
        }
    }

    // Tell the sandbox to mount the socket into the user's runtime dir.
    // Must be RW.
    extra_binds.push((parent.socket_path.clone(), inside_socket_path.clone(), false));

    // Now point env at the bridged socket living under /run/user/<uid>.
    set_if_missing(
        env_pairs,
        "WAYLAND_DISPLAY",
        parent.socket_name.clone(),
    );
    set_if_missing(env_pairs, "XDG_SESSION_TYPE", "wayland".to_string());

    // Ensure we didn’t accidentally leave XDG_RUNTIME_DIR pointing to parent runtime.
    // (We want DBus in /run/user/<uid>.)
    set_override(env_pairs, "XDG_RUNTIME_DIR", target_runtime.to_string_lossy().to_string());

    maybe_wrap_dbus_run_session(cmd_vec, verbosity);
    extra_binds
}

// -------- small helpers --------

fn env_has(env: &[(String, String)], k: &str) -> bool {
    env.iter().any(|(ek, _)| ek == k)
}

fn set_if_missing(env: &mut Vec<(String, String)>, k: &str, v: String) {
    if !env.iter().any(|(ek, _)| ek == k) {
        env.push((k.to_string(), v));
    }
}

/// Force-set (replace if exists, otherwise push).
fn set_override(env: &mut Vec<(String, String)>, k: &str, v: String) {
    if let Some(pos) = env.iter().position(|(ek, _)| ek == k) {
        env[pos] = (k.to_string(), v);
    } else {
        env.push((k.to_string(), v));
    }
}

/// If dbus-run-session exists and command is not already wrapped, wrap it:
///   dbus-run-session -- <orig...>
fn maybe_wrap_dbus_run_session(cmd_vec: &mut Vec<String>, verbosity: u8) {
    if cmd_vec.is_empty() {
        return;
    }
    if cmd_vec[0] == "dbus-run-session" {
        return;
    }

    // Best-effort existence check.
    let ok = Command::new("sh")
        .args(["-lc", "command -v dbus-run-session >/dev/null 2>&1"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !ok {
        if verbosity > 0 {
            log_error("gui: dbus-run-session not found; skipping dbus wrapping");
        }
        return;
    }

    let mut wrapped = Vec::with_capacity(cmd_vec.len() + 2);
    wrapped.push("dbus-run-session".to_string());
    wrapped.push("--".to_string());
    wrapped.extend(cmd_vec.drain(..));
    *cmd_vec = wrapped;
}
