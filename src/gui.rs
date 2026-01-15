// src/gui.rs
use crate::{log_error, wayland};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Prepare a “desktop-like” environment when running as root but dropping to a
/// real user (Chrome/Firefox etc).
///
/// Returns extra bind mounts to be applied by the mount namespace code:
///   (host_path, inside_path, read_only)
///
/// Policy:
/// - Respect explicit user overrides: if WAYLAND_DISPLAY or DISPLAY are provided, do nothing.
/// - Ensure XDG_RUNTIME_DIR points to /run/user/<uid>.
/// - Bridge parent Wayland socket if it lives outside target runtime.
/// - Best-effort: bind PipeWire socket if present.
/// - Avoid portal/FUSE inside sandbox (document portal mount spam) by disabling portals
///   in this proclet GUI mode. (This keeps it clean without needing /dev/fuse.)
/// - Wrap with dbus-run-session (best-effort) unless already wrapped.
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

    let target_runtime = wayland::runtime_dir_for_uid(target_uid);
    set_if_missing(
        env_pairs,
        "XDG_RUNTIME_DIR",
        target_runtime.to_string_lossy().to_string(),
    );

    // Disable portals for this "minimal desktop" mode to avoid:
    //  - xdg-document-portal trying to mount FUSE at /run/user/<uid>/doc
    //  - repeated "Authorization required..." spam from portal/systemd integration
    //
    // This is best-effort and only applied if user didn't override it explicitly.
    set_if_missing(env_pairs, "GTK_USE_PORTAL", "0".to_string());

    // A few harmless desktop hints (do not override user settings).
    set_if_missing(env_pairs, "XDG_SESSION_TYPE", "wayland".to_string());
    set_if_missing(env_pairs, "XDG_CURRENT_DESKTOP", "KDE".to_string());
    set_if_missing(env_pairs, "DESKTOP_SESSION", "plasma".to_string());

    // Try to find a live parent Wayland socket.
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

    // If the parent socket already lives under target runtime dir, just point env there.
    if parent.runtime_dir == target_runtime {
        wayland::ensure_env_points_to_parent_socket(env_pairs, &parent);
    } else {
        // Bridge socket inode into /run/user/<uid>/<socket_name>
        let inside_socket_path = target_runtime.join(&parent.socket_name);

        // Best-effort ACL grant so uid can connect.
        if let Err(e) = wayland::grant_wayland_acl_best_effort(target_uid, &parent) {
            if verbosity > 0 {
                log_error(&format!("gui: wayland ACL grant failed (best-effort): {e}"));
            }
        }

        // Must be RW.
        extra_binds.push((parent.socket_path.clone(), inside_socket_path.clone(), false));

        // Point env at the bridged socket.
        set_if_missing(env_pairs, "WAYLAND_DISPLAY", parent.socket_name.clone());

        // Ensure runtime dir is correct for the user.
        set_override(
            env_pairs,
            "XDG_RUNTIME_DIR",
            target_runtime.to_string_lossy().to_string(),
        );
    }

    // Best-effort PipeWire:
    // bind /run/user/<uid>/pipewire-0 into the sandbox if it exists *and is a socket*.
    // This avoids portal warnings when something tries to use PipeWire (even if portals are off).
    let pw = target_runtime.join("pipewire-0");
    if path_is_socket(&pw) {
        extra_binds.push((pw.clone(), pw.clone(), false));
        // optional hint; harmless if unused
        set_if_missing(env_pairs, "PIPEWIRE_REMOTE", "pipewire-0".to_string());
    } else if verbosity > 1 {
        log_error(&format!(
            "gui: pipewire socket not found or not a socket at {}",
            pw.display()
        ));
    }

    maybe_wrap_dbus_run_session(cmd_vec, verbosity);
    extra_binds
}

// -------- helpers --------

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

fn path_is_socket(p: &Path) -> bool {
    std::fs::metadata(p)
        .ok()
        .map(|m| m.file_type().is_socket())
        .unwrap_or(false)
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
