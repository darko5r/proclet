// src/gui.rs
use crate::{log_error, wayland};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;

fn is_socket(p: &Path) -> bool {
    std::fs::metadata(p)
        .ok()
        .map(|m| m.file_type().is_socket())
        .unwrap_or(false)
}

fn socket_is_live(p: &Path) -> bool {
    UnixStream::connect(p).is_ok()
}

fn target_has_working_socket(p: &Path) -> bool {
    is_socket(p) && socket_is_live(p)
}

// For file/socket bind targets: create only the parent directory.
// Never create_dir_all(target) because target is not a directory.
fn ensure_parent_dir(target: &Path) {
    if let Some(parent) = target.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
}

/// Ensure the bind target path is suitable for binding a socket:
/// - Create parent dirs
/// - If target exists as a directory, remove it (common ENOTDIR cause)
/// - Ensure a placeholder file exists so mount(2) has a target
fn ensure_socket_bind_target(target: &Path) {
    ensure_parent_dir(target);

    if let Ok(md) = std::fs::symlink_metadata(target) {
        if md.is_dir() {
            let _ = std::fs::remove_dir_all(target);
        }
    }

    // Create placeholder file if missing (bind mount will cover it).
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(target);
}

/// Adds a bind mount for a socket if:
/// - source is a live socket
/// - target does NOT already have a working socket
///
/// It only prepares the target path correctly (parent dirs).
fn bridge_socket_if_present(
    extra_binds: &mut Vec<(PathBuf, PathBuf, bool)>,
    verbosity: u8,
    label: &str,
    src: &Path,
    dst: &Path,
) {
    // If destination already works, don't touch it.
    if target_has_working_socket(dst) {
        if verbosity >= 1 {
            eprintln!(
                "proclet: gui: {label}: target already has live socket at {}",
                dst.display()
            );
        }
        return;
    }

    // Source must be a live socket.
    if !target_has_working_socket(src) {
        if verbosity >= 2 {
            eprintln!(
                "proclet: gui: {label}: source socket not available at {}",
                src.display()
            );
        }
        return;
    }

    ensure_parent_dir(dst);

    if verbosity >= 1 {
        eprintln!(
            "proclet: gui: {label}: bridging socket {} -> {}",
            src.display(),
            dst.display()
        );
    }

    // ro=false (sockets need rw)
    extra_binds.push((src.to_path_buf(), dst.to_path_buf(), false));
}

/// Prepare a “desktop-like” environment when running as root but dropping to a
/// real user (Chrome/Firefox etc).
///
/// Returns extra bind mounts to be applied by the mount namespace code:
///   (host_path, inside_path, read_only)
///
/// Policy:
/// - Keep XDG_RUNTIME_DIR as /run/user/<uid> for sane DBus + per-user runtime.
/// - If parent compositor sockets are elsewhere (often /run/user/0), bind-mount the
///   socket inode into /run/user/<uid>/<socket_name>.
/// - Best-effort ACL grant so uid can connect.
/// - Wrap with dbus-run-session (best-effort) to ensure a working session bus.
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

    let target_runtime = PathBuf::from(format!("/run/user/{target_uid}"));
    set_if_missing(
        env_pairs,
        "XDG_RUNTIME_DIR",
        target_runtime.to_string_lossy().to_string(),
    );

    // --- Wayland socket bridging ---
    let parent = match wayland::find_parent_wayland_socket() {
        Some(p) => p,
        None => {
            if verbosity > 0 {
                log_error("gui: no live Wayland socket detected; leaving GUI env untouched");
            }
            setup_dbus_and_portals(env_pairs, cmd_vec, target_uid, verbosity);
            return extra_binds;
        }
    };

    if parent.runtime_dir == target_runtime {
        // Already same runtime; just point env to it.
        wayland::ensure_env_points_to_parent_socket(env_pairs, &parent);
    } else {
        // Example: /run/user/0/wayland-0 -> /run/user/1000/wayland-0
        let inside_socket_path = target_runtime.join(&parent.socket_name);

        if verbosity > 0 {
            log_error(&format!(
                "gui: wayland: bridging socket {} -> {}",
                parent.socket_path.display(),
                inside_socket_path.display()
            ));
        }

        if let Err(e) = wayland::grant_wayland_acl_best_effort(target_uid, &parent) {
            if verbosity > 0 {
                log_error(&format!("gui: wayland ACL grant failed (best-effort): {e}"));
            }
        }

        // IMPORTANT: ensure correct target type (file) to avoid ENOTDIR
        ensure_socket_bind_target(&inside_socket_path);
        extra_binds.push((parent.socket_path.clone(), inside_socket_path.clone(), false));

        set_if_missing(env_pairs, "WAYLAND_DISPLAY", parent.socket_name.clone());
        set_if_missing(env_pairs, "XDG_SESSION_TYPE", "wayland".to_string());
        set_override(
            env_pairs,
            "XDG_RUNTIME_DIR",
            target_runtime.to_string_lossy().to_string(),
        );
    }

    // --- PipeWire / Pulse sockets bridging ---
    // Use the SAME parent runtime we just detected (not hardcoded /run/user/0).
    // Only bridge if runtimes differ; if same runtime, everything is already local.
    if parent.runtime_dir != target_runtime {
        let parent_rt = parent.runtime_dir.clone();

        // 1) Pulse socket (covers PipeWire-Pulse AND PulseAudio)
        bridge_socket_if_present(
            &mut extra_binds,
            verbosity,
            "pulse",
            &parent_rt.join("pulse/native"),
            &target_runtime.join("pulse/native"),
        );

        // 2) Native PipeWire socket (optional, but helpful)
        bridge_socket_if_present(
            &mut extra_binds,
            verbosity,
            "pipewire",
            &parent_rt.join("pipewire-0"),
            &target_runtime.join("pipewire-0"),
        );
    }

    // Provide a session bus (best-effort).
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

/// If dbus-run-session exists and command is not already wrapped, wrap it:
///   dbus-run-session -- <orig...>
fn maybe_wrap_dbus_run_session(cmd_vec: &mut Vec<String>, verbosity: u8) {
    if cmd_vec.is_empty() {
        return;
    }
    if cmd_vec[0] == "dbus-run-session" {
        return;
    }

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

fn host_user_bus_path(uid: u32) -> PathBuf {
    PathBuf::from(format!("/run/user/{uid}/bus"))
}

fn has_live_socket(p: &Path) -> bool {
    is_socket(p) && socket_is_live(p)
}

/// Prefer the real user session bus when available.
/// Otherwise fall back to dbus-run-session.
/// If we must fall back, disable portals to avoid FUSE doc portal failures.
fn setup_dbus_and_portals(
    env_pairs: &mut Vec<(String, String)>,
    cmd_vec: &mut Vec<String>,
    target_uid: u32,
    verbosity: u8,
) {
    // If caller already set DBUS_SESSION_BUS_ADDRESS explicitly, respect it.
    if env_has(env_pairs, "DBUS_SESSION_BUS_ADDRESS") {
        return;
    }

    let bus = host_user_bus_path(target_uid);

    if has_live_socket(&bus) {
        // Use the real session bus (best integration: KWallet, KDE services, portals).
        set_if_missing(
            env_pairs,
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}", bus.display()),
        );

        // IMPORTANT: don't wrap with dbus-run-session if we're using the real bus.
        if verbosity >= 1 {
            log_error(&format!("gui: dbus: using existing user bus at {}", bus.display()));
        }
        return;
    }

    // No user bus found → fallback: dbus-run-session
    if verbosity >= 1 {
        log_error("gui: dbus: no user bus found; falling back to dbus-run-session");
    }

    // Portals often fail in sandbox-ish environments (doc portal FUSE mount).
    // Disable portals in fallback mode to avoid noisy failures.
    set_if_missing(env_pairs, "GTK_USE_PORTAL", "0".to_string());

    maybe_wrap_dbus_run_session(cmd_vec, verbosity);
}

