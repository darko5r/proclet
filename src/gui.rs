// src/gui.rs
use crate::{log_error, wayland};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::os::unix::fs::PermissionsExt;

// ---------- low-level helpers ----------

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

// For bind targets that are files/sockets: create only the parent directory.
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

    let _ = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(target);
}

/// Add a bind mount for a socket if:
/// - src is a live socket
/// - dst does NOT already have a working socket
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

    ensure_socket_bind_target(dst);

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

/// Bind any path if it exists (used for devices like /dev/fuse).
fn bind_if_exists(
    extra_binds: &mut Vec<(PathBuf, PathBuf, bool)>,
    verbosity: u8,
    label: &str,
    src: &Path,
    dst: &Path,
    read_only: bool,
) {
    if !src.exists() {
        if verbosity >= 2 {
            eprintln!("proclet: gui: {label}: not present at {}", src.display());
        }
        return;
    }

    ensure_parent_dir(dst);

    if verbosity >= 1 {
        eprintln!(
            "proclet: gui: {label}: binding {} -> {}",
            src.display(),
            dst.display()
        );
    }

    extra_binds.push((src.to_path_buf(), dst.to_path_buf(), read_only));
}

/// Best-effort: ensure /run/user/<uid>/doc exists and is owned by target uid.
/// This is important because xdg-document-portal mounts a FUSE fs there.
fn ensure_doc_mountpoint_best_effort(target_uid: u32, target_runtime: &Path, verbosity: u8) {
    let doc = target_runtime.join("doc");

    // Create directory if missing.
    if let Err(e) = std::fs::create_dir_all(&doc) {
        if verbosity >= 1 {
            log_error(&format!(
                "gui: portal: failed to create {} (best-effort): {e}",
                doc.display()
            ));
        }
        return;
    }

    // If owned by someone else (often root when runtime dirs are weird), try to fix.
    if let Ok(md) = std::fs::metadata(&doc) {
        let uid = md.uid();
        let gid = md.gid();

        if uid != target_uid as u32 {
            // Best-effort chown to target uid; keep gid unchanged.
            // Requires proclet to still be privileged at this point (usually true).
            let status = Command::new("chown")
                .arg(format!("{target_uid}:{gid}"))
                .arg(&doc)
                .status();

            if verbosity >= 1 {
                match status {
                    Ok(s) if s.success() => {
                        eprintln!(
                            "proclet: gui: portal: ensured {} ownership -> {}",
                            doc.display(),
                            target_uid
                        );
                    }
                    Ok(_) | Err(_) => {
                        log_error(&format!(
                            "gui: portal: could not chown {} to uid {} (best-effort)",
                            doc.display(),
                            target_uid
                        ));
                    }
                }
            }
        }
    }

    // Tight-ish perms help (portal will mount over it anyway).
    let _ = std::fs::set_permissions(&doc, std::fs::Permissions::from_mode(0o700));
}

// ---------- env helpers ----------

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

// ---------- main entry ----------

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
/// - Bind /dev/fuse and ensure /run/user/<uid>/doc exists for xdg-document-portal.
/// - Wrap with dbus-run-session (best-effort) to ensure a working session bus.
pub fn prepare_desktop(
    env_pairs: &mut Vec<(String, String)>,
    cmd_vec: &mut Vec<String>,
    target_uid: u32,
    verbosity: u8,
) -> Vec<(PathBuf, PathBuf, bool)> {
    let mut extra_binds: Vec<(PathBuf, PathBuf, bool)> = Vec::new();

    // Respect explicit user intent: if caller already set GUI display variables,
    // don't force our own.
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
            // Still do dbus-run-session best-effort.
            maybe_wrap_dbus_run_session(cmd_vec, verbosity);
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
    if parent.runtime_dir != target_runtime {
        let parent_rt = parent.runtime_dir.clone();

        // Pulse socket covers PipeWire-Pulse AND PulseAudio
        bridge_socket_if_present(
            &mut extra_binds,
            verbosity,
            "pulse",
            &parent_rt.join("pulse/native"),
            &target_runtime.join("pulse/native"),
        );

        // Native PipeWire socket is optional but helpful
        bridge_socket_if_present(
            &mut extra_binds,
            verbosity,
            "pipewire",
            &parent_rt.join("pipewire-0"),
            &target_runtime.join("pipewire-0"),
        );
    }

    // --- FUSE support for xdg-document-portal ---
    // A1) Provide /dev/fuse inside the sandbox.
    bind_if_exists(
        &mut extra_binds,
        verbosity,
        "fuse",
        Path::new("/dev/fuse"),
        Path::new("/dev/fuse"),
        false,
    );

    // A2) Ensure the portal mountpoint exists and is writable by the target user.
    ensure_doc_mountpoint_best_effort(target_uid, &target_runtime, verbosity);

    // Provide a session bus (best-effort).
    maybe_wrap_dbus_run_session(cmd_vec, verbosity);

    extra_binds
}
