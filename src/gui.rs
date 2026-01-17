// src/gui.rs
use crate::{log_error, wayland};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;

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

/// Bind any path if it exists (used for devices like /dev/fuse or X11 socket dir).
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

    // Directory bind target must exist (for file binds, ensure_socket_bind_target handles it).
    if src.is_dir() {
        let _ = std::fs::create_dir_all(dst);
    } else {
        ensure_parent_dir(dst);
        let _ = std::fs::OpenOptions::new().create(true).write(true).open(dst);
    }

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

// ---------- ACL helpers (best-effort) ----------

fn have_setfacl() -> bool {
    Command::new("sh")
        .args(["-lc", "command -v setfacl >/dev/null 2>&1"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Best-effort ACL grant for a path: allow target_uid to rw.
/// This avoids needing render/video group membership inside userns.
fn grant_path_acl_rw_best_effort(target_uid: u32, path: &Path, verbosity: u8, label: &str) {
    if !path.exists() {
        return;
    }
    if !have_setfacl() {
        if verbosity >= 2 {
            eprintln!("proclet: gui: {label}: setfacl not found; skipping ACL grant");
        }
        return;
    }

    // setfacl -m u:<uid>:rw <path>
    let status = Command::new("setfacl")
        .args(["-m", &format!("u:{target_uid}:rw")])
        .arg(path)
        .status();

    if verbosity >= 2 {
        match status {
            Ok(s) if s.success() => {
                eprintln!(
                    "proclet: gui: {label}: granted ACL rw for uid {} on {}",
                    target_uid,
                    path.display()
                );
            }
            Ok(_) | Err(_) => {
                // best-effort: don't fail, just log
                log_error(&format!(
                    "gui: {label}: could not setfacl rw for uid {} on {} (best-effort)",
                    target_uid,
                    path.display()
                ));
            }
        }
    }
}

/// Ensure GPU device nodes are accessible to the sandbox user.
/// We grant ACL rw on render nodes and card nodes (best-effort).
fn ensure_gpu_access_best_effort(target_uid: u32, verbosity: u8) {
    let dri = Path::new("/dev/dri");
    if dri.exists() {
        // Grant on card* and renderD*
        if let Ok(rd) = std::fs::read_dir(dri) {
            for ent in rd.flatten() {
                let p = ent.path();
                if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                    if name.starts_with("card") || name.starts_with("renderD") {
                        grant_path_acl_rw_best_effort(target_uid, &p, verbosity, "gpu-acl");
                    }
                }
            }
        }
    }

    // NVIDIA device nodes (optional; helps some stacks)
    for dev in [
        "/dev/nvidia0",
        "/dev/nvidiactl",
        "/dev/nvidia-modeset",
        "/dev/nvidia-uvm",
        "/dev/nvidia-uvm-tools",
    ] {
        grant_path_acl_rw_best_effort(target_uid, Path::new(dev), verbosity, "gpu-acl");
    }

    // NVIDIA caps are often restrictive; if present, try to grant read too.
    // (If this fails, it’s still best-effort.)
    let nvcaps = Path::new("/dev/nvidia-caps");
    if nvcaps.exists() {
        if let Ok(rd) = std::fs::read_dir(nvcaps) {
            for ent in rd.flatten() {
                let p = ent.path();
                grant_path_acl_rw_best_effort(target_uid, &p, verbosity, "gpu-acl");
            }
        }
    }
}

// ---------- env helpers ----------

fn env_has(env: &[(String, String)], k: &str) -> bool {
    env.iter().any(|(ek, _)| ek == k)
}

fn env_get(env: &[(String, String)], k: &str) -> Option<String> {
    env.iter().find(|(ek, _)| ek == k).map(|(_, v)| v.clone())
}

fn env_effective_has(env: &[(String, String)], k: &str) -> bool {
    env_has(env, k) || std::env::var(k).ok().filter(|v| !v.is_empty()).is_some()
}

fn env_effective_get(env: &[(String, String)], k: &str) -> Option<String> {
    env_get(env, k).or_else(|| std::env::var(k).ok())
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

// ---------- EGL vendor pinning (GLVND) ----------

fn maybe_pin_egl_vendor(env_pairs: &mut Vec<(String, String)>, verbosity: u8) {
    // User override:
    //   PROCLET_EGL_VENDOR=auto|nvidia|mesa|none
    // default = auto
    let mode = std::env::var("PROCLET_EGL_VENDOR").unwrap_or_else(|_| "auto".to_string());
    let mode = mode.to_lowercase();

    if mode == "none" {
        if verbosity >= 2 {
            eprintln!("proclet: gui: egl: vendor pinning disabled (PROCLET_EGL_VENDOR=none)");
        }
        return;
    }

    // If caller already set __EGL_VENDOR_LIBRARY_FILENAMES explicitly, respect it.
    if env_effective_has(env_pairs, "__EGL_VENDOR_LIBRARY_FILENAMES") {
        if verbosity >= 2 {
            eprintln!("proclet: gui: egl: respecting existing __EGL_VENDOR_LIBRARY_FILENAMES");
        }
        return;
    }

    let nvidia_json = Path::new("/usr/share/glvnd/egl_vendor.d/10_nvidia.json");
    let mesa_json = Path::new("/usr/share/glvnd/egl_vendor.d/50_mesa.json");
    let have_nvidia_dev = Path::new("/dev/nvidia0").exists();

    match mode.as_str() {
        "nvidia" => {
            if nvidia_json.exists() {
                set_override(
                    env_pairs,
                    "__EGL_VENDOR_LIBRARY_FILENAMES",
                    nvidia_json.to_string_lossy().to_string(),
                );
                // GLX too, just to keep it consistent.
                set_if_missing(env_pairs, "__GLX_VENDOR_LIBRARY_NAME", "nvidia".to_string());
                if verbosity >= 1 {
                    eprintln!("proclet: gui: egl: pinned vendor -> {}", nvidia_json.display());
                }
            } else if verbosity >= 1 {
                log_error("gui: egl: requested NVIDIA vendor pin but 10_nvidia.json not found");
            }
        }
        "mesa" => {
            if mesa_json.exists() {
                set_override(
                    env_pairs,
                    "__EGL_VENDOR_LIBRARY_FILENAMES",
                    mesa_json.to_string_lossy().to_string(),
                );
                if verbosity >= 1 {
                    eprintln!("proclet: gui: egl: pinned vendor -> {}", mesa_json.display());
                }
            } else if verbosity >= 1 {
                log_error("gui: egl: requested Mesa vendor pin but 50_mesa.json not found");
            }
        }
        // auto
        _ => {
            // Only pin to NVIDIA in auto mode when it clearly exists.
            if have_nvidia_dev && nvidia_json.exists() {
                set_override(
                    env_pairs,
                    "__EGL_VENDOR_LIBRARY_FILENAMES",
                    nvidia_json.to_string_lossy().to_string(),
                );
                set_if_missing(env_pairs, "__GLX_VENDOR_LIBRARY_NAME", "nvidia".to_string());
                if verbosity >= 1 {
                    eprintln!(
                        "proclet: gui: egl: auto-pinned vendor -> {}",
                        nvidia_json.display()
                    );
                }
            }
        }
    }
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
/// - Wayland-first: if parent Wayland socket exists, bridge it.
/// - If no Wayland socket exists: if DISPLAY exists, bridge X11 (/tmp/.X11-unix) and XAUTHORITY if present.
/// - Bind /dev/fuse and ensure /run/user/<uid>/doc exists for xdg-document-portal.
/// - Bind GPU nodes (/dev/dri + /dev/nvidia*) and grant best-effort ACL so EGL works.
/// - Wrap with dbus-run-session (best-effort) to ensure a working session bus.
/// - Pin EGL vendor (GLVND) to NVIDIA when appropriate (reduces libEGL/Mesa probe spam).
pub fn prepare_desktop(
    env_pairs: &mut Vec<(String, String)>,
    cmd_vec: &mut Vec<String>,
    target_uid: u32,
    verbosity: u8,
) -> Vec<(PathBuf, PathBuf, bool)> {
    let mut extra_binds: Vec<(PathBuf, PathBuf, bool)> = Vec::new();

    let target_runtime = PathBuf::from(format!("/run/user/{target_uid}"));
    set_if_missing(
        env_pairs,
        "XDG_RUNTIME_DIR",
        target_runtime.to_string_lossy().to_string(),
    );

    // Pin EGL vendor early (pure env change).
    maybe_pin_egl_vendor(env_pairs, verbosity);

    // --- Wayland socket bridging (Wayland-first) ---
    let parent_wayland = wayland::find_parent_wayland_socket();

    if let Some(parent) = parent_wayland {
        // If parent runtime differs, bind the socket inode into target runtime.
        if parent.runtime_dir == target_runtime {
            // Already same runtime; just ensure env points at it if caller didn't specify.
            if !env_effective_has(env_pairs, "WAYLAND_DISPLAY") {
                wayland::ensure_env_points_to_parent_socket(env_pairs, &parent);
            }
        } else {
            let inside_socket_path = target_runtime.join(&parent.socket_name);

            if verbosity > 0 {
                eprintln!(
                    "proclet: gui: wayland: bridging socket {} -> {}",
                    parent.socket_path.display(),
                    inside_socket_path.display()
                );
            }

            if let Err(e) = wayland::grant_wayland_acl_best_effort(target_uid, &parent) {
                if verbosity > 0 {
                    log_error(&format!("gui: wayland ACL grant failed (best-effort): {e}"));
                }
            }

            ensure_socket_bind_target(&inside_socket_path);
            extra_binds.push((parent.socket_path.clone(), inside_socket_path.clone(), false));

            // Do NOT stomp caller-provided values; only set if missing.
            set_if_missing(env_pairs, "WAYLAND_DISPLAY", parent.socket_name.clone());
            set_if_missing(env_pairs, "XDG_SESSION_TYPE", "wayland".to_string());
            set_override(
                env_pairs,
                "XDG_RUNTIME_DIR",
                target_runtime.to_string_lossy().to_string(),
            );
        }

        // --- PipeWire / Pulse sockets bridging ---
        if parent.runtime_dir != target_runtime {
            let parent_rt = parent.runtime_dir.clone();

            bridge_socket_if_present(
                &mut extra_binds,
                verbosity,
                "pulse",
                &parent_rt.join("pulse/native"),
                &target_runtime.join("pulse/native"),
            );

            bridge_socket_if_present(
                &mut extra_binds,
                verbosity,
                "pipewire",
                &parent_rt.join("pipewire-0"),
                &target_runtime.join("pipewire-0"),
            );
        }
    } else {
        // --- X11 fallback (only if DISPLAY exists) ---
        if env_effective_has(env_pairs, "DISPLAY") {
            // Bind /tmp/.X11-unix directory (X11 socket dir)
            bind_if_exists(
                &mut extra_binds,
                verbosity,
                "x11",
                Path::new("/tmp/.X11-unix"),
                Path::new("/tmp/.X11-unix"),
                false,
            );

            // Bind XAUTHORITY file if present (don’t force it; just support it).
            if let Some(xauth) = env_effective_get(env_pairs, "XAUTHORITY") {
                let xauth_path = PathBuf::from(xauth);
                if xauth_path.exists() {
                    bind_if_exists(
                        &mut extra_binds,
                        verbosity,
                        "x11-xauth",
                        &xauth_path,
                        &xauth_path,
                        true,
                    );
                } else if verbosity >= 2 {
                    eprintln!(
                        "proclet: gui: x11-xauth: XAUTHORITY points to missing file: {}",
                        xauth_path.display()
                    );
                }
            }

            // We explicitly do NOT set DISPLAY here.
            // If the host/inherited environment has DISPLAY, the payload will see it.
        } else if verbosity > 0 {
            log_error("gui: no live Wayland socket detected and no DISPLAY present; leaving GUI env untouched");
        }
    }

    // --- FUSE support for xdg-document-portal ---
    bind_if_exists(
        &mut extra_binds,
        verbosity,
        "fuse",
        Path::new("/dev/fuse"),
        Path::new("/dev/fuse"),
        false,
    );

    ensure_doc_mountpoint_best_effort(target_uid, &target_runtime, verbosity);

    // --- GPU integration (EGL/GBM/DRM) ---
    // Bind GPU nodes and grant best-effort ACL so sandbox user can open them,
    // even if supplementary groups are not preserved inside the user namespace.
    //
    // You can disable this with: PROCLET_GPU=0
    let gpu_mode = std::env::var("PROCLET_GPU").unwrap_or_else(|_| "1".to_string());
    if gpu_mode != "0" {
        bind_if_exists(
            &mut extra_binds,
            verbosity,
            "dri",
            Path::new("/dev/dri"),
            Path::new("/dev/dri"),
            false,
        );

        // Optional NVIDIA nodes (best-effort)
        for dev in [
            "/dev/nvidia0",
            "/dev/nvidiactl",
            "/dev/nvidia-modeset",
            "/dev/nvidia-uvm",
            "/dev/nvidia-uvm-tools",
        ] {
            bind_if_exists(
                &mut extra_binds,
                verbosity,
                "nvidia",
                Path::new(dev),
                Path::new(dev),
                false,
            );
        }
        bind_if_exists(
            &mut extra_binds,
            verbosity,
            "nvidia-caps",
            Path::new("/dev/nvidia-caps"),
            Path::new("/dev/nvidia-caps"),
            false,
        );

        // ACL grants are best-effort and safe: they only widen access for the target uid.
        ensure_gpu_access_best_effort(target_uid, verbosity);
    } else if verbosity >= 2 {
        eprintln!("proclet: gui: gpu: disabled (PROCLET_GPU=0)");
    }

    // Provide a session bus (best-effort).
    maybe_wrap_dbus_run_session(cmd_vec, verbosity);

    extra_binds
}
