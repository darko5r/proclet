// src/gui.rs
use crate::{log_error, wayland};
use libc;
use nix::errno::Errno;
use std::collections::HashMap;
use std::ffi::CString;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use std::os::unix::ffi::OsStrExt;

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

        if src == dst {
        // No-op: same path
        return;
    }
    

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

        if uid != target_uid {
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

// ---------- Desktop-bus spawn support (stable user DBus even if root has none) ----------

static DESKTOP_BUS_CHILD: Mutex<Option<Child>> = Mutex::new(None);

fn command_exists(name: &str) -> bool {
    Command::new("sh")
        .args(["-lc", &format!("command -v {name} >/dev/null 2>&1")])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn kill_desktop_bus_best_effort(verbosity: u8) {
    let mut guard = DESKTOP_BUS_CHILD.lock().unwrap();
    if let Some(mut child) = guard.take() {
        let _ = child.kill();
        let _ = child.wait();
        if verbosity >= 2 {
            eprintln!("proclet: gui: dbus: stopped spawned desktop bus");
        }
    }
}

/// Ensure /run/user/<uid> exists, mode=0700, owned by uid:gid (best-effort).
fn ensure_user_runtime_dir(uid: u32, gid: u32, verbosity: u8) -> std::io::Result<PathBuf> {
    let rt = PathBuf::from(format!("/run/user/{uid}"));
    std::fs::create_dir_all(&rt)?;
    let _ = std::fs::set_permissions(&rt, std::fs::Permissions::from_mode(0o700));

    // Best-effort: chown it. (Root should succeed; if not, we still try.)
    let cpath = CString::new(rt.as_os_str().as_bytes()).unwrap();
    unsafe {
        if libc::chown(cpath.as_ptr(), uid as libc::uid_t, gid as libc::gid_t) != 0 {
            if verbosity >= 1 {
                log_error(&format!(
                    "gui: dbus: could not chown {} to {}:{} (best-effort): {}",
                    rt.display(),
                    uid,
                    gid,
                    Errno::last()
                ));
            }
        }
    }

    Ok(rt)
}

/// Spawn a real session bus for uid, bound to /run/user/<uid>/bus and kept alive
/// for the lifetime of proclet (caller must call cleanup after payload exits).
///
/// Prefers dbus-broker-launch if present; otherwise falls back to dbus-daemon.
/// Returns the address to use in DBUS_SESSION_BUS_ADDRESS (unix:path=...).
fn spawn_user_dbus_at_runtime(uid: u32, gid: u32, verbosity: u8) -> Option<String> {
    let rt = ensure_user_runtime_dir(uid, gid, verbosity).ok()?;
    let bus_path = rt.join("bus");

    // If it already exists and is live, reuse it.
    if target_has_working_socket(&bus_path) {
        if verbosity >= 2 {
            eprintln!("proclet: gui: dbus: target bus already live at {}", bus_path.display());
        }
        return Some(format!("unix:path={}", bus_path.display()));
    }

    // Remove stale non-socket target.
    if let Ok(md) = std::fs::symlink_metadata(&bus_path) {
        if !md.file_type().is_socket() {
            let _ = std::fs::remove_file(&bus_path);
        }
    }

    let have_broker = command_exists("dbus-broker-launch");
    let have_daemon = command_exists("dbus-daemon");

    if !have_broker && !have_daemon {
        if verbosity >= 1 {
            log_error("gui: dbus: neither dbus-broker-launch nor dbus-daemon found; cannot spawn bus");
        }
        return None;
    }

    let addr = format!("unix:path={}", bus_path.display());

    let mut cmd = if have_broker {
        let mut c = Command::new("dbus-broker-launch");
        c.args(["--scope", "user", "--address", &addr]);
        c
    } else {
        let mut c = Command::new("dbus-daemon");
        c.args(["--session", "--nofork", "--nopidfile", "--address", &addr]);
        c
    };

    // Make it behave like a user bus.
    cmd.env("XDG_RUNTIME_DIR", rt.to_string_lossy().to_string());
    cmd.env_remove("DBUS_SESSION_BUS_ADDRESS");

    // Run it as the target uid (important: ownership & EXTERNAL auth expectations).
    unsafe {
        cmd.pre_exec(move || {
            libc::setgroups(0, std::ptr::null());

            if libc::setgid(gid as libc::gid_t) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setuid(uid as libc::uid_t) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            if verbosity >= 1 {
                log_error(&format!("gui: dbus: failed to spawn session bus: {e}"));
            }
            return None;
        }
    };

    {
        let mut guard = DESKTOP_BUS_CHILD.lock().unwrap();
        *guard = Some(child);
    }

    // Wait briefly for bus socket to come alive.
    let start = Instant::now();
    let deadline = Duration::from_millis(900);
    while start.elapsed() < deadline {
        if target_has_working_socket(&bus_path) {
            if verbosity >= 1 {
                eprintln!(
                    "proclet: gui: dbus: spawned session bus at {}",
                    bus_path.display()
                );
            }
            return Some(addr);
        }
        std::thread::sleep(Duration::from_millis(25));
    }

    if verbosity >= 1 {
        log_error(&format!(
            "gui: dbus: spawned bus but socket did not become live at {} (best-effort)",
            bus_path.display()
        ));
    }

    kill_desktop_bus_best_effort(verbosity);
    None
}

/// Call this after payload exit to avoid leaving broker/daemon alive.
pub fn cleanup_desktop_bus(verbosity: u8) {
    kill_desktop_bus_best_effort(verbosity);
}

// ---------- DBus discovery (KDE/session bus) ----------

fn read_to_string_best_effort(p: &Path) -> Option<String> {
    std::fs::read_to_string(p).ok()
}

fn parse_proc_uid_from_status(status: &str) -> Option<u32> {
    // Format:
    // Uid:    1000    1000    1000    1000
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            let mut it = rest.split_whitespace();
            if let Some(uid) = it.next() {
                return uid.parse::<u32>().ok();
            }
        }
    }
    None
}

fn proc_pid_uid(pid: i32) -> Option<u32> {
    let p = PathBuf::from(format!("/proc/{pid}/status"));
    let s = read_to_string_best_effort(&p)?;
    parse_proc_uid_from_status(&s)
}

fn proc_pid_comm(pid: i32) -> Option<String> {
    let p = PathBuf::from(format!("/proc/{pid}/comm"));
    let s = read_to_string_best_effort(&p)?;
    Some(s.trim().to_string())
}

fn proc_pid_environ(pid: i32) -> Option<HashMap<String, String>> {
    let p = PathBuf::from(format!("/proc/{pid}/environ"));
    let bytes = std::fs::read(p).ok()?;
    let mut env = HashMap::new();

    for part in bytes.split(|b| *b == 0u8) {
        if part.is_empty() {
            continue;
        }
        let s = String::from_utf8_lossy(part);
        if let Some((k, v)) = s.split_once('=') {
            env.insert(k.to_string(), v.to_string());
        }
    }
    Some(env)
}

fn primary_gid_for_uid(uid: u32) -> Option<u32> {
    // Use libc getpwuid_r (works even with NSS; doesn’t assume /etc/passwd only).
    unsafe {
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut result: *mut libc::passwd = std::ptr::null_mut();

        // Reasonable buffer for NSS backends
        let mut buf = vec![0u8; 16 * 1024];

        let rc = libc::getpwuid_r(
            uid as libc::uid_t,
            &mut pwd as *mut _,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result as *mut _,
        );

        if rc != 0 || result.is_null() {
            return None;
        }

        Some(pwd.pw_gid as u32)
    }
}

/// Find the latest PID (best-effort) of a process owned by `uid` whose comm matches any of `names`.
/// IMPORTANT: /proc is racy — we must not abort the search on a single unreadable entry.
fn find_latest_pid_by_comm(uid: u32, names: &[&str]) -> Option<i32> {
    let rd = std::fs::read_dir("/proc").ok()?;
    let mut best: Option<i32> = None;

    for ent in rd.flatten() {
        let file_name = ent.file_name();
        let s = file_name.to_string_lossy();
        let pid: i32 = match s.parse() {
            Ok(v) => v,
            Err(_) => continue,
        };

        match proc_pid_uid(pid) {
            Some(puid) if puid == uid => {}
            _ => continue,
        }

        let comm = match proc_pid_comm(pid) {
            Some(c) => c,
            None => continue,
        };

        if !names.iter().any(|n| *n == comm) {
            continue;
        }

        best = match best {
            None => Some(pid),
            Some(cur) => Some(cur.max(pid)),
        };
    }

    best
}

fn dbus_unix_path_from_addr(addr: &str) -> Option<PathBuf> {
    // We only handle bind-mountable form:
    //   unix:path=/some/socket[,guid=...]
    // Also allow: unix:path=/some/socket;guid=...
    let s = addr.trim();
    let s = s.strip_prefix("unix:")?;
    for chunk in s.split(&[',', ';'][..]) {
        let chunk = chunk.trim();
        if let Some(p) = chunk.strip_prefix("path=") {
            if !p.is_empty() {
                return Some(PathBuf::from(p));
            }
        }
    }
    None
}

fn discover_kde_session_bus(uid: u32) -> Option<String> {
    // Priority order: session core -> shell -> compositor -> helpers
    let candidates: [&[&str]; 4] = [
        &["ksmserver"],
        &["plasmashell"],
        &["kwin_wayland", "kwin_x11"],
        &["kded6", "klauncher", "startplasma-wayland", "startplasma-x11"],
    ];

    for names in candidates {
        if let Some(pid) = find_latest_pid_by_comm(uid, names) {
            if let Some(env) = proc_pid_environ(pid) {
                if let Some(addr) = env.get("DBUS_SESSION_BUS_ADDRESS") {
                    if !addr.trim().is_empty() {
                        return Some(addr.clone());
                    }
                }
            }
        }
    }
    None
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
/// - DBus:
///   - In root->user "emulation" mode, do NOT trust caller-provided DBUS_SESSION_BUS_ADDRESS.
///     Prefer discovering the target user's real session bus, then /run/user/<uid>/bus.
///   - Optionally spawn a user bus at /run/user/<uid>/bus (PROCLET_DBUS=spawn).
///   - Fallback: dbus-run-session.
/// - Pin EGL vendor (GLVND) to NVIDIA when appropriate (reduces libEGL/Mesa probe spam).
pub fn prepare_desktop(
    env_pairs: &mut Vec<(String, String)>,
    cmd_vec: &mut Vec<String>,
    target_uid: u32,
    verbosity: u8,
) -> Vec<(PathBuf, PathBuf, bool)> {
    let mut extra_binds: Vec<(PathBuf, PathBuf, bool)> = Vec::new();

    // ---- runtime dir (always sane) ----
    let target_runtime = PathBuf::from(format!("/run/user/{target_uid}"));
    set_if_missing(
        env_pairs,
        "XDG_RUNTIME_DIR",
        target_runtime.to_string_lossy().to_string(),
    );

    // ---- KDE / Plasma identity (helps Chrome pick kwalletd6 + correct portal paths) ----
    // Only set if missing, so we don't stomp on explicit user configs.
    set_if_missing(env_pairs, "XDG_CURRENT_DESKTOP", "KDE".to_string());
    set_if_missing(env_pairs, "XDG_SESSION_DESKTOP", "KDE".to_string());
    set_if_missing(env_pairs, "DESKTOP_SESSION", "plasma".to_string());
    set_if_missing(env_pairs, "KDE_FULL_SESSION", "true".to_string());
    set_if_missing(env_pairs, "KDE_SESSION_VERSION", "6".to_string());

    // ---- DBus session handling ----
    //
    // Modes:
    //   PROCLET_DBUS=auto|discover|host|spawn|session|inherit
    //
    // auto (default):
    //   1) discover KDE session bus from target user process env
    //   2) /run/user/<uid>/bus
    //   3) (only if NOT switching user) use caller bus
    //   4) dbus-run-session
    //
    // spawn:
    //   If /run/user/<uid>/bus is missing, create /run/user/<uid> and spawn a real user bus there.
    //
    // session:
    //   always force dbus-run-session
    let dbus_mode = std::env::var("PROCLET_DBUS")
        .unwrap_or_else(|_| "auto".to_string())
        .to_lowercase();

    if dbus_mode == "session" {
        maybe_wrap_dbus_run_session(cmd_vec, verbosity);
        if verbosity >= 1 {
            eprintln!("proclet: gui: dbus: forced dbus-run-session (PROCLET_DBUS=session)");
        }
    } else {
        let caller_uid = unsafe { libc::geteuid() as u32 };
        let switching_user = caller_uid != target_uid;

        let caller_bus = env_effective_get(env_pairs, "DBUS_SESSION_BUS_ADDRESS")
            .filter(|v| !v.trim().is_empty());

        let mut decided_bus: Option<String> = None;

        // 1) Explicit inherit: trust caller env even if switching user.
        if dbus_mode == "inherit" {
            if let Some(v) = &caller_bus {
                decided_bus = Some(v.clone());
                if verbosity >= 1 {
                    eprintln!("proclet: gui: dbus: forced inherit of caller DBUS_SESSION_BUS_ADDRESS");
                }
            } else if verbosity >= 1 {
                log_error("gui: dbus: PROCLET_DBUS=inherit but caller DBUS_SESSION_BUS_ADDRESS is empty");
            }
        }

        // 2) Discover KDE bus from target user's existing desktop session processes.
        if decided_bus.is_none() && (dbus_mode == "auto" || dbus_mode == "discover") {
            if let Some(addr) = discover_kde_session_bus(target_uid) {
                decided_bus = Some(addr);
                if verbosity >= 1 {
                    eprintln!("proclet: gui: dbus: discovered KDE session bus from user process env");
                }
            } else if verbosity >= 2 {
                eprintln!("proclet: gui: dbus: KDE session bus discovery failed");
            }
        }

        // 3) Host bus socket: /run/user/<uid>/bus (systemd user bus), optionally spawn it.
        if decided_bus.is_none()
            && (dbus_mode == "auto" || dbus_mode == "host" || dbus_mode == "spawn")
        {
            let host_bus = PathBuf::from(format!("/run/user/{target_uid}/bus"));

            if target_has_working_socket(&host_bus) {
                let inside_bus = target_runtime.join("bus");
                bridge_socket_if_present(&mut extra_binds, verbosity, "dbus", &host_bus, &inside_bus);
                decided_bus = Some(format!("unix:path={}", inside_bus.display()));

                if verbosity >= 1 {
                    eprintln!(
                        "proclet: gui: dbus: using target user bus via {}",
                        inside_bus.display()
                    );
                }
            } else {
                if verbosity >= 2 {
                    eprintln!(
                        "proclet: gui: dbus: no usable /run/user/{}/bus socket",
                        target_uid
                    );
                }

                if dbus_mode == "spawn" {
                    // Best-effort gid: use uid (common when gid==uid), but you can wire real gid later.
                    let target_gid = primary_gid_for_uid(target_uid).unwrap_or(target_uid);
			if let Some(addr) = spawn_user_dbus_at_runtime(target_uid, target_gid, verbosity) {
    			decided_bus = Some(addr);
		    }
                }
            }
        }

        // 4) Only when NOT switching users in auto mode: accept caller bus as a fallback.
        if decided_bus.is_none() && dbus_mode == "auto" && !switching_user {
            if let Some(v) = &caller_bus {
                decided_bus = Some(v.clone());
                if verbosity >= 1 {
                    eprintln!("proclet: gui: dbus: using caller DBUS_SESSION_BUS_ADDRESS (same uid)");
                }
            }
        }

        // Apply decision (or fallback to dbus-run-session).
        if let Some(addr) = decided_bus {
            if let Some(src_path) = dbus_unix_path_from_addr(&addr) {
                let run_user_prefix = PathBuf::from(format!("/run/user/{target_uid}/"));
                if src_path.starts_with(&run_user_prefix) {
                    if let Ok(rel) = src_path.strip_prefix(&run_user_prefix) {
                        let dst_path = target_runtime.join(rel);
                        bridge_socket_if_present(&mut extra_binds, verbosity, "dbus", &src_path, &dst_path);
                        set_override(
                            env_pairs,
                            "DBUS_SESSION_BUS_ADDRESS",
                            format!("unix:path={}", dst_path.display()),
                        );
                    } else {
                        set_override(env_pairs, "DBUS_SESSION_BUS_ADDRESS", addr);
                    }
                } else {
                    set_override(env_pairs, "DBUS_SESSION_BUS_ADDRESS", addr);
                }
            } else {
                set_override(env_pairs, "DBUS_SESSION_BUS_ADDRESS", addr);
            }

            if verbosity >= 2 {
                eprintln!("proclet: gui: dbus: using existing/discovered DBUS_SESSION_BUS_ADDRESS (no dbus-run-session)");
            }
        } else {
            maybe_wrap_dbus_run_session(cmd_vec, verbosity);
            if verbosity >= 1 {
                eprintln!("proclet: gui: dbus: no usable target bus; using dbus-run-session");
            }
        }
    }

    // Pin EGL vendor early (pure env change).
    maybe_pin_egl_vendor(env_pairs, verbosity);

    // --- Wayland socket bridging (Wayland-first) ---
    let parent_wayland = wayland::find_parent_wayland_socket();

    if let Some(parent) = parent_wayland {
        // If parent runtime differs, bind the socket inode into target runtime.
        if parent.runtime_dir == target_runtime {
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

            set_if_missing(env_pairs, "WAYLAND_DISPLAY", parent.socket_name.clone());
            set_if_missing(env_pairs, "XDG_SESSION_TYPE", "wayland".to_string());
            set_override(
                env_pairs,
                "XDG_RUNTIME_DIR",
                target_runtime.to_string_lossy().to_string(),
            );
        }

        // --- PipeWire / Pulse sockets bridging ---
        {
            let target_pulse = target_runtime.join("pulse/native");
            let target_pw = target_runtime.join("pipewire-0");

            if parent.runtime_dir != target_runtime {
                let parent_rt = parent.runtime_dir.clone();

                if !target_has_working_socket(&target_pulse) {
                    bridge_socket_if_present(
                        &mut extra_binds,
                        verbosity,
                        "pulse",
                        &parent_rt.join("pulse/native"),
                        &target_pulse,
                    );
                } else if verbosity >= 2 {
                    eprintln!(
                        "proclet: gui: pulse: using target user socket at {}",
                        target_pulse.display()
                    );
                }

                if !target_has_working_socket(&target_pw) {
                    bridge_socket_if_present(
                        &mut extra_binds,
                        verbosity,
                        "pipewire",
                        &parent_rt.join("pipewire-0"),
                        &target_pw,
                    );
                } else if verbosity >= 2 {
                    eprintln!(
                        "proclet: gui: pipewire: using target user socket at {}",
                        target_pw.display()
                    );
                }
            }
        }
    } else {
        // --- X11 fallback (only if DISPLAY exists) ---
        if env_effective_has(env_pairs, "DISPLAY") {
            bind_if_exists(
                &mut extra_binds,
                verbosity,
                "x11",
                Path::new("/tmp/.X11-unix"),
                Path::new("/tmp/.X11-unix"),
                false,
            );

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

        ensure_gpu_access_best_effort(target_uid, verbosity);
    } else if verbosity >= 2 {
        eprintln!("proclet: gui: gpu: disabled (PROCLET_GPU=0)");
    }

    extra_binds
}
