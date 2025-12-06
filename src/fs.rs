use nix::{
    errno::Errno,
    mount::{mount, MsFlags},
    sys::stat::{makedev, mknod, Mode, SFlag},
};

use std::{
    fs::{self, File},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Command,
};

use crate::to_errno;

/// Prepare a “fat” new root by bind-mounting core dirs (if requested).
pub fn prepare_new_root(root: &Path, auto_populate: bool) -> Result<(), Errno> {
    // Ensure the root directory exists.
    fs::create_dir_all(root).map_err(to_errno)?;

    if !auto_populate {
        return Ok(());
    }

    const CORE_DIRS: &[&str] = &["/usr", "/bin", "/sbin", "/lib", "/lib64"];

    for host in CORE_DIRS {
        let host_path = Path::new(host);
        if !host_path.exists() {
            continue;
        }

        // Map "/usr" -> root/"usr", "/bin" -> root/"bin", etc.
        let rel = host.trim_start_matches('/');
        let inside = root.join(rel);

        if host_path.is_dir() {
            let _ = fs::create_dir_all(&inside);
        } else if let Some(parent) = inside.parent() {
            let _ = fs::create_dir_all(parent);
        }

        v3!("auto bind core {:?} -> {:?}", host_path, inside);

        mount(
            Some(host_path),
            &inside,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )?;
    }

    Ok(())
}

/// Build a "thin" / minimal rootfs skeleton at `root`:
/// - Ensures root exists
/// - Creates basic dirs: /bin, /usr/bin, /dev, /tmp, /etc, /proc, /sys, /dev/pts, /run
/// - Creates /dev/null, /dev/zero, /dev/tty via mknod()
///   and falls back to bind-mounting host /dev/* if mknod is not permitted.
pub fn build_minimal_rootfs(root: &Path) -> Result<(), Errno> {
    v3!("building minimal rootfs skeleton at {:?}", root);

    fs::create_dir_all(root).map_err(to_errno)?;

    // Basic directory skeleton
    const DIRS: &[&str] = &[
        "bin",
        "usr/bin",
        "dev",
        "tmp",
        "etc",
        "proc",
        "sys",
        "dev/pts",
        "run",
    ];
    for d in DIRS {
        let path = root.join(d);
        fs::create_dir_all(&path).map_err(to_errno)?;
    }

    // === Create minimal /dev nodes (null, zero, tty) ===
    //
    // First try mknod() inside the new rootfs. On kernels / configs where
    // mknod is not permitted in user namespaces, fall back to bind-mounting
    // the host /dev/<name> into the minimal rootfs.
    let dev_dir = root.join("dev");
    let devs: &[(&str, u64, u64)] = &[
        ("null", 1, 3),
        ("zero", 1, 5),
        ("tty", 5, 0),
    ];

    for (name, maj, min) in devs {
        let path = dev_dir.join(name);

        // Try mknod first.
        v3!("minimal-rootfs: attempting mknod for /dev/{} at {:?}", name, path);
        match mknod(
            &path,
            SFlag::S_IFCHR,
            Mode::from_bits_truncate(0o666),
            makedev(*maj, *min),
        ) {
            Ok(_) => {
                v3!("minimal-rootfs: mknod /dev/{} succeeded", name);
            }
            Err(e) if e == Errno::EPERM || e == Errno::EACCES => {
                // Fallback: bind-mount host /dev/<name> if it exists.
                let host = Path::new("/dev").join(name);
                v3!(
                    "minimal-rootfs: mknod /dev/{} denied ({:?}), falling back to bind mount from {:?}",
                    name,
                    e,
                    host
                );

                if !host.exists() {
                    v3!(
                        "minimal-rootfs: host device {:?} does not exist, skipping",
                        host
                    );
                    continue;
                }

                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).map_err(to_errno)?;
                }

                if !path.exists() {
                    v3!(
                        "minimal-rootfs: creating placeholder device file {:?} for bind mount",
                        path
                    );
                    File::create(&path).map_err(to_errno)?;
                }

                mount(
                    Some(host.as_path()),
                    &path,
                    None::<&str>,
                    MsFlags::MS_BIND,
                    None::<&str>,
                )?;
            }
            Err(e) => {
                v3!(
                    "minimal-rootfs: mknod /dev/{} failed with unexpected error {:?}",
                    name,
                    e
                );
                return Err(e);
            }
        }
    }

    Ok(())
}

pub fn mount_overlay(root: &Path, lower: &Path, upper: &Path, work: &Path) -> Result<(), Errno> {
    v3!(
        "mount overlay: lower={:?} upper={:?} work={:?} -> {:?}",
        lower,
        upper,
        work,
        root
    );

    fs::create_dir_all(root).map_err(to_errno)?;
    fs::create_dir_all(upper).map_err(to_errno)?;
    fs::create_dir_all(work).map_err(to_errno)?;

    let opts = format!(
        "lowerdir={},upperdir={},workdir={}",
        lower.display(),
        upper.display(),
        work.display()
    );

    mount::<str, Path, str, str>(
        Some("overlay"),
        root,
        Some("overlay"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID,
        Some(&opts),
    )?;

    Ok(())
}

pub fn copy_into_new_root(root: &Path, sources: &[PathBuf]) -> Result<(), Errno> {
    for src in sources {
        if !src.is_absolute() {
            // Keep it strict for now; we can relax later if we add custom dest paths.
            v2!("new-root-copy: path {:?} is not absolute, rejecting", src);
            return Err(Errno::EINVAL);
        }

        if !src.exists() {
            // Best-effort: skip missing files, but log at v2.
            v2!("new-root-copy: source {:?} does not exist, skipping", src);
            continue;
        }

        // Strip leading "/" so "/etc/resolv.conf" -> "etc/resolv.conf"
        let rel = match src.strip_prefix("/") {
            Ok(r) => r,
            Err(_) => src.as_path(),
        };
        let dest = root.join(rel);

        if let Some(parent) = dest.parent() {
            let _ = fs::create_dir_all(parent);
        }

        v2!("new-root-copy: {:?} -> {:?}", src, dest);
        fs::copy(src, &dest).map_err(to_errno)?;
    }

    Ok(())
}

/// Copy one absolute path into `root`, preserving its absolute layout.
/// Example: src=/usr/bin/ls, root=/tmp/proclet-XXXXXX →
/// dest=/tmp/proclet-XXXXXX/usr/bin/ls
fn copy_path_into_root(root: &Path, src: &Path) -> Result<(), Errno> {
    use std::fs;

    if !src.is_absolute() {
        return Err(Errno::EINVAL);
    }
    if !src.exists() {
        v2!("copy-bin: source {:?} does not exist, skipping", src);
        return Ok(());
    }

    let rel = src.strip_prefix("/").unwrap_or(src);
    let dest = root.join(rel);

    // If dest already exists and is literally the same inode, skip to avoid
    // clobbering host binaries when root contains bind-mounts like /bin, /usr.
    if dest.exists() {
        if let (Ok(sm), Ok(dm)) = (fs::metadata(src), fs::metadata(&dest)) {
            if sm.dev() == dm.dev() && sm.ino() == dm.ino() {
                v2!(
                    "copy-bin: {:?} already mapped to same inode inside root, \
                     skipping to avoid self-copy",
                    dest
                );
                return Ok(());
            }
        }
    }

    if let Some(parent) = dest.parent() {
        let _ = fs::create_dir_all(parent);
    }

    v2!("copy-bin: {:?} -> {:?}", src, dest);
    fs::copy(src, &dest).map_err(to_errno)?;
    Ok(())
}

/// Use `ldd` to discover shared libs for each binary and copy them into new-root.
pub fn copy_bins_with_deps(root: &Path, bins: &[PathBuf]) -> Result<(), Errno> {
    for bin in bins {
        if !bin.is_absolute() {
            v2!("copy-bin: path {:?} is not absolute, rejecting", bin);
            return Err(Errno::EINVAL);
        }

        if !bin.exists() {
            v2!("copy-bin: {:?} does not exist, skipping", bin);
            continue;
        }

        // 1) Copy the binary itself.
        copy_path_into_root(root, bin)?;

        // 2) Ask ldd about its dependencies.
        let output = match Command::new("ldd").arg(bin).output() {
            Ok(o) => o,
            Err(e) => {
                v2!("copy-bin: failed to run ldd on {:?}: {}", bin, e);
                continue;
            }
        };

        if !output.status.success() {
            v2!("copy-bin: ldd {:?} returned non-zero, skipping libs", bin);
            continue;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            // Typical patterns:
            //   linux-vdso.so.1 (0x0000...)
            //   libm.so.6 => /usr/lib/libm.so.6 (0x0000...)
            //   /lib64/ld-linux-x86-64.so.2 (0x0000...)
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            // Look for the first token that looks like an absolute path.
            let mut candidate: Option<&str> = None;
            for &p in &parts {
                if p.starts_with('/') {
                    // Strip trailing ':' if any.
                    let cleaned = p.trim_end_matches(':');
                    candidate = Some(cleaned);
                    break;
                }
            }

            if let Some(path_str) = candidate {
                let lib_path = PathBuf::from(path_str);
                if lib_path.exists() {
                    copy_path_into_root(root, &lib_path)?;
                } else {
                    v3!(
                        "copy-bin: ldd reported {:?} but it does not exist, skipping",
                        lib_path
                    );
                }
            }
        }

        // Also ensure the dynamic linker itself is present if ldd reported it
        // (usually handled by the parsing above).
        let ld_candidates = ["/lib64/ld-linux-x86-64.so.2", "/lib/ld-linux.so.2"];
        for ld in ld_candidates {
            let p = Path::new(ld);
            if p.exists() {
                let _ = copy_path_into_root(root, p);
            }
        }
    }

    Ok(())
}
