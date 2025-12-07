// src/cursed.rs

use std::path::PathBuf;

use crate::ProcletOpts;

/// HyperRoot lab mode: strong isolation, but still host-safe.
/// This is what `--cursed` should feel like.
pub fn apply_lab_mode(opts: &mut ProcletOpts) {
    v2!("cursed: applying HyperRoot lab profile (--cursed)");

    // Always run with full isolation in lab mode.
    opts.use_user = true;
    opts.use_pid = true;
    opts.use_mnt = true;

    // Fresh /proc inside sandbox.
    opts.mount_proc = true;

    // Prefer a tmpfs /tmp inside the sandbox.
    if !opts.tmpfs_tmp {
        v3!("cursed: enabling tmpfs /tmp inside sandbox");
        opts.tmpfs_tmp = true;
    }

    // If no new_root was requested, default to a 'fat' root under /tmp.
    if opts.new_root.is_none() {
        let default_root = PathBuf::from("/tmp/proclet-cursed-root");
        v3!(
            "cursed: no --new-root provided, using default {:?} with --new-root-auto",
            default_root
        );
        opts.new_root = Some(default_root);
        opts.new_root_auto = true;
    }

    // If both minimal_rootfs and new_root_auto are set, prefer minimal_rootfs.
    if opts.minimal_rootfs && opts.new_root_auto {
        v3!("cursed: both minimal_rootfs and new_root_auto set; preferring minimal_rootfs");
        opts.new_root_auto = false;
    }

    // Strong default: make the root read-only unless the user already asked otherwise.
    if !opts.readonly_root {
        v3!("cursed: forcing readonly_root=true for lab profile");
        opts.readonly_root = true;
    }

    // We *keep* whatever binds/env/copy_bin user requested.
}

/// Host-root profile: no userns, real host UID/GID, but still PID/mount isolated.
/// This is what `--cursed-host` should feel like.
pub fn apply_host_mode(opts: &mut ProcletOpts) {
    v2!("cursed-host: applying host-root profile (--cursed-host)");

    // Never use a user namespace here: we want real host credentials.
    if opts.use_user {
        v3!("cursed-host: disabling user namespace (running as real host uid/gid)");
        opts.use_user = false;
    }

    // We *do* want PID + mount isolation so experiments don't leak everywhere.
    if !opts.use_pid {
        v3!("cursed-host: enabling PID namespace for supervision");
        opts.use_pid = true;
    }
    if !opts.use_mnt {
        v3!("cursed-host: enabling mount namespace for host-safe experiments");
        opts.use_mnt = true;
    }

    // Always mount a fresh /proc in this profile.
    opts.mount_proc = true;

    // In host-cursed mode we generally expect to operate against host root.
    // If user configured a new_root, respect it but log it.
    if let Some(ref r) = opts.new_root {
        v3!(
            "cursed-host: using user-specified new_root {:?} (still powered by host root)",
            r
        );
    }
}
