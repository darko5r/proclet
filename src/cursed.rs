// src/cursed.rs

//! HyperRoot / "cursed" modes
//!
//! This module is intentionally conservative for now:
//! - It validates flag combinations;
//! - It logs what was requested;
//! - Actual dangerous behavior (host-cursed, kernel games, /dev/mem, etc.)
//!   will be added explicitly and behind cfg/feature gates.

use nix::errno::Errno;

use crate::ProcletOpts;

/// Validate cursed options before we start touching namespaces.
///
/// Right now we just forbid obviously nonsense combos. Later we can also
/// enforce "must be real root", "must have userns", etc.
pub fn validate_cursed_flags(opts: &ProcletOpts) -> Result<(), Errno> {
    // Example invariant: you can't be both "cursed in userns" and "host-cursed"
    if opts.cursed && opts.cursed_host {
        // For now, treat as an invalid combination.
        return Err(Errno::EINVAL);
    }

    Ok(())
}

/// Log what kind of cursed mode the user asked for.
///
/// This is purely informational right now; real behavior will be wired in
/// once we implement the HyperRoot engine.
pub fn report_cursed_mode(opts: &ProcletOpts) {
    if opts.cursed_host {
        // Extremely dangerous path (will be feature-gated later)
        v2!("HyperRoot: host-cursed mode requested (stub, no-op for now)");
    } else if opts.cursed {
        // Safe-ish experimental mode: userns + extra toys inside the sandbox
        v2!("HyperRoot: userns cursed mode requested (stub, no-op for now)");
    }
}
