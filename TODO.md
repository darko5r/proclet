## To-do list for 11/05/2025-11/15/2025

done ✓ Add subreaper + signalfd + full signal forward + exhaustive reap.

done ✓ Implement UTS ns when --hostname is used.

to do:

Mount helpers: /tmp tmpfs, minimal /dev, pivot_root path for --readonly.

Harden --bind parser (options + sanitization) and improve exit codes.

Add --env/--env-file/--clear-env.

Introduce --rlimit (nofile, as, nproc).

Add NET (lo only) for --ns net to remove the placeholder.

Write 3–4 integration tests to lock behavior.