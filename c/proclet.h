#ifndef PROCLET_H        // ⮑ Header guard start: ensures this header is included only once per compilation unit.
#define PROCLET_H        //     Prevents duplicate definition errors and multiple inclusion issues.

/*
 * proclet_run_pid_mount()
 * -----------------------
 * Spawns a new "proclet" process that runs inside new PID and mount namespaces.
 * Essentially, it creates a lightweight sandboxed environment for a command.
 *
 * Parameters:
 *   argv[] — a NULL-terminated array of arguments (argv[0] = program to exec).
 *
 * Returns:
 *   On success: does not return (the child process replaces itself via exec()).
 *   On failure: returns a negative errno-style code or exits with an error.
 *
 * This function is implemented in proclet.c.
 */
int proclet_run_pid_mount(char *const argv[]);

#endif  // PROCLET_H      // ⮑ Header guard end: closes the protection block.
