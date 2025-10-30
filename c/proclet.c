#define _GNU_SOURCE
#include <sched.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifndef STACK_SIZE
#define STACK_SIZE (1024 * 1024) // 1 MiB
#endif

static int child_fn(void *arg) {
    char *const *argv = (char *const *)arg;

    // make mounts private so changes don’t leak back
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
        perror("mount(MS_PRIVATE)");
        return 1;
    }

    // ensure /proc exists
    if (access("/proc", F_OK) == -1) {
        perror("access(/proc)");
        return 1;
    }

    // mount a fresh proc for the new PID namespace
    if (mount("proc", "/proc", "proc",
              MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) == -1) {
        perror("mount(proc)");
        return 1;
    }

    // execute target
    execvp(argv[0], argv);
    perror("execvp");
    return 127;
}

int proclet_run_pid_mount(char *const argv[]) {
    // allocate child stack
    void *stack = malloc(STACK_SIZE);
    if (!stack) {
        perror("malloc");
        return 1;
    }
    void *stack_top = (char *)stack + STACK_SIZE;

    // CLONE_NEWNS: mount namespace, CLONE_NEWPID: new PID ns
    int flags = CLONE_NEWNS | CLONE_NEWPID | SIGCHLD;

    pid_t child = clone(child_fn, stack_top, flags, (void *)argv);
    if (child == -1) {
        perror("clone");
        free(stack);
        return 1;
    }

    int status = 0;
    if (waitpid(child, &status, 0) == -1) {
        perror("waitpid");
        free(stack);
        return 1;
    }
    free(stack);

    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 1;
}
