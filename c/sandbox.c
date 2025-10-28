#define _GNU_SOURCE
#include <sched.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

// Child runs inside the new PID namespace
static int child_fn(void *arg) {
    char *const *argv = (char *const *)arg;
    // NOTE: no chroot/mount yet — just exec
    execvp(argv[0], (char *const *)argv);
    perror("execvp");
    return 127;
}

int run_pid_ns(char *const argv[]) {
    const int STACK_SIZE = 1024 * 1024;
    void *stack = malloc(STACK_SIZE);
    if (!stack) {
        perror("malloc");
        return 1;
    }
    void *stack_top = (char *)stack + STACK_SIZE;

    // Create new PID namespace; child will be PID 1 there
    pid_t child = clone(child_fn, stack_top, CLONE_NEWPID | SIGCHLD, (void*)argv); 
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
    if (WIFSIGNALED(status)) {
        fprintf(stderr, "child terminated by signal %d\n", WTERMSIG(status));
        return 128 + WTERMSIG(status);
    }
    return 1;
}
