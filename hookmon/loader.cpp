#include <unistd.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

int main(int argc, char *argv[]) {
    pid_t pid = fork();

    if (pid == 0) {
        // Child: allow tracing and exec the target
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(argv[1], "target_program", NULL);
    } else {
        // Parent: wait, inject, etc.
        waitpid(pid, NULL, 0);
        printf("Child launched with PID %d\n", pid);
        // TODO: inject code via ptrace, call dlopen, etc.
    }

    return 0;
}
