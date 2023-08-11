#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <program> [args...]\n", argv[0]);
        return 1;
    }

    pid_t child;
    long orig_rax;
    int status;

    child = fork();

    if (child == 0) {
        // Child process: execute the traced program
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            return 1;
        }
        execvp(argv[1], &argv[1]);
    } else if (child > 0) {
        // Parent process: trace the child and print syscalls
        wait(&status);

        while (WIFSTOPPED(status)) {
            orig_rax = ptrace(PTRACE_PEEKUSER, child, 8 * ORIG_RAX, NULL);

            if (orig_rax != -1) {
                printf("Syscall %ld\n", orig_rax);
            }

            // Continue the child
            if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) < 0) {
                perror("ptrace");
                return 1;
            }

            wait(&status);
        }
    } else {
        perror("fork");
        return 1;
    }

    return 0;
}
// save return of rand() and BLOCK syscall and give to second run
// print input args, and syscall returns, write to disk
// ldpreload and glibc 
