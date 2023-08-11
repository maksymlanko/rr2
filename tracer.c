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
    long rdi, rsi, rdx, r10, r8, r9;  // Registers for syscall arguments
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
                rdi = ptrace(PTRACE_PEEKUSER, child, 8 * RDI, NULL);
                rsi = ptrace(PTRACE_PEEKUSER, child, 8 * RSI, NULL);
                rdx = ptrace(PTRACE_PEEKUSER, child, 8 * RDX, NULL);
                r10 = ptrace(PTRACE_PEEKUSER, child, 8 * R10, NULL);
                r8 = ptrace(PTRACE_PEEKUSER, child, 8 * R8, NULL);
                r9 = ptrace(PTRACE_PEEKUSER, child, 8 * R9, NULL);

                printf("Syscall %ld: rdi=%ld, rsi=%ld, rdx=%ld, r10=%ld, r8=%ld, r9=%ld\n",
                       orig_rax, rdi, rsi, rdx, r10, r8, r9);
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
