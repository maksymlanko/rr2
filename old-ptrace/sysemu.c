#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <syscall.h>
#include <string.h>
#include <errno.h>

int main() {
    pid_t child;
    int status;
    struct user_regs_struct regs;

    child = fork();

    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP); // Send SIGSTOP to itself
        int my_pid = syscall(SYS_getpid);
        write(1, "texto 1\n", 9);
        fprintf(stderr, "texto 2\n");
        fprintf(stderr, "pid: %d\n", my_pid);
        write(1, "texto 3\n", 9);
        syscall(SYS_exit, 0);
        syscall(SYS_getpid);
    } else {
        waitpid(child, &status, 0);

        if (WIFSTOPPED(status)) {
            printf("Child has stopped, ptracing with PTRACE_SYSEMU\n");

            while (1) {
                ptrace(PTRACE_SYSEMU, child, NULL, NULL);
                waitpid(child, &status, 0);

                if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
                    ptrace(PTRACE_GETREGS, child, NULL, &regs);
                    switch (regs.orig_rax) {
                        case SYS_getpid:
                            printf("Intercepted getpid()\n");
                            regs.rax = 1234;
                            ptrace(PTRACE_SETREGS, child, NULL, &regs);
                            break;
                        case SYS_write:
                            printf("Intercepted write() to fd %ld\n", regs.rdi);
                            ptrace(PTRACE_SYSCALL, child, NULL, NULL); // Let the syscall execute
                            waitpid(child, &status, 0); // Wait for syscall to complete
                            ptrace(PTRACE_SYSEMU, child, NULL, NULL); // Switch back to SYSEMU after syscall completes
                            break;
                        case SYS_exit:
                            printf("Intercepted exit()\n");
                            // Allow the exit syscall to execute
                            ptrace(PTRACE_SYSCALL, child, NULL, NULL); // Let the syscall execute
                            waitpid(child, &status, 0); // Wait for the child to actually exit
                            break;
                        default:
                            break;
                    }
                } else {
                    break; // Break on normal exit or if signaled
                }
            }

            printf("Child process has exited or was terminated.\n");
        }
    }

    return 0;
}
