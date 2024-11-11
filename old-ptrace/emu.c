
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>

#define READ_SYSCALL_NUM 0  // Adjust this to the correct value for your architecture

void emulate_read_syscall(pid_t child) {
    struct user_regs_struct regs;
    char buffer[100];  // Buffer for our emulated read

    // Get the registers
    ptrace(PTRACE_GETREGS, child, NULL, &regs);

    // Assuming x86_64 architecture
    // Registers for system call arguments: RDI (file descriptor), RSI (buffer), RDX (count)
    int fd = regs.rdi;
    void *buf = (void *)regs.rsi;
    size_t count = regs.rdx;

    // Emulate the read by reading from the specified file descriptor (if it's a standard one)
    ssize_t bytes_read = 0;
    if (fd == STDIN_FILENO) {
        bytes_read = read(fd, buffer, count);
        if (bytes_read > 0) {
            for (ssize_t i = 0; i < bytes_read; ++i) {
                ptrace(PTRACE_POKEDATA, child, buf + i, *(long *)(buffer + i));
            }
        }
    } else {
        // For simplicity, let's say we don't handle other file descriptors in this example
        bytes_read = -1;
    }

    // Update the registers to reflect the result of our emulation
    regs.rax = bytes_read;  // Return value of read
    ptrace(PTRACE_SETREGS, child, NULL, &regs);

    // Resume the process
    ptrace(PTRACE_SYSCALL, child, NULL, NULL);
}

int main() {
    pid_t child;
    int status;
    struct user_regs_struct regs;

    child = fork();
    if (child == 0) {
        // Child process
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        //execl("/bin/ls", "ls", NULL);
        kill(getpid(), SIGSTOP);
        execl("java md6reflection", "java", "md6reflection", "dynamicMethod", NULL);
    } else {
        // Parent process
        while (1) {

            wait(&status);
            if (WIFEXITED(status))
                break;

            // Get the system call number
            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            long syscall_num = regs.orig_rax;

            if (syscall_num == READ_SYSCALL_NUM) {
                printf("Emulating read system call\n");
                // Use PTRACE_SYSEMU to emulate the read system call
                ptrace(PTRACE_SYSEMU, child, NULL, NULL);
                wait(&status);
                if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
                    emulate_read_syscall(child);
                }
            } else {
                // For other system calls, use PTRACE_SYSCALL
                ptrace(PTRACE_SYSCALL, child, NULL, NULL);
            }
        }
    }
    return 0;
}

