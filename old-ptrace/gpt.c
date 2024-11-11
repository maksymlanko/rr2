#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <string.h>

#define BUFFER_SIZE 256
#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_OPEN 2
#define SYS_CLOSE 3
#define long_size sizeof(long)

void poke_data(pid_t child, long addr, char *data, int len) {
    int i;
    for (i = 0; i < len; i += long_size) {
        long val;
        memcpy(&val, data + i, long_size);
        ptrace(PTRACE_POKEDATA, child, addr + i, val);
    }
}

void getdata(pid_t child, long addr, char *str, int len) {
    int i, j;
    union u {
        long val;
        char chars[long_size];
    } data;
    i = 0;
    j = len / long_size;
    char *laddr = str;
    while (i < j) {
        data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * long_size, NULL);
        memcpy(laddr, data.chars, long_size);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    if (j != 0) {
        data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * long_size, NULL);
        memcpy(laddr, data.chars, j);
    }
    str[len] = '\0';
}

int main() {
    pid_t child;
    long orig_rax;
    int status;

    // Create a child process
    child = fork();

    if (child == 0) {
        // Child process
        // Allow tracing of this process
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        // Trigger a SIGSTOP to notify the parent
        raise(SIGSTOP);
        
        // Open the file using syscall
        int fd = syscall(SYS_open, "hash.txt", O_RDONLY);
        if (fd == -1) {
            perror("syscall(SYS_open)");
            exit(EXIT_FAILURE);
        }

        // Read and print the file contents using syscalls
        char buffer[BUFFER_SIZE];
        ssize_t bytesRead;
        while ((bytesRead = syscall(SYS_read, fd, buffer, BUFFER_SIZE - 1)) > 0) {
            buffer[bytesRead] = '\0'; // Null-terminate the buffer
            // Write the content to stdout using syscall
            if (syscall(SYS_write, STDOUT_FILENO, buffer, bytesRead) == -1) {
                perror("syscall(SYS_write)");
                exit(EXIT_FAILURE);
            }
        }

        if (bytesRead == -1) {
            perror("syscall(SYS_read)");
            exit(EXIT_FAILURE);
        }

        // Close the file using syscall
        if (syscall(SYS_close, fd) == -1) {
            perror("syscall(SYS_close)");
            exit(EXIT_FAILURE);
        }

        exit(EXIT_SUCCESS);
    } else if (child > 0) {
        // Parent process
        // Wait for the child process to stop
        wait(&status);
        if (WIFSTOPPED(status)) {
            // Set the ptrace option to PTRACE_O_TRACESYSGOOD to make the differentiation of syscall stops easier
            ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);
            // Start tracing syscalls
            ptrace(PTRACE_SYSCALL, child, NULL, NULL);
        }

        while (1) {
            // Wait for the child process to stop again
            wait(&status);
            if (WIFEXITED(status)) break;
            if (WIFSTOPPED(status) && (status >> 8) == (SIGTRAP | 0x80)) {
                // Read the system call number
                orig_rax = ptrace(PTRACE_PEEKUSER, child, sizeof(long) * ORIG_RAX, NULL);
                printf("System call number: %ld\n", orig_rax);

                if (orig_rax == SYS_READ) {
                    // Intercept the read syscall using PTRACE_SYSEMU
                    struct user_regs_struct regs;
                    ptrace(PTRACE_GETREGS, child, NULL, &regs);
                    int fd = regs.rdi;
                    void *buf = (void *)regs.rsi;
                    size_t count = regs.rdx;

                    // Perform the read syscall in the child process context
                    char local_buffer[BUFFER_SIZE];
                    ssize_t bytesRead = syscall(SYS_read, fd, local_buffer, count);

                    if (bytesRead == -1) {
                        perror("syscall(SYS_read)");
                        exit(EXIT_FAILURE);
                    }

                    // Write the data read to the child's buffer
                    poke_data(child, (long)buf, local_buffer, bytesRead);

                    // Print the data read
                    printf("Data read: %.*s\n", (int)bytesRead, local_buffer);

                    // Set the return value of the read syscall in the child's registers
                    regs.rax = bytesRead;
                    ptrace(PTRACE_SETREGS, child, NULL, &regs);

                    // Continue the child process with PTRACE_SYSCALL
                    ptrace(PTRACE_SYSCALL, child, NULL, NULL);
                } else {
                    // Continue the child process and let it enter/exit the system call
                    ptrace(PTRACE_SYSCALL, child, NULL, NULL);
                }
            } else {
                // Continue the child process normally
                ptrace(PTRACE_SYSCALL, child, NULL, NULL);
            }
        }
    } else {
        // Fork failed
        perror("fork");
        exit(EXIT_FAILURE);
    }

    return 0;
}

