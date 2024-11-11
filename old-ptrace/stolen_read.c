#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#define MAX_LEN 1000

/**
 * Copy data from "addr" (from the process "pid") to "buff"
 */
int read_addr_into_buff(const pid_t pid, const unsigned long long addr, char * buff, unsigned int buff_size){
    unsigned int bytes_read = 0;
    long * read_addr = (long *) addr;
    long * copy_addr = (long *) buff;
    unsigned long ret;
    memset(buff, '\0', buff_size);
    do {
        ret = ptrace(PTRACE_PEEKTEXT, pid, (read_addr++), NULL);
        *(copy_addr++) = ret;
        bytes_read += sizeof(long);
    } while(ret && bytes_read < (buff_size - sizeof(long)));
    return bytes_read;
}

int main(int argc, char* argv[]){
    if (argc < 2) {
        fprintf(stderr, "Missing arguments:\n\t%s <binary> [binary args]\n", argv[0]);
        return EXIT_FAILURE;
    }
    int status;

    pid_t pid = fork();
    if (pid == 0) {
        // launch child process
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(argv[1], &argv[1]);
    } else {
        char str[MAX_LEN];
        int entry_flag = 1;  // flag to distinguish before/after syscall signals
        struct user_regs_struct regs; // struct representing CPU registers

        // loop on signal produced by child process
        while (1) {
            // wait for child notification
            wait(&status);
            // quit if child terminated
            if(WIFEXITED(status))
                break;

            // spy registers
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);

            // orig_rax contains the syscall identifier
            switch (regs.orig_rax) {
                case SYS_write:
                    if (entry_flag) {
                        // read string at the address stored in the rsi register
                        read_addr_into_buff(pid, regs.rsi, str, MAX_LEN);
                        fprintf(stderr, "WRITE: %s\n", str);
                    }
                    entry_flag = !entry_flag;
                    break;

                case SYS_open:
                    if (entry_flag) {
                        // read string at the address stored in the rdi register
                        read_addr_into_buff(pid, regs.rdi, str, MAX_LEN);
                        fprintf(stderr, "OPEN: %s\n",  str);
                    }
                    entry_flag = !entry_flag;
                    break;

                default:
                    entry_flag = 1;
                    break;
            }

            // Continue child execution, and:
            // - raise a signal when it reaches a syscall,
            // - raise another signal after the syscall execution,
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);

        }
    }
    return EXIT_SUCCESS;
}

