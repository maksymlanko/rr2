#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char* argv[]){
    if (argc < 2){
        printf("Usage: %s <program> [args...]\n", argv[0]);
        return 1;
    }

    pid_t child;
    struct user_regs_struct regs;
    int status;

    child = fork();

    if (child == 0){
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            return 1;
        }
        execvp(argv[1], &argv[1]);
    } else if (child > 0){
        wait(&status);
        ptrace(PTRACE_SETOPTIONS, child, NULL, PTRACE_SETOPTIONS | PTRACE_O_TRACEFORK | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE);

        while (WIFSTOPPED(status)){
            ptrace(PTRACE_GETREGS, child, NULL, &regs);

            if (regs.orig_rax != -1){
                printf("FROM: %d, Syscall %ld: rdi=%ld, rsi=%ld, rdx=%ld, r10=%ld\n",
                        child, regs.orig_rax, regs.rbx, regs.rcx, regs.rdx, regs.r10);
            }
            if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) < 0){
                perror("ptrace");
                return 1;
            }

            wait(&status);
        }
    } else{
        perror("fork");
        return 1;
    }

    return 0;
}
