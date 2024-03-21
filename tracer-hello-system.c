#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <unistd.h>
#include <errno.h>
#include <sys/user.h>
#include <sys/syscall.h>

int main(int argc, char* argv[]) {

    pid_t child;
    int status;
    struct user_regs_struct regs;
    int in = 0;

    child = fork();
    if (child == 0){
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0){
            perror("ptrace");
            return 1;
        }
        //execvp(argv[1], &argv[1]);
        execvp("./helloworld", NULL);
        //execvp("java", "HelloWorld");
        
    } else if (child > 0){
        wait(&status);

        while (WIFSTOPPED(status)){
            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            if (in == 0){
                if(regs.orig_rax == 39){
                    printf("SystemCall %ld called with %ld, %ld, %ld\n", regs.orig_rax, regs.rsi, regs.rdx, regs.r10);
                    in = 1;
                }
            }
            else {
                if (regs.orig_rax == 39){
                    printf("Original getpid() return was: %ld\n", regs.rax);
                    regs.rax = 12345;
                    ptrace(PTRACE_SETREGS, child, NULL, &regs);
                }
                printf("Return was: %ld\n", regs.rax);
                in = 0;
            }

            if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) < 0){
                perror("ptrace");
                return 1;
            }

            wait(&status);
        }
        if (WIFEXITED(status) && !WEXITSTATUS(status)) {
            /* the program terminated normally and executed successfully */
            system("java HelloWorld");
            //execvp("java", "HelloWorld");
        }

    } else{
        perror("fork");
        return 1;
    }

    return 0;
}


