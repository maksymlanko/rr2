#include <stdio.h>
#include <stdlib.h>
#include <time.h>

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

#include "libwrapperexample.h"

void callJavaProgram(int argc, char **argv);
int callEntryPoint(int argc, char **argv);

int main(int argc, char **argv) {

    /*
    if (argc < 2) {
        printf("Usage: %s <program> [method...]\n", argv[0]);
        return 1;
    }
    */

    pid_t child;
    int status;
    struct user_regs_struct regs;
    int in = 1;

    child = fork();
    if (child == 0){
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0){
            perror("ptrace");
            return 1;
        }
        //kill(getpid(), SIGSTOP);
        kill(getpid(), SIGSTOP);

        //instead of execvp call entrypoint
        //execvp(argv[1], &argv[1]);
                
        int res = callEntryPoint(argc, argv);
        printf("finished callEntryPoint\n\n");

        return 0;

    } else if (child > 0){
            int status, syscall, retval;
            FILE *fptr = fopen("entry.log", "w");
        //wait(&status);
        //wait(&status);

        do {
            wait(&status);
            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            if (in == 0){
                printf("SystemCall %ld called with %ld, %ld, %ld\n", regs.orig_rax, regs.rsi, regs.rdx, regs.r10);
                fprintf(fptr, "syscall(%d) = ", regs.orig_rax);
                in = 1;
            }
            else {
                printf("Return was: %ld\n", regs.rax);
                fprintf(fptr, "%d\n", regs.rax);
                in = 0;
            }

            //sleep(1);
            if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) < 0){
                perror("ptrace");
                return 1;
            }

        } while (WIFSTOPPED(status));
        fclose(fptr); 
    } else{
        perror("fork");
        return 1;
    }

    return 0;
}

int callEntryPoint(int argc, char **argv){
    graal_isolate_t *isolate = NULL;
    graal_isolatethread_t *thread = NULL;

    if (graal_create_isolate(NULL, &isolate, &thread) != 0) {
        fprintf(stderr, "initialization error\n");
        return 1;
    }

    int result = run_c(thread, argv[1]);
    printf("Return was %d\n", result);

    graal_tear_down_isolate(thread);
    return result;
 }

