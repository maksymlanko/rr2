
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

int main(int argc, char* argv[]) {

    graal_isolate_t *isolate = NULL;
    graal_isolatethread_t *thread = NULL;

    if (graal_create_isolate(NULL, &isolate, &thread) != 0) {
        fprintf(stderr, "initialization error\n");
        return 1;
    }
    //printf("antes\n");
    int result = run_c(thread, argv[1]);
    //printf("Return was %d\n", result);
    if (result != 0){
        printf("Failed\n");
        //callJavaProgram(argc, argv);
        //char *command[] = {"java", "HelloWorld", NULL};
        //if(execvp("java", command) != 0){
        //    perror("execvp java");
        //}
    }


    graal_tear_down_isolate(thread);    
}