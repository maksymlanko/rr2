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

    char *command[] = {"java", "HelloWorld", NULL};
    if(execvp("java", command) != 0){
        perror("execvp java");
    }
    
    return 0;
}


