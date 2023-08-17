#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/wait.h>

int main() {
    pid_t pid;
    int status;

    pid = fork();
    if(pid == 0){
        sleep(1);
    }
    srand(time(NULL));

    for (int i = 0; i < 30; i++) {
        printf("%d ", rand() & 0xf);
    }
    printf("\n");

    if(pid != 0){
        wait(&status);
    }
    return 0;
}
