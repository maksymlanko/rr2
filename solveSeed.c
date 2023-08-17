#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {

    if(fork() == 0){
        sleep(1);
    }
    printf("This code's PID is %d\n",getpid());
    srand(time(NULL));

    for (int i = 0; i < 30; i++) {
        printf("%d ", rand() & 0xf);
    }
    printf("\n");
    sleep(3);
    return 0;
}
