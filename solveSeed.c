#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
    // Set the seed for srand to the current time
    
    if(fork() == 0){
        sleep(1);
    }
    srand(time(NULL));

    // Print 30 random numbers
    for (int i = 0; i < 30; i++) {
        printf("%d ", rand() & 0xf);
    }
    printf("\n");

    return 0;
}
