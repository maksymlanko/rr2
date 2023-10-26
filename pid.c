#include <stdio.h>
#include <unistd.h>

int main() {
    int pid = getpid();
    printf("Pid is : %d\n", pid);
}