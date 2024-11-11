#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

int main() {
    struct sock_filter filter[] = {
        // Allow all system calls
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
        .filter = filter,
    };

    // Enable seccomp

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)");
        return 1;
    }
    
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
        fprintf(stderr, "seccomp is not supported: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    printf("seccomp is supported and enabled\n");
    return 0;
}
