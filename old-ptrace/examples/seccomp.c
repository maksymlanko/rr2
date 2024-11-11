#include <seccomp.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

int main(void) {
    scmp_filter_ctx ctx;

    //ctx = seccomp_init(SCMP_ACT_KILL);  // Default action: kill the process
    ctx = seccomp_init(SCMP_ACT_LOG);  // Log actions instead of killing the process


    // Allow exiting
    printf("Adding rule: Allow exit_group\n");
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

    // Allow changing data segment size, as required by glibc
    printf("Adding rule: Allow brk\n");
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);

    // Allow writing up to 512 bytes to fd 1
    printf("Adding rule: Allow write up to 512 bytes to FD 1\n");
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
        SCMP_A0(SCMP_CMP_EQ, 1),
        SCMP_A2(SCMP_CMP_LE, 512));

    // If writing to any other fd, return -EBADF
    printf("Adding rule: Deny write to any FD except 1\n");
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
        SCMP_A0(SCMP_CMP_NE, 1));

    printf("Adding rule : Allow getpid\n");
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);

    /* // Block getpid
    printf("Adding rule: Deny getpid\n");
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
    */

    // Load and enforce the filters
    printf("Load rules and enforce\n");
    seccomp_load(ctx);
    seccomp_release(ctx);

    // This line may produce an error or be blocked based on the seccomp rules
    printf("This process is %d\n", getpid());

    return 0;
}
