#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>   // Required for struct user_regs_struct
#include <linux/seccomp.h>
#include <seccomp.h>
#include <sys/prctl.h>

int main() {
    pid_t child = fork();

    if (child == 0) {
        // Child process: Set up seccomp and trigger a syscall
        //printf("Ola\n");
        
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        
        //scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_TRACE(0)); // Trace matched syscalls
        scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL); // Trace matched syscalls

        
        seccomp_rule_add(ctx, SCMP_ACT_TRACE(0), SCMP_SYS(getpid), 0); // Trace getpid
        
        seccomp_load(ctx);
        
        printf("OLA");
        

        ptrace(PTRACE_TRACEME);
        
        kill(getpid(), SIGSTOP); // Stop to allow parent to attach

        printf("Child calling getpid...\n");
        int pid = getpid();
        printf("getpid() returned: %d\n", pid);

        seccomp_release(ctx);
        _exit(0);  // Ensure child exits cleanly
    } else if (child > 0) {
        // Parent process: Handle tracing and modify syscall results
        int status;
        waitpid(child, &status, 0);  // Wait for the child to stop at SIGSTOP
        printf("PAI\n");
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESECCOMP);
        printf("PAI2\n");

        while (1) {
            ptrace(PTRACE_CONT, child, NULL, NULL);
            waitpid(child, &status, 0);
            //printf("WHILE\n");
            
            if (WIFEXITED(status)) exit(-1);

            //if (WIFSTOPPED(status) && (status >> 16 == PTRACE_EVENT_SECCOMP)) {
            if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))){
                printf("WTF\n");
                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS, child, NULL, &regs);
                if (regs.orig_rax == 39) {
                    printf("Intercepting and emulating getpid()\n");
                    regs.rax = 1234;  // Set the return value
                    ptrace(PTRACE_SETREGS, child, NULL, &regs);
                }
                ptrace(PTRACE_CONT, child, NULL, NULL);  // Continue the child
            }
        }
        printf("Parent process exiting.\n");
    } else {
        perror("fork");
        return 1;
    }
    return 0;
}
