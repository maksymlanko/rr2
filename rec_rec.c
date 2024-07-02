#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>
#include "libwrapperexample.h"


#define ARRAY_SIZE(arr)  (sizeof(arr) / sizeof((arr)[0]))

int                 notifyFd;
pthread_mutex_t     mutex_notifyfd;

static int
seccomp(unsigned int operation, unsigned int flags, void *args)
{
    return syscall(SYS_seccomp, operation, flags, args);
}

/* The following is the x86-64-specific BPF boilerplate code for checking
    that the BPF program is running on the right architecture + ABI. At
    completion of these instructions, the accumulator contains the system
    call number. */

/* For the x32 ABI, all system call numbers have bit 30 set */

#define X32_SYSCALL_BIT         0x40000000

#define X86_64_CHECK_ARCH_AND_LOAD_SYSCALL_NR \
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, \
                (offsetof(struct seccomp_data, arch))), \
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 2), \
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, \
                (offsetof(struct seccomp_data, nr))), \
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1), \
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)

/* installNotifyFilter() installs a seccomp filter that generates
    user-space notifications (SECCOMP_RET_USER_NOTIF) when the process
    calls mkdir(2); the filter allows all other system calls.

    The function return value is a file descriptor from which the
    user-space notifications can be fetched. */

static int
installNotifyFilter(void)
{

    struct sock_filter filter[] = {
        X86_64_CHECK_ARCH_AND_LOAD_SYSCALL_NR,

        /* mkdir() triggers notification to user-space supervisor */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_read, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getpid, 1, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mkdir, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_USER_NOTIF),

        /* Every other system call is allowed */

        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len = ARRAY_SIZE(filter),
        .filter = filter,
    };

    /* Install the filter with the SECCOMP_FILTER_FLAG_NEW_LISTENER flag;
        as a result, seccomp() returns a notification file descriptor. */

    notifyFd = seccomp(SECCOMP_SET_MODE_FILTER,
                        SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (notifyFd == -1)
        err(EXIT_FAILURE, "seccomp-install-notify-filter");

    return notifyFd;
}

/* Implementation of the target process; create a child process that:

    (1) installs a seccomp filter with the
        SECCOMP_FILTER_FLAG_NEW_LISTENER flag;
    (2) writes the seccomp notification file descriptor returned from
        the previous step onto the UNIX domain socket, 'sockPair[0]';
    (3) calls mkdir(2) for each element of 'argv'.

    The function return value in the parent is the PID of the child
    process; the child does not return from this function. */

static int
callEntryPoint(char **argv)
{
    graal_isolate_t *isolate = NULL;
    graal_isolatethread_t *thread = NULL;

    if (graal_create_isolate(NULL, &isolate, &thread) != 0)
        err(EXIT_FAILURE, "graal_create_isolate");

    int result = run_c(thread, argv[0]);
    printf("T: native image returned %d\n", result);
    graal_tear_down_isolate(thread);
    return result;
 }

void *
targetProcess(void *argv[])
{
    int    notifyFd, s;
    pid_t  targetPid;
    char   **arg;

    arg = (char **) argv;

    /* Child falls through to here */

    printf("T: PID = %ld\n", (long) getpid());

    /* Install seccomp filter(s) */

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        err(EXIT_FAILURE, "prctl");

    notifyFd = installNotifyFilter();

    pthread_mutex_unlock(&mutex_notifyfd);

    callEntryPoint(arg);

    /* Perform a mkdir() call for each of the command-line arguments */
    for (char **ap = arg; *ap != NULL; ap++) {
        printf("\nT: about to mkdir(\"%s\")\n", *ap);

        s = mkdir(*ap, 0700);
        if (s == -1)
            perror("T: ERROR: mkdir(2)");
        else
            printf("T: SUCCESS: mkdir(2) returned %d\n", s);
    }
    int pid = getpid();
    printf("\nT: pid returned %d\n", pid);

    char buf[10];
    //strncpy(buf, "abcdefg", 10);
    printf("T: addr of buf: %p\n", &buf);
    int numRead = read(STDIN_FILENO, buf, 9);
    buf[numRead] = '\0';
    printf("T: read \"%s\"", buf);

    printf("\nT: terminating\n");
    exit(EXIT_SUCCESS);
}

/* Check that the notification ID provided by a SECCOMP_IOCTL_NOTIF_RECV
    operation is still valid. It will no longer be valid if the target
    process has terminated or is no longer blocked in the system call that
    generated the notification (because it was interrupted by a signal).

    This operation can be used when doing such things as accessing
    /proc/PID files in the target process in order to avoid TOCTOU race
    conditions where the PID that is returned by SECCOMP_IOCTL_NOTIF_RECV
    terminates and is reused by another process. */

static bool
cookieIsValid(int notifyFd, uint64_t id)
{
    return ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == 0;
}

/* Access the memory of the target process in order to fetch the
    pathname referred to by the system call argument 'argNum' in
    'req->data.args[]'.  The pathname is returned in 'path',
    a buffer of 'len' bytes allocated by the caller.

    Returns true if the pathname is successfully fetched, and false
    otherwise. For possible causes of failure, see the comments below. */

static bool
getTargetPathname(struct seccomp_notif *req, int notifyFd,
                    int argNum, char *path, size_t len)
{
    int      procMemFd;
    char     procMemPath[PATH_MAX];
    ssize_t  nread;

    snprintf(procMemPath, sizeof(procMemPath), "/proc/%d/mem", req->pid);

    procMemFd = open(procMemPath, O_RDONLY | O_CLOEXEC);
    if (procMemFd == -1)
        return false;

    /* Check that the process whose info we are accessing is still alive
        and blocked in the system call that caused the notification.
        If the SECCOMP_IOCTL_NOTIF_ID_VALID operation (performed in
        cookieIsValid()) succeeded, we know that the /proc/PID/mem file
        descriptor that we opened corresponded to the process for which we
        received a notification. If that process subsequently terminates,
        then read() on that file descriptor will return 0 (EOF). */

    if (!cookieIsValid(notifyFd, req->id)) {
        close(procMemFd);
        return false;
    }

    /* Read bytes at the location containing the pathname argument */

    nread = pread(procMemFd, path, len, req->data.args[argNum]);

    close(procMemFd);

    if (nread <= 0)
        return false;

    /* Once again check that the notification ID is still valid. The
        case we are particularly concerned about here is that just
        before we fetched the pathname, the target's blocked system
        call was interrupted by a signal handler, and after the handler
        returned, the target carried on execution (past the interrupted
        system call). In that case, we have no guarantees about what we
        are reading, since the target's memory may have been arbitrarily
        changed by subsequent operations. */

    if (!cookieIsValid(notifyFd, req->id)) {
        perror("\tS: notification ID check failed!!!");
        return false;
    }

    /* Even if the target's system call was not interrupted by a signal,
        we have no guarantees about what was in the memory of the target
        process. (The memory may have been modified by another thread, or
        even by an external attacking process.) We therefore treat the
        buffer returned by pread() as untrusted input. The buffer should
        contain a terminating null byte; if not, then we will trigger an
        error for the target process. */

    if (strnlen(path, nread) < nread)
        return true;

    return false;
}

/* Allocate buffers for the seccomp user-space notification request and
    response structures. It is the caller's responsibility to free the
    buffers returned via 'req' and 'resp'. */

static void
allocSeccompNotifBuffers(struct seccomp_notif **req,
                        struct seccomp_notif_resp **resp,
                        struct seccomp_notif_sizes *sizes)
{
    size_t  resp_size;

    /* Discover the sizes of the structures that are used to receive
        notifications and send notification responses, and allocate
        buffers of those sizes. */

    if (seccomp(SECCOMP_GET_NOTIF_SIZES, 0, sizes) == -1)
        err(EXIT_FAILURE, "seccomp-SECCOMP_GET_NOTIF_SIZES");

    *req = malloc(sizes->seccomp_notif);
    if (*req == NULL)
        err(EXIT_FAILURE, "malloc-seccomp_notif");

    /* When allocating the response buffer, we must allow for the fact
        that the user-space binary may have been built with user-space
        headers where 'struct seccomp_notif_resp' is bigger than the
        response buffer expected by the (older) kernel. Therefore, we
        allocate a buffer that is the maximum of the two sizes. This
        ensures that if the supervisor places bytes into the response
        structure that are past the response size that the kernel expects,
        then the supervisor is not touching an invalid memory location. */

    resp_size = sizes->seccomp_notif_resp;
    if (sizeof(struct seccomp_notif_resp) > resp_size)
        resp_size = sizeof(struct seccomp_notif_resp);

    *resp = malloc(resp_size);
    if (*resp == NULL)
        err(EXIT_FAILURE, "malloc-seccomp_notif_resp");

}

/* Handle notifications that arrive via the SECCOMP_RET_USER_NOTIF file
    descriptor, 'notifyFd'. */

static void
handleNotifications(int notifyFd)
{
    bool                        pathOK;
    char                        path[PATH_MAX];
    struct seccomp_notif        *req;
    struct seccomp_notif_resp   *resp;
    struct seccomp_notif_sizes  sizes;

    allocSeccompNotifBuffers(&req, &resp, &sizes);

    /* Loop handling notifications */

    for (;;) {

        /* Wait for next notification, returning info in '*req' */

        memset(req, 0, sizes.seccomp_notif);
        if (ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_RECV, req) == -1) {
            if (errno == EINTR)
                continue;
            err(EXIT_FAILURE, "\tS: ioctl-SECCOMP_IOCTL_NOTIF_RECV");
        }

        printf("\tS: got notification (ID %#llx) for PID %d\n",
                req->id, req->pid);

        if (req->data.nr == SYS_getpid) {
            resp->val = 1234;
            resp->id = req->id;
            resp->flags = 0;
            resp->error = 0;
            printf("\tS: success! spoofed return of getpid() = %lld\n",
                resp->val);
            printf("\tS: sending response "
                "(flags = %#x; val = %lld; error = %d)\n",
                resp->flags, resp->val, resp->error);

            if (ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_SEND, resp) == -1) {
                if (errno == ENOENT)
                    printf("\tS: response failed with ENOENT; "
                            "perhaps target process's syscall was "
                            "interrupted by a signal?\n");
                else
                    perror("ioctl-SECCOMP_IOCTL_NOTIF_SEND");
            }
            continue;
        }
        if (req->data.nr == SYS_read){
            printf("\tS: SYS_read Arg0: %u, Arg1: %p, Arg2: %zu, Arg3: %llu\n",
                (unsigned int) req->data.args[0], (intptr_t) req->data.args[1], req->data.args[2], req->data.args[3]);

            /*
            intptr_t addr = req->data.args[1];
            char *read_addr = (char *) addr;
            char *test = "ola sou";
            strncpy(read_addr, test, strlen(test)+1);            
            printf("\tS: read_addr content = %s\n", read_addr);

            resp->id = req->id;
            resp->flags = 0;
            resp->error = 0;
            resp->val = strlen(test);
            */
            
            resp->id = req->id;
            resp->error = 0;
            resp->val = 0;
            resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;

            printf("\tS: sending response "
                "(flags = %#x; val = %lld; error = %d)\n",
                resp->flags, resp->val, resp->error);

            if (ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_SEND, resp) == -1) {
                if (errno == ENOENT)
                    printf("\tS: response failed with ENOENT; "
                            "perhaps target process's syscall was "
                            "interrupted by a signal?\n");
                else
                    perror("ioctl-SECCOMP_IOCTL_NOTIF_SEND");
            }
            continue;
        }

        pathOK = getTargetPathname(req, notifyFd, 0, path, sizeof(path));

        /* Prepopulate some fields of the response */

        resp->id = req->id;     /* Response includes notification ID */
        resp->flags = 0;
        resp->val = 0;

        printf("\tS: Arg0: %p, Arg1: %llo, Arg2: %zu, Arg3: %llu\n",
            (int) req->data.args[0], req->data.args[1], req->data.args[2], req->data.args[3]);
        // here we use cast to int because cast to intptr_t has 12 bytes instead of 8

        /* If getTargetPathname() failed, trigger an EINVAL error
            response (sending this response may yield an error if the
            failure occurred because the notification ID was no longer
            valid); if the directory is in /tmp, then create it on behalf
            of the supervisor; if the pathname starts with '.', tell the
            kernel to let the target process execute the mkdir();
            otherwise, give an error for a directory pathname in any other
            location. */

        if (!pathOK) {
            resp->error = -EINVAL;
            printf("\tS: spoofing error for invalid pathname (%s)\n",
                    strerror(-resp->error));
        } else if (strncmp(path, "/tmp/", strlen("/tmp/")) == 0) {
            printf("\tS: executing: mkdir(\"%s\", %#llo)\n",
                    path, req->data.args[1]);

            if (mkdir(path, req->data.args[1]) == 0) {
                resp->error = 0;            /* "Success" */
                resp->val = strlen(path);   /* Used as return value of
                                                mkdir() in target */
                printf("\tS: success! spoofed return = %lld\n",
                        resp->val);
            } else {

                /* If mkdir() failed in the supervisor, pass the error
                    back to the target */

                resp->error = -errno;
                printf("\tS: failure! (errno = %d; %s)\n", errno,
                        strerror(errno));
            }
        } else if (strncmp(path, "./", strlen("./")) == 0) {
            resp->error = resp->val = 0;
            resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            printf("\tS: target can execute system call\n");
        } else {
            resp->error = -EOPNOTSUPP;
            printf("\tS: spoofing error response (%s)\n",
                    strerror(-resp->error));
        }

        /* Send a response to the notification */

        printf("\tS: sending response "
                "(flags = %#x; val = %lld; error = %d)\n",
                resp->flags, resp->val, resp->error);

        if (ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_SEND, resp) == -1) {
            if (errno == ENOENT)
                printf("\tS: response failed with ENOENT; "
                        "perhaps target process's syscall was "
                        "interrupted by a signal?\n");
            else
                perror("ioctl-SECCOMP_IOCTL_NOTIF_SEND");
        }

        /* If the pathname is just "/bye", then the supervisor breaks out
            of the loop and terminates. This allows us to see what happens
            if the target process makes further calls to mkdir(2). */

        if (strcmp(path, "/bye") == 0)
            break;
    }

    free(req);
    free(resp);
    printf("\tS: terminating **********\n");
    exit(EXIT_FAILURE);
}

/* Implementation of the supervisor process:

    (1) obtains the notification file descriptor from 'sockPair[1]'
    (2) handles notifications that arrive on that file descriptor. */

static void
supervisor()
{   
    pthread_mutex_lock(&mutex_notifyfd);
    if (notifyFd == -1)
        err(EXIT_FAILURE, "recvfd");
    pthread_mutex_unlock(&mutex_notifyfd);

    handleNotifications(notifyFd);
}

int
main(int argc, char *argv[])
{
    struct sigaction  sa;
    pthread_t         tid;

    setbuf(stdout, NULL);

    if (argc < 2) {
        fprintf(stderr, "At least one pathname argument is required\n");
        exit(EXIT_FAILURE);
    }

    /* Create a UNIX domain socket that is used to pass the seccomp
        notification file descriptor from the target process to the
        supervisor process. */

    pthread_mutex_init(&mutex_notifyfd, NULL);
    /* Create a child process--the "target"--that installs seccomp
        filtering. The target process writes the seccomp notification
        file descriptor onto 'sockPair[0]' and then calls mkdir(2) for
        each directory in the command-line arguments. */
    pthread_mutex_lock(&mutex_notifyfd);

    pthread_create(&tid, NULL, (void *) targetProcess, &argv[optind]);

    supervisor();

    printf("Shouldn't reach here\n");
    pthread_mutex_destroy(&mutex_notifyfd);
    exit(EXIT_FAILURE);
}