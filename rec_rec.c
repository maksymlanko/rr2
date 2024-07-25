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
#include <jni.h>


#define ARRAY_SIZE(arr)  (sizeof(arr) / sizeof((arr)[0]))

#ifdef DEBUG
#define DEBUGPRINT(fmt, args...) fprintf(stderr, "DEBUG: " fmt "\n", ## args)
#else
#define DEBUGPRINT(fmt, args...) // No operation
#endif

enum executionPhase {
    IGNORE,
    RECORD,
    RESTART,
    RECOVER
};

int                         macro_test;
int                         notifyFd;
int                         logFd;
char                        bufLog[1024] = {0};
enum executionPhase         phase;
void                        **curPointer;

void debugPrint(const char *fmt, ...) {
    char debugBuf[1024];  // Adjust size as needed
    va_list args;
    va_start(args, fmt);
    vsnprintf(debugBuf, sizeof(debugBuf), fmt, args);
    va_end(args);

    write(macro_test, debugBuf, strlen(debugBuf));
}

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
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_USER_NOTIF),
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

void
callJavaProgram(int argc, char **argv)
{

    int countArgs = 1;                  // TEMPORARY WAY TO GET ARGC
    while (argv[countArgs] != NULL) {   // TODO: GET ARGC+ARGV AS ARGUMENT FROM THREAD LATER
        countArgs++;
    }

    JavaVMInitArgs  vm_args;
    JavaVM          *jvm;
    JNIEnv          *env;
    JavaVMOption    *options = malloc(4 * sizeof(JavaVMOption));

    options[0].optionString = "-Xint";
    options[1].optionString = "-XX:+UseSerialGC";
    options[2].optionString = "-XX:+ReduceSignalUsage";
    options[3].optionString = "-XX:+DisableAttachMechanism";
    vm_args.nOptions = 4;
    vm_args.options = options;
    vm_args.version = JNI_VERSION_21;
    vm_args.ignoreUnrecognized = JNI_FALSE;

    jint rc = JNI_CreateJavaVM(&jvm, (void**)&env, &vm_args);
    if (rc != JNI_OK)
        err(EXIT_FAILURE, "JNI_CreateJavaVM %d", rc);
    free(options);

    jclass cls = (*env)->FindClass(env, "md6reflection");
    if (cls == NULL)
        err(EXIT_FAILURE, "FindClass");

    jmethodID mid = (*env)->GetStaticMethodID(env, cls, "main", "([Ljava/lang/String;)V");
    if (mid == NULL)
        err(EXIT_FAILURE, "main(String[]) not found");

    jobjectArray arr = (*env)->NewObjectArray(env, countArgs - 1, (*env)->FindClass(env, "java/lang/String"), NULL);
    for (int i = 1; i < countArgs; i++) {
        //printf("JVM argv[%d]: %s", i, argv[i]);
        (*env)->SetObjectArrayElement(env, arr, i-1, (*env)->NewStringUTF(env, argv[i]));
    }
    phase = RESTART; // reset to beginning of log file and start emulating syscalls
    (*env)->CallStaticVoidMethod(env, cls, mid, arr);
    phase = IGNORE;
    (*jvm)->DestroyJavaVM(jvm);
}

static int
callEntryPoint(char **argv)
{
    int                     result;
    graal_isolate_t         *isolate;
    graal_isolatethread_t   *thread;

    if (graal_create_isolate(NULL, &isolate, &thread) != 0)
        err(EXIT_FAILURE, "graal_create_isolate");

    int countArgs = 1;                  // TEMPORARY WAY TO GET ARGC
    while (argv[countArgs] != NULL) {   // TODO: GET ARGC+ARGV AS ARGUMENT FROM THREAD LATER
        countArgs++;
    }

    phase = RECORD;
    result = run_c(thread, countArgs, argv);
    phase = IGNORE;
    printf("\t\tnative image returned %d\n", result);
    printf("\t\tRECOVERING...\n");
    graal_tear_down_isolate(thread);
    return result;
 }

void *
targetProcess(void *argv[])     // TODO: change to argc+argv struct
{
    int    s;
    pid_t  targetPid;
    char   **arg;

    arg = (char **) argv;

    /* Child falls through to here */

    printf("T: PID = %ld\n", (long) getpid());

    /* Install seccomp filter(s) */

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        err(EXIT_FAILURE, "prctl");

    installNotifyFilter();

    callEntryPoint(arg);
    callJavaProgram(1, arg);    // TODO: change to argc+argv struct

    /* Perform a mkdir() call for each of the command-line arguments */
    /*
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
    */
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

void 
sendNotifResponse(struct seccomp_notif_resp *resp){
    if (ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_SEND, resp) == -1) {
        if (errno == ENOENT)
            printf("\tS: response failed with ENOENT; "
                    "perhaps target process's syscall was "
                    "interrupted by a signal?\n");
        else
            perror("ioctl-SECCOMP_IOCTL_NOTIF_SEND");
    }
}

void 
serializeStat(struct stat some_stat, int fd){

}

void
debug_fd(int fd, pid_t pid) {
    char        fd_path[256];
    char        target_path[PATH_MAX];
    ssize_t     len;

    snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%d", pid, fd);
    
    len = readlink(fd_path, target_path, sizeof(target_path) - 1);
    if (len != -1) {
        target_path[len] = '\0';
        printf("FD %d (in pid %d) points to: %s\n", fd, pid, target_path);
    } else {
        err(EXIT_FAILURE, "readlink");
    }
}

bool
is_fd_valid(int fd) {
    return fcntl(fd, F_GETFD) != -1 || errno != EBADF;
}

void
printPath(int fd){
    char    fd_path[PATH_MAX];
    char    real_path[PATH_MAX];

    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    ssize_t len = readlink(fd_path, real_path, sizeof(real_path)-1);
    if (len != -1) {
        real_path[len] = '\0';
        printf("fstat called on fd %d, which points to: %s\n", fd, real_path);
    } else {
        printf("fstat called on fd %d, but couldn't resolve path\n", fd);
    }
}

void
socketRecord(struct seccomp_notif *req, struct seccomp_notif_resp *resp) {
    int     domain = req->data.args[0];
    int     type = req->data.args[1];
    int     protocol = req->data.args[2];

    int result = socket(domain, type, protocol);
    resp->error = (result == -1) ? -errno : 0;
    resp->val = result;
    sendNotifResponse(resp);

    sprintf(bufLog, "%0*X%0*X\n", sizeof(short) * 2, req->data.nr, sizeof(int) * 2, result);
    write(logFd, bufLog, strlen(bufLog));
}

void
connectRecord(struct seccomp_notif *req, struct seccomp_notif_resp *resp) {
    int                     sockfd = req->data.args[0];
    const struct sockaddr   *addr = (struct sockaddr *) req->data.args[1];
    socklen_t               addrlen = (socklen_t) req->data.args[2];

    int result = connect(sockfd, addr, addrlen);
    resp->error = (result == -1) ? -errno : 0;
    resp->val = result;
    sendNotifResponse(resp);

    sprintf(bufLog, "%0*X%0*X\n", sizeof(short) * 2, req->data.nr, sizeof(int) * 2, result);
    write(logFd, bufLog, strlen(bufLog));
}

void
sendtoRecord(struct seccomp_notif *req, struct seccomp_notif_resp *resp) {
    int                     sockfd = req->data.args[0];
    const void              *buf = (const void *) req->data.args[1];
    size_t                  len = (socklen_t) req->data.args[2];
    int                     flags = req->data.args[3];
    const struct sockaddr   *dest_addr = (const struct sockaddr *) req->data.args[4];
    socklen_t               addrlen = (socklen_t) req->data.args[5];

    int result = sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    resp->error = (result == -1) ? -errno : 0;
    resp->val = result;
    sendNotifResponse(resp);

    sprintf(bufLog, "%0*X%0*X\n", sizeof(short) * 2, req->data.nr, sizeof(int) * 2, result);
    write(logFd, bufLog, strlen(bufLog));
}

void
recvmsgRecord(struct seccomp_notif *req, struct seccomp_notif_resp *resp) {
    int                 sockfd = req->data.args[0];
    struct msghdr       *msg = (struct msghdr *) req->data.args[1];
    int                 flags = req->data.args[2];

    int result = recvmsg(sockfd, msg, flags);
    resp->error = (result == -1) ? -errno : 0;
    resp->val = result;
    sendNotifResponse(resp);

    struct msghdr *savedMsg = malloc(sizeof(struct msghdr));
    if (savedMsg == NULL)
        err(EXIT_FAILURE, "Failed to allocate memory to struct msghdr");
    memcpy(savedMsg, msg, sizeof(struct msghdr));
    *(curPointer++) = savedMsg;

    sprintf(bufLog, "%0*X%0*lX%0*X\n", sizeof(short) * 2, req->data.nr, 
                                        sizeof(struct msghdr *) * 2, savedMsg, 
                                        sizeof(int) * 2, result);
    write(logFd, bufLog, strlen(bufLog));
}

void
shutdownRecord(struct seccomp_notif *req, struct seccomp_notif_resp *resp) {
    int     sockfd = req->data.args[0];
    int     how = req->data.args[1];

    int result = shutdown(sockfd, how);
    resp->error = (result == -1) ? -errno : 0;
    resp->val = result;
    sendNotifResponse(resp);

    sprintf(bufLog, "%0*X%0*X\n", sizeof(short) * 2, req->data.nr, sizeof(int) * 2, result);
    write(logFd, bufLog, strlen(bufLog));
}

void
bindRecord(struct seccomp_notif *req, struct seccomp_notif_resp *resp) {
    int                     sockfd = req->data.args[0];
    const struct sockaddr   *addr = (struct sockaddr *) req->data.args[1];
    socklen_t               addrlen = (socklen_t) req->data.args[2];

    int result = bind(sockfd, addr, addrlen);
    resp->error = (result == -1) ? -errno : 0;
    resp->val = result;
    sendNotifResponse(resp);

    sprintf(bufLog, "%0*X%0*X\n", sizeof(short) * 2, req->data.nr, sizeof(int) * 2, result);
    write(logFd, bufLog, strlen(bufLog));
}

void
getsocknameRecord(struct seccomp_notif *req, struct seccomp_notif_resp *resp) {
    int                 sockfd = req->data.args[0];
    struct sockaddr     *addr = (struct sockaddr *) req->data.args[1];
    socklen_t           *addrlen = (socklen_t *) req->data.args[2];

    int result = getsockname(sockfd, addr, addrlen);
    resp->error = (result == -1) ? -errno : 0;
    resp->val = result;
    sendNotifResponse(resp);

    struct sockaddr *savedSockaddr = malloc(sizeof(struct sockaddr));
    if (savedSockaddr == NULL)
        err(EXIT_FAILURE, "Failed to allocate memory to struct sockaddr");
    memcpy(savedSockaddr, addr, sizeof(struct sockaddr));
    *(curPointer++) = savedSockaddr;

    socklen_t *savedAddrlen = malloc(sizeof(socklen_t));
    if (savedAddrlen == NULL)
        err(EXIT_FAILURE, "Failed to allocate memory to socklen_t");
    memcpy(savedAddrlen, addrlen, sizeof(socklen_t));
    *(curPointer++) = savedAddrlen;
    
    sprintf(bufLog, "%0*X%0*lX%0*lX%0*X\n", sizeof(short) * 2, req->data.nr, 
                                            sizeof(struct sockaddr *) * 2, savedSockaddr, 
                                            sizeof(socklen_t *) * 2, savedAddrlen, 
                                            sizeof(int) * 2, result);
    write(logFd, bufLog, strlen(bufLog));
}

void
setsockoptRecord(struct seccomp_notif *req, struct seccomp_notif_resp *resp) {
    int             sockfd = req->data.args[0];
    int             level = req->data.args[1];
    int             optname = req->data.args[2];
    const void      *optval = (void *) req->data.args[3];
    socklen_t       optlen = req->data.args[4];

    int result = setsockopt(sockfd, level, optname, optval, optlen);
    resp->error = (result == -1) ? -errno : 0;
    resp->val = result;
    sendNotifResponse(resp);

    sprintf(bufLog, "%0*X%0*X\n", sizeof(short) * 2, req->data.nr, sizeof(int) * 2, result);
    write(logFd, bufLog, strlen(bufLog));
}

void
getsockoptRecord(struct seccomp_notif *restrict req, struct seccomp_notif_resp *restrict resp) {
    int             sockfd = req->data.args[0];
    int             level = req->data.args[1];
    int             optname = req->data.args[2];
    void            *optval = (void *) req->data.args[3];
    socklen_t       *optlen = (socklen_t *) req->data.args[4];

    int result = getsockopt(sockfd, level, optname, optval, optlen);
    resp->error = (result == -1) ? -errno : 0;
    resp->val = result;
    sendNotifResponse(resp);

    void *savedOptval = malloc(sizeof(char) * 256); // 256 bytes !!! is there a better way to do this?
    if (savedOptval == NULL)
        err(EXIT_FAILURE, "Failed to allocate memory to optval");
    memcpy(savedOptval, optval, sizeof(char) * 256);
    *(curPointer++) = savedOptval;

    socklen_t *savedOptlen = malloc(sizeof(socklen_t));
    if (savedOptlen == NULL)
        err(EXIT_FAILURE, "Failed to allocate memory to optlen");
    memcpy(savedOptlen, optlen, sizeof(socklen_t));
    *(curPointer++) = savedOptlen;

    sprintf(bufLog, "%0*X%0*lX%0*lX%0*X\n", sizeof(short) * 2, req->data.nr, 
                                sizeof(void *) * 2, savedOptval, 
                                sizeof(socklen_t) * 2, savedOptlen,
                                sizeof(int) * 2, result);
    write(logFd, bufLog, strlen(bufLog));
}

void
newfstatatRecord(struct seccomp_notif *req, struct seccomp_notif_resp *resp) {
    int             dirfd = req->data.args[0];
    const char      *pathname = (char *) req->data.args[1];
    struct stat64   *buf = (struct stat64 *) req->data.args[2];
    int             flags = req->data.args[3];

    int result = fstatat64(dirfd, pathname, buf, flags);
    if (result == -1)
        err(EXIT_FAILURE, "Failed to emulate newfstatat");

    resp->error = (result == -1) ? -errno : 0;
    resp->val = result;
    sendNotifResponse(resp);

    struct stat64 *savedStat = malloc(sizeof(struct stat));
    if (savedStat == NULL)
        err(EXIT_FAILURE, "Failed to allocate memory to struct stat");
    memcpy(savedStat, buf, sizeof(struct stat64));
    *(curPointer++) = savedStat;
    // maybe %p instead of %lx? but %lx has correct amount of 0s
    sprintf(bufLog, "%0*X%0*lX%0*X\n", sizeof(short) * 2, req->data.nr, sizeof(struct stat64 *) * 2, savedStat, sizeof(int) * 2, result);
    write(logFd, bufLog, strlen(bufLog));
}

void
newfstatatRecover(struct seccomp_notif *req, struct seccomp_notif_resp *resp) {
    int             dirfd = (int) req->data.args[0];
    const char      *pathname = (char *) req->data.args[1];
    struct stat64   *buf = (struct stat64 *) req->data.args[2];
    int             flags = (int) req->data.args[3];

    int result = read(logFd, bufLog, sizeof(struct stat64 *) * 2);     // not used, currently using from curPointer
    if (result == -1)
        err(EXIT_FAILURE, "newfstatat in recover");
    bufLog[result] = '\0';

    result = read(logFd, bufLog, sizeof(int) * 2);           // has result
    if (result == -1)
        err(EXIT_FAILURE, "Read from file in recover");
    bufLog[result] = '\0';

    result = strtol(bufLog, NULL, 16);
    memcpy(buf, *(curPointer++), sizeof(struct stat64));
    resp->val = result;

    sendNotifResponse(resp);        // refactor so this isn't here !!!
}

/* Handle notifications that arrive via the SECCOMP_RET_USER_NOTIF file
    descriptor, 'notifyFd'. */

static void
handleNotifications(int notifyFd)
{
    bool                        pathOK;
    int                         writeCounter = 0; // TEMPORARY !!!
    char                        path[PATH_MAX];
    // char                        bufLog[1024] = {0};
    void                        **savedPointers;
    //void                        **curPointer;
    struct seccomp_notif        *req;
    struct seccomp_notif_resp   *resp;
    struct seccomp_notif_sizes  sizes;

    allocSeccompNotifBuffers(&req, &resp, &sizes);
    savedPointers = malloc(sizeof(void *) * 10);
    curPointer = savedPointers;
    logFd = open("execution.log", O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH); // TODO: also log targetProcess prints?
    macro_test = open("logfile", O_WRONLY | O_CREAT | O_TRUNC, 0644);

    if (logFd == -1)
        err(EXIT_FAILURE, "Failed to open logFd");


    for (;;) {


        memset(req, 0, sizes.seccomp_notif);
        if (ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_RECV, req) == -1) {
            if (errno == EINTR)
                continue;
            err(EXIT_FAILURE, "\tS: ioctl-SECCOMP_IOCTL_NOTIF_RECV");
        }
        if (phase == IGNORE){
            resp->id = req->id;
            resp->error = 0;
            resp->val = 0;
            resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;

            sendNotifResponse(resp);
            continue;

        } else if (phase == RECORD) {
            resp->id = req->id;
            resp-> flags = 0;

            // printf("RECORD syscall nr: %d\n", req->data.nr);
            // resp->val = 0;
            // resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE; // emulate for new program, to see which syscalls are used
            // sendNotifResponse(resp);

            //continue;  

            switch(req->data.nr) {
                case SYS_read:
                    int fd5 = req->data.args[0];
                    void *buf3 = (void *) req->data.args[1];
                    size_t count2 = (size_t) req->data.args[2];

                    ssize_t bytesRead = read(fd5, buf3, count2);
                    if (bytesRead == -1)
                        err(EXIT_FAILURE, "Failed to emulate read");

                    resp->error = (bytesRead == -1) ? -errno : 0;
                    resp->val = bytesRead;
                    sendNotifResponse(resp);

                    char *savedBuf = malloc(sizeof(char) * (bytesRead + 1));
                    if (savedBuf == NULL)
                        err(EXIT_FAILURE, "Failed to allocate memory to savedBuf");
                    memcpy(savedBuf, buf3, sizeof(char) * bytesRead);
                    savedBuf[bytesRead] = '\0'; // TODO: pode nao ser preciso isto // pode dar erro
                    //printf("savedBuf content: %s\n", savedBuf);
                    *(curPointer++) = savedBuf;
                    //DEBUGPRINT("%0*X%0*lx%0*X\n", sizeof(short) * 2, req->data.nr, sizeof(char *) * 2, savedBuf, sizeof(int) * 2, bytesRead);
                    sprintf(bufLog, "%0*X%0*lx%0*X\n", sizeof(short) * 2, req->data.nr, sizeof(char *) * 2, savedBuf, sizeof(int) * 2, bytesRead);
                    write(logFd, bufLog, strlen(bufLog));
                    break;

                case SYS_write:
                    int fd = req->data.args[0];
                    const char *sys_buf = (const char *) req->data.args[1];
                    size_t count = req->data.args[2];

                    ssize_t bytesWritten = write(fd, sys_buf, count);
                    if (bytesWritten == -1) 
                        err(EXIT_FAILURE, "Failed to emulate write");

                    resp->error = (bytesWritten == -1) ? -errno : 0;
                    resp->val = bytesWritten;
                    sendNotifResponse(resp);

                    //DEBUGPRINT("%0*X%0*zX\n", sizeof(short) * 2, req->data.nr, sizeof(ssize_t) * 2, bytesWritten);
                    sprintf(bufLog, "%0*X%0*zX\n", sizeof(short) * 2, req->data.nr, sizeof(ssize_t) * 2, bytesWritten);
                    write(logFd, bufLog, strlen(bufLog));
                    break;

                case SYS_close:
                    int fd4 = req->data.args[0];
                    int result = close(fd4);
                    if (result == -1)
                        err(EXIT_FAILURE, "Failed to emulate close");

                    resp->error = (result == -1) ? -errno : 0;
                    resp->val = result;
                    sendNotifResponse(resp);

                    sprintf(bufLog, "%0*X%0*X\n", sizeof(short) * 2, req->data.nr, sizeof(int) * 2, result);
                    write(logFd, bufLog, strlen(bufLog));
                    break;

                case SYS_fstat:
                    
                    int fd2 = req->data.args[0];
                    struct stat *sys_buf2 = (struct stat *) req->data.args[1];

                    int resultFstat = fstat(fd2, sys_buf2);
                    if (resultFstat == -1)
                        err(EXIT_FAILURE, "Failed to emulate fstat");

                    resp->error = (resultFstat == -1) ? -errno : 0;
                    resp->val = resultFstat;
                    sendNotifResponse(resp);

                    struct stat *savedStat = malloc(sizeof(struct stat));
                    printf("savedStat saved at: %p\n", savedStat);
                    if (savedStat == NULL)
                        err(EXIT_FAILURE, "Failed to allocate memory to struct stat");
                    memcpy(savedStat, sys_buf2, sizeof(struct stat));
                    *(curPointer++) = savedStat;
                    // maybe %p instead of %lx? but %lx has correct amount of 0s
                    sprintf(bufLog, "%0*X%0*lx%0*X\n", sizeof(short) * 2, req->data.nr, sizeof(struct stat *) * 2, savedStat, sizeof(int) * 2, resultFstat);
                    write(logFd, bufLog, strlen(bufLog));                    
                    break;

                case SYS_lseek:
                    int fd3 = req->data.args[0];
                    off_t offset = (off_t) req->data.args[1];
                    int whence = req->data.args[2];
                    
                    off_t resultOffset = lseek(fd3, offset, whence);
                    if (resultOffset == -1)
                        err(EXIT_FAILURE, "Failed to emulate lseek");

                    resp->error = (resultOffset == -1) ? -errno : 0;
                    resp->val = resultOffset;
                    sendNotifResponse(resp);

                    sprintf(bufLog, "%0*X%0*jd\n", sizeof(short) * 2, req->data.nr, sizeof(intmax_t) * 2, (intmax_t) resultOffset);
                    write(logFd, bufLog, strlen(bufLog));
                    break;

                case SYS_socket:
                    socketRecord(req, resp);
                    break;

                case SYS_connect:
                    connectRecord(req, resp);
                    break;

                case SYS_sendto:
                    sendtoRecord(req, resp);
                    break;

                case SYS_recvmsg:
                    recvmsgRecord(req, resp);
                    break;

                case SYS_shutdown:
                    shutdownRecord(req, resp);
                    break;

                case SYS_bind:
                    bindRecord(req, resp);
                    break;

                case SYS_getsockname:
                    getsocknameRecord(req, resp);
                    break;

                case SYS_setsockopt:
                    setsockoptRecord(req, resp);
                    break;

                case SYS_getsockopt:
                    getsockoptRecord(req, resp);
                    break;
                
                case SYS_openat:
                    int dirfd = req->data.args[0];
                    const char *pathname = (const char *) req->data.args[1];
                    int flags = req->data.args[2];
                    mode_t mode = req->data.args[3];

                    int responseFd = openat(dirfd, pathname, flags, mode);
                    //if (responseFd == -1)
                    //    err(EXIT_FAILURE, "Failed to emulate openat");

                    resp->error = (responseFd == -1) ? -errno : 0;
                    resp->val = responseFd;
                    sendNotifResponse(resp);

                    sprintf(bufLog, "%0*X%0*zX\n", sizeof(short) * 2, req->data.nr, sizeof(long) * 2, responseFd);
                    write(logFd, bufLog, strlen(bufLog));
                    break;

                case SYS_newfstatat:
                    newfstatatRecord(req, resp);
                    break;

                case SYS_futex:
                case SYS_uname:
                case SYS_mmap:
                case SYS_mprotect:
                case SYS_prctl:
                case SYS_munmap:
                case SYS_rt_sigprocmask:
                case SYS_rt_sigaction:
                case SYS_ioctl:
                    DEBUGPRINT("SKIPPED syscall nr: %d\n", req->data.nr);
                    resp->error = 0;
                    resp->val = 0;
                    resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE; // emulate for new program, to see which syscalls are used
                    sendNotifResponse(resp);

                    //sprintf(bufLog, "SKIPPED syscall nr: %d\n", req->data.nr);        // think how to skip them on recover...
                    //write(logFd, bufLog, strlen(bufLog));
                    
                    continue;

                default:
                    printf("HAVE NOT IMPLEMENTED syscall nr: %d\n", req->data.nr);
                    exit(0);
                    resp->id = req->id;
                    resp->error = 0;
                    resp->val = 0;
                    resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                    sendNotifResponse(resp);

                    continue;  
            }
            continue;
        } else if (phase == RESTART) {
            phase = RECOVER;
            off_t lseekResult = lseek(logFd, 0, SEEK_SET); // add error checking
            curPointer = savedPointers;
        } 
        // separate from previous if-else block so that we can reset the file and move here
        if (phase == RECOVER) {
            char newBuf[200] = {0};
            ssize_t numRead;

            resp->id = req->id;
            resp-> flags = 0;
            resp->error = 0;

            numRead = read(logFd, newBuf, sizeof(short) * 2); // read syscall nr
            if (numRead == -1)
                err(EXIT_FAILURE, "Read from file in recover");
            newBuf[numRead] = '\0';
            //printf("Read from file: %s\n", newBuf);
            long int syscallNumber = strtol(newBuf, NULL, 16);
            //printf("Emulating syscall nr: %d\n", syscallNumber);

            long int        syscallResult;
            /*
            numRead = read(logFd, newBuf, sizeof(ssize_t) * 2); // we cant use this because it might be different size
            if (numRead == -1)
                err(EXIT_FAILURE, "Read from file in recover");
            */

            printf("req->data.nr = %d\n", req->data.nr);
            switch(req->data.nr) {
                case SYS_read:

                    char *userBuf = (char *) req->data.args[1];

                    numRead = read(logFd, newBuf, sizeof(char *) * 2); //   has struct char *
                    if (numRead == -1)
                        err(EXIT_FAILURE, "Read from file in recover");
                    newBuf[numRead] = '\0';

                    long int savedBuf = strtol(newBuf, NULL, 16);
                    //printf("savedbuf: %s\n", (char *) savedBuf);

                    numRead = read(logFd, newBuf, sizeof(int) * 2); //      has struct length of str
                    if (numRead == -1)
                        err(EXIT_FAILURE, "Read from file in recover");
                    newBuf[numRead] = '\0';

                    int bufLen = strtol(newBuf, NULL, 16);

                    memcpy(userBuf, *(curPointer++), sizeof(char) * bufLen);

                    //printf("userbuf: %s\n", userBuf);
                    resp->val = bufLen;

                    break;

                case SYS_write:

                    /* temp way to change to IGNORE again after finishing RECOVER copy */
                    writeCounter++;
                    if (writeCounter == 2){
                        phase = IGNORE;
                        printf("\t\tFINISHED RECOVERY, CONTINUING\n");
                    }
                    
                    numRead = read(logFd, newBuf, sizeof(ssize_t) * 2);
                    if (numRead == -1)
                        err(EXIT_FAILURE, "Read from file in recover");

                    newBuf[numRead] = '\0';
                    //printf("RECOVER write: %s\n", newBuf);
                    syscallResult = strtol(newBuf, NULL, 16);
                    
                    //printf("RECOVER write: %zd\n", syscallResult);
                    resp->val = syscallResult;
                    break;
                    
                case SYS_close:
                    numRead = read(logFd, newBuf, sizeof(int) * 2);
                    newBuf[numRead] = '\0';

                    syscallResult = strtol(newBuf, NULL, 16);
                    //printf("RECOVER close: %d\n", syscallResult);

                    resp->val = syscallResult;
                    break;

                case SYS_fstat:

                    int fd = (int) req->data.args[0];
                    struct stat *user_statbuf = (struct stat *) req->data.args[1];

                    numRead = read(logFd, newBuf, sizeof(struct stat *) * 2); // has struct stat *, not used
                    if (numRead == -1)
                        err(EXIT_FAILURE, "Read from file in recover");
                    newBuf[numRead] = '\0';

                    numRead = read(logFd, newBuf, sizeof(int) * 2);           // has result
                    if (numRead == -1)
                        err(EXIT_FAILURE, "Read from file in recover");
                    newBuf[numRead] = '\0';

                    syscallResult = strtol(newBuf, NULL, 16);
                    // Copy the recorded struct stat to the user's buffer
                    memcpy(user_statbuf, *(curPointer++), sizeof(struct stat));

                    // For debugging, print some of the stat info
                    //printf("RECOVER fstat: fd=%d, user_statbuf=%p, original_result=%d\n", 
                    //    fd, (void*)user_statbuf, syscallResult);
                    //printf("  st_size=%ld, st_mode=%o\n", user_statbuf->st_size, user_statbuf->st_mode);
                    resp->val = syscallResult;
                    break;

                case SYS_lseek:
                
                    fd = req->data.args[0];
                    off_t offset = req->data.args[1];
                    int whence = req->data.args[2];

                    ssize_t numRead = read(logFd, newBuf, sizeof(intmax_t) * 2);
                    if (numRead == -1)
                        err(EXIT_FAILURE, "Read from file in recover");
                    newBuf[numRead] = '\0';

                    syscallResult = strtol(newBuf, NULL, 16);
                    //printf("RECOVER lseek: fd=%d, offset=%ld, whence=%d, result=%ld\n",
                    //    fd, (long)offset, whence, syscallResult);

                    resp->val = syscallResult;       
                    break;

                case SYS_openat:

                    int resultFd = openat((int) req->data.args[0], (const char *) req->data.args[1], (int) req->data.args[2], (mode_t) req->data.args[3]);

                    numRead = read(logFd, newBuf, sizeof(ssize_t) * 2);
                    //if (numRead == -1)
                    //    err(EXIT_FAILURE, "Read from file in recover");
                    newBuf[numRead] = '\0';

                    syscallResult = strtol(newBuf, NULL, 16);
                    //printf("RECOVER result: %ld\n", syscallResult); // in recover its 6, but in OG process it was given 7
                    // debug_fd(resultFd, req->pid);  // Use the PID from the request
                    
                    //resp->val = resultFd; 
                    resp->val = syscallResult; 
                    break;

                case SYS_newfstatat:
                    newfstatatRecover(req, resp);
                    break;
                    
                default:
                    printf("Received syscall nr: %d\n", req->data.nr);
                    resp->id = req->id;
                    resp->error = 0;
                    resp->val = 0;
                    resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                    sendNotifResponse(resp);

                    continue;                
            }
            
            sendNotifResponse(resp);
            numRead = read(logFd, newBuf, 1); // consume \n
            continue;
        }
        
        
        sprintf(bufLog, "\tS: got notification (ID %#llx) for PID %d\n", req->id, req->pid);
        //write(logFd, buf, strlen(buf));
        //write(1, buf, strlen(buf));

        resp->id = req->id;
        resp->error = 0;
        resp->val = 0;
        resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;

        sprintf(bufLog, "\tS: sending response "
            "(flags = %#x; val = %lld; error = %d)\n",
            resp->flags, resp->val, resp->error);
        //write(logFd, buf, strlen(buf));
        //write(1, buf, strlen(buf));

        //sprintf(buf, "\tS: SYSCALL %u, Arg1: %p, Arg2: %zu, Arg3: %llu\n", // lol forget this, need individual because of numArgs and types
        //    (unsigned int) req->data.args[0], (intptr_t) req->data.args[1], req->data.args[2], req->data.args[3]);
        sprintf(bufLog, "Syscall %u\n",
            (unsigned int) req->data.nr);
        //write(logFd, buf, strlen(buf));
        write(1, bufLog, strlen(bufLog));
        
        //printf("\tS: SYS_read Arg0: %u, Arg1: %p, Arg2: %zu, Arg3: %llu\n",
        //    (unsigned int) req->data.args[0], (intptr_t) req->data.args[1], req->data.args[2], req->data.args[3]);

        if (ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_SEND, resp) == -1) {
            if (errno == ENOENT)
                printf("\tS: response failed with ENOENT; "
                        "perhaps target process's syscall was "
                        "interrupted by a signal?\n");
            else
                perror("ioctl-SECCOMP_IOCTL_NOTIF_SEND");
        }
        continue;

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
    while (notifyFd == -1)
        sched_yield();
        //err(EXIT_FAILURE, "recvfd");

    handleNotifications(notifyFd);
}

int
main(int argc, char *argv[])
{
    struct sigaction  sa;
    pthread_t         tid;

    setbuf(stdout, NULL);
    notifyFd = -1;
    phase = IGNORE;

    if (argc < 2) {
        fprintf(stderr, "At least one pathname argument is required\n");
        exit(EXIT_FAILURE);
    }

    /* Create a UNIX domain socket that is used to pass the seccomp
        notification file descriptor from the target process to the
        supervisor process. */

    /* Create a child process--the "target"--that installs seccomp
        filtering. The target process writes the seccomp notification
        file descriptor onto 'sockPair[0]' and then calls mkdir(2) for
        each directory in the command-line arguments. */

    pthread_create(&tid, NULL, (void *) targetProcess, &argv[optind]);

    supervisor();

    printf("Shouldn't reach here\n");
    exit(EXIT_FAILURE);
}