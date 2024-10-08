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
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/limits.h>


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

typedef struct fdInfo{
    int     status;
    char    path[PATH_MAX];
} fdInfo;

int                         macro_test;
int                         notifyFd;
int                         logFd;
char                        bufLog[1024] = {0};
enum executionPhase         phase;
void                        **curPointer;
int                         curCounter = 0;
fdInfo                      fdArray[56] = {0};

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
    JavaVMOption    *options = malloc(5 * sizeof(JavaVMOption));

    options[0].optionString = "-Xint";
    options[1].optionString = "-XX:+UseSerialGC";
    options[2].optionString = "-XX:+ReduceSignalUsage";
    options[3].optionString = "-XX:+DisableAttachMechanism";
    //options[4].optionString = "-cp .:/usr/share/java/postgresql-jdbc/postgresql-42.5.3.jar";
    options[4].optionString = "-Djava.class.path=.:/usr/share/java/postgresql-jdbc/postgresql-42.5.3.jar";

    vm_args.nOptions = 5;
    vm_args.options = options;
    vm_args.version = JNI_VERSION_21;
    vm_args.ignoreUnrecognized = JNI_FALSE;

    jint rc = JNI_CreateJavaVM(&jvm, (void**)&env, &vm_args);
    if (rc != JNI_OK)
        err(EXIT_FAILURE, "JNI_CreateJavaVM %d", rc);
    free(options);

    DEBUGPRINT("argv[0] in JVM: %s", argv[0]);

    jclass cls = (*env)->FindClass(env, argv[0]);
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

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        err(EXIT_FAILURE, "prctl");

    installNotifyFilter();

    result = run_c(thread, countArgs, argv);
    phase = IGNORE;
    // printf("\t\tnative image returned %d\n", result);
    graal_tear_down_isolate(thread);
    return result;
 }

void *
targetProcess(void *argv[])     // TODO: change to argc+argv struct
{
    int     s;
    pid_t   targetPid;
    char    **arg;
    int     failed;

    arg = (char **) argv;

    /* Child falls through to here */

    //printf("T: PID = %ld\n", (long) getpid());

    /* Install seccomp filter(s) */



    failed = callEntryPoint(arg);

    #ifdef NI_ONLY
        exit(failed);
    #endif

    if (failed) {
        // printf("\t\tRECOVERING...\n"); // remove this for transparent recovery
        callJavaProgram(1, arg);    // TODO: change to argc+argv struct
    }

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

int isFdUsed(int fd) {
    return fcntl(fd, F_GETFD) != -1;
}

int addFd(int fd, const char* path){
    fdArray[fd].status = 1;
    //fdArray[fd].path = path;
    //strcpy(fdArray[fd].path, path);
    strncpy(fdArray[fd].path, path, PATH_MAX - 1);
    fdArray[fd].path[PATH_MAX - 1] = '\0';  // Ensure null-termination
    return 0;
}

int sameFd(int fd, const char* path){
    if (fdArray[fd].status != 1)
        return -1;
    if (strcmp(fdArray[fd].path, path) != 0)
        return -1;
    return 0;
}

int removeFd(int fd){
    fdArray[fd].status = 0;
    //strcpy(fdArray[fd].path, '\0');
    fdArray[fd].path[0] = '\0';
    return 0;
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
readRecord(struct seccomp_notif *req, struct seccomp_notif_resp *resp) {
    int     fd = req->data.args[0];
    void    *buf = (void *) req->data.args[1];
    size_t  count = (size_t) req->data.args[2];
    int     result;

    result = read(fd, buf, count);
    if (result == -1)
        err(EXIT_FAILURE, "Failed to emulate read");

    resp->error = (result == -1) ? -errno : 0;
    resp->val = result;

    char *savedBuf = malloc(sizeof(char) * (result + 1));
    if (savedBuf == NULL)
        err(EXIT_FAILURE, "Failed to allocate memory to savedBuf");

    memcpy(savedBuf, buf, sizeof(char) * result);
    savedBuf[result] = '\0'; // TODO: pode nao ser preciso isto // pode dar erro


    DEBUGPRINT("Read %d bytes", result);
    DEBUGPRINT("savedBuf content:\n%s", savedBuf);
    *(curPointer++) = savedBuf;
    curCounter++;

    sprintf(bufLog, "%0*X%0*lX%0*X\n", sizeof(short) * 2, req->data.nr, sizeof(char *) * 2, savedBuf, sizeof(int) * 2, result);
    write(logFd, bufLog, strlen(bufLog));
    sendNotifResponse(resp);
}

void
socketRecord(struct seccomp_notif *req, struct seccomp_notif_resp *resp) {
    int     domain = req->data.args[0];
    int     type = req->data.args[1];
    int     protocol = req->data.args[2];

    int result = socket(domain, type, protocol);
    
    char domain_str[2];
    domain_str[0] = (char)(domain & 0xFF);
    domain_str[1] = '\0';
    addFd(result, domain_str);

    resp->error = (result == -1) ? -errno : 0;
    resp->val = result;

    DEBUGPRINT("Recover socket: domain=%d, type=%d, protocol=%d, result=%d", domain, type, protocol, result);
    sprintf(bufLog, "%0*X%0*X\n", sizeof(short) * 2, req->data.nr, sizeof(int) * 2, result);
    write(logFd, bufLog, strlen(bufLog));
    sendNotifResponse(resp);
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

/* not used, something was breaking, check backup file for ideas */
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
    size_t              size;

    int result = getsockname(sockfd, addr, addrlen);
    resp->error = (result == -1) ? -errno : 0;
    resp->val = result;
    DEBUGPRINT("addr->sa_family=%u", addr->sa_family);

    switch(addr->sa_family){
        case AF_INET:
            size = sizeof(struct sockaddr_in);
            DEBUGPRINT("getsockname record: sizeof(struct sockaddr_in)=%d", size);
            break;
        case AF_NETLINK:
            size = sizeof(struct sockaddr_nl);
            DEBUGPRINT("getsockname record: sizeof(struct sockaddr_nl)=%d", size);
            break;
        case AF_INET6:
            size = sizeof(struct sockaddr_in6);
            DEBUGPRINT("getsockname record: sizeof(struct sockaddr_in6)=%d", size);
            struct sockaddr_in6   *addr_in6 = (struct sockaddr_in6 *) req->data.args[1];
            DEBUGPRINT("AFTER getsockname record sin6_scope_id=%u", addr_in6->sin6_scope_id);
            break;
        default:
            size = sizeof(struct sockaddr_storage);
            DEBUGPRINT("getsockname record: sizeof(struct sockaddr_storage)=%d", size);
            break;
    }

    struct sockaddr *savedSockaddr = malloc(size);
    memset(savedSockaddr, 0, size);
    if (savedSockaddr == NULL)
        err(EXIT_FAILURE, "Failed to allocate memory to struct sockaddr");
    memcpy(savedSockaddr, addr, size);
    *(curPointer++) = savedSockaddr;
    curCounter++;
    DEBUGPRINT("curCounter=%d\n\n\n", curCounter);

    socklen_t *savedAddrlen = malloc(sizeof(socklen_t));
    if (savedAddrlen == NULL)
        err(EXIT_FAILURE, "Failed to allocate memory to socklen_t");
    memcpy(savedAddrlen, addrlen, sizeof(socklen_t));
    *(curPointer++) = savedAddrlen;
    curCounter++;
    DEBUGPRINT("curCounter=%d\n\n\n", curCounter);

    DEBUGPRINT("Record getsockname: sockfd=%d, addr->data=%s, addrlen=%d, result=%d", sockfd, addr->sa_data, *addrlen, result);
    sprintf(bufLog, "%0*X%0*lX%0*lX%0*X\n", sizeof(short) * 2, req->data.nr, 
                                            sizeof(struct sockaddr *) * 2, savedSockaddr, 
                                            sizeof(socklen_t *) * 2, savedAddrlen, 
                                            sizeof(int) * 2, result);
    write(logFd, bufLog, strlen(bufLog));
    sendNotifResponse(resp);
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

    sprintf(bufLog, "%0*X%0*X\n", sizeof(short) * 2, req->data.nr, sizeof(int) * 2, result);
    write(logFd, bufLog, strlen(bufLog));
    sendNotifResponse(resp);
}

void
getsockoptRecord(struct seccomp_notif *restrict req, struct seccomp_notif_resp *restrict resp) {
    int             sockfd = req->data.args[0];
    int             level = req->data.args[1];
    int             optname = req->data.args[2];
    void            *optval = (void *) req->data.args[3];
    socklen_t       *optlen = (socklen_t *) req->data.args[4];
    int             result;

    result = getsockopt(sockfd, level, optname, optval, optlen);
    resp->error = (result == -1) ? -errno : 0;
    resp->val = result;

    socklen_t *savedOptlen = malloc(sizeof(socklen_t));
    if (savedOptlen == NULL)
        err(EXIT_FAILURE, "Failed to allocate memory to optlen");
    *savedOptlen = *optlen;
    *(curPointer++) = savedOptlen;
    curCounter++;
    DEBUGPRINT("curCounter=%d\n", curCounter);

    void *savedOptval = malloc(*optlen);
    if (savedOptval == NULL)
        err(EXIT_FAILURE, "Failed to allocate memory to optval");
    memcpy(savedOptval, optval, *optlen);
    *(curPointer++) = savedOptval;
    curCounter++;
    DEBUGPRINT("curCounter=%d\n", curCounter);

    sprintf(bufLog, "%0*X%0*lX%0*lX%0*X\n",
            sizeof(short) * 2, req->data.nr,
            sizeof(socklen_t *) * 2, (unsigned long)savedOptlen,
            sizeof(void *) * 2, (unsigned long)savedOptval,
            sizeof(int) * 2, result);
    
    write(logFd, bufLog, strlen(bufLog));
    sendNotifResponse(resp);
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

    DEBUGPRINT("pathname is: %s", pathname);
    char *savedPath = malloc(sizeof(char) * PATH_MAX);
    if (savedPath == NULL)
        err(EXIT_FAILURE, "Failed to allocate memory to char *");
    memcpy(savedPath, pathname, PATH_MAX);
    //*(curPointer++) = savedPath;
    *curPointer = savedPath;
    DEBUGPRINT("\n\n\n\ncurPointer has saved %s at %lX", *curPointer, *curPointer);
    curPointer++;
    curCounter++;
    DEBUGPRINT("curCounter=%d\n\n\n", curCounter);
    DEBUGPRINT("savedPath str: %s\nsavedPath ptr: %lX", savedPath, savedPath);

    struct stat64 *savedStat = malloc(sizeof(struct stat));
    if (savedStat == NULL)
        err(EXIT_FAILURE, "Failed to allocate memory to struct stat");
    memcpy(savedStat, buf, sizeof(struct stat64));
    *(curPointer++) = savedStat;
    curCounter++;
    DEBUGPRINT("curCounter=%d\n\n\n", curCounter);

    sprintf(bufLog, "%0*X%0*lX%0*lX%0*X\n", sizeof(short) * 2, req->data.nr, sizeof(char *) * 2, savedPath, 
                                            sizeof(struct stat64 *) * 2, savedStat, sizeof(int) * 2, result);
    write(logFd, bufLog, strlen(bufLog));
    sendNotifResponse(resp);
}



/* RECOVERY */

void
newfstatatRecover(struct seccomp_notif *req, struct seccomp_notif_resp *resp) {
    int             dirfd = (int) req->data.args[0];
    const char      *pathname = (char *) req->data.args[1];
    struct stat64   *buf = (struct stat64 *) req->data.args[2];
    int             flags = (int) req->data.args[3];
    int             result;

    result = read(logFd, bufLog, sizeof(char *) * 2);     // pathname not used here
    if (result == -1)
        err(EXIT_FAILURE, "newfstatat in recover: savedPath");
    bufLog[result] = '\0';

    result = read(logFd, bufLog, sizeof(struct stat64 *) * 2);     // not used, currently using from curPointer
    if (result == -1)
        err(EXIT_FAILURE, "newfstatat in recover");
    bufLog[result] = '\0';

    result = read(logFd, bufLog, sizeof(int) * 2);           // has result
    if (result == -1)
        err(EXIT_FAILURE, "Read from file in recover");
    bufLog[result] = '\0';

    result = strtol(bufLog, NULL, 16);
    memcpy(buf, *(curPointer++), sizeof(struct stat64));
    curCounter++;
    DEBUGPRINT("curCounter=%d\n\n\n", curCounter);
    resp->val = result;
}

void
socketRecover(struct seccomp_notif *req, struct seccomp_notif_resp *resp) {
    int     domain = req->data.args[0];
    int     type = req->data.args[1];
    int     protocol = req->data.args[2];
    int     result;

    ssize_t numRead = read(logFd, bufLog, sizeof(int) * 2);
    if (numRead == -1)
        err(EXIT_FAILURE, "Read from file in recover");
    bufLog[numRead] = '\0';
    result = strtol(bufLog, NULL, 16);

    char domain_str[2];
    domain_str[0] = (char)(domain & 0xFF);
    domain_str[1] = '\0';
    addFd(result, domain_str);

    if(sameFd(result, domain_str) == 0){
        DEBUGPRINT("Same fd as from NI!!!\n");
        resp->val = result;       
    }
    else{
        while (isFdUsed(result)){
            DEBUGPRINT("SOCKET %d ALREADY IN USE !!!", result);
            result++;
        }
        resp->val = result;     
    }

    DEBUGPRINT("Recover socket: domain=%d, type=%d, protocol=%d, result=%d", domain, type, protocol, result);
}

void
connectRecover(struct seccomp_notif *req, struct seccomp_notif_resp *resp) {
    int                     sockfd = req->data.args[0];
    const struct sockaddr   *addr = (struct sockaddr *) req->data.args[1];
    socklen_t               addrlen = (socklen_t) req->data.args[2];
    int                     result;

    result = read(logFd, bufLog, sizeof(int) * 2);
    if (result == -1)
        err(EXIT_FAILURE, "Read from file in recover");
    bufLog[result] = '\0';

    result = strtol(bufLog, NULL, 16);
    DEBUGPRINT("Recover connect: sockfd=%d, addr->data=%s, addrlen=%d, result=%d", sockfd, addr->sa_data, addrlen, result);
    resp->val = result;       
}

void
sendtoRecover(struct seccomp_notif *req, struct seccomp_notif_resp *resp) {
    int                     sockfd = req->data.args[0];
    const void              *buf = (const void *) req->data.args[1];
    size_t                  len = (socklen_t) req->data.args[2];
    int                     flags = req->data.args[3];
    const struct sockaddr   *dest_addr = (const struct sockaddr *) req->data.args[4];
    socklen_t               addrlen = (socklen_t) req->data.args[5];
    int                     result;

    result = read(logFd, bufLog, sizeof(ssize_t) * 2);
    if (result == -1)
        err(EXIT_FAILURE, "Read from file in recover");
    bufLog[result] = '\0';
    result = strtol(bufLog, NULL, 16);

    DEBUGPRINT("Recover sendto: result=%zd", result);
    resp->val = result;       
}

/* not used, something was breaking, check backup file for ideas */
void recvmsgRecover(struct seccomp_notif *req, struct seccomp_notif_resp *resp) {
    int sockfd = req->data.args[0];
    struct msghdr *msg = (struct msghdr *) req->data.args[1];
    int flags = req->data.args[2];

    DEBUGPRINT("NOT IMPLEMENTED RECVMSG RECOVER");
    exit(0);
}

void
shutdownRecover(struct seccomp_notif *req, struct seccomp_notif_resp *resp) {
    int     sockfd = req->data.args[0];
    int     how = req->data.args[1];
    int     result;

    result = read(logFd, bufLog, sizeof(int) * 2);
    if (result == -1)
        err(EXIT_FAILURE, "Read from file in recover");
    bufLog[result] = '\0';
    result = strtol(bufLog, NULL, 16);

    resp->val = result;
}

void
bindRecover(struct seccomp_notif *req, struct seccomp_notif_resp *resp) {
    int                     sockfd = req->data.args[0];
    struct sockaddr         *addr = (struct sockaddr *) req->data.args[1];;
    socklen_t               addrlen = (socklen_t) req->data.args[2];
    int                     result;

    ssize_t numRead = read(logFd, bufLog, sizeof(int) * 2);
    if (numRead == -1)
        err(EXIT_FAILURE, "Read from file in recover");
    bufLog[numRead] = '\0';
    result = strtol(bufLog, NULL, 16);

    DEBUGPRINT("Recover bind: sockfd=%d, addr->data=%s, addrlen=%d, result=%d", sockfd, addr->sa_data, addrlen, result);
    resp->val = result;       
}

void
setsockoptRecover(struct seccomp_notif *req, struct seccomp_notif_resp *resp) {
    int result = read(logFd, bufLog, sizeof(int) * 2);
    if (result == -1)
        err(EXIT_FAILURE, "setsockopt recover");
    bufLog[result] = '\0';
    result = strtol(bufLog, NULL, 16);
    
    DEBUGPRINT("RECOVER setsockopt: %d\n", result);
    resp->val = result;
}

void getsockoptRecover(struct seccomp_notif *req, struct seccomp_notif_resp *resp) {
    int         sockfd = req->data.args[0];
    int         level = req->data.args[1];
    int         optname = req->data.args[2];
    void        *optval = (void *) req->data.args[3];
    socklen_t   *optlen = (socklen_t *) req->data.args[4];
    int         result;

    result = read(logFd, bufLog, sizeof(socklen_t *) * 2);
    if (result == -1)
        err(EXIT_FAILURE, "getsockopt recover");
    bufLog[result] = '\0';

    memcpy(optlen, *(curPointer++), sizeof(socklen_t));
    curCounter++;
    DEBUGPRINT("curCounter=%d\n\n\n", curCounter);

    result = read(logFd, bufLog, sizeof(void *) * 2);
    if (result == -1)
        err(EXIT_FAILURE, "getsockopt recover");
    bufLog[result] = '\0';

    memcpy(optval, *(curPointer++), *optlen);
    curCounter++;
    DEBUGPRINT("curCounter=%d\n\n\n", curCounter);
    
    result = read(logFd, bufLog, sizeof(int) * 2);
    if (result == -1)
        err(EXIT_FAILURE, "setsockopt recover");
    bufLog[result] = '\0';
    result = strtol(bufLog, NULL, 16);

    resp->val = result;
}

void
getsocknameRecover(struct seccomp_notif *req, struct seccomp_notif_resp *resp) {
    int                 sockfd = req->data.args[0];
    struct sockaddr     *addr = (struct sockaddr *) req->data.args[1];
    socklen_t           *addrlen = (socklen_t *) req->data.args[2];
    int                 result;

    result = read(logFd, bufLog, sizeof(struct sockaddr *) * 2); // not used, currently using from curPointer
    if (result == -1)
        err(EXIT_FAILURE, "Read from file in recover");
    bufLog[result] = '\0';
    
    struct sockaddr *temp = (struct sockaddr *) *curPointer;
    DEBUGPRINT("temp->sa_family=%u", temp->sa_family);

    size_t size;
    switch (temp->sa_family) {
        case AF_INET:
            size = sizeof(struct sockaddr_in);
            DEBUGPRINT("getsockname size=%d", size);
            struct sockaddr_in   *addr_in = (struct sockaddr_in *) req->data.args[1];
            break;
        case AF_INET6:
            size = sizeof(struct sockaddr_in6);
            DEBUGPRINT("getsockname size=%d", size);
            break;
        case AF_NETLINK:
            size = sizeof(struct sockaddr_nl);
            DEBUGPRINT("getsockname size=%d", size);
            struct sockaddr_nl   *addr_nl = (struct sockaddr_nl *) req->data.args[1];
            break;
        default:
            size = sizeof(struct sockaddr_storage);
            DEBUGPRINT("getsockname size=%d", size);
            struct sockaddr_storage  *addr_storage = (struct sockaddr_storage *) req->data.args[1];
            break;
    }

    memcpy(addr, *(curPointer++), size);
    curCounter++;
    DEBUGPRINT("curCounter=%d\n\n\n", curCounter);
    DEBUGPRINT("GETSOCKNAME addr->sa_data=%s", addr->sa_data);

    result = read(logFd, bufLog, sizeof(socklen_t *) * 2);     // not used, currently using from curPointer
    if (result == -1)
        err(EXIT_FAILURE, "newfstatat in recover");
    bufLog[result] = '\0';

    memcpy(addrlen, *(curPointer++), sizeof(socklen_t));
    curCounter++;
    DEBUGPRINT("curCounter=%d\n\n\n", curCounter);

    result = read(logFd, bufLog, sizeof(int) * 2);
    if (result == -1)
        err(EXIT_FAILURE, "newfstatat in recover");
    bufLog[result] = '\0';
    result = strtol(bufLog, NULL, 16);

    DEBUGPRINT("Recover getsockname: sockfd=%d, addr->data=%s, addrlen=%d, result=%d", sockfd, addr->sa_data, *addrlen, result);
    resp->val = result;   
}

void
skipSyscall(struct seccomp_notif *req, struct seccomp_notif_resp *resp) {
    resp->id = req->id;
    resp->error = 0;
    resp->val = 0;
    resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    sendNotifResponse(resp);
}

void
advanceTillClose(struct seccomp_notif *req, struct seccomp_notif_resp *resp, struct seccomp_notif_sizes  sizes) {
    int afterClose = 0;
    resp->id = req->id;
    resp->val = 0;
    resp->error = 0;
    resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    sendNotifResponse(resp);

    while (!afterClose) {
        memset(req, 0, sizes.seccomp_notif);
        if (ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_RECV, req) == -1) {
            if (errno == EINTR){
                // might have problem here? or does it go back to do while
                DEBUGPRINT("Got error inside recv notif!!\n"); 
                // this probably stops working...?
                continue;
            }
            err(EXIT_FAILURE, "\tS: ioctl-SECCOMP_IOCTL_NOTIF_RECV");
        }

        if (req->data.nr == SYS_close)
            afterClose = 1;
        DEBUGPRINT("Trash: %d", req->data.nr);
        resp->id = req->id;
        resp->val = 0;
        resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        sendNotifResponse(resp);
    }
}

/* Handle notifications that arrive via the SECCOMP_RET_USER_NOTIF file
    descriptor, 'notifyFd'. */

static void
handleNotifications()
{
    bool                        pathOK;
    char                        path[PATH_MAX];
    // char                        bufLog[1024] = {0};
    void                        **savedPointers;
    //void                        **curPointer;
    struct seccomp_notif        *req;
    struct seccomp_notif_resp   *resp;
    struct seccomp_notif_sizes  sizes;

    char                        *mypathname;
    int                         myDomain;


    allocSeccompNotifBuffers(&req, &resp, &sizes);
    savedPointers = malloc(sizeof(void *) * 100);
    curPointer = savedPointers;
    logFd = open("execution.log", O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH); // TODO: also log targetProcess prints?
    macro_test = open("logfile", O_WRONLY | O_CREAT | O_TRUNC, 0644);

    while (notifyFd == -1)

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

            DEBUGPRINT("RECORD syscall nr: %d\n", req->data.nr);
            // resp->val = 0;
            // resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE; // emulate for new program, to see which syscalls are used
            // sendNotifResponse(resp);

            //continue;  
            
            if ((req->data.nr == SYS_newfstatat) ||
                (req->data.nr == SYS_openat)) {
                DEBUGPRINT("Caught in %d!", req->data.nr);
                mypathname = (char *) req->data.args[1];
                DEBUGPRINT("pathname caught: %s!", mypathname);

                if ((strstr(mypathname, "nsswitch.conf") != NULL) || 
                    (strstr(mypathname, "resolv.conf") != NULL) || 
                    (strstr(mypathname, "libnss_mymachines.so") != NULL) || 
                    (strstr(mypathname, "libcap.so") != NULL) || 
                    (strstr(mypathname, "libnss_mdns_minimal.so") != NULL) || 
                    (strstr(mypathname, "ld.so.cache") != NULL) || 
                    (strstr(mypathname, "libnss_resolve.so") != NULL) || 
                    (strstr(mypathname, "gai.conf") != NULL)) {
                        // also libgcc, libresolv, libm.so.6 ..?
                        DEBUGPRINT("Entered NI trash loop: %s", mypathname);
                        advanceTillClose(req, resp, sizes);
                        continue; // return to normal recv notif loop
                }
            }

            if (req->data.nr == SYS_socket) {
                DEBUGPRINT("Caught in %d!", req->data.nr);
                myDomain = req->data.args[0];
                DEBUGPRINT("domain caught: %d!", myDomain);

                if (myDomain == AF_NETLINK) {
                        // because we cant replay recvmsg :/
                        DEBUGPRINT("Entered NI trash loop: %s", mypathname);
                        advanceTillClose(req, resp, sizes);
                        continue; // return to normal recv notif loop
                }
            }

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
                    curCounter++;
                    DEBUGPRINT("curCounter=%d\n\n\n", curCounter);

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
                    removeFd(result);

                    sprintf(bufLog, "%0*X%0*X\n", sizeof(short) * 2, req->data.nr, sizeof(int) * 2, result);
                    write(logFd, bufLog, strlen(bufLog));
                    sendNotifResponse(resp);
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
                    DEBUGPRINT("savedStat saved at: %p\n", savedStat);
                    if (savedStat == NULL)
                        err(EXIT_FAILURE, "Failed to allocate memory to struct stat");
                    memcpy(savedStat, sys_buf2, sizeof(struct stat));
                    *(curPointer++) = savedStat;
                    curCounter++;
                    DEBUGPRINT("curCounter=%d\n\n\n", curCounter);

                    DEBUGPRINT("RECORD fstat: fd=%d, user_statbuf=%p, original_result=%d\n", 
                        fd2, (void*) sys_buf2, resultFstat);
                    DEBUGPRINT("  st_size=%ld, st_mode=%o\n", sys_buf2->st_size, sys_buf2->st_mode);

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
                    resp->error = (responseFd == -1) ? -errno : 0;
                    resp->val = responseFd;
                    addFd(result, pathname);

                    DEBUGPRINT("strlen of pathname = %d", strlen(pathname));
                    char *savedPath = malloc(sizeof(char) * PATH_MAX);
                    if (savedPath == NULL)
                        err(EXIT_FAILURE, "Failed to allocate memory to char *");
                    strncpy(savedPath, pathname, strlen(pathname));
                    savedPath[strlen(pathname)] = '\0';  // Ensure null termination
                    *(curPointer++) = savedPath;
                    curCounter++;
                    DEBUGPRINT("curCounter=%d\n\n\n", curCounter);
                    DEBUGPRINT("savedPath str openat: %s + savedPath ptr: %lX", savedPath, savedPath);

                    sprintf(bufLog, "%0*X%0*lX%0*zX\n", sizeof(short) * 2, req->data.nr, sizeof(char *) * 2, savedPath, sizeof(long) * 2, responseFd);
                    write(logFd, bufLog, strlen(bufLog));
                    sendNotifResponse(resp);
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
                case SYS_pread64:       // for JVM
                case SYS_readlink:
                case SYS_getcwd:        // is this one supposed to be here..?
                // for driver
                // case SYS_getuid:
                // case SYS_fcntl:
                // case SYS_poll:
                // for server
                case SYS_listen:
                case SYS_accept:
                case SYS_fcntl:

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
            curCounter = 0;
        } 
        // separate from previous if-else block so that we can reset the file and move here
        if (phase == RECOVER) {
            char            newBuf[200] = {0};
            ssize_t         numRead;
            long int        syscallResult;
            long int        syscallNumber;
            unsigned long   addr;

            resp->id = req->id;
            resp-> flags = 0;
            resp->error = 0;

            numRead = read(logFd, newBuf, sizeof(short) * 2); // read syscall nr
            if (numRead == -1)
                err(EXIT_FAILURE, "Read from file in recover");
            newBuf[numRead] = '\0';

            if (numRead == 0){
                DEBUGPRINT("END OF FILE !!!!!!");
                phase = IGNORE;
                skipSyscall(req, resp);
                //exit(0);
                continue;
            }

            syscallNumber = strtol(newBuf, NULL, 16);
            DEBUGPRINT("SYSCALLS: log=%d curr=%d", syscallNumber, req->data.nr);

            if (req->data.nr != syscallNumber) {
                skipSyscall(req, resp);
                lseek(logFd, -4, SEEK_CUR);      
                continue;
            }

            if ((req->data.nr == SYS_newfstatat) ||
                (req->data.nr == SYS_openat)) {

                mypathname = (char *) req->data.args[1];
                DEBUGPRINT("RECOVER pathname caught: %s!", mypathname);
                
                if ((strstr(mypathname, "nsswitch.conf") != NULL) ||
                    (strstr(mypathname, "META-INF") != NULL)      || 
                    (strstr(mypathname, "resolv.conf") != NULL) ) {
                        DEBUGPRINT("Skipped JVM syscall: %s", mypathname);
                        skipSyscall(req, resp);
                        lseek(logFd, -4, SEEK_CUR);
                        continue;
                }

                if ((strstr(mypathname, "libnet.so") != NULL) || 
                    (strstr(mypathname, "if_inet6") != NULL) || 
                    (strstr(mypathname, "libnio.so") != NULL) || 
                    (strstr(mypathname, "libjimage.so") != NULL) ||
                    (strstr(mypathname, "java.security") != NULL) ||
                    (strstr(mypathname, "cpu.max") != NULL) || 
                    (strstr(mypathname, "libextnet.so") != NULL) || 
                    (strstr(mypathname, "net.properties") != NULL) ) {
                        DEBUGPRINT("Entered JVM trash loop: %s", mypathname);
                        advanceTillClose(req, resp, sizes);
                        lseek(logFd, -4, SEEK_CUR);
                        continue;
                    }

                numRead = read(logFd, newBuf, sizeof(char *) * 2);
                if (numRead == -1)
                    err(EXIT_FAILURE, "Read from file in recover");
                newBuf[numRead] = '\0';
                addr = strtol(newBuf, NULL, 16);

                DEBUGPRINT("Addr: %lX\n", addr);
                DEBUGPRINT("Content at addr: %s\n", addr);

                if (strcmp((char *) req->data.args[1], (char *) addr)){
                    DEBUGPRINT("DIFFERENT STRS COMPARED: log = %s and curr = %s", addr, req->data.args[1]);
                    DEBUGPRINT("Entering wrong args for open/stat loop");
                    lseek(logFd, -(sizeof(char *) * 2 + 4), SEEK_CUR);
                    advanceTillClose(req, resp, sizes);
                    continue; // return to normal recv notif loop
                } else {
                    DEBUGPRINT("Same STRS compared !!!: %s and %s\n\n\n\n", (char *) req->data.args[1], (char *) addr);
                    lseek(logFd, -(sizeof(char *) * 2), SEEK_CUR);
                }
            }

            if (req->data.nr == SYS_socket) {
                DEBUGPRINT("Caught in recover %d!", req->data.nr);
                myDomain = req->data.args[0];
                DEBUGPRINT("domain caught: %d!", myDomain);

                if (myDomain == AF_NETLINK) {
                        // cant replay recvmsg :/
                        DEBUGPRINT("Entered NI trash loop: %s", mypathname);
                        lseek(logFd, -4, SEEK_CUR);
                        advanceTillClose(req, resp, sizes);
                        continue; // return to normal recv notif loop
                }
            }

            DEBUGPRINT("req->data.nr = %d\n", req->data.nr);
            switch(req->data.nr) {
                case SYS_read:
                    char        *userBuf = (char *) req->data.args[1];
                    long int    savedBuf;

                    numRead = read(logFd, newBuf, sizeof(char *) * 2); //   has char *
                    if (numRead == -1)
                        err(EXIT_FAILURE, "Read from file in recover");
                    newBuf[numRead] = '\0';

                    DEBUGPRINT("Read: %s", newBuf);
                    savedBuf = strtol(newBuf, NULL, 16);
                    //printf("savedbuf: %s\n", (char *) savedBuf);

                    numRead = read(logFd, newBuf, sizeof(int) * 2); //      has struct length of str
                    if (numRead == -1)
                        err(EXIT_FAILURE, "Read from file in recover");
                    newBuf[numRead] = '\0';
                    int bufLen = strtol(newBuf, NULL, 16);

                    memcpy(userBuf, *(curPointer++), sizeof(char) * bufLen);
                    curCounter++;
                    DEBUGPRINT("curCounter=%d\n\n\n", curCounter);

                    //printf("userbuf: %s\n", userBuf);
                    resp->val = bufLen;

                    break;

                case SYS_write:
                    
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
                    curCounter++;
                    DEBUGPRINT("curCounter=%d\n\n\n", curCounter);


                    // For debugging, print some of the stat info
                    DEBUGPRINT("RECOVER fstat: fd=%d, user_statbuf=%p, original_result=%d\n", 
                        fd, (void*)user_statbuf, syscallResult);
                    DEBUGPRINT("  st_size=%ld, st_mode=%o\n", user_statbuf->st_size, user_statbuf->st_mode);
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

                case SYS_socket:
                    socketRecover(req, resp);
                    break;

                case SYS_connect:
                    connectRecover(req, resp);
                    break;

                case SYS_sendto:
                    sendtoRecover(req, resp);
                    break;
                
                case SYS_recvmsg:
                    recvmsgRecover(req, resp);
                    break;

                case SYS_shutdown:
                    shutdownRecover(req, resp);
                    break;

                case SYS_bind:
                    bindRecover(req, resp);
                    break;

                case SYS_getsockname:
                    getsocknameRecover(req, resp);
                    break;

                case SYS_setsockopt:
                    setsockoptRecover(req, resp);
                    break;

                case SYS_getsockopt:
                    getsockoptRecover(req, resp);
                    break;

                case SYS_openat:

                    int         dirfd = req->data.args[0];
                    char        *pathname = (char *) req->data.args[1];
                    int         flags = req->data.args[2];
                    int         result;

                    int resultFd = openat((int) req->data.args[0], (const char *) req->data.args[1], (int) req->data.args[2], (mode_t) req->data.args[3]);

                    result = read(logFd, newBuf, sizeof(char *) * 2);     // pathname not used here
                    if (result == -1)
                        err(EXIT_FAILURE, "newfstatat in recover: savedPath");
                    newBuf[result] = '\0';

                    char *savedPathname = (char *) *(curPointer++);
                    DEBUGPRINT("savedPathname: %s", savedPathname);
                    curCounter++;
                    DEBUGPRINT("curCounter=%d\n\n\n", curCounter);

                    // !!! above using buflog, here using newbuf !! careful
                    numRead = read(logFd, newBuf, sizeof(ssize_t) * 2);
                    newBuf[numRead] = '\0';

                    syscallResult = (int32_t)strtol(newBuf, NULL, 16);
                    DEBUGPRINT("Recover openat: result=%d", syscallResult);
                    resp->val = syscallResult; 
                    break;

                case SYS_newfstatat:
                    newfstatatRecover(req, resp);
                    break;
                    
                case SYS_pread64:       // for JVM
                case SYS_readlink:
                case SYS_getcwd:        // is this one supposed to be here..?
                case SYS_mmap:
                case SYS_munmap:
                case SYS_mprotect:
                    DEBUGPRINT("SKIPPED syscall nr: %d\n", req->data.nr);
                    resp->error = 0;
                    resp->val = 0;
                    resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE; // emulate for new program, to see which syscalls are used
                    sendNotifResponse(resp);

                    //sprintf(bufLog, "SKIPPED syscall nr: %d\n", req->data.nr);        // think how to skip them on recover...
                    //write(logFd, bufLog, strlen(bufLog));
                    
                    lseek(logFd, -4, SEEK_CUR);      // go back 4 chars of syscall we didnt use !!!
                    continue;

                default:
                    printf("Received syscall nr: %d\n", req->data.nr);
                    resp->id = req->id;
                    resp->error = 0;
                    resp->val = 0;
                    resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                    sendNotifResponse(resp);

                    continue;                
            }
            numRead = read(logFd, newBuf, 1); // consume \n
            sendNotifResponse(resp);
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
    //while (notifyFd == -1)
        //sched_yield();
        //err(EXIT_FAILURE, "recvfd");

    //handleNotifications(notifyFd);
    handleNotifications();
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