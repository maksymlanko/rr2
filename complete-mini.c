#include <sys/ptrace.h>
#include <bits/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <string.h>

#include "syscalls.h"
#include "syscallents.h"

void callJavaProgram(int argc, char **argv);

/* cheap trick for reading syscall number / return value. */
#ifdef __amd64__
#define eax rax
#define orig_eax orig_rax
#else
#endif

#define offsetof(a, b) __builtin_offsetof(a,b)
#define get_reg(child, name) __get_reg(child, offsetof(struct user, regs.name))

long __get_reg(pid_t child, int off) {
    long val = ptrace(PTRACE_PEEKUSER, child, off);
    assert(errno == 0);
    return val;
}

int wait_for_syscall(pid_t child) {
    int status;
    while (1) {
        ptrace(PTRACE_SYSCALL, child, 0, 0);
        waitpid(child, &status, 0);
        if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
            return 0;
        if (WIFEXITED(status))
            return 1;
        fprintf(stderr, "[stopped %d (%x)]\n", status, WSTOPSIG(status));
    }
}

const char *syscall_name(int scn) {
    struct syscall_entry *ent;
    static char buf[128];
    if (scn <= MAX_SYSCALL_NUM) {
        ent = &syscalls[scn];
        if (ent->name)
            return ent->name;
    }
    snprintf(buf, sizeof buf, "sys_%d", scn);
    return buf;
}

long get_syscall_arg(pid_t child, int which) {
    switch (which) {
#ifdef __amd64__
    case 0: return get_reg(child, rdi);
    case 1: return get_reg(child, rsi);
    case 2: return get_reg(child, rdx);
    case 3: return get_reg(child, r10);
    case 4: return get_reg(child, r8);
    case 5: return get_reg(child, r9);
#else
    case 0: return get_reg(child, ebx);
    case 1: return get_reg(child, ecx);
    case 2: return get_reg(child, edx);
    case 3: return get_reg(child, esi);
    case 4: return get_reg(child, edi);
    case 5: return get_reg(child, ebp);
#endif
    default: return -1L;
    }
}

char *read_string(pid_t child, unsigned long addr) {
    char *val = malloc(4096);
    int allocated = 4096;
    int read = 0;
    unsigned long tmp;
    while (1) {
        if (read + sizeof tmp > allocated) {
            allocated *= 2;
            val = realloc(val, allocated);
        }
        tmp = ptrace(PTRACE_PEEKDATA, child, addr + read);
        if(errno != 0) {
            val[read] = 0;
            break;
        }
        memcpy(val + read, &tmp, sizeof tmp);
        if (memchr(&tmp, 0, sizeof tmp) != NULL)
            break;
        read += sizeof tmp;
    }
    return val;
}

void print_syscall_args(pid_t child, int num) {
    struct syscall_entry *ent = NULL;
    int nargs = SYSCALL_MAXARGS;
    int i;
    char *strval;

    if (num <= MAX_SYSCALL_NUM && syscalls[num].name) {
        ent = &syscalls[num];
        nargs = ent->nargs;
    }
    for (i = 0; i < nargs; i++) {
        long arg = get_syscall_arg(child, i);
        int type = ent ? ent->args[i] : ARG_PTR;
        switch (type) {
        case ARG_INT:
            fprintf(stderr, "%ld", arg);
            break;
        case ARG_STR:
            strval = read_string(child, arg);
            fprintf(stderr, "\"%s\"", strval);
            free(strval);
            break;
        default:
            fprintf(stderr, "0x%lx", arg);
            break;
        }
        if (i != nargs - 1)
            fprintf(stderr, ", ");
    }
}

void print_syscall(pid_t child, int syscall_req) {
    int num;
    num = get_reg(child, orig_eax);
    assert(errno == 0);

    fprintf(stderr, "%s(", syscall_name(num));
    print_syscall_args(child, num);
    fprintf(stderr, ") = ");

    if( syscall_req <= MAX_SYSCALL_NUM) {
        pause_on( num, syscall_req);
    }
}

int pause_on(int syscall_req, int syscall) {
    if(syscall == syscall_req)
        do {
            char buf[2];
            fgets(buf, sizeof(buf), stdin); // waits until enter to continue
        } while(0);
}

int do_trace(pid_t child, int syscall_req) {
    int status;
    int retval;
    waitpid(child, &status, 0);
    assert(WIFSTOPPED(status));
    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);
    while(1) {
        if (wait_for_syscall(child) != 0)
            break;

        print_syscall(child, syscall_req);

        if (wait_for_syscall(child) != 0)
            break;

        retval = get_reg(child, eax);
        assert(errno == 0);

        fprintf(stderr, "%d\n", retval);
    }
    return 0;
}

int do_child(int argc, char **argv) {
    char *args [argc+1];
    int i;
    for (i=0;i<argc;i++)
        args[i] = argv[i];
    args[argc] = NULL;

    ptrace(PTRACE_TRACEME);
    kill(getpid(), SIGSTOP);
    return execvp(args[0], args);
}

int main(int argc, char **argv) {
    pid_t child;
    int push = 1;
    int syscall = -1;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s [-s <syscall int>|-n <syscall name>] <program> <args>\n", argv[0]);
        exit(1);
    }

    if(strcmp(argv[1], "-s") == 0) {
        syscall = atoi(argv[2]);
        if (syscall > MAX_SYSCALL_NUM || syscall < 0) {
            fprintf(stderr, "Error: %s is an invalid syscall\n", argv[2]);
            exit(1);
        }
        push = 3;
    }

    if(strcmp(argv[1], "-n") == 0) {
        char *syscallname = argv[2];
        struct syscall_entry *ent;
        int i;

        for(i = 0; i < sizeof(syscalls)/sizeof(*syscalls); i++) {
            ent = &syscalls[i];
            if(strcmp(syscallname, ent->name) == 0) {
                syscall = i;
                break;
            }
        }

        if(syscall == -1) {
            fprintf(stderr, "Error: %s is an invalid syscall\n", argv[2]);
            exit(1);
        }

        push = 3;
    }


    child = fork();
    if (child == 0) {
        return do_child(argc-push, argv+push);
    } else {
        return do_trace(child, syscall);
    }
}


void callJavaProgram(int argc, char **argv) {

    JavaVM *jvm; // Pointer to the JVM (Java Virtual Machine)
    JNIEnv *env; // Pointer to native interface
    // Prepare loading of Java VM
    JavaVMInitArgs vm_args;
    JavaVMOption* options = malloc(sizeof(JavaVMOption));
    //options[0].optionString = "-Djava.class.path=."; // Path to the java .class file
    options[0].optionString = "-Djava.class.path=/home/maksym/Documents/tese-rr/rr2";
    vm_args.version = JNI_VERSION_1_6; // Minimum Java version
    vm_args.nOptions = 1;
    vm_args.options = options;
    vm_args.ignoreUnrecognized = JNI_FALSE;
    // Load and initialize Java VM and JNI interface
    jint rc = JNI_CreateJavaVM(&jvm, (void**)&env, &vm_args);
    free(options); // Free the options array
    if (rc != JNI_OK) {
        fprintf(stderr, "ERROR: JNI_CreateJavaVM() failed, error code: %d\n", rc);
        exit(EXIT_FAILURE);
    }
    // Execute main method of the specified Java class

    jclass cls = (*env)->FindClass(env, "HelloWorld");

    if (cls == NULL) {
        fprintf(stderr, "ERROR: class not found !\n");
    } else {
        jmethodID mid = (*env)->GetStaticMethodID(env, cls, "main", "([Ljava/lang/String;)V");
        
        if (mid == NULL) {
            fprintf(stderr, "ERROR: method void main(String[]) not found !\n");
        } else {
            jobjectArray arr = (*env)->NewObjectArray(env, argc, (*env)->FindClass(env, "java/lang/String"), NULL);
            for (int i = 0; i < argc; i++) {
                (*env)->SetObjectArrayElement(env, arr, i, (*env)->NewStringUTF(env, argv[i]));
            }
            
            (*env)->CallStaticVoidMethod(env, cls, mid, arr);

        }
    }
    (*jvm)->DestroyJavaVM(jvm); // Destroy the JVM
}