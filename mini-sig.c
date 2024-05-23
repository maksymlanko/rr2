#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <jni.h>
//#include "libwrapperexample.h"
#include "libmd5.h"
#include "syscall_args.h"

int do_child(int argc, char **argv);
int do_trace(pid_t child);
void callJavaProgram(int argc, char **argv);
int callEntryPoint(int argc, char **argv);
int open_files(int argc, char **argv);
static void my_sig_handler(int signo);
void init_signal_handler();
void print_syscall(int syscall, long regs[6]);

static volatile sig_atomic_t got_signal = 0;
//static volatile FILE *fptr; // error
FILE *fptr;

int main(int argc, char **argv) {
    pid_t child = fork();
    if (child == 0) {
        //return do_child(argc-1, argv+1);
        return do_child(argc, argv);
    } else {
        //open_files(int argc, char **argv);
        init_signal_handler();
        return do_trace(child);
    }
}

int do_child(int argc, char **argv) {
    //ptrace(PTRACE_TRACEME);
    //kill(getpid(), SIGSTOP);
    // ver pipe // sq com select

    
    int res = callEntryPoint(argc, argv);
    kill(getppid(), SIGUSR1);
    printf("finished callEntryPoint\n\n");
    
    
    if (res != 0){
        printf("StartedcallJavaProgram\n");
        callJavaProgram(argc-1, argv+1);
        printf("finished callJavaProgram\n");

    } else {
        kill(getppid(), SIGKILL);
    }
    
    

    //callJavaProgram(argc, argv);
    return 0;
}

int wait_for_syscall(pid_t child) {
    int status;
    while (1) {
        ptrace(PTRACE_SYSCALL, child, 0, 0);
        waitpid(child, &status, 0);
        if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80) {
            return 0;
        }
        if (WIFEXITED(status)) {
            return 1;
        }
        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            printf("The child was stopped by signal: %d\n", sig);
            if (sig == SIGTRAP) {
                printf("Handled SIGTRAP, continuing...\n");
                //ptrace(PTRACE_CONT, child, 0, 0);
                ptrace(PTRACE_SYSCALL, child, 0, sig);
                //return 0; // this make a syscall wrong syscall(435)=-1
            }/* else if (sig == SIGUSR1){
                printf("Received SIGUSR1, continuing...\n");
                fclose(fptr);
                fptr = fopen("jvm.log", "w");
            }*/ else {
                //ptrace(PTRACE_CONT, child, 0, sig);
                ptrace(PTRACE_SYSCALL, child, 0, sig);
                //return 0; // this reverses ptrace syscall_nr -> return order??
            }
        } else {
            printf("Unexpected status received\n");
            return 2;
        }
    }
}

int do_trace(pid_t child) {
    int status, syscall, retval;
    fptr = fopen("entry.log", "w");
    if (fptr == NULL) {
        perror("Error opening file");
        return 1;
    }

    waitpid(child, &status, 0);
    //ptrace(PTRACE_SETOPTIONS, child, NULL, PTRACE_O_TRACEFORK | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE);
    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);
    struct user_regs_struct regs;

    while (!got_signal) {
        if (wait_for_syscall(child) != 0) break;
        //syscall = ptrace(PTRACE_PEEKUSER, child, sizeof(long) * ORIG_RAX);
        ptrace(PTRACE_GETREGS, child, NULL, &regs);
        long temp_regs[6] = {regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9};  // Example register values
        syscall = regs.orig_rax;
        print_syscall(syscall, temp_regs);
        //fprintf(stderr, "syscall(%d) {%d, %d, %d, %d, %d, %d} = ", syscall, regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
        //fprintf(fptr, "syscall(%d) {%d, %d, %d, %d, %d, %d} = ", syscall, regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);     
        if (wait_for_syscall(child) != 0) break;
        //retval = ptrace(PTRACE_PEEKUSER, child, sizeof(long) * RAX);
        ptrace(PTRACE_GETREGS, child, NULL, &regs);
        retval = regs.rax;
        fprintf(stderr, "%d\n", retval);
        fprintf(fptr, "%d\n", retval);
    }
    //init_signal_handler();
    
    
    
    //ptrace(PTRACE_DETACH, child, 0, 0);
    fclose(fptr);
    fptr = fopen("jvm.log", "w");
    if (fptr == NULL) {
        perror("Error opening file");
        return 1;
    }
    ptrace(PTRACE_CONT, child, 0, 0);
    
    sigset_t sigset;
    sigemptyset(&sigset);
    int signal;
    sigaddset(&sigset, SIGUSR1);

    waitpid(child, &status, 0);

    if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            printf("The child was stopped by signal: %d\n", sig);
            if (sig == SIGTRAP) {
                printf("Handled SIGTRAP, continuing...\n");
                //ptrace(PTRACE_CONT, child, 0, 0);
                ptrace(PTRACE_SYSCALL, child, 0, sig);
                //return 0; // this make a syscall wrong syscall(435)=-1
            } else {
                //ptrace(PTRACE_CONT, child, 0, sig);
                ptrace(PTRACE_CONT, child, 0, sig);
                //return 0; // this reverses ptrace syscall_nr -> return order??
            }
    }
    //sigwait(&sigset, &signal);
    
    
    pause();
    //printf("hello\n");
    //ptrace(PTRACE_ATTACH, child, 0, 0);
    got_signal = 0; // something wrong here
    //printf("got_signal: %d \n", got_signal);
    while (!got_signal) {
        if (wait_for_syscall(child) != 0) break;
        //syscall = ptrace(PTRACE_PEEKUSER, child, sizeof(long) * ORIG_RAX);
        ptrace(PTRACE_GETREGS, child, NULL, &regs);
        long temp_regs[6] = {regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9};  // Example register values
        syscall = regs.orig_rax;
        print_syscall(syscall, temp_regs);
        //fprintf(stderr, "syscall(%d) {%d, %d, %d, %d, %d, %d} = ", syscall, regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
        //fprintf(fptr, "syscall(%d) {%d, %d, %d, %d, %d, %d} = ", syscall, regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9); 
        if (wait_for_syscall(child) != 0) break;
        //retval = ptrace(PTRACE_PEEKUSER, child, sizeof(long) * RAX);
        ptrace(PTRACE_GETREGS, child, NULL, &regs);
        retval = regs.rax;
        fprintf(stderr, "%d\n", retval);
        fprintf(fptr, "%d\n", retval);
    }
    ptrace(PTRACE_DETACH, child, 0, 0);

    fclose(fptr); 
    return 0;
}

void callJavaProgram(int argc, char **argv) {
    JavaVM *jvm;
    JNIEnv *env;
    JavaVMInitArgs vm_args;
    JavaVMOption* options = malloc(5 * sizeof(JavaVMOption));
    options[0].optionString = "-Djava.class.path=.";
    options[1].optionString = "-Xint";
    options[2].optionString = "-XX:+UseSerialGC";
    options[3].optionString = "-XX:+ReduceSignalUsage";
    options[4].optionString = "-XX:+DisableAttachMechanism";
    vm_args.version = JNI_VERSION_1_6; //upgrade later !!
    vm_args.nOptions = 5;
    vm_args.options = options;
    vm_args.ignoreUnrecognized = JNI_FALSE;
    jint rc = JNI_CreateJavaVM(&jvm, (void**)&env, &vm_args);
    free(options);
    if (rc != JNI_OK) {
        fprintf(stderr, "ERROR: JNI_CreateJavaVM() failed, error code: %d\n", rc);
        exit(EXIT_FAILURE);
    }
    //jclass cls = (*env)->FindClass(env, "HelloWorld");
    jclass cls = (*env)->FindClass(env, "ReflectionExample");
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
            kill(getppid(), SIGUSR1);
            kill(getpid(), SIGSTOP);
            (*env)->CallStaticVoidMethod(env, cls, mid, arr);
            kill(getppid(), SIGUSR1);
            //printf("killed\n");
        }
    }
    (*jvm)->DestroyJavaVM(jvm);
}



int callEntryPoint(int argc, char **argv){
    graal_isolate_t *isolate = NULL;
    graal_isolatethread_t *thread = NULL;

    if (graal_create_isolate(NULL, &isolate, &thread) != 0) {
        fprintf(stderr, "initialization error\n");
        return 1;
    }

    //replace printf with signal to initiate recording
    ptrace(PTRACE_TRACEME);
    kill(getpid(), SIGSTOP);

    //printf("Argv[1]: %s\n", argv[1]);
    int result = run_c(thread, argv[1]);
    printf("Return was %d\n", result);

    graal_tear_down_isolate(thread);
    return result;
 }

 int open_files(int argc, char **argv){
    FILE *fptr;
    fptr = fopen("jni.log", "w");
    fclose(fptr);
 }
 

static void my_sig_handler(int signo){
    got_signal = 1; //functions below are NOT async-signal-safe , im only trying this way because of perf reasons
    //fclose(fptr);
    //fptr = fopen("jvm.log", "w");
    struct sigaction sa = {
            .sa_handler = my_sig_handler,
            .sa_flags = SA_RESTART, // or 0??
            .sa_mask = 0,
    };

    if (sigaction(SIGUSR1, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }
}

void init_signal_handler(){
    struct sigaction sa = {
            .sa_handler = my_sig_handler,
            .sa_flags = SA_RESTART, // or 0??
            .sa_mask = 0,
    };

    if (sigaction(SIGUSR1, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

}

void print_syscall(int syscall, long regs[6]) {
    char format[100]; // Buffer for the format string
    int i;

    // Start building the format string
    strcpy(format, "syscall(%d) {");
    
    // Append the right number of %d's, based on args_len[syscall]
    for (i = 0; i < args_len[syscall]; i++) {
        strcat(format, "%d, ");
    }
    
    // Remove the last comma and space if there were any %d added
    if (args_len[syscall] > 0) {
        format[strlen(format) - 2] = '\0'; // Cut off the last ", "
    }
    
    // Finish the format string
    strcat(format, "} = ");
    
    // Use fprintf to print to stdout
    fprintf(stderr, format, syscall,
            args_len[syscall] > 0 ? regs[0] : 0,
            args_len[syscall] > 1 ? regs[1] : 0,
            args_len[syscall] > 2 ? regs[2] : 0,
            args_len[syscall] > 3 ? regs[3] : 0,
            args_len[syscall] > 4 ? regs[4] : 0,
            args_len[syscall] > 5 ? regs[5] : 0);

    // Use fprintf to print to the file
    fprintf(fptr, format, syscall,
            args_len[syscall] > 0 ? regs[0] : 0,
            args_len[syscall] > 1 ? regs[1] : 0,
            args_len[syscall] > 2 ? regs[2] : 0,
            args_len[syscall] > 3 ? regs[3] : 0,
            args_len[syscall] > 4 ? regs[4] : 0,
            args_len[syscall] > 5 ? regs[5] : 0);
}