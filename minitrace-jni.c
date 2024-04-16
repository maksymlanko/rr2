#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <jni.h>

#include <sys/types.h>
#include <signal.h>


int do_child(int argc, char **argv);
int do_trace(pid_t child);
void callJavaProgram(int argc, char **argv);

int main(int argc, char **argv) {
    /*
    if (argc < 2) {
        fprintf(stderr, "Usage: %s prog args\n", argv[0]);
        exit(1);
    }
    */

    pid_t child = fork();
    if (child == 0) {
        return do_child(argc-1, argv+1);
    } else {
        return do_trace(child);
    }
}

int do_child(int argc, char **argv) {
    ptrace(PTRACE_TRACEME);
    kill(getpid(), SIGSTOP);

    callJavaProgram(argc, argv);
    //return execvp(args[0], args);
}

int wait_for_syscall(pid_t child);

int do_trace(pid_t child) {
    int status, syscall, retval;
    waitpid(child, &status, 0);
    ptrace(PTRACE_SETOPTIONS, child, NULL, PTRACE_O_TRACEFORK |
            PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE);
    //ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);

    siginfo_t info;
    
    while(1) {
        if (wait_for_syscall(child) != 0) break;

        //ptrace(PTRACE_GETSIGINFO, child, NULL, &info);
        //printf("Signal number: %d, signal code: %d\n", info.si_signo, info.si_code);

        syscall = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*ORIG_RAX);
        fprintf(stderr, "syscall(%d) = ", syscall);

        if (wait_for_syscall(child) != 0) break;

        //ptrace(PTRACE_GETSIGINFO, child, NULL, &info);
        //printf("Signal number: %d, signal code: %d\n", info.si_signo, info.si_code);

        retval = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*RAX);
        fprintf(stderr, "%d\n", retval);
    }
    
    //sleep(5);
    return 0;
}

int wait_for_syscall(pid_t child) {
    int status;
    while (1) {
        //ptrace(PTRACE_SYSCALL, child, 0, 0);
        ptrace(PTRACE_SYSCALL, child, 0, 0);
        waitpid(child, &status, 0);
        if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80){
            //printf("signal: %d\n", WSTOPSIG(status));
            return 0;
        }
            
        if (WIFEXITED(status))
            return 1;
        if (WIFSIGNALED(status))
            printf("signaled!!!!!!!");
        if (WIFSTOPPED(status)){
            printf("signal: %d\n", WSTOPSIG(status));
            //ptrace(PTRACE_SYSCALL, child, 0, 0);
            //ptrace(PTRACE_CONT, child, 0, SIGSEGV);
            return 5;
        }
        else
            printf("SAIU signal: \n");
            //return 5;
        
    }
}

void callJavaProgram(int argc, char **argv) {

    JavaVM *jvm; // Pointer to the JVM (Java Virtual Machine)
    JNIEnv *env; // Pointer to native interface
    // Prepare loading of Java VM
    JavaVMInitArgs vm_args;
    JavaVMOption* options = malloc(5 * sizeof(JavaVMOption));
    options[0].optionString = "-Djava.class.path=."; // Path to the java .class file
    //options[0].optionString = "-Djava.class.path=/home/maksym/Documents/tese-rr/rr2";
    //options[1].optionString = "-Djava.compiler=NONE";
    options[1].optionString = "-Xint";
    options[2].optionString = "-XX:+UseSerialGC";
    options[3].optionString = "-XX:+ReduceSignalUsage";
    options[4].optionString = "-XX:+DisableAttachMechanism";
    //options[5].optionString = "-verbose:gc";
    //options[5].optionString = "-Xss1280k";
    //options[5].optionString = "-verbose:jni"; // assim faz print passado x segs
    //options[5].optionString = "-Xrs";
    //options[5].optionString = "-XX:+AllowUserSignalHandlers";
    vm_args.version = JNI_VERSION_21; // Minimum Java version
    vm_args.nOptions = 5;
    vm_args.options = options;
    vm_args.ignoreUnrecognized = JNI_FALSE;
    // Load and initialize Java VM and JNI interface
    jint rc = JNI_CreateJavaVM(&jvm, (void**)&env, &vm_args);
    //return 0;
    free(options); // Free the options array
    if (rc != JNI_OK) {
        fprintf(stderr, "ERROR: JNI_CreateJavaVM() failed, error code: %d\n", rc);
        exit(EXIT_FAILURE);
    }
    // Execute main method of the specified Java class

    jclass cls = (*env)->FindClass(env, "HelloWorld");
    //jclass cls = (*env)->FindClass(env, "WrapperExample");

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