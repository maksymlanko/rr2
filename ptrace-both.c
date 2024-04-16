#include <jni.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <unistd.h>
#include <errno.h>
#include <sys/user.h>
#include <sys/syscall.h>

#include "libwrapperexample.h"

void callJavaProgram(int argc, char **argv);
int callEntryPoint(int argc, char **argv);

int main(int argc, char **argv) {

    /*
    if (argc < 2) {
        printf("Usage: %s <program> [args...]\n", argv[0]);
        return 1;
    }
    */

    pid_t child;
    int status;
    struct user_regs_struct regs;
    int in = 0;

    child = fork();
    if (child == 0){
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0){
            perror("ptrace");
            return 1;
        }
        kill(getpid(), SIGSTOP);
        kill(getpid(), SIGSTOP);

        //instead of execvp call entrypoint
        //execvp(argv[1], &argv[1]);
        //callJavaProgram(argc, argv);
                
        int res = callEntryPoint(argc, argv);
        printf("finished callEntryPoint\n\n");

        //return 0;
        
        /*
        if (res != 0){
            printf("StartedcallJavaProgram\n\n");
            callJavaProgram(argc, argv);
            printf("finished callJavaProgram\n\n");

        }
        */
        
        

        return 0;

    } else if (child > 0){
        wait(&status);
        //wait(&status);

        while (WIFSTOPPED(status)){
            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            if (in == 0){
                printf("SystemCall %ld called with %ld, %ld, %ld\n", regs.orig_rax, regs.rsi, regs.rdx, regs.r10);
                in = 1;
            }
            else {
                printf("Return was: %ld\n", regs.rax);
                in = 0;
            }

            //sleep(1);
            if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) < 0){
                perror("ptrace");
                return 1;
            }

            wait(&status);
        }
    } else{
        perror("fork");
        return 1;
    }

    return 0;
}

int callEntryPoint(int argc, char **argv){
    graal_isolate_t *isolate = NULL;
    graal_isolatethread_t *thread = NULL;

    if (graal_create_isolate(NULL, &isolate, &thread) != 0) {
        fprintf(stderr, "initialization error\n");
        return 1;
    }

    int result = run_c(thread, argv[1]);
    printf("Return was %d\n", result);

    graal_tear_down_isolate(thread);
    return result;
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

    jclass cls = (*env)->FindClass(env, "WrapperExample");

    if ((*env)->ExceptionOccurred(env)) {
    (*env)->ExceptionDescribe(env);
    (*env)->ExceptionClear(env);
    // Handle error appropriately
}

    if (cls == NULL) {
        fprintf(stderr, "ERROR: class not found !\n");
    } else {
        jmethodID mid = (*env)->GetStaticMethodID(env, cls, "main", "([Ljava/lang/String;)V");
        
        if (mid == NULL) {
            fprintf(stderr, "ERROR: method void main(String[]) not found !\n");
        } else {
            //jobjectArray arr = (*env)->NewObjectArray(env, argc, (*env)->FindClass(env, "java/lang/String"), NULL);
            jobjectArray arr = (*env)->NewObjectArray(env, argc-1, (*env)->FindClass(env, "java/lang/String"), NULL);
            //for (int i = 0; i < argc; i++) {
            for (int i = 1; i < argc; i++) {
                //(*env)->SetObjectArrayElement(env, arr, i, (*env)->NewStringUTF(env, argv[i]));
                (*env)->SetObjectArrayElement(env, arr, i-1, (*env)->NewStringUTF(env, argv[i]));
            }            
            (*env)->CallStaticVoidMethod(env, cls, mid, arr);
        }
    }
    (*jvm)->DestroyJavaVM(jvm); // Destroy the JVM
}