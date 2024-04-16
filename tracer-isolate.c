
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
#include <jni.h>

#include "libwrapperexample.h"

void callJavaProgram(int argc, char **argv);

int main(int argc, char* argv[]) {

    pid_t child;
    int status;
    struct user_regs_struct regs;
    int in = 0;
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <methodName>\n", argv[0]);
        exit(1);
    }

    child = fork();
    if (child == 0){
        //callJavaProgram(argc, argv);
        graal_isolate_t *isolate = NULL;
        graal_isolatethread_t *thread = NULL;

        if (graal_create_isolate(NULL, &isolate, &thread) != 0) {
            fprintf(stderr, "initialization error\n");
            return 1;
        }
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0){
            perror("ptrace");
            return 1;
        }
        int result = run_c(thread, argv[1]);
        printf("Return was %d\n", result);
        if (result != 0){
            callJavaProgram(argc, argv);
            //char *command[] = {"java", "HelloWorld", NULL};
            //if(execvp("java", command) != 0){
            //    perror("execvp java");
            //}
        }


        graal_tear_down_isolate(thread);

        //execvp(argv[1], &argv[1]);
        //execvp("./helloworld", NULL);
        //execvp("java", "HelloWorld");
        
    } else if (child > 0){
        wait(&status);

        while (WIFSTOPPED(status)){
            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            if (in == 0){
                if(regs.orig_rax == 39){
                    printf("SystemCall %ld called with %ld, %ld, %ld\n", regs.orig_rax, regs.rsi, regs.rdx, regs.r10);
                    in = 1;
                }
            }
            else {
                if (regs.orig_rax == 39){
                    printf("Original getpid() return was: %ld\n", regs.rax);
                    regs.rax = 12345;
                    ptrace(PTRACE_SETREGS, child, NULL, &regs);
                }
                printf("Return was: %ld\n", regs.rax);
                in = 0;
            }

            if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) < 0){
                perror("ptrace");
                return 1;
            }

            wait(&status);
        }
        if (WIFEXITED(status) && !WEXITSTATUS(status)) {
            /* the program terminated normally and executed successfully */
            //callJavaProgram(argc, argv);
            printf("Correu bem\n");
            //check if fails
        }

    } else{
        perror("fork");
        return 1;
    }

    return 0;
}


void callJavaProgram(int argc, char **argv) {
    JavaVM *jvm; // Pointer to the JVM (Java Virtual Machine)
    JNIEnv *env; // Pointer to native interface
    // Prepare loading of Java VM
    JavaVMInitArgs vm_args;
    JavaVMOption* options = malloc(sizeof(JavaVMOption));
    options[0].optionString = "-Djava.class.path=."; // Path to the java .class file
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
            
            (*env)->CallStaticVoidMethod(env, cls, mid, arr);
        }
    }
    (*jvm)->DestroyJavaVM(jvm); // Destroy the JVM
}




