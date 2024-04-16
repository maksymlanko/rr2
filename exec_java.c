#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <jni.h>

int do_child(int argc, char **argv);
void callJavaProgram(int argc, char **argv);

int main(int argc, char **argv) {
    pid_t child = fork();
    if (child == 0) {

        return do_child(argc-1, argv+1);

        /*
        // Child process
        char *javaPath = "/usr/bin/java"; // Path to the Java executable
        char *javaArgs[] = { javaPath, "-cp", ".", "HelloWorld", NULL }; // Arguments for the Java program
        char *envp[] = { NULL }; // Environment variables; inherit the current process's environment

        ptrace(PTRACE_TRACEME, 0, NULL, NULL); // Signal the parent to trace this process
        kill(getpid(), SIGSTOP); // Stop itself and wait for the parent to continue

        if (execve(javaPath, javaArgs, envp) == -1) {
            perror("execve"); // Print error if execve fails
            exit(EXIT_FAILURE);
        }
        exit(0); // Exit if execve somehow doesn't replace the process image

        */
    } else {
        // Parent process
        int status;
        waitpid(child, &status, 0); // Wait for the child to stop itself
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);

        while (1) {
            // Resume the child process and wait for a system call
            ptrace(PTRACE_SYSCALL, child, 0, 0);
            waitpid(child, &status, 0);

            if (WIFEXITED(status)) {
                // Child has exited
                printf("Child exited with status %d\n", WEXITSTATUS(status));
                break;
            } else if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80) {
                // Child is stopped, indicating a syscall stop
                long syscall = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*ORIG_RAX, NULL);
                printf("System call: %ld\n", syscall);
            } else if (WIFSIGNALED(status)) {
                // Child was killed by a signal
                printf("Child killed by signal %d\n", WTERMSIG(status));
                break;
            }
        }
    }

    return 0;
}


int do_child(int argc, char **argv) {
    /*
    char *args [argc+1];
    memcpy(args, argv, argc * sizeof(char*));
    args[argc] = NULL;
    */
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    kill(getpid(), SIGSTOP);

    /*
    //ptrace(PTRACE_TRACEME);
    kill(getpid(), SIGSTOP);

    char *javaPath = "/usr/bin/java"; // Path to the Java executable
    char *javaArgs[] = { javaPath, "-cp", ".", "HelloWorld", NULL }; // Arguments for the Java program
    char *envp[] = { NULL }; // Environment variables; inherit the current process's environment
    //extern char **environ;

    if (execve(javaPath, javaArgs, envp) == -1) {
        perror("execve");
        exit(EXIT_FAILURE);
    }
    */

    callJavaProgram(argc, argv);
    //return execvp(args[0], args);
}

void callJavaProgram(int argc, char **argv) {

    JavaVM *jvm; // Pointer to the JVM (Java Virtual Machine)
    JNIEnv *env; // Pointer to native interface
    // Prepare loading of Java VM
    JavaVMInitArgs vm_args;
    JavaVMOption* options = malloc(6 * sizeof(JavaVMOption));
    options[0].optionString = "-Djava.class.path=."; // Path to the java .class file
    //options[0].optionString = "-Djava.class.path=/home/maksym/Documents/tese-rr/rr2";
    //options[1].optionString = "-Djava.compiler=NONE";
    options[1].optionString = "-Xint";
    options[2].optionString = "-XX:+UseSerialGC";
    options[3].optionString = "-XX:+ReduceSignalUsage";
    options[4].optionString = "-XX:+DisableAttachMechanism";
    options[5].optionString = "-verbose:jni"; // assim faz print passado x segs
    vm_args.version = JNI_VERSION_1_6; // Minimum Java version
    vm_args.nOptions = 6;
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