#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h> 

void callJavaProgram(int argc, char **argv);

int main(int argc, char **argv) {
    callJavaProgram(argc, argv);
    return 0;
}

void callJavaProgram(int argc, char **argv) {

    JavaVM *jvm; // Pointer to the JVM (Java Virtual Machine)
    JNIEnv *env; // Pointer to native interface
    // Prepare loading of Java VM
    JavaVMInitArgs vm_args;
    JavaVMOption* options = malloc(sizeof(JavaVMOption) * 5);
    options[0].optionString = "-Djava.class.path=."; // Path to the java .class file
    //options[0].optionString = "-Djava.class.path=/home/maksym/Documents/tese-rr/rr2";
    options[1].optionString = "-Xint";
    options[2].optionString = "-XX:+UseSerialGC";
    options[3].optionString = "-XX:+ReduceSignalUsage";
    options[4].optionString = "-XX:+DisableAttachMechanism";
    //options[5].optionString = "-verbose:jni"; // assim faz print passado x segs
    vm_args.version = JNI_VERSION_1_6; // Minimum Java version
    vm_args.nOptions = 5;
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