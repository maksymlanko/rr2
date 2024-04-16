#include <jni.h>
#include <stdio.h>

int main() {
    JavaVM *jvm;
    JNIEnv *env;
    JavaVMInitArgs vm_args;
    JavaVMOption options[1];

    // Path to the Java source code
    options[0].optionString = "-Djava.class.path=.";
    vm_args.version = JNI_VERSION_21;  // Ensure this matches your JDK version
    vm_args.nOptions = 1;
    vm_args.options = options;
    vm_args.ignoreUnrecognized = JNI_FALSE;

    // Load and initialize a Java VM, return a JNI interface pointer in env
    jint res = JNI_CreateJavaVM(&jvm, (void**)&env, &vm_args);
    if (res != JNI_OK) {
        fprintf(stderr, "Failed to create JVM, error code %d\n", res);
        return 1;
    }

    // Find the class from which the method will be called
    jclass cls = (*env)->FindClass(env, "HelloWorld");
    if (cls == NULL) {
        jthrowable exc = (*env)->ExceptionOccurred(env);
        if (exc) {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        fprintf(stderr, "Class HelloWorld not found\n");
        (*jvm)->DestroyJavaVM(jvm);
        return 1;
    }

    // Find the method ID of the method to be called
    //jmethodID mid = (*env)->GetStaticMethodID(env, cls, "main", "()V");
    jmethodID mid = (*env)->GetStaticMethodID(env, cls, "main", "([Ljava/lang/String;)V");

    if (mid == NULL) {
        jthrowable exc = (*env)->ExceptionOccurred(env);
        if (exc) {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        fprintf(stderr, "Method displayMessage not found\n");
        (*jvm)->DestroyJavaVM(jvm);
        return 1;
    }

    // Call the method
    (*env)->CallStaticVoidMethod(env, cls, mid);

    // Check for exceptions during the method call
    jthrowable exc = (*env)->ExceptionOccurred(env);
    if (exc) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        fprintf(stderr, "An exception occurred while calling the method.\n");
        (*jvm)->DestroyJavaVM(jvm);
        return 1;
    }

    // Clean up and close the VM
    (*jvm)->DestroyJavaVM(jvm);

    return 0;
}
