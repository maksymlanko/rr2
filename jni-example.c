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

    clock_t t; 
    t = clock(); 
    t = clock() - t; 
    double time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds 
    printf("Initialization() took %f seconds to execute \n", time_taken); 

    JavaVM *jvm; // Pointer to the JVM (Java Virtual Machine)
    JNIEnv *env; // Pointer to native interface
    // Prepare loading of Java VM
    JavaVMInitArgs vm_args;
    JavaVMOption* options = malloc(sizeof(JavaVMOption));
    t = clock() - t; 
    time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds 
    printf("malloc() took %f seconds to execute \n", time_taken);
    options[0].optionString = "-Djava.class.path=."; // Path to the java .class file
    vm_args.version = JNI_VERSION_1_6; // Minimum Java version
    vm_args.nOptions = 1;
    vm_args.options = options;
    vm_args.ignoreUnrecognized = JNI_FALSE;
    // Load and initialize Java VM and JNI interface
    jint rc = JNI_CreateJavaVM(&jvm, (void**)&env, &vm_args);
    t = clock() - t; 
    time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds 
    printf("createVM() took %f seconds to execute \n", time_taken);

    free(options); // Free the options array
    if (rc != JNI_OK) {
        fprintf(stderr, "ERROR: JNI_CreateJavaVM() failed, error code: %d\n", rc);
        exit(EXIT_FAILURE);
    }
    // Execute main method of the specified Java class

    jclass cls = (*env)->FindClass(env, "HelloWorld");
    t = clock() - t; 
    time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds 
    printf("findClass() took %f seconds to execute \n", time_taken);

    if (cls == NULL) {
        fprintf(stderr, "ERROR: class not found !\n");
    } else {
        jmethodID mid = (*env)->GetStaticMethodID(env, cls, "main", "([Ljava/lang/String;)V");
        t = clock() - t; 
        time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds 
        printf("getStaticMethod() took %f seconds to execute \n", time_taken);
        
        if (mid == NULL) {
            fprintf(stderr, "ERROR: method void main(String[]) not found !\n");
        } else {
            jobjectArray arr = (*env)->NewObjectArray(env, argc, (*env)->FindClass(env, "java/lang/String"), NULL);
            for (int i = 0; i < argc; i++) {
                (*env)->SetObjectArrayElement(env, arr, i, (*env)->NewStringUTF(env, argv[i]));
            }
            t = clock() - t; 
            time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds 
            printf("setObjectArrayElement() took %f seconds to execute \n", time_taken);
            
                        (*env)->CallStaticVoidMethod(env, cls, mid, arr);
            t = clock() - t; 
            time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds 
            printf("callMain() took %f seconds to execute \n", time_taken);

        }
    }
    (*jvm)->DestroyJavaVM(jvm); // Destroy the JVM

    t = clock() - t; 
            time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds 
            printf("destroyVM() took %f seconds to execute \n", time_taken);
}