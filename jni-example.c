#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h> 
#include <err.h>
#include <errno.h>
#include <getopt.h>

void callJavaProgram(int argc, char **argv);
//void callEntryPoint(char **argv)

int main(int argc, char **argv) {
    callJavaProgram(argc, &argv[optind]);
    return 0;
}

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
    (*env)->CallStaticVoidMethod(env, cls, mid, arr);
    (*jvm)->DestroyJavaVM(jvm);
}