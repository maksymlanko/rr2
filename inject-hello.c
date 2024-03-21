//Compile: gcc -FPIC -shared inject-hello.c -o inject-hello.so

#include <stdio.h> 

void __attribute__((constructor)) run_me_at_load_time() {
  printf("\nInject.so Loaded!\n");
}

void __attribute__((destructor)) run_me_at_unload() {
  printf("\nInject.so is being unloaded!\n");

}