#ifndef __LIBMD5_H
#define __LIBMD5_H

#include <graal_isolate.h>


#if defined(__cplusplus)
extern "C" {
#endif

int run_main(int argc, char** argv);

int run_c(graal_isolatethread_t*, char*);

#if defined(__cplusplus)
}
#endif
#endif