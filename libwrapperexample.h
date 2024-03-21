#ifndef __LIBWRAPPEREXAMPLE_H
#define __LIBWRAPPEREXAMPLE_H

#include <graal_isolate.h>


#if defined(__cplusplus)
extern "C" {
#endif

int run_main(int argc, char** argv);

int filter_env(graal_isolatethread_t*, char*);

int run_c(graal_isolatethread_t*, char*);

#if defined(__cplusplus)
}
#endif
#endif
