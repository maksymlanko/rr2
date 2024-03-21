#ifndef __LIBWRAPPEREXAMPLE_H
#define __LIBWRAPPEREXAMPLE_H

#include <graal_isolate_dynamic.h>


#if defined(__cplusplus)
extern "C" {
#endif

typedef int (*run_main_fn_t)(int argc, char** argv);

typedef int (*filter_env_fn_t)(graal_isolatethread_t*, char*);

typedef int (*run_c_fn_t)(graal_isolatethread_t*, char*);

#if defined(__cplusplus)
}
#endif
#endif
