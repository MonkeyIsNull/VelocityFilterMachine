#ifdef __linux__
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L  /* For clock_gettime, strdup, and other POSIX functions */
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE  /* For sysconf and other system functions */
#endif
#ifndef _ISOC11_SOURCE
#define _ISOC11_SOURCE  /* For aligned_alloc and other C11 functions */
#endif
#endif

#include "vfm.h"

// Note: Most functions are implemented as static functions in vfm.c
// This file is kept for any future stub implementations that may be needed