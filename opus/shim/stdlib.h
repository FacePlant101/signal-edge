/* <stdlib.h> for libopus: the allocator and abort() come from opus/src/lib.rs. */
#ifndef SIGNAL_OPUS_STDLIB_H
#define SIGNAL_OPUS_STDLIB_H
#include <stddef.h>
void *malloc(size_t n);
void *calloc(size_t count, size_t n);
void *realloc(void *p, size_t n);
void free(void *p);
_Noreturn void abort(void);
static inline int abs(int x) { return x < 0 ? -x : x; }
#endif
