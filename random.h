#ifndef RANDOM_H
#define RANDOM_H

#include <stddef.h>
#include <stdint.h>
#include "simple_inttypes.h"

#define ERROR_REPORT(x) do {fprintf(stderr, "FILE: %s | LINE: %d | ERROR: %s\n", __FILE__, __LINE__, error_parse(x));} while (0)

typedef enum {
    ERR_NONE = 0,
    ERR_OOB,
    ERR_SHA,
    ERR_NULL,
    ERR_FAIL,
} status_t;

status_t random_create(u32 key[8]);
void     random_print(void);
void     random_destroy(void);
u32      random_get(const u64 index);
char*    error_parse(const status_t err);

#endif
