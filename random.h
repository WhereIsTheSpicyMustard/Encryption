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
} status_t;

typedef struct {
    u32 data[8];
    u32 key[8];
} RandomContext;

status_t random_create(RandomContext* context, u32 key[8]);
u32 random_get(RandomContext* context);
void     random_print(const RandomContext* context);
void     random_splitmix64_set(const u64 seed);
char* error_parse(const status_t err);

#endif
