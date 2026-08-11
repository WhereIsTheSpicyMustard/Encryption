#ifndef RANDOM_H
#define RANDOM_H

#include <stddef.h>
#include <stdint.h>
#include "error.h"
#include "simple_inttypes.h"

typedef struct {
    u32 data[8];
    u32 key[8];
} RandomContext;

status_t random_create(RandomContext* context, u32 key[8]);
status_t random_get(RandomContext* context, const u64 counter);
u64      random_splitmix64(void);
void     random_splitmix64_set(const u64 seed);

#endif
