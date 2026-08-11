#ifndef RANDOM_H
#define RANDOM_H

#include <stddef.h>
#include <stdint.h>
#include "error.h"
#include "simple_inttypes.h"

typedef struct {
    const u32 key[8];
} RandomContext;

u64 random_splitmix64(const u64 x);
status_t random_get(RandomContext* context, const u32 counter);

#endif
