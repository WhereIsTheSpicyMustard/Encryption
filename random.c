#include "random.h"

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "simple_inttypes.h"
#include "sha256.h"

typedef struct RandomContext {
    u32 key[8];
    u32 cache_data[8];
    u64 cache_block;
    int cache_valid;
} RandomContext;

static RandomContext context = {0};

status_t random_create(u32 new_key[8])
{
    if (new_key == NULL) {
        ERROR_REPORT(ERR_NULL);
        return ERR_NULL;
    }
    memcpy(context.key, new_key, 32);
    context.cache_valid = 0;
    return ERR_NONE;
}

static status_t random_generate_block(const u64 block)
{
    u8 hash_bytes[40];
    memcpy(hash_bytes, context.key, 32);
    memcpy(hash_bytes + 32, &block, 8);

    if (sha256(hash_bytes, 40, context.cache_data)) {
        ERROR_REPORT(ERR_SHA);
        return ERR_SHA;
    }
    context.cache_block = block;
    context.cache_valid = 1;
    return ERR_NONE;
}

u32 random_get(const u64 index)
{
    const u64 block = index / 8;
    if (!context.cache_valid || block != context.cache_block) {
        if (random_generate_block(block)) return 0;
    }
    return context.cache_data[index % 8];
}

void random_print(void)
{
    for (int i = 0; i < 8; ++i)
        printf("%08x", context.cache_data[i]);
    printf("\n");
}

void random_destroy(void)
{
    context.cache_valid = 0;
}

char* error_parse(const status_t err)
{
    switch (err) {
        case ERR_NONE:   return "Error: none";
        case ERR_OOB:    return "Error: array index out of bounds";
        case ERR_SHA:    return "Error: SHA256 failed";
        case ERR_NULL:   return "Error: NULL pointer";
        default:         return "Error: uknown";
    }
}

