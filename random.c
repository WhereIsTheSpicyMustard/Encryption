#include "random.h"

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "error.h"
#include "simple_inttypes.h"
#include "sha256.h"

static u64 x = 0;

status_t random_create(RandomContext* context, u32 new_key[8])
{
    if (context == NULL || new_key == NULL) {
        ERROR_REPORT(ERR_NULL);
        return ERR_NULL;
    }

    memcpy(context->key, new_key, 32);

    return ERR_NONE;
}

status_t random_get(RandomContext* context, const u64 counter)
{
    u8 hash_bytes[40];
    u32 hash[8];

    if (context == NULL) {
        ERROR_REPORT(ERR_NULL);
        return ERR_NULL;
    }

    memcpy(hash_bytes, context->key, 32);
    memcpy(hash_bytes + 32, &counter, 8);

    if (sha256(hash_bytes, 40, hash)) {
        ERROR_REPORT(ERR_SHA);
        return ERR_SHA;
    }

    memcpy(context->data, hash, 32);

    return ERR_NONE;
}


u64 random_splitmix64(void)
{
    u64    z = (x        += 0x9e3779b97f4a7c15ULL);
    z =   (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z =   (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

void random_splitmix64_set(const u64 seed) {
    x = seed;
}
