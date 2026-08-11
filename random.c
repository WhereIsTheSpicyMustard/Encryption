#include "random.h"

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "error.h"
#include "simple_inttypes.h"
#include "sha256.h"

u64 random_splitmix64(const u64 x)
{
    u64 z = (x + 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

status_t random_get(RandomContext* context, const u32 counter)
{
    u8 hash_bytes[36];
    u32 hash[8];

    if (context == NULL)
        ERROR_FAIL(ERR_NULL);

    memcpy(hash_bytes, context->key, 32);
    memcpy(hash_bytes + 32, &counter, 4);

    if (sha256(hash_bytes, 36, hash))
        ERROR_FAIL(ERR_SHA);

    return ERR_NONE;
}
