#include "random.h"

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "simple_inttypes.h"
#include "sha256.h"

static u64 x = 0; // splitmix internal state

status_t random_create(RandomContext* context, u32 new_key[8])
{
    if (context == NULL || new_key == NULL) {
        ERROR_REPORT(ERR_NULL);
        return ERR_NULL;
    }

    memcpy(context->key, new_key, 32);

    return ERR_NONE;
}

u32 random_get(const RandomContext* context, const int index)
{
    return context->data[index];
}

status_t random_generate(RandomContext* context, const u64 counter)
{
    u8 hash_bytes[40];

    if (context == NULL) {
        ERROR_REPORT(ERR_NULL);
        return ERR_NULL;
    }

    memcpy(hash_bytes, context->key, 32);
    memcpy(hash_bytes + 32, &counter, 8);

    if (sha256(hash_bytes, 40, context->data)) {
        ERROR_REPORT(ERR_SHA);
        return ERR_SHA;
    }

    return ERR_NONE;
}

void random_print(const RandomContext* context)
{
    if (context == NULL) return;
    for (int i = 0; i < 8; ++i)
        printf("%08x", context->data[i]);
    printf("\n");
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

