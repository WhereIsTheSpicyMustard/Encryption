#include "random.h"

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "simple_inttypes.h"
#include "sha256.h"

typedef struct RandomContext {
    u32 data[8];
    u32 key[8];
} RandomContext;

static RandomContext context = {0};
static u32* random_buffer = NULL;
static size_t random_buffer_size = 0;

status_t random_create(u32 new_key[8])
{
    if (new_key == NULL) {
        ERROR_REPORT(ERR_NULL);
        return ERR_NULL;
    }

    memcpy(context.key, new_key, 32);

    return ERR_NONE;
}

static status_t random_generate(const u64 counter)
{
    u8 hash_bytes[40];

    memcpy(hash_bytes, context.key, 32);
    memcpy(hash_bytes + 32, &counter, 8);

    if (sha256(hash_bytes, 40, context.data)) {
        ERROR_REPORT(ERR_SHA);
        return ERR_SHA;
    }

    return ERR_NONE;
}

static u32 random_get_internal(void)
{
    static size_t idx = 0;
    ++idx;
    if (idx % 8 == 0) {
        if (random_generate(idx))
            return 0;
    }
    return context.data[idx % 8];
}

status_t random_precompute(const size_t count)
{
    random_buffer = malloc(count * sizeof(*random_buffer));
    if (random_buffer == NULL) {
        ERROR_REPORT(ERR_NULL);
        return ERR_NULL;
    }

    random_buffer_size = count;

    for (size_t i = 0; i < count; ++i)
        random_buffer[i] = random_get_internal();

    return ERR_NONE;
}

void random_destroy(void)
{
    free(random_buffer);
    random_buffer = NULL;
}

u32 random_get(const size_t index)
{
    if (random_buffer == NULL) {
        ERROR_REPORT(ERR_NULL);
        return 0;
    }

    if (index >= random_buffer_size) {
        ERROR_REPORT(ERR_OOB);
        return ERR_OOB;
    }
    return random_buffer[index];
}

void random_print(void)
{
    for (int i = 0; i < 8; ++i)
        printf("%08x", context.data[i]);
    printf("\n");
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

