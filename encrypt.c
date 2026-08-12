#include "encrypt.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "error.h"
#include "random.h"

static const size_t N = 16;

/*****************************************************************************************************************/
// These are helper functions that trust the caller.
// I know this is generally bad practice but here we are, I don't care.
// Ensure n != 0, a != 0, b != 0, c != 0
static inline u8  ROTR_8  (u32 x, u32 n) { return (u8) ((x >> n) | (x << (8  - n))); }
static inline u16 ROTR_16 (u32 x, u32 n) { return (u16)((x >> n) | (x << (16 - n))); }
static inline u32 ROTR_32 (u32 x, u32 n) { return (x >> n) | (x << (32 - n)); }
static inline u64 ROTR_64 (u64 x, u32 n) { return (x >> n) | (x << (64 - n)); }

static inline u8  SIG_8  (u8  x, u32 a, u32 b, u32 c) { return ROTR_8 (x, a) ^ ROTR_8 (x, b) ^ ROTR_8 (x, c); }
static inline u16 SIG_16 (u16 x, u32 a, u32 b, u32 c) { return ROTR_16(x, a) ^ ROTR_16(x, b) ^ ROTR_16(x, c); }
static inline u32 SIG_32 (u32 x, u32 a, u32 b, u32 c) { return ROTR_32(x, a) ^ ROTR_32(x, b) ^ ROTR_32(x, c); }
static inline u64 SIG_64 (u64 x, u32 a, u32 b, u32 c) { return ROTR_64(x, a) ^ ROTR_64(x, b) ^ ROTR_64(x, c); }
/*****************************************************************************************************************/


/*****************************************************************************************************************/
// These are getters and setters, they also trust the caller.
// Ensure buffer != NULL obviously, ensure buffer will not overflow, each function
// steps forward in memory a different amount.
// My way of preventing this from being a bug-infested distastor is to
// pad the buffer from the very start such that the total number of bytes
// is a multiple of 840.  LCM(1,2,3,4,5,6,7,8) = 840.
static inline u16 get_block_16(u8* buffer) {
    return (u16)(((u32)buffer[0] << 8) | (u32)buffer[1]);
}
static inline u32 get_block_24(u8* buffer) {
    return ((u32)buffer[0] << 16) | ((u32)buffer[1] << 8) | ((u32)buffer[2]);
}
static inline u32 get_block_32(u8* buffer) {
    return ((u32)buffer[0] << 24) | ((u32)buffer[1] << 16) | ((u32)buffer[2] << 8) | ((u32)buffer[3]);
}
static inline u64 get_block_40(u8* buffer) {
    return ((u64)buffer[0] << 32) | ((u64)buffer[1] << 24) | ((u64)buffer[2] << 16) | ((u64)buffer[3] << 8) | ((u64)buffer[4]);
}
static inline u64 get_block_48(u8* buffer) {
    return ((u64)buffer[0] << 40) | ((u64)buffer[1] << 32) | ((u64)buffer[2] << 24) | ((u64)buffer[3] << 16) | ((u64)buffer[4] << 8)  | ((u64)buffer[5]);
}
static inline u64 get_block_56(u8* buffer) {
    return ((u64)buffer[0] << 48) | ((u64)buffer[1] << 40) | ((u64)buffer[2] << 32) | ((u64)buffer[3] << 24) | ((u64)buffer[4] << 16) | ((u64)buffer[5] << 8) | ((u64)buffer[6]);
}
static inline u64 get_block_64(u8* buffer) {
    return ((u64)buffer[0] << 56) | ((u64)buffer[1] << 48) | ((u64)buffer[2] << 40) | ((u64)buffer[3] << 32) | ((u64)buffer[4] << 24) | ((u64)buffer[5] << 16) | ((u64)buffer[6] <<  8) | ((u64)buffer[7]);
}

static void set_block_16(u8* buffer, const u16 val);
static void set_block_24(u8* buffer, const u32 val);
static void set_block_32(u8* buffer, const u32 val);
static void set_block_40(u8* buffer, const u64 val);
static void set_block_48(u8* buffer, const u64 val);
static void set_block_56(u8* buffer, const u64 val);
static void set_block_64(u8* buffer, const u64 val);
/*****************************************************************************************************************/

// performs a xor opperation on the entire buffer
status_t xor(u8* buffer, const size_t size, RandomContext* context)
{
    if (buffer == NULL || context == NULL) {
        ERROR_REPORT(ERR_NULL);
        return ERR_NULL;
    }

    int idx = 0;
    for (size_t j = 0; (j + 3) < size; j += 4) {

        // get 256 bit hash derived from key and splitmix
        if (idx % 8 == 0) {
            if (random_generate(context, random_splitmix64()))
                return 1;
        }

        set_block_32(buffer + j, get_block_32(buffer + j) ^ random_get(context, idx % 8));
        ++idx;
    }

    return ERR_NONE;
}


status_t encrypt(u8* dest, u8* src, const size_t dest_size, const size_t src_size, RandomContext* context)
{
    if (dest == NULL || src == NULL || context == NULL) {
        ERROR_REPORT(ERR_NULL);
        return ERR_NULL;
    }


    // set splitmix seed based on hash key,
    // used to modify the hash state instead of counter
    random_splitmix64_set(
        ((u64)(context->key[0] ^ context->key[1] ^ context->key[2] ^ context->key[3])) |
        ((u64)(context->key[4] ^ context->key[5] ^ context->key[6] ^ context->key[7]) << 32)
    );


    if (xor(src, src_size, context)) return 1;

    // copy into dest
    for (size_t i = 0; i < src_size; ++i) {
        dest[i] = src[i];
    }

    return ERR_NONE;
}

static void set_block_16(u8* buffer, const u16 val)
{
    buffer[0] = (u8)(val >> 8);
    buffer[1] = (u8)(val);
}

static void set_block_24(u8* buffer, const u32 val)
{
    buffer[0] = (u8)(val >> 16);
    buffer[1] = (u8)(val >> 8);
    buffer[2] = (u8) val;
}

static void set_block_32(u8* buffer, const u32 val)
{
    buffer[0] = (u8)(val >> 24);
    buffer[1] = (u8)(val >> 16);
    buffer[2] = (u8)(val >> 8);
    buffer[3] = (u8) val;
}

static void set_block_40(u8* buffer, const u64 val)
{
    buffer[0] = (u8)(val >> 32);
    buffer[1] = (u8)(val >> 24);
    buffer[2] = (u8)(val >> 16);
    buffer[3] = (u8)(val >> 8);
    buffer[4] = (u8) val;
}

static void set_block_48(u8* buffer, const u64 val)
{
    buffer[0] = (u8)(val >> 40);
    buffer[1] = (u8)(val >> 32);
    buffer[2] = (u8)(val >> 24);
    buffer[3] = (u8)(val >> 16);
    buffer[4] = (u8)(val >> 8);
    buffer[5] = (u8) val;
}

static void set_block_56(u8* buffer, const u64 val)
{
    buffer[0] = (u8)(val >> 48);
    buffer[1] = (u8)(val >> 40);
    buffer[2] = (u8)(val >> 32);
    buffer[3] = (u8)(val >> 24);
    buffer[4] = (u8)(val >> 16);
    buffer[5] = (u8)(val >> 8);
    buffer[6] = (u8) val;
}

static void set_block_64(u8* buffer, const u64 val)
{
    buffer[0] = (u8)(val >> 56);
    buffer[1] = (u8)(val >> 48);
    buffer[2] = (u8)(val >> 40);
    buffer[3] = (u8)(val >> 32);
    buffer[4] = (u8)(val >> 24);
    buffer[5] = (u8)(val >> 16);
    buffer[6] = (u8)(val >> 8);
    buffer[7] = (u8) val;
}
