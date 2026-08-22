#include "encrypt.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "random.h"

#define RANDOM_ROT_OFFSET INT64_MAX
#define RANDOM_PERM_OFFSET (INT64_MAX >> 2)

/*****************************************************************************************************************/
// These are helper functions that trust the caller.
// Ensure n > 0 and n < width of shift (ie. n < 32 for ROTR_32)
static inline u8  ROT_8  (u32 x, u32 n) { return (u8) ((x >> n) | (x << (8  - n)));}
static inline u16 ROT_16 (u32 x, u32 n) { return (u16)((x >> n) | (x << (16 - n)));}
static inline u32 ROT_24 (u32 x, u32 n) { return       (x >> n) | (x << (24 - n)); }
static inline u32 ROT_32 (u32 x, u32 n) { return       (x >> n) | (x << (32 - n)); }
static inline u64 ROT_40 (u64 x, u32 n) { return       (x >> n) | (x << (40 - n)); }
static inline u64 ROT_48 (u64 x, u32 n) { return       (x >> n) | (x << (48 - n)); }
static inline u64 ROT_56 (u64 x, u32 n) { return       (x >> n) | (x << (56 - n)); }
static inline u64 ROT_64 (u64 x, u32 n) { return       (x >> n) | (x << (64 - n)); }
/*****************************************************************************************************************/


/*****************************************************************************************************************/
// These are getters and setters, they also trust the caller.
// Ensure buffer != NULL obviously, ensure buffer will not overflow, each function
// steps forward in memory a different amount.
// My way of preventing this from being a bug-infested distaster is to
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
// These are permutation algorithms which shuffle the given buffer
// in chunks.  This is why the buffer is padded to be a multiple of
// 840 bytes, which is evenly divisible by all the numbers 1-8 inclusive.
static void encrypt_perm_block_8 (u8* buffer, const size_t size, const size_t rand_index);
static void encrypt_perm_block_16(u8* buffer, const size_t size, const size_t rand_index);
static void encrypt_perm_block_24(u8* buffer, const size_t size, const size_t rand_index);
static void encrypt_perm_block_32(u8* buffer, const size_t size, const size_t rand_index);
static void encrypt_perm_block_40(u8* buffer, const size_t size, const size_t rand_index);
static void encrypt_perm_block_48(u8* buffer, const size_t size, const size_t rand_index);
static void encrypt_perm_block_56(u8* buffer, const size_t size, const size_t rand_index);
static void encrypt_perm_block_64(u8* buffer, const size_t size, const size_t rand_index);

static void decrypt_perm_block_8 (u8* buffer, const size_t size, const size_t rand_index);
static void decrypt_perm_block_16(u8* buffer, const size_t size, const size_t rand_index);
static void decrypt_perm_block_24(u8* buffer, const size_t size, const size_t rand_index);
static void decrypt_perm_block_32(u8* buffer, const size_t size, const size_t rand_index);
static void decrypt_perm_block_40(u8* buffer, const size_t size, const size_t rand_index);
static void decrypt_perm_block_48(u8* buffer, const size_t size, const size_t rand_index);
static void decrypt_perm_block_56(u8* buffer, const size_t size, const size_t rand_index);
static void decrypt_perm_block_64(u8* buffer, const size_t size, const size_t rand_index);
/*****************************************************************************************************************/

/*****************************************************************************************************************/
// These are ROTR algorithms which scan the buffer byte by byte and rotate
// by the specified chunk of bytes
static void encrypt_rot_8 (u8* buffer, const size_t size, const size_t rand_index);
static void encrypt_rot_16(u8* buffer, const size_t size, const size_t rand_index);
static void encrypt_rot_24(u8* buffer, const size_t size, const size_t rand_index);
static void encrypt_rot_32(u8* buffer, const size_t size, const size_t rand_index);
static void encrypt_rot_40(u8* buffer, const size_t size, const size_t rand_index);
static void encrypt_rot_48(u8* buffer, const size_t size, const size_t rand_index);
static void encrypt_rot_56(u8* buffer, const size_t size, const size_t rand_index);
static void encrypt_rot_64(u8* buffer, const size_t size, const size_t rand_index);

static void decrypt_rot_8 (u8* buffer, const size_t size, const size_t rand_index);
static void decrypt_rot_16(u8* buffer, const size_t size, const size_t rand_index);
static void decrypt_rot_24(u8* buffer, const size_t size, const size_t rand_index);
static void decrypt_rot_32(u8* buffer, const size_t size, const size_t rand_index);
static void decrypt_rot_40(u8* buffer, const size_t size, const size_t rand_index);
static void decrypt_rot_48(u8* buffer, const size_t size, const size_t rand_index);
static void decrypt_rot_56(u8* buffer, const size_t size, const size_t rand_index);
static void decrypt_rot_64(u8* buffer, const size_t size, const size_t rand_index);
/*****************************************************************************************************************/


// performs a xor opperation on the entire buffer
static void encrypt_xor(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    for (size_t j = 0; (j + 3) < size; j += 4)
        set_block_32(buffer + j, get_block_32(buffer + j) ^ random_get(rand_index + (rand_counter++)));
}

status_t encrypt(u8* buffer, const size_t src_size)
{
    if (src_size % 840 != 0 || src_size < 840) {
        ERROR_REPORT(ERR_FAIL);
        return ERR_FAIL;
    }

    if (buffer == NULL) {
        ERROR_REPORT(ERR_NULL);
        return ERR_NULL;
    }

    u64 random_perm_offset = RANDOM_PERM_OFFSET;
    u64 random_rot_offset = RANDOM_ROT_OFFSET;

    encrypt_rot_8(buffer, src_size, random_rot_offset);
    encrypt_perm_block_64(buffer, src_size, random_perm_offset);
    encrypt_xor(buffer, src_size, (src_size >> 2) * 0);
    random_perm_offset += src_size / 8;
    random_rot_offset += src_size;

    encrypt_rot_16(buffer, src_size, random_rot_offset);
    encrypt_perm_block_56(buffer, src_size, random_perm_offset);
    encrypt_xor(buffer, src_size, (src_size >> 2) * 1);
    random_perm_offset += src_size / 7;
    random_rot_offset += src_size;

    encrypt_rot_24(buffer, src_size, random_rot_offset);
    encrypt_perm_block_48(buffer, src_size, random_perm_offset);
    encrypt_xor(buffer, src_size, (src_size >> 2) * 2);
    random_perm_offset += src_size / 6;
    random_rot_offset += src_size;

    encrypt_rot_32(buffer, src_size, random_rot_offset);
    encrypt_perm_block_40(buffer, src_size, random_perm_offset);
    encrypt_xor(buffer, src_size, (src_size >> 2) * 3);
    random_perm_offset += src_size / 5;
    random_rot_offset += src_size;

    encrypt_rot_40(buffer, src_size, random_rot_offset);
    encrypt_perm_block_32(buffer, src_size, random_perm_offset);
    encrypt_xor(buffer, src_size, (src_size >> 2) * 4);
    random_perm_offset += src_size / 4;
    random_rot_offset += src_size;

    encrypt_rot_48(buffer, src_size, random_rot_offset);
    encrypt_perm_block_24(buffer, src_size, random_perm_offset);
    encrypt_xor(buffer, src_size, (src_size >> 2) * 5);
    random_perm_offset += src_size / 3;
    random_rot_offset += src_size;

    encrypt_rot_56(buffer, src_size, random_rot_offset);
    encrypt_perm_block_16(buffer, src_size, random_perm_offset);
    encrypt_xor(buffer, src_size, (src_size >> 2) * 6);
    random_perm_offset += src_size / 2;
    random_rot_offset += src_size;

    encrypt_rot_64(buffer, src_size, random_rot_offset);
    encrypt_perm_block_8(buffer, src_size, random_perm_offset);
    encrypt_xor(buffer, src_size, (src_size >> 2) * 7);

    return ERR_NONE;
}

status_t decrypt(u8* buffer, const size_t src_size)
{
    if (src_size % 840 != 0 || src_size < 840) {
        ERROR_REPORT(ERR_FAIL);
        return ERR_FAIL;
    }

    if (buffer == NULL) {
        ERROR_REPORT(ERR_NULL);
        return ERR_NULL;
    }

    // number of random values needed for permuations
    const u64 perm_random_count = (u64)(
        (src_size / 1) + (src_size / 2) + (src_size / 3) + (src_size / 4) +
        (src_size / 5) + (src_size / 6) + (src_size / 7) + (src_size / 8)
    );

    u64 random_perm_offset = RANDOM_PERM_OFFSET + perm_random_count;
    u64 random_rot_offset = RANDOM_ROT_OFFSET + ((u64)src_size * 8);

    encrypt_xor(buffer, src_size, (src_size >> 2) * 7);
    decrypt_perm_block_8(buffer, src_size, random_perm_offset - 1);
    decrypt_rot_64(buffer, src_size, random_rot_offset - 8);
    random_perm_offset -= src_size / 1;
    random_rot_offset -= src_size;

    encrypt_xor(buffer, src_size, (src_size >> 2) * 6);
    decrypt_perm_block_16(buffer, src_size, random_perm_offset - 1);
    decrypt_rot_56(buffer, src_size, random_rot_offset - 7);
    random_perm_offset -= src_size / 2;
    random_rot_offset -= src_size;

    encrypt_xor(buffer, src_size, (src_size >> 2) * 5);
    decrypt_perm_block_24(buffer, src_size, random_perm_offset - 1);
    decrypt_rot_48(buffer, src_size, random_rot_offset - 6);
    random_perm_offset -= src_size / 3;
    random_rot_offset -= src_size;

    encrypt_xor(buffer, src_size, (src_size >> 2) * 4);
    decrypt_perm_block_32(buffer, src_size, random_perm_offset - 1);
    decrypt_rot_40(buffer, src_size, random_rot_offset - 5);
    random_perm_offset -= src_size / 4;
    random_rot_offset -= src_size;

    encrypt_xor(buffer, src_size, (src_size >> 2) * 3);
    decrypt_perm_block_40(buffer, src_size, random_perm_offset - 1);
    decrypt_rot_32(buffer, src_size, random_rot_offset - 4);
    random_perm_offset -= src_size / 5;
    random_rot_offset -= src_size;

    encrypt_xor(buffer, src_size, (src_size >> 2) * 2);
    decrypt_perm_block_48(buffer, src_size, random_perm_offset - 1);
    decrypt_rot_24(buffer, src_size, random_rot_offset - 3);
    random_perm_offset -= src_size / 6;
    random_rot_offset -= src_size;

    encrypt_xor(buffer, src_size, (src_size >> 2) * 1);
    decrypt_perm_block_56(buffer, src_size, random_perm_offset - 1);
    decrypt_rot_16(buffer, src_size, random_rot_offset - 2);
    random_perm_offset -= src_size / 7;
    random_rot_offset -= src_size;

    encrypt_xor(buffer, src_size, (src_size >> 2) * 0);
    decrypt_perm_block_64(buffer, src_size, random_perm_offset - 1);
    decrypt_rot_8(buffer, src_size, random_rot_offset - 1);

    return ERR_NONE;
}

/*****************************************************************************************************************/
static void encrypt_rot_8 (u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    for (size_t i = 0; i < size; ++i) {
        buffer[i] = ROT_8((u32)buffer[i], 1 + (random_get(rand_index + (rand_counter++)) % 7));
    }
}
static void encrypt_rot_16(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    for (size_t i = 0; (i + 1) < size; ++i) {
        set_block_16(
            buffer + i,
            ROT_16(get_block_16(buffer + i), 1 + (random_get(rand_index + (rand_counter++)) % 15)));
    }
}
static void encrypt_rot_24(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    for (size_t i = 0; (i + 2) < size; ++i) {
        set_block_24(
            buffer + i,
            ROT_24(get_block_24(buffer + i), 1 + (random_get(rand_index + (rand_counter++)) % 23)));
    }
}
static void encrypt_rot_32(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    for (size_t i = 0; (i + 3) < size; ++i) {
        set_block_32(
            buffer + i,
            ROT_32(get_block_32(buffer + i), 1 + (random_get(rand_index + (rand_counter++)) % 31)));
    }
}
static void encrypt_rot_40(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    for (size_t i = 0; (i + 4) < size; ++i) {
        set_block_40(
            buffer + i,
            ROT_40(get_block_40(buffer + i), 1 + (random_get(rand_index + (rand_counter++)) % 39)));
    }
}
static void encrypt_rot_48(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    for (size_t i = 0; (i + 5) < size; ++i) {
        set_block_48(
            buffer + i,
            ROT_48(get_block_48(buffer + i), 1 + (random_get(rand_index + (rand_counter++)) % 47)));
    }
}
static void encrypt_rot_56(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    for (size_t i = 0; (i + 6) < size; ++i) {
        set_block_56(
            buffer + i,
            ROT_56(get_block_56(buffer + i), 1 + (random_get(rand_index + (rand_counter++)) % 55)));
    }
}
static void encrypt_rot_64(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    for (size_t i = 0; (i + 7) < size; ++i) {
        set_block_64(
            buffer + i,
            ROT_64(get_block_64(buffer + i), 1 + (random_get(rand_index + (rand_counter++)) % 63)));
    }
}

static void decrypt_rot_8 (u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    for (size_t i = size; i > 0; --i) {
        buffer[i - 1] = ROT_8((u32)buffer[i - 1], 7 - (random_get(rand_index - (rand_counter++)) % 7));
    }
}
static void decrypt_rot_16(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    size_t i = size - 1;
    for (; i > 0;) {
        --i;
        set_block_16(
            buffer + i,
            ROT_16(get_block_16(buffer + i), 15 - (random_get(rand_index - (rand_counter++)) % 15)));
    }
}
static void decrypt_rot_24(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    size_t i = size - 2;
    for (; i > 0;) {
        --i;
        set_block_24(
            buffer + i,
            ROT_24(get_block_24(buffer + i), 23 - (random_get(rand_index - (rand_counter++)) % 23)));
    }
}
static void decrypt_rot_32(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    size_t i = size - 3;
    for (; i > 0;) {
        --i;
        set_block_32(
            buffer + i,
            ROT_32(get_block_32(buffer + i), 31 - (random_get(rand_index - (rand_counter++)) % 31)));
    }
}
static void decrypt_rot_40(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    size_t i = size - 4;
    for (; i > 0;) {
        --i;
        set_block_40(
            buffer + i,
            ROT_40(get_block_40(buffer + i), 39 - (random_get(rand_index - (rand_counter++)) % 39)));
    }
}
static void decrypt_rot_48(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    size_t i = size - 5;
    for (; i > 0;) {
        --i;
        set_block_48(
            buffer + i,
            ROT_48(get_block_48(buffer + i), 47 - (random_get(rand_index - (rand_counter++)) % 47)));
    }
}
static void decrypt_rot_56(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    size_t i = size - 6;
    for (; i > 0;) {
        --i;
        set_block_56(
            buffer + i,
            ROT_56(get_block_56(buffer + i), 55 - (random_get(rand_index - (rand_counter++)) % 55)));
    }
}
static void decrypt_rot_64(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    size_t i = size - 7;
    for (; i > 0;) {
        --i;
        set_block_64(
            buffer + i,
            ROT_64(get_block_64(buffer + i), 63 - (random_get(rand_index - (rand_counter++)) % 63)));
    }
}

/*****************************************************************************************************************/

static void encrypt_perm_block_8(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    for (size_t i = 0; i < size; ++i) {
        const size_t j = random_get(rand_index + (rand_counter++)) % (i + 1);
        const u8 temp = buffer[i];
        buffer[i] = buffer[j];
        buffer[j] = temp;
    }
}

static void decrypt_perm_block_8(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    for (size_t i = size; i > 0; --i) {
        const size_t j = random_get(rand_index - (rand_counter++)) % ((i - 1) + 1);
        const u8 temp = buffer[i - 1];
        buffer[i - 1] = buffer[j];
        buffer[j] = temp;
    }
}


static void encrypt_perm_block_16(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    for (size_t i = 0; (i + 1) < size; i += 2) {
        const size_t j = (random_get(rand_index + (rand_counter++)) % (i/2 + 1) * 2);
        const u16 temp = get_block_16(buffer + i);
        set_block_16(buffer + i, get_block_16(buffer + j));
        set_block_16(buffer + j, temp);
    }
}

static void decrypt_perm_block_16(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    size_t i = size;
    for (; i >= 2;) {
        i -= 2;
        const size_t j = (random_get(rand_index - (rand_counter++)) % (i/2 + 1) * 2);
        const u16 temp = get_block_16(buffer + i);
        set_block_16(buffer + i, get_block_16(buffer + j));
        set_block_16(buffer + j, temp);
    }
}


static void encrypt_perm_block_24(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    for (size_t i = 0; (i + 2) < size; i += 3) {
        const size_t j = (random_get(rand_index + (rand_counter++)) % (i/3 + 1) * 3);
        const u32 temp = get_block_24(buffer + i);
        set_block_24(buffer + i, get_block_24(buffer + j));
        set_block_24(buffer + j, temp);
    }
}

static void decrypt_perm_block_24(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    size_t i = size;
    for (; i >= 3;) {
        i -= 3;
        const size_t j = (random_get(rand_index - (rand_counter++)) % (i/3 + 1) * 3);
        const u32 temp = get_block_24(buffer + i);
        set_block_24(buffer + i, get_block_24(buffer + j));
        set_block_24(buffer + j, temp);
    }
}


static void encrypt_perm_block_32(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    for (size_t i = 0; (i + 3) < size; i += 4) {
        const size_t j = (random_get(rand_index + (rand_counter++)) % (i/4 + 1) * 4);
        const u32 temp = get_block_32(buffer + i);
        set_block_32(buffer + i, get_block_32(buffer + j));
        set_block_32(buffer + j, temp);
    }
}

static void decrypt_perm_block_32(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    size_t i = size;
    for (; i >= 4;) {
        i -= 4;
        const size_t j = (random_get(rand_index - (rand_counter++)) % (i/4 + 1) * 4);
        const u32 temp = get_block_32(buffer + i);
        set_block_32(buffer + i, get_block_32(buffer + j));
        set_block_32(buffer + j, temp);
    }
}


static void encrypt_perm_block_40(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    for (size_t i = 0; (i + 4) < size; i += 5) {
        const size_t j = (random_get(rand_index + (rand_counter++)) % (i/5 + 1) * 5);
        const u64 temp = get_block_40(buffer + i);
        set_block_40(buffer + i, get_block_40(buffer + j));
        set_block_40(buffer + j, temp);
    }
}

static void decrypt_perm_block_40(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    size_t i = size;
    for (; i >= 5;) {
        i -= 5;
        const size_t j = (random_get(rand_index - (rand_counter++)) % (i/5 + 1) * 5);
        const u64 temp = get_block_40(buffer + i);
        set_block_40(buffer + i, get_block_40(buffer + j));
        set_block_40(buffer + j, temp);
    }
}


static void encrypt_perm_block_48(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    for (size_t i = 0; (i + 5) < size; i += 6) {
        const size_t j = (random_get(rand_index + (rand_counter++)) % (i/6 + 1) * 6);
        const u64 temp = get_block_48(buffer + i);
        set_block_48(buffer + i, get_block_48(buffer + j));
        set_block_48(buffer + j, temp);
    }
}

static void decrypt_perm_block_48(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    size_t i = size;
    for (; i >= 6;) {
        i -= 6;
        const size_t j = (random_get(rand_index - (rand_counter++)) % (i/6 + 1) * 6);
        const u64 temp = get_block_48(buffer + i);
        set_block_48(buffer + i, get_block_48(buffer + j));
        set_block_48(buffer + j, temp);
    }
}


static void encrypt_perm_block_56(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    for (size_t i = 0; (i + 6) < size; i += 7) {
        const size_t j = (random_get(rand_index + (rand_counter++)) % (i/7 + 1) * 7);
        const u64 temp = get_block_56(buffer + i);
        set_block_56(buffer + i, get_block_56(buffer + j));
        set_block_56(buffer + j, temp);
    }
}

static void decrypt_perm_block_56(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    size_t i = size;
    for (; i >= 7;) {
        i -= 7;
        const size_t j = (random_get(rand_index - (rand_counter++)) % (i/7 + 1) * 7);
        const u64 temp = get_block_56(buffer + i);
        set_block_56(buffer + i, get_block_56(buffer + j));
        set_block_56(buffer + j, temp);
    }
}


static void encrypt_perm_block_64(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    for (size_t i = 0; (i + 7) < size; i += 8) {
        const size_t j = (random_get(rand_index + (rand_counter++)) % (i/8 + 1) * 8);
        const u64 temp = get_block_64(buffer + i);
        set_block_64(buffer + i, get_block_64(buffer + j));
        set_block_64(buffer + j, temp);
    }
}

static void decrypt_perm_block_64(u8* buffer, const size_t size, const u64 rand_index)
{
    u64 rand_counter = 0;
    size_t i = size;
    for (; i >= 8;) {
        i -= 8;
        const size_t j = (random_get(rand_index - (rand_counter++)) % (i/8 + 1) * 8);
        const u64 temp = get_block_64(buffer + i);
        set_block_64(buffer + i, get_block_64(buffer + j));
        set_block_64(buffer + j, temp);
    }
}

/*****************************************************************************************************************/

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
