#include "sha256.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define WORD_SIZE 32

typedef uint64_t          u64;
typedef uint32_t          u32;
typedef uint8_t           u8;

static const u32 K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static inline u32 ROTR  (u32 x, u32 n)        { return (x >> n) | (x << (WORD_SIZE - n));       }
static inline u32 ROTL  (u32 x, u32 n)        { return (x << n) | (x >> (WORD_SIZE - n));       }
static inline u32 CH    (u32 x, u32 y, u32 z) { return (x & y) ^ (~x & z);                      }
static inline u32 MAJ   (u32 x, u32 y, u32 z) { return (x & y) ^ (x & z) ^ (y & z);             }

static inline u32 CSIG0 (u32 x)               { return ROTR(x, 2)  ^ ROTR(x, 13) ^ ROTR(x, 22); }
static inline u32 CSIG1 (u32 x)               { return ROTR(x, 6)  ^ ROTR(x, 11) ^ ROTR(x, 25); }
static inline u32 SIG0  (u32 x)               { return ROTR(x, 7)  ^ ROTR(x, 18) ^ (x >> 3);    }
static inline u32 SIG1  (u32 x)               { return ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10);   }

static void process_block (u32 block[16], u32 H[8])
{
    u32 W[64]; // message schedule

    // init working variables
    u32 a = H[0]; u32 e = H[4];
    u32 b = H[1]; u32 f = H[5];
    u32 c = H[2]; u32 g = H[6];
    u32 d = H[3]; u32 h = H[7];

    for (int t = 0; t < 16; t++) // first 16 words
        W[t] = block[t];
    for (int t = 16; t < 64; t++) // compute remaining schedule
        W[t] = SIG1(W[t-2]) + W[t-7] + SIG0(W[t-15]) + W[t-16];

    for (int t = 0; t < 64; t++) {
        const u32 T1 = h + CSIG1(e) + CH(e, f, g) + K[t] + W[t];
        const u32 T2 = CSIG0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    // update hash values
    H[0] = a + H[0]; H[4] = e + H[4];
    H[1] = b + H[1]; H[5] = f + H[5];
    H[2] = c + H[2]; H[6] = g + H[6];
    H[3] = d + H[3]; H[7] = h + H[7];
}


// assumes M has already been checked for NULL
// length is in bytes
static u32* parse_message (u8* M1, const size_t length, size_t* new_length)
{
    *new_length = ((length + 9 + 63) / 64) * 64;

    // this is confusing but the size of M2 depends on the size of M1
    // since its a multiple of 64 bytes it will also be a multiple of 4 bytes (32 bits)
    u32* M2 = calloc(*new_length, 1);
    if (M2 == NULL) return NULL;
    u8* M2_bytes = (u8*)M2;

    memcpy(M2_bytes, M1, length);

    M2_bytes[length] = 0x80; // append 1 bit

     // append length
    u64 bit_length = (u64)length * 8;
    for (size_t i = 0; i < 8; i++) {
        M2_bytes[*new_length - 1 - i] =
        (u8)(bit_length >> (i * 8));
    }

    for (size_t i = 0; i < *new_length; i += 4) {
        const u32 word =
        ((u32)M2_bytes[i + 0] << 24) |
        ((u32)M2_bytes[i + 1] << 16) |
        ((u32)M2_bytes[i + 2] << 8 ) |
        ((u32)M2_bytes[i + 3]      );
        M2[i / 4] = word;
    }

    return M2;
}

int sha256 (u8* raw, const size_t len, u32 H[8])
{
    if (raw == NULL) return 1;

    size_t length;
    u32* M = parse_message(raw, len, &length); // length is in bytes
    if (M == NULL) return 1;
    length /= 4; // get length in terms of number of words (4 bytes each)

    // init hash
    H[0] = 0x6a09e667; H[4] = 0x510e527f;
    H[1] = 0xbb67ae85; H[5] = 0x9b05688c;
    H[2] = 0x3c6ef372; H[6] = 0x1f83d9ab;
    H[3] = 0xa54ff53a; H[7] = 0x5be0cd19;


    for (size_t i = 0; i < length; i += 16)
        process_block(M + i, H);

    free(M);
    M = NULL;
    return 0;
}



