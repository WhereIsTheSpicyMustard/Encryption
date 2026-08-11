#include "encrypt.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "error.h"
#include "random.h"

// set of allowed byte values for output
static const u8 CHAR_SET[64] = {
    ' ','!','#','$','%','&','(',')','*','+',',','-','.','/','0','1',
    '2','3','4','5','6','7','8','9',':',';','<','=','>','?','@','[',
    ']','^','a','b','c','d','e','f','g','h','i','j','k','l','m','n',
    'o','p','q','r','s','t','u','v','w','x','y','z','{','|','}','~'
};

static const size_t N = 10;


// assumes dest is un-allocated and null
status_t encrypt(u8* dest, u8* src, const size_t dest_size, const size_t src_size, RandomContext* context)
{
    if (dest == NULL || src == NULL || context == NULL) {
        ERROR_REPORT(ERR_NULL);
        return ERR_NULL;
    }


    /**************  initial xor with key **************/
    int key_idx = 0;
    for (size_t i = 0; i < src_size; ++i) {
        const size_t shift_idx = (8 * (i % 4));
        src[i] ^= (u8)(0xFF & (context->key[key_idx] >> shift_idx));
        if ((i + 1) % 4 == 0)
            key_idx = (key_idx + 1) % 8;
    }
    /**************  initial xor with key **************/


    random_splitmix64_set(
        ((u64)(context->key[0] ^ context->key[1] ^ context->key[2] ^ context->key[3])) |
        ((u64)(context->key[4] ^ context->key[5] ^ context->key[6] ^ context->key[7]) << 32));

    int data_idx = 0;
    for (size_t i = 0; i < N; ++i) {
        if (random_get(context, random_splitmix64()))
            return 1;
        for (size_t j = 0; j < src_size; ++j) {
            const size_t shift_idx = (8 * (j % 4));
            src[j] ^= (u8)(0xFF & (context->data[data_idx] >> shift_idx));
            if ((j + 1) % 4 == 0)
                data_idx = (data_idx + 1) % 8;
        }
    }

    for (size_t i = 0; i < src_size; ++i) {
        dest[i] = src[i];
    }

    return ERR_NONE;
}
